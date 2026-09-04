#!/usr/bin/env node
/* GraphSmith standalone gateway -- session capture, correlation, and finalization
 * (Standalone Gateway TRD SS3.3/SS3.4/SS3.5). Pure, transport-independent functions:
 * no fs/net/process here, so this is testable without spinning up real connections.
 *
 * SS3.4 (session boundary): this build resolves the TRD's own explicitly-unresolved
 * open design point in favor of the TRD's OWN stated lean (SS10, item 1) --
 * "connection-lifetime": one session per agent connection, sealed on disconnect. This
 * is the config's `session_boundary: "connection"` default (see scripts/gateway/
 * config.js). "time_window" is accepted by the config schema as a placeholder for a
 * later increment but is NOT implemented by this build -- selecting it currently
 * throws NOT_IMPLEMENTED at gateway startup rather than silently behaving like
 * "connection" (see gateway.js). Disclosed in the build report, not silently guessed.
 *
 * Concurrency requirement (SS3.3, stated explicitly because it is easy to get wrong):
 * correlation is keyed by JSON-RPC `id` via a Map, never by arrival order -- a response
 * can legitimately arrive for any pending id in any order, and a response for an id that
 * was never sent must be recorded as an anomaly rather than crash the proxy.
 */
"use strict";

const { sealBoundaryBundle } = require("../gsa-mcp-shim.js");

function fail(message, code = "GATEWAY_SESSION_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

/** Creates a fresh, empty in-memory session record (SS5.1's shape). */
function createSession(connectionId, options = {}) {
  if (typeof connectionId !== "string" || connectionId.length === 0) {
    throw fail("connectionId must be a non-empty string", "INVALID_ARGUMENT");
  }
  return {
    connectionId,
    initialize: null,
    tools: [],
    calls: [],
    anomalies: [],
    pendingCalls: new Map(),
    goal: typeof options.goal === "string" ? options.goal : undefined,
    startedAt: typeof options.now === "function" ? options.now() : Date.now(),
    finalized: false,
    nextCallSeq: 1, // monotonic per-session invocation counter; see recordCallStart.
  };
}

/** Records the initialize handshake verbatim (SS3.3). Downstream serverInfo responses
 * are merged by the caller (SS3.2, one gateway may front several servers) before being
 * passed here as a single merged object. */
function recordInitialize(session, initializeInfo) {
  if (session.finalized) throw fail("Cannot record into a finalized session", "SESSION_FINALIZED");
  session.initialize = {
    clientInfo: (initializeInfo && initializeInfo.clientInfo) || null,
    serverInfo: (initializeInfo && initializeInfo.serverInfo) || null,
    model: (initializeInfo && initializeInfo.model) || undefined,
  };
}

/** Records the merged, aggregated tools/list surface (SS3.3/SS6 step 4). Each tool
 * MUST already carry the `server` field that owns it (SS3.3: "tools are recorded with
 * their owning server name"). */
function recordToolsList(session, tools) {
  if (session.finalized) throw fail("Cannot record into a finalized session", "SESSION_FINALIZED");
  if (!Array.isArray(tools)) throw fail("tools must be an array", "INVALID_ARGUMENT");
  session.tools = tools.map((t) => ({ name: t.name, server: t.server, schema: t.schema }));
}

/** Records the outgoing half of a tools/call (or sampling/createMessage) request,
 * keyed by JSON-RPC id (SS3.3's concurrency requirement). `isModelCall` must be decided
 * by the caller at the protocol level (method name), never guessed from the tool name
 * (SS3.3, last paragraph). */
function recordCallStart(session, jsonRpcId, call) {
  if (session.finalized) throw fail("Cannot record into a finalized session", "SESSION_FINALIZED");
  if (jsonRpcId === undefined || jsonRpcId === null) {
    throw fail("jsonRpcId is required to correlate a pending call", "INVALID_ARGUMENT");
  }
  if (session.pendingCalls.has(jsonRpcId)) {
    throw fail(`Duplicate in-flight JSON-RPC id ${JSON.stringify(jsonRpcId)} on this connection`, "DUPLICATE_JSONRPC_ID");
  }
  session.pendingCalls.set(jsonRpcId, {
    tool: call.tool,
    server: call.server,
    arguments: call.arguments,
    model_call: Boolean(call.isModelCall),
    ts: call.ts !== undefined ? call.ts : Date.now(),
    /* Reserves this call's position in invocation order (SS3.3) at the moment it
     * STARTS, not when its response happens to arrive. Concurrent calls can complete
     * in any order (the whole point of id-based correlation), but the persisted
     * execution_trace's step numbers must reflect when each call was actually
     * invoked -- see toSealableSession's sort by this field. */
    seq: session.nextCallSeq++,
  });
}

/** Records the response half, correlating strictly by JSON-RPC id. A response for an id
 * that was never sent (protocol violation from a misbehaving downstream, or a bug) is
 * recorded as an anomaly and does NOT crash the proxy and is NOT attributed to any real
 * pending call (SS3.3, test plan item 11). Returns true if correlated, false if recorded
 * as an anomaly. */
function recordCallResult(session, jsonRpcId, result) {
  if (session.finalized) throw fail("Cannot record into a finalized session", "SESSION_FINALIZED");
  const pending = session.pendingCalls.get(jsonRpcId);
  if (!pending) {
    session.anomalies.push({
      kind: "UNMATCHED_RESPONSE",
      jsonRpcId,
      detail: "response arrived for a JSON-RPC id with no matching pending call",
      ts: result && result.ts !== undefined ? result.ts : Date.now(),
    });
    return false;
  }
  session.pendingCalls.delete(jsonRpcId);
  session.calls.push({
    tool: pending.tool,
    server: pending.server,
    arguments: pending.arguments,
    result: result ? result.result : undefined,
    isError: Boolean(result && result.isError),
    model_call: pending.model_call,
    ts: pending.ts,
    seq: pending.seq,
  });
  return true;
}

/** Called when the downstream side of a connection disconnects (or the whole session is
 * finalized) with calls still pending: each is recorded with an explicit disconnect
 * marker, never silently dropped (SS7 failure mode / test plan item 10).
 *
 * `serverFilter`, when given, scopes this to only the pending calls whose recorded
 * `server` matches it -- a downstream disconnect must not corrupt the attestation of a
 * call pending against a different, still-healthy downstream. Omitted entirely (the
 * connection-close / full-finalize callers) means "every pending call on this session",
 * as before. */
function markPendingAsDisconnected(session, reason, now, serverFilter) {
  const at = typeof now === "function" ? now() : Date.now();
  for (const [jsonRpcId, pending] of session.pendingCalls.entries()) {
    if (serverFilter !== undefined && pending.server !== serverFilter) continue;
    session.calls.push({
      tool: pending.tool,
      server: pending.server,
      arguments: pending.arguments,
      result: null,
      isError: true,
      model_call: pending.model_call,
      ts: pending.ts,
      seq: pending.seq,
      disconnected: true,
      disconnect_reason: reason || "downstream disconnected",
      jsonRpcId,
    });
    session.pendingCalls.delete(jsonRpcId);
  }
}

/** Projects the internal session record into the shape sealBoundaryBundle expects
 * (SS5.2: unchanged, this is gsa-mcp-shim.js's existing contract, not a new schema) --
 * plus two additive, backward-compatible extensions gsa-mcp-shim.js reads when present
 * (never required): each call's disconnect marker (so a downstream disconnect or
 * unmatched response is distinguishable from an ordinary tool error in the persisted
 * bundle, not just in the gateway's own in-memory state) and the session's anomalies.
 *
 * Calls are sorted by invocation order (`seq`, reserved at recordCallStart) rather than
 * left in response-arrival order, so the execution_trace step numbers sealBoundaryBundle
 * assigns reflect when each call actually started, even when a later call's response
 * arrives first. */
function toSealableSession(session) {
  const orderedCalls = session.calls.slice().sort((a, b) => (a.seq || 0) - (b.seq || 0));
  return {
    initialize: session.initialize || {},
    tools: session.tools,
    calls: orderedCalls.map((c) => ({
      tool: c.tool,
      server: c.server,
      arguments: c.arguments,
      result: c.result,
      isError: c.isError,
      model_call: c.model_call,
      ts: c.ts,
      ...(c.disconnected ? { disconnected: true, disconnect_reason: c.disconnect_reason, jsonRpcId: c.jsonRpcId } : {}),
    })),
    goal: session.goal,
    anomalies: session.anomalies,
  };
}

/** Finalizes a session: fails closed if pendingCalls is non-empty (SS6 step 10 / SS7 --
 * the caller must have already drained/marked-disconnected every pending call before
 * calling this; a non-empty pendingCalls map reaching sealBoundaryBundle would silently
 * produce an incomplete execution_trace). Calls sealBoundaryBundle UNCHANGED (SS3.5). */
function finalizeSession(session, keys) {
  if (session.finalized) throw fail("Session already finalized", "SESSION_FINALIZED");
  if (session.pendingCalls.size > 0) {
    throw fail(
      `Refusing to finalize session ${session.connectionId}: ${session.pendingCalls.size} call(s) still ` +
        "pending. Every in-flight call must be resolved or marked disconnected before sealing " +
        "(see markPendingAsDisconnected) -- sealing a session with pending calls would silently " +
        "produce an incomplete execution_trace.",
      "SESSION_HAS_PENDING_CALLS"
    );
  }
  let sealed;
  try {
    sealed = sealBoundaryBundle(toSealableSession(session), keys);
  } catch (error) {
    /* SS7: "sealBoundaryBundle throws ... fail-closed ... log the full session state for
     * debugging, do not attempt to seal a partial/guessed bundle." The caller (gateway.js)
     * is responsible for the actual logging; this wraps the error with the full session
     * attached so that logging has something to log. */
    const wrapped = fail(`sealBoundaryBundle threw while finalizing session ${session.connectionId}: ${error.message}`, "SEAL_FAILED");
    wrapped.session = session;
    wrapped.cause = error;
    throw wrapped;
  }
  session.finalized = true;
  return sealed;
}

module.exports = {
  createSession,
  recordInitialize,
  recordToolsList,
  recordCallStart,
  recordCallResult,
  markPendingAsDisconnected,
  toSealableSession,
  finalizeSession,
};
