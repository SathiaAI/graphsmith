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

const crypto = require("crypto");
const { sealBoundaryBundle } = require("../gsa-mcp-shim.js");

function fail(message, code = "GATEWAY_SESSION_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

/** Creates a fresh, empty in-memory session record (SS5.1's shape).
 *
 * `options.sessionId` (Cluster B: session-identity distinctness in the audit trail --
 * see gsa-mcp-shim.js#sealBoundaryBundle's own doc comment on why bundle_id needs this):
 * a permanent, unique identifier for this session, generated ONCE, folded into the
 * sealed bundle's bundle_id so two sessions that happen to record identical
 * {init, tools, calls} content are never treated as "the same session" just because a
 * content-only hash cannot tell them apart.
 *
 * Three ways this argument is used, distinguished so replay never invents a new
 * identity for an old session (which would break replay-idempotency -- the same
 * session's own WAL replayed twice must produce the same bundle_id) while a genuinely
 * new live session always gets a real one:
 *   - omitted entirely (proxy.js#openConnection, the live-dispatch path): a fresh
 *     `crypto.randomUUID()` is minted here, once, and the caller is expected to persist
 *     it (proxy.js writes it into the WAL's own SESSION_START event) so a later replay
 *     of this exact session reads the SAME id back rather than minting a new one.
 *   - a non-empty string (gateway.js#recoverCrashedSessions/abandonConnection replaying
 *     a WAL whose SESSION_START event already carries a `session_id`): reused verbatim,
 *     so replaying the same WAL twice yields the same session_id and therefore the same
 *     bundle_id.
 *   - explicitly `null`/absent-on-the-event (replaying an older WAL written before this
 *     field existed): stays `null` rather than randomly generated -- an old WAL replayed
 *     twice must still be idempotent, and inventing a random id here on every replay
 *     would break that for data that predates this fix. */
function createSession(connectionId, options = {}) {
  if (typeof connectionId !== "string" || connectionId.length === 0) {
    throw fail("connectionId must be a non-empty string", "INVALID_ARGUMENT");
  }
  const sessionId =
    typeof options.sessionId === "string" && options.sessionId.length > 0
      ? options.sessionId
      : options.sessionId === undefined
      ? crypto.randomUUID()
      : null;
  return {
    connectionId,
    sessionId,
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

/* CodeRabbit/Codex PR #29 review round 8 "keep unmatched downstream IDs out of agent
 * correlation": a fixed, non-speculative cap on session.anomalies, matching the same
 * discipline as MAX_PENDING_CALLS_PER_SESSION/MAX_COMPLETED_CALLS_PER_SESSION (proxy.js).
 * Without one, a misbehaving or compromised downstream emitting a stream of responses
 * with unknown ids could grow this array (and the eventual sealed bundle) without bound,
 * independently of both call-history caps -- neither of which this ever went through.
 *
 * Cluster I (frontier-panel review, 2026-09-14, 5/5 unanimous): Option C's own
 * recordAnomaly (below) originally bypassed this cap entirely on the theory that an
 * internally-detected event (an ambiguous-retry-blocked attestation) is trusted where an
 * externally-supplied one is not. The panel's unanimous view: internal detection doesn't
 * make the FREQUENCY trusted -- an agent that can repeatedly trigger the internal
 * condition (e.g. by retrying ambiguously) can still drive unbounded growth through an
 * uncapped path, reopening the exact resource-exhaustion class this cap was added to
 * close. Both anomaly-recording entry points below now share one capped, internal
 * implementation so there is a single bound on session.anomalies regardless of which
 * one records the event. */
const MAX_ANOMALIES_PER_SESSION = 1000;

/** Shared internal implementation for every anomaly-recording entry point in this file.
 * Appends `anomaly` (stamped with ts unless the caller already supplied one) once
 * session.anomalies is below MAX_ANOMALIES_PER_SESSION; once the cap is reached, further
 * anomalies are dropped rather than grow session.anomalies without bound, but the cap
 * being hit is itself recorded once (a single terminal marker entry) so it leaves a
 * trace rather than silently truncating. Returns true if the anomaly was recorded
 * (or the cap-reached marker was just appended), false if it was dropped. Not exported --
 * recordAnomaly and recordUnmatchedResponseAnomaly are the only external entry points,
 * so no existing call site anywhere in this codebase needs to change. */
function pushCappedAnomaly(session, anomaly) {
  if (session.finalized) throw fail("Cannot record into a finalized session", "SESSION_FINALIZED");
  if (session.anomalies.length >= MAX_ANOMALIES_PER_SESSION) return false;
  const entry = { ts: Date.now(), ...anomaly };
  session.anomalies.push(entry);
  if (session.anomalies.length >= MAX_ANOMALIES_PER_SESSION) {
    // Reuses entry.ts (an explicit historical ts if the caller supplied one, e.g.
    // recordUnmatchedResponseAnomaly's ts param) rather than a fresh Date.now(), matching
    // recordUnmatchedResponseAnomaly's original pre-merge behavior exactly.
    session.anomalies.push({
      kind: "ANOMALY_CAP_REACHED",
      detail: `This session reached the ${MAX_ANOMALIES_PER_SESSION}-anomaly cap -- further anomalies are dropped, not recorded.`,
      ts: entry.ts,
    });
  }
  return true;
}

/** Records a protocol-level irregularity that is not itself a call outcome -- generic
 * and additive, mirroring recordCallResult's own UNMATCHED_RESPONSE anomaly shape so
 * sealBoundaryBundle's existing anomaly handling needs no changes. Added for Option C
 * (Codex PR #29 Finding 2, external-panel-reviewed design -- see
 * option-c-hardened-design.md): records an ambiguous-retry-blocked event so the sealed
 * bundle attests that a duplicate dispatch was prevented, not just that one happened to
 * not occur. Routed through the shared, capped pushCappedAnomaly (Cluster I,
 * frontier-panel review 2026-09-14) rather than appending directly -- see that helper's
 * comment for why an internally-detected event still needs the same cap as an
 * externally-supplied one. */
function recordAnomaly(session, anomaly) {
  return pushCappedAnomaly(session, anomaly);
}

/** Records a downstream response that could not be correlated to any pending call,
 * WITHOUT going through recordCallResult's agent-facing pendingCalls lookup (CodeRabbit
 * PR #29 review round 8 "record unmatched downstream responses without agent-call
 * correlation" / Codex PR #29 review round 8 "keep unmatched downstream IDs out of agent
 * correlation"). The id on an unmatched DOWNSTREAM response is the downstream leg's own
 * internal id (assigned by scripts/gateway/downstream.js), not an agent-facing JSON-RPC
 * id -- recordCallResult's pendingCalls Map is keyed by the latter. Feeding a
 * downstream-internal id into recordCallResult risked colliding with an unrelated LIVE
 * agent call that happens to share the same id value: recordCallResult would delete that
 * live pending call and record this stale/foreign response as its result, corrupting the
 * session trace and losing the UNMATCHED_RESPONSE anomaly entirely. This function only
 * ever appends the anomaly -- it never touches pendingCalls.
 *
 * Capped at MAX_ANOMALIES_PER_SESSION via the shared pushCappedAnomaly helper (Codex
 * PR #29 review round 8 "cap unmatched-response anomalies per session", generalized by
 * Cluster I, frontier-panel review 2026-09-14). */
function recordUnmatchedResponseAnomaly(session, jsonRpcId, detail, ts) {
  return pushCappedAnomaly(session, {
    kind: "UNMATCHED_RESPONSE",
    jsonRpcId,
    detail: detail || "response arrived for a JSON-RPC id with no matching pending call",
    ts: ts !== undefined ? ts : Date.now(),
  });
}

/** Called when the downstream side of a connection disconnects (or the whole session is
 * finalized) with calls still pending: each is recorded with an explicit disconnect
 * marker, never silently dropped (SS7 failure mode / test plan item 10).
 *
 * `serverFilter`, when given, scopes this to only the pending calls whose recorded
 * `server` matches it -- a downstream disconnect must not corrupt the attestation of a
 * call pending against a different, still-healthy downstream. Omitted entirely (the
 * connection-close / full-finalize callers) means "every pending call on this session",
 * as before.
 *
 * `onDisconnect(call, at)`, when given, is invoked once per call actually moved into
 * `session.calls` here (Codex PR #29 review round 4 "log calls finalized as
 * disconnected": a call finalized this way previously got no matching
 * "gateway_call_completed" log line at all -- neither here nor later, since
 * handleMessage() only logs a call it itself still finds pending -- leaving disconnected
 * steps with no run ID, status, or duration in the operational log even though they are
 * fully recorded in the persisted trace). This module has no logger of its own by design
 * (see its header); the caller decides what, if anything, to log. */
function markPendingAsDisconnected(session, reason, now, serverFilter, onDisconnect) {
  const at = typeof now === "function" ? now() : Date.now();
  for (const [jsonRpcId, pending] of session.pendingCalls.entries()) {
    if (serverFilter !== undefined && pending.server !== serverFilter) continue;
    const call = {
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
    };
    session.calls.push(call);
    session.pendingCalls.delete(jsonRpcId);
    /* CodeRabbit PR #29 review round 4 "contain disconnect-callback failures during
     * session finalization": onDisconnect is the caller's own side effect (proxy.js
     * wires it to a JSON.stringify + this.log() call) and this module deliberately has
     * no logger of its own (see header) to report a failure in it -- but letting such a
     * failure escape uncaught is far worse than losing that one log line: it would abort
     * this loop (leaving any REMAINING pending calls on this session never marked
     * disconnected), and propagate up through closeConnection/handleDownstreamDisconnect,
     * skipping session removal, finalizeSession, and chain.appendSession entirely. Inside
     * gateway.js's shutdown drain loop that uncaught throw would also abort finalizing
     * every OTHER open session and skip writerClaim.release(), leaking a stale
     * writer-claim that blocks the next gateway start. A failed logging side effect must
     * never take down session bookkeeping or shutdown with it. */
    if (typeof onDisconnect === "function") {
      try {
        onDisconnect(call, at);
      } catch (error) {
        // Swallowed deliberately -- see the comment above. This module has no logger to
        // report it to, and the call itself is already correctly recorded in
        // session.calls above regardless of whether the caller's side effect succeeded.
      }
    }
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
    session_id: session.sessionId || null,
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
  recordAnomaly,
  recordUnmatchedResponseAnomaly,
  MAX_ANOMALIES_PER_SESSION,
  markPendingAsDisconnected,
  toSealableSession,
  finalizeSession,
};
