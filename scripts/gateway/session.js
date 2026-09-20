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
    /* Per docs/contracts/wal-append-failure-semantics.md (C1 SS2): the moment an
     * appendWalEvent call fails for this connection, this is set to {reason, at} and
     * every later append attempt on the same connection must be refused before it
     * touches the filesystem -- a torn line from the first failure could otherwise be
     * concatenated onto by a second attempt (see the contract doc). In-memory only,
     * connection-scoped, never written to the sealed bundle (toSealableSession below
     * does not include it) or the WAL itself; a fresh connection/session always starts
     * with this null. Not read or written anywhere in this file -- callers (gateway.js's
     * forwardDownstreamRequestToAgent, and every appendWalEvent call site in proxy.js as
     * of the round-2 fix pass closing commit 5's enforcement gap) set and check it
     * directly on the session record, the same way they already read/write
     * pendingCalls/calls. */
    walPoisoned: null,
    /* Re-triage fix: running total of retained call payload bytes (request params +
     * response result, serialized -- see proxy.js's MAX_SESSION_CALL_BYTES for why),
     * updated alongside session.calls in recordCallResult/markPendingAsDisconnected. */
    totalCallBytes: 0,
    /* Codex PR #29 review "treat sampling as a negotiated client capability" (comment
     * 4000335132): whether this connection negotiated the sampling capability (set by
     * GatewayProxy#openConnection from gateway.js's own agentTransportSupportsSampling).
     * Carried through toSealableSession below so sealBoundaryBundle (gsa-mcp-shim.js) can
     * grant a model_call entry by this fact instead of checking sampling/createMessage
     * against the downstream tools/list surface, which was never meant to cover it. */
    samplingNegotiated: Boolean(options.samplingNegotiated),
  };
}

/** Serialized byte size of a JSON-RPC-safe value (request params or a call result),
 * matching downstream.js's own MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES style
 * (Buffer.byteLength(JSON.stringify(...))). `value` always originated from a JSON-parsed
 * wire message, so JSON.stringify cannot throw here -- the `|| ""` guard only covers the
 * `undefined` case (e.g. an argument-less call), where JSON.stringify itself returns
 * `undefined` rather than a string. */
function payloadByteSize(value) {
  return Buffer.byteLength(JSON.stringify(value) || "");
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
  const callResult = result ? result.result : undefined;
  session.calls.push({
    tool: pending.tool,
    server: pending.server,
    arguments: pending.arguments,
    result: callResult,
    isError: Boolean(result && result.isError),
    /* PR #29 review thread 4000335147, frontier-panel review (4/4 converged) "flag
     * structurally malformed tools/call results distinctly from tool-level errors":
     * `malformedResult` is the caller's (proxy.js) own pure, `tools/call`-only,
     * transport-success-only judgement (see isMalformedToolCallResult) of whether
     * `callResult` itself is even a recognizable CallToolResult shape -- this module
     * stores it verbatim, exactly like `isError`, and does not itself compute or
     * re-derive it (this module has no opinion on MCP result shapes, by design -- see
     * this file's header). Always Boolean-coerced so an absent field (every non-
     * tools/call caller, e.g. a sampling/createMessage result) stores a plain `false`,
     * never `undefined`, keeping this an audit-only annotation that never needs a
     * caller to opt in. */
    malformedResult: Boolean(result && result.malformedResult),
    model_call: pending.model_call,
    ts: pending.ts,
    seq: pending.seq,
    /* Codex PR #33 review "persist cached replays in the session trace": an OPTIONAL,
     * additive marker (absent on every ordinary call, exactly like `disconnected` above)
     * letting proxy.js record an idempotency-key cache hit as a real, ordered step that
     * is nonetheless not claimed to be a fresh downstream dispatch. Only the caller can
     * know this -- session.js never decides it -- so it is passed in rather than derived,
     * and toSealableSession spreads it conditionally the same way it already spreads the
     * disconnect fields, so no ordinary session's sealed shape (or bundle_id) changes. */
    ...(result && result.replayed
      ? { replayed: true, replayed_from_intent_key: result.replayedFromIntentKey || null }
      : {}),
  });
  /* Re-triage fix: MAX_SESSION_CALL_BYTES (proxy.js) needs a running total of what this
   * session has actually retained -- see payloadByteSize's own comment above. */
  session.totalCallBytes += payloadByteSize(pending.arguments) + payloadByteSize(callResult);
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
    /* Re-triage fix: a disconnected call still retains its request params in
     * session.calls (its result is always null) -- count it the same as an ordinarily
     * completed call so the byte cap cannot be bypassed via repeated disconnects. */
    session.totalCallBytes += payloadByteSize(call.arguments);
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
      /* Additive, backward-compatible field (see recordCallResult's own comment above
       * and gsa-mcp-shim.js's sealBoundaryBundle, which folds this into the signed
       * `malformed_result` trace field ONLY when true -- a well-formed call's trace line
       * is unaffected). Carried through unconditionally here (like isError/model_call)
       * because it is now part of every call's base recorded shape, not an optional
       * extra like disconnected/jsonRpcId below. */
      malformedResult: c.malformedResult,
      model_call: c.model_call,
      ts: c.ts,
      ...(c.disconnected ? { disconnected: true, disconnect_reason: c.disconnect_reason, jsonRpcId: c.jsonRpcId } : {}),
      ...(c.replayed ? { replayed: true, replayed_from_intent_key: c.replayed_from_intent_key } : {}),
    })),
    goal: session.goal,
    anomalies: session.anomalies,
    samplingNegotiated: Boolean(session.samplingNegotiated),
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
