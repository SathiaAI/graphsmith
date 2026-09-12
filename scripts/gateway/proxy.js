#!/usr/bin/env node
/* GraphSmith standalone gateway -- proxy/correlation engine (Standalone Gateway TRD
 * SS3.3/SS6). Transport-independent: takes parsed JSON-RPC messages in, returns JSON-RPC
 * responses to send back, and calls out to the downstream connections
 * (scripts/gateway/downstream.js) and the session engine (scripts/gateway/session.js).
 * Kept separate from gateway.js (which owns real stdio/http listeners, process
 * lifecycle, and writer-claim) so this dispatch logic is unit-testable without any real
 * socket or child process.
 *
 * Session-boundary resolution (SS3.4): "connection" -- one session per agent connection,
 * sealed when the agent disconnects. See scripts/gateway/session.js's header for the
 * full rationale; this is the one this build implements.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const session = require("./session.js");
const chain = require("./chain.js");

function fail(message, code = "GATEWAY_PROXY_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

/* Codex PR #29 review round 3 "retain sessions when persistence fails": chain.
 * appendSession can throw on a transient or environmental failure (ENOSPC, EACCES, a
 * one-off filesystem error) well after session.finalizeSession has already produced the
 * fully sealed, signed bundle -- until now, that already-computed `sealed` object was
 * discarded the moment closeConnection's catch block returned null, leaving nothing but
 * onSealFailure's own summary log (call count, pending count) to show a session ever
 * existed. This does not change closeConnection's documented null-on-failure contract or
 * decide retry/halt policy (a genuine architecture question, given every append also
 * upholds the sole-writer chain-sequencing invariant) -- it only keeps the one thing that
 * was about to be lost forever: a best-effort, non-throwing write of the sealed bundle to
 * a quarantine directory an operator can inspect and manually re-append once the
 * underlying failure (e.g. disk full) is resolved. */
function quarantineSealedBundle(stateDir, connectionId, sealed, cause) {
  try {
    const dir = path.join(chain.sessionsDir(stateDir), "quarantine");
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, `${connectionId}-${Date.now()}.json`);
    fs.writeFileSync(target, JSON.stringify({ sealed, quarantined_at: new Date().toISOString(), reason: cause && cause.message }, null, 2), { encoding: "utf8", flag: "wx" });
    return target;
  } catch (quarantineError) {
    // Best effort only: a quarantine-write failure (e.g. the same ENOSPC that caused the
    // original append failure) must never mask or replace the original error/callback.
    return null;
  }
}

/* MCP sampling requests are how a downstream server asks the AGENT'S model to do
 * inference (createMessage) -- SS3.3: "model_call ... is set when the proxied call is
 * itself an MCP sampling request rather than an ordinary tool call ... at the protocol
 * level, not guess from tool names." Recognized by method name, per the MCP spec's
 * sampling capability. */
function isModelCallMethod(method) {
  return method === "sampling/createMessage";
}

/* This build only ever negotiates the one protocol version it actually implements
 * (matching the literal default this file used to echo back unconditionally). Kept as a
 * named constant so "what we claim to speak" and "what we validate against" cannot drift
 * apart independently. */
const GATEWAY_PROTOCOL_VERSION = "2025-06-18";

/* Codex PR #29 review round 5 "cap in-flight calls per agent session": without a bound,
 * one authenticated client (stdio, or one HTTP session) could open arbitrarily many
 * concurrent tools/call or sampling requests -- each retaining session state, a
 * downstream pending entry, and a timer -- without ever waiting for a response. The
 * active-session cap (MAX_HTTP_SESSIONS in agent-transport.js) bounds how many SESSIONS
 * exist; it does nothing to bound growth WITHIN one session. Same "fixed,
 * non-speculative default" discipline as that constant and MAX_TOOLS_LIST_PAGES/
 * MAX_HTTP_RESPONSE_BYTES/MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES in downstream.js -- make it
 * configurable once a real deployment needs a different number, not before. */
const MAX_PENDING_CALLS_PER_SESSION = 1000;

/* Codex PR #29 review "bound completed call history retained by each session":
 * MAX_PENDING_CALLS_PER_SESSION above bounds only calls genuinely IN FLIGHT at once --
 * once a call resolves, session.recordCallResult moves it out of pendingCalls and into
 * session.calls (SS3.3's execution_trace), which has no cap at all. A connection with no
 * enforced lifetime (stdio) or one that keeps resetting its own idle timer (an active
 * HTTP client issuing calls sequentially, never exceeding the pending cap) can therefore
 * grow session.calls -- full arguments and result retained per entry -- without bound
 * until this process exhausts memory, entirely bypassing the pending-call admission
 * check above. Same "fixed, non-speculative default" discipline as that constant. */
const MAX_COMPLETED_CALLS_PER_SESSION = 100000;

class GatewayProxy {
  /**
   * @param {object} opts
   * @param {Map<string, object>} opts.connections serverName -> downstream connection (scripts/gateway/downstream.js)
   * @param {Array<{name,server,schema}>} opts.mergedTools the cached, startup-time tool surface (SS3.2)
   * @param {Map<string,string>} opts.toolOwners toolName -> serverName
   * @param {object} opts.serverInfos serverName -> serverInfo (from startup handshake)
   * @param {object} opts.keys sealBoundaryBundle's signing keys (SS3.5)
   * @param {(connectionId: string, entry: object, sealed: object) => void} [opts.onSessionFinalized]
   * @param {(session: object, error: Error) => void} [opts.onSealFailure] SS7: sealBoundaryBundle throws
   * @param {string} opts.stateDir passed straight to chain.appendSession (SG-FR-5)
   * @param {() => number} [opts.now]
   */
  constructor(opts) {
    this.connections = opts.connections;
    this.mergedTools = opts.mergedTools;
    this.toolOwners = opts.toolOwners;
    this.serverInfos = opts.serverInfos || {};
    this.keys = opts.keys;
    this.onSessionFinalized = opts.onSessionFinalized || (() => {});
    this.onSealFailure = opts.onSealFailure || (() => {});
    this.stateDir = opts.stateDir;
    this.now = opts.now || (() => Date.now());
    this.sessions = new Map(); // connectionId -> in-memory session (scripts/gateway/session.js)
    this.acceptingNewSessions = true; // SS3.7/SS7: false once writer-claim is lost
    this.downstreamCallIds = new Map(); // `${connectionId}:${agentJsonRpcId}` -> { server, downstreamId } (SS3.3 cancellation)
    /* Per-connection agent-initialization lifecycle (board decision 2026-09-04, PR #29
     * review "enforce the agent initialization lifecycle"): tracked here rather than on
     * the session.js record itself, since it is purely a dispatch-gating concern of this
     * proxy, not part of the sealed session's own attested shape. */
    this.agentInitialized = new Map(); // connectionId -> boolean
    /* Optional structured per-call log sink (board decision 2026-09-04, PR #29 review
     * "emit the required structured log for each call") -- defaults to a no-op so unit
     * tests that construct a GatewayProxy directly (no logging concern of their own)
     * stay silent, mirroring onSessionFinalized/onSealFailure's own default-no-op
     * contract above. */
    this.log = typeof opts.log === "function" ? opts.log : (() => {});
  }

  openConnection(connectionId, options = {}) {
    if (!this.acceptingNewSessions) {
      throw fail("Gateway is no longer accepting new sessions (writer-claim lost or shutting down)", "GATEWAY_NOT_ACCEPTING");
    }
    if (this.sessions.has(connectionId)) throw fail(`connectionId "${connectionId}" is already open`, "GATEWAY_DUPLICATE_CONNECTION");
    const s = session.createSession(connectionId, { now: this.now, goal: options.goal });
    /* SS3.3: the granted tool surface must be recorded regardless of whether the agent
     * ever bothers to issue tools/list on this connection -- otherwise a cached tool
     * invoked without a prior tools/list would be sealed with an empty granted surface,
     * making sealBoundaryBundle's granted-tool check falsely report "not granted" for a
     * call the gateway legitimately authorized. The (idempotent) tools/list handler below
     * simply re-records the same surface if the agent does ask. */
    session.recordToolsList(s, this.mergedTools);
    this.sessions.set(connectionId, s);
    this.agentInitialized.set(connectionId, false);
    return s;
  }

  /** Dispatches one JSON-RPC request/notification from an agent on `connectionId`.
   * Returns the JSON-RPC response object to send back, or null for a notification /
   * a message the agent must not receive a reply to. Never throws for a well-formed
   * JSON-RPC envelope -- protocol-shaped errors come back as JSON-RPC error objects. */
  async handleMessage(connectionId, msg) {
    const s = this.sessions.get(connectionId);
    if (!s) throw fail(`No open session for connectionId "${connectionId}"`, "GATEWAY_UNKNOWN_CONNECTION");
    if (!msg || typeof msg !== "object" || Array.isArray(msg) || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
      return { jsonrpc: "2.0", id: msg && typeof msg === "object" && !Array.isArray(msg) ? msg.id : null, error: { code: -32600, message: "Malformed JSON-RPC 2.0 request envelope." } };
    }
    /* Codex PR #29 review round 6 "reject invalid JSON-RPC identifier types": JSON-RPC
     * 2.0 restricts "id" to a string, a number, or null (a request with no "id" at all is
     * a notification, handled via isNotification below) -- this check previously accepted
     * any other type (boolean, object, array) since it only ever compared id to
     * `undefined`. For "tools/call" that let a malformed id reach dispatch, execute a real
     * downstream side effect, and come back in a response/correlation record no
     * spec-conforming caller could use. Reject before computing isNotification/dispatch;
     * the offending id is never echoed back since its type is exactly what is invalid. */
    /* CodeRabbit PR #29 review round 7 "reject numeric identifiers outside the
     * safe-integer range": handleMessage uses a numeric id both as a pendingCalls Map key
     * and (serialized) as a downstream correlation id -- JS numbers cannot distinguish
     * some adjacent JSON integers once they exceed Number.MAX_SAFE_INTEGER (or are
     * non-finite), so two distinct requests could collide on the same correlation key.
     * The round-6 fix above only ruled out non-string/non-number/non-null types, not an
     * out-of-safe-range or non-finite number. */
    const invalidNumericId = typeof msg.id === "number" && (!Number.isFinite(msg.id) || !Number.isSafeInteger(msg.id));
    const invalidIdType = msg.id !== undefined && msg.id !== null && typeof msg.id !== "string" && typeof msg.id !== "number";
    if (invalidIdType || invalidNumericId) {
      return { jsonrpc: "2.0", id: null, error: { code: -32600, message: `Invalid JSON-RPC "id": must be a string, a finite safe-integer number, or null (or omitted for a notification).` } };
    }
    const { method, params, id } = msg;
    const isNotification = id === undefined;

    if (method === "notifications/cancelled") {
      /* Codex PR #29 review round 5 "continue processing cancellations while draining":
       * this must run BEFORE the acceptingNewSessions gate below, not after -- a
       * cancellation notification for an already-in-flight call is not "new work" the
       * drain is refusing to admit, it is how an agent asks the gateway to stop existing
       * work SOONER. Gating it behind acceptingNewSessions silently dropped every
       * cancellation once shutdown began, so an agent's cancel request during drain could
       * never reach conn.cancel() and the gateway would wait out the full drain deadline
       * even though the agent had already asked to stop the call.
       *
       * SS3.3: downstream calls run under a gateway-internal id, not the agent's own
       * JSON-RPC id, so a bare pass-through of the cancellation payload would target the
       * wrong id on the downstream leg (or no id at all, for a downstream that happens to
       * reuse numbering). Translate via the mapping recorded when the call started. */
      const targetRequestId = params && params.requestId;
      const key = `${connectionId}:${JSON.stringify(targetRequestId)}`;
      const mapping = this.downstreamCallIds.get(key);
      if (mapping) {
        const conn = this.connections.get(mapping.server);
        if (conn && typeof conn.cancel === "function") {
          try { conn.cancel(mapping.downstreamId); } catch (error) { /* best effort */ }
        }
      }
      return null;
    }

    /* SS3.7/SS7: once the writer-claim is lost, stop admitting NEW work on every
     * connection, not just new connections (openConnection already refuses those) --
     * otherwise an already-open agent connection could keep issuing calls indefinitely
     * after a replacement writer has acquired the state directory, risking concurrent
     * chain-append corruption. A call already in flight (already past this point in an
     * earlier handleMessage invocation, already awaiting its downstream response) is
     * unaffected and is allowed to drain normally -- only messages that arrive AFTER the
     * flag flips are refused. notifications/cancelled is exempted above: it never admits
     * new work, only stops existing work sooner. */
    if (!this.acceptingNewSessions) {
      if (isNotification) return null;
      return { jsonrpc: "2.0", id, error: { code: -32000, message: "Gateway is draining (writer-claim lost or shutting down): not accepting new requests on this connection." } };
    }

    if (method === "initialize") {
      /* Board decision 2026-09-04, PR #29 review "enforce the agent initialization
       * lifecycle": a second initialize on an already-initialized connection would
       * silently overwrite the metadata already attached to calls made under the first
       * one (session.recordInitialize below just replaces the recorded clientInfo/
       * serverInfo/model), producing a sealed trace whose initialize record no longer
       * matches what was actually true when those earlier calls ran. Reject it instead. */
      if (this.agentInitialized.get(connectionId)) {
        if (isNotification) return null;
        return { jsonrpc: "2.0", id, error: { code: -32600, message: "This connection has already completed \"initialize\" -- a repeated initialize is not permitted." } };
      }
      /* SS3.2/SS6: the downstream handshake already ran once at gateway startup; this
       * records the AGENT's own clientInfo alongside the already-cached downstream
       * serverInfo (merged: single server's info verbatim, or a composite name when
       * more than one downstream is configured, so session.initialize never silently
       * picks just one of several fronted servers). */
      const serverNames = Object.keys(this.serverInfos);
      const mergedServerInfo = serverNames.length === 1
        ? this.serverInfos[serverNames[0]]
        : { name: "graphsmith-standalone-gateway(" + serverNames.join("+") + ")", version: "1.0", fronted: this.serverInfos };
      session.recordInitialize(s, {
        clientInfo: params && params.clientInfo,
        serverInfo: mergedServerInfo,
        model: params && params.model,
      });
      this.agentInitialized.set(connectionId, true);
      if (isNotification) return null;
      /* This gateway implements exactly one protocol version (GATEWAY_PROTOCOL_VERSION);
       * echoing back whatever the agent asked for (SS3.3) would let a client believe
       * initialization succeeded under a contract this build does not actually implement,
       * causing later requests to be misinterpreted per the client's own (wrong)
       * assumption. Always return the version actually selected, never the request. */
      return { jsonrpc: "2.0", id, result: { protocolVersion: GATEWAY_PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: mergedServerInfo } };
    }

    if (method.startsWith("notifications/")) return null;

    /* Board decision 2026-09-04, PR #29 review "enforce the agent initialization
     * lifecycle": without this gate, an agent could list or invoke tools under an empty
     * initialization record (no clientInfo/serverInfo ever attested for that session),
     * which sealBoundaryBundle would then attest as if it were a normal, complete
     * session. Gates only the two AGENT-initiated methods this applies to -- a
     * downstream-pushed sampling/createMessage is not agent-initiated and is unaffected. */
    if ((method === "tools/list" || method === "tools/call") && !this.agentInitialized.get(connectionId)) {
      if (isNotification) return null;
      return { jsonrpc: "2.0", id, error: { code: -32600, message: `Cannot call "${method}" before this connection has completed "initialize".` } };
    }

    if (method === "tools/list") {
      session.recordToolsList(s, this.mergedTools);
      if (isNotification) return null;
      /* Codex PR #29 review "forward the full cached tool descriptor": downstream.js's
       * connectAllDownstreams already preserves each tool's complete descriptor
       * (description, outputSchema, annotations, title, etc. -- see its own comment
       * "Preserve the tool's full descriptor ... rather than keeping only name+schema")
       * onto `t`, alongside two gateway-private bookkeeping fields it adds: `server`
       * (tool ownership, internal routing only) and `schema` (an internal alias of
       * `inputSchema` session.js/this dispatch code reads). Projecting down to just
       * {name, description, inputSchema} here discarded everything else the downstream
       * actually advertised, handing the agent a narrower tool contract than the
       * downstream provides -- e.g. no outputSchema for a client that validates
       * structured results against it. Strip only the two gateway-private fields; forward
       * the rest of the real descriptor (including the original `inputSchema`) verbatim. */
      return { jsonrpc: "2.0", id, result: { tools: this.mergedTools.map((t) => { const { server, schema, ...descriptor } = t; return descriptor; }) } };
    }

    if (method === "tools/call" || isModelCallMethod(method)) {
      const toolName = method === "tools/call" ? params && params.name : "sampling/createMessage";
      const serverName = method === "tools/call" ? this.toolOwners.get(toolName) : (params && params.server);
      if (method === "tools/call" && !serverName) {
        const error = { code: -32602, message: `Unknown tool "${String(toolName)}" -- not present in this gateway's granted tool surface.` };
        if (isNotification) return null;
        return { jsonrpc: "2.0", id, error };
      }
      /* Codex PR #29 review round 5 "cap in-flight calls per agent session": refuse
       * admitting another concurrent call once this session already has
       * MAX_PENDING_CALLS_PER_SESSION genuinely pending, rather than let one session's
       * own pending-call bookkeeping (and the downstream timers/sockets each entry
       * retains) grow without bound. */
      if (s.pendingCalls.size >= MAX_PENDING_CALLS_PER_SESSION) {
        const error = { code: -32000, message: `This session already has ${MAX_PENDING_CALLS_PER_SESSION} call(s) pending -- refusing to admit another concurrent call until at least one resolves.` };
        if (isNotification) return null;
        return { jsonrpc: "2.0", id, error };
      }
      /* Codex PR #29 review "bound completed call history retained by each session": a
       * client issuing calls one at a time (never tripping the pending-call cap above)
       * can still grow this session's completed-call history without bound over the
       * connection's lifetime. Refuse admission the same way the pending-call cap does --
       * the client must end this session and start a new one -- rather than let one
       * long-lived connection's retained history grow unbounded. */
      if (s.calls.length >= MAX_COMPLETED_CALLS_PER_SESSION) {
        const error = { code: -32000, message: `This session has already completed ${MAX_COMPLETED_CALLS_PER_SESSION} call(s) -- refusing to admit another call on this connection; start a new session.` };
        if (isNotification) return null;
        return { jsonrpc: "2.0", id, error };
      }
      const conn = method === "tools/call" ? this.connections.get(serverName) : this.connections.values().next().value;
      const callArgs = method === "tools/call" ? (params && params.arguments) : params;
      const ts = this.now();
      /* Correlate by an internally-generated marker even for notification-shaped calls
       * (SS3.3's Map-keyed-by-id requirement is about the DOWNSTREAM leg's own id, which
       * downstream.js already manages; here we key the SESSION record by the AGENT's own
       * JSON-RPC id when present, or a synthetic one for a fire-and-forget call). */
      /* Codex PR #29 review "handle JSON-RPC null IDs before recording calls": JSON-RPC
       * 2.0 permits an explicit `id: null` on a REQUEST (distinct from a notification,
       * which omits the id key entirely) -- `isNotification` above only catches the
       * latter. Using `id` (null) directly as this call's correlation key made it into
       * session.recordCallStart's Map key, which explicitly throws INVALID_ARGUMENT on a
       * null/undefined key -- turning a legal-if-unusual request into an uncaught
       * internal error instead of a normal response. A null id still gets a real
       * response below (the outer `id` variable, unchanged, is echoed back as JSON-RPC
       * requires) -- only the internal bookkeeping key needs to never be null. */
      const correlationKey = isNotification || id === null ? Symbol(`${isNotification ? "notify" : "null-id"}:${toolName}`) : id;
      session.recordCallStart(s, correlationKey, { tool: toolName, server: method === "tools/call" ? serverName : "sampling", arguments: callArgs, isModelCall: isModelCallMethod(method), ts });
      const cancelKey = !isNotification ? `${connectionId}:${JSON.stringify(id)}` : null;
      let result, transportFailed = false;
      try {
        result = await conn.call(method, params, undefined, cancelKey
          ? (downstreamId) => this.downstreamCallIds.set(cancelKey, { server: serverName, downstreamId })
          : undefined);
      } catch (error) {
        /* Board decision 2026-09-04, PR #29 review "preserve downstream JSON-RPC error
         * envelopes": downstream.js's connectStdio/connectHttp both already attach the
         * original JSON-RPC error object (code, message, optional data) as `error.
         * rpcError` -- kept here so the response below can propagate it instead of
         * flattening every downstream failure into a generic -32000. */
        result = { error: error.message, code: error.code, rpcError: error.rpcError || null };
        transportFailed = true;
      } finally {
        if (cancelKey) this.downstreamCallIds.delete(cancelKey);
      }
      /* Board decision 2026-09-04, PR #29 review "honor MCP tool-level error results":
       * a `tools/call` result can be a structurally successful, well-transported MCP
       * response that nonetheless carries `isError: true` on the result itself (the MCP
       * spec's own way for a TOOL's execution to fail, distinct from a transport/RPC
       * failure). That must be reflected in the SESSION record (sealed trace, output
       * manifest) -- but per MCP semantics a tool-level error is still a normal
       * `tools/call` RESULT, not a JSON-RPC protocol error, so the response sent back to
       * the agent below is still keyed on `transportFailed` alone, unchanged. */
      const toolLevelError = !transportFailed && method === "tools/call" && result && typeof result === "object" && result.isError === true;
      const isError = transportFailed || toolLevelError;
      const completedAt = this.now();
      /* CodeRabbit PR #29 review "recording the result after the session is closed can
       * throw or write a false anomaly": closeConnection()/handleDownstreamDisconnect()
       * can run for this same connectionId WHILE conn.call() above is still being
       * awaited (both call session.markPendingAsDisconnected, which removes the pending
       * entry). If that happened, this call's correlationKey is no longer a real pending
       * call by the time the response lands: recording it anyway would either throw
       * SESSION_FINALIZED (if the session already finished finalizing -- escaping
       * handleMessage's own "never throws for a well-formed envelope" contract) or push a
       * spurious UNMATCHED_RESPONSE anomaly (if not yet finalized) for an entry the
       * gateway itself removed, not a real downstream protocol violation. Only record
       * (and log) when the call is still genuinely pending. */
      const correlatedNow = !s.finalized && s.pendingCalls.has(correlationKey);
      if (correlatedNow) {
        session.recordCallResult(s, correlationKey, { result, isError, ts: completedAt });
        /* Board decision 2026-09-04, PR #29 review "emit the required structured log for
         * each call": the only prior gateway log for a call was the session-finalize log
         * emitted much later (or never, if the process crashes first) -- this gives every
         * completed call its own operational line, regardless of how the session ends. */
        const recordedCall = s.calls[s.calls.length - 1];
        this.log(JSON.stringify({
          event: "gateway_call_completed",
          connection_id: connectionId,
          step: recordedCall ? recordedCall.seq : null,
          tool: toolName,
          server: method === "tools/call" ? serverName : "sampling",
          status: isError ? "error" : "ok",
          duration_ms: completedAt - ts,
        }));
      }
      if (isNotification) return null;
      if (transportFailed) {
        const rpcError = result.rpcError;
        return {
          jsonrpc: "2.0",
          id,
          error: rpcError && typeof rpcError === "object" && typeof rpcError.code === "number"
            ? { code: rpcError.code, message: rpcError.message || "downstream call failed", ...(rpcError.data !== undefined ? { data: rpcError.data } : {}) }
            : { code: -32000, message: typeof result.error === "string" ? result.error : "downstream call failed" },
        };
      }
      return { jsonrpc: "2.0", id, result };
    }

    if (isNotification) return null;
    return { jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown method: "${method}".` } };
  }

  /** Codex PR #29 review round 4 "log calls finalized as disconnected": every OTHER path
   * that finishes a call (GatewayProxy#handleMessage's own completion above) emits a
   * structured "gateway_call_completed" log line for it; a call finalized instead via
   * session.markPendingAsDisconnected got no such line from anywhere -- handleMessage
   * can't log it later because the pending entry is already gone by the time its own
   * response (if any) arrives. Shared by both call sites below so the log shape stays
   * identical to handleMessage's own. */
  logDisconnectedCall(connectionId, call, at) {
    this.log(JSON.stringify({
      event: "gateway_call_completed",
      connection_id: connectionId,
      step: call.seq,
      tool: call.tool,
      server: call.server,
      status: "disconnected",
      duration_ms: at - call.ts,
    }));
  }

  /** Called when a downstream connection drops mid-session (SS7): marks only the pending
   * calls actually routed to `reasonServerName` as disconnected, across every open
   * session. A pending call to a DIFFERENT, still-healthy downstream is left alone -- if
   * it later succeeds, the persisted trace must show that real success, not a false
   * "disconnected" error borrowed from an unrelated server's failure. */
  handleDownstreamDisconnect(reasonServerName) {
    for (const s of this.sessions.values()) {
      session.markPendingAsDisconnected(
        s,
        `downstream server "${reasonServerName}" disconnected`,
        this.now,
        reasonServerName,
        (call, at) => this.logDisconnectedCall(s.connectionId, call, at)
      );
    }
  }

  /** Finalizes and persists one connection's session (SS3.4/SS3.5/SS6 steps 8-10).
   * Any pending calls are first marked disconnected (SS7: "any of that connection's
   * in-flight calls that never get a response must be recorded ... never silently
   * dropped") -- covers both a genuine downstream disconnect and an agent that hangs up
   * mid-call. Returns the appended chain entry, or null if sealing/persistence failed
   * (already reported via onSealFailure). */
  async closeConnection(connectionId, reason) {
    const s = this.sessions.get(connectionId);
    if (!s) return null;
    if (s.pendingCalls.size > 0) {
      session.markPendingAsDisconnected(
        s,
        reason || "connection closed with calls still pending",
        this.now,
        undefined,
        (call, at) => this.logDisconnectedCall(connectionId, call, at)
      );
    }
    this.sessions.delete(connectionId);
    this.agentInitialized.delete(connectionId);
    let sealed;
    try {
      sealed = session.finalizeSession(s, this.keys);
    } catch (error) {
      this.onSealFailure(s, error);
      return null;
    }
    /* CodeRabbit PR #29 review "chain.appendSession is not guarded, so a persistence
     * failure aborts shutdown and leaks the writer-claim": the doc comment above this
     * method says closeConnection returns null "if sealing/persistence failed", but only
     * session.finalizeSession was ever inside a try/catch -- chain.appendSession can
     * throw GATEWAY_BUNDLE_ID_COLLISION (sealBoundaryBundle derives bundle_id from
     * {init, grantedTools, n} alone, so the same agent reconnecting with identical
     * clientInfo and call count reproduces it) or on any filesystem error. Uncaught, that
     * throw escapes closeConnection entirely -- inside gateway.js's stop()/doStop()
     * finalize loop this would abort the remaining sessions' finalization, skip every
     * downstream conn.close(), and skip writerClaim.release(), leaking a stale claim that
     * blocks the next gateway start. Route it through the same onSealFailure/return-null
     * contract as a sealing failure so the documented behavior actually holds. */
    let entry;
    try {
      entry = chain.appendSession(this.stateDir, sealed);
    } catch (error) {
      error.quarantinedTo = quarantineSealedBundle(this.stateDir, connectionId, sealed, error);
      this.onSealFailure(s, error);
      return null;
    }
    this.onSessionFinalized(connectionId, entry, sealed);
    return entry;
  }

  /** SS3.7: stop admitting new sessions (writer-claim lost, or graceful shutdown
   * draining). Already-open sessions are unaffected and may still be closed normally. */
  stopAcceptingNewSessions() {
    this.acceptingNewSessions = false;
  }

  openSessionCount() {
    return this.sessions.size;
  }
}

module.exports = { GatewayProxy, isModelCallMethod, MAX_PENDING_CALLS_PER_SESSION, MAX_COMPLETED_CALLS_PER_SESSION };
