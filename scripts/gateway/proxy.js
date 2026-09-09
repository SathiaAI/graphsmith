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

const session = require("./session.js");
const chain = require("./chain.js");
const recovery = require("./recovery.js");

function fail(message, code = "GATEWAY_PROXY_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
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
    /* Codex PR #29 Finding 1 (Option C, external-panel-reviewed design -- see
     * option-c-hardened-design.md): crash-recovery WAL, recorded from the very start of
     * the connection so a crash before any tool call still leaves a durable record of
     * the granted tool surface and goal. Separate, unsigned, outside the hash chain --
     * see recovery.js's own header for why this makes zero changes to session.js's own
     * call-recording functions or to sealBoundaryBundle. */
    recovery.appendWalEvent(this.stateDir, connectionId, {
      type: "SESSION_START",
      started_at: s.startedAt,
      goal: s.goal || null,
      tools: this.mergedTools.map((t) => ({ name: t.name, server: t.server, schema: t.schema })),
    });
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
    const { method, params, id } = msg;
    const isNotification = id === undefined;

    /* SS3.7/SS7: once the writer-claim is lost, stop admitting NEW work on every
     * connection, not just new connections (openConnection already refuses those) --
     * otherwise an already-open agent connection could keep issuing calls indefinitely
     * after a replacement writer has acquired the state directory, risking concurrent
     * chain-append corruption. A call already in flight (already past this point in an
     * earlier handleMessage invocation, already awaiting its downstream response) is
     * unaffected and is allowed to drain normally -- only messages that arrive AFTER the
     * flag flips are refused. */
    if (!this.acceptingNewSessions) {
      if (isNotification) return null;
      return { jsonrpc: "2.0", id, error: { code: -32000, message: "Gateway is draining (writer-claim lost or shutting down): not accepting new requests on this connection." } };
    }

    if (method === "notifications/cancelled") {
      /* SS3.3: downstream calls run under a gateway-internal id, not the agent's own
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
      recovery.appendWalEvent(this.stateDir, connectionId, {
        type: "INITIALIZE",
        clientInfo: params && params.clientInfo,
        serverInfo: mergedServerInfo,
        model: params && params.model,
      });
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
      const conn = method === "tools/call" ? this.connections.get(serverName) : this.connections.values().next().value;
      const callArgs = method === "tools/call" ? (params && params.arguments) : params;

      /* Codex PR #29 Finding 2 (Option C, external-panel-reviewed design -- see
       * option-c-hardened-design.md): a durable idempotency fence for real tools/call
       * dispatch, keyed by (connectionId, tool, canonicalized arguments) so a retry
       * under a NEW JSON-RPC id is still recognized as the same logical operation.
       * Deliberately scoped to real tools/call only -- the isModelCallMethod branch
       * (an agent sending "sampling/createMessage" into this dispatcher, a different
       * case from gateway.js's own downstream-initiated sampling forward) is out of
       * scope for this fix; see the design doc's disclosed limitations. */
      let intentKey = null;
      if (method === "tools/call") {
        intentKey = recovery.computeIntentKey(connectionId, toolName, callArgs);
        let intentDecision = null;
        for (let attempt = 0; attempt < 2 && !intentDecision; attempt++) {
          const existing = recovery.readIntent(this.stateDir, intentKey);
          if (existing && existing.state === "completed") {
            intentDecision = { kind: "replay", cachedResult: existing.cached_result };
          } else if (existing && existing.state === "dispatched") {
            intentDecision = {
              kind: "block",
              code: -32080,
              gatewayCode: "GATEWAY_AMBIGUOUS_RETRY",
              message: "A prior attempt of this exact operation is still in flight -- dispatch halted to avoid a duplicate side effect.",
            };
          } else if (existing && existing.state === "ambiguous") {
            intentDecision = {
              kind: "block",
              code: -32081,
              gatewayCode: "GATEWAY_DOWNSTREAM_OUTCOME_UNKNOWN",
              message: "A prior attempt of this exact operation did not reach a confirmed successful outcome -- dispatch halted pending operator resolution (see recovery-resolve).",
            };
          } else {
            const created = recovery.createIntentIfAbsent(this.stateDir, intentKey, {
              connection_id: connectionId,
              tool: toolName,
              arguments: callArgs,
              state: "dispatched",
              dispatched_at: this.now(),
            });
            if (created) intentDecision = { kind: "dispatch" };
            // else: lost a race to a concurrent identical call on this connection --
            // loop once to re-read its freshly-created state and respond consistently.
          }
        }
        if (!intentDecision) {
          // Two races back to back is vanishingly unlikely; fail closed rather than loop
          // forever or risk a double dispatch on an assumption.
          intentDecision = {
            kind: "block",
            code: -32080,
            gatewayCode: "GATEWAY_AMBIGUOUS_RETRY",
            message: "Could not establish a durable dispatch intent for this operation -- halted rather than risk a duplicate side effect.",
          };
        }
        if (intentDecision.kind === "replay") {
          if (isNotification) return null;
          /* Codex PR #33 review "emit complete step logs for replayed and blocked
           * calls": this used to emit only the special-purpose gateway_intent_replayed
           * line, missing the step/status/duration fields every other handled call gets
           * via gateway_call_completed below -- an operator scanning for one
           * consistently-shaped log line per call would miss this one. Emit both: the
           * existing event (kept for any consumer already matching on it) and a normal
           * structured completion record. */
          this.log(JSON.stringify({ event: "gateway_intent_replayed", connection_id: connectionId, tool: toolName, intent_key: intentKey }));
          this.log(JSON.stringify({ event: "gateway_call_completed", connection_id: connectionId, step: null, tool: toolName, server: serverName, status: "replayed", duration_ms: 0 }));
          return { jsonrpc: "2.0", id, result: intentDecision.cachedResult };
        }
        if (intentDecision.kind === "block") {
          session.recordAnomaly(s, { kind: intentDecision.gatewayCode, tool: toolName, intent_key: intentKey, detail: intentDecision.message });
          /* Codex PR #33 review "append blocked-retry anomalies to the WAL": the
           * anomaly above is recorded in-memory only -- a crash before this connection's
           * own close would silently drop it from the recovered/sealed bundle, even
           * though the gateway genuinely prevented a duplicate dispatch. Durable WAL
           * event + the matching structured log line (see the replay branch above). */
          recovery.appendWalEvent(this.stateDir, connectionId, { type: "ANOMALY", kind: intentDecision.gatewayCode, tool: toolName, intent_key: intentKey, detail: intentDecision.message, ts: this.now() });
          this.log(JSON.stringify({ event: "gateway_call_completed", connection_id: connectionId, step: null, tool: toolName, server: serverName, status: "blocked", duration_ms: 0 }));
          if (isNotification) return null;
          return {
            jsonrpc: "2.0",
            id,
            error: { code: intentDecision.code, message: intentDecision.message, data: { gateway_code: intentDecision.gatewayCode, intent_key: intentKey, retryable: false } },
          };
        }
        // intentDecision.kind === "dispatch": fall through to the existing dispatch path.
      }

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
      // Captured BEFORE recordCallStart consumes it -- see recovery.js's header on why
      // this already-monotonic per-session counter is exactly the stable, JSON-safe
      // replay identity Option C's WAL needs (a live correlationKey can be a Symbol,
      // which cannot round-trip through the WAL's JSON lines).
      const walCallSeq = s.nextCallSeq;
      session.recordCallStart(s, correlationKey, { tool: toolName, server: method === "tools/call" ? serverName : "sampling", arguments: callArgs, isModelCall: isModelCallMethod(method), ts });
      if (method === "tools/call") {
        /* Codex PR #33 review "undo the fence when CALL_START persistence fails": the
         * intent was already durably created as "dispatched" above (createIntentIfAbsent),
         * before downstream dispatch, before this WAL append -- if THIS fails (e.g. the
         * state volume is full), the call never actually reaches conn.call() below, but
         * without this catch that exception would escape handleMessage entirely (breaking
         * its own documented "never throws for a well-formed envelope" contract) while
         * leaving the intent permanently "dispatched": every identical retry would then be
         * blocked forever as "still in flight" for an operation that in fact never
         * dispatched. Roll back both the intent and the just-added pendingCalls entry, and
         * return a normal, retryable JSON-RPC error instead. */
        try {
          recovery.appendWalEvent(this.stateDir, connectionId, { type: "CALL_START", call_seq: walCallSeq, tool: toolName, server: serverName, arguments: callArgs, ts });
        } catch (walError) {
          s.pendingCalls.delete(correlationKey);
          try { recovery.deleteIntent(this.stateDir, intentKey); } catch (cleanupError) { /* best effort */ }
          session.recordAnomaly(s, { kind: "GATEWAY_RECOVERY_WAL_APPEND_FAILED", tool: toolName, intent_key: intentKey, detail: walError.message });
          if (isNotification) return null;
          return { jsonrpc: "2.0", id, error: { code: -32000, message: `Failed to durably record this call before dispatch: ${walError.message}. Not dispatched -- safe to retry.` } };
        }
      }
      const cancelKey = !isNotification ? `${connectionId}:${JSON.stringify(id)}` : null;
      let result, transportFailed = false, transportErrorCode = null;
      try {
        /* Option C: propagate this call's durable intent key to downstream.js's _meta
         * merge (both transports) so a downstream that itself understands a conventional
         * idempotency key gets genuine at-most-once execution too -- see downstream.js's
         * META_IDEMPOTENCY_KEY header comment. Only ever set for real tools/call dispatch
         * (intentKey is null for the isModelCallMethod branch, matching the dispatch
         * guard above's own "deliberately scoped to tools/call only" decision). */
        result = await conn.call(method, params, undefined, cancelKey
          ? (downstreamId) => this.downstreamCallIds.set(cancelKey, { server: serverName, downstreamId })
          : undefined, intentKey || undefined);
      } catch (error) {
        /* Board decision 2026-09-04, PR #29 review "preserve downstream JSON-RPC error
         * envelopes": downstream.js's connectStdio/connectHttp both already attach the
         * original JSON-RPC error object (code, message, optional data) as `error.
         * rpcError` -- kept here so the response below can propagate it instead of
         * flattening every downstream failure into a generic -32000. */
        result = { error: error.message, code: error.code, rpcError: error.rpcError || null };
        transportFailed = true;
        transportErrorCode = error.code;
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

      /* Codex PR #29 Finding 2 (Option C): resolve the intent based on the outcome. Only
       * a structurally CLEAN success (no transport failure, no tool-level isError)
       * proves the downstream reached a known-good terminal state -- deliberately
       * stricter than treating an explicit downstream error as "safe to retry" (design
       * doc point 7a: a tool can commit a side effect and still report failure).
       * Everything else becomes `ambiguous`, a durable fence only an operator can clear.
       * Runs regardless of `correlatedNow` below: the intent tracks the downstream's
       * real outcome, independent of whether this session is still around to record it
       * (if closeConnection already fenced this same intent as ambiguous while this call
       * was in flight, a later proven outcome correctly resolves it here). */
      if (method === "tools/call") {
        /* Codex PR #33 review "guard the post-dispatch intent update": closeConnection
         * can fence this same intent to "ambiguous" and remove the session WHILE conn.call
         * above is still being awaited; recovery-resolve --confirmed not-executed (now
         * writer-claim-gated, but a live gateway can still be mid-shutdown when its own
         * claim is lost) can also delete it. Either way updateIntent then throws
         * GATEWAY_RECOVERY_INTENT_NOT_FOUND -- previously uncaught, escaping handleMessage
         * entirely and preventing the JSON-RPC response for a call that DID complete.
         * Catch only that specific error and log it; anything else is a real bug and
         * should still surface. */
        try {
          if (!isError) {
            recovery.updateIntent(this.stateDir, intentKey, { state: "completed", completed_at: completedAt, cached_result: result });
          } else {
            recovery.updateIntent(this.stateDir, intentKey, {
              state: "ambiguous",
              ambiguous_at: completedAt,
              ambiguous_reason: transportFailed ? `transport failure: ${transportErrorCode || "unknown"}` : "downstream reported a tool-level error (isError: true)",
            });
          }
        } catch (error) {
          if (error.code !== "GATEWAY_RECOVERY_INTENT_NOT_FOUND") throw error;
          this.log(JSON.stringify({ event: "gateway_intent_update_skipped", connection_id: connectionId, tool: toolName, intent_key: intentKey, reason: "intent no longer exists (concurrently removed by close or an operator resolution)" }));
        }
      }
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
        if (method === "tools/call") {
          recovery.appendWalEvent(this.stateDir, connectionId, { type: "CALL_RESULT", call_seq: walCallSeq, result, isError, ts: completedAt });
        }
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

  /** Called when a downstream connection drops mid-session (SS7): marks only the pending
   * calls actually routed to `reasonServerName` as disconnected, across every open
   * session. A pending call to a DIFFERENT, still-healthy downstream is left alone -- if
   * it later succeeds, the persisted trace must show that real success, not a false
   * "disconnected" error borrowed from an unrelated server's failure. */
  handleDownstreamDisconnect(reasonServerName) {
    for (const s of this.sessions.values()) {
      session.markPendingAsDisconnected(s, `downstream server "${reasonServerName}" disconnected`, this.now, reasonServerName);
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
    if (s.pendingCalls.size > 0) session.markPendingAsDisconnected(s, reason || "connection closed with calls still pending", this.now);
    /* Codex PR #29 Finding 2 (Option C): a "dispatched" intent whose owning connection
     * is closing (agent hung up, or the connection is being force-closed) is exactly
     * Finding 2's ambiguous case -- the downstream may still complete the side effect
     * after this point even though the session itself is ending. Fence it the same way
     * a crash mid-flight would; do not leave it looking permanently "in flight" once
     * nothing is left to receive its response, and do not guess it failed. */
    for (const intent of recovery.listIntentsForConnection(this.stateDir, connectionId)) {
      if (intent.state === "dispatched") {
        recovery.updateIntent(this.stateDir, intent.intent_key, {
          state: "ambiguous",
          ambiguous_at: this.now(),
          ambiguous_reason: reason || "connection closed with this call still in flight",
        });
      }
    }
    this.sessions.delete(connectionId);
    this.agentInitialized.delete(connectionId);
    recovery.appendWalEvent(this.stateDir, connectionId, { type: "CLOSING", reason: reason || null });
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
      this.onSealFailure(s, error);
      return null;
    }
    /* Durably sealed: the WAL's job is done, and any intent that reached a clean
     * "completed" state before close is no longer needed either. An `ambiguous` intent
     * (see above) is NOT cleaned up here -- the fence must survive this session's own
     * lifecycle; only an explicit operator resolution (recovery-resolve) removes one. */
    recovery.deleteWal(this.stateDir, connectionId);
    for (const intent of recovery.listIntentsForConnection(this.stateDir, connectionId)) {
      if (intent.state === "completed") recovery.deleteIntent(this.stateDir, intent.intent_key);
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

module.exports = { GatewayProxy, isModelCallMethod };
