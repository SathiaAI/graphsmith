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
      return { jsonrpc: "2.0", id, result: { tools: this.mergedTools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.schema })) } };
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
      const ts = this.now();
      /* Correlate by an internally-generated marker even for notification-shaped calls
       * (SS3.3's Map-keyed-by-id requirement is about the DOWNSTREAM leg's own id, which
       * downstream.js already manages; here we key the SESSION record by the AGENT's own
       * JSON-RPC id when present, or a synthetic one for a fire-and-forget call). */
      const correlationKey = isNotification ? Symbol(`notify:${toolName}`) : id;
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
    this.sessions.delete(connectionId);
    this.agentInitialized.delete(connectionId);
    let sealed;
    try {
      sealed = session.finalizeSession(s, this.keys);
    } catch (error) {
      this.onSealFailure(s, error);
      return null;
    }
    const entry = chain.appendSession(this.stateDir, sealed);
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
