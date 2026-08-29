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
  }

  openConnection(connectionId, options = {}) {
    if (!this.acceptingNewSessions) {
      throw fail("Gateway is no longer accepting new sessions (writer-claim lost or shutting down)", "GATEWAY_NOT_ACCEPTING");
    }
    if (this.sessions.has(connectionId)) throw fail(`connectionId "${connectionId}" is already open`, "GATEWAY_DUPLICATE_CONNECTION");
    const s = session.createSession(connectionId, { now: this.now, goal: options.goal });
    this.sessions.set(connectionId, s);
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

    if (method === "initialize") {
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
      if (isNotification) return null;
      return { jsonrpc: "2.0", id, result: { protocolVersion: (params && params.protocolVersion) || "2025-06-18", capabilities: { tools: {} }, serverInfo: mergedServerInfo } };
    }

    if (method.startsWith("notifications/")) return null;

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
      let result, isError = false;
      try {
        result = await conn.call(method, params);
      } catch (error) {
        result = { error: error.message, code: error.code };
        isError = true;
      }
      session.recordCallResult(s, correlationKey, { result, isError, ts: this.now() });
      if (isNotification) return null;
      return isError
        ? { jsonrpc: "2.0", id, error: { code: -32000, message: typeof result.error === "string" ? result.error : "downstream call failed" } }
        : { jsonrpc: "2.0", id, result };
    }

    if (isNotification) return null;
    return { jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown method: "${method}".` } };
  }

  /** Called when a downstream connection drops mid-session (SS7): marks every call this
   * connection had pending against that (any) downstream as disconnected, rather than
   * silently dropping it. This build treats a downstream loss as affecting every
   * currently-open session uniformly (a real gateway could scope this to only the
   * sessions that actually called the lost server; disclosed as a simplification, not
   * a correctness gap for the case that matters -- no evidence is ever silently lost). */
  handleDownstreamDisconnect(reasonServerName) {
    for (const s of this.sessions.values()) {
      session.markPendingAsDisconnected(s, `downstream server "${reasonServerName}" disconnected`, this.now);
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
