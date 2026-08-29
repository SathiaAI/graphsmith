#!/usr/bin/env node
/* GraphSmith standalone gateway -- downstream MCP server connections (Standalone
 * Gateway TRD SS3.1/SS3.2).
 *
 * "The downstream-facing side (gateway -> real MCP server) needs its own client-side
 * transport (the existing code is server-side only), matching whatever transport the
 * downstream server(s) actually speak" (SS3.1). This implements a JSON-RPC 2.0 client
 * for the two transports the config schema allows (stdio, http):
 *   - stdio: spawns the configured command, speaks newline-delimited JSON-RPC over its
 *     stdin/stdout -- the same wire framing mcp-server/src/stdioTransport.js implements
 *     server-side, mirrored here client-side (SS3.1: "reuse ... rather than reinventing
 *     wire framing", "the difference is behavioral, not transport-level").
 *   - http: POSTs a JSON-RPC request body to the configured endpoint URL and parses the
 *     JSON response. A plain, generic JSON-RPC-over-HTTP request/response (not the
 *     Streamable-HTTP session/header-mirroring dialect mcp-server/src/httpTransport.js
 *     implements for ITS OWN callers -- that dialect is a property of one specific
 *     server implementation in this repo, not of "HTTP" as a downstream transport in
 *     general, so this client does not assume a downstream server speaks it).
 *
 * Correlation is by JSON-RPC id, generated internally per outgoing request -- a
 * gateway-assigned id, independent of whatever id the agent-facing side used, so a
 * gateway fronting multiple agent connections never collides ids on the downstream leg.
 *
 * Zero-dependency (child_process, readline, http, https, net are all stdlib), Node >= 18.
 */
"use strict";

const { spawn } = require("child_process");
const http = require("http");
const https = require("https");
const readline = require("readline");
const { URL } = require("url");
const crypto = require("crypto");

function fail(message, code = "GATEWAY_DOWNSTREAM_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30000;

/** A downstream connection over stdio: spawns `endpoint` (a shell command line, split on
 * whitespace -- simplest form; a downstream needing shell quoting can wrap itself in a
 * small launcher script) and speaks newline-delimited JSON-RPC over its stdio, matching
 * stdioTransport.js's own framing. */
function connectStdio(endpoint, options = {}) {
  const parts = String(endpoint).trim().split(/\s+/);
  const [command, ...args] = parts;
  const child = spawn(command, args, { stdio: ["pipe", "pipe", options.inheritStderr ? "inherit" : "ignore"] });

  const pending = new Map();
  let nextId = 1;
  let closed = false;
  let closeError = null;
  const notificationHandlers = [];

  const rl = readline.createInterface({ input: child.stdout, terminal: false });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (error) {
      return; // malformed line from downstream: not this client's job to crash on it
    }
    if (msg && Object.prototype.hasOwnProperty.call(msg, "id") && msg.id !== null && pending.has(msg.id)) {
      const { resolve, reject, timer } = pending.get(msg.id);
      clearTimeout(timer);
      pending.delete(msg.id);
      if (msg.error) reject(Object.assign(fail(msg.error.message || "downstream error", "GATEWAY_DOWNSTREAM_RPC_ERROR"), { rpcError: msg.error }));
      else resolve(msg.result);
    } else if (msg && typeof msg.method === "string" && !Object.prototype.hasOwnProperty.call(msg, "id")) {
      for (const handler of notificationHandlers) handler(msg);
    }
    // A response for an unrecognized id, or any other shape, is silently ignored at
    // THIS layer -- the gateway's own session-correlation layer (scripts/gateway/
    // session.js) is where an "unmatched response" anomaly is recorded, keeping this
    // transport client itself a dumb, honest pipe.
  });

  const closedPromise = new Promise((resolve) => {
    child.on("close", (code) => {
      closed = true;
      closeError = fail(`downstream process exited (code ${code})`, "GATEWAY_DOWNSTREAM_DISCONNECTED");
      for (const [, { reject, timer }] of pending.entries()) {
        clearTimeout(timer);
        reject(closeError);
      }
      pending.clear();
      resolve(code);
    });
  });
  child.on("error", (error) => {
    closed = true;
    closeError = fail(`downstream process failed to start: ${error.message}`, "GATEWAY_DOWNSTREAM_DISCONNECTED");
  });

  function call(method, params, timeoutMs) {
    if (closed) return Promise.reject(closeError || fail("downstream connection is closed", "GATEWAY_DOWNSTREAM_DISCONNECTED"));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(fail(`downstream call "${method}" timed out after ${timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS}ms`, "GATEWAY_DOWNSTREAM_TIMEOUT"));
      }, timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS);
      if (typeof timer.unref === "function") timer.unref();
      pending.set(id, { resolve, reject, timer });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  function notify(method, params) {
    if (closed) return;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
  }

  function close() {
    try { child.stdin.end(); } catch (error) { /* best effort */ }
    try { child.kill(); } catch (error) { /* best effort */ }
  }

  return {
    transport: "stdio",
    call,
    notify,
    close,
    onNotification: (handler) => notificationHandlers.push(handler),
    isClosed: () => closed,
    whenClosed: () => closedPromise,
  };
}

/** A downstream connection over plain JSON-RPC-over-HTTP: each call is one POST, one
 * parsed JSON response. There is no persistent "connection" to hold open -- `close()` is
 * a no-op provided for interface symmetry with connectStdio. */
function connectHttp(endpoint, options = {}) {
  const url = new URL(endpoint);
  const client = url.protocol === "https:" ? https : http;
  let nextId = 1;
  let closed = false;
  const notificationHandlers = []; // never fired: plain request/response HTTP has no server push

  function call(method, params, timeoutMs) {
    if (closed) return Promise.reject(fail("downstream connection is closed", "GATEWAY_DOWNSTREAM_DISCONNECTED"));
    const id = nextId++;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve, reject) => {
      const req = client.request(
        url,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body),
            ...(options.headers || {}),
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (chunk) => chunks.push(chunk));
          res.on("end", () => {
            let parsed;
            try {
              parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            } catch (error) {
              reject(fail(`downstream HTTP response was not valid JSON: ${error.message}`, "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"));
              return;
            }
            if (parsed && parsed.error) {
              reject(Object.assign(fail(parsed.error.message || "downstream error", "GATEWAY_DOWNSTREAM_RPC_ERROR"), { rpcError: parsed.error }));
            } else {
              resolve(parsed ? parsed.result : undefined);
            }
          });
        }
      );
      req.on("error", (error) => reject(fail(`downstream HTTP request failed: ${error.message}`, "GATEWAY_DOWNSTREAM_DISCONNECTED")));
      req.setTimeout(timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS, () => req.destroy(fail("downstream HTTP request timed out", "GATEWAY_DOWNSTREAM_TIMEOUT")));
      req.end(body);
    });
  }

  function notify(method, params) {
    // Best-effort, fire-and-forget POST; response (if any) is ignored.
    call(method, params).catch(() => {});
  }

  function close() {
    closed = true;
  }

  return {
    transport: "http",
    call,
    notify,
    close,
    onNotification: (handler) => notificationHandlers.push(handler),
    isClosed: () => closed,
    whenClosed: () => Promise.resolve(null),
  };
}

/** Connects to one configured downstream server per its `transport`. */
function connectDownstream(serverConfig, options) {
  if (serverConfig.transport === "stdio") return connectStdio(serverConfig.endpoint, options);
  if (serverConfig.transport === "http") return connectHttp(serverConfig.endpoint, options);
  throw fail(`Unknown downstream transport "${serverConfig.transport}"`, "INVALID_ARGUMENT");
}

/** Connects to every configured downstream server, running the initialize + tools/list
 * handshake against each (SS3.2). On any connection or handshake failure, closes every
 * connection already opened and rethrows -- SS7's "downstream unreachable at startup:
 * refuse to start" (the hard-refuse resolution this build makes explicitly; see the
 * build report's "TRD ambiguity resolved" section for SS10 OQ-2). */
async function connectAllDownstreams(downstreamServers, options = {}) {
  const connections = new Map();
  const toolOwners = new Map(); // toolName -> serverName (first-registered wins, duplicates flagged)
  const mergedTools = [];
  const serverInfos = {};
  try {
    for (const serverConfig of downstreamServers) {
      let conn;
      try {
        conn = connectDownstream(serverConfig, options);
        const initResult = await conn.call("initialize", { clientInfo: options.clientInfo || { name: "graphsmith-standalone-gateway", version: "1.0" } });
        serverInfos[serverConfig.name] = (initResult && initResult.serverInfo) || null;
        const toolsResult = await conn.call("tools/list", {});
        const tools = (toolsResult && Array.isArray(toolsResult.tools)) ? toolsResult.tools : [];
        for (const tool of tools) {
          const owned = { name: tool.name, server: serverConfig.name, schema: tool.inputSchema || tool.schema || null };
          mergedTools.push(owned);
          if (!toolOwners.has(tool.name)) toolOwners.set(tool.name, serverConfig.name);
        }
      } catch (error) {
        throw fail(
          `Refusing to start: downstream server "${serverConfig.name}" (${serverConfig.transport} ${serverConfig.endpoint}) ` +
            `is unreachable or failed its handshake: ${error.message}`,
          "GATEWAY_DOWNSTREAM_UNREACHABLE"
        );
      }
      connections.set(serverConfig.name, conn);
    }
  } catch (error) {
    for (const conn of connections.values()) {
      try { conn.close(); } catch (closeError) { /* best effort */ }
    }
    throw error;
  }
  return { connections, mergedTools, toolOwners, serverInfos };
}

module.exports = {
  connectStdio,
  connectHttp,
  connectDownstream,
  connectAllDownstreams,
  DEFAULT_REQUEST_TIMEOUT_MS,
};
