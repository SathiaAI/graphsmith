#!/usr/bin/env node
/* GraphSmith standalone gateway -- agent-facing transports (Standalone Gateway TRD
 * SS3.1). Extracted out of gateway.js (which owns process lifecycle/writer-claim) to
 * keep that file under this repo's default file-size guideline and because these two
 * runners have no dependency on writer-claim/mode-gate/config -- only on a GatewayProxy.
 *
 * stdio: one process, one connection (mirrors mcp-server/src/stdioTransport.js's own
 * newline-delimited JSON-RPC framing and "stdin closed -> exit cleanly" convention).
 * http: sessions keyed by the underlying TCP socket (`req.socket`), so a keep-alive
 * connection's multiple requests share one session and two concurrent connections
 * (SS8 test 3) get independent sessions with no cross-contamination.
 *
 * **Known, disclosed scope limit (board decision 2026-09-04, PR #29 review "key HTTP
 * sessions by protocol identity"):** this "one TCP socket = one session" identity is
 * deliberate and intentional for `session_boundary: "connection"` (the only boundary
 * this build implements -- "time_window" is rejected at startup, see gateway.js), and
 * it assumes no connection-pooling reverse proxy sits in front of this listener
 * multiplexing distinct agents over one shared backend socket. That assumption is not
 * enforced in code -- it is an operational requirement on how this gateway is deployed,
 * stated here and in KNOWN-LIMITATIONS.md rather than silently relied on. Real
 * session-id-based identity (a client-supplied header/cookie, independent of the
 * socket, with its own lifecycle policy) was deliberately NOT built now -- there is no
 * concrete "time_window" deployment needing it yet (SS3.4 is still unresolved), and
 * building that lifecycle machinery speculatively would be scope creep against a
 * boundary mode that isn't used. Revisit when SS3.4's time_window session boundary is
 * actually designed, or if a pooling-reverse-proxy deployment is planned.
 */
"use strict";

const crypto = require("crypto");
const http = require("http");
const readline = require("readline");
const { isAuthenticated } = require("../../mcp-server/src/auth.js");
const { MAX_BODY_BYTES, REQUEST_TIMEOUT_MS } = require("../../mcp-server/src/httpTransport.js");
const { DEFAULT_REQUEST_TIMEOUT_MS } = require("./downstream.js");

/** Runs the agent-facing stdio transport against `ctx.proxy`. Returns
 * { connectionId, closed, stop, pushRequest } -- `closed` resolves once the session has
 * already been finalized (the caller does not need to call closeConnection itself).
 *
 * `pushRequest(method, params, timeoutMs)` lets the gateway send the agent a request IT
 * did not ask for and get back a promise for the agent's reply -- e.g. forwarding a
 * downstream server's own `sampling/createMessage` request up to this agent's model
 * (board decision 2026-09-04, PR #29 review "forward downstream sampling requests
 * upstream"). This is deliberately stdio-only: stdio can write to the agent at any time,
 * while the HTTP agent transport below is plain request/response with no way to push --
 * see runHttpAgentTransport's own header note and gateway.js's wiring, which leaves
 * downstream-initiated requests erroring cleanly (never silently dropped) when the agent
 * transport is HTTP. Pushed-request ids are namespaced ("gw-push-...") so they cannot
 * collide with whatever id scheme the agent itself uses for its own requests, mirroring
 * downstream.js's own "gateway-assigned id, independent of the other leg's ids"
 * convention for the downstream leg. */
function runStdioAgentTransport(ctx) {
  const connectionId = "stdio-" + crypto.randomBytes(8).toString("hex");
  ctx.proxy.openConnection(connectionId);
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  const pendingPushed = new Map(); // gw-push id -> { resolve, reject, timer }

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (error) {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: `Parse error: ${error.message}` } }) + "\n");
      return;
    }
    /* A reply to a request THIS gateway pushed to the agent (has an id matching one this
     * transport itself minted, and no "method" -- a genuine agent-initiated request
     * always has one) -- must NOT go through proxy.handleMessage, which only understands
     * new agent-initiated requests and would otherwise reject this as a malformed
     * envelope. */
    if (msg && typeof msg === "object" && !Array.isArray(msg) && Object.prototype.hasOwnProperty.call(msg, "id") && msg.id !== null && typeof msg.method !== "string" && pendingPushed.has(msg.id)) {
      const { resolve, reject, timer } = pendingPushed.get(msg.id);
      clearTimeout(timer);
      pendingPushed.delete(msg.id);
      if (msg.error) reject(Object.assign(new Error(msg.error.message || "agent returned an error"), { rpcError: msg.error }));
      else resolve(msg.result);
      return;
    }
    ctx.proxy.handleMessage(connectionId, msg).then((response) => {
      if (response !== null) process.stdout.write(JSON.stringify(response) + "\n");
    }).catch((error) => {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32603, message: error.message } }) + "\n");
    });
  });

  function pushRequest(method, params, timeoutMs) {
    const id = "gw-push-" + crypto.randomBytes(8).toString("hex");
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingPushed.delete(id);
        reject(Object.assign(new Error(`agent did not respond to pushed "${method}" within ${timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS}ms`), { code: "GATEWAY_AGENT_PUSH_TIMEOUT" }));
      }, timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS);
      if (typeof timer.unref === "function") timer.unref();
      pendingPushed.set(id, { resolve, reject, timer });
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  const closed = new Promise((resolve) => {
    rl.on("close", async () => {
      // Any request this gateway pushed to the agent and never got a reply for (the
      // agent hung up first) must be rejected now, not left to time out minutes later
      // against a connection that is already gone.
      for (const [id, { reject, timer }] of pendingPushed.entries()) {
        clearTimeout(timer);
        reject(new Error("agent stdio disconnected before responding to a pushed request"));
      }
      pendingPushed.clear();
      await ctx.proxy.closeConnection(connectionId, "agent stdio disconnected");
      resolve();
    });
  });
  return { connectionId, closed, stop: () => rl.close(), pushRequest };
}

/** Runs the agent-facing HTTP transport (config `agent_listen.transport: "http"`).
 * `token` is the already-resolved bearer token (see config.js#resolveSecretRef). */
function runHttpAgentTransport(ctx, listenConfig, token) {
  /* Same hard requirement mcp-server/src/httpTransport.js#createHttpServer already
   * enforces for its own HTTP listener: the config schema itself does not (and cannot,
   * since token_ref is only a reference, not the resolved secret) bound the resolved
   * token's strength, so this is the one place that can actually refuse a
   * trivially-brute-forceable bearer token before binding a network-accessible socket. */
  if (!token || typeof token !== "string" || token.length < 16) {
    throw new Error(
      "graphsmith-gateway: refusing to start the agent-facing HTTP transport without a strong bearer " +
        "token. agent_listen.token_ref must resolve to a value of at least 16 characters -- this is a " +
        "hard requirement for any non-stdio agent transport, not a configurable-away default."
    );
  }
  const socketConnectionIds = new WeakMap();

  function connectionIdFor(socket) {
    if (!socketConnectionIds.has(socket)) {
      const id = "http-" + crypto.randomBytes(8).toString("hex");
      socketConnectionIds.set(socket, id);
      ctx.proxy.openConnection(id);
      socket.on("close", () => {
        ctx.proxy.closeConnection(id, "agent HTTP connection closed").catch(() => {});
      });
    }
    return socketConnectionIds.get(socket);
  }

  const server = http.createServer((req, res) => {
    /* Mirrors mcp-server/src/httpTransport.js#createHttpServer's own contract (that
     * module explicitly returns 405 for non-POST -- see its own comment on this): reject
     * every method but POST before authentication or body processing, so a GET/PUT/etc.
     * intermediaries may treat as safe or replayable can never reach a side-effecting
     * tools/call the way a POST-only endpoint would refuse to let it (board decision
     * 2026-09-04, PR #29 review "reject non-POST requests on the agent HTTP listener"). */
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json", allow: "POST" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Only POST is supported on this endpoint." } }));
      return;
    }
    /* Reuses mcp-server/src/auth.js's already-adversarially-reviewed
     * isAuthenticated() (constant-time comparison via crypto.timingSafeEqual, fail-
     * closed on a missing/malformed header or an unconfigured token) rather than a
     * second, naive `===` string comparison, which would reopen exactly the
     * timing-attack surface that module exists to close. */
    if (!isAuthenticated(req.headers["authorization"], token)) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": "Bearer" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "Unauthenticated." } }));
      return;
    }
    /* Bounds an authenticated (or compromised) agent's request body/duration the same
     * way mcp-server/src/httpTransport.js does for its own listener: an absolute
     * per-request deadline (a slow-trickled body would never trip Node's default
     * inactivity-based server timeout) plus a byte cap enforced by counting real bytes
     * received, not string length (see that module's own header comment on why). Without
     * this, one connection could exhaust memory or stay open indefinitely, including
     * during graceful shutdown's drain. */
    const requestDeadline = setTimeout(() => req.destroy(), REQUEST_TIMEOUT_MS);
    if (typeof requestDeadline.unref === "function") requestDeadline.unref();
    req.on("close", () => clearTimeout(requestDeadline));

    const chunks = [];
    let bytesReceived = 0;
    let tooLarge = false;
    req.on("data", (c) => {
      bytesReceived += c.length;
      if (bytesReceived > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (tooLarge) return; // connection already destroyed, nothing to respond with
      let msg;
      try {
        msg = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch (error) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: `Parse error: ${error.message}` } }));
        return;
      }
      const connectionId = connectionIdFor(req.socket);
      ctx.proxy.handleMessage(connectionId, msg).then((response) => {
        if (response === null) {
          res.writeHead(202);
          res.end();
        } else {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(response));
        }
      }).catch((error) => {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32603, message: error.message } }));
      });
    });
  });

  return new Promise((resolve, reject) => {
    /* server.listen() emits "error" (not a thrown exception) on an async bind failure
     * (port already in use, EACCES on a privileged port, etc.) -- without a one-shot
     * handler here, that error had no rejection path, so startGateway()'s own try/catch
     * never ran its cleanup and the default process crashed uncaught after already
     * acquiring the writer claim and spawning downstream children (board decision
     * 2026-09-04, PR #29 review "reject HTTP listener bind failures through the startup
     * promise"). Removed once "listening" fires so a later, unrelated runtime error
     * event on the same server doesn't also try to settle this already-settled promise. */
    function onError(error) {
      server.removeListener("listening", onListening);
      reject(Object.assign(new Error(`graphsmith-gateway: failed to start the agent-facing HTTP listener: ${error.message}`), { cause: error }));
    }
    function onListening() {
      server.removeListener("error", onError);
      resolve({ server, port: server.address().port });
    }
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(listenConfig.port || 0);
  });
}

module.exports = { runStdioAgentTransport, runHttpAgentTransport };
