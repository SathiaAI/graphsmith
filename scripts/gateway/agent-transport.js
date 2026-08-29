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
 */
"use strict";

const crypto = require("crypto");
const http = require("http");
const readline = require("readline");
const { isAuthenticated } = require("../../mcp-server/src/auth.js");

/** Runs the agent-facing stdio transport against `ctx.proxy`. Returns
 * { connectionId, closed, stop } -- `closed` resolves once the session has already been
 * finalized (the caller does not need to call closeConnection itself). */
function runStdioAgentTransport(ctx) {
  const connectionId = "stdio-" + crypto.randomBytes(8).toString("hex");
  ctx.proxy.openConnection(connectionId);
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

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
    ctx.proxy.handleMessage(connectionId, msg).then((response) => {
      if (response !== null) process.stdout.write(JSON.stringify(response) + "\n");
    }).catch((error) => {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32603, message: error.message } }) + "\n");
    });
  });

  const closed = new Promise((resolve) => {
    rl.on("close", async () => {
      await ctx.proxy.closeConnection(connectionId, "agent stdio disconnected");
      resolve();
    });
  });
  return { connectionId, closed, stop: () => rl.close() };
}

/** Runs the agent-facing HTTP transport (config `agent_listen.transport: "http"`).
 * `token` is the already-resolved bearer token (see config.js#resolveSecretRef). */
function runHttpAgentTransport(ctx, listenConfig, token) {
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
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
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

  return new Promise((resolve) => {
    server.listen(listenConfig.port || 0, () => resolve({ server, port: server.address().port }));
  });
}

module.exports = { runStdioAgentTransport, runHttpAgentTransport };
