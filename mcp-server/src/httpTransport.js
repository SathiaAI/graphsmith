"use strict";

const http = require("http");
const { handleMessage } = require("./server.js");
const { isAuthenticated } = require("./auth.js");
const { ERROR_CODES } = require("./protocol.js");

const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB -- this server's only real payload is a no-arg tool call.

/* Network (HTTP, "streamable-http"-style) transport.
 *
 * THIS IS THE TRANSPORT THE ADVERSARIAL AUTH TEST TARGETS. Per the frozen
 * Lane C design ("If a network transport is added in a later release,
 * per-request bearer-token auth is a hard prerequisite, not a follow-up")
 * and the Wave 1 kickoff's explicit instruction not to repeat
 * clarity-agent's zero-auth sse/streamable-http mistake:
 *
 *   1. createHttpServer() REFUSES TO CONSTRUCT the server at all without a
 *      configured token -- there is no "network mode with auth off" code
 *      path to accidentally reach for local testing and forget to remove.
 *   2. The auth check runs as the FIRST thing the request handler does,
 *      before the request body is even read off the socket, let alone
 *      parsed as JSON or dispatched to handleMessage(). An unauthenticated
 *      caller cannot reach the JSON-RPC dispatcher under any method name,
 *      including "initialize" -- unlike stdio, this transport never grants
 *      the legacy handshake path a pass on auth (statelessness applies to
 *      the connection model too: every HTTP request gets a *fresh*
 *      connectionState, so there is no "session" here for a legacy
 *      handshake to establish in the first place).
 *   3. Auth failure returns 401 with WWW-Authenticate: Bearer and never
 *      falls through to any other code path.
 */
function createHttpServer(options) {
  const opts = options || {};
  const token = opts.token;

  if (!token || typeof token !== "string" || token.length < 16) {
    throw new Error(
      "graphsmith-mcp: refusing to start the HTTP transport without a strong bearer token. " +
        "Set GRAPHSMITH_MCP_TOKEN (>=16 characters) in the environment or pass { token } explicitly. " +
        "This is a hard requirement for any non-stdio transport, not a configurable-away default."
    );
  }

  const server = http.createServer((req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json", allow: "POST" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: ERROR_CODES.INVALID_REQUEST, message: "Only POST is supported on this endpoint." },
        })
      );
      return;
    }

    /* --- Auth gate: runs before ANY body read/parse/dispatch. --- */
    const authHeader = req.headers["authorization"];
    if (!isAuthenticated(authHeader, token)) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": "Bearer" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: {
            code: ERROR_CODES.UNAUTHENTICATED,
            message: "Unauthenticated: a valid \"Authorization: Bearer <token>\" header is required on every request.",
          },
        })
      );
      req.destroy();
      return;
    }

    let body = "";
    let tooLarge = false;
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
      }
    });

    req.on("end", () => {
      if (tooLarge) return; // connection already destroyed, nothing to respond with
      let msg;
      try {
        msg = JSON.parse(body);
      } catch (err) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: { code: ERROR_CODES.PARSE_ERROR, message: `Parse error: ${err.message}` },
          })
        );
        return;
      }

      /* Fresh, unshared connectionState per HTTP request -- no session ID,
       * no cross-request memory. This means the legacy initialize
       * handshake's "remembered" state never applies over this transport;
       * every call must carry a valid _meta block. */
      const connectionState = { legacyInitialized: false };
      const response = handleMessage(msg, { connectionState, authenticated: true });

      if (response === null) {
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(response));
    });
  });

  return server;
}

module.exports = { createHttpServer, MAX_BODY_BYTES };
