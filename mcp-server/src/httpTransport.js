"use strict";

const http = require("http");
const { handleMessage } = require("./server.js");
const { isAuthenticated } = require("./auth.js");
const { ERROR_CODES } = require("./protocol.js");

const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB -- this server's only real payload is a no-arg tool call.

/* Maps a JSON-RPC error code to the HTTP status this transport reports it
 * under, so HTTP-level tooling (proxies, health checks, monitoring, a
 * generic `curl -f`) can tell success from failure without parsing the
 * JSON-RPC body. METHOD_NOT_FOUND -> 404 and UNSUPPORTED_PROTOCOL_VERSION /
 * HEADER_MISMATCH -> 400 are spec-mandated (modelcontextprotocol.io/
 * specification/draft/basic/transports/streamable-http: "If the server
 * does not implement the requested RPC method, it MUST respond with 404
 * Not Found..."; UnsupportedProtocolVersionError and HeaderMismatchError
 * both "MUST be 400 Bad Request"). The remaining mappings (PARSE_ERROR /
 * INVALID_REQUEST / INVALID_PARAMS -> 400, INTERNAL_ERROR -> 500) follow
 * standard JSON-RPC-over-HTTP convention; the spec doesn't mandate them
 * for this server's remaining error codes. */
function errorHttpStatus(code) {
  switch (code) {
    case ERROR_CODES.METHOD_NOT_FOUND:
      return 404;
    case ERROR_CODES.UNAUTHENTICATED:
      return 401;
    case ERROR_CODES.INTERNAL_ERROR:
      return 500;
    case ERROR_CODES.PARSE_ERROR:
    case ERROR_CODES.INVALID_REQUEST:
    case ERROR_CODES.INVALID_PARAMS:
    case ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION:
    case ERROR_CODES.HEADER_MISMATCH:
      return 400;
    default:
      return 500;
  }
}

function getHeader(headers, name) {
  // Node lowercases incoming header names itself, but normalize defensively.
  const v = headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/* Decodes the "=?base64?...?=" sentinel form the spec requires for header
 * values that can't be safely represented as plain ASCII (e.g. a Mcp-Name
 * containing non-ASCII characters). Returns the input unchanged if it
 * doesn't match the sentinel pattern. */
function decodeMcpHeaderValue(raw) {
  if (typeof raw !== "string") return raw;
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(raw);
  if (!m) return raw;
  try {
    return Buffer.from(m[1], "base64").toString("utf8");
  } catch (_err) {
    return raw; // malformed encoding -- let the equality check below fail naturally
  }
}

/* Validates the Streamable HTTP transport's mirrored request-metadata
 * headers against the JSON-RPC body, per the 2026-07-28 revision's
 * "Request Metadata" section (modelcontextprotocol.io/specification/
 * draft/basic/transports/streamable-http#request-metadata):
 *   - MCP-Protocol-Version is required on every request and MUST match
 *     _meta["io.modelcontextprotocol/protocolVersion"] in the body.
 *   - Mcp-Method is required on every request and MUST match the body's
 *     "method".
 *   - Mcp-Name is required specifically for "tools/call" (the only
 *     name-bearing method this server implements) and MUST match
 *     params.name, decoding the base64 sentinel form first if present.
 * Per spec, header requirements are undefined for notification POSTs, so
 * callers must not invoke this for a notification-shaped message.
 * Returns a human-readable mismatch description on failure, or null if
 * every required header is present and agrees with the body. */
function validateMirroredHeaders(headers, msg) {
  const method = msg && typeof msg === "object" && typeof msg.method === "string" ? msg.method : undefined;

  const protocolVersionHeader = getHeader(headers, "mcp-protocol-version");
  if (!protocolVersionHeader) {
    return "Missing required header: MCP-Protocol-Version.";
  }
  const bodyProtocolVersion =
    msg && msg.params && typeof msg.params === "object" && msg.params._meta && typeof msg.params._meta === "object"
      ? msg.params._meta["io.modelcontextprotocol/protocolVersion"]
      : undefined;
  /* Only compared when the body actually carries a _meta block -- a
   * missing/malformed _meta is INVALID_PARAMS territory that the JSON-RPC
   * dispatcher (validateMeta in server.js) already reports on its own;
   * this check's job is only to catch a header/body DISAGREEMENT, not to
   * duplicate that separate validation. */
  if (bodyProtocolVersion !== undefined && protocolVersionHeader !== bodyProtocolVersion) {
    return `Header mismatch: MCP-Protocol-Version header value '${protocolVersionHeader}' does not match body value '${bodyProtocolVersion}'.`;
  }

  const methodHeader = getHeader(headers, "mcp-method");
  if (!methodHeader) {
    return "Missing required header: Mcp-Method.";
  }
  if (method !== undefined && methodHeader !== method) {
    return `Header mismatch: Mcp-Method header value '${methodHeader}' does not match body value '${method}'.`;
  }

  if (method === "tools/call") {
    const nameHeaderRaw = getHeader(headers, "mcp-name");
    if (!nameHeaderRaw) {
      return "Missing required header: Mcp-Name (required for tools/call).";
    }
    const nameHeader = decodeMcpHeaderValue(nameHeaderRaw);
    const bodyName = msg.params && typeof msg.params === "object" ? msg.params.name : undefined;
    if (bodyName !== undefined && nameHeader !== bodyName) {
      return `Header mismatch: Mcp-Name header value '${nameHeader}' does not match body value '${bodyName}'.`;
    }
  }

  return null;
}

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

    /* Accumulate as raw Buffer chunks and count actual bytes received --
     * NOT `body += chunk`, which implicitly decodes each chunk as UTF-8
     * and measures `.length` in UTF-16 code units. For multi-byte UTF-8
     * content that under-counts MAX_BODY_BYTES (a 3-byte-per-char payload
     * can be ~3x the real cap before the check trips), and it can also
     * silently corrupt characters that straddle a chunk boundary -- a
     * partial multi-byte sequence decodes to U+FFFD replacement
     * character(s) with no error raised, and the resulting corrupted
     * string can still pass JSON.parse(). Decoding once, from the fully
     * reassembled bytes, avoids both problems. */
    let chunks = [];
    let bytesReceived = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      bytesReceived += chunk.length;
      if (bytesReceived > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (tooLarge) return; // connection already destroyed, nothing to respond with
      let msg;
      try {
        msg = JSON.parse(Buffer.concat(chunks).toString("utf8"));
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

      /* Notification-shaped messages (no meaningful response expected) are
       * exempt from header/body mirroring requirements -- the spec's
       * "Sending Messages" section notes header requirements for
       * notification POSTs are not defined by this revision. Detected the
       * same way server.js's own dispatcher detects them, so the two stay
       * in agreement about what counts as a notification. */
      const isNotification =
        msg && typeof msg === "object" && !Array.isArray(msg) && typeof msg.method === "string" &&
        msg.method.startsWith("notifications/");

      if (!isNotification) {
        const headerError = validateMirroredHeaders(req.headers, msg);
        if (headerError) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: msg && typeof msg === "object" && !Array.isArray(msg) && msg.id !== undefined ? msg.id : null,
              error: { code: ERROR_CODES.HEADER_MISMATCH, message: headerError },
            })
          );
          return;
        }
      }

      /* Fresh, unshared connectionState per HTTP request -- no session ID,
       * no cross-request memory. This means the legacy initialize
       * handshake's "remembered" state never applies over this transport;
       * every call must carry a valid _meta block. */
      const connectionState = { legacyInitialized: false };
      const response = handleMessage(msg, { connectionState, authenticated: true });

      if (response === null) {
        /* Notification accepted: spec requires 202 Accepted with no body
         * (Streamable HTTP, "Sending Messages"), not an arbitrary 2xx. */
        res.writeHead(202);
        res.end();
        return;
      }
      const status = response.error ? errorHttpStatus(response.error.code) : 200;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(response));
    });
  });

  return server;
}

module.exports = { createHttpServer, MAX_BODY_BYTES };
