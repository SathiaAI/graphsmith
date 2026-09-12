#!/usr/bin/env node
/* GraphSmith standalone gateway -- agent-facing transports (Standalone Gateway TRD
 * SS3.1). Extracted out of gateway.js (which owns process lifecycle/writer-claim) to
 * keep that file under this repo's default file-size guideline and because these two
 * runners have no dependency on writer-claim/mode-gate/config -- only on a GatewayProxy.
 *
 * stdio: one process, one connection (mirrors mcp-server/src/stdioTransport.js's own
 * newline-delimited JSON-RPC framing and "stdin closed -> exit cleanly" convention).
 *
 * http: sessions keyed by an explicit, server-minted `Mcp-Session-Id` (board decision
 * 2026-09-08, revising the 2026-09-04 "key HTTP sessions by protocol identity" review
 * item -- see runHttpAgentTransport's own header comment for the full design and why
 * this supersedes the prior "one TCP socket = one session" identity). That prior
 * identity model, and the explicit 2026-09-04 decision NOT to build anything past it,
 * are preserved here only as history: KNOWN-LIMITATIONS.md documents what changed and
 * why.
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
      /* Codex PR #29 review round 3 "validate agent replies to pushed sampling
       * requests": this previously accepted any id-matching, method-less message as a
       * valid reply, without requiring "jsonrpc": "2.0" or exactly one of "result"/
       * "error" -- mirroring the same gap downstream.js's connectStdio had (and already
       * fixed) on its own response-correlation path. A malformed reply such as
       * `{"id":"gw-push-..."}` would resolve as a successful `undefined` sampling result
       * and be forwarded to the downstream, and be attested, as though it had genuinely
       * succeeded. */
      const hasResult = Object.prototype.hasOwnProperty.call(msg, "result");
      const hasError = Object.prototype.hasOwnProperty.call(msg, "error");
      const wellFormed = msg.jsonrpc === "2.0" && (hasResult || hasError) && !(hasResult && hasError);
      if (!wellFormed) {
        reject(new Error(`agent's reply to pushed request (id ${JSON.stringify(msg.id)}) was not a well-formed JSON-RPC 2.0 response (missing/invalid "jsonrpc", or not exactly one of "result"/"error" present)`));
      } else if (hasError) {
        /* CodeRabbit PR #29 review round 4 "a reply with a present but falsy error
         * resolves as a successful undefined result": branching on msg.error's truthiness
         * (rather than the hasError presence flag already computed above) let a reply
         * shaped like {"jsonrpc":"2.0","id":"gw-push-...","error":null} pass the
         * exactly-one-of-result-or-error check above and then fall through to resolve()
         * with an undefined result -- the exact false-success outcome that check exists to
         * prevent. Same class of bug already fixed in downstream.js's own response
         * correlation. */
        reject(Object.assign(new Error((msg.error && msg.error.message) || "agent returned an error"), { rpcError: msg.error }));
      } else {
        resolve(msg.result);
      }
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
 * `token` is the already-resolved bearer token (see config.js#resolveSecretRef).
 *
 * **Session identity (board decision 2026-09-08).** Sessions are identified by an
 * explicit, server-minted `Mcp-Session-Id` -- mirroring the MCP streamable-HTTP
 * transport spec's own convention -- not by the underlying TCP socket (the prior
 * design; see git history / KNOWN-LIMITATIONS.md for what this replaces and why). Only
 * `initialize` may be sent without a session ID; the gateway mints one there, opens the
 * proxy session under it, and returns it on the `Mcp-Session-Id` response header. Every
 * later request on that session must echo the header back; an unrecognized or expired
 * ID gets 404 (MCP's own convention for "this session is gone -- start over with
 * initialize"). A session ends on an explicit `DELETE` (204), after
 * SESSION_IDLE_TIMEOUT_MS of inactivity, or when the gateway process shuts down
 * (gateway.js#stop already force-closes every session still open in `proxy.sessions` at
 * that point, unconditionally, regardless of transport) -- deliberately NOT when the
 * TCP socket that carried a given request happens to close.
 *
 * This was scoped deliberately narrower than "real HTTP session resumption": it fixes
 * the two concrete problems an explicit ID actually needs to fix --
 * (1) a pooling reverse proxy multiplexing distinct agents onto one shared backend
 *     socket can no longer corrupt session identity, because identity no longer comes
 *     from the socket at all;
 * (2) one well-behaved agent whose HTTP client rotates connections mid-session (a
 *     recycled keep-alive socket, a client-side reconnect) no longer loses its already-
 *     `initialize`d session for a reason entirely outside its control --
 * without reopening `session_boundary: "time_window"` (still refused at startup, see
 * gateway.js) or building the fuller reconnect/replay/multi-node session store that
 * mode would eventually need. Sought a second opinion from an external panel of five
 * non-Anthropic frontier models before landing on this scope (2026-09-08); see the
 * project's own decision log for the full brief and dissenting views.
 *
 * **Disclosed cost of this scope, not hidden:** an agent that vanishes uncleanly (crash,
 * network partition, no DELETE) now leaves its session open -- and counted in
 * `active_sessions`, and un-sealed in the audit chain -- for up to
 * SESSION_IDLE_TIMEOUT_MS, instead of the near-instant cleanup the old socket-close
 * handler gave for free. That is the deliberate trade for no longer conflating "this
 * TCP connection ended" with "this agent is done." */
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

  const SESSION_ID_HEADER = "mcp-session-id";
  /* Not yet exposed as a config field. A fixed, documented default matches this change's
   * own "minimal, non-speculative" scope (see header comment) -- the same discipline the
   * 2026-09-04 decision applied to `time_window` itself. Make it configurable once a
   * real deployment needs a different value, not before. */
  const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
  /* Codex PR #29 review "cap concurrently retained HTTP sessions": without a bound, a
   * client that repeatedly sends headerless "initialize" (each one opens a brand-new
   * session -- see the no-sessionId branch below) and never DELETEs could grow
   * httpSessions/proxy.sessions/idle-timer state without limit, exhausting memory despite
   * the per-request body-size cap. Same "fixed, non-speculative default" discipline as
   * SESSION_IDLE_TIMEOUT_MS just above -- make it configurable once a real deployment
   * needs a different number, not before. */
  const MAX_HTTP_SESSIONS = 10000;

  const httpSessions = new Map(); // sessionId -> { idleTimer } -- transport-level bookkeeping proxy.js has no reason to know about.

  function sealSession(sessionId, reason) {
    const entry = httpSessions.get(sessionId);
    if (!entry) return;
    clearTimeout(entry.idleTimer);
    httpSessions.delete(sessionId);
    ctx.proxy.closeConnection(sessionId, reason).catch(() => {});
  }

  function touchSession(sessionId) {
    const entry = httpSessions.get(sessionId);
    if (!entry) return;
    clearTimeout(entry.idleTimer);
    entry.idleTimer = setTimeout(() => sealSession(sessionId, "agent HTTP session idle timeout exceeded"), SESSION_IDLE_TIMEOUT_MS);
    if (typeof entry.idleTimer.unref === "function") entry.idleTimer.unref();
  }

  function openSession() {
    /* 128 random bits, not the prior design's 64 -- an id that is now a client-visible,
     * bearer-like session credential (rather than an internal WeakMap key nobody outside
     * this process ever saw) warrants the larger, standard margin against guessing. */
    const id = "http-" + crypto.randomBytes(16).toString("hex");
    ctx.proxy.openConnection(id);
    httpSessions.set(id, { idleTimer: null });
    touchSession(id);
    return id;
  }

  const server = http.createServer((req, res) => {
    /* Mirrors mcp-server/src/httpTransport.js#createHttpServer's own contract (that
     * module explicitly returns 405 for non-POST -- see its own comment on this): reject
     * every method but POST/DELETE before authentication or body processing, so a
     * GET/PUT/etc. intermediaries may treat as safe or replayable can never reach a
     * side-effecting tools/call the way a POST-only endpoint would refuse to let it
     * (board decision 2026-09-04, PR #29 review "reject non-POST requests on the agent
     * HTTP listener"). DELETE is admitted alongside POST for explicit session
     * termination (board decision 2026-09-08) -- it carries no JSON-RPC payload and is
     * not itself a side-effecting call. */
    if (req.method !== "POST" && req.method !== "DELETE") {
      res.writeHead(405, { "content-type": "application/json", allow: "POST, DELETE" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Only POST and DELETE are supported on this endpoint." } }));
      return;
    }
    /* Reuses mcp-server/src/auth.js's already-adversarially-reviewed
     * isAuthenticated() (constant-time comparison via crypto.timingSafeEqual, fail-
     * closed on a missing/malformed header or an unconfigured token) rather than a
     * second, naive `===` string comparison, which would reopen exactly the
     * timing-attack surface that module exists to close. Runs before any session lookup
     * so an unauthenticated caller learns nothing about which session IDs exist. */
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

    const sessionIdHeader = req.headers[SESSION_ID_HEADER];

    if (req.method === "DELETE") {
      req.resume(); // no body expected; drain and discard whatever the client sends anyway
      req.on("end", () => {
        if (!sessionIdHeader) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: `DELETE requires the ${SESSION_ID_HEADER} header.` } }));
          return;
        }
        if (!httpSessions.has(sessionIdHeader)) {
          res.writeHead(404, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "Unknown or already-ended session." } }));
          return;
        }
        sealSession(sessionIdHeader, "agent explicitly terminated session (DELETE)");
        res.writeHead(204);
        res.end();
      });
      return;
    }

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

      let sessionId = sessionIdHeader;
      if (!sessionId) {
        /* No session ID presented: the ONLY message this can legitimately be is
         * "initialize" (board decision 2026-09-08) -- anything else means either a
         * client bug or a stale session the server already forgot; both get the same
         * clear, actionable error rather than proxy.js's generic "no open session"
         * throw. */
        if (!msg || typeof msg !== "object" || msg.method !== "initialize") {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32600, message: `Missing ${SESSION_ID_HEADER} header -- a new session must begin with "initialize".` } }));
          return;
        }
        if (httpSessions.size >= MAX_HTTP_SESSIONS) {
          res.writeHead(503, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32000, message: `This gateway is already at its concurrent HTTP session limit (${MAX_HTTP_SESSIONS}); cannot start a new session right now.` } }));
          return;
        }
        /* Codex PR #29 review "reject new HTTP sessions cleanly while draining":
         * ctx.proxy.openConnection() (called inside openSession()) throws synchronously
         * once stopAcceptingNewSessions() has run (writer-claim lost, or graceful
         * shutdown draining) -- this call sat outside any try/catch, so that throw
         * escaped this synchronous req "end" handler uncaught, crashing the process
         * exactly when a clean, finished shutdown mattered most. Catch the expected
         * refusal and answer it like any other "not accepting requests" case instead. */
        try {
          sessionId = openSession();
        } catch (error) {
          res.writeHead(503, { "content-type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32000, message: `Cannot start a new session: ${error.message}` } }));
          return;
        }
      } else if (!httpSessions.has(sessionId)) {
        res.writeHead(404, { "content-type": "application/json", [SESSION_ID_HEADER]: sessionId });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id, error: { code: -32001, message: "Unknown or expired session -- start a new session with \"initialize\"." } }));
        return;
      } else {
        touchSession(sessionId);
      }

      ctx.proxy.handleMessage(sessionId, msg).then((response) => {
        if (response === null) {
          res.writeHead(202, { [SESSION_ID_HEADER]: sessionId });
          res.end();
        } else {
          res.writeHead(200, { "content-type": "application/json", [SESSION_ID_HEADER]: sessionId });
          res.end(JSON.stringify(response));
        }
      }).catch((error) => {
        res.writeHead(500, { "content-type": "application/json", [SESSION_ID_HEADER]: sessionId });
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
    /* CodeRabbit PR #29 review "bind the agent HTTP listener to an explicit host":
     * omitting `host` from Node's server.listen() binds Node's wildcard address (::  or
     * 0.0.0.0), exposing this bearer-token-protected listener on every network interface
     * instead of just the local machine. Default to loopback-only; an operator who
     * genuinely needs a different bind interface can say so via agent_listen.host
     * (schemas/gateway-config.schema.json / config.js's validateAgentListen). */
    server.listen(listenConfig.port || 0, listenConfig.host || "127.0.0.1");
  });
}

module.exports = { runStdioAgentTransport, runHttpAgentTransport };
