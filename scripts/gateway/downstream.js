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
const { resolveSecretRef } = require("./config.js");

function fail(message, code = "GATEWAY_DOWNSTREAM_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30000;

/* The MCP protocol version this client negotiates on the downstream leg's own
 * initialize handshake -- matches the literal version scripts/gateway/proxy.js selects
 * on the agent-facing leg (both legs of this gateway speak the same one version). */
const MCP_PROTOCOL_VERSION = "2025-06-18";

/* Mirrors mcp-server/src/protocol.js's own _meta key names and validateMeta()
 * contract -- literal duplication rather than a cross-package require, matching this
 * file's existing convention of mirroring wire-level constants rather than reaching
 * across the scripts/ <-> mcp-server/ package boundary (see MCP_PROTOCOL_VERSION
 * above, and the mirrored Streamable HTTP headers in connectHttp below). Needed
 * because a plain JSON-RPC-over-HTTP downstream is stateless: mcp-server/src/
 * httpTransport.js hands handleMessage a FRESH connectionState on every single
 * request, so connectionState.legacyInitialized from an earlier `initialize` call
 * never carries over -- every tools/list, tools/call, and server/discover request
 * over HTTP must carry its own complete _meta block or a downstream enforcing this
 * repo's own stateless MCP contract (SEP-2575) rejects it with "_meta is required"
 * even though this client's own `initialize` succeeded moments earlier (board
 * decision 2026-09-04, PR #29 review "send stateless metadata to HTTP downstreams"). */
const META_PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo";
const META_CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities";
const STATELESS_META_METHODS = new Set(["tools/list", "tools/call", "server/discover"]);

/* Mirrors mcp-server/src/protocol.js's own STATELESS_PROTOCOL_VERSION -- a DIFFERENT
 * literal from MCP_PROTOCOL_VERSION above. That constant is the legacy handshake
 * version this client negotiates via the top-level `initialize` call (mcp-server's own
 * handleLegacyInitialize doesn't even check it); _meta's own protocolVersion key is
 * validated against this separate stateless-protocol literal instead (mcp-server/src/
 * server.js's validateMeta), and the two must never be conflated -- sending the legacy
 * version inside _meta is itself an UNSUPPORTED_PROTOCOL_VERSION error there. */
const STATELESS_META_PROTOCOL_VERSION = "2026-07-28";

function buildStatelessMeta(options) {
  return {
    [META_PROTOCOL_VERSION_KEY]: STATELESS_META_PROTOCOL_VERSION,
    [META_CLIENT_INFO_KEY]: options.clientInfo || { name: "graphsmith-standalone-gateway", version: "1.0" },
    [META_CLIENT_CAPABILITIES_KEY]: {},
  };
}

/* Safety cap on a single downstream HTTP response body, and the absolute wall-clock
 * deadline (independent of the idle-socket timeout below, which only trips on
 * inactivity) a response has to finish arriving -- board decision 2026-09-04, PR #29
 * review "bound downstream HTTP response bodies": without both, a compromised or
 * faulty configured HTTP downstream could exhaust gateway memory (unbounded buffering)
 * or keep a call alive indefinitely (a response that keeps trickling bytes never goes
 * "inactive" long enough to trip req.setTimeout). */
const MAX_HTTP_RESPONSE_BYTES = 10 * 1024 * 1024;

/* Bounds on how many tools/list pages a downstream may hand back before this client
 * gives up rather than looping forever on a downstream that returns a cursor cycle or an
 * unbounded number of pages. */
const MAX_TOOLS_LIST_PAGES = 1000;

/* Bounds the CUMULATIVE size of a downstream's entire tools/list surface, summed across
 * every page -- Codex PR #29 review round 5 "bound aggregate tool discovery data":
 * MAX_HTTP_RESPONSE_BYTES already bounds any single page's response body, and
 * MAX_TOOLS_LIST_PAGES bounds how many pages are followed, but neither bounds the
 * cumulative bytes actually RETAINED in `tools` across those pages -- a downstream
 * returning close to MAX_HTTP_RESPONSE_BYTES on every one of MAX_TOOLS_LIST_PAGES pages
 * could still make this client buffer roughly 10 GiB before startup fails. A generous,
 * fixed multiple of the per-page cap (not yet a config field -- same "fixed,
 * non-speculative default" discipline as MAX_TOOLS_LIST_PAGES above and MAX_HTTP_SESSIONS
 * in agent-transport.js; make it configurable once a real deployment needs a different
 * number, not before). */
const MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES = 50 * 1024 * 1024;

/** Pure helper for connectStdio's unterminated-line byte cap (CodeRabbit PR #29 review
 * round 4 "make this regression test deterministic"): given the residual unterminated
 * byte count carried over from the previous chunk and the newly-received chunk, returns
 * the new residual -- the number of trailing bytes not yet followed by a newline. A
 * chunk containing no newline extends the residual by its full length; a chunk
 * containing one or more newlines resets the residual to just the bytes after its LAST
 * newline. Exported separately from the "data" listener that calls it so a test can
 * drive it directly with an explicit in-memory Buffer, independent of how an OS pipe
 * happens to chunk a real child process's stdout. */
function nextResidualLineBytes(prevResidualBytes, buf) {
  const lastNewline = buf.lastIndexOf(0x0a);
  return lastNewline === -1 ? prevResidualBytes + buf.length : buf.length - lastNewline - 1;
}

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

  /* Codex PR #29 review round 3 "handle errors from the downstream stdin stream": a
   * downstream that exits just before or during a write can make child.stdin emit an
   * asynchronous EPIPE (or ERR_STREAM_WRITE_AFTER_END) error rather than throwing into
   * the call()/notify()/write-back call sites below -- Node treats an unhandled "error"
   * event on a stream as fatal and crashes the whole gateway process. Every write already
   * goes through call()/notify()'s own `closed` guard or the unhandled-method write below
   * (now also guarded, see there), so the pending calls this would have failed are already
   * rejected via the child's own "close"/"error" handlers; this listener exists solely to
   * absorb the stream-level error event itself so it cannot crash the process. */
  child.stdin.on("error", () => { /* best effort: absorbed to prevent an unhandled 'error' event from crashing the gateway */ });

  const rl = readline.createInterface({ input: child.stdout, terminal: false });
  /* Codex PR #29 review round 3 "bound newline-delimited responses from stdio
   * downstreams": readline buffers an unbounded amount of input while waiting for a
   * newline, so a faulty or compromised downstream that never terminates a line could
   * exhaust gateway memory even though the HTTP path already caps a single response at
   * MAX_HTTP_RESPONSE_BYTES. Track bytes received since the last completed line and
   * force-close the connection if a single unterminated line grows past that same cap. */
  let bytesSinceLastLine = 0;
  /* CodeRabbit PR #29 review round 4 "track only the bytes after the last newline":
   * readline registers its own "data" listener on child.stdout before this one, so for a
   * chunk containing one or more COMPLETE lines, readline has already emitted "line"
   * (resetting bytesSinceLastLine to 0 below) by the time this listener runs -- which then
   * added the chunk's FULL length on top of that reset, rather than only the bytes still
   * unterminated after the chunk's last newline. Several complete, individually
   * well-formed lines delivered together in one chunk (e.g. pipelined/batched downstream
   * writes) could therefore be misreported as a single oversized unterminated line and
   * force-close a perfectly healthy connection. Derive the residual directly from each
   * chunk's own last newline instead of relying on ordering against readline's listener.
   *
   * CodeRabbit PR #29 review round 4 "make this regression test deterministic": the
   * regression test for the bug above drove this indirectly through a real child
   * process's stdout, relying on a single process.stdout.write() call arriving as one
   * "data" chunk on this side -- which the OS pipe is free to split into many smaller
   * chunks regardless (and typically does, e.g. Linux's default ~64KB pipe buffer), so
   * the test could pass against the OLD buggy logic too without ever exercising the
   * multiple-complete-lines-in-one-chunk case it claims to cover. Extracted into this
   * pure, exported helper so a test can drive it directly with an explicit in-memory
   * Buffer -- deterministic, no child process or OS pipe chunking involved. */
  child.stdout.on("data", (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytesSinceLastLine = nextResidualLineBytes(bytesSinceLastLine, buf);
    if (bytesSinceLastLine > MAX_HTTP_RESPONSE_BYTES) {
      bytesSinceLastLine = 0;
      if (!closed) {
        closeError = fail(`downstream stdio produced an unterminated line exceeding the ${MAX_HTTP_RESPONSE_BYTES}-byte limit`, "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE");
        close();
      }
    }
  });
  /* Correlation order matters: a bidirectional stdio connection gives the downstream
   * its OWN independent id namespace for requests it initiates (see the sampling-relay
   * comment below), so a downstream-initiated request can legitimately reuse a numeric
   * id this client currently has pending on the OTHER direction. Requiring the absence
   * of "method" before treating a message as "the response to one of our own calls"
   * (rather than checking `pending.has(msg.id)` alone) is what keeps those two
   * directions from being confused with each other (board decision 2026-09-04, PR #29
   * review "distinguish downstream requests before correlating responses"). */
  rl.on("line", (line) => {
    // bytesSinceLastLine is now derived per-chunk (from each chunk's own last newline) in
    // the "data" listener above, so it needs no reset here.
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (error) {
      return; // malformed line from downstream: not this client's job to crash on it
    }
    if (msg && Object.prototype.hasOwnProperty.call(msg, "id") && msg.id !== null && !Object.prototype.hasOwnProperty.call(msg, "method") && pending.has(msg.id)) {
      const { resolve, reject, timer } = pending.get(msg.id);
      clearTimeout(timer);
      pending.delete(msg.id);
      /* Codex PR #29 review "reject malformed stdio response envelopes": this branch
       * previously accepted ANY id-matching, method-less message as a valid response --
       * unlike connectHttp's own fail-closed envelope check (jsonrpc/id/shape validated
       * below), a downstream that omits "jsonrpc": "2.0" or sends neither "result" nor
       * "error" would still be resolved/rejected as if it were well-formed, sealing a
       * malformed exchange as a normal successful (or normally-failed) tool result. */
      const hasResult = Object.prototype.hasOwnProperty.call(msg, "result");
      const hasError = Object.prototype.hasOwnProperty.call(msg, "error");
      /* Codex PR #29 review round 5 "require exactly one result or error in stdio
       * replies": the prior check accepted a message carrying BOTH fields, or an
       * "error" key present but falsy (e.g. {"error":null}) -- branching on msg.error's
       * truthiness rather than the hasError presence flag let that second shape fall
       * through to the success branch and resolve(msg.result) with an undefined result,
       * the same false-success outcome the "neither present" half of this check already
       * guards against. Require exactly one of "result"/"error" as an own property and
       * branch on presence, matching connectHttp's own envelope check just above (and
       * agent-transport.js's own pushed-reply correlation, fixed the same way). */
      const wellFormed = msg.jsonrpc === "2.0" && (hasResult || hasError) && !(hasResult && hasError);
      if (!wellFormed) {
        reject(fail(`downstream stdio response for id ${JSON.stringify(msg.id)} was not a well-formed JSON-RPC 2.0 response (missing/invalid "jsonrpc", or not exactly one of "result"/"error" present)`, "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"));
      } else if (hasError) {
        reject(Object.assign(fail(msg.error.message || "downstream error", "GATEWAY_DOWNSTREAM_RPC_ERROR"), { rpcError: msg.error }));
      } else {
        resolve(msg.result);
      }
    } else if (msg && typeof msg.method === "string" && !Object.prototype.hasOwnProperty.call(msg, "id")) {
      for (const handler of notificationHandlers) handler(msg);
    } else if (msg && typeof msg.method === "string" && Object.prototype.hasOwnProperty.call(msg, "id") && msg.id !== null) {
      /* An unsolicited REQUEST *from* the downstream server itself (has both a method
       * and an id -- distinct from a notification, which has no id, and distinct from a
       * response to something this client called, which has no method). The MCP
       * sampling capability (`sampling/createMessage`) is the motivating case: a
       * downstream server asks the connected agent's own model to do inference.
       * Previously fell through both branches above and was silently dropped -- neither
       * a recognized response nor a notification (board decision 2026-09-04, PR #29
       * review "forward downstream sampling requests upstream"). `options.onRequest`,
       * when provided, decides how (or whether) to answer it; this transport client
       * itself stays a dumb pipe and always writes back whatever response object
       * onRequest resolves to, so the downstream never hangs waiting on an id that will
       * never come back. */
      if (typeof options.onRequest === "function") {
        Promise.resolve(options.onRequest(msg))
          .then((response) => {
            if (response && !closed) child.stdin.write(JSON.stringify(response) + "\n");
          })
          .catch((error) => {
            if (!closed) child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32603, message: error.message } }) + "\n");
          });
      } else if (!closed) {
        /* Codex PR #29 review round 3 "handle errors from the downstream stdin stream":
         * this branch previously wrote unconditionally, unlike the two onRequest branches
         * above it -- a downstream that has already exited (closed=true, e.g. its own
         * "close"/"error" handlers already ran) would still attempt a write here, which
         * could throw synchronously or, with the stdin error listener above absorbing the
         * async case, would otherwise be a pointless write to a stream nobody reads from
         * anymore. Consistent with those two branches' own `!closed` guard. */
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `This gateway does not handle downstream-initiated method "${msg.method}".` } }) + "\n");
      }
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

  function call(method, params, timeoutMs, onIdAssigned) {
    if (closed) return Promise.reject(closeError || fail("downstream connection is closed", "GATEWAY_DOWNSTREAM_DISCONNECTED"));
    const id = nextId++;
    if (typeof onIdAssigned === "function") onIdAssigned(id);
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

  /** Cancels a still-pending call by the internal id `call()` assigned it (via
   * `onIdAssigned`): rejects the caller's promise locally and best-effort notifies the
   * downstream process so it can stop doing the (possibly expensive/irreversible) work,
   * per MCP's notifications/cancelled. No-op (returns false) if the id is no longer
   * pending -- already resolved/rejected/timed out. */
  function cancel(id) {
    const entry = pending.get(id);
    if (!entry) return false;
    clearTimeout(entry.timer);
    pending.delete(id);
    entry.reject(fail(`downstream call (id ${id}) was cancelled`, "GATEWAY_DOWNSTREAM_CANCELLED"));
    notify("notifications/cancelled", { requestId: id });
    return true;
  }

  function close() {
    /* CodeRabbit PR #29 review "set closed inside connectStdio's close() method":
     * closed was previously only set by the child's own "close"/"error" events, which
     * fire asynchronously after this function returns. In that gap, call()/notify()'s own
     * `if (closed) return...` guards (above) would not yet trip, so a caller invoking
     * either between this close() and the child actually exiting could still write to
     * child.stdin after .end() -- child.stdin has no "error" listener, so that write
     * throws as an unhandled stream error. Set the flag synchronously, first. */
    closed = true;
    if (!closeError) closeError = fail("downstream connection is closed", "GATEWAY_DOWNSTREAM_DISCONNECTED");
    try { child.stdin.end(); } catch (error) { /* best effort */ }
    try { child.kill(); } catch (error) { /* best effort */ }
  }

  return {
    transport: "stdio",
    call,
    notify,
    cancel,
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
  /* Distinct from `closed` (a local, caller-driven "we're done with this connection"
   * flag): this tracks the last OBSERVED network outcome, so buildHealthStatus's
   * reachability signal reflects reality instead of a flag that only ever gets set by
   * this client's own close(). Starts true (optimistic) since no request has failed yet;
   * a single request error or timeout flips it false, and the next request that actually
   * completes (success OR a well-formed RPC error -- either proves the endpoint is up)
   * flips it back true. */
  let reachable = true;
  const notificationHandlers = []; // never fired: plain request/response HTTP has no server push

  function call(method, params, timeoutMs, onIdAssigned) {
    if (closed) return Promise.reject(fail("downstream connection is closed", "GATEWAY_DOWNSTREAM_DISCONNECTED"));
    const id = nextId++;
    if (typeof onIdAssigned === "function") onIdAssigned(id);
    const isStatelessMetaMethod = STATELESS_META_METHODS.has(method);
    /* See buildStatelessMeta's header comment: this leg is stateless per-request, so
     * every request under a method the stateless MCP protocol requires _meta on gets
     * one attached here, centrally, rather than at each call site -- a caller-supplied
     * _meta (if any) wins over the generated one, field by field. */
    const effectiveParams = isStatelessMetaMethod
      ? { ...(params || {}), _meta: { ...buildStatelessMeta(options), ...((params && params._meta) || {}) } }
      : params;
    /* The mirrored header (below) must agree with whatever protocol version this
     * request's own body actually declares -- STATELESS_META_PROTOCOL_VERSION for a
     * _meta-carrying request, the legacy MCP_PROTOCOL_VERSION for "initialize" (which
     * carries no _meta at all) -- or mcp-server's own header/body agreement check
     * (validateMirroredHeaders) rejects the disagreement with HEADER_MISMATCH. */
    const declaredProtocolVersion = isStatelessMetaMethod ? STATELESS_META_PROTOCOL_VERSION : MCP_PROTOCOL_VERSION;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params: effectiveParams });
    return new Promise((resolve, reject) => {
      let settled = false;
      const settleResolve = (value) => { if (!settled) { settled = true; clearTimeout(absoluteDeadline); resolve(value); } };
      const settleReject = (error) => { if (!settled) { settled = true; clearTimeout(absoluteDeadline); reject(error); } };
      /* Absolute wall-clock deadline on receiving the COMPLETE response body, separate
       * from req.setTimeout below (which only trips on socket INACTIVITY -- a downstream
       * that keeps trickling bytes slowly enough to stay "active" would never trip it,
       * per MAX_HTTP_RESPONSE_BYTES's header comment). */
      const absoluteDeadline = setTimeout(() => {
        reachable = false;
        req.destroy();
        settleReject(fail(`downstream HTTP response deadline exceeded after ${timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS}ms`, "GATEWAY_DOWNSTREAM_TIMEOUT"));
      }, timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS);
      if (typeof absoluteDeadline.unref === "function") absoluteDeadline.unref();
      const req = client.request(
        url,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body),
            /* Mirrors the Streamable HTTP "Request Metadata" headers this repo's own MCP
             * HTTP server requires on every request (mcp-server/src/httpTransport.js) --
             * a downstream that enforces the same contract (including this repo's own
             * server, fronted as a downstream) would otherwise reject every request for
             * missing headers regardless of authentication. */
            "mcp-protocol-version": declaredProtocolVersion,
            "mcp-method": method,
            ...(method === "tools/call" && params && typeof params.name === "string" ? { "mcp-name": params.name } : {}),
            ...(options.headers || {}),
          },
        },
        (res) => {
          const chunks = [];
          let bytesReceived = 0;
          res.on("data", (chunk) => {
            if (settled) return;
            bytesReceived += chunk.length;
            if (bytesReceived > MAX_HTTP_RESPONSE_BYTES) {
              reachable = false;
              req.destroy();
              settleReject(fail(`downstream HTTP response exceeded the ${MAX_HTTP_RESPONSE_BYTES}-byte limit`, "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"));
              return;
            }
            chunks.push(chunk);
          });
          res.on("end", () => {
            if (settled) return;
            let parsed;
            try {
              parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            } catch (error) {
              settleReject(fail(`downstream HTTP response was not valid JSON: ${error.message}`, "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"));
              return;
            }
            /* Fail-closed on the response envelope itself (matching the stdio path's own
             * strict id-correlation discipline): a wrong/missing JSON-RPC id, a wrong/
             * missing "jsonrpc" version, or a non-response object are all rejected rather
             * than attested as this call's real result. Codex PR #29 review round 3
             * "require a result or error in HTTP responses": this previously stopped short
             * of the stdio path's own "neither/both result-and-error present" check, so an
             * envelope with the right jsonrpc/id but no "result" and no "error" (e.g.
             * `{"jsonrpc":"2.0","id":1}`) fell through to the success branch below and
             * resolved `undefined` as though the call had genuinely succeeded. */
            const hasResult = parsed && typeof parsed === "object" && Object.prototype.hasOwnProperty.call(parsed, "result");
            const hasError = parsed && typeof parsed === "object" && Object.prototype.hasOwnProperty.call(parsed, "error");
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.jsonrpc !== "2.0" || parsed.id !== id || (!hasResult && !hasError) || (hasResult && hasError)) {
              settleReject(fail(`downstream HTTP response was not a well-formed JSON-RPC 2.0 response matching request id ${id}`, "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"));
              return;
            }
            reachable = true; // a well-formed response (success or RPC error) proves the endpoint IS reachable
            if (parsed.error) {
              settleReject(Object.assign(fail(parsed.error.message || "downstream error", "GATEWAY_DOWNSTREAM_RPC_ERROR"), { rpcError: parsed.error }));
            } else {
              settleResolve(parsed.result);
            }
          });
        }
      );
      req.on("error", (error) => {
        reachable = false;
        settleReject(fail(`downstream HTTP request failed: ${error.message}`, "GATEWAY_DOWNSTREAM_DISCONNECTED"));
      });
      req.setTimeout(timeoutMs || DEFAULT_REQUEST_TIMEOUT_MS, () => {
        reachable = false;
        req.destroy(fail("downstream HTTP request timed out", "GATEWAY_DOWNSTREAM_TIMEOUT"));
      });
      req.end(body);
    });
  }

  /** Plain request/response HTTP has no way to abort work already handed to the
   * downstream (the request is already sent; there is no persistent connection to send a
   * follow-up cancellation notification over, per this transport's own doc comment
   * above). Best-effort no-op, disclosed rather than pretending to cancel. */
  function cancel() {
    return false;
  }

  function notify(method, params) {
    /* CodeRabbit PR #29 review "send notifications/initialized without an id": call()
     * unconditionally assigns a JSON-RPC `id` (nextId++), which turns every notification
     * sent through it into a request instead -- a real protocol violation (JSON-RPC 2.0 /
     * MCP both define a notification as exactly "no id member"), and a conforming
     * downstream is free to reject it. Post the notification directly, with no id, rather
     * than delegating to call().
     *
     * Codex PR #29 review round 5 "await HTTP initialized delivery before listing
     * tools": this used to fire-and-forget with no way for a caller to know the request
     * had actually been sent, so connectAllDownstreams's own initialize -> notify
     * ("notifications/initialized") -> tools/list sequence issued tools/list on a
     * separate, unordered HTTP request/socket without waiting for the notification to
     * even leave this process -- a strict, stateful downstream enforcing MCP's own
     * "initialized before further requests" ordering could receive or process tools/list
     * first and reject the handshake. Returns a Promise that resolves once this request
     * SETTLES (success or failure) rather than a raw fire-and-forget void -- this stays
     * best-effort in that a network failure here is never surfaced to the caller as a
     * rejection (a downstream that is unreachable is not this caller's problem, matching
     * call()'s own "closed" short-circuit); only the TIMING is now observable, bounded by
     * the same DEFAULT_REQUEST_TIMEOUT_MS every other request in this file uses, so an
     * unresponsive downstream cannot hang a caller that awaits this indefinitely. */
    if (closed) return Promise.resolve();
    const isStatelessMetaMethod = STATELESS_META_METHODS.has(method);
    const effectiveParams = isStatelessMetaMethod
      ? { ...(params || {}), _meta: { ...buildStatelessMeta(options), ...((params && params._meta) || {}) } }
      : params;
    const declaredProtocolVersion = isStatelessMetaMethod ? STATELESS_META_PROTOCOL_VERSION : MCP_PROTOCOL_VERSION;
    // No "id" field: this must stay a real JSON-RPC/MCP notification (see comment above),
    // unlike call()'s request body which always assigns one.
    const body = JSON.stringify({ jsonrpc: "2.0", method, params: effectiveParams });
    return new Promise((resolve) => {
      let settled = false;
      const settle = () => { if (!settled) { settled = true; clearTimeout(timer); resolve(); } };
      const timer = setTimeout(settle, DEFAULT_REQUEST_TIMEOUT_MS);
      if (typeof timer.unref === "function") timer.unref();
      const req = client.request(url, {
        method: "POST",
        // Mirrors call()'s own header construction above (kept in sync manually --
        // notify() has no id/response to correlate, so it cannot share call()'s promise body).
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          "mcp-protocol-version": declaredProtocolVersion,
          "mcp-method": method,
          ...(method === "tools/call" && params && typeof params.name === "string" ? { "mcp-name": params.name } : {}),
          ...(options.headers || {}),
        },
      });
      req.on("error", () => { reachable = false; settle(); }); // best-effort: nothing to reject, no caller treats this as a failure
      req.on("response", (res) => { res.resume(); res.on("end", settle); res.on("error", settle); }); // drain and discard; notify() never reads a result
      req.end(body);
    });
  }

  function close() {
    closed = true;
  }

  return {
    transport: "http",
    call,
    notify,
    cancel,
    close,
    onNotification: (handler) => notificationHandlers.push(handler),
    isClosed: () => closed,
    isReachable: () => reachable,
    whenClosed: () => Promise.resolve(null),
  };
}

/** Connects to one configured downstream server per its `transport`. `serverConfig.
 * token_ref`, when present (http only -- board decision 2026-09-04, PR #29 review "speak
 * authenticated MCP over downstream HTTP"), is resolved via config.js's own
 * resolveSecretRef (the same "env var name or file path, never the raw secret"
 * convention signing_key_ref and agent_listen.token_ref already use) and sent as a
 * standard bearer Authorization header -- this repo's own MCP HTTP server, and any
 * downstream enforcing the same contract, requires one on every request. */
function connectDownstream(serverConfig, options = {}) {
  if (serverConfig.transport === "stdio") return connectStdio(serverConfig.endpoint, options);
  if (serverConfig.transport === "http") {
    let httpOptions = options;
    if (serverConfig.token_ref) {
      const token = resolveSecretRef(serverConfig.token_ref, `downstream_servers["${serverConfig.name}"].token_ref`);
      httpOptions = { ...options, headers: { ...(options.headers || {}), authorization: `Bearer ${token}` } };
    }
    return connectHttp(serverConfig.endpoint, httpOptions);
  }
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
  /* Codex PR #29 review round 3 "store server information without prototype-sensitive
   * keys": downstream server names are arbitrary configured strings, and a plain object
   * literal treats a name of "__proto__" as a prototype assignment rather than an
   * enumerable own property -- silently corrupting this object's prototype instead of
   * recording that server's info, while the server's tools remain routable through the
   * (Map-keyed, not affected by this) toolOwners/mergedTools structures. A null-prototype
   * object accepts any string as a genuine own key. */
  const serverInfos = Object.create(null);
  try {
    for (const serverConfig of downstreamServers) {
      let conn;
      try {
        /* Codex PR #29 review round 4 "preserve the originating server for sampling": the
         * shared `options.onRequest` (when provided) previously reached every downstream
         * connection completely unchanged, so nothing in that shared closure could tell
         * which configured server actually emitted a given unsolicited request -- every
         * downstream-initiated sampling call was attributed to a single placeholder
         * instead of the real originating server. Bind this server's own name into its
         * own connection's callback here, once, rather than have every caller of
         * connectAllDownstreams re-derive it. */
        const perServerOptions = typeof options.onRequest === "function"
          ? { ...options, onRequest: (msg) => options.onRequest(msg, serverConfig.name) }
          : options;
        conn = connectDownstream(serverConfig, perServerOptions);
        /* Full MCP initialize params (protocolVersion + capabilities, not just
         * clientInfo) -- a downstream that actually validates the initialization
         * contract (this repo's own MCP server included) rejects a request missing
         * either. Followed by the required post-initialize "initialized" notification
         * before this client is allowed to send any other request (tools/list here) --
         * skipping it left the handshake incomplete even though the permissive test
         * fixture tolerated it.
         *
         * Codex PR #29 review round 4 "advertise sampling before accepting sampling
         * requests": gateway.js only ever relays a downstream's sampling/createMessage
         * request when the agent transport is stdio (the only transport that can push a
         * request to the agent) -- but this call previously declared `capabilities: {}`
         * unconditionally, so a conforming downstream server would never send that
         * request in the first place, having negotiated that this client supports no
         * optional capabilities. Advertise the sampling client capability exactly when
         * the caller says the agent transport can actually relay it. */
        const initResult = await conn.call("initialize", {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: options.supportsSampling ? { sampling: {} } : {},
          clientInfo: options.clientInfo || { name: "graphsmith-standalone-gateway", version: "1.0" },
        });
        serverInfos[serverConfig.name] = (initResult && initResult.serverInfo) || null;
        /* Codex PR #29 review round 5 "await HTTP initialized delivery before listing
         * tools": notify() now returns a Promise that resolves once this notification
         * has actually settled (see its own header comment in connectHttp) -- awaited
         * here so tools/list below is never issued before "notifications/initialized"
         * has been sent, closing the ordering gap a strict, stateful HTTP downstream
         * could otherwise observe. connectStdio's own notify() returns no Promise; await
         * on a non-thenable resolves on the next microtask, so this line is a no-op wait
         * for stdio downstreams, not a behavior change for them. */
        await conn.notify("notifications/initialized", {});

        /* Follows tools/list's nextCursor until the downstream reports none, so a
         * paginated surface is fully advertised rather than silently truncated to its
         * first page. Bounded (page cap + cursor-cycle detection, AND cumulative byte
         * size -- see MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES above) so a downstream that never
         * terminates pagination, or returns unboundedly large pages, fails this server's
         * startup instead of hanging or exhausting memory. */
        const tools = [];
        const seenCursors = new Set();
        let cursor;
        let pages = 0;
        let totalToolsBytes = 0;
        do {
          const toolsResult = await conn.call("tools/list", cursor !== undefined ? { cursor } : {});
          /* Codex PR #29 review "reject malformed tools/list payloads": a well-formed
           * JSON-RPC envelope whose "tools" field is present but not an array (or empty)
           * would previously fall through to the "[]" default -- gateway startup then
           * succeeds with a silently truncated (or entirely empty) tool surface instead
           * of failing loudly, unlike this same function's own tool-name-collision and
           * pagination-loop guards a few lines below. Round 3 tightened this further
           * ("require the tools array in every tools/list result"): the MCP spec requires
           * "tools" to be present (as an array, possibly empty) on every successful
           * tools/list result, but the check above only rejected a WRONG-TYPE "tools" --
           * a result missing the property entirely (e.g. `{}`) still silently fell through
           * to the same "[]" default this comment already flags as the wrong behavior. */
          if (!toolsResult || typeof toolsResult !== "object" || !Object.prototype.hasOwnProperty.call(toolsResult, "tools") || !Array.isArray(toolsResult.tools)) {
            throw fail(
              `downstream server "${serverConfig.name}" returned a malformed tools/list result: "tools" must be ` +
                `present and an array (got ${toolsResult && typeof toolsResult === "object" ? typeof toolsResult.tools : "no result object"}).`,
              "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"
            );
          }
          const pageTools = toolsResult.tools;
          for (const tool of pageTools) {
            if (!tool || typeof tool !== "object" || typeof tool.name !== "string" || tool.name.length === 0) {
              throw fail(
                `downstream server "${serverConfig.name}" returned a malformed tool descriptor in tools/list ` +
                  `(missing or invalid "name").`,
                "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"
              );
            }
            /* Codex PR #29 review round 5 "reject tool descriptors without a valid input
             * schema": the check above validates only "name" -- a descriptor such as
             * {"name":"x"} (no inputSchema at all) previously passed, was normalized to
             * `schema: null` a few lines below, and was forwarded to agents as a tool
             * with no input contract. The MCP Tool schema requires inputSchema on every
             * tool; a client that validates the advertised contract can reject this
             * gateway's otherwise successful tools/list over a single misbehaving
             * downstream tool descriptor. */
            if (!tool.inputSchema || typeof tool.inputSchema !== "object" || Array.isArray(tool.inputSchema)) {
              throw fail(
                `downstream server "${serverConfig.name}" returned a malformed tool descriptor for ` +
                  `"${tool.name}" in tools/list (missing or invalid "inputSchema": must be an object).`,
                "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"
              );
            }
          }
          tools.push(...pageTools);
          totalToolsBytes += Buffer.byteLength(JSON.stringify(pageTools));
          if (totalToolsBytes > MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES) {
            throw fail(
              `downstream server "${serverConfig.name}" tools/list surface exceeded the cumulative ` +
                `${MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES}-byte cap across its paginated pages`,
              "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"
            );
          }
          pages++;
          const nextCursor = toolsResult && toolsResult.nextCursor;
          if (nextCursor === undefined || nextCursor === null) {
            cursor = undefined;
          } else if (pages >= MAX_TOOLS_LIST_PAGES || seenCursors.has(nextCursor)) {
            throw fail(
              `downstream server "${serverConfig.name}" tools/list pagination did not terminate ` +
                `(page cap ${MAX_TOOLS_LIST_PAGES} reached or a repeated cursor was returned)`,
              "GATEWAY_DOWNSTREAM_PAGINATION_LOOP"
            );
          } else {
            seenCursors.add(nextCursor);
            cursor = nextCursor;
          }
        } while (cursor !== undefined);

        for (const tool of tools) {
          if (toolOwners.has(tool.name)) {
            throw fail(
              `Refusing to start: tool name "${tool.name}" is advertised by both downstream server ` +
                `"${toolOwners.get(tool.name)}" and "${serverConfig.name}" -- configure unique tool ` +
                "names across downstreams (colliding names would silently route an agent's call for " +
                "the second server's tool to the first server's implementation).",
              "GATEWAY_TOOL_NAME_COLLISION"
            );
          }
          // Preserve the tool's full descriptor (description, annotations, outputSchema,
          // etc.) rather than keeping only name+schema -- GatewayProxy's tools/list
          // response reads t.description, which a narrower projection would discard.
          const owned = { ...tool, name: tool.name, server: serverConfig.name, schema: tool.inputSchema || tool.schema || null };
          mergedTools.push(owned);
          toolOwners.set(tool.name, serverConfig.name);
        }
      } catch (error) {
        if (conn) { try { conn.close(); } catch (closeError) { /* best effort */ } }
        if (error.code === "GATEWAY_TOOL_NAME_COLLISION" || error.code === "GATEWAY_DOWNSTREAM_PAGINATION_LOOP" || error.code === "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE") throw error;
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
  MAX_HTTP_RESPONSE_BYTES,
  MAX_TOTAL_TOOLS_DESCRIPTOR_BYTES,
  nextResidualLineBytes,
}
