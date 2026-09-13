#!/usr/bin/env node
/* GraphSmith standalone gateway -- process entry point and lifecycle (Standalone
 * Gateway TRD SS3.7/SS3.8, SG-FR-1 through SG-FR-5, SG-FR-7). Ties together:
 *   - mode-gate.js       SG-FR-1/SG-FR-2, checked FIRST, ahead of even writer-claim (SS3.8)
 *   - config.js          SS4 config schema
 *   - writer-claim.js    FR-1..FR-4, reused unchanged (SS3.7)
 *   - downstream.js       SS3.1/SS3.2
 *   - proxy.js            SS3.3/SS6 dispatch (session capture/correlation/finalization)
 *   - chain.js            SG-FR-5 persistence
 *
 * Agent-facing transport: stdio is this build's primary, fully-exercised path (one
 * process, one connection, matching mcp-server/src/stdioTransport.js's own framing and
 * this codebase's existing "the OS process boundary IS the trust boundary" convention
 * for stdio). An HTTP agent-facing listener is also implemented (config `agent_listen.
 * transport: "http"`) for the "multiple concurrent agents" scenario (SS8 test 3) --
 * sessions are keyed by an explicit, server-minted `Mcp-Session-Id` (board decision
 * 2026-09-08; see scripts/gateway/agent-transport.js#runHttpAgentTransport's own header
 * comment), not by TCP socket, so multiple logical sessions can even share one
 * connection-pooling backend socket without colliding.
 *
 * Zero-dependency, Node >= 18.
 */
"use strict";

const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const modeGate = require("./mode-gate.js");
const gatewayConfig = require("./config.js");
const chain = require("./chain.js");
const session = require("./session.js");
const { GatewayProxy, MAX_PENDING_CALLS_PER_SESSION, MAX_COMPLETED_CALLS_PER_SESSION } = require("./proxy.js");
const downstream = require("./downstream.js");
const { runStdioAgentTransport, runHttpAgentTransport } = require("./agent-transport.js");
const writerClaimModule = require("../writer-claim.js");
const { WriterClaim } = writerClaimModule;
const registerGatewaySessions = require("../../checks/register-gateway-sessions.js");
const stateStore = require("../state-store.js");

/** SS3.7's bounded drain: waits (polling) until every open session on `proxy` has no
 * calls still in flight, or `timeoutMs` elapses, whichever first. Extracted as its own
 * function so it is unit-testable directly against a GatewayProxy + fake slow downstream
 * connection, without needing a real OS SIGTERM (which Windows cannot deliver for
 * graceful in-process handling -- see tests/gateway/e2e's own header comment). Returns
 * true if drained cleanly, false if the timeout was hit with calls still pending. */
async function drainOpenSessions(proxy, timeoutMs, pollMs = 25) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const stillInFlight = Array.from(proxy.sessions.values()).some((s) => s.pendingCalls.size > 0);
    if (!stillInFlight) return true;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return !Array.from(proxy.sessions.values()).some((s) => s.pendingCalls.size > 0);
}

/* Codex PR #29 review round 3 "preserve the configured shutdown deadline for HTTP
 * calls": Node's http.Server#close() waits for every still-active response to finish
 * before its callback fires -- a request still awaiting a slow (up to
 * DEFAULT_REQUEST_TIMEOUT_MS, 30s) downstream call can hold shutdown well past the
 * nominal drainTimeoutMs (default 5s) drain cap above. This bounds how long doStop()
 * will wait for the listener to close cleanly before force-terminating any sockets
 * still open on it, so a slow HTTP call can no longer extend shutdown indefinitely. */
const HTTP_LISTENER_CLOSE_TIMEOUT_MS = 2000;

/* Codex PR #29 review round 8 "install shutdown handlers before gateway startup
 * completes": before this, main() only registers SIGTERM/SIGINT handlers AFTER
 * startGateway() resolves -- a termination signal received while a slow downstream
 * handshake is still in progress fell through to Node's default immediate-exit behavior,
 * skipping cleanup of an already-acquired writer-claim and any already-spawned stdio
 * downstream children (leaking both: a stale claim blocking the next start, and orphaned
 * child processes). The 5-model external panel's majority position (Paul-approved) was
 * explicitly AGAINST building a signal handler that tries to safely tear down
 * partially-initialized startup state -- that is a real correctness risk on the
 * WriterClaim lock-safety path, worse than the status quo. This bounds the slow step
 * itself instead: if the downstream-connection phase (connectAllDownstreams below --
 * empirically the one startup step with no bound of its own, unlike every downstream RPC
 * inside it, which already times out via DEFAULT_REQUEST_TIMEOUT_MS) hasn't completed
 * within this deadline, it is routed through the SAME startup-failure path an outright
 * connection failure already uses (writerClaim.release() + rethrow) rather than left to
 * hang indefinitely waiting for a signal handler that isn't installed yet. Comfortably
 * exceeds DEFAULT_REQUEST_TIMEOUT_MS (downstream.js, 30s) -- a downstream pagination
 * handshake can legitimately need more than one such round trip -- while still being a
 * fixed, non-speculative bound (same discipline as every other *_TIMEOUT_MS constant in
 * this codebase), not an unbounded wait. Overridable via options for tests that need a
 * short deadline to run fast (mirrors drainTimeoutMs/statusWriteIntervalMs's own
 * options-override pattern below). */
const STARTUP_DOWNSTREAM_CONNECT_TIMEOUT_MS = 60000;

function fail(message, code = "GATEWAY_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

/** Races `promise` against a bounded timeout, rejecting with `makeError()` if the timeout
 * elapses first. `promise` itself is NOT cancelled on timeout (there is no cancellation
 * primitive for an in-flight downstream handshake) -- see startGateway's own call site for
 * how it best-effort cleans up a connect that finishes late, after this has already given
 * up on it. */
function withTimeout(promise, timeoutMs, makeError) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(makeError());
    }, timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
    promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

/** Answers a downstream server's own unsolicited request (board decision 2026-09-04, PR
 * #29 review "forward downstream sampling requests upstream"). Only `sampling/
 * createMessage` is recognized -- the one MCP-defined case of a server asking the
 * client's model to do inference. Only forwarded when `agentPusher.current` is set,
 * which gateway.js's own startGateway() only ever does for the stdio agent transport
 * (the only one that can push a request to the agent rather than merely reply to one --
 * see agent-transport.js's header). Any other case (an http agent transport, or no agent
 * currently connected) gets a real JSON-RPC error naming exactly why, rather than the
 * silent drop this was before. */
function forwardDownstreamRequestToAgent(msg, agentPusher, log, proxy, serverName) {
  if (msg.method !== "sampling/createMessage") {
    return Promise.resolve({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `This gateway does not forward downstream-initiated method "${msg.method}" to the agent.` } });
  }
  if (!agentPusher.current) {
    return Promise.resolve({
      jsonrpc: "2.0",
      id: msg.id,
      error: {
        code: -32000,
        message:
          'Forwarding a downstream server\'s "sampling/createMessage" request to the agent is only ' +
          "supported when this gateway's agent_listen.transport is \"stdio\" (stdio is the only agent " +
          "transport that can push a request to the agent rather than only reply to one it sent). This " +
          "gateway is not currently configured for stdio agent transport, or no agent is connected.",
      },
    });
  }
  /* Codex PR #29 review "record downstream-initiated sampling in the session": this
   * forward previously ran entirely outside session.js's bookkeeping -- the sealed
   * bundle for the connection that actually observed and relayed this model invocation
   * never recorded it (model_call:true and its hashed input/result), even though the
   * gateway genuinely handled it. An attestation gap, not just a missing log line.
   * agentPusher.connectionId unambiguously names the one session this belongs to: this
   * branch is only ever reachable when agentPusher.current is set, which gateway.js only
   * does for the stdio agent transport (see this function's own doc above), and stdio is
   * a strict one-process-one-connection transport (agent-transport.js's own header). */
  const s = proxy && agentPusher.connectionId ? proxy.sessions.get(agentPusher.connectionId) : null;
  const correlationKey = s ? Symbol("downstream-initiated-sample") : null;
  const startTs = proxy ? proxy.now() : Date.now();
  /* Codex PR #29 review round 4 "preserve the originating server for sampling": with
   * multiple stdio downstreams configured, every connection's onRequest callback used to
   * be this exact same function reference, so nothing here could tell which downstream
   * server actually emitted the request -- every sampling step was recorded and logged
   * under the placeholder server name "sampling" regardless of which real downstream
   * initiated it. `serverName` is now bound per-connection by connectAllDownstreams (see
   * downstream.js), so fall back to the old placeholder only for a caller that predates
   * this parameter (there is none in this codebase, but this keeps the function honest
   * about its own default rather than crashing on a missing argument). */
  const recordedServerName = serverName || "sampling";
  /* Codex PR #29 review round 6 "bound downstream-pushed sampling calls": this path
   * records and forwards every downstream-initiated sampling request unconditionally,
   * unlike GatewayProxy#handleMessage's own agent-initiated dispatch (proxy.js), which
   * refuses to admit another concurrent call once a session already has
   * MAX_PENDING_CALLS_PER_SESSION genuinely pending. Without the same admission bound
   * here, a faulty or compromised sampling-capable stdio downstream could still exhaust
   * memory via this separate route despite that cap. Mirrors proxy.js's own error shape. */
  if (s && s.pendingCalls.size >= MAX_PENDING_CALLS_PER_SESSION) {
    return Promise.resolve({
      jsonrpc: "2.0",
      id: msg.id,
      error: {
        code: -32000,
        message: `This session already has ${MAX_PENDING_CALLS_PER_SESSION} call(s) pending -- refusing to admit another concurrent downstream-initiated sampling call until at least one resolves.`,
      },
    });
  }
  /* Codex PR #29 review round 8 "cap completed downstream sampling history": proxy.js's
   * own agent-initiated dispatch (GatewayProxy#handleMessage) additionally enforces
   * MAX_COMPLETED_CALLS_PER_SESSION -- bounding session.calls itself, not just calls
   * genuinely in flight -- but this separate downstream-initiated sampling path never
   * consulted it. A sampling-capable stdio downstream that issues requests SEQUENTIALLY
   * (each response removing the prior request from pendingCalls before the next starts)
   * never trips the pending-call check above, so this path could append to session.calls
   * without bound over an indefinitely-connected downstream's lifetime, exhausting memory.
   * Mirrors proxy.js's own admission-refusal shape exactly (same code, same message
   * template, same s.calls.length + s.pendingCalls.size admission math as that file's own
   * post-round-8 fix) so both paths present one consistent contract to whatever is on the
   * other end of a session. */
  if (s && s.calls.length + s.pendingCalls.size >= MAX_COMPLETED_CALLS_PER_SESSION) {
    return Promise.resolve({
      jsonrpc: "2.0",
      id: msg.id,
      error: {
        code: -32000,
        message: `This session has already completed ${MAX_COMPLETED_CALLS_PER_SESSION} call(s) -- refusing to admit another call on this connection; start a new session.`,
      },
    });
  }
  if (s) {
    session.recordCallStart(s, correlationKey, {
      tool: "sampling/createMessage",
      server: recordedServerName,
      arguments: msg.params,
      isModelCall: true,
      ts: startTs,
    });
  }
  /* Codex PR #29 review round 3 "log completed downstream-initiated sampling steps":
   * proxy.js's own agent-initiated call path (GatewayProxy#handleMessage) emits a
   * structured "gateway_call_completed" log line for every call it records -- this
   * separate downstream-initiated sampling path records the same kind of execution-trace
   * step (model_call:true) but previously emitted no matching completion log on success,
   * and its failure log above lacked the connection id, step, status, and duration every
   * other completed-call log line carries. Mirror that same structured shape here so a
   * session containing a downstream-initiated sampling call has a complete, consistent
   * operational log regardless of which side (agent or downstream) initiated the call. */
  function logCompletion(isError) {
    const completedAt = proxy ? proxy.now() : Date.now();
    const recordedCall = s ? s.calls[s.calls.length - 1] : null;
    log(JSON.stringify({
      event: "gateway_call_completed",
      connection_id: agentPusher.connectionId || null,
      step: recordedCall ? recordedCall.seq : null,
      tool: "sampling/createMessage",
      server: recordedServerName,
      status: isError ? "error" : "ok",
      duration_ms: completedAt - startTs,
    }));
  }
  return agentPusher.current(msg.method, msg.params).then(
    (result) => {
      /* Mirrors proxy.js's own "correlatedNow" guard (CodeRabbit PR #29 review, round 1):
       * the session can finalize (agent disconnects) while this forwarded request is
       * still in flight awaiting the agent's model. Only record if it's still genuinely
       * pending, so this never throws SESSION_FINALIZED or logs a spurious anomaly for an
       * entry the gateway itself already removed. */
      const correlatedNow = s && !s.finalized && s.pendingCalls.has(correlationKey);
      if (correlatedNow) {
        session.recordCallResult(s, correlationKey, { result, isError: false, ts: proxy.now() });
        logCompletion(false);
      }
      return { jsonrpc: "2.0", id: msg.id, result };
    },
    (error) => {
      const correlatedNow = s && !s.finalized && s.pendingCalls.has(correlationKey);
      /* Codex PR #29 review round 4 "emit only one log line for sampling failures":
       * this used to unconditionally log the plain diagnostic below AND, when
       * correlatedNow, also call logCompletion(true) -- double-logging the same failed
       * step and violating AGENTS.md's "one log line per step" contract. The structured
       * completion record already carries the failure (status:"error"); only fall back to
       * the plain diagnostic when there is no session to record a structured line against
       * in the first place, so every failure still gets exactly one log line either way.
       *
       * CodeRabbit PR #29 review round 4 "use the fallback only when no session exists":
       * `correlatedNow` also goes false once a stdio agent disconnect has already run this
       * call through closeConnection/handleDownstreamDisconnect's own pending-call
       * cleanup (session.markPendingAsDisconnected) -- and that cleanup already emitted
       * this exact step's structured gateway_call_completed/status:"disconnected" log via
       * its onDisconnect callback (see proxy.js#logDisconnectedCall). `s` is still truthy
       * in that case (the session object itself isn't gone, just this call's pending
       * entry), so the old unconditional `else` fired the plain diagnostic below on top of
       * that already-emitted completion log -- two log lines for one step. Only fall back
       * to the plain diagnostic when there was never a session to correlate against at
       * all, so a disconnect-during-forward gets exactly the one completion log
       * closeConnection/handleDownstreamDisconnect already recorded, not a second one. */
      if (correlatedNow) {
        session.recordCallResult(s, correlationKey, { result: { error: error.message }, isError: true, ts: proxy.now() });
        logCompletion(true);
      } else if (!s) {
        log(`downstream sampling/createMessage forward to agent failed: ${error.message}`);
      }
      return { jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: error.message } };
    }
  );
}

/** Codex PR #29 review "surface unmatched stdio responses to the session recorder": a
 * stdio downstream response whose id has no live pending call (already timed out, or a
 * downstream fabricating/replaying an id this gateway never sent) previously vanished
 * silently at the transport layer (downstream.js), even though that file's own doc
 * comment already promised the session-correlation layer records it as an anomaly --
 * nothing actually wired the two together. Mirrors forwardDownstreamRequestToAgent's own
 * attribution rule just above: a downstream connection is shared by every currently open
 * agent session, so this can only be honestly attributed to ONE session's sealed audit
 * trail when this gateway's agent transport is stdio (the one transport that can only
 * ever have a single open session -- agentPusher.connectionId names it; see that
 * function's own header for why). Any other case (HTTP agent transport with zero or
 * multiple concurrent sessions, or no agent currently connected) still surfaces the
 * observed protocol violation, just as a plain operational log line naming the
 * originating server -- recording it against an arbitrarily-chosen session's audit trail
 * would misattribute a violation this gateway cannot actually pin on that session. */
function recordUnmatchedDownstreamResponse(msg, agentPusher, log, proxy, serverName) {
  const s = proxy && agentPusher.connectionId ? proxy.sessions.get(agentPusher.connectionId) : null;
  if (s && !s.finalized) {
    /* CodeRabbit PR #29 review round 8 "record unmatched downstream responses without
     * agent-call correlation" / Codex PR #29 review round 8 "keep unmatched downstream IDs
     * out of agent correlation": msg.id here is the DOWNSTREAM leg's own internal id
     * (downstream.js's own numbering), not an agent-facing JSON-RPC id -- session.
     * pendingCalls (which recordCallResult looks up by id) is keyed by the latter. Calling
     * recordCallResult(s, msg.id, ...) risked colliding with an unrelated LIVE agent call
     * that happens to share the same id value: a late response for a timed-out downstream
     * id "1" arriving while a different live agent request also has id "1" would be
     * (mis)treated as correlated, deleting that still-live pending call from pendingCalls
     * and sealing this stale/foreign response as its result -- corrupting the session trace
     * and losing the UNMATCHED_RESPONSE anomaly entirely. Use the dedicated helper, which
     * only ever appends the anomaly and never touches pendingCalls. */
    session.recordUnmatchedResponseAnomaly(
      s,
      msg.id,
      "response arrived on a downstream connection with an id that does not correlate to any agent-facing pending call",
      proxy.now()
    );
    return;
  }
  log(JSON.stringify({ event: "gateway_unmatched_downstream_response", server: serverName || null, id: msg.id }));
}

function loadSigningKeys(config) {
  const material = gatewayConfig.resolveSecretRef(config.signing_key_ref, "signing_key_ref");
  /* The signing_key_ref convention (SS4) is "a reference ... never the raw key
   * material" -- resolved to a PEM-encoded ed25519 private key by this build (the same
   * algorithm gsa-mcp-shim.js's own selftest and gsa-produce.js's other callers use). A
   * deployment that has not yet provisioned one can point signing_key_ref at any file/
   * env var; if it isn't a valid PEM this throws a clear, named error rather than
   * silently sealing unsigned/garbage bundles. */
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(material);
  } catch (error) {
    throw fail(`signing_key_ref did not resolve to a valid private key: ${error.message}`, "GATEWAY_BAD_SIGNING_KEY");
  }
  /* createPrivateKey() happily accepts an RSA or EC key too -- Node can sign with either
   * -- but this build unconditionally labels the key "ed25519" regardless of what was
   * actually loaded. gsa-verify.js#44-49 rejects a declared-algorithm/key-type mismatch,
   * so every bundle sealed with a non-ed25519 key would persist successfully and then be
   * unverifiable. Check the real key type before startup completes rather than let that
   * surface only much later, at verify time. */
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw fail(
      `signing_key_ref resolved to a ${privateKey.asymmetricKeyType || "unknown"} key, but this gateway ` +
        'only signs with ed25519 (gsa-verify.js requires the declared algorithm to match the actual key ' +
        "type). Provide an ed25519 private key.",
      "GATEWAY_BAD_SIGNING_KEY"
    );
  }
  return { privateKey, signer: config.host_id || "graphsmith-standalone-gateway", algo: "ed25519" };
}

/** SS3.8: the very first check, ahead of even writer-claim acquisition. Returns
 * { dormant: true } if attach mode is active (not an error -- SS3.8: "log that
 * standalone is dormant and exit 0"). Throws (fail-closed) on every other SS7 condition. */
function checkModeGate(root, log) {
  try {
    const record = modeGate.readGatewayMode(root, { expectedMode: "standalone" });
    log(`mode-selection: standalone confirmed by "${record.confirmation.confirmed_by}" at ${new Date(record.confirmation.confirmed_at).toISOString()}`);
    return { dormant: false, record };
  } catch (error) {
    if (error.code === "GATEWAY_MODE_WRONG_BINARY") {
      log(`mode-selection: attach mode is active -- standalone gateway is dormant. ${error.message}`);
      return { dormant: true };
    }
    throw error;
  }
}

/** Health/status surface (SG-NFR-3): connected downstream servers and their
 * reachability, active session count, current chain seq/tail hash, time since last
 * persisted bundle, and time since the chain tail was last pushed to the remote anchor
 * (always "not implemented" in this build -- see chain.js#pushChainTailToRemoteAnchor). */
function buildHealthStatus(ctx) {
  const stateDir = ctx.config.state_dir;
  /* Codex PR #29 review "return a health report when HEAD is corrupt": chain.readHead
   * fails closed BY DESIGN (see chain.js's own header) on an unreadable or malformed
   * HEAD.json -- but that throw was previously unguarded here, so the one moment an
   * operator most needs this health surface to keep responding (chain corruption) was
   * exactly the moment it threw instead, taking the whole status/health endpoint down. */
  let head = null;
  let headError = null;
  try {
    head = chain.readHead(stateDir);
  } catch (error) {
    headError = error.message;
  }

  // Time since the last persisted bundle (SG-NFR-3's stated contract): HEAD.json is
  // written last in chain.appendSession's write order, so its own mtime is exactly that.
  let lastPersistedAt = null;
  try {
    lastPersistedAt = fs.statSync(chain.headPath(stateDir)).mtime.toISOString();
  } catch (error) {
    /* ENOENT (nothing persisted yet) or any other stat failure: report null rather than
     * let an operator mistake a missing timestamp for "just persisted". */
  }

  /* SG-FR-7's session-chain integrity walk (checks/register-gateway-sessions.js) existed
   * only as a synthetic --selftest before this: no production code ever actually ran it
   * against this deployment's real on-disk chain. Wiring it into the health surface is a
   * real operational path an operator or monitor can act on -- a non-"verified" result
   * here is a fail-closed, visible signal (tampering, a sequence gap, or an incomplete
   * append), not silently invisible until someone thinks to run --selftest by hand. */
  let sessionChainIntegrity;
  if (headError) {
    // HEAD.json is already known corrupt/unreadable -- don't bother attempting the walk
    // (which needs `head`) just to rediscover the same failure less clearly.
    sessionChainIntegrity = { status: "failed", evidence: [], assumptions: [], failure_domain: "trusted-core", reason: `HEAD.json is corrupt or unreadable: ${headError}` };
  } else {
    try {
      sessionChainIntegrity = registerGatewaySessions.run({
        chain: chain.readChain(stateDir),
        head,
        computeEntrySha256: chain.computeEntrySha256,
        bundleExists: (bundleId) => fs.existsSync(chain.bundlePath(stateDir, bundleId)),
      });
    } catch (error) {
      sessionChainIntegrity = { status: "failed", evidence: [], assumptions: [], failure_domain: "trusted-core", reason: `session-chain verification threw: ${error.message}` };
    }
  }

  return {
    schema_version: "1.0",
    writer_claim: ctx.writerClaim.status(),
    downstream_servers: Array.from(ctx.connections.keys()).map((name) => {
      const conn = ctx.connections.get(name);
      return { name, reachable: typeof conn.isReachable === "function" ? conn.isReachable() : !conn.isClosed() };
    }),
    active_sessions: ctx.proxy.openSessionCount(),
    chain: head
      ? { seq: head.seq, entry_sha256: head.entry_sha256, last_persisted_at: lastPersistedAt }
      : { seq: 0, entry_sha256: null, last_persisted_at: lastPersistedAt, ...(headError ? { error: headError } : {}) },
    session_chain_integrity: sessionChainIntegrity,
    remote_anchor: { implemented: false, reason: "SG-FR-6 not implemented in this build -- see chain.js#pushChainTailToRemoteAnchor" },
  };
}

/* Cluster D: operational exposure for buildHealthStatus(ctx) above. This is a
 * single-tenant, locally-run process (not a hosted service with a real ops network
 * surface) -- SG-NFR-3's health/status report existed only as `.status()` on the
 * in-process handle before this, reachable from a unit test or an embedder that already
 * holds the handle, but from nothing an operator could actually run against a gateway
 * they only know how to reach by its config file (a separate `status` invocation, a cron
 * job, a shell one-liner). A separate ops HTTP port is deliberately out of scope for this
 * fix (it would need its own auth/bind-address story, mirroring agent_listen's own,
 * before it could ship responsibly) -- a periodically-written status FILE plus a `status`
 * CLI subcommand that reads it is the minimal, honest version of "operationally exposed"
 * for a process that already writes durable state to `state_dir` for other reasons. */
const STATUS_FILE_NAME = "gateway-status.json";
/* Fixed, non-speculative default -- same discipline as SESSION_IDLE_TIMEOUT_MS/
 * MAX_HTTP_SESSIONS in agent-transport.js and the MAX_* constants in downstream.js/
 * proxy.js: make it configurable once a real deployment needs a different cadence, not
 * before. 10s keeps `gateway.js status` usefully fresh without meaningfully adding to
 * this process's I/O -- one small JSON write, not on any request's critical path. */
const STATUS_WRITE_INTERVAL_MS = 10000;

function gatewayStatusPath(stateDir) {
  return path.join(stateDir, STATUS_FILE_NAME);
}

/* Best-effort, non-throwing by design: a failure to write the status file (e.g. a
 * momentarily full disk) is an operational inconvenience for whoever next runs `status`,
 * never a reason to disrupt request handling or bring down the gateway process itself --
 * this is purely an observability side channel, not part of SG-FR-5's persisted-session
 * write path. Reuses state-store.js's own atomic-write primitive (temp file + fsync +
 * rename), same as chain.js#appendSession's HEAD.json write, so a reader (the `status`
 * subcommand, or an operator's own tool) can never observe a half-written file. */
function writeStatusFile(ctx, log) {
  try {
    const stateDir = ctx.config.state_dir;
    fs.mkdirSync(stateDir, { recursive: true });
    const status = { ...buildHealthStatus(ctx), written_at: new Date().toISOString() };
    stateStore.atomicOverwriteFile(gatewayStatusPath(stateDir), JSON.stringify(status, null, 2), stateDir);
  } catch (error) {
    log(`failed to write status file (non-fatal): ${error.message}`);
  }
}

/**
 * Starts the standalone gateway process. Returns { dormant: true } if attach mode is
 * active (caller should exit 0). Otherwise returns a running gateway handle with
 * `.stop()` for graceful shutdown (SIGTERM/SIGINT, SS3.7) and `.status()` (SG-NFR-3).
 */
async function startGateway(options) {
  const log = options.log || ((...args) => console.error("[graphsmith-gateway]", ...args));

  /* Cluster E (partial fix -- see PR description for what is deliberately NOT included
   * here): the mode-gate validation root must track whichever project's config this
   * invocation is actually loading, not this process's cwd. `gateway.js --config
   * /path/to/project-b/gateway.json` run with cwd `/path/to/project-a/` previously
   * validated project A's <cwd>/.graphsmith/gateway-mode.json (checkModeGate's `root`
   * defaulted to process.cwd()) while loadConfig() below loaded project B's config
   * entirely independently -- two different projects' state read through one mode-gate
   * check that named neither of them. Deriving `root` from configPath's own directory
   * instead makes "which mode-selection record gates this run" track "which config this
   * run loads" by construction: whatever project configPath points into is the project
   * whose .graphsmith/ this checks, for every caller (the CLI's own configPath resolution
   * below, and any direct startGateway() caller), not only the common case where cwd and
   * the config's directory happen to coincide. options.root remains available to
   * override this explicitly for a caller that genuinely keeps its config file outside
   * the project root it means to validate against -- it is no longer the default source
   * of truth. */
  const configPath = options.configPath || path.join(process.cwd(), "gateway-config.json");
  const root = options.root || path.dirname(path.resolve(configPath));

  const modeResult = checkModeGate(root, log);
  if (modeResult.dormant) return { dormant: true };

  const config = gatewayConfig.loadConfig(configPath);
  if (config.session_boundary === "time_window") {
    throw fail(
      "session_boundary=\"time_window\" is accepted by the config schema as a forward-compatible " +
        "placeholder but is NOT IMPLEMENTED by this build (see scripts/gateway/session.js's header). " +
        "Use \"connection\" (the default) or omit the field.",
      "NOT_IMPLEMENTED"
    );
  }

  const keys = loadSigningKeys(config);

  const writerClaim = new WriterClaim(config.state_dir, { hostId: config.host_id });
  writerClaim.acquire(); // FR-1: throws and this process must exit non-zero on refusal
  log(`writer-claim acquired: instance ${writerClaim.instanceId} on host ${writerClaim.hostId}`);

  let proxy;
  writerClaim.onClaimLost = (error) => {
    log(`writer-claim lost: ${error.message} -- halting: no new sessions will be accepted.`);
    if (proxy) proxy.stopAcceptingNewSessions();
    // SS7: "In-flight sessions at the moment of loss should still attempt to finalize
    // and persist" -- already-open sessions are left alone here; only new admission
    // stops. That is deliberately NOT the whole story: a session already open when the
    // claim is lost is still allowed to run to completion and finalize, which is exactly
    // where the single-writer invariant chain.appendSession depends on could be violated
    // by a replacement writer that has since taken over this state directory (Cluster C).
    // GatewayProxy's own isWriterClaimValid check (wired below, consulted synchronously
    // right before chain.appendSession in closeConnection) is what actually closes that
    // gap -- not by halting every in-flight session the instant claim loss is first
    // detected, but by re-checking liveness at the one write that matters.
  };
  writerClaim.startHeartbeat();

  /* Mutable box, not a plain variable: connectAllDownstreams() below runs (and each
   * downstream stdio connection's onRequest closure over it is created) BEFORE the
   * agent transport is started further down, so at closure-creation time there is
   * nothing to push to yet. `.current` is set once the stdio transport actually starts
   * (never, for the http transport -- see forwardDownstreamRequestToAgent's own doc). */
  const agentPusher = { current: null, connectionId: null };

  /* Codex PR #29 review round 4 "advertise sampling before accepting sampling requests":
   * forwardDownstreamRequestToAgent only relays sampling/createMessage when the agent
   * transport is stdio (the one transport that can push a request to the agent -- see its
   * own doc above), but every downstream initialize previously declared `capabilities: {}`
   * regardless. A conforming MCP server never sends a request the client hasn't declared
   * support for, so a real downstream would never exercise this relay at all -- only the
   * test fixture worked, because it ignores capability negotiation. `config.agent_listen`
   * is already loaded above, so this is knowable before connectAllDownstreams runs. */
  const agentTransportSupportsSampling = (config.agent_listen || { transport: "stdio" }).transport !== "http";

  /* Codex PR #29 review "keep gateway secrets out of downstream subprocess environments":
   * every configured stdio downstream is spawned as a child process that, absent an
   * explicit `env`, inherits this gateway's complete process.env -- including whichever
   * env vars signing_key_ref / agent_listen.token_ref / a downstream's own token_ref
   * resolve secrets from. Collect just those NAMES (never the resolved secret values,
   * which this gateway process never needs to hand back to itself) once, here, so
   * connectStdio (via connectAllDownstreams/connectDownstream) can strip them from every
   * stdio child's environment regardless of which downstream is spawned. */
  const gatewaySecretEnvNames = new Set(
    [config.signing_key_ref, (config.agent_listen || {}).token_ref, ...(config.downstream_servers || []).map((s) => s.token_ref)].filter(
      (name) => typeof name === "string" && name.length > 0
    )
  );

  let downstreamHandles;
  const startupDownstreamConnectTimeoutMs = options.startupDownstreamConnectTimeoutMs || STARTUP_DOWNSTREAM_CONNECT_TIMEOUT_MS;
  /* Codex PR #29 review round 8 "install shutdown handlers before gateway startup
   * completes": kept as its own variable (not inlined into the try below) so the
   * watchdog-timeout catch path can still reach the real connect promise to best-effort
   * close whatever it eventually produces -- see that catch block's own comment. */
  const connectAllDownstreamsPromise = downstream.connectAllDownstreams(config.downstream_servers, {
    clientInfo: { name: "graphsmith-standalone-gateway", version: "1.0" },
    supportsSampling: agentTransportSupportsSampling,
    secretEnvNames: gatewaySecretEnvNames,
    /* Codex PR #29 review round 4 "preserve the originating server for sampling": with
     * multiple stdio downstreams, connectAllDownstreams binds each connection's own
     * onRequest to its configured server name (see downstream.js) -- forward it through
     * so the recorded/logged step is attributed to the real downstream, not a single
     * shared placeholder. */
    onRequest: (msg, serverName) => forwardDownstreamRequestToAgent(msg, agentPusher, log, proxy, serverName),
    onUnmatchedResponse: (msg, serverName) => recordUnmatchedDownstreamResponse(msg, agentPusher, log, proxy, serverName),
  });
  try {
    downstreamHandles = await withTimeout(
      connectAllDownstreamsPromise,
      startupDownstreamConnectTimeoutMs,
      () =>
        fail(
          `downstream connection phase did not complete within ${startupDownstreamConnectTimeoutMs}ms -- ` +
            "treating startup as failed (a downstream handshake that hangs this long, ignoring " +
            "DEFAULT_REQUEST_TIMEOUT_MS on every individual RPC inside it, is not making progress).",
          "GATEWAY_STARTUP_TIMEOUT"
        )
    );
  } catch (error) {
    writerClaim.release();
    /* If connectAllDownstreams eventually settles AFTER this watchdog has already given up
     * (and already released the writer-claim above), don't leak whatever downstream child
     * processes/sockets it produced -- best-effort close them once they show up. This is
     * deliberately NOT an attempt to safely tear down partially-initialized startup state
     * in general (the panel's own explicitly-rejected approach, see this constant's own
     * header comment) -- it only cleans up the one promise this function itself started. */
    connectAllDownstreamsPromise
      .then((handles) => {
        for (const conn of handles.connections.values()) {
          try { conn.close(); } catch (closeError) { /* best effort */ }
        }
      })
      .catch(() => {});
    throw error; // SS7: downstream unreachable (or timed out) at startup -> refuse to start (hard-refuse resolution)
  }

  proxy = new GatewayProxy({
    connections: downstreamHandles.connections,
    mergedTools: downstreamHandles.mergedTools,
    toolOwners: downstreamHandles.toolOwners,
    serverInfos: downstreamHandles.serverInfos,
    keys,
    stateDir: config.state_dir,
    log,
    onSessionFinalized: (connectionId, entry) => log(`session ${connectionId} finalized: chain seq ${entry.seq}, bundle ${entry.bundle_id}`),
    onSealFailure: (session, error) => log(`SEAL FAILURE for connection ${session.connectionId}: ${error.message} -- session state:`, JSON.stringify({ calls: session.calls.length, pendingCalls: session.pendingCalls.size, quarantinedTo: error.quarantinedTo || null })),
    // Cluster C: read fresh from disk (WriterClaim#status's own contract) rather than
    // trust writerClaim's in-memory _claimToken -- a claim lost out-of-band (the file
    // removed or overwritten by a replacement writer underneath this process) must be
    // caught here even if this instance's own heartbeat hasn't yet noticed and fired
    // onClaimLost.
    isWriterClaimValid: () => writerClaim.status().held_by_this_instance,
  });

  for (const [name, conn] of downstreamHandles.connections.entries()) {
    if (conn.whenClosed) {
      conn.whenClosed().then(() => proxy.handleDownstreamDisconnect(name)).catch(() => {});
    }
  }

  const listenConfig = config.agent_listen || { transport: "stdio" };
  let stdioHandle = null;
  let httpHandle = null;
  try {
    if (listenConfig.transport === "http") {
      const token = gatewayConfig.resolveSecretRef(listenConfig.token_ref, "agent_listen.token_ref");
      httpHandle = await runHttpAgentTransport({ proxy }, listenConfig, token);
      log(`agent-facing HTTP listener on port ${httpHandle.port}`);
    } else {
      stdioHandle = runStdioAgentTransport({ proxy });
      // See forwardDownstreamRequestToAgent's doc above: only the stdio transport can
      // push a request to the agent, so this is the one branch that ever populates it.
      agentPusher.current = stdioHandle.pushRequest;
      agentPusher.connectionId = stdioHandle.connectionId;
      /* stdio is a one-process-per-connection transport (mirrors mcp-server/src/
       * stdioTransport.js's own "stdin closed -> exit cleanly" convention): once the
       * agent disconnects, the connection's session is already finalized (inside
       * runStdioAgentTransport's own rl "close" handler, which resolves this promise
       * AFTER closeConnection completes) -- there is nothing left for this process to do
       * but release the claim and exit. Without this, the process would sit idle forever
       * (the writer-claim heartbeat timer and the still-open downstream child keep the
       * event loop alive), never actually stopping. */
      stdioHandle.closed.then(() => stop("agent stdio disconnected").then(() => process.exit(0)));
    }
  } catch (error) {
    /* Everything up to here (writer-claim, heartbeat, downstream connections) already
     * succeeded by the time agent-listener setup can fail (an unresolved token_ref, or a
     * bind failure) -- without this cleanup, that already-acquired state (in particular
     * the writer-claim and any still-alive stdio downstream child) would leak: the
     * process could remain running after setting a non-zero exitCode, block a future
     * restart's claim acquisition, and need manual termination. */
    proxy.stopAcceptingNewSessions();
    /* Codex PR #29 review round 8 "bound termination of stdio downstream children":
     * conn.close() now returns a promise that resolves only once the child has actually
     * exited (bounded SIGTERM wait, then SIGKILL) rather than firing SIGTERM and returning
     * immediately -- await it here so this cleanup path genuinely finishes terminating
     * every downstream child before releasing the writer-claim, instead of leaving a child
     * that traps/ignores SIGTERM running past this point. */
    for (const conn of downstreamHandles.connections.values()) {
      try { await conn.close(); } catch (closeError) { /* best effort */ }
    }
    writerClaim.release();
    throw error;
  }

  const ctx = { config, writerClaim, connections: downstreamHandles.connections, proxy };

  /* Cluster D: write an initial status file immediately (not just on the first
   * interval tick, options.statusWriteIntervalMs or STATUS_WRITE_INTERVAL_MS away) so a
   * `status` invocation right after startup already finds fresh data, then keep it
   * refreshed on a fixed cadence for the rest of this process's life. unref'd, matching
   * every other background timer in this file (writer-claim's own heartbeat, HTTP
   * session idle timers) -- a status-file refresh must never be the reason this process
   * fails to exit. */
  writeStatusFile(ctx, log);
  const statusWriteIntervalMs = options.statusWriteIntervalMs || STATUS_WRITE_INTERVAL_MS;
  const statusWriteTimer = setInterval(() => writeStatusFile(ctx, log), statusWriteIntervalMs);
  if (typeof statusWriteTimer.unref === "function") statusWriteTimer.unref();

  const drainTimeoutMs = options.drainTimeoutMs || 5000;
  /* CodeRabbit PR #29 review "make stop() await the in-progress shutdown instead of
   * returning early": the SIGTERM/SIGINT handler and the stdio-disconnect path
   * (stdioHandle.closed.then(...)) can both call stop(), and both call process.exit(0)
   * once THEIR OWN promise settles. The previous `if (stopped) return;` resolved a
   * second caller's promise immediately, while the first caller's drain/finalize/
   * writer-claim-release work was still in flight -- letting the second caller's
   * process.exit(0) race ahead and kill the process mid-finalize, losing sessions that
   * were never sealed/appended to the chain. Memoize the actual shutdown promise instead,
   * so every caller (first or later) awaits the SAME work and only resolves once it is
   * genuinely done. */
  let stopPromise = null;
  function stop(reason) {
    if (!stopPromise) stopPromise = doStop(reason);
    return stopPromise;
  }
  async function doStop(reason) {
    log(`shutting down (${reason || "requested"}): draining ${proxy.openSessionCount()} open session(s)`);
    clearInterval(statusWriteTimer); // Cluster D: stop refreshing the status file once shutdown begins
    proxy.stopAcceptingNewSessions();
    /* SS3.7: "finish in-flight sessions" means actually WAIT (bounded) for calls already
     * in flight to complete and be recorded with their real result -- not immediately
     * truncate the connection and let closeConnection's own pending-call handling mark
     * a call that was about to succeed as an artificial "disconnected" error. Only a
     * call that is STILL pending once the drain timeout elapses gets that treatment. */
    await drainOpenSessions(proxy, drainTimeoutMs);
    agentPusher.current = null; // no agent left to push a forwarded sampling request to
    agentPusher.connectionId = null;
    if (stdioHandle) stdioHandle.stop();
    if (httpHandle) {
      await new Promise((resolve) => {
        let settled = false;
        const finish = () => { if (!settled) { settled = true; resolve(); } };
        httpHandle.server.close(finish);
        const forceCloseTimer = setTimeout(() => {
          // Stop accepting new connections is already implied by close() above; this
          // forcibly ends any still-open sockets/responses so the callback above (or
          // this fallback) fires within the bounded deadline rather than whenever the
          // last active response happens to finish.
          if (typeof httpHandle.server.closeAllConnections === "function") httpHandle.server.closeAllConnections();
          finish();
        }, HTTP_LISTENER_CLOSE_TIMEOUT_MS);
        if (typeof forceCloseTimer.unref === "function") forceCloseTimer.unref();
      });
    }
    // Finalize any still-open sessions (drained above, or forced closed after the timeout).
    for (const connectionId of Array.from(proxy.sessions.keys())) {
      await proxy.closeConnection(connectionId, `gateway shutdown (${reason || "requested"})`);
    }
    /* Codex PR #29 review round 8 "bound termination of stdio downstream children": same
     * reasoning as the startup-failure cleanup above -- await close() so a downstream that
     * traps/ignores SIGTERM is actually confirmed gone (or forcibly SIGKILLed) before this
     * releases the writer-claim, rather than left running past shutdown. */
    for (const conn of downstreamHandles.connections.values()) {
      try { await conn.close(); } catch (error) { /* best effort */ }
    }
    writerClaim.release();
    // Cluster D: one last write so `gateway.js status` run after this process has
    // exited reports an accurate "not claimed by this instance" / drained snapshot
    // instead of silently going stale mid-run-looking data.
    writeStatusFile(ctx, log);
    log("shutdown complete: writer-claim released.");
  }

  return {
    dormant: false,
    proxy,
    writerClaim,
    config,
    stop,
    status: () => buildHealthStatus(ctx),
  };
}

/* Cluster D: `node gateway.js status [configPath]` -- reads the status FILE a running
 * gateway (started against the same config) periodically writes to <state_dir>/
 * gateway-status.json (see writeStatusFile above) and pretty-prints it. Deliberately a
 * separate, short-lived process reading a file, not an RPC to the running gateway or a
 * new ops HTTP port (out of scope -- see writeStatusFile's own header comment): this
 * mirrors how `node scripts/writer-claim.js status` already reports on-disk state
 * without needing a running process to ask. Exits non-zero with a clear, actionable
 * message when the config can't be loaded, no status file exists yet (no gateway has
 * run against this config, or state_dir doesn't match), or the file is unreadable/
 * corrupt -- never a stack trace. */
function runStatusCommand(configPathArg) {
  const configPath = configPathArg || path.join(process.cwd(), "gateway-config.json");
  let config;
  try {
    config = gatewayConfig.loadConfig(configPath);
  } catch (error) {
    console.error(`[graphsmith-gateway] status: could not load config at ${configPath}: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const statusPath = gatewayStatusPath(config.state_dir);
  let raw;
  try {
    raw = fs.readFileSync(statusPath, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      console.error(
        `[graphsmith-gateway] status: no status file at ${statusPath} -- has a gateway ever been ` +
          `started against this config (state_dir: ${config.state_dir})?`
      );
    } else {
      console.error(`[graphsmith-gateway] status: could not read ${statusPath}: ${error.message}`);
    }
    process.exitCode = 1;
    return;
  }

  let status;
  try {
    status = JSON.parse(raw);
  } catch (error) {
    console.error(`[graphsmith-gateway] status: ${statusPath} contains invalid JSON: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.log(JSON.stringify(status, null, 2));

  // A status file this stale means the writer that produced it stopped refreshing it --
  // either a clean shutdown (see doStop's own final write) or a crash that skipped that
  // final write. Either way, flag it rather than let stale data read as "still running".
  const writtenAt = Date.parse(status.written_at);
  if (Number.isFinite(writtenAt)) {
    const ageMs = Date.now() - writtenAt;
    const staleAfterMs = STATUS_WRITE_INTERVAL_MS * 3;
    if (ageMs > staleAfterMs) {
      console.error(
        `[graphsmith-gateway] status: WARNING -- this snapshot is ${Math.round(ageMs / 1000)}s old ` +
          `(refreshed every ~${Math.round(STATUS_WRITE_INTERVAL_MS / 1000)}s while running); the ` +
          "gateway that wrote it may no longer be running."
      );
    }
  }
}

function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "status") {
    runStatusCommand(argv[1]);
    return;
  }

  const configPath = argv[0] || path.join(process.cwd(), "gateway-config.json");
  startGateway({ configPath }).then((handle) => {
    if (handle.dormant) {
      process.exit(0);
    }
    const shutdown = (signal) => handle.stop(signal).then(() => process.exit(0));
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  }).catch((error) => {
    console.error(`[graphsmith-gateway] FATAL: ${error.message}`);
    process.exitCode = 1;
  });
}

if (require.main === module) main();

module.exports = {
  startGateway,
  checkModeGate,
  buildHealthStatus,
  loadSigningKeys,
  drainOpenSessions,
  gatewayStatusPath,
  STATUS_WRITE_INTERVAL_MS,
  runStatusCommand,
  // Exported for direct unit testing against fake sessions/connections (mirrors
  // drainOpenSessions' own existing testability rationale above) -- not part of this
  // module's own CLI/programmatic surface otherwise.
  forwardDownstreamRequestToAgent,
  recordUnmatchedDownstreamResponse,
  STARTUP_DOWNSTREAM_CONNECT_TIMEOUT_MS,
};
