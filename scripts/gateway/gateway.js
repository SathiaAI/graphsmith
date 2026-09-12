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
const { GatewayProxy, MAX_PENDING_CALLS_PER_SESSION } = require("./proxy.js");
const downstream = require("./downstream.js");
const { runStdioAgentTransport, runHttpAgentTransport } = require("./agent-transport.js");
const writerClaimModule = require("../writer-claim.js");
const { WriterClaim } = writerClaimModule;
const registerGatewaySessions = require("../../checks/register-gateway-sessions.js");

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

function fail(message, code = "GATEWAY_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
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

/**
 * Starts the standalone gateway process. Returns { dormant: true } if attach mode is
 * active (caller should exit 0). Otherwise returns a running gateway handle with
 * `.stop()` for graceful shutdown (SIGTERM/SIGINT, SS3.7) and `.status()` (SG-NFR-3).
 */
async function startGateway(options) {
  const root = options.root || process.cwd();
  const log = options.log || ((...args) => console.error("[graphsmith-gateway]", ...args));

  const modeResult = checkModeGate(root, log);
  if (modeResult.dormant) return { dormant: true };

  const config = gatewayConfig.loadConfig(options.configPath);
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
    // and persist" -- already-open sessions are left alone; only new admission stops.
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

  let downstreamHandles;
  try {
    downstreamHandles = await downstream.connectAllDownstreams(config.downstream_servers, {
      clientInfo: { name: "graphsmith-standalone-gateway", version: "1.0" },
      supportsSampling: agentTransportSupportsSampling,
      /* Codex PR #29 review round 4 "preserve the originating server for sampling": with
       * multiple stdio downstreams, connectAllDownstreams binds each connection's own
       * onRequest to its configured server name (see downstream.js) -- forward it through
       * so the recorded/logged step is attributed to the real downstream, not a single
       * shared placeholder. */
      onRequest: (msg, serverName) => forwardDownstreamRequestToAgent(msg, agentPusher, log, proxy, serverName),
    });
  } catch (error) {
    writerClaim.release();
    throw error; // SS7: downstream unreachable at startup -> refuse to start (hard-refuse resolution)
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
    for (const conn of downstreamHandles.connections.values()) {
      try { conn.close(); } catch (closeError) { /* best effort */ }
    }
    writerClaim.release();
    throw error;
  }

  const ctx = { config, writerClaim, connections: downstreamHandles.connections, proxy };

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
    for (const conn of downstreamHandles.connections.values()) {
      try { conn.close(); } catch (error) { /* best effort */ }
    }
    writerClaim.release();
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

function main() {
  const configPath = process.argv[2] || path.join(process.cwd(), "gateway-config.json");
  startGateway({ configPath, root: process.cwd() }).then((handle) => {
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

module.exports = { startGateway, checkModeGate, buildHealthStatus, loadSigningKeys, drainOpenSessions };
