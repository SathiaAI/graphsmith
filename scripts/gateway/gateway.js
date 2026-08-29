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
 * sessions are keyed by the underlying TCP socket, so multiple requests on one
 * keep-alive connection share a session and two different connections never collide.
 *
 * Zero-dependency, Node >= 18.
 */
"use strict";

const path = require("path");
const crypto = require("crypto");

const modeGate = require("./mode-gate.js");
const gatewayConfig = require("./config.js");
const chain = require("./chain.js");
const { GatewayProxy } = require("./proxy.js");
const downstream = require("./downstream.js");
const { runStdioAgentTransport, runHttpAgentTransport } = require("./agent-transport.js");
const writerClaimModule = require("../writer-claim.js");
const { WriterClaim } = writerClaimModule;

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

function fail(message, code = "GATEWAY_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
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
  const head = chain.readHead(ctx.config.state_dir);
  return {
    schema_version: "1.0",
    writer_claim: ctx.writerClaim.status(),
    downstream_servers: Array.from(ctx.connections.keys()).map((name) => ({
      name,
      reachable: !ctx.connections.get(name).isClosed(),
    })),
    active_sessions: ctx.proxy.openSessionCount(),
    chain: head ? { seq: head.seq, entry_sha256: head.entry_sha256 } : { seq: 0, entry_sha256: null },
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

  let downstreamHandles;
  try {
    downstreamHandles = await downstream.connectAllDownstreams(config.downstream_servers, {
      clientInfo: { name: "graphsmith-standalone-gateway", version: "1.0" },
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
    onSessionFinalized: (connectionId, entry) => log(`session ${connectionId} finalized: chain seq ${entry.seq}, bundle ${entry.bundle_id}`),
    onSealFailure: (session, error) => log(`SEAL FAILURE for connection ${session.connectionId}: ${error.message} -- session state:`, JSON.stringify({ calls: session.calls.length, pendingCalls: session.pendingCalls.size })),
  });

  for (const [name, conn] of downstreamHandles.connections.entries()) {
    if (conn.whenClosed) {
      conn.whenClosed().then(() => proxy.handleDownstreamDisconnect(name)).catch(() => {});
    }
  }

  const listenConfig = config.agent_listen || { transport: "stdio" };
  let stdioHandle = null;
  let httpHandle = null;
  if (listenConfig.transport === "http") {
    const token = gatewayConfig.resolveSecretRef(listenConfig.token_ref, "agent_listen.token_ref");
    httpHandle = await runHttpAgentTransport({ proxy }, listenConfig, token);
    log(`agent-facing HTTP listener on port ${httpHandle.port}`);
  } else {
    stdioHandle = runStdioAgentTransport({ proxy });
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

  const ctx = { config, writerClaim, connections: downstreamHandles.connections, proxy };

  const drainTimeoutMs = options.drainTimeoutMs || 5000;
  let stopped = false;
  async function stop(reason) {
    if (stopped) return;
    stopped = true;
    log(`shutting down (${reason || "requested"}): draining ${proxy.openSessionCount()} open session(s)`);
    proxy.stopAcceptingNewSessions();
    /* SS3.7: "finish in-flight sessions" means actually WAIT (bounded) for calls already
     * in flight to complete and be recorded with their real result -- not immediately
     * truncate the connection and let closeConnection's own pending-call handling mark
     * a call that was about to succeed as an artificial "disconnected" error. Only a
     * call that is STILL pending once the drain timeout elapses gets that treatment. */
    await drainOpenSessions(proxy, drainTimeoutMs);
    if (stdioHandle) stdioHandle.stop();
    if (httpHandle) await new Promise((resolve) => httpHandle.server.close(resolve));
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
