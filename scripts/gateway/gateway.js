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
const recovery = require("./recovery.js");
const { GatewayProxy } = require("./proxy.js");
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
function forwardDownstreamRequestToAgent(msg, agentPusher, log, proxy) {
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
  if (s) {
    session.recordCallStart(s, correlationKey, {
      tool: "sampling/createMessage",
      server: "sampling",
      arguments: msg.params,
      isModelCall: true,
      ts: proxy.now(),
    });
  }
  return agentPusher.current(msg.method, msg.params).then(
    (result) => {
      /* Mirrors proxy.js's own "correlatedNow" guard (CodeRabbit PR #29 review, round 1):
       * the session can finalize (agent disconnects) while this forwarded request is
       * still in flight awaiting the agent's model. Only record if it's still genuinely
       * pending, so this never throws SESSION_FINALIZED or logs a spurious anomaly for an
       * entry the gateway itself already removed. */
      if (s && !s.finalized && s.pendingCalls.has(correlationKey)) session.recordCallResult(s, correlationKey, { result, isError: false, ts: proxy.now() });
      return { jsonrpc: "2.0", id: msg.id, result };
    },
    (error) => {
      log(`downstream sampling/createMessage forward to agent failed: ${error.message}`);
      if (s && !s.finalized && s.pendingCalls.has(correlationKey)) session.recordCallResult(s, correlationKey, { result: { error: error.message }, isError: true, ts: proxy.now() });
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

  /* Option C: surface every intent an operator still needs to act on (or that is merely
   * "dispatched" and not yet stale enough to worry about) so this is discoverable without
   * an operator having to already know a crash happened -- the whole point of a durable,
   * un-auto-expired fence (recovery.js's own header) is defeated if nothing ever points an
   * operator at it. Read directly from disk rather than cached from the one-time startup
   * recoverCrashedSessions() pass, since a NEW ambiguous intent can appear at any time
   * during normal operation (proxy.js's closeConnection fences a "dispatched" intent
   * ambiguous the moment its owning connection closes mid-call, not just at startup). */
  let recoveryStatus;
  try {
    const allIntents = recovery.listAllIntents(stateDir);
    recoveryStatus = {
      pending_operator_review: allIntents
        .filter((i) => i.state === "ambiguous")
        .map((i) => ({ connection_id: i.connection_id, intent_key: i.intent_key, tool: i.tool, ambiguous_since: i.ambiguous_at || null, reason: i.ambiguous_reason || null })),
      in_flight: allIntents.filter((i) => i.state === "dispatched").length,
    };
  } catch (error) {
    recoveryStatus = { pending_operator_review: [], in_flight: 0, error: error.message };
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
    recovery: recoveryStatus,
    remote_anchor: { implemented: false, reason: "SG-FR-6 not implemented in this build -- see chain.js#pushChainTailToRemoteAnchor" },
  };
}

/** Startup crash-recovery pass (Codex PR #29 Finding 1, Option C -- external-panel-
 * reviewed design, see option-c-hardened-design.md). Runs once, after the writer-claim
 * is acquired (so this process is the sole owner of state_dir) and BEFORE any downstream
 * connection or agent-facing listener starts, replaying any WAL a prior crashed instance
 * left behind under recovery.js's `gateway-recovery/active/` directory.
 *
 * Replay reconstructs a session using session.js's real, UNMODIFIED recorder functions
 * (recordInitialize/recordToolsList/recordCallStart/recordCallResult/
 * markPendingAsDisconnected) -- there is no second, parallel session shape to keep in
 * sync with the live one. A call with no matching CALL_RESULT event is exactly Finding
 * 1's "crash after a completed call but before disconnect" gap turned inside out: it was
 * IN FLIGHT at crash time, so its real intent record (recovery.js's idempotency store,
 * Finding 2) is consulted for a proven outcome; only a session with every call proven
 * terminal is auto-sealed. Anything else is left alone and reported -- never guessed. */
function recoverCrashedSessions(stateDir, keys, log) {
  const pendingOperatorReview = [];
  for (const connectionId of recovery.listActiveConnections(stateDir)) {
    /* CodeRabbit PR #33 review "continue recovery after an unreadable connection state":
     * readWalEvents/readIntent below can throw (GATEWAY_RECOVERY_WAL_UNREADABLE,
     * GATEWAY_RECOVERY_INTENT_UNREADABLE, GATEWAY_RECOVERY_INTENT_CORRUPT) on a genuine
     * fs-level read failure for THIS connection's own state -- a permissions or I/O
     * problem, not a content/JSON one (which readWalEvents already handles by stopping
     * at the first bad line, not throwing). Previously unguarded, so one such connection
     * aborted recovery for every other connection still waiting in this same loop. Wrap
     * the whole per-connection body so a failure here is isolated to this connection --
     * flagged for the operator (whose recovery-abandon can now quarantine an unreadable
     * WAL without needing to re-read it -- see abandonConnection below) and otherwise
     * left alone, exactly like this function's other own failure branches already do. */
    try {
      const events = recovery.readWalEvents(stateDir, connectionId);
      if (events.length === 0) {
        // Every line was torn (crash mid-write of the very first event) or the file was
        // empty -- nothing durable was ever recorded for this connection.
        recovery.deleteWal(stateDir, connectionId);
        continue;
      }

      const startEvent = events.find((e) => e.type === "SESSION_START");
      const s = session.createSession(connectionId, { now: () => Date.now(), goal: startEvent ? startEvent.goal : undefined });
      // Maps this replay's own stable Symbol.for() keys back to the CALL_START event that
      // produced them, needed only to look up that call's real intent record below.
      const keyToStartEvent = new Map();

      for (const event of events) {
        if (event.type === "SESSION_START") {
          session.recordToolsList(s, event.tools || []);
        } else if (event.type === "INITIALIZE") {
          session.recordInitialize(s, { clientInfo: event.clientInfo, serverInfo: event.serverInfo, model: event.model });
        } else if (event.type === "CALL_START") {
          // Symbol.for (the global registry), not Symbol(): this replay's own CALL_START
          // and CALL_RESULT events for the same call_seq must resolve to the SAME symbol
          // reference for session.js's Map-keyed pendingCalls to correlate them -- a live
          // correlationKey may have been a non-reproducible Symbol() or a real JSON-RPC id,
          // but replay only needs internal consistency within itself, not to match what
          // the crashed process originally used.
          const key = Symbol.for(`wal-replay:${connectionId}:${event.call_seq}`);
          keyToStartEvent.set(key, event);
          session.recordCallStart(s, key, { tool: event.tool, server: event.server, arguments: event.arguments, isModelCall: false, ts: event.ts });
        } else if (event.type === "CALL_RESULT") {
          const key = Symbol.for(`wal-replay:${connectionId}:${event.call_seq}`);
          if (s.pendingCalls.has(key)) session.recordCallResult(s, key, { result: event.result, isError: event.isError, ts: event.ts });
        } else if (event.type === "ANOMALY") {
          // Codex PR #33 review "append blocked-retry anomalies to the WAL": replays a
          // dispatch-guard block (GATEWAY_AMBIGUOUS_RETRY/GATEWAY_DOWNSTREAM_OUTCOME_UNKNOWN)
          // that was recorded in-memory only via session.recordAnomaly in the live proxy --
          // without this, a crash before the connection's own close would silently drop
          // that attestation from the recovered/sealed bundle.
          session.recordAnomaly(s, { kind: event.kind, tool: event.tool, intent_key: event.intent_key, detail: event.detail, ts: event.ts });
        }
        // CLOSING is informational only for replay -- if present, the crash happened
        // between "closeConnection began" and "chain.appendSession completed", which the
        // GATEWAY_BUNDLE_ID_COLLISION handling below already covers.
      }

      // Any call still pending after replaying every event was in flight at crash time.
      // Consult its real intent record for a proven outcome before deciding anything.
      let needsOperator = false;
      for (const [key] of Array.from(s.pendingCalls.entries())) {
        const startedFrom = keyToStartEvent.get(key);
        if (!startedFrom) continue; // defensive; should not happen
        const intentKey = recovery.computeIntentKey(connectionId, startedFrom.tool, startedFrom.arguments);
        const intent = recovery.readIntent(stateDir, intentKey);
        if (intent && intent.state === "completed") {
          session.recordCallResult(s, key, { result: intent.cached_result, isError: false, ts: Date.now() });
        } else if (intent && intent.state === "not_executed") {
          /* Codex PR #33 review "persist a terminal not-executed resolution": an operator
           * already answered "did it execute?" (no) via recovery-resolve while this
           * connection was crashed -- record that as a real (failed) terminal result now,
           * rather than re-flagging the same connection for operator review forever
           * because no "completed" intent will ever appear for a call that never ran. */
          session.recordCallResult(s, key, { result: { error: "operator confirmed via recovery-resolve that this call did not execute downstream" }, isError: true, ts: Date.now() });
        } else {
          needsOperator = true;
        }
      }

      if (needsOperator) {
        pendingOperatorReview.push(connectionId);
        log(
          `RECOVERY_AMBIGUOUS_INTENT: connection "${connectionId}" crashed with a call in flight whose outcome is not proven -- ` +
            `leaving its WAL and intent record in place rather than guessing. Resolve with ` +
            `"node scripts/gateway/gateway.js recovery-resolve --connection ${connectionId} --intent <key> --confirmed executed|not-executed", ` +
            `or "node scripts/gateway/gateway.js recovery-abandon --connection ${connectionId}" to seal only the calls that did reach a proven outcome.`
        );
        continue; // do not touch this connection's WAL/intents any further
      }

      if (s.pendingCalls.size > 0) {
        session.markPendingAsDisconnected(s, "gateway restarted after a crash; connection never received a clean close", () => Date.now());
      }
      let sealed;
      try {
        sealed = session.finalizeSession(s, keys);
      } catch (error) {
        log(`RECOVERY SEAL FAILURE for connection "${connectionId}": ${error.message} -- leaving its WAL in place for investigation.`);
        pendingOperatorReview.push(connectionId);
        continue;
      }
      try {
        chain.appendSession(stateDir, sealed);
      } catch (error) {
        if (error.code === "GATEWAY_BUNDLE_ID_COLLISION") {
          /* Verified directly against gsa-mcp-shim.js: bundle_id = sha256({init,
           * grantedTools, n: calls.length}) -- a coarse fingerprint with no timestamp,
           * nonce, or actual call content. Re-running recovery for the SAME crash
           * deterministically reproduces the same bundle_id, which is "already durably
           * appended," not a real conflict -- but a DIFFERENT crashed session that
           * merely happens to share {init, grantedTools, call count} would ALSO collide
           * here, and blindly trusting the id match would then discard that other
           * session's real WAL and completed intents, permanently. Codex PR #33 review
           * "verify bundle collisions before discarding recovery state": read back the
           * bundle actually on disk and compare its real content (the execution trace,
           * which is itself a hash of every call's real arguments/result) before
           * deciding this is the expected repeated-recovery case. */
          let sameContent = false;
          try {
            const existingRaw = fs.readFileSync(chain.bundlePath(stateDir, sealed.bundle.manifest.bundle_id), "utf8");
            const existingBundle = JSON.parse(existingRaw);
            // gsa-produce.js#produceBundle never stores artifact bodies on the bundle
            // itself -- manifest.artifacts.<name>.sha256 is the real per-artifact content
            // fingerprint (the raw bodies live in bundle.contents, keyed by file path, but
            // the hash already IS the exact equality check needed here). execution_trace
            // alone (per-call input/result hashes, tool, granted, error/model flags) is
            // sufficient: it is a hash of every call's real arguments and result, so two
            // sessions cannot share it without sharing their actual call content.
            const existingHash = existingBundle.manifest && existingBundle.manifest.artifacts && existingBundle.manifest.artifacts.execution_trace && existingBundle.manifest.artifacts.execution_trace.sha256;
            const newHash = sealed.bundle.manifest && sealed.bundle.manifest.artifacts && sealed.bundle.manifest.artifacts.execution_trace && sealed.bundle.manifest.artifacts.execution_trace.sha256;
            sameContent = Boolean(existingHash) && existingHash === newHash;
          } catch (readError) {
            sameContent = false; // could not verify -- treat as a genuine, unverified conflict below
          }
          if (sameContent) {
            log(`recovery: connection "${connectionId}" was already durably sealed (bundle_id collision, content-verified match) -- cleaning up.`);
          } else {
            log(
              `RECOVERY BUNDLE COLLISION for connection "${connectionId}": bundle_id "${sealed.bundle.manifest.bundle_id}" ` +
                `already exists on disk but its recorded content does not match this connection's recovered session -- ` +
                `a genuine conflict between two different sessions, not a repeated recovery attempt of the same one. ` +
                `Leaving this connection's WAL and intents in place for investigation rather than discarding them.`
            );
            pendingOperatorReview.push(connectionId);
            continue;
          }
        } else {
          log(`RECOVERY CHAIN-APPEND FAILURE for connection "${connectionId}": ${error.message} -- leaving its WAL in place for investigation.`);
          pendingOperatorReview.push(connectionId);
          continue;
        }
      }
      recovery.deleteWal(stateDir, connectionId);
      for (const intent of recovery.listIntentsForConnection(stateDir, connectionId)) {
        if (intent.state === "completed" || intent.state === "not_executed") recovery.deleteIntent(stateDir, intent.intent_key);
      }
      log(`recovery: connection "${connectionId}" recovered and sealed from a crash-left WAL (${s.calls.length} call(s)).`);
    } catch (error) {
      log(`RECOVERY FAILURE for connection "${connectionId}": ${error.message} (${error.code || "no code"}) -- leaving its state in place for investigation. Use "recovery-abandon --connection ${connectionId}" to quarantine it without needing to re-read that state.`);
      pendingOperatorReview.push(connectionId);
    }
  }
  return { pendingOperatorReview };
}

/** Operator override for a connection stuck in `pendingOperatorReview` (recovery-abandon
 * CLI, see main() below): unlike recoverCrashedSessions' own auto-seal path, this treats
 * EVERY call still pending after WAL replay as terminal regardless of whether its intent
 * ever reached a proven "completed" outcome -- an explicit "I am giving up on finding out
 * whether this executed, seal what I have" decision, not a guess made on the operator's
 * behalf. Any intent still `dispatched`/`ambiguous` for this connection is deleted
 * afterward: the durable fence Finding 2 provides is deliberately given up on for THIS
 * specific connection, by explicit operator action, not silently -- if the downstream
 * operation actually executed, a future identical call is no longer fenced against
 * re-running it. This tradeoff (and that it is scoped per-connection, never global) is
 * documented in KNOWN-LIMITATIONS.md. */
function abandonConnection(stateDir, keys, connectionId, log) {
  /* Codex PR #33 review "continue recovery after an unreadable connection state": this
   * command is recoverCrashedSessions' own documented remediation path for a connection
   * it could not process -- including one whose WAL could not even be READ (permissions/
   * I/O error, not a content problem). Before this, that same unreadable-WAL error would
   * simply be thrown again here, leaving the operator with no way to actually resolve
   * it. Quarantine (rename, not delete -- see recovery.quarantineWal's own doc comment)
   * instead: an operator who explicitly asked to abandon this connection does not need
   * this command to succeed at reading state it already knows is unreadable, only to stop
   * this connection from blocking every future startup. */
  let events;
  try {
    events = recovery.readWalEvents(stateDir, connectionId);
  } catch (error) {
    const quarantined = recovery.quarantineWal(stateDir, connectionId);
    for (const intent of recovery.listIntentsForConnection(stateDir, connectionId)) recovery.deleteIntent(stateDir, intent.intent_key);
    log(
      `recovery-abandon: connection "${connectionId}"'s WAL could not be read (${error.message}) -- ` +
        (quarantined ? `moved it to "${quarantined}" for manual inspection` : "no WAL file was found to quarantine") +
        `, and released any of its idempotency fence(s). This connection was NOT sealed into the chain ` +
        `(there is nothing readable to seal from) -- if it made any real downstream calls, that record is now unrecoverable through this gateway.`
    );
    return;
  }
  if (events.length === 0) {
    recovery.deleteWal(stateDir, connectionId);
    for (const intent of recovery.listIntentsForConnection(stateDir, connectionId)) recovery.deleteIntent(stateDir, intent.intent_key);
    log(`recovery-abandon: connection "${connectionId}" had no WAL to replay -- nothing to seal, cleaned up any leftover intents.`);
    return;
  }
  const startEvent = events.find((e) => e.type === "SESSION_START");
  const s = session.createSession(connectionId, { now: () => Date.now(), goal: startEvent ? startEvent.goal : undefined });
  for (const event of events) {
    if (event.type === "SESSION_START") {
      session.recordToolsList(s, event.tools || []);
    } else if (event.type === "INITIALIZE") {
      session.recordInitialize(s, { clientInfo: event.clientInfo, serverInfo: event.serverInfo, model: event.model });
    } else if (event.type === "CALL_START") {
      const key = Symbol.for(`wal-replay:${connectionId}:${event.call_seq}`);
      session.recordCallStart(s, key, { tool: event.tool, server: event.server, arguments: event.arguments, isModelCall: false, ts: event.ts });
    } else if (event.type === "CALL_RESULT") {
      const key = Symbol.for(`wal-replay:${connectionId}:${event.call_seq}`);
      if (s.pendingCalls.has(key)) session.recordCallResult(s, key, { result: event.result, isError: event.isError, ts: event.ts });
    } else if (event.type === "ANOMALY") {
      session.recordAnomaly(s, { kind: event.kind, tool: event.tool, intent_key: event.intent_key, detail: event.detail, ts: event.ts });
    }
  }
  if (s.pendingCalls.size > 0) {
    session.recordAnomaly(s, { kind: "OPERATOR_ABANDONED_RECOVERY", detail: `operator explicitly abandoned recovery for connection "${connectionId}" with ${s.pendingCalls.size} call(s) of unproven outcome` });
    session.markPendingAsDisconnected(s, "operator ran recovery-abandon: outcome could not be confirmed and was not waited on further", () => Date.now());
  }
  const sealed = session.finalizeSession(s, keys);
  try {
    chain.appendSession(stateDir, sealed);
  } catch (error) {
    if (error.code !== "GATEWAY_BUNDLE_ID_COLLISION") throw error;
    log(`recovery-abandon: connection "${connectionId}" was already durably sealed (bundle_id collision, expected on a repeated attempt).`);
  }
  recovery.deleteWal(stateDir, connectionId);
  for (const intent of recovery.listIntentsForConnection(stateDir, connectionId)) recovery.deleteIntent(stateDir, intent.intent_key);
  log(`recovery-abandon: connection "${connectionId}" sealed (${s.calls.length} call(s)) and its idempotency fence(s) released.`);
}

/** Minimal `--flag value` / `--boolean-flag` parser for the recovery-* CLI subcommands
 * below. Not a general-purpose arg parser (no short flags, no `=` form) -- these two
 * subcommands are the only CLI surface this build needs beyond `node gateway.js
 * [configPath]` itself. */
function parseFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

/** `node scripts/gateway/gateway.js recovery-resolve --connection <id> --intent <key>
 * --confirmed executed|not-executed [--result-file <path>] [--config <path>]`: answers
 * recoverCrashedSessions' own RECOVERY_AMBIGUOUS_INTENT log line. Does not itself seal the
 * connection -- only updates the one intent record; restart the gateway (or run
 * recovery-abandon) to actually finish sealing once every ambiguous intent on a connection
 * has been resolved this way. */
function runRecoveryResolveCli(argv, log) {
  const flags = parseFlags(argv);
  const configPath = flags.config || path.join(process.cwd(), "gateway-config.json");
  const config = gatewayConfig.loadConfig(configPath);
  const connectionId = flags.connection;
  const intentKey = flags.intent;
  const confirmed = flags.confirmed;
  if (!connectionId || !intentKey || !confirmed) {
    throw fail("recovery-resolve requires --connection <id> --intent <key> --confirmed executed|not-executed", "GATEWAY_RECOVERY_CLI_USAGE");
  }
  if (confirmed !== "executed" && confirmed !== "not-executed") {
    throw fail(`--confirmed must be "executed" or "not-executed", got ${JSON.stringify(confirmed)}.`, "GATEWAY_RECOVERY_CLI_USAGE");
  }
  /* Codex PR #33 review "acquire the writer claim before resolving intents": this
   * mutates the same intent files the live proxy dispatch guard consults and updates
   * (recovery.js's readIntent/updateIntent/deleteIntent), unlike recovery-abandon (which
   * already takes the claim below). Without this, the documented operator workflow --
   * run this command, then restart the gateway -- could instead run WHILE a gateway
   * still holds the claim: a live dispatch resolving the same intent to "completed"/
   * "ambiguous" and this command deleting/overwriting it concurrently can each observe
   * the other's half-applied state (updateIntent throwing GATEWAY_RECOVERY_INTENT_NOT_FOUND
   * on a competing delete, or a plain last-write-wins clobber of either resolution). */
  const writerClaim = new WriterClaim(config.state_dir, { hostId: config.host_id });
  writerClaim.acquire();
  try {
    const existing = recovery.readIntent(config.state_dir, intentKey);
    if (!existing) throw fail(`No such intent "${intentKey}" under this gateway's state_dir.`, "GATEWAY_RECOVERY_INTENT_NOT_FOUND");
    if (existing.connection_id !== connectionId) {
      throw fail(`Intent "${intentKey}" belongs to connection "${existing.connection_id}", not "${connectionId}" -- refusing (likely a copy/paste mismatch).`, "GATEWAY_RECOVERY_CLI_MISMATCH");
    }
    if (confirmed === "executed") {
      /* CodeRabbit PR #33 review "require --result-file for --confirmed executed": a
       * missing --result-file used to silently resolve with cached_result: null, which
       * recoverCrashedSessions then replays as an ordinary CLEAN SUCCESS (isError:
       * false) -- the sealed bundle would attest a confident, is_error:false null
       * result for a call the gateway itself never actually observed completing; the
       * operator confirmed only that the external effect occurred, not what it
       * returned. Reject instead of guessing a shape for evidence that doesn't exist. */
      if (!flags["result-file"]) {
        throw fail(
          "recovery-resolve --confirmed executed requires --result-file <path>: a null result would be " +
            "replayed as an unverified clean success in the sealed bundle. If the real result is truly " +
            "unknown, use --confirmed not-executed instead (or recovery-abandon to give up on this connection).",
          "GATEWAY_RECOVERY_CLI_USAGE"
        );
      }
      const result = JSON.parse(fs.readFileSync(flags["result-file"], "utf8"));
      recovery.resolveIntentExecuted(config.state_dir, intentKey, result);
      log(`recovery-resolve: intent "${intentKey}" (connection "${connectionId}") marked EXECUTED. Restart the gateway to finish sealing this connection.`);
    } else {
      recovery.resolveIntentNotExecuted(config.state_dir, intentKey);
      log(`recovery-resolve: intent "${intentKey}" (connection "${connectionId}") marked NOT EXECUTED; fence released. Restart the gateway to finish sealing this connection.`);
    }
  } finally {
    writerClaim.release();
  }
}

/** `node scripts/gateway/gateway.js recovery-abandon --connection <id> [--config <path>]`:
 * the "give up on the fence, seal what we have" override -- see abandonConnection's own
 * doc comment above for exactly what this does and does not guarantee. Requires the
 * writer-claim (this mutates the same trusted chain a live gateway instance would), so it
 * cannot run concurrently with an actual gateway process against the same state_dir. */
function runRecoveryAbandonCli(argv, log) {
  const flags = parseFlags(argv);
  const configPath = flags.config || path.join(process.cwd(), "gateway-config.json");
  const config = gatewayConfig.loadConfig(configPath);
  const connectionId = flags.connection;
  if (!connectionId) throw fail("recovery-abandon requires --connection <id>", "GATEWAY_RECOVERY_CLI_USAGE");
  const keys = loadSigningKeys(config);
  const writerClaim = new WriterClaim(config.state_dir, { hostId: config.host_id });
  writerClaim.acquire();
  try {
    abandonConnection(config.state_dir, keys, connectionId, log);
  } finally {
    writerClaim.release();
  }
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

  /* Option C (crash-recovery/idempotency hardening, external-panel-reviewed design --
   * see option-c-hardened-design.md): replay any WAL left behind by a crashed prior
   * instance now, while this process holds exclusive writer ownership of state_dir and
   * BEFORE any new downstream/agent work starts. Recovery must not race a fresh
   * session's own WAL writes, and no new session should be admitted while a prior
   * session's calls are still ambiguous. */
  /* CodeRabbit PR #33 review "release the writer claim when startup recovery fails":
   * the writer-claim and its heartbeat are already live by this point. Without this,
   * an exception from recoverCrashedSessions (an unreadable WAL/intent this function's
   * own per-connection try/catch does not fully absorb, or any other unexpected
   * failure) would reject startGateway's promise while leaving the claim held -- an
   * immediate restart would then be refused until the lease goes stale, and any other
   * live handle to this WriterClaim instance would keep renewing an orphaned claim
   * indefinitely (writerClaim.release() already stops the heartbeat itself). */
  let pendingOperatorReview;
  try {
    ({ pendingOperatorReview } = recoverCrashedSessions(config.state_dir, keys, log));
  } catch (error) {
    writerClaim.release();
    throw error;
  }
  if (pendingOperatorReview.length > 0) {
    log(
      `startup recovery: ${pendingOperatorReview.length} connection(s) left pending operator ` +
        `review (see RECOVERY_AMBIGUOUS_INTENT log lines above) -- resolve via the ` +
        "recovery-resolve/recovery-abandon CLI before their state is cleaned up."
    );
  }

  /* Mutable box, not a plain variable: connectAllDownstreams() below runs (and each
   * downstream stdio connection's onRequest closure over it is created) BEFORE the
   * agent transport is started further down, so at closure-creation time there is
   * nothing to push to yet. `.current` is set once the stdio transport actually starts
   * (never, for the http transport -- see forwardDownstreamRequestToAgent's own doc). */
  const agentPusher = { current: null, connectionId: null };

  let downstreamHandles;
  try {
    downstreamHandles = await downstream.connectAllDownstreams(config.downstream_servers, {
      clientInfo: { name: "graphsmith-standalone-gateway", version: "1.0" },
      onRequest: (msg) => forwardDownstreamRequestToAgent(msg, agentPusher, log, proxy),
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
  const log = (...args) => console.error("[graphsmith-gateway]", ...args);
  const subcommand = process.argv[2];
  if (subcommand === "recovery-resolve" || subcommand === "recovery-abandon") {
    try {
      if (subcommand === "recovery-resolve") runRecoveryResolveCli(process.argv.slice(3), log);
      else runRecoveryAbandonCli(process.argv.slice(3), log);
    } catch (error) {
      console.error(`[graphsmith-gateway] FATAL: ${error.message}`);
      process.exitCode = 1;
    }
    return;
  }
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

module.exports = {
  startGateway,
  checkModeGate,
  buildHealthStatus,
  loadSigningKeys,
  drainOpenSessions,
  recoverCrashedSessions,
  abandonConnection,
  runRecoveryResolveCli,
  runRecoveryAbandonCli,
};
