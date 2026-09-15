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
  /* Codex PR #33 review "persist sampling calls in the recovery WAL": this forward is
   * recorded into the in-memory session (above) but, before this fix, NEVER into
   * recovery.js's WAL at all -- unlike proxy.js's own tools/call path. A crash after the
   * agent answers this sampling request but before the connection's own close would
   * silently omit that model invocation from a recovered/sealed bundle: recoverCrashedSessions
   * replays this connection's WAL from scratch and previously had no event type for it,
   * and even hard-coded isModelCall:false on every CALL_START it did replay. This is
   * deliberately NOT the same gap as the disclosed one in KNOWN-LIMITATIONS.md item 11
   * ("an agent-initiated sampling/createMessage forwarded through proxy.js's own dispatch
   * branch is out of scope for the fence") -- that disclosure is scoped to the opposite
   * direction (an AGENT sending sampling/createMessage INTO this gateway) and says so
   * explicitly ("rather than a downstream server"); this is a downstream SERVER's own
   * request being forwarded UP to the agent, a different code path (this function, not
   * proxy.js's handleMessage) with no matching disclosure. Reuses the same CALL_START/
   * CALL_RESULT WAL event shape proxy.js's tools/call path uses (same recoverCrashedSessions/
   * abandonConnection replay code handles both), with isModelCall:true now carried through
   * so replay can tell the two apart instead of assuming every replayed call is a plain
   * tool call. No idempotency-intent fencing is added here (Finding 2's fence is
   * deliberately scoped to tools/call only, unchanged) -- only Finding 1's WAL/attestation
   * coverage is extended to this path.
   *
   * Ordering note (Cluster H, frontier-panel review 2026-09-14, 5/5 unanimous): the
   * MAX_COMPLETED_CALLS_PER_SESSION refusal above runs FIRST and returns early, so a
   * refused call is never admitted, recorded in session.calls, or forwarded to the agent
   * -- it correctly never reaches the WAL either. The admission gate and the durability
   * write share one boundary, not two: there is no "evicted call still needs a WAL
   * entry" case on this path, since eviction here means outright refusal, not eviction
   * of an already-recorded call from memory. The WAL append below remains unconditional
   * on whatever this admission check decided; it is never itself capped or tombstoned. */
  let walCallSeq = null;
  let walAppendFailed = null;
  if (s) {
    walCallSeq = s.nextCallSeq;
    session.recordCallStart(s, correlationKey, {
      tool: "sampling/createMessage",
      server: recordedServerName,
      arguments: msg.params,
      isModelCall: true,
      ts: startTs,
    });
    try {
      recovery.appendWalEvent(proxy.stateDir, agentPusher.connectionId, {
        type: "CALL_START",
        call_seq: walCallSeq,
        tool: "sampling/createMessage",
        server: "sampling",
        arguments: msg.params,
        isModelCall: true,
        ts: proxy.now(),
      });
    } catch (walError) {
      walAppendFailed = walError;
    }
  }
  if (walAppendFailed) {
    /* Codex PR #33 review "refuse sampling when its CALL_START cannot be saved": unlike
     * the CALL_RESULT append further below (where the downstream call has ALREADY
     * completed and there is no "don't forward" option left), this append happens
     * strictly BEFORE agentPusher.current() is ever invoked -- nothing has been sent to
     * the agent yet at this point, so forwarding anyway is not "already in flight," it is
     * choosing to forward work this gateway just proved it cannot durably attest. A crash
     * before this connection's own close would then replay with no CALL_START for this
     * call at all, recreating exactly the attestation gap Finding 1 exists to close. Roll
     * back the in-memory pending-call entry (there is nothing durable to undo) and return
     * a real JSON-RPC error to the downstream server instead, matching proxy.js's own
     * "not dispatched -- safe to retry" contract for the identical failure mode. */
    if (s) s.pendingCalls.delete(correlationKey);
    log(`Refusing to forward a downstream-initiated sampling/createMessage request to the agent: its CALL_START could not be durably recorded (${walAppendFailed.message}).`);
    return Promise.resolve({
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32000, message: `Failed to durably record this sampling request before forwarding it to the agent: ${walAppendFailed.message}. Not forwarded -- safe to retry.` },
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
        if (walCallSeq !== null) {
          try {
            recovery.appendWalEvent(proxy.stateDir, agentPusher.connectionId, { type: "CALL_RESULT", call_seq: walCallSeq, result, isError: false, ts: proxy.now() });
          } catch (walError) {
            log(`Failed to durably record a downstream-initiated sampling call's result: ${walError.message}`);
          }
        }
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
        if (walCallSeq !== null) {
          try {
            recovery.appendWalEvent(proxy.stateDir, agentPusher.connectionId, { type: "CALL_RESULT", call_seq: walCallSeq, result: { error: error.message }, isError: true, ts: proxy.now() });
          } catch (walError) {
            log(`Failed to durably record a downstream-initiated sampling call's error result: ${walError.message}`);
          }
        }
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
    /* Codex PR #33 review "report each unresolved intent key in recovery output": a
     * "dispatched" intent is normal (a live call genuinely in flight on a healthy
     * connection) on most gateways most of the time, BUT it is also exactly the state a
     * crashed connection's own unresolved call is left in when startup recovery could not
     * prove its outcome (recoverCrashedSessions' RECOVERY_AMBIGUOUS_INTENT case) -- the
     * aggregate `in_flight` count alone cannot tell those two apart, and an operator
     * cannot act on a plain number. Itemize the same way `pending_operator_review`
     * already does for `ambiguous` intents, so a stuck one is directly actionable
     * (recovery-resolve/recovery-abandon both require the exact intent key) without first
     * having to know a crash happened and go hunting through raw recovery files. */
    const dispatched = allIntents
      .filter((i) => i.state === "dispatched")
      .map((i) => ({ connection_id: i.connection_id, intent_key: i.intent_key, tool: i.tool, dispatched_since: i.dispatched_at || null }));
    recoveryStatus = {
      pending_operator_review: allIntents
        .filter((i) => i.state === "ambiguous")
        .map((i) => ({ connection_id: i.connection_id, intent_key: i.intent_key, tool: i.tool, ambiguous_since: i.ambiguous_at || null, reason: i.ambiguous_reason || null })),
      in_flight: dispatched.length,
      dispatched,
    };
  } catch (error) {
    recoveryStatus = { pending_operator_review: [], in_flight: 0, dispatched: [], error: error.message };
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

/** Shared by recoverCrashedSessions and abandonConnection's own GATEWAY_BUNDLE_ID_
 * COLLISION handling (Codex PR #33 review "verify bundle collisions before discarding
 * recovery state", and its follow-up "verify collisions in recovery-abandon before
 * cleanup"): verified directly against gsa-mcp-shim.js: bundle_id = sha256({init,
 * grantedTools, n: calls.length}) -- a coarse fingerprint with no timestamp, nonce, or
 * actual call content. Re-running recovery/abandon for the SAME crash deterministically
 * reproduces the same bundle_id, which is "already durably appended," not a real
 * conflict -- but a DIFFERENT crashed session that merely happens to share {init,
 * grantedTools, call count} would ALSO collide here, and blindly trusting the id match
 * would then discard that other session's real WAL and completed intents, permanently.
 * Reads back the bundle actually on disk and compares its real content (the execution
 * trace, itself a hash of every call's real arguments/result) before treating this as
 * the expected repeated-attempt case. Returns true only when content is read back and
 * verified identical; any read/parse failure or mismatch returns false (an unverified
 * collision must never be treated as "safe to clean up"). */
function bundleCollisionIsSameContent(stateDir, sealed) {
  try {
    const existingRaw = fs.readFileSync(chain.bundlePath(stateDir, sealed.bundle.manifest.bundle_id), "utf8");
    const existingBundle = JSON.parse(existingRaw);
    // gsa-produce.js#produceBundle never stores artifact bodies on the bundle itself --
    // manifest.artifacts.<name>.sha256 is the real per-artifact content fingerprint (the
    // raw bodies live in bundle.contents, keyed by file path, but the hash already IS the
    // exact equality check needed here). execution_trace alone (per-call input/result
    // hashes, tool, granted, error/model flags) is sufficient: it is a hash of every
    // call's real arguments and result, so two sessions cannot share it without sharing
    // their actual call content.
    const existingHash = existingBundle.manifest && existingBundle.manifest.artifacts && existingBundle.manifest.artifacts.execution_trace && existingBundle.manifest.artifacts.execution_trace.sha256;
    const newHash = sealed.bundle.manifest && sealed.bundle.manifest.artifacts && sealed.bundle.manifest.artifacts.execution_trace && sealed.bundle.manifest.artifacts.execution_trace.sha256;
    return Boolean(existingHash) && existingHash === newHash;
  } catch (readError) {
    return false; // could not verify -- treat as a genuine, unverified conflict
  }
}

/** Codex PR #33 review "verify the chain entry before cleaning a colliding WAL": content
 * verification alone (bundleCollisionIsSameContent above) proves the bundle FILE on disk
 * (chain.appendSession's own step 1) really is this connection's own durable record -- it
 * does NOT prove step 2 (the chain.jsonl append) ever happened. If chain.appendSession
 * crashed after writing the bundle file but before appending chain.jsonl, a recovery pass
 * that stops at content verification would still delete this connection's WAL/intents as
 * "already durably sealed," permanently omitting it from the attestation chain even though
 * it was never actually chain-appended. Shared by recoverCrashedSessions and
 * abandonConnection (same two callers bundleCollisionIsSameContent already serves) so both
 * paths get the identical repair, not just content verification. Returns true (safe to
 * clean up this connection's WAL/intents now -- durably sealed, chain entry confirmed
 * present, repairing it first if it was merely missing) or false (unverified conflict with
 * a genuinely different session; caller must not clean up). May throw if content is
 * verified but the repair write itself fails -- callers must not clean up in that case
 * either, since the chain still does not durably reference this bundle. */
function verifyAndRepairBundleCollision(stateDir, sealed, log) {
  if (!bundleCollisionIsSameContent(stateDir, sealed)) return false;
  const bundleId = sealed.bundle.manifest.bundle_id;
  if (!chain.chainHasEntryForBundle(stateDir, bundleId)) {
    chain.repairMissingChainEntry(stateDir, bundleId);
    log(
      `recovery: bundle "${bundleId}" was durably written but never chain-appended (crash between ` +
        `chain.appendSession's own bundle-write and chain.jsonl-append steps) -- completed the missing ` +
        `chain.jsonl/HEAD.json append now.`
    );
  }
  return true;
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
function recoverCrashedSessions(stateDir, keys, log, writerClaim = null) {
  const pendingOperatorReview = [];
  for (const connectionId of recovery.listActiveConnections(stateDir)) {
    /* Codex PR #33 review "renew ownership during synchronous recovery": this whole
     * per-connection body below is synchronous fs work (WAL replay, session.finalizeSession,
     * chain.appendSession) -- with enough or large enough crash-left WALs it can run past
     * writer-claim.js's own staleAfterMs before ever yielding to the event loop, which is
     * the only place the heartbeat startHeartbeat() already started can actually fire.
     * writer-claim.js's own startHeartbeat() doc comment discloses exactly this gap and
     * prescribes a synchronous renew() call at the boundary of any long synchronous phase
     * this claim is held across (mirroring state-store.js's own _assertStillOwned fix) --
     * done here once PER CONNECTION, not once for the whole loop, so many small WALs are
     * covered the same as one huge one. `writerClaim` is optional (existing direct callers/
     * tests that construct no real claim keep working, renewal simply skipped) but
     * startGateway's own real call site below always passes its live claim. A failed renew
     * means another process may already hold this state_dir -- propagate immediately
     * (uncaught by this loop's own per-connection try/catch further down) rather than keep
     * mutating shared chain/WAL state under a claim that might no longer be exclusive. */
    if (writerClaim) writerClaim.renew();
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
      // Cluster B: reuse the exact session_id this session's own SESSION_START event
      // persisted (proxy.js#openConnection) rather than letting session.createSession
      // mint a fresh one -- replaying the SAME crash-left WAL twice (e.g. this recovery
      // pass itself crashing before cleanup, see recoverIsIdempotentAcrossACrashDuring
      // RecoveryItself in tests/gateway/recovery/run-tests.js) must produce the SAME
      // bundle_id both times. An older WAL written before this field existed has no
      // session_id on its SESSION_START event; passed through as `null` explicitly
      // (never generated here) for the same reason -- see session.js#createSession's own
      // doc comment on the three-way distinction this argument makes.
      const sessionId = startEvent && typeof startEvent.session_id === "string" && startEvent.session_id.length > 0 ? startEvent.session_id : null;
      const s = session.createSession(connectionId, { now: () => Date.now(), goal: startEvent ? startEvent.goal : undefined, sessionId });
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
          session.recordCallStart(s, key, { tool: event.tool, server: event.server, arguments: event.arguments, isModelCall: Boolean(event.isModelCall), ts: event.ts });
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
      // Codex PR #33 review "include the intent key in the advertised resolution
      // command": collected as we go so the RECOVERY_AMBIGUOUS_INTENT log below can name
      // every actual unresolved key, rather than the literal "<key>" placeholder it used
      // to print regardless of how many calls (or which ones) were actually unresolved --
      // recovery-resolve requires the exact key, which an operator otherwise had to
      // discover by hand-parsing raw recovery files.
      const unresolvedIntentKeys = [];
      for (const [key] of Array.from(s.pendingCalls.entries())) {
        const startedFrom = keyToStartEvent.get(key);
        if (!startedFrom) continue; // defensive; should not happen
        if (startedFrom.isModelCall) {
          /* A downstream-initiated sampling/createMessage forward (see
           * forwardDownstreamRequestToAgent's own WAL comment above) has no
           * idempotency-intent fence at all -- Finding 2's fence is deliberately scoped to
           * real tools/call dispatch only, so there is no intent record to consult here and
           * never will be. Unlike a fenced tool call, there is also no external side effect
           * this gateway must avoid duplicating: the only real risk of an unresolved
           * sampling call is an incomplete attestation of what the agent was asked, which
           * this WAL replay has already captured (the CALL_START event, recorded above).
           * Record it as a real, disconnected/unproven result and move on rather than
           * blocking this whole connection's auto-seal on operator review for a call that
           * has nothing an operator could actually resolve (there is no --result-file or
           * --confirmed answer that applies to "did the agent's model happen to finish
           * replying before the crash"). */
          session.recordCallResult(s, key, { result: { error: "gateway restarted after a crash while this downstream-initiated sampling/createMessage forward was still awaiting the agent's response" }, isError: true, ts: Date.now() });
          continue;
        }
        const intentKey = recovery.computeIntentKey(connectionId, startedFrom.tool, startedFrom.arguments);
        const intent = recovery.readIntent(stateDir, intentKey);
        /* Cluster A (generation-aware crash recovery): the intent file's own `generation`
         * field is overwritten IN PLACE on every supersede (proxy.js's dispatch guard),
         * so by the time recovery runs it always reflects the MOST RECENT generation --
         * which is not necessarily the generation THIS specific crashed CALL_START event
         * belongs to. Concretely: generation 1 completes, but its own CALL_RESULT WAL
         * write fails (best-effort, logged, not fatal -- see proxy.js's own comment on
         * that append); the SAME connection later dispatches generation 2 of the exact
         * same (tool, arguments), which also completes and DOES get its CALL_RESULT
         * durably written. A later crash then leaves generation 1's CALL_START forever
         * unresolved in the WAL while the intent file now sits at generation 2. Without
         * this check, the loop below would bind generation 2's cached_result (a
         * DIFFERENT call's real outcome) to generation 1's own pending call -- a false
         * attestation. Comparing against the generation THIS CALL_START event itself
         * recorded (defaulting to 1 for a WAL line written before this field existed)
         * ensures a proven outcome is only ever applied to the generation it actually
         * belongs to; any other generation's crashed call is left for operator review,
         * exactly like a call with no intent record at all. */
        const expectedGeneration = typeof startedFrom.generation === "number" ? startedFrom.generation : 1;
        const intentGeneration = intent && typeof intent.generation === "number" ? intent.generation : 1;
        if (intent && intent.state === "completed" && intentGeneration === expectedGeneration) {
          session.recordCallResult(s, key, { result: intent.cached_result, isError: false, ts: Date.now() });
        } else if (intent && intent.state === "not_executed" && intentGeneration === expectedGeneration) {
          /* Codex PR #33 review "persist a terminal not-executed resolution": an operator
           * already answered "did it execute?" (no) via recovery-resolve while this
           * connection was crashed -- record that as a real (failed) terminal result now,
           * rather than re-flagging the same connection for operator review forever
           * because no "completed" intent will ever appear for a call that never ran. */
          session.recordCallResult(s, key, { result: { error: "operator confirmed via recovery-resolve that this call did not execute downstream" }, isError: true, ts: Date.now() });
        } else {
          needsOperator = true;
          unresolvedIntentKeys.push(intentKey);
        }
      }

      if (needsOperator) {
        pendingOperatorReview.push(connectionId);
        const resolveCommands = unresolvedIntentKeys
          .map((key) => `"node scripts/gateway/gateway.js recovery-resolve --connection ${connectionId} --intent ${key} --confirmed executed|not-executed"`)
          .join(", ");
        log(
          `RECOVERY_AMBIGUOUS_INTENT: connection "${connectionId}" crashed with ${unresolvedIntentKeys.length} call(s) in flight whose outcome is not proven (intent key(s): ${unresolvedIntentKeys.join(", ")}) -- ` +
            `leaving its WAL and intent record(s) in place rather than guessing. Resolve each with ${resolveCommands}, ` +
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
          let verified;
          try {
            verified = verifyAndRepairBundleCollision(stateDir, sealed, log);
          } catch (repairError) {
            log(`RECOVERY CHAIN-REPAIR FAILURE for connection "${connectionId}": ${repairError.message} -- leaving its WAL in place for investigation.`);
            pendingOperatorReview.push(connectionId);
            continue;
          }
          if (verified) {
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
function abandonConnection(stateDir, keys, connectionId, log, writerClaim = null) {
  /* Codex PR #33 review "renew ownership during synchronous recovery": same rationale as
   * recoverCrashedSessions' own per-connection renew() above, applied to this CLI's own
   * synchronous WAL replay/finalize/chain-append for its one connection -- "sufficiently
   * large" applies just as well to a single big WAL as to many small ones. */
  if (writerClaim) writerClaim.renew();
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
  // Cluster B: same reuse-not-regenerate rule as recoverCrashedSessions' own replay
  // above -- see that call site's doc comment and session.js#createSession's.
  const sessionId = startEvent && typeof startEvent.session_id === "string" && startEvent.session_id.length > 0 ? startEvent.session_id : null;
  const s = session.createSession(connectionId, { now: () => Date.now(), goal: startEvent ? startEvent.goal : undefined, sessionId });
  for (const event of events) {
    if (event.type === "SESSION_START") {
      session.recordToolsList(s, event.tools || []);
    } else if (event.type === "INITIALIZE") {
      session.recordInitialize(s, { clientInfo: event.clientInfo, serverInfo: event.serverInfo, model: event.model });
    } else if (event.type === "CALL_START") {
      const key = Symbol.for(`wal-replay:${connectionId}:${event.call_seq}`);
      session.recordCallStart(s, key, { tool: event.tool, server: event.server, arguments: event.arguments, isModelCall: Boolean(event.isModelCall), ts: event.ts });
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
    /* Codex PR #33 review "verify collisions in recovery-abandon before cleanup": this
     * used to treat EVERY collision here as the expected repeated-attempt case and fall
     * straight through to deleting this connection's WAL/intents below -- unlike
     * recoverCrashedSessions' own already-hardened handling of the identical error code,
     * which reads back the bundle on disk and verifies its real content first. An
     * operator running recovery-abandon on a connection that happens to collide with a
     * genuinely DIFFERENT session's bundle_id would silently discard this connection's
     * only remaining unrecoverable record. Apply the same content verification here. */
    let verified;
    try {
      verified = verifyAndRepairBundleCollision(stateDir, sealed, log);
    } catch (repairError) {
      throw fail(
        `recovery-abandon: connection "${connectionId}" bundle "${sealed.bundle.manifest.bundle_id}" was content-verified as this connection's own record, but completing its missing chain.jsonl append failed: ${repairError.message}. Refusing to abandon: this connection's WAL/intents are NOT cleaned up (the chain still does not durably reference this bundle) -- investigate and retry.`,
        "GATEWAY_RECOVERY_CHAIN_REPAIR_FAILED"
      );
    }
    if (!verified) {
      throw fail(
        `recovery-abandon: connection "${connectionId}" produced bundle_id "${sealed.bundle.manifest.bundle_id}", which already exists on disk, but its recorded content does NOT match this connection's recovered session -- a genuine conflict with a different session, not a repeated abandon attempt. Refusing to abandon: deleting this connection's WAL/intents now would discard its only remaining, unrecoverable record. Investigate the existing bundle before retrying.`,
        "GATEWAY_RECOVERY_UNVERIFIED_BUNDLE_COLLISION"
      );
    }
    log(`recovery-abandon: connection "${connectionId}" was already durably sealed (bundle_id collision, content-verified match) -- cleaning up.`);
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
        /* Codex PR #33 review "stop advising a false not-executed resolution": this
         * message used to suggest "use --confirmed not-executed instead" as the fallback
         * when the operator lacks a result file -- but an operator who chose --confirmed
         * executed in the first place is telling this CLI they KNOW the side effect ran;
         * following that suggestion would record the opposite of what they know happened,
         * seal it as a failed/non-executed call, and release the fence so a retry repeats
         * the side effect. The only truthful options when the exact result is unrecoverable
         * are to leave the intent unresolved for now, or to explicitly give up the fence
         * via recovery-abandon -- never to assert non-execution that isn't true. */
        throw fail(
          "recovery-resolve --confirmed executed requires --result-file <path>: a null result would be " +
            "replayed as an unverified clean success in the sealed bundle. If you know this call executed " +
            "but cannot recover its exact result, do NOT use --confirmed not-executed -- that records the " +
            "opposite of what you know happened and lets a future retry repeat the side effect. Instead, " +
            "either supply the real result via --result-file once you can recover it, leave this intent " +
            "unresolved for now (this connection will keep being flagged for operator review on every " +
            "restart, harmlessly), or use recovery-abandon to explicitly give up the fence on this connection.",
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
    abandonConnection(config.state_dir, keys, connectionId, log, writerClaim);
  } finally {
    writerClaim.release();
  }
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
    ({ pendingOperatorReview } = recoverCrashedSessions(config.state_dir, keys, log, writerClaim));
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
    // Frontier-panel decision (Paul, 2026-09-10, cluster E2): see proxy.js's own
    // pendingOperatorReviewConnections constructor comment for why a startup snapshot
    // is sufficient here.
    pendingOperatorReviewConnections: pendingOperatorReview,
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
    /* Codex PR #33 review "release the writer claim when intent cleanup aborts shutdown":
     * closeConnection can throw before reaching its own guarded sealing block (e.g.
     * recovery.listIntentsForConnection hitting a corrupt/unreadable intent FILE for this
     * connection -- a genuine fs-level problem, not the kind of failure this codebase
     * treats as recoverable). Previously unguarded here, so one such connection's failure
     * escaped this loop entirely, skipping every remaining connection's own close, every
     * downstream conn.close() below, and writerClaim.release() -- leaking a stale claim
     * that blocks the next restart. Isolate per-connection failures (mirrors
     * recoverCrashedSessions' own per-connection try/catch) so shutdown always reaches
     * the downstream-close and writer-claim-release steps regardless. */
    for (const connectionId of Array.from(proxy.sessions.keys())) {
      try {
        await proxy.closeConnection(connectionId, `gateway shutdown (${reason || "requested"})`);
      } catch (error) {
        log(`SHUTDOWN CLOSE FAILURE for connection "${connectionId}": ${error.message} (${error.code || "no code"}) -- continuing shutdown for other sessions and releasing the writer claim regardless.`);
      }
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
  const log = (...args) => console.error("[graphsmith-gateway]", ...args);
  const argv = process.argv.slice(2);
  if (argv[0] === "recovery-resolve" || argv[0] === "recovery-abandon") {
    try {
      if (argv[0] === "recovery-resolve") runRecoveryResolveCli(argv.slice(1), log);
      else runRecoveryAbandonCli(argv.slice(1), log);
    } catch (error) {
      console.error(`[graphsmith-gateway] FATAL: ${error.message}`);
      process.exitCode = 1;
    }
    return;
  }
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
  recoverCrashedSessions,
  abandonConnection,
  runRecoveryResolveCli,
  runRecoveryAbandonCli,
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
