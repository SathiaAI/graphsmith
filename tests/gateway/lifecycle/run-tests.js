#!/usr/bin/env node
"use strict";

/* Regression suite for the graceful-shutdown DRAIN behavior (Standalone Gateway TRD
 * SS3.7/SS8 test 5), at the unit level -- against scripts/gateway/gateway.js's
 * drainOpenSessions() directly with a fake slow downstream connection, NOT via a real
 * OS SIGTERM. This is deliberate: Windows cannot deliver a real SIGTERM for graceful
 * in-process handling (child.kill('SIGTERM') force-terminates there), so
 * tests/gateway/e2e's own SIGTERM test is skipped on win32 -- this suite instead proves
 * the actual drain LOGIC cross-platform, independent of OS signal delivery. The real
 * end-to-end proof (a genuine SIGTERM to a real child process) still runs on any
 * non-Windows CI runner via tests/gateway/e2e/run-tests.js.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const { drainOpenSessions, startGateway } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
const { GatewayProxy } = require(path.join(ROOT, "scripts", "gateway", "proxy.js"));
const { WriterClaim } = require(path.join(ROOT, "scripts", "writer-claim.js"));
const { writeConfirmedMode } = require("../_fixtures/mode-file.js");
const recovery = require(path.join(ROOT, "scripts", "gateway", "recovery.js"));
const FIXTURE_SERVER = path.join(ROOT, "tests", "gateway", "_fixtures", "fixture-mcp-server.js");

let failures = 0;
const results = [];
function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}
function check(name, cond, reason) {
  record(name, cond ? "PASS" : "FAIL", reason);
}

function freshDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-lifecycle-${prefix}-`));
}
function makeKeys() {
  const kp = crypto.generateKeyPairSync("ed25519");
  return { privateKey: kp.privateKey, signer: "test-key", algo: "ed25519" };
}

/** A downstream connection whose call resolves after `delayMs`. */
function delayedConnection(delayMs, result) {
  return {
    transport: "fake",
    call: () => new Promise((resolve) => setTimeout(() => resolve(result), delayMs)),
    close: () => {},
    isClosed: () => false,
    whenClosed: () => new Promise(() => {}),
  };
}

async function drainWaitsForInFlightCallToComplete() {
  const dir = freshDir("waits");
  const conn = delayedConnection(150, { ok: true, marker: "real-result" });
  const proxy = new GatewayProxy({
    connections: new Map([["srv", conn]]),
    mergedTools: [{ name: "slow", server: "srv", schema: {} }],
    toolOwners: new Map([["slow", "srv"]]),
    serverInfos: {},
    keys: makeKeys(),
    stateDir: dir,
  });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", method: "notifications/initialized" });
  const callPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: {} } });

  const drained = await drainOpenSessions(proxy, 2000, 10);
  check("drain-reports-clean-when-call-finishes-in-time", drained === true, String(drained));

  const response = await callPromise;
  check("drained-call-still-completed-with-real-result", response.result && response.result.marker === "real-result", JSON.stringify(response));

  const s = proxy.sessions.get("conn-1");
  check("session-has-no-pending-calls-after-drain", s.pendingCalls.size === 0, String(s.pendingCalls.size));
  const entry = await proxy.closeConnection("conn-1", "test cleanup");
  const bundle = JSON.parse(fs.readFileSync(require(path.join(ROOT, "scripts", "gateway", "chain.js")).bundlePath(dir, entry.bundle_id), "utf8"));
  check("finalized-bundle-shows-the-call-as-NOT-an-error", /"is_error":false/.test(bundle.contents["execution_trace.jsonl"]), bundle.contents["execution_trace.jsonl"]);
}

async function drainTimesOutAndReportsIncomplete() {
  const dir = freshDir("timeout");
  const conn = delayedConnection(5000, { ok: true }); // far longer than the drain budget below
  const proxy = new GatewayProxy({
    connections: new Map([["srv", conn]]),
    mergedTools: [{ name: "veryslow", server: "srv", schema: {} }],
    toolOwners: new Map([["veryslow", "srv"]]),
    serverInfos: {},
    keys: makeKeys(),
    stateDir: dir,
  });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", method: "notifications/initialized" });
  proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "veryslow", arguments: {} } }); // fire and forget

  const drained = await drainOpenSessions(proxy, 100, 10); // budget far shorter than the call
  check("drain-reports-incomplete-on-timeout", drained === false, String(drained));

  // After a timed-out drain, gateway.js's stop() proceeds to closeConnection anyway,
  // which must mark the still-pending call disconnected rather than hang forever.
  const entry = await proxy.closeConnection("conn-1", "drain timeout exceeded");
  check("timed-out-drain-still-produces-a-finalized-bundle", entry !== null, "no entry appended");
}

async function drainWithNoOpenSessionsReturnsImmediately() {
  const dir = freshDir("none-open");
  const proxy = new GatewayProxy({ connections: new Map(), mergedTools: [], toolOwners: new Map(), serverInfos: {}, keys: makeKeys(), stateDir: dir });
  const start = Date.now();
  const drained = await drainOpenSessions(proxy, 5000, 10);
  const elapsed = Date.now() - start;
  check("drain-with-no-sessions-returns-true", drained === true, String(drained));
  check("drain-with-no-sessions-returns-fast", elapsed < 500, `took ${elapsed}ms`);
}

/* Codex PR #29 review round 8 "install shutdown handlers before gateway startup
 * completes": main() only registers SIGTERM/SIGINT AFTER startGateway() resolves, so a
 * termination received while a slow downstream handshake is still in progress previously
 * fell through to Node's default immediate-exit behavior, skipping cleanup of an
 * already-acquired writer-claim. Rather than move handler registration earlier (the
 * panel-rejected approach -- see STARTUP_DOWNSTREAM_CONNECT_TIMEOUT_MS's own header
 * comment in gateway.js), startGateway() now bounds the slow step itself: a downstream
 * that spawns but never completes its handshake makes startup fail cleanly instead of
 * hanging forever, through the SAME failure path (writerClaim.release() + reject) an
 * outright connection refusal already uses. Uses a real hung child process (a `node -e`
 * one-liner that spawns and idles forever, never speaking JSON-RPC), not a fake, since
 * this exercises connectAllDownstreams' real spawn/handshake path -- but calls
 * startGateway() directly (not the CLI) with a short startupDownstreamConnectTimeoutMs
 * override so the test runs in well under a second rather than waiting out the real
 * production default (mirrors drainTimeoutMs/statusWriteIntervalMs's own existing
 * options-override pattern in this same function). */
async function startupWatchdogTimesOutOnHungDownstreamConnect() {
  const root = freshDir("startup-watchdog");
  writeConfirmedMode(root, "standalone");
  const kp = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  const stateDir = path.join(root, "state");
  // connectStdio splits its endpoint on whitespace with no shell (see its own header
  // comment) -- an inline `node -e "..."` one-liner containing spaces/parens would be
  // split apart wrong, so this spawns a tiny real script file instead, matching the
  // existing fixture-server convention (`node <path> [args]`, no embedded shell syntax).
  const hangScriptPath = path.join(root, "hangs-forever.js");
  const hangPidPath = path.join(root, "hangs-forever.pid");
  // Writes its own pid before idling so this test can reap it afterward (see the
  // try/finally below) -- this scenario is EXACTLY "a downstream that never completes its
  // handshake" (the panel deliberately did not ask this fix to safely tear down
  // partially-initialized startup state -- see this test's own header comment), so nothing
  // inside startGateway()/connectAllDownstreams itself kills this child; only this test's
  // own cleanup does, so it doesn't leave an orphan idling on the machine after the test.
  fs.writeFileSync(hangScriptPath, `require("fs").writeFileSync(${JSON.stringify(hangPidPath)}, String(process.pid)); setInterval(() => {}, 1 << 30);\n`);
  const config = {
    schema_version: "1.0",
    state_dir: stateDir,
    // Spawns successfully (so connectAllDownstreams gets a live child) but never speaks a
    // word of JSON-RPC -- its "initialize" call hangs forever, exactly the "slow
    // downstream handshake in progress" scenario this watchdog exists to bound.
    downstream_servers: [{ name: "hangs", transport: "stdio", endpoint: `${process.execPath} ${hangScriptPath}` }],
    signing_key_ref: keyPath,
  };
  const configPath = path.join(root, "gateway-config.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

  const start = Date.now();
  let thrown = null;
  try {
    await startGateway({ configPath, startupDownstreamConnectTimeoutMs: 200 });
  } catch (error) {
    thrown = error;
  }
  const elapsed = Date.now() - start;

  check("startup-watchdog-fails-closed-rather-than-hanging-forever", thrown !== null, "startGateway resolved instead of rejecting");
  check("startup-watchdog-error-names-the-timeout", Boolean(thrown && thrown.code === "GATEWAY_STARTUP_TIMEOUT"), thrown && thrown.message);
  check("startup-watchdog-fires-within-a-bounded-window-not-indefinitely", elapsed < 5000, `took ${elapsed}ms`);

  // The SAME startup-failure cleanup path a genuine connect failure already uses must
  // still have released the writer-claim -- otherwise a timed-out startup would leave a
  // stale claim blocking the next start attempt, exactly the failure mode this fix exists
  // to avoid. status().claimed reads fresh from disk and is instance-independent (unlike
  // held_by_this_instance, which only ever answers for the SAME WriterClaim instance that
  // acquired it), so a fresh WriterClaim here can honestly observe whether the on-disk
  // claim file was actually removed.
  const claimStatus = new WriterClaim(stateDir).status();
  check("startup-watchdog-failure-releases-the-writer-claim", claimStatus.claimed === false, JSON.stringify(claimStatus));

  // Reap the hung child this test itself spawned (see hangScriptPath's own comment) --
  // best effort, polling briefly since the pidfile write races this test's own assertions.
  for (let i = 0; i < 20 && !fs.existsSync(hangPidPath); i++) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  try {
    const pid = parseInt(fs.readFileSync(hangPidPath, "utf8"), 10);
    if (Number.isInteger(pid)) process.kill(pid, "SIGKILL");
  } catch (error) {
    // best effort only -- an already-dead or never-spawned process is not this test's
    // own assertion to make.
  }
}

/* Codex PR #29 review round 8 "cap completed downstream sampling history": proxy.js's own
 * agent-initiated dispatch enforces MAX_COMPLETED_CALLS_PER_SESSION, but this SEPARATE
 * downstream-initiated sampling path (forwardDownstreamRequestToAgent, exercised
 * end-to-end via a real downstream in tests/gateway/e2e's own sampling tests) never
 * consulted it -- a sampling-capable stdio downstream issuing requests sequentially could
 * grow session.calls without bound. Exercised here at the unit level, against a fake
 * session/proxy/agentPusher, specifically to prove the ADMISSION REFUSAL at the cap --
 * driving session.calls up to the real cap via genuine round trips would be far too slow
 * for a unit suite (same rationale proxy/run-tests.js's own completedCallHistoryCapped
 * test already documents for the agent-initiated case). */
async function samplingForwardRefusesOnceCompletedCallCapReached() {
  const { forwardDownstreamRequestToAgent } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
  const { MAX_COMPLETED_CALLS_PER_SESSION } = require(path.join(ROOT, "scripts", "gateway", "proxy.js"));
  const sessionModule = require(path.join(ROOT, "scripts", "gateway", "session.js"));
  const s = sessionModule.createSession("agent-conn-1");
  s.calls.length = MAX_COMPLETED_CALLS_PER_SESSION; // cheap stand-in for that many genuinely-completed calls
  const proxy = { sessions: new Map([["agent-conn-1", s]]), now: () => Date.now() };
  let agentWasAsked = false;
  const agentPusher = { current: () => { agentWasAsked = true; return Promise.resolve({}); }, connectionId: "agent-conn-1" };

  const resp = await forwardDownstreamRequestToAgent(
    { jsonrpc: "2.0", id: 7, method: "sampling/createMessage", params: {} },
    agentPusher,
    () => {},
    proxy,
    "srv"
  );
  check(
    "sampling-forward-refuses-once-completed-call-cap-reached",
    Boolean(resp.error && resp.error.code === -32000 && /already completed/.test(resp.error.message)),
    JSON.stringify(resp)
  );
  check("sampling-forward-does-not-reach-the-agent-once-refused", agentWasAsked === false, String(agentWasAsked));
  check("sampling-forward-cap-refusal-does-not-grow-session-calls", s.calls.length === MAX_COMPLETED_CALLS_PER_SESSION, String(s.calls.length));
}

/* Same cap, exercised well BELOW it: a session with room left must still have its
 * downstream-initiated sampling request forwarded to the agent as normal -- proving the
 * new check in samplingForwardRefusesOnceCompletedCallCapReached's own fix is a genuine
 * admission gate, not an accidental blanket refusal. */
async function samplingForwardStillWorksBelowTheCap() {
  const { forwardDownstreamRequestToAgent } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
  const sessionModule = require(path.join(ROOT, "scripts", "gateway", "session.js"));
  const s = sessionModule.createSession("agent-conn-2");
  // Cluster H (frontier-panel review, 2026-09-14): forwardDownstreamRequestToAgent now
  // unconditionally appends a CALL_START/CALL_RESULT pair to the recovery WAL for this
  // path too (PR #33), so this fake proxy needs a real stateDir for recovery.appendWalEvent
  // to write into -- this test predates that addition and previously got away with a
  // bare {sessions, now} stand-in.
  const stateDir = freshDir("sampling-forward-below-cap");
  const proxy = { sessions: new Map([["agent-conn-2", s]]), now: () => Date.now(), stateDir };
  const agentPusher = { current: () => Promise.resolve({ role: "assistant", content: { type: "text", text: "ok" } }), connectionId: "agent-conn-2" };

  const resp = await forwardDownstreamRequestToAgent(
    { jsonrpc: "2.0", id: 8, method: "sampling/createMessage", params: {} },
    agentPusher,
    () => {},
    proxy,
    "srv"
  );
  check("sampling-forward-succeeds-below-the-cap", Boolean(resp.result && resp.result.content && resp.result.content.text === "ok"), JSON.stringify(resp));
  check("sampling-forward-records-the-completed-call-below-the-cap", s.calls.length === 1 && s.calls[0].model_call === true, JSON.stringify(s.calls));
}


/* Codex PR #33 review "prevent shutdown diagnostics from aborting claim release": an
 * earlier round of this PR wrapped each connection's closeConnection in a try/catch so one
 * failing session could not abort shutdown -- but the HANDLER itself called the
 * caller-supplied `log` callback directly. `log` is caller plumbing and is allowed to
 * throw, so a throwing logger reintroduced the exact failure one level up: doStop rejected
 * before the remaining sessions, the downstream closes, and writerClaim.release() ever ran,
 * leaving an embedding process renewing an orphaned claim indefinitely. */
async function aThrowingLoggerDuringShutdownStillReleasesTheWriterClaim() {
  const root = freshDir("shutdown-throwing-logger");
  writeConfirmedMode(root, "standalone");
  const kp = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  const stateDir = path.join(root, "state");
  const tokenPath = path.join(root, "agent-token.txt");
  fs.writeFileSync(tokenPath, "shutdown-logger-test-token");
  const configPath = path.join(root, "gateway-config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    schema_version: "1.0",
    state_dir: stateDir,
    downstream_servers: [{ name: "fixture", transport: "stdio", endpoint: `${process.execPath} ${FIXTURE_SERVER} --server-name fixture` }],
    signing_key_ref: keyPath,
    /* Deliberately the HTTP agent transport, not stdio: the stdio branch wires
     * `stdioHandle.closed -> stop() -> process.exit(0)`, so stopping a stdio gateway
     * in-process would terminate this whole test runner before it could report. The
     * shutdown path under test (doStop's diagnostics and writerClaim.release()) is
     * transport-independent. */
    agent_listen: { transport: "http", token_ref: tokenPath },
  }, null, 2));

  // A logger that works during startup (so the gateway actually starts) but throws for
  // every shutdown diagnostic -- precisely the caller-supplied-plumbing failure mode.
  let shuttingDown = false;
  const log = () => { if (shuttingDown) throw new Error("caller-supplied logger exploded during shutdown"); };

  const handle = await startGateway({ configPath, root, log });
  check("throwing-logger-shutdown-gateway-actually-started", Boolean(handle) && handle.dormant !== true, JSON.stringify(handle && { dormant: handle.dormant }));

  // Open a real session AND make its close fail, so the catch handler (the one that used
  // to call the throwing logger directly) is genuinely entered during shutdown.
  handle.proxy.openConnection("conn-shutdown");
  await handle.proxy.handleMessage("conn-shutdown", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  fs.mkdirSync(recovery.intentsDir(stateDir), { recursive: true });
  fs.mkdirSync(recovery.intentPath(stateDir, "corrupt-intent"), { recursive: true });

  shuttingDown = true;
  let stopError = null;
  try {
    await handle.stop("test shutdown");
  } catch (error) {
    stopError = error;
  }
  check("throwing-logger-during-shutdown-does-not-reject-stop", stopError === null, stopError && stopError.message);

  // Decisive proof the claim was actually released: a brand-new instance must be able to
  // acquire it immediately, with no stale-lease wait.
  const fresh = new WriterClaim(stateDir, { hostId: "post-shutdown-check" });
  let acquireError = null;
  try { fresh.acquire(); fresh.release(); } catch (error) { acquireError = error; }
  check("throwing-logger-during-shutdown-still-releases-the-writer-claim", acquireError === null, acquireError && acquireError.message);
}

async function main() {
  await drainWaitsForInFlightCallToComplete();
  await drainTimesOutAndReportsIncomplete();
  await drainWithNoOpenSessionsReturnsImmediately();
  await samplingForwardRefusesOnceCompletedCallCapReached();
  await samplingForwardStillWorksBelowTheCap();
  await startupWatchdogTimesOutOnHungDownstreamConnect();
  await aThrowingLoggerDuringShutdownStillReleasesTheWriterClaim();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main().catch((error) => {
  console.error("FATAL:", error.stack || error.message);
  process.exit(1);
});
