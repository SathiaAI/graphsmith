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
const { drainOpenSessions } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
const { GatewayProxy } = require(path.join(ROOT, "scripts", "gateway", "proxy.js"));

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

async function main() {
  await drainWaitsForInFlightCallToComplete();
  await drainTimesOutAndReportsIncomplete();
  await drainWithNoOpenSessionsReturnsImmediately();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main().catch((error) => {
  console.error("FATAL:", error.stack || error.message);
  process.exit(1);
});
