#!/usr/bin/env node
"use strict";

/* tests/state-store/numeric-edge-cases/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. `positiveInteger()` (scripts/
 * state-store.js:41-44) backs every numeric knob in the file (leaseMs, heartbeatMs, window
 * n, max_window_wall_time_ms) but every existing test always supplies a well-formed positive
 * integer through the PRIMARY field name -- the fallback-on-invalid-value branch and the
 * capitalized `N` alias have never been exercised. Also covers the heartbeat-must-be-below-
 * lease auto-adjustment (:496) and the lease-expiry safe-integer overflow guard (:484),
 * neither of which any existing suite forces off its happy path. */

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const { createStore: rawCreateStore } = require(STATE_STORE);
const { createManualClock } = require("../../_harness/clock.js");

let failures = 0;
const results = [];

function report(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) report(name, "PASS"); else report(name, "FAIL", reason);
}

function tempRoot(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `gs-numeric-${label}-`)); }
function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
function withEnv(patch, fn) {
  const prev = {};
  for (const k of Object.keys(patch)) { prev[k] = process.env[k]; if (patch[k] === undefined) delete process.env[k]; else process.env[k] = patch[k]; }
  try { return fn(); } finally { for (const k of Object.keys(patch)) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; } }
}
function createStore(root, opts = {}) { return rawCreateStore(root, Object.assign({ clock: createManualClock() }, opts)); }

/* ---- admitPending's `n`/`N` alias and its invalid-value fallback to the default (5) ---- */
function admitPendingNAliasAndFallback() {
  const root = tempRoot("n-alias");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const withCapitalN = store.window.admitPending({ txid: "tx-capital-n", fingerprint: "fp1", tree_id: "t1", N: 7 });
      check("admitPending-capital-N-alias-used", withCapitalN.window.n === 7,
        `expected n:7 via the capitalized N alias, got ${withCapitalN.window.n}`);

      const store2 = createStore(tempRoot("n-invalid"), { leaseMs: 5000, heartbeatMs: 500 });
      const withInvalidN = store2.window.admitPending({ txid: "tx-invalid-n", fingerprint: "fp2", tree_id: "t2", n: -3 });
      check("admitPending-negative-n-falls-back-to-default-5", withInvalidN.window.n === 5,
        `a negative n must fall back to the default of 5, got ${withInvalidN.window.n}`);

      const store3 = createStore(tempRoot("n-zero"), { leaseMs: 5000, heartbeatMs: 500 });
      const withZeroN = store3.window.admitPending({ txid: "tx-zero-n", fingerprint: "fp3", tree_id: "t3", n: 0 });
      check("admitPending-zero-n-falls-back-to-default-5", withZeroN.window.n === 5,
        `a zero n must fall back to the default of 5 (n must be positive), got ${withZeroN.window.n}`);
    });
  } catch (e) { report("admit-pending-n-alias-and-fallback", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- max_window_wall_time_ms: invalid custom value falls back to the 7-day default ---- */
function maxWindowWallTimeInvalidFallsBackToDefault() {
  const root = tempRoot("wall-fallback");
  const DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const result = store.window.admitPending({ txid: "tx-wall-fallback", fingerprint: "fp-wf", tree_id: "t-wf", n: 1, max_window_wall_time_ms: -1 });
      check("max-window-wall-time-invalid-falls-back-to-7-day-default",
        result.window.max_window_wall_time_ms === DEFAULT_WINDOW_MS,
        `an invalid (negative) max_window_wall_time_ms must fall back to the 7-day default (${DEFAULT_WINDOW_MS}), got ${result.window.max_window_wall_time_ms}`);
    });
  } catch (e) { report("max-window-wall-time-invalid-falls-back-to-default", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- heartbeatMs >= leaseMs auto-adjustment: floor(leaseMs / 3), at and past the boundary ---- */
function heartbeatAutoAdjustsWhenNotBelowLease() {
  const root = tempRoot("heartbeat-adjust");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      // Exactly EQUAL: `>=` must fire here, not only when heartbeatMs exceeds leaseMs.
      const store = createStore(root, { leaseMs: 90, heartbeatMs: 90 });
      check("heartbeat-equal-to-lease-is-auto-adjusted", store.heartbeatMs === Math.floor(90 / 3),
        `heartbeatMs equal to leaseMs must be auto-adjusted to floor(leaseMs/3)=30, got ${store.heartbeatMs}`);

      // One less than leaseMs: must NOT be adjusted (a `>` mutant would fail to adjust the
      // equal case above; a `>=` boundary test alone cannot tell `>=` from `>` without also
      // confirming the non-adjusted side still behaves as a genuine below-lease value).
      const store2 = createStore(tempRoot("heartbeat-below"), { leaseMs: 90, heartbeatMs: 89 });
      check("heartbeat-one-below-lease-is-not-adjusted", store2.heartbeatMs === 89,
        `heartbeatMs one below leaseMs must be left alone, got ${store2.heartbeatMs}`);

      // Genuinely exceeding: also adjusted.
      const store3 = createStore(tempRoot("heartbeat-above"), { leaseMs: 90, heartbeatMs: 500 });
      check("heartbeat-above-lease-is-auto-adjusted", store3.heartbeatMs === Math.floor(90 / 3),
        `heartbeatMs above leaseMs must be auto-adjusted to floor(leaseMs/3)=30, got ${store3.heartbeatMs}`);

      // The floor has its own floor: Math.max(1, ...) so a tiny leaseMs never produces 0.
      const store4 = createStore(tempRoot("heartbeat-tiny"), { leaseMs: 2, heartbeatMs: 2 });
      check("heartbeat-adjustment-never-goes-below-1", store4.heartbeatMs === 1,
        `floor(2/3)=0, so the Math.max(1, ...) floor must keep heartbeatMs at 1, got ${store4.heartbeatMs}`);
    });
  } catch (e) { report("heartbeat-auto-adjusts-when-not-below-lease", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- lease-expiry overflow guard: a leaseMs large enough to push `now + leaseMs` outside
 * Number.MAX_SAFE_INTEGER must be reported as BAD_LEASE_CLOCK, not silently wrap/truncate. ---- */
function leaseExpiryOverflowIsRejected() {
  const root = tempRoot("expiry-overflow");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: Number.MAX_SAFE_INTEGER });
      let threw = null;
      try { store.runRegistry.register("run-overflow", "tree-overflow"); }
      catch (e) { threw = e; }
      check("lease-expiry-overflow-throws-bad-lease-clock",
        Boolean(threw) && threw.code === "BAD_LEASE_CLOCK",
        `a lease expiry that overflows the safe-integer range must throw BAD_LEASE_CLOCK, got ${threw ? threw.code : "no error"}`);
      check("lease-expiry-overflow-message-names-both-operands",
        Boolean(threw) && threw.message.includes("leaseMs"),
        `expected the overflow message to name leaseMs, got ${threw && threw.message}`);
    });
  } catch (e) { report("lease-expiry-overflow-is-rejected", "FAIL", e.message); }
  finally { rmrf(root); }
}

function main() {
  admitPendingNAliasAndFallback();
  maxWindowWallTimeInvalidFallsBackToDefault();
  heartbeatAutoAdjustsWhenNotBelowLease();
  leaseExpiryOverflowIsRejected();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
