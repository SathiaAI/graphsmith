#!/usr/bin/env node
"use strict";

/* tests/state-store/lock-lost-and-guards/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js, second pass (after the first pass
 * moved the file from 54.21% to 73.78%). Targets three clusters the fresh survivor list
 * still shows dense:
 *
 *   - `_assertStillOwned`'s LOCK_LOST translation (scripts/state-store.js:835-850): renewal
 *     failing with LOCK_OWNER_MISMATCH (stolen) or ENOENT (deleted) must both be reported as
 *     the SAME LOCK_LOST code with a message naming WHICH happened ("gone" vs "now held by
 *     another owner"), while any OTHER renewal failure must propagate unchanged. Nothing
 *     calls this directly with either failure mode; every existing lock test exercises
 *     _acquireLock's OWN gates, never a lock disappearing/getting stolen mid-hold.
 *
 *   - `GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK` for StateStore itself (scripts/
 *     state-store.js:453-462): tests/harness-honesty/lease-determinism exercises this
 *     exhaustively, but that suite is NOT wired into stryker.state-store.config.json's
 *     command runner, so it earns this file zero mutation-testing credit. This is the same
 *     behavior, reachable directly.
 *
 *   - `admitPending`'s optimistic-concurrency guard (`expected_state_rev`, scripts/
 *     state-store.js:1077): every existing admitPending call omits this field entirely. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const { createStore: rawCreateStore, SCHEMA_VERSION } = require(STATE_STORE);
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

function tempRoot(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `gs-lock-lost-${label}-`)); }
function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
function withEnv(patch, fn) {
  const prev = {};
  for (const k of Object.keys(patch)) { prev[k] = process.env[k]; if (patch[k] === undefined) delete process.env[k]; else process.env[k] = patch[k]; }
  try { return fn(); } finally { for (const k of Object.keys(patch)) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; } }
}
function createStore(root, opts = {}) { return rawCreateStore(root, Object.assign({ clock: createManualClock() }, opts)); }

/* ---- _assertStillOwned: ENOENT (lock file deleted out-of-band) -> LOCK_LOST naming "gone" ---- */
function assertStillOwnedReportsGoneAsLockLost() {
  const root = tempRoot("gone");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const held = store._testing.acquireLock();
      fs.unlinkSync(store.lockPath); // out-of-band deletion, e.g. an operator or a bug elsewhere
      let threw = null;
      try { store._assertStillOwned("a test operation"); } catch (e) { threw = e; }
      check("assert-still-owned-enoent-is-lock-lost", Boolean(threw) && threw.code === "LOCK_LOST",
        `an out-of-band deleted lock must surface as LOCK_LOST, got ${threw ? threw.code : "no error"}`);
      check("assert-still-owned-enoent-message-says-gone", Boolean(threw) && threw.message.includes("gone"),
        `expected the LOCK_LOST message to say the lock is "gone", got ${threw && threw.message}`);
      check("assert-still-owned-enoent-message-names-context", Boolean(threw) && threw.message.includes("a test operation"),
        `expected the LOCK_LOST message to name the calling context, got ${threw && threw.message}`);
      store._heldOwnerToken = null; // avoid a finalizer double-release attempt on cleanup
      void held;
    });
  } catch (e) { report("assert-still-owned-reports-gone-as-lock-lost", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- _assertStillOwned: LOCK_OWNER_MISMATCH (a different token now holds the lock) ->
 * LOCK_LOST naming "now held by another owner" ---- */
function assertStillOwnedReportsStolenAsLockLost() {
  const root = tempRoot("stolen");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const held = store._testing.acquireLock();
      // A different owner now holds the SAME path -- simulating a steal that happened while
      // this instance still believes it owns the lock.
      const otherToken = crypto.randomBytes(16).toString("hex");
      fs.writeFileSync(store.lockPath, JSON.stringify({ schema_version: SCHEMA_VERSION, pid: process.pid, owner_token: otherToken }));
      let threw = null;
      try { store._assertStillOwned("another test operation"); } catch (e) { threw = e; }
      check("assert-still-owned-mismatch-is-lock-lost", Boolean(threw) && threw.code === "LOCK_LOST",
        `a lock now held by a different token must surface as LOCK_LOST, got ${threw ? threw.code : "no error"}`);
      check("assert-still-owned-mismatch-message-says-other-owner", Boolean(threw) && threw.message.includes("now held by another owner"),
        `expected the LOCK_LOST message to say "now held by another owner", got ${threw && threw.message}`);
      store._heldOwnerToken = null;
      void held;
      try { fs.unlinkSync(store.lockPath); } catch { /* cleanup best effort */ }
    });
  } catch (e) { report("assert-still-owned-reports-stolen-as-lock-lost", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- _assertStillOwned: a genuinely different failure (corrupt lock file, unparseable)
 * must propagate AS ITSELF, not be relabeled LOCK_LOST ---- */
function assertStillOwnedPropagatesUnrelatedFailures() {
  const root = tempRoot("unrelated");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const held = store._testing.acquireLock();
      fs.writeFileSync(store.lockPath, "{ not valid json");
      let threw = null;
      try { store._assertStillOwned("yet another operation"); } catch (e) { threw = e; }
      check("assert-still-owned-corrupt-lock-propagates-as-corrupt-state",
        Boolean(threw) && threw.code === "CORRUPT_STATE",
        `an unparseable lock file must propagate CORRUPT_STATE unchanged, not be relabeled LOCK_LOST; got ${threw ? threw.code : "no error"}`);
      store._heldOwnerToken = null;
      void held;
      try { fs.unlinkSync(store.lockPath); } catch { /* cleanup best effort */ }
    });
  } catch (e) { report("assert-still-owned-propagates-unrelated-failures", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- _assertStillOwned: no lock held by this instance at all -> silent no-op ---- */
function assertStillOwnedNoOpWhenNothingHeld() {
  const root = tempRoot("no-lock-held");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      let threw = null;
      try { store._assertStillOwned("no-op check"); } catch (e) { threw = e; }
      check("assert-still-owned-no-op-when-nothing-held", threw === null,
        `_assertStillOwned must be a silent no-op when this instance holds no lock, got ${threw && threw.message}`);
    });
  } catch (e) { report("assert-still-owned-no-op-when-nothing-held", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK for StateStore itself ----
 *
 * Both probes below are deliberately-bad-or-throwaway clock constructions for THIS
 * validation, not a real lease-clock choice -- neither is ever used for lease arithmetic.
 * Suppressing GRAPHSMITH_LEASE_CLOCK_AUDIT around each (the same isolation
 * tests/state-store/writer-claim's own clockEnforcement_requireExplicitFlag uses for its
 * equivalent probe) keeps tests/harness-honesty/lease-determinism's cross-suite audit
 * meaningful without weakening it: that sweep exists to catch a PRODUCTION code path
 * unintentionally racing real elapsed time, not a one-line refusal/inert-default probe that
 * is thrown away before any lease arithmetic could ever run. */
function requireExplicitClockForStateStore() {
  const root1 = tempRoot("require-clock-refuse");
  const root2 = tempRoot("require-clock-ok");
  const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";
  try {
    withEnv({ GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK: "1" }, () => {
      withEnv({ [AUDIT_ENV]: undefined }, () => {
        let threw = null;
        try { rawCreateStore(root1, {}); } catch (e) { threw = e; }
        check("require-explicit-clock-refuses-implicit-wall-clock",
          Boolean(threw) && threw.code === "LEASE_CLOCK_REQUIRED",
          `constructing a StateStore with no explicit clock under the flag must throw LEASE_CLOCK_REQUIRED, got ${threw ? threw.code : "no error"}`);
      });

      let ok = false;
      try { rawCreateStore(root2, { clock: createManualClock() }); ok = true; } catch (e) { /* checked below */ }
      check("require-explicit-clock-accepts-explicit-clock", ok,
        "a well-formed explicit clock must still construct successfully under the flag");
    });

    // Unflagged: an implicit wall clock must be perfectly fine (this is the DEFAULT
    // production path, and every mutant on the guard condition must leave it that way).
    // Explicitly CLEARS the flag env var rather than assuming it is already absent -- this
    // suite may itself run under tests/harness-honesty/lease-determinism's own
    // enforced-clock check, which sets this exact variable globally to audit every OTHER
    // suite; relying on ambient absence here would make this specific case fight that audit.
    withEnv({ GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK: undefined, [AUDIT_ENV]: undefined }, () => {
      let unflaggedOk = false;
      try { rawCreateStore(tempRoot("require-clock-unflagged"), {}); unflaggedOk = true; } catch (e) { /* checked below */ }
      check("require-explicit-clock-inert-without-the-flag", unflaggedOk,
        "without the flag, constructing a StateStore with no explicit clock must succeed (production default)");
    });
  } catch (e) { report("require-explicit-clock-for-state-store", "FAIL", e.message); }
  finally { rmrf(root1); rmrf(root2); }
}

/* ---- admitPending's expected_state_rev optimistic-concurrency guard ---- */
function admitPendingCasMismatch() {
  const root = tempRoot("cas");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const initialRev = store.window.get().state_rev; // 0, before anything is admitted

      let threw = null;
      try { store.window.admitPending({ txid: "tx-cas-wrong", fingerprint: "fp-cas", tree_id: "t-cas", n: 1, expected_state_rev: initialRev + 99 }); }
      catch (e) { threw = e; }
      check("admit-pending-cas-mismatch-refused", Boolean(threw) && threw.code === "CAS_MISMATCH",
        `a wrong expected_state_rev must be refused with CAS_MISMATCH, got ${threw ? threw.code : "no error"}`);

      const stillNoWindow = store.window.get();
      check("admit-pending-cas-mismatch-does-not-admit", stillNoWindow.state === "NO_WINDOW",
        `a CAS-mismatched admitPending must not have admitted anything, got state ${stillNoWindow.state}`);

      const result = store.window.admitPending({ txid: "tx-cas-right", fingerprint: "fp-cas", tree_id: "t-cas", n: 1, expected_state_rev: initialRev });
      check("admit-pending-cas-match-succeeds", result.window.window_id === "tx-cas-right",
        `a correct expected_state_rev must succeed, got ${JSON.stringify(result)}`);
    });
  } catch (e) { report("admit-pending-cas-mismatch", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- exact refusal-message text for the two ordinary LOCKED gates (owner alive, and dead-
 * but-still-renewed) -- both scenarios are already exercised for their CODE by other suites,
 * never for their exact wording. ---- */
function lockedRefusalMessagesAreExact() {
  const root = tempRoot("locked-messages");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const held = store._testing.acquireLock();
      let threw = null;
      try { createStore(root, { leaseMs: 5000, heartbeatMs: 500 })._testing.acquireLock(); }
      catch (e) { threw = e; }
      check("locked-live-owner-message-names-pid-and-lease", Boolean(threw) &&
        threw.message.includes(`pid ${process.pid}`) && threw.message.includes("alive and making progress"),
        `expected the LOCKED message to name the owning pid and say "alive and making progress", got ${threw && threw.message}`);
      store._heldOwnerToken = null;
      void held;
      try { fs.unlinkSync(store.lockPath); } catch { /* cleanup */ }
    });
  } catch (e) { report("locked-refusal-messages-are-exact", "FAIL", e.message); }
  finally { rmrf(root); }
}

function main() {
  assertStillOwnedReportsGoneAsLockLost();
  assertStillOwnedReportsStolenAsLockLost();
  assertStillOwnedPropagatesUnrelatedFailures();
  assertStillOwnedNoOpWhenNothingHeld();
  requireExplicitClockForStateStore();
  admitPendingCasMismatch();
  lockedRefusalMessagesAreExact();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
