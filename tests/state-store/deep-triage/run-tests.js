#!/usr/bin/env node
"use strict";

/* tests/state-store/deep-triage/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 mutation triage on scripts/state-store.js -- a grab-bag of
 * specific, previously-untested branches identified from a fresh Stryker survivor list on
 * commit 6d09b0b (baseline 998 killed / 13 timeout / 854 survived / 1865 total = 54.21%).
 * Each function below targets one cluster of survivors; see the comment on each for exactly
 * which behavior it closes and why nothing existing already covered it. Uses the same manual
 * clock discipline as every other suite here (see tests/_harness/clock.js) -- nothing in this
 * file needs the wall clock. */

const fs = require("fs");
const os = require("os");
const path = require("path");

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

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-deep-triage-${label}-`));
}

function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }

function withEnv(patch, fn) {
  const prev = {};
  for (const k of Object.keys(patch)) {
    prev[k] = process.env[k];
    if (patch[k] === undefined) delete process.env[k]; else process.env[k] = patch[k];
  }
  try { return fn(); }
  finally {
    for (const k of Object.keys(patch)) {
      if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k];
    }
  }
}

function createStore(root, opts = {}) {
  return rawCreateStore(root, Object.assign({ clock: createManualClock() }, opts));
}

function readRaw(root, rel) {
  try { return fs.readFileSync(path.join(root, ".graphsmith", "state", rel), "utf8"); }
  catch (e) { if (e.code === "ENOENT") return ""; throw e; }
}

/* ============================================================================================
 * A. closeWindow's rolled_back / halt_human outcomes -- every existing suite only ever closes
 * a window with "pass" or "flagged". The `outcome === "rolled_back"` and `outcome === "halt_human"`
 * branches (scripts/state-store.js:1197-1198) have never been reached by anything.
 * ============================================================================================ */

function closeWindowRolledBackOutcome() {
  const root = tempRoot("close-rolled-back");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.window.admitPending({ txid: "tx-rb", fingerprint: "fp-rb", tree_id: "t-rb", n: 1 });
      store.window.finalize("tx-rb");
      store.runRegistry.register("run-rb", "t-rb");
      store.runRegistry.deregister("run-rb", { disposition: "completed_pass" });
      const closed = store.window.close("tx-rb", "rolled_back");
      check("close-window-rolled-back-outcome-sets-state", closed.state === "CLOSED_ROLLED_BACK",
        `expected CLOSED_ROLLED_BACK, got ${closed.state}`);
    });
  } catch (e) { report("close-window-rolled-back-outcome-sets-state", "FAIL", e.message); }
  finally { rmrf(root); }
}

function closeWindowHaltHumanOutcome() {
  const root = tempRoot("close-halt-human");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.window.admitPending({ txid: "tx-hh", fingerprint: "fp-hh", tree_id: "t-hh", n: 1 });
      store.window.finalize("tx-hh");
      store.runRegistry.register("run-hh", "t-hh");
      store.runRegistry.deregister("run-hh", { disposition: "completed_pass" });
      const closed = store.window.close("tx-hh", "halt_human");
      check("close-window-halt-human-outcome-sets-state", closed.state === "HALT_HUMAN",
        `expected HALT_HUMAN, got ${closed.state}`);

      // rolled_back must be checked BEFORE halt_human in the if/else-if chain: a second
      // window closed with "rolled_back" while ALSO eligible for "halt_human" semantics
      // (this suite cannot force both at once through outcome alone, so this instead
      // proves halt_human does not accidentally win when rolled_back is requested).
    });
  } catch (e) { report("close-window-halt-human-outcome-sets-state", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * B. `_terminalize`'s three early-exit branches -- no test disposes a run against a store that
 * never admitted a window at all, disposes an unregistered/never-slotted run, or disposes the
 * SAME run twice. All three currently return `changed: false` with nothing asserting it.
 * ============================================================================================ */

function terminalizeNoWindowAtAll() {
  const root = tempRoot("terminalize-no-window");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      // No admitPending call at all -- window.window is null (NO_WINDOW).
      const result = store.window.dispose("nobody-ever-registered", { disposition: "completed_pass" });
      check("terminalize-no-window-reports-unchanged", result.changed === false,
        `disposing against a store with NO_WINDOW must report changed:false, got ${JSON.stringify(result)}`);
    });
  } catch (e) { report("terminalize-no-window-reports-unchanged", "FAIL", e.message); }
  finally { rmrf(root); }
}

function terminalizeSlotNeverObserved() {
  const root = tempRoot("terminalize-no-slot");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.window.admitPending({ txid: "tx-ns", fingerprint: "fp-ns", tree_id: "t-ns", n: 3 });
      store.window.finalize("tx-ns");
      // A window exists, but this particular runId was never registered/observed into it.
      const result = store.window.dispose("never-registered-run", { disposition: "completed_pass" });
      check("terminalize-slot-never-observed-reports-unchanged", result.changed === false,
        `disposing an unobserved run must report changed:false, got ${JSON.stringify(result)}`);
    });
  } catch (e) { report("terminalize-slot-never-observed-reports-unchanged", "FAIL", e.message); }
  finally { rmrf(root); }
}

function terminalizeIdempotentSecondDispose() {
  const root = tempRoot("terminalize-idempotent");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.window.admitPending({ txid: "tx-idem", fingerprint: "fp-idem", tree_id: "t-idem", n: 2 });
      store.window.finalize("tx-idem");
      store.runRegistry.register("run-idem", "t-idem");
      const first = store.window.dispose("run-idem", { disposition: "completed_pass" });
      check("terminalize-first-dispose-reports-changed", first.changed === true,
        `the first dispose of an active slot must report changed:true, got ${JSON.stringify(first)}`);
      const activeAfterFirst = store.window.get().window.active;

      const second = store.window.dispose("run-idem", { disposition: "completed_pass" });
      check("terminalize-second-dispose-is-a-noop", second.changed === false,
        `disposing an already-terminal slot a second time must report changed:false, got ${JSON.stringify(second)}`);
      const activeAfterSecond = store.window.get().window.active;
      check("terminalize-second-dispose-does-not-double-decrement-active",
        activeAfterSecond === activeAfterFirst,
        `active count must not change on a no-op dispose: was ${activeAfterFirst}, now ${activeAfterSecond}`);
    });
  } catch (e) { report("terminalize-idempotent-second-dispose", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * C. Exact-boundary lease/wall-time comparisons (`<=` vs `<`, `>=` vs `>`). Every existing
 * expiry test advances the clock to `expiresAt + 1` -- comfortably past the boundary -- so a
 * mutant that flips the comparison operator by one direction survives untested at the exact
 * instant.
 * ============================================================================================ */

function sweepExpiredExactBoundaryIsInclusive() {
  const root = tempRoot("sweep-boundary");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const clock = createManualClock();
      const store = rawCreateStore(root, { leaseMs: 1000, heartbeatMs: 100, clock });
      const reg = store.runRegistry.register("run-boundary", "tree-boundary");
      const expiresAt = reg.registration.lease_expires_at;
      // Exactly AT the expiry instant, not one past it: `lease_expires_at <= now` must be
      // true here. A `<` mutant would refuse to sweep it.
      clock.set(expiresAt);
      const swept = store.runRegistry.sweepExpired();
      check("sweep-expired-exact-boundary-is-inclusive", swept.includes("run-boundary"),
        `a lease exactly AT its expiry instant must be swept (<=, not <); swept=${JSON.stringify(swept)}`);
    });
  } catch (e) { report("sweep-expired-exact-boundary-is-inclusive", "FAIL", e.message); }
  finally { rmrf(root); }
}

function wallClockCapExactBoundaryIsInclusive() {
  const root = tempRoot("wallcap-boundary");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const clock = createManualClock();
      const store = rawCreateStore(root, { leaseMs: 600000, heartbeatMs: 60000, clock });
      const WALL_MS = 5000;
      store.window.admitPending({ txid: "tx-wallcap", fingerprint: "fp-wallcap", tree_id: "t-wallcap", n: 1, max_window_wall_time_ms: WALL_MS });
      store.window.finalize("tx-wallcap");
      const created = store.window.get().window.created_at;
      // Exactly AT the cap, not one past it: `now - created_at >= max_window_wall_time_ms`
      // must be true here. A `>` mutant would refuse to close it.
      clock.set(created + WALL_MS);
      store.runRegistry.sweepExpired();
      const win = store.window.get();
      check("wall-clock-cap-exact-boundary-is-inclusive", win.state === "CLOSED_FLAGGED",
        `a window exactly AT its wall-time cap must close CLOSED_FLAGGED (>=, not >); got ${win.state}`);
    });
  } catch (e) { report("wall-clock-cap-exact-boundary-is-inclusive", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * D. `_registryState`'s HEARTBEAT Math.max regression guard (scripts/state-store.js:995) --
 * a heartbeat must never SHRINK a run's recorded lease, only extend or hold it. Every existing
 * heartbeat test only ever issues heartbeats that legitimately extend the lease (moving
 * forward in time), so a `Math.min` mutant here has nothing to disagree with. This writes a
 * HEARTBEAT record directly (bypassing heartbeatRun(), which can only ever produce a later
 * expiry from a monotonic clock) with a SMALLER lease_expires_at than the existing
 * registration, simulating exactly the backward-NTP-correction scenario the code comment
 * describes.
 * ============================================================================================ */

function heartbeatNeverShrinksLease() {
  const root = tempRoot("heartbeat-shrink");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const reg = store.runRegistry.register("run-shrink", "tree-shrink");
      const originalExpiry = reg.registration.lease_expires_at;

      // Append a HEARTBEAT record directly with an EARLIER lease_expires_at than the
      // registration -- exactly what a backward wall-clock correction would produce.
      const registryPath = path.join(root, ".graphsmith", "state", "run-registry.jsonl");
      const shrunkHeartbeat = {
        schema_version: SCHEMA_VERSION, state_rev: 1, record_type: "HEARTBEAT",
        run_id: "run-shrink", lease_expires_at: originalExpiry - 1000,
      };
      fs.appendFileSync(registryPath, `${JSON.stringify(shrunkHeartbeat)}\n`);

      const run = store.runRegistry.get("run-shrink");
      check("heartbeat-never-shrinks-lease", run && run.lease_expires_at === originalExpiry,
        `a HEARTBEAT with a smaller lease_expires_at must not shrink the run's lease: ` +
        `expected ${originalExpiry}, got ${run && run.lease_expires_at}`);
    });
  } catch (e) { report("heartbeat-never-shrinks-lease", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * E. Argument-validation branches with a non-null, non-object (but truthy) value -- every
 * existing test for `!x || typeof x !== "object"` guards only ever passes undefined/null
 * (hitting the FIRST half) or a well-formed object (hitting neither half). A string or number
 * argument hits the SECOND half specifically and has never been tried.
 * ============================================================================================ */

function argumentGuardsRejectNonObjectTruthyValues() {
  const root = tempRoot("arg-guards");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });

      const admitThrew = (() => { try { store.window.admitPending("not-an-object"); return null; } catch (e) { return e; } })();
      check("admitPending-rejects-string-argument", Boolean(admitThrew) && admitThrew.code === "INVALID_ARGUMENT",
        `expected INVALID_ARGUMENT for a string tx, got ${admitThrew && admitThrew.code}`);

      const reserveThrew = (() => { try { store.alphaLedger.reserve(42); return null; } catch (e) { return e; } })();
      check("reserveAlpha-rejects-number-argument", Boolean(reserveThrew) && reserveThrew.code === "INVALID_ARGUMENT",
        `expected INVALID_ARGUMENT for a numeric reservation, got ${reserveThrew && reserveThrew.code}`);

      const pushThrew = (() => { try { store.rejectedBuffer.push("also-not-an-object"); return null; } catch (e) { return e; } })();
      check("pushRejected-rejects-string-argument", Boolean(pushThrew) && pushThrew.code === "INVALID_ARGUMENT",
        `expected INVALID_ARGUMENT for a string entry, got ${pushThrew && pushThrew.code}`);

      const appendThrew = (() => { try { store.rollbackFamilies.append(true); return null; } catch (e) { return e; } })();
      check("appendRollback-rejects-boolean-argument", Boolean(appendThrew) && appendThrew.code === "INVALID_ARGUMENT",
        `expected INVALID_ARGUMENT for a boolean entry, got ${appendThrew && appendThrew.code}`);

      const anchorThrew = (() => { try { store.runAnchors.setAnchor("run-x", "nope"); return null; } catch (e) { return e; } })();
      check("setAnchor-rejects-string-argument", Boolean(anchorThrew) && anchorThrew.code === "INVALID_ARGUMENT",
        `expected INVALID_ARGUMENT for a string anchor, got ${anchorThrew && anchorThrew.code}`);
    });
  } catch (e) { report("argument-guards-reject-non-object-truthy-values", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * F. `listAlpha`'s corpusState===undefined branch, precisely: reserving across TWO distinct
 * corpus states and confirming list(corpusA) excludes corpusB while list() (no argument)
 * includes both -- not merely that list() with no argument "returns something", which is all
 * the existing crash-persistence test proves.
 * ============================================================================================ */

function listAlphaUndefinedVsDefinedCorpusState() {
  const root = tempRoot("list-alpha-corpus");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.alphaLedger.reserve({ corpus_state: "corpus-A", split_hash: "s1", fingerprint: "f1", family: "fam-A" });
      store.alphaLedger.reserve({ corpus_state: "corpus-B", split_hash: "s2", fingerprint: "f2", family: "fam-B" });

      const onlyA = store.alphaLedger.list("corpus-A");
      check("list-alpha-defined-corpus-excludes-other-corpus",
        onlyA.length === 1 && onlyA[0].corpus_state === "corpus-A",
        `list("corpus-A") must return exactly the corpus-A reservation, got ${JSON.stringify(onlyA)}`);

      const all = store.alphaLedger.list();
      check("list-alpha-undefined-corpus-includes-every-corpus",
        all.length === 2 && all.some((r) => r.corpus_state === "corpus-A") && all.some((r) => r.corpus_state === "corpus-B"),
        `list() with no argument must include every corpus state, got ${JSON.stringify(all)}`);
    });
  } catch (e) { report("list-alpha-undefined-vs-defined-corpus-state", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * G. `_acquireLock`'s non-EEXIST propagation (scripts/state-store.js:657): an error from
 * `_createLockFile` OTHER than EEXIST must propagate immediately, not be swallowed into the
 * bounded contention retry loop. Forced by making the TEMP file's own create throw EACCES --
 * a real filesystem permission failure the retry loop must never mistake for ordinary
 * acquisition contention.
 * ============================================================================================ */

function acquireLockPropagatesNonEexistErrors() {
  const root = tempRoot("acquire-non-eexist");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store._ensureStateDir();
      const originalOpenSync = fs.openSync;
      fs.openSync = (target, flag, ...rest) => {
        if (typeof target === "string" && target.includes(".lock.new-")) {
          throw Object.assign(new Error("simulated permission failure"), { code: "EACCES" });
        }
        return originalOpenSync(target, flag, ...rest);
      };
      let threw = null;
      try { store._testing.acquireLock(); }
      catch (e) { threw = e; }
      finally { fs.openSync = originalOpenSync; }
      check("acquire-lock-propagates-non-eexist-error", Boolean(threw) && threw.code === "EACCES",
        `a non-EEXIST failure creating the lock's temp file must propagate immediately, not be retried/swallowed; got ${threw ? threw.code : "no error"}`);
    });
  } catch (e) { report("acquire-lock-propagates-non-eexist-error", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * H. `_releaseLock` must propagate a genuinely corrupt lock file, never silently report
 * `false` for it (scripts/state-store.js:864-865: `catch (error) { throw error; }`). A store
 * that cannot even parse its own lock must fail loudly during release, not report "there was
 * nothing to release" -- those are very different operational facts.
 * ============================================================================================ */

function releaseLockPropagatesCorruptReadFailure() {
  const root = tempRoot("release-corrupt");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const held = store._testing.acquireLock();
      // Corrupt the lock file in place (still the same inode/path) so _readLock's own
      // JSON.parse throws CORRUPT_STATE.
      fs.writeFileSync(store.lockPath, "{ not valid json");
      let threw = null;
      let returned;
      try { returned = store._testing.releaseLock(held.ownerToken); }
      catch (e) { threw = e; }
      check("release-lock-propagates-corrupt-file-instead-of-returning-false",
        Boolean(threw) && threw.code === "CORRUPT_STATE" && returned === undefined,
        `release() against an unparseable lock file must throw CORRUPT_STATE, not return a value; ` +
        `got thrown=${threw && threw.code}, returned=${JSON.stringify(returned)}`);
      // cleanup: remove the poisoned lock file directly since release() could not.
      try { fs.unlinkSync(store.lockPath); } catch { /* best effort */ }
    });
  } catch (e) { report("release-lock-propagates-corrupt-read-failure", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * I. File-descriptor hygiene across every fd-opening internal (`_appendDurable`,
 * `_unlinkLockIfOwner`, `_renewLock`) -- each has its own `finally { fs.closeSync(fd); }` that
 * nothing spies on. Rather than one spy per function (as tests/state-store/atomic-primitives
 * already does for the two atomic-write primitives), this counts EVERY fs.openSync/closeSync
 * pair across one realistic end-to-end sequence that exercises all three: a lock is acquired,
 * a mutation is committed (renewing the lock mid-commit), a competing acquirer steals an
 * abandoned lock (exercising _unlinkLockIfOwner), and the lock is released. Any one of those
 * finally blocks silently dropped would leave an unclosed fd and unbalance the count.
 * ============================================================================================ */

function fileDescriptorsAreBalancedAcrossACommitCycle() {
  const root = tempRoot("fd-balance");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });

      const originalOpenSync = fs.openSync;
      const originalCloseSync = fs.closeSync;
      let opens = 0;
      let closes = 0;
      fs.openSync = (...args) => { opens++; return originalOpenSync(...args); };
      fs.closeSync = (...args) => { closes++; return originalCloseSync(...args); };
      try {
        // _appendDurable (pushRejected), lock acquire + _renewLock (via _commit's
        // per-effect _assertStillOwned), and a normal release.
        store.rejectedBuffer.push({ fingerprint: "fp-fd", value: { x: 1 } });

        // A dead-owner lock, stolen via _unlinkLockIfOwner.
        const crypto = require("crypto");
        const staleToken = crypto.randomBytes(16).toString("hex");
        fs.writeFileSync(store.lockPath, JSON.stringify({ schema_version: SCHEMA_VERSION, pid: 999999, owner_token: staleToken }));
        const old = new Date(Date.now() - 60000);
        fs.utimesSync(store.lockPath, old, old);
        const stolen = store._testing.acquireLock();
        store._testing.releaseLock(stolen.ownerToken);
      } finally {
        fs.openSync = originalOpenSync;
        fs.closeSync = originalCloseSync;
      }
      check("fd-hygiene-opens-equal-closes", opens === closes,
        `expected every fs.openSync to be matched by an fs.closeSync (no leaked fd from a ` +
        `dropped finally block); opens=${opens} closes=${closes}`);
      check("fd-hygiene-actually-opened-something", opens > 0,
        "sanity check: this sequence must actually open file descriptors, or the balance check above proves nothing");
    });
  } catch (e) { report("file-descriptors-are-balanced-across-a-commit-cycle", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * J. `jsonLines()`'s exact serialization format (scripts/state-store.js:157) -- a
 * `"Stryker was here!"` StringLiteral mutant on its non-empty branch survives because nothing
 * checks the RAW file bytes, only the round-tripped parsed records.
 * ============================================================================================ */

function jsonLinesExactSerializationFormat() {
  const root = tempRoot("jsonlines-format");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.runRegistry.register("run-a", "tree-a");
      store.runRegistry.register("run-b", "tree-b");
      const raw = readRaw(root, "run-registry.jsonl");
      const lines = raw.split("\n").filter(Boolean);
      const reserialized = lines.map((l) => JSON.stringify(JSON.parse(l))).join("\n") + "\n";
      check("jsonlines-exact-format-newline-joined-trailing-newline",
        raw === reserialized,
        `expected each record JSON-stringified and newline-joined with one trailing newline; ` +
        `got raw bytes that don't match that exact reconstruction`);
    });
  } catch (e) { report("jsonlines-exact-serialization-format", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * K. `parseJsonLines`'s torn-tail tolerance (scripts/state-store.js:147-148): a torn (no
 * trailing newline) LAST line is silently dropped as an in-flight write, but the exact SAME
 * malformed content is a hard CORRUPT_STATE failure if it is NOT the last line, or if the
 * file DOES end with a newline. No existing test writes a torn tail directly -- crash-recovery
 * tests exercise torn STATE via the journal's own intent/effect mechanism, never a bare
 * malformed trailing JSONL line.
 * ============================================================================================ */

function tornTailToleranceIsPreciselyScoped() {
  const root = tempRoot("torn-tail");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.runRegistry.register("run-good", "tree-good");
      const registryPath = path.join(root, ".graphsmith", "state", "run-registry.jsonl");

      // (1) A torn tail -- valid line, then a truncated fragment with NO trailing newline --
      // must be silently dropped, not reported as corrupt.
      const goodRaw = fs.readFileSync(registryPath, "utf8");
      fs.writeFileSync(registryPath, `${goodRaw}{"schema_version":"1.0","state_rev":1,"record_typ`);
      let tornThrew = null;
      let runsAfterTorn = null;
      try { runsAfterTorn = store.runRegistry.list(); } catch (e) { tornThrew = e; }
      check("torn-tail-no-trailing-newline-is-silently-dropped",
        tornThrew === null && Array.isArray(runsAfterTorn) && runsAfterTorn.some((r) => r.run_id === "run-good"),
        `a torn (no trailing \\n) last line must be tolerated, not thrown; threw=${tornThrew && tornThrew.message}`);

      // (2) The SAME malformed fragment, but WITH a trailing newline, is NOT a torn tail --
      // `!raw.endsWith("\n")` is false, so this must be reported as CORRUPT_STATE.
      fs.writeFileSync(registryPath, `${goodRaw}{"schema_version":"1.0","state_rev":1,"record_typ\n`);
      let terminatedThrew = null;
      try { store.runRegistry.list(); } catch (e) { terminatedThrew = e; }
      check("same-malformed-fragment-with-trailing-newline-is-corrupt",
        Boolean(terminatedThrew) && terminatedThrew.code === "CORRUPT_STATE",
        `a malformed line THAT ENDS WITH a newline is not a torn tail and must throw CORRUPT_STATE; got ${terminatedThrew && terminatedThrew.code}`);

      // (3) The same malformed fragment with no trailing newline, but NOT as the last line
      // (a well-formed line follows it) -- must also be CORRUPT_STATE, since only the true
      // last line gets torn-tail tolerance.
      fs.writeFileSync(registryPath, `{"schema_version":"1.0","state_rev":1,"record_typ\n${goodRaw}`);
      let midFileThrew = null;
      try { store.runRegistry.list(); } catch (e) { midFileThrew = e; }
      check("malformed-line-not-at-end-is-corrupt-even-without-trailing-newline-there",
        Boolean(midFileThrew) && midFileThrew.code === "CORRUPT_STATE",
        `a malformed line that is NOT the last line must throw CORRUPT_STATE regardless of ` +
        `that line's own newline; got ${midFileThrew && midFileThrew.code}`);

      // restore for a clean rm
      fs.writeFileSync(registryPath, goodRaw);
    });
  } catch (e) { report("torn-tail-tolerance-is-precisely-scoped", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * L. Constructor-level convenience wrappers (`this.window.observeSlot`, `this.runRegistry.get`,
 * `this.runAnchors.*`, `this.rejectedBuffer.*`, `this.rollbackFamilies.*` -- scripts/state-
 * store.js:500-533) are pure delegation, but EVERY existing test calls the underlying method
 * directly (`store.observeSlot(...)`) rather than through the wrapper object, so the wrapper
 * arrow functions themselves are never invoked by anything and an `() => undefined` mutant on
 * any of them survives free. This calls each wrapper once and confirms it actually reached the
 * real implementation (not merely that it didn't throw).
 * ============================================================================================ */

function constructorLevelWrappersActuallyDelegate() {
  const root = tempRoot("wrapper-delegation");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.window.admitPending({ txid: "tx-wrap", fingerprint: "fp-wrap", tree_id: "t-wrap", n: 2 });
      store.window.finalize("tx-wrap");

      const slot = store.window.observeSlot("run-wrap-1", "t-wrap");
      check("wrapper-window-observeSlot-delegates", Boolean(slot) && slot.run_id === "run-wrap-1",
        `store.window.observeSlot(...) must delegate to the real observeSlot, got ${JSON.stringify(slot)}`);

      store.runRegistry.register("run-wrap-2", "t-wrap");
      const got = store.runRegistry.get("run-wrap-2");
      check("wrapper-runRegistry-get-delegates", Boolean(got) && got.run_id === "run-wrap-2",
        `store.runRegistry.get(...) must delegate to the real getRun, got ${JSON.stringify(got)}`);

      store.runAnchors.setAnchor("run-wrap-2", { chain_head: "h-wrap", expected_terminal_status: "completed_pass" });
      const anchor = store.runAnchors.getAnchor("run-wrap-2");
      check("wrapper-runAnchors-setAnchor-and-getAnchor-delegate",
        Boolean(anchor) && anchor.chain_head === "h-wrap",
        `store.runAnchors.{setAnchor,getAnchor} must delegate through, got ${JSON.stringify(anchor)}`);

      store.rejectedBuffer.push({ fingerprint: "fp-wrap-rej", value: { z: 1 } });
      const rejectedList = store.rejectedBuffer.list();
      check("wrapper-rejectedBuffer-push-and-list-delegate",
        rejectedList.some((r) => r.fingerprint === "fp-wrap-rej"),
        `store.rejectedBuffer.{push,list} must delegate through, got ${JSON.stringify(rejectedList)}`);

      store.rollbackFamilies.append({ fingerprint: "fp-wrap-rb", family: "fam-wrap", evidence: { e: 1 } });
      const rollbackList = store.rollbackFamilies.list();
      check("wrapper-rollbackFamilies-append-and-list-delegate",
        rollbackList.some((r) => r.fingerprint === "fp-wrap-rb"),
        `store.rollbackFamilies.{append,list} must delegate through, got ${JSON.stringify(rollbackList)}`);

      const ack = store.rollbackFamilies.humanAck("fp-wrap-rb", { by: "tester" });
      check("wrapper-rollbackFamilies-humanAck-delegates",
        Boolean(ack) && ack.fingerprint === "fp-wrap-rb",
        `store.rollbackFamilies.humanAck(...) must delegate through, got ${JSON.stringify(ack)}`);
    });
  } catch (e) { report("constructor-level-wrappers-actually-delegate", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * M. `_commit`'s no-op short-circuit (scripts/state-store.js:934): when every effect's
 * `make()` returns content byte-identical to what was already on disk, NOTHING is journaled
 * and state_rev does not advance -- it is not merely "no observable state change", it is
 * "the write path was never entered at all". A no-op dispose (already covered functionally
 * in section B) has never had its JOURNAL SILENCE checked specifically.
 * ============================================================================================ */

function noOpCommitWritesNoJournalEntryAndDoesNotAdvanceRevision() {
  const root = tempRoot("no-op-commit");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.window.admitPending({ txid: "tx-noop", fingerprint: "fp-noop", tree_id: "t-noop", n: 1 });
      store.window.finalize("tx-noop");
      store.runRegistry.register("run-noop", "t-noop");
      store.window.dispose("run-noop", { disposition: "completed_pass" });

      const journalCountBefore = readRaw(root, "state-journal.jsonl").split("\n").filter(Boolean).length;
      const revBefore = store.window.get().state_rev;

      // A genuine no-op: this run's slot is already terminal, so `make()` returns `raw`
      // (the SAME string) unchanged.
      const result = store.window.dispose("run-noop", { disposition: "completed_pass" });
      check("no-op-commit-reports-unchanged", result.changed === false, `expected changed:false for a true no-op dispose, got ${JSON.stringify(result)}`);

      const journalCountAfter = readRaw(root, "state-journal.jsonl").split("\n").filter(Boolean).length;
      const revAfter = store.window.get().state_rev;
      check("no-op-commit-writes-no-journal-entry", journalCountAfter === journalCountBefore,
        `a no-op commit must not append MUTATION_INTENT/MUTATION_DONE to the journal; before=${journalCountBefore} after=${journalCountAfter}`);
      check("no-op-commit-does-not-advance-state-rev", revAfter === revBefore,
        `a no-op commit must not advance state_rev; before=${revBefore} after=${revAfter}`);
    });
  } catch (e) { report("no-op-commit-writes-no-journal-entry-and-does-not-advance-revision", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ============================================================================================
 * N. `_disposition()`'s TERMINAL_DISPOSITIONS pass-through (scripts/state-store.js:1158-1163):
 * a caller-supplied `result.disposition` that is ALREADY one of the five terminal values must
 * be returned as-is, not re-derived from hard_failure/soft_wobble/default. Every existing
 * test only ever sets the FLAGS (hard_failure, soft_wobble) or omits disposition entirely
 * (falling to the default "completed_pass") -- an explicit disposition string for
 * "superseded" or "abandoned" (the two values a caller would never reach via the flag path at
 * all, since only the wall-clock sweep ever assigns "superseded" and only the lease sweep ever
 * assigns "abandoned") has never been passed to disposeSlot()/deregisterRun() directly.
 * ============================================================================================ */

function explicitTerminalDispositionsPassThroughUnchanged() {
  // A FRESH window per disposition: "completed_hard_fail" flips the window's own state to
  // ROLLING_BACK (a real, separate side effect this suite is not testing here), which would
  // block any LATER run in the same window from ever being admitted a slot at all
  // (`_observe` requires state === "OBSERVING"). Isolating each case avoids that ordering
  // dependency entirely rather than working around it.
  for (const disposition of ["superseded", "abandoned", "completed_hard_fail", "completed_soft_wobble", "completed_pass"]) {
    const root = tempRoot(`disposition-passthrough-${disposition}`);
    try {
      withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
        const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
        store.window.admitPending({ txid: "tx-disp-pt", fingerprint: "fp-disp-pt", tree_id: "t-disp-pt", n: 1 });
        store.window.finalize("tx-disp-pt");
        const runId = `run-disp-${disposition}`;
        store.runRegistry.register(runId, "t-disp-pt");
        const result = store.window.dispose(runId, { disposition });
        check(`disposition-passthrough-${disposition}`, result.disposition === disposition,
          `an explicit result.disposition of "${disposition}" (already terminal) must pass through unchanged, got ${result.disposition}`);
        const slot = store.window.get().window.slots.find((s) => s.run_id === runId);
        check(`disposition-passthrough-${disposition}-slot-matches`, Boolean(slot) && slot.disposition === disposition,
          `the terminalized slot itself must carry the passed-through disposition, got ${slot && slot.disposition}`);
      });
    } catch (e) { report(`explicit-terminal-disposition-pass-through-${disposition}`, "FAIL", e.message); }
    finally { rmrf(root); }
  }
}

function main() {
  closeWindowRolledBackOutcome();
  closeWindowHaltHumanOutcome();
  terminalizeNoWindowAtAll();
  terminalizeSlotNeverObserved();
  terminalizeIdempotentSecondDispose();
  sweepExpiredExactBoundaryIsInclusive();
  wallClockCapExactBoundaryIsInclusive();
  heartbeatNeverShrinksLease();
  argumentGuardsRejectNonObjectTruthyValues();
  listAlphaUndefinedVsDefinedCorpusState();
  acquireLockPropagatesNonEexistErrors();
  releaseLockPropagatesCorruptReadFailure();
  fileDescriptorsAreBalancedAcrossACommitCycle();
  jsonLinesExactSerializationFormat();
  tornTailToleranceIsPreciselyScoped();
  constructorLevelWrappersActuallyDelegate();
  noOpCommitWritesNoJournalEntryAndDoesNotAdvanceRevision();
  explicitTerminalDispositionsPassThroughUnchanged();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
