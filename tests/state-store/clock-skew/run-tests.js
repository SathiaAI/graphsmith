#!/usr/bin/env node
"use strict";

/* Lock staleness is decided by `Date.now() - observed.stat.mtimeMs`. That subtraction
 * assumes the mtime is in the PAST. It is not always: a backward NTP correction, a VM
 * resuming from suspend, a network filesystem whose server clock leads this host, or a
 * restored backup that preserved mtimes all leave a lock whose mtime is in the FUTURE.
 *
 * Before the skew gate, `age` went negative, `unrenewed` was false, and BOTH steal gates
 * refused -- for the whole duration of the skew, even with the owning pid long dead. That
 * is an outage rather than a slow acquire: `_operation` takes this lock for every store
 * call INCLUDING READS, and promote's `recover()` takes it too, so the repair path is
 * blocked by the fault it repairs. Observed message: "renewed -3599995ms ago ... that
 * owner is alive and making progress".
 *
 * This suite pins all SEVEN reachable (owner-liveness x mtime-position) states, not just
 * the two the fix added. A gate that only tests its own new branch cannot tell you it
 * left the other branches alone -- and the two pre-existing gates here are the ones that
 * took three attempts to get right. Cases 1-4 are the negative controls: they must keep
 * failing the way they always did.
 *
 * The lock protocol deliberately uses REAL time (see the clock seam note in
 * state-store.js): lease expiry is arithmetic on stored values and is injectable, lock
 * staleness compares against an mtime the OS wrote and must stay real. So these cases
 * move the FILE's mtime, never a clock. A store clock is still injected because the store
 * requires one under the determinism gate; it plays no part in what is asserted here. */

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const { createStore, SCHEMA_VERSION } = require(STATE_STORE);
const { createManualClock } = require("../../_harness/clock.js");

const CLOCK = createManualClock();
const LEASE_MS = 1000;

/* A pid that cannot be running. Not `process.pid + 1` and not a spawned-then-exited child:
 * both can be reused by the OS between the write and the read, which would silently turn a
 * "dead owner" case into a "live owner" case and make this suite lie in the safe
 * direction. 999999 is above the default pid_max on every platform in the CI matrix. */
const DEAD_PID = 999999;

let failures = 0;
const results = [];

function record(name, status, reason) {
  const line =
    status === "PASS"
      ? `PASS ${name}`
      : status === "SKIPPED"
        ? `SKIPPED ${name}+${reason || "no reason"}`
        : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-skew-${prefix}-`));
}

function store(root) {
  return createStore(root, { leaseMs: LEASE_MS, clock: CLOCK });
}

/* Plant a lock owned by `pid` whose mtime sits `offsetMs` from now, then observe what a
 * DIFFERENT store instance does with it. Writing the record directly is the point: an
 * acquired-then-abandoned lock cannot be given a future mtime without also being owned by
 * this live process, which would collapse two of the seven states into one. */
function observe({ pid, offsetMs, legacyField = false }) {
  const root = freshRoot("s");
  const planted = store(root);
  fs.mkdirSync(path.dirname(planted.lockPath), { recursive: true });
  const rec = {
    schema_version: SCHEMA_VERSION,
    pid,
    owner_token: "c".repeat(32),
  };
  if (legacyField) rec.proc_start_hint = `${pid}:1700000000000`;
  fs.writeFileSync(planted.lockPath, `${JSON.stringify(rec)}\n`);

  const when = new Date(Date.now() + offsetMs);
  const fd = fs.openSync(planted.lockPath, "r+");
  try { fs.futimesSync(fd, when, when); } finally { fs.closeSync(fd); }

  try {
    store(root)._testing.acquireLock();
    return "ACQUIRED";
  } catch (error) {
    return error.code || "UNKNOWN_ERROR";
  }
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function state(name, plant, expected) {
  let got;
  try { got = observe(plant); }
  catch (error) { record(name, "FAIL", `harness could not plant the lock: ${error.message}`); return; }
  if (got === expected) record(name, "PASS");
  else record(name, "FAIL", `expected ${expected}, got ${got}`);
}

/* ---- the four pre-existing states: negative controls, must be unchanged ---- */

function preExistingGatesStillHold() {
  state("live-owner-fresh-mtime-refused", { pid: process.pid, offsetMs: -100 }, "LOCKED");
  state("live-owner-unrenewed-stealable", { pid: process.pid, offsetMs: -60_000 }, "ACQUIRED");
  state("dead-owner-fresh-mtime-refused", { pid: DEAD_PID, offsetMs: -100 }, "LOCKED");
  state("dead-owner-unrenewed-stealable", { pid: DEAD_PID, offsetMs: -60_000 }, "ACQUIRED");
}

/* ---- the wedge itself ---- */

function futureMtimeDoesNotWedgeADeadOwner() {
  state("dead-owner-future-mtime-stealable", { pid: DEAD_PID, offsetMs: 24 * 60 * 60 * 1000 }, "ACQUIRED");

  /* THE CASE THIS SUITE ORIGINALLY MISSED, AND THE REGRESSION IT LET THROUGH.
   *
   * The first version of the gate wrote `skewed = age < -TOLERANCE` and applied it to both
   * branches, so a dead owner with a mtime INSIDE the tolerance fell through to the two
   * original gates -- where a negative age is never `> leaseMs`, `unrenewed` stays false,
   * and the second gate refuses. That reproduced the wedge, bounded at skew + lease rather
   * than unbounded, while the refusal message still promised "stealable as soon as that pid
   * exits". Measured on the shipped diff, dead pid, 30s lease, 5s tolerance:
   *
   *   +0ms -> LOCKED   +1000ms -> LOCKED   +3000ms -> LOCKED   +4999ms -> LOCKED
   *   +20000ms -> ACQUIRED   +86400000ms -> ACQUIRED
   *
   * The suite passed 12/12 throughout, because every dead-owner case sat OUTSIDE the band.
   * Two independent reviewers found it by reading the diff. The tolerance is now diagnostic
   * only and only for a live owner; owner death is decisive at any offset. These cases walk
   * the band so a reintroduced tolerance-on-the-dead-branch cannot pass. */
  /* The smallest offset here is 1000ms, not 1ms, and that is a limit of the harness rather
   * than a gap in the rule. Several milliseconds elapse between planting the mtime and the
   * observing acquire, so a 1ms-ahead mtime is simply in the PAST by the time it is read --
   * the case degenerates into "dead owner, fresh mtime", which is a different (and already
   * pinned) state. A 1ms case was written, failed, and was removed rather than papered over:
   * it is the third time in this suite that an offset smaller than the plant-to-observe
   * latency has claimed a boundary it could not reach. Sub-millisecond futures are
   * indistinguishable from "just written" and the product treats them that way on purpose. */
  for (const offsetMs of [1_000, 3_000, 4_999]) {
    state(`dead-owner-${offsetMs}ms-ahead-still-stealable`, { pid: DEAD_PID, offsetMs }, "ACQUIRED");
  }
}

function futureMtimeOnALiveOwnerIsNamedNotMisreported() {
  state("live-owner-future-mtime-reports-skew", { pid: process.pid, offsetMs: 24 * 60 * 60 * 1000 }, "LOCK_CLOCK_SKEW");

  /* The old behaviour was not merely "refuse" -- it refused while ASSERTING the owner was
   * "alive and making progress" and printing a negative age. A refusal that misdescribes
   * why is how an operator spends an hour looking at the wrong thing, so the message is
   * part of the contract here, not decoration. */
  const root = freshRoot("m");
  const planted = store(root);
  fs.mkdirSync(path.dirname(planted.lockPath), { recursive: true });
  fs.writeFileSync(planted.lockPath, `${JSON.stringify({
    schema_version: SCHEMA_VERSION, pid: process.pid, owner_token: "e".repeat(32),
  })}\n`);
  const ahead = new Date(Date.now() + 3_600_000);
  const fd = fs.openSync(planted.lockPath, "r+");
  try { fs.futimesSync(fd, ahead, ahead); } finally { fs.closeSync(fd); }

  try {
    store(root)._testing.acquireLock();
    record("skew-refusal-explains-itself", "FAIL", "a live owner with a future mtime was not refused at all");
  } catch (error) {
    const m = error.message || "";
    /* `-\d` was the first version of this check and it was WRONG: the message embeds the
     * lock path, and `fs.mkdtempSync` appends random characters, so a temp directory named
     * `gs-skew-m-3xk9q2` made the assertion fire on its own scaffolding. It was caught by a
     * mutation control failing for a reason unrelated to the mutation. Anchor on the unit
     * so only an actual duration can match. */
    if (/-\d+(\.\d+)?ms/.test(m)) record("skew-refusal-explains-itself", "FAIL", `refusal still reports a negative age: ${m.slice(0, 120)}`);
    else if (!/FUTURE/.test(m) || !/CLOCK SKEW/.test(m)) record("skew-refusal-explains-itself", "FAIL", `refusal does not name clock skew: ${m.slice(0, 120)}`);
    else if (/making progress/.test(m)) record("skew-refusal-explains-itself", "FAIL", "refusal still claims the owner is making progress");
    else record("skew-refusal-explains-itself", "PASS");
  }
}

/* ---- the boundary the fix must NOT swallow ---- */

function smallForwardOffsetsAreNotSkew() {
  /* The gate must fire on a clock correction, not on filesystem timestamp granularity. A
   * filesystem that rounds mtime up (FAT32: 2s; HFS+: 1s) can return a mtime slightly
   * ahead of the writer's own clock, and a strict `age < 0` test would then report
   * LOCK_CLOCK_SKEW for healthy contention on every single acquire -- on exactly the
   * platforms hardest for us to reproduce.
   *
   * These cases pin BOTH sides of the tolerance. Inside it, the two original gates decide
   * unchanged; outside it, the skew branch takes over.
   *
   * An earlier version of this suite had a case named "mtime equal to now" that planted
   * offsetMs: 0. A mutation control (classify `age <= 0` as skew) did not fail it, because
   * several milliseconds elapse between planting the mtime and the observing acquire, so
   * the case never actually reached age 0 -- the check was about a different boundary than
   * its name claimed, which is the defect class this project keeps finding. It was
   * replaced with these, which are deterministic because the offsets are large relative to
   * the elapsed time between plant and observe. */
  state("live-owner-1s-ahead-is-not-skew", { pid: process.pid, offsetMs: 1_000 }, "LOCKED");
  state("live-owner-4s-ahead-is-not-skew", { pid: process.pid, offsetMs: 4_000 }, "LOCKED");
  state("live-owner-30s-ahead-is-skew", { pid: process.pid, offsetMs: 30_000 }, "LOCK_CLOCK_SKEW");

  /* The tolerance is now asymmetric by design, so the asymmetry itself is pinned: the SAME
   * offset must be an ordinary LOCKED for a live owner and a steal for a dead one. A single
   * test that only walked one liveness value would have missed the regression above. */
  check("tolerance-applies-to-live-owners-only",
    observe({ pid: process.pid, offsetMs: 3_000 }) === "LOCKED"
    && observe({ pid: DEAD_PID, offsetMs: 3_000 }) === "ACQUIRED",
    "the same in-tolerance offset must be LOCKED for a live owner and stealable for a dead one");
}

/* ---- upgrade compatibility for the removed field ---- */

function legacyLockFilesStillValidate() {
  /* `proc_start_hint` is no longer written, but the lock schema is
   * `additionalProperties: false`. Hard-removing the property (rather than only removing
   * it from `required`) makes every lock written by a PREVIOUS version fail validation as
   * CORRUPT_STATE -- and CORRUPT_STATE in the acquire path is not recoverable by the tool.
   * That would have been a self-inflicted upgrade outage of the same shape as the wedge
   * this suite exists for. This case fails if anyone later "tidies up" the property. */
  state("legacy-lock-with-proc-start-hint-still-parses",
    { pid: DEAD_PID, offsetMs: -60_000, legacyField: true }, "ACQUIRED");

  /* And the field really is gone from what we write now. */
  const root = freshRoot("w");
  const s = store(root);
  try {
    s._testing.acquireLock();
    const written = JSON.parse(fs.readFileSync(s.lockPath, "utf8"));
    if (Object.prototype.hasOwnProperty.call(written, "proc_start_hint")) {
      record("new-locks-omit-proc-start-hint", "FAIL", "the dead field is still being written");
    } else if (!written.owner_token || !written.pid) {
      record("new-locks-omit-proc-start-hint", "FAIL", `lock record lost a live field: ${JSON.stringify(written)}`);
    } else {
      record("new-locks-omit-proc-start-hint", "PASS");
    }
  } catch (error) {
    record("new-locks-omit-proc-start-hint", "FAIL", `could not acquire a lock on an empty store: ${error.message}`);
  }
}

function main() {
  preExistingGatesStillHold();
  futureMtimeDoesNotWedgeADeadOwner();
  futureMtimeOnALiveOwnerIsNamedNotMisreported();
  smallForwardOffsetsAreNotSkew();
  legacyLockFilesStillValidate();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main();
