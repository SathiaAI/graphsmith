/* tests/_harness/clock.js — a chosen instant, for tests of lease arithmetic.
 *
 * WHY THIS EXISTS
 *
 * Six defects on this branch shared one shape: a test needed a run to still be live
 * (or to have just lapsed) when it made an assertion, and established that by hoping
 * the machine was fast enough. Every StateStore operation sweeps lapsed leases before
 * doing anything, and on a contended Windows runner a lock+fsync cycle costs ~200ms,
 * so a 1000ms lease could not survive a twelve-operation test body. The tests then
 * reported losing that race as a PRODUCT defect. One of them accused a fail-closed
 * refusal of letting a window close over active slots -- a false finding against a
 * security guarantee, produced by a slow disk.
 *
 * The previous response was to detect the lost race and report INCONCLUSIVE. That is
 * containment, not a fix: it accepts the race, and every guard is a place a real
 * defect can hide (one draft guard checked a condition true in BOTH branches and would
 * have swallowed a genuine "sweepExpired returns the wrong ids" bug).
 *
 * A lease is arithmetic: given a stored `lease_expires_at` and an instant, is this run
 * live. A test of that arithmetic does not need a real clock -- it needs to CHOOSE the
 * instant. Then the precondition is an assignment, and the false product verdict is
 * unreachable rather than merely tagged.
 *
 *   const clock = createManualClock();
 *   const store = new StateStore(dir, { leaseMs: 1000, clock });
 *   registerThreeRuns(store);
 *   assert(store.getWindow().window.active === 3);   // cannot lapse: time has not moved
 *   clock.advance(1001);                             // the ONLY way time moves
 *   assert(store.runRegistry.sweepExpired().includes(id));
 *
 * THE LINE THIS MUST NOT CROSS
 *
 * This is the LEASE clock only. StateStore deliberately does not route lock staleness
 * through it -- that compares against an mtime the OS wrote, and freezing it would make
 * every lock look infinitely stale or never stale, silently testing a different
 * product. If you find yourself wanting to fake that too, stop: that is the bug this
 * comment exists to prevent.
 *
 * NOT scaled by harnessDeadline(). A lease TTL is a product budget; see the WHAT IT
 * DELIBERATELY DOES NOT SCALE note in tests/harness-honesty/starvation/.
 */

"use strict";

/* A fixed, arbitrary epoch. Deliberately NOT Date.now(): if the start instant came
 * from the wall clock, two runs of the same test would write different
 * `lease_expires_at` values, and any test comparing recorded state across runs would
 * be nondeterministic again for a new reason. */
const DEFAULT_EPOCH_MS = 1_700_000_000_000;

/**
 * A lease clock whose only source of movement is an explicit call.
 * @param {number} [startMs] initial instant
 */
function createManualClock(startMs = DEFAULT_EPOCH_MS) {
  if (!Number.isFinite(startMs)) throw new Error("createManualClock: startMs must be finite");
  let current = startMs;
  let advances = 0;
  return {
    now: () => current,
    /** Move time forward. Refuses to go backward: a lease that un-expires is not a
     * scenario the product can produce, and a test that needs one is testing a fiction. */
    advance(ms) {
      if (!Number.isFinite(ms) || ms < 0) throw new Error(`clock.advance: ${ms} is not a non-negative number of ms`);
      current += ms;
      advances += 1;
      return current;
    },
    /** Jump to an absolute instant, forward only. Useful for "just past this
     * lease_expires_at the store issued", which is exact rather than a guess. */
    set(ms) {
      if (!Number.isFinite(ms)) throw new Error("clock.set: ms must be finite");
      if (ms < current) throw new Error(`clock.set: refusing to move time backward (${ms} < ${current})`);
      current = ms;
      advances += 1;
      return current;
    },
    /** How many times time was moved. Lets a case assert it controlled its own timeline. */
    advanceCount: () => advances,
  };
}

/* The real clock, named so a deliberate use is visible in review rather than being the
 * silent default. Under GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK=1 a StateStore
 * construction must pass one of these two explicitly. */
function systemLeaseClock() {
  return { now: () => Date.now() };
}

module.exports = { createManualClock, systemLeaseClock, DEFAULT_EPOCH_MS };
