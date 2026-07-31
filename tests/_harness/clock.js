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
  /* The product requires a non-negative safe integer instant. Accepting merely-finite
   * inputs here let createManualClock(0.5) through and surfaced later as BAD_LEASE_CLOCK
   * from inside the store -- a HARNESS input error diagnosed as a product clock error. */
  if (!Number.isSafeInteger(startMs) || startMs < 0) {
    throw new Error(`createManualClock: startMs must be a non-negative safe integer, got ${startMs}`);
  }
  let current = startMs;
  let advances = 0;
  return {
    /* Tagged so the lease-clock audit can record WHICH KIND of clock a construction
     * used, not merely that one was passed. Presence alone is not the property: an
     * inline `{ now: () => Date.now() }` satisfies a presence check while
     * reintroducing exactly the wall-clock race this file exists to remove. The audit
     * classifies an untagged object as "custom", which the determinism sweep treats as
     * undeclared residual surface. */
    __leaseClockKind: "manual",
    now: () => current,
    /** Move time forward. Refuses to go backward: a lease that un-expires is not a
     * scenario the product can produce, and a test that needs one is testing a fiction. */
    advance(ms) {
      if (!Number.isSafeInteger(ms) || ms < 0) throw new Error(`clock.advance: ${ms} is not a non-negative safe integer of ms`);
      if (!Number.isSafeInteger(current + ms)) throw new Error("clock.advance: would leave the safe-integer range");
      current += ms;
      advances += 1;
      return current;
    },
    /** Jump to an absolute instant, forward only. Useful for "just past this
     * lease_expires_at the store issued", which is exact rather than a guess. */
    set(ms) {
      if (!Number.isSafeInteger(ms) || ms < 0) throw new Error(`clock.set: ms must be a non-negative safe integer, got ${ms}`);
      if (ms < current) throw new Error(`clock.set: refusing to move time backward (${ms} < ${current})`);
      current = ms;
      advances += 1;
      return current;
    },
    /** How many times time was moved. Lets a case assert it controlled its own timeline. */
    advanceCount: () => advances,
  };
}

/* The real clock, re-exported from the product rather than re-implemented here. There were
 * two near-identical definitions, one tagged and one not, so a caller passing the product's
 * own copy was recorded as an untagged "custom" clock and failed the determinism gate for
 * doing the right thing. One definition, one behaviour. */
const { systemLeaseClock } = require("../../scripts/state-store.js");

module.exports = { createManualClock, systemLeaseClock, DEFAULT_EPOCH_MS };
