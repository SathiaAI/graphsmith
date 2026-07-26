/* tests/_harness/deadline.js — one knob for every HARNESS deadline.
 *
 * WHAT THIS IS FOR
 *
 * A test that waits for a precondition and then draws a conclusion has two ways
 * to reach the same verdict: the thing genuinely did not happen, or the wait
 * simply ran out. Those are completely different facts, and a harness that cannot
 * tell them apart will eventually report the second as the first. One case in this
 * repo did exactly that -- A8 announced "no interface for manager to detect guard
 * death", a claim about the PRODUCT, when it had merely run out of time waiting
 * for the guard to arm.
 *
 * Patching that case fixes one instance. This exists to make the class
 * MECHANICALLY DETECTABLE: scale every harness deadline toward zero and re-run.
 * Under near-zero deadlines every precondition wait must fail, so an honest suite
 * can only report INCONCLUSIVE. Any case that instead emits a confident verdict --
 * a PASS claiming a guarantee, or a FAIL asserting a product defect -- is lying by
 * construction, and tests/harness-honesty/starvation/ catches it.
 *
 * The inverse is just as useful: scale deadlines UP and re-run. Any case that
 * flips from FAIL to PASS was timing-limited, not product-limited. That is the
 * question that consumed most of one debugging session -- "is this finding real or
 * is my harness impatient" -- answered across the corpus by one env var.
 *
 * THE LINE THIS MUST NOT CROSS
 *
 * This scales HARNESS deadlines only: how long the TEST is willing to wait. It
 * must never scale a PRODUCT budget -- a watchdog budget_ms, a lease TTL, a
 * max_wall_time_ms -- because those are the values under test. Scaling them would
 * not stress the harness, it would change the experiment. If you find yourself
 * passing a product budget through this function, stop: that is the bug this
 * comment exists to prevent.
 *
 * USAGE
 *
 *   const { harnessDeadline } = require("../../_harness/deadline.js");
 *   ... setTimeout(fn, harnessDeadline(5000))
 *   ... const until = Date.now() + harnessDeadline(45000)
 *
 * Unset or invalid GRAPHSMITH_DEADLINE_SCALE leaves every deadline exactly as
 * written, so normal runs are unaffected and this file is inert in CI by default.
 */

"use strict";

const ENV_VAR = "GRAPHSMITH_DEADLINE_SCALE";

function scale() {
  const raw = Number(process.env[ENV_VAR]);
  if (!Number.isFinite(raw) || raw <= 0) return 1;
  return raw;
}

/**
 * Scale a harness deadline in milliseconds.
 * @param {number} ms the deadline as written for a normal run
 * @returns {number} the deadline to actually use, never below 1ms
 */
function harnessDeadline(ms) {
  const s = scale();
  if (s === 1) return ms;
  // Floor at 1ms: several timer APIs treat 0 as "no timeout" or "next tick",
  // which would turn starvation into something other than a short deadline.
  return Math.max(1, Math.round(Number(ms) * s));
}

/** True when deadlines are being deliberately starved (scale well below 1). */
function isStarved() {
  return scale() <= 0.05;
}

module.exports = { harnessDeadline, isStarved, ENV_VAR };
