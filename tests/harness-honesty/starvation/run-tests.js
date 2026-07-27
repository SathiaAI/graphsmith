/* Harness honesty under starvation — a mechanical detector for tests that lie.
 *
 * THE DEFECT THIS HUNTS
 *
 * A test that waits for a precondition and then draws a conclusion can reach the
 * same verdict two ways: the thing genuinely did not happen, or the wait ran out.
 * Those are different facts. A harness that cannot tell them apart will eventually
 * report the second as the first.
 *
 * That is not hypothetical here. A8 (then named ...-no-manager-notice-channel)
 * in tests/watchdog/grok announced:
 *
 *   "watchdog death leaves blocked run unguarded; no interface for manager to
 *    detect guard death (no reverse heartbeat / exit pipe requirement)"
 *
 * -- a claim about the PRODUCT, describing an architectural gap -- when the harness
 * had simply run out of time waiting for the guard to arm. The dead-man switch it
 * declared missing exists and works; several commits on this branch built it.
 *
 * The same shape appeared pointing the other way, which is worse: in
 * tests/scaffold/deepseek, BOTH branches of the dead-man-switch check called
 * pass(), with a comment excusing the miss as "may be a Windows/scheduling issue".
 * The most safety-critical mechanism in the product could fail to arm entirely and
 * that gating suite exited 0.
 *
 * HOW THIS DETECTS IT RATHER THAN PATCHING INSTANCES
 *
 * Re-run the target suites with every HARNESS deadline scaled toward zero
 * (tests/_harness/deadline.js, GRAPHSMITH_DEADLINE_SCALE). Under near-zero
 * deadlines every precondition wait MUST fail. So an honest suite has exactly one
 * verdict available for those cases: INCONCLUSIVE. A case that instead emits a
 * confident product verdict is lying by construction -- no judgement call, no
 * reading of intent, just arithmetic.
 *
 * Cases that never wait for anything (pure logic checks) legitimately still PASS
 * under starvation, and that is fine. The invariant is only about FAILURES: under
 * starvation, a FAIL that is not tagged INCONCLUSIVE is a case asserting something
 * it could not have observed.
 *
 * WHAT IT DELIBERATELY DOES NOT SCALE
 *
 * Product budgets -- watchdog budget_ms, lease TTLs, max_wall_time_ms -- are the
 * values under test. Scaling those would not stress the harness, it would change
 * the experiment. Only the harness's own patience is scaled.
 *
 * PER-SUITE CONTROL
 *
 * A target that shows no failure at all under starvation has told us nothing, and
 * there are two causes that must not be conflated -- conflating them would make
 * this gate cry wolf, which is how gates come to be ignored:
 *
 *   WIRING GAP    the suite is listed here but never calls harnessDeadline(), so
 *                 the knob does nothing to it and this sweep is vacuous for it.
 *                 A real defect in this sweep's own setup. FAILS.
 *   INERT here    the suite IS wired, but on this platform its starvation-sensitive
 *                 cases do not run -- several watchdog cases are platform-skipped,
 *                 so on Windows there is nothing for starvation to break. Not a
 *                 defect. PASSES, but says loudly that it provides no coverage on
 *                 this leg, the same treatment report-integrity gives its INERT
 *                 detector.
 *
 * The discriminator is static (does the file reference harnessDeadline?) rather
 * than behavioural, so a platform skip can never be mistaken for a wiring gap.
 */

"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { ENV_VAR } = require("../../_harness/deadline.js");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const SCALE = process.env.HONESTY_SCALE || "0.001";
const PER_SUITE_TIMEOUT_MS = 600000;

// Suites whose harness deadlines have been threaded through harnessDeadline().
// Adding a suite here without wiring the knob into it fails as a WIRING GAP rather
// than passing vacuously.
const TARGETS = [
  "tests/watchdog/grok/run-tests.js",
  "tests/watchdog/gpt-sol-pro/run-tests.js",
  "tests/scaffold/deepseek/run-tests.js",
  "tests/watch/grok/run-tests.js",
  "tests/scaffold/gpt-sol-pro/run-tests.js",
  "tests/attacks/toctou/run-tests.js",
  "tests/attacks/module-escape/run-tests.js",
  "tests/adopt/grok/run-tests.js",
];

let pass = 0;
let fail = 0;
const failures = [];

function report(ok, id, detail) {
  if (ok) {
    pass += 1;
    process.stdout.write("PASS " + id + " - " + detail + "\n");
  } else {
    fail += 1;
    failures.push(id);
    process.stdout.write("FAIL " + id + " - " + detail + "\n");
  }
}

// Verdict lines across this repo's hand-rolled harnesses take these shapes:
//   [FAIL] name — reason        (watchdog/grok, scaffold/deepseek)
//   FAIL name: reason           (watchdog/gpt-sol-pro)
//   FAIL: name -- reason        (verify/deepseek style)
// Structured JSON dumps also contain "status": "FAIL"; those are the same verdicts
// echoed a second time, so they are excluded to avoid double counting.
function failVerdictLines(text) {
  return String(text)
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^(\[FAIL\]|FAIL[:\s])/.test(l))
    .filter((l) => l.indexOf('"status"') === -1);
}

function isTagged(line) {
  return line.indexOf("INCONCLUSIVE (harness)") !== -1;
}

function main() {
  process.stdout.write(
    "starving harness deadlines: " + ENV_VAR + "=" + SCALE +
      " (a 45000ms wait becomes " + Math.max(1, Math.round(45000 * Number(SCALE))) + "ms)\n\n"
  );

  for (const rel of TARGETS) {
    const env = Object.assign({}, process.env);
    env[ENV_VAR] = SCALE;
    const r = spawnSync(process.execPath, [rel], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: PER_SUITE_TIMEOUT_MS,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
      env: env,
    });

    if (r.error) {
      report(false, rel, "could not run under starvation: " + String(r.error.message || r.error));
      continue;
    }

    const combined = (r.stdout || "") + (r.stderr || "");
    const failLines = failVerdictLines(combined);
    const untagged = failLines.filter((l) => !isTagged(l));
    const tagged = failLines.filter(isTagged);

    if (failLines.length === 0) {
      // No failure at all under near-zero deadlines. Two very different causes,
      // and conflating them would make this gate cry wolf -- which is how gates
      // come to be ignored, the failure mode this whole line of work is about.
      //
      //   (a) WIRING GAP: the suite is listed here but its deadlines never go
      //       through harnessDeadline(), so the knob does nothing. That is a real
      //       defect in this sweep's own setup and must fail.
      //   (b) LEGITIMATELY INERT: the suite IS wired, but on this platform the
      //       starvation-sensitive cases do not run at all -- several watchdog
      //       cases are platform-skipped, so on Windows there is nothing for
      //       starvation to break. That is not a defect; it means this sweep
      //       provides no coverage for that suite on this leg, which must be
      //       stated loudly rather than either failing or passing silently.
      //
      // The discriminator is static, not behavioural: is harnessDeadline actually
      // referenced in the file? Same reasoning as report-integrity's INERT
      // detector -- a check that cannot fire on this platform should say so, not
      // manufacture a verdict.
      const wired = fs.existsSync(path.join(ROOT, rel)) &&
        fs.readFileSync(path.join(ROOT, rel), "utf8").indexOf("harnessDeadline") !== -1;
      if (!wired) {
        report(
          false,
          rel,
          "WIRING GAP: listed as a starvation target but the file never calls " +
            "harnessDeadline(), so " + ENV_VAR + " does nothing to it and this sweep is " +
            "vacuous for it. Wire its deadlines or remove it from TARGETS"
        );
      } else {
        report(
          true,
          rel,
          "INERT on this platform: the suite is wired to " + ENV_VAR + " but no verdict failed " +
            "at " + SCALE + "x, so its starvation-sensitive cases do not run here (several " +
            "watchdog cases are platform-skipped). This sweep provides NO COVERAGE for this " +
            "suite on this leg"
        );
      }
      continue;
    }

    if (untagged.length) {
      report(
        false,
        rel,
        untagged.length + " of " + failLines.length + " failure(s) under starvation are NOT tagged " +
          "INCONCLUSIVE, so they assert something the harness could not have observed. First: " +
          untagged[0].slice(0, 240)
      );
      continue;
    }

    report(
      true,
      rel,
      "all " + failLines.length + " failure(s) under starvation correctly reported INCONCLUSIVE " +
        "(" + tagged.length + " tagged, 0 confident verdicts)"
    );
  }

  process.stdout.write("\nSUMMARY PASS=" + pass + " FAIL=" + fail + "\n");
  if (failures.length) process.stdout.write("FAILING: " + failures.join(", ") + "\n");
  process.exitCode = fail > 0 ? 1 : 0;
}

main();
