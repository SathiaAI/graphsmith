/* Harness honesty under CONTENTION — the missing half of the starvation sweep.
 *
 * WHY THIS EXISTS
 *
 * tests/harness-honesty/starvation/ proves a suite stays honest when its deadlines are
 * made absurdly SHORT. That catches a case which cannot tell "the thing did not happen"
 * from "I did not wait long enough".
 *
 * It does not catch the case that actually happens in CI: the deadlines are as written,
 * and the MACHINE is slow. A shared runner with other jobs on it, a virus scanner in the
 * path, Windows process creation — and a case whose verdict depends on something
 * finishing fast enough flips to a confident, wrong answer.
 *
 * That gap was not theoretical. Three consecutive CI runs of one branch failed on three
 * DIFFERENT cases, none of them related to the change under test:
 *
 *   run #79  watchdog/gpt-sol-pro  a spawned process had 3s to become ready
 *   run #81  scenario 6b           two identical corpus runs, different bundle hashes
 *            state-store 11        a 200ms window expired during test setup
 *   run #82  (windows AND ubuntu)  different again
 *
 * Each looks like a separate bug. They are one population: cases whose verdict depends on
 * wall-clock speed. Which one trips is close to random, so patching them as they surface
 * never converges — and a gate that fails randomly teaches people to re-run until green,
 * which is precisely the habit contract 10 List C exists to prevent.
 *
 * THE INVARIANT
 *
 * Different from starvation, and simpler. Under starvation every wait MUST expire, so
 * INCONCLUSIVE is the only honest verdict available. Under contention the product still
 * works — it is merely slower — so:
 *
 *     A suite that passes on an idle machine must also pass under load.
 *     Any NEW failure under load is a verdict that depends on machine speed rather than
 *     on the product.
 *
 * A new failure has exactly two honest resolutions, and this sweep does not care which:
 *
 *   - the case holds a tight timing assumption -> widen it, or make it detect that its
 *     own timing window was violated and report INCONCLUSIVE (List C rule 1); or
 *   - the product genuinely misbehaves under load -> a real finding, and a valuable one.
 *
 * Either way the current state — a confident product verdict produced by a busy CPU — is
 * inadmissible.
 *
 * WHAT IT DOES NOT DO
 *
 * It does not scale any deadline, harness or product. Nothing in the suite under test is
 * modified. The only variable is how much CPU the rest of the box is consuming, which is
 * the one thing CI varies and local runs never do.
 *
 * Cost: each target runs twice (idle, then loaded). Set CONTENTION_TARGETS to a
 * comma-separated subset while iterating.
 */

"use strict";

const { spawn, spawnSync } = require("child_process");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const PER_SUITE_TIMEOUT_MS = 900000;

/* Load factor. 2x the core count keeps every core oversubscribed without pushing the box
 * into swap — the goal is a slow machine, not a broken one. A GitHub runner is 2 cores,
 * so this approximates a runner sharing itself with one other busy job. */
const LOAD_FACTOR = Number(process.env.CONTENTION_LOAD || 8);
/* How many loaded passes per target. These failures are probabilistic, so more samples
 * means better detection at linear cost. */
const LOADED_PASSES = Math.max(1, Number(process.env.CONTENTION_PASSES || 2));
const WORKERS = Math.max(2, (os.cpus() || { length: 2 }).length * LOAD_FACTOR);

const DEFAULT_TARGETS = [
  "tests/state-store/deepseek/run-tests.js",
  "tests/scenario/run-tests.js",
  "tests/watchdog/gpt-sol-pro/run-tests.js",
  "tests/watchdog/grok/run-tests.js",
  "tests/scaffold/deepseek/run-tests.js",
  "tests/watch/grok/run-tests.js",
];

const TARGETS = process.env.CONTENTION_TARGETS
  ? process.env.CONTENTION_TARGETS.split(",").map((s) => s.trim()).filter(Boolean)
  : DEFAULT_TARGETS;

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

/* Same verdict-line shapes the starvation sweep parses; kept in step with it deliberately
 * so a harness that adopts a new format has to update one convention, not two. */
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

/* A verdict line reduced to its case NAME, so the idle and loaded runs can be compared
 * without the detail text (which legitimately differs run to run: hashes, pids, timings). */
function caseKey(line) {
  return line
    .replace(/^(\[FAIL\]|FAIL:?)\s*/, "")
    .split(/\s+[—–-]{1,2}\s+|\t|: /)[0]
    .trim()
    .slice(0, 120);
}

function runSuite(rel) {
  const r = spawnSync(process.execPath, [rel], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: PER_SUITE_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
  });
  return {
    error: r.error || null,
    text: (r.stdout || "") + (r.stderr || ""),
  };
}

/* Busy-loop children. Deliberately plain CPU burn: no I/O, no memory growth, nothing that
 * could corrupt a suite's fixtures. They only compete for the scheduler. */
function startLoad() {
  const kids = [];
  for (let i = 0; i < WORKERS; i += 1) {
    kids.push(spawn(process.execPath, ["-e", "for(;;){Math.sqrt(Math.random());}"], {
      stdio: "ignore",
      windowsHide: true,
    }));
  }
  return kids;
}

function stopLoad(kids) {
  for (const k of kids) {
    try { k.kill("SIGKILL"); } catch (_) { /* already gone */ }
  }
}

function main() {
  /* OPT-IN. scripts/ci-run-suites.js discovers every run-tests.js, so without this gate
   * this file would run on every CI job — and it deliberately saturates the CPU and runs
   * each target three times, which is hours rather than minutes. That would make the gate
   * unusable and, worse, would itself become a source of the timing flake it exists to
   * find: a sweep that saturates the box while other suites queue behind it.
   *
   * This is a DIAGNOSTIC, run deliberately when investigating a timing failure, not a
   * per-commit gate. The skip is stated loudly rather than passing silently — an
   * unexercised check that prints nothing is the shape contract 10 List C rule 4 exists
   * to prevent.
   *
   * Run it with: CONTENTION_SWEEP=1 node tests/harness-honesty/contention/run-tests.js */
  if (!process.env.CONTENTION_SWEEP) {
    process.stdout.write(
      "SKIPPED contention-sweep - NOT RUN. This diagnostic saturates the CPU and runs each\n" +
      "target several times (hours, not minutes), so it is opt-in rather than a per-commit\n" +
      "gate. THIS RUN PROVIDES NO CONTENTION COVERAGE. Enable with CONTENTION_SWEEP=1.\n"
    );
    return;
  }

  process.stdout.write(
    "contention sweep: " + WORKERS + " CPU-burning workers on " +
      ((os.cpus() || { length: "?" }).length) + " core(s), " + LOADED_PASSES + " loaded pass(es) per target\n" +
      "invariant: a case that passes idle must pass under load, or its verdict depends on\n" +
      "machine speed rather than on the product\n\n"
  );

  for (const rel of TARGETS) {
    const idle = runSuite(rel);
    if (idle.error) {
      report(false, rel, "could not run idle: " + String(idle.error.message || idle.error));
      continue;
    }
    const idleFails = new Set(failVerdictLines(idle.text).map(caseKey));

    /* Repeat the loaded pass. Proven necessary the hard way while building this: a direct
     * measurement showed state-store's window setup taking 523ms against a 200ms budget
     * under load, yet a single loaded pass of the whole suite still came back clean. One
     * sample under-detects, and a sweep that reports "clean" off one sample is the same
     * false confidence this file exists to catch. */
    const loadedLines = [];
    const seenLoaded = new Set();
    let loadError = null;
    for (let attempt = 0; attempt < LOADED_PASSES; attempt += 1) {
      const kids = startLoad();
      let loaded;
      try {
        loaded = runSuite(rel);
      } finally {
        stopLoad(kids);
      }
      if (loaded.error) {
        loadError = "could not run under load (pass " + (attempt + 1) + "): " +
          String(loaded.error.message || loaded.error);
        break;
      }
      for (const l of failVerdictLines(loaded.text)) {
        const k = caseKey(l);
        if (seenLoaded.has(k)) continue;
        seenLoaded.add(k);
        loadedLines.push(l);
      }
    }
    if (loadError) { report(false, rel, loadError); continue; }
    const newFails = loadedLines.filter((l) => !idleFails.has(caseKey(l)));
    const newConfident = newFails.filter((l) => !isTagged(l));
    const newTagged = newFails.filter(isTagged);

    if (newConfident.length) {
      report(
        false,
        rel,
        newConfident.length + " case(s) that PASS idle emit a CONFIDENT failure under load — " +
          "the verdict depends on how fast the machine is, not on the product. Widen the " +
          "assumption, or make the case report INCONCLUSIVE when its own timing window is " +
          "violated (contract 10 List C rule 1). First: " + newConfident[0].slice(0, 220)
      );
      continue;
    }

    if (newTagged.length) {
      /* Degraded but honest: the extra failures under load all said "I could not observe
       * this". Fail-closed still stops a merge, so this is not silently fine — but it is
       * the correct behaviour, and it is a different problem from a lie. */
      report(
        true,
        rel,
        "no confident failures under load; " + newTagged.length + " additional case(s) " +
          "correctly degraded to INCONCLUSIVE. Honest, though it still gates — widening " +
          "those waits would make the suite usable on a slow runner"
      );
      continue;
    }

    report(
      true,
      rel,
      "identical verdicts idle and under " + WORKERS + "x load (" + loadedLines.length +
        " pre-existing failure(s), unchanged)"
    );
  }

  process.stdout.write("\nSUMMARY PASS=" + pass + " FAIL=" + fail + "\n");
  if (failures.length) process.stdout.write("FAILING: " + failures.join(", ") + "\n");
  process.exitCode = fail > 0 ? 1 : 0;
}

main();
