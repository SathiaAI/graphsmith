#!/usr/bin/env node
/* GraphSmith CI suite runner — scripts/ci-run-suites.js
 *
 * Discovers every committed tests/<component>/<family>/run-tests.js, classifies
 * each against ci-suite-manifest.json, runs them all, and gates the job.
 *
 * WHY THIS IS A FILE. This logic used to live as a ~2000-character `node -e`
 * one-liner inside .github/workflows/ci.yml, duplicated again in
 * ci-templates/gitlab-ci.yml. That shape could not be run locally the way CI runs
 * it, could not be syntax-checked by the repo's own `node --check scripts/*.js`
 * step, and any quoting slip broke all six matrix legs at once. It is a file now,
 * so it is covered by the syntax check and both CI templates call the same code.
 *
 * WHAT IT ADDS. On failure it also writes the failing-suite list to
 * $GITHUB_STEP_SUMMARY. The classification and exit behaviour are otherwise
 * byte-for-byte the same policy as before. That summary exists because the log
 * viewer is not a reliable way to find out WHICH suite failed on a matrix leg:
 * the failing names are ~3300 lines into a virtualised log. Emitting them to the
 * summary puts the one fact a maintainer needs on the run's front page.
 *
 * A failing gating suite is ALSO re-run once with its output captured, and the
 * FAIL/SUMMARY lines go into the summary. A suite that passes on that second run
 * is FLAKY rather than broken, and the summary says so explicitly — that
 * distinction is the whole difference between "a component regressed" and "a test
 * makes a timing assumption", and it is otherwise invisible from a single run.
 *
 * Policy (unchanged, see ci-suite-manifest.json's own header):
 *   gating       -> must be green, failure fails the job
 *   evidence_only-> run and logged in full, never gates
 *   unlisted     -> FAIL-SAFE: treated as GATING with an explicit warning
 * Usage: node scripts/ci-run-suites.js [--root tests] [--manifest ci-suite-manifest.json]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

function parseArgs(argv) {
  const out = { root: "tests", manifest: "ci-suite-manifest.json" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root" && argv[i + 1]) out.root = argv[++i];
    else if (argv[i] === "--manifest" && argv[i + 1]) out.manifest = argv[++i];
  }
  return out;
}

function discover(root) {
  const suites = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name).split(path.sep).join("/");
      if (entry.isDirectory()) walk(p);
      else if (entry.name === "run-tests.js") suites.push(p);
    }
  })(root);
  suites.sort();
  return suites;
}


// Files that LOOK like committed suites but that discover() will never return,
// because it matches the literal filename "run-tests.js" and nothing else.
//
// Three such files exist in this repo (tests/matrix/claude/tests.js,
// tests/shadow/gemini/tests.js, tests/banned-lint/gemini/tests.js) and until this
// was added, nothing anywhere said so: they are committed, they are executable,
// they were written to be run, and no CI surface ran them. A test that silently
// does not run is worse than a missing test, because the directory listing implies
// coverage that does not exist.
//
// This does NOT start running them. Auto-adopting unreviewed suites into a gate is
// how a gate gets disabled the first time one is flaky. It states the gap so the
// choice -- rename into discovery, wire elsewhere, or delete -- is a decision
// somebody makes rather than a fact nobody notices.
function undiscovered(root, discovered) {
  const seen = new Set(discovered);
  const out = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name).split(path.sep).join("/");
      if (entry.isDirectory()) walk(p);
      else if (/(?:^|[-.])(?:tests|battery)\.js$/.test(entry.name) && !seen.has(p)) out.push(p);
    }
  })(root);
  out.sort();
  return out;
}

// A prefix list is only safe to match with String#startsWith if every entry is
// a non-empty string: "".startsWith("") is true for ANY suite path, so a stray
// empty-string (or non-string) entry in evidence_only would silently swallow
// every suite -- including ones explicitly listed as gating -- into
// evidence_only, with none of the fail-safe's warnings, because evidence_only
// is checked before gating_suites. That is a silent, total defanging of the
// gate from a one-character manifest typo. Fail loudly and refuse to run
// rather than let that happen quietly.
function validatePrefixList(list, key, manifestPath) {
  if (list === undefined) return [];
  if (!Array.isArray(list)) {
    throw new Error(manifestPath + ": \"" + key + "\" must be an array of path-prefix strings.");
  }
  for (const pre of list) {
    if (typeof pre !== "string" || pre.length === 0) {
      throw new Error(manifestPath + ": \"" + key + "\" contains an invalid prefix (" +
        JSON.stringify(pre) + ") -- prefixes must be non-empty strings. An empty " +
        "string matches every suite path and would silently disable the gate.");
    }
  }
  return list;
}

function makeClassifier(manifest, manifestPath) {
  const gating = validatePrefixList(manifest.gating_suites, "gating_suites", manifestPath || "<manifest>");
  const evidence = validatePrefixList(manifest.evidence_only, "evidence_only", manifestPath || "<manifest>");
  return function classify(p) {
    if (evidence.some((pre) => p.startsWith(pre))) return "evidence_only";
    if (gating.some((pre) => p.startsWith(pre))) return "gating";
    return "unknown_gating";
  };
}

// A case that could not establish its preconditions reports
//   FAIL <name> - INCONCLUSIVE (harness): <reason>
// It did not pass and it did not find a defect: it did not run. That still fails
// the gate -- a check that never executed must never read as green, the same
// fail-closed rule the manifest applies to unlisted suites -- but it must never
// be counted or displayed as a product finding either. Mixing the two is how a
// harness timeout comes to be reported as a product defect, which is exactly what
// one watchdog case did: it announced "no interface for manager to detect guard
// death" when it had merely run out of time waiting for the guard to arm.
function inconclusiveLines(text) {
  return String(text)
    .split("\n")
    .filter(function (line) { return line.indexOf("INCONCLUSIVE (harness)") !== -1; })
    .join("\n");
}

// Only the lines a human needs to see: the verdicts, not the whole transcript.
function interestingLines(text, limit) {
  return String(text)
    .split("\n")
    .filter((line) => /^\s*(FAIL|\[FAIL\])|SUMMARY|=== Results|TOTAL=|"status": "FAIL"|Error:/.test(line))
    .slice(-limit)
    .join("\n");
}

function writeSummary(failedGating, reruns) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  const out = [];
  out.push("## FAILED gating suite(s) — " + process.platform + ", node " + process.version);
  out.push("");
  for (const f of failedGating) out.push("- `" + f + "`");
  out.push("");
  const anyInconclusive = reruns.some((r) => r.inconclusive);
  if (anyInconclusive) {
    out.push("### Inconclusive case(s) — NOT product findings");
    out.push("");
    out.push("These checks could not establish their preconditions, so they did not run. " +
      "They are counted as failures because a check that never executed must not read as " +
      "green, but nothing below says anything about whether the product is correct. A " +
      "recurring inconclusive is a bug with an owner — a deadline too tight, or a component " +
      "too slow to arm — not a condition to be tolerated.");
    out.push("");
    for (const r of reruns) {
      if (!r.inconclusive) continue;
      out.push("- `" + r.suite + "`" + (r.flaky ? " (cleared on re-run — transient)" : " (still inconclusive on re-run)"));
      out.push("");
      out.push("```");
      out.push(r.inconclusive);
      out.push("```");
      out.push("");
    }
  }
  for (const r of reruns) {
    out.push(r.flaky
      ? "### " + r.suite + " — re-run PASSED, so this suite is FLAKY, not broken"
      : "### " + r.suite + " — re-run also failed (exit " + r.status + ")");
    out.push("");
    out.push("```");
    out.push(r.lines || "(no FAIL/SUMMARY lines captured on the re-run)");
    out.push("```");
    out.push("");
  }
  try { fs.appendFileSync(summaryPath, out.join("\n") + "\n"); }
  catch (error) { process.stderr.write("ci-run-suites: could not write step summary: " + error.message + "\n"); }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = JSON.parse(fs.readFileSync(args.manifest, "utf8"));
  const classify = makeClassifier(manifest, args.manifest);
  const suites = discover(args.root);

  console.log("Discovered " + suites.length + " suite(s):");
  for (const s of suites) console.log("  " + s + "  [" + classify(s) + "]");

  const notRun = undiscovered(args.root, suites);
  if (notRun.length) {
    console.log("");
    console.log("NOT DISCOVERED -- " + notRun.length + " committed file(s) under " + args.root +
      " look like suites but are not named run-tests.js, so this runner never executes them.");
    console.log("This is stated, not acted on: they are NOT run and do NOT gate. Rename them into");
    console.log("discovery, confirm they are run by another CI step, or delete them.");
    for (const f of notRun) console.log("  " + f);
  }

  const failedGating = [];
  const failedEvidence = [];
  const unknownWarned = [];

  for (const s of suites) {
    const kind = classify(s);
    if (kind === "unknown_gating") {
      unknownWarned.push(s);
      console.warn("WARNING -- " + s + " is not listed in " + args.manifest +
        " (gating_suites or evidence_only) -- treating as GATING (fail-safe).");
    }
    console.log("");
    console.log("=== " + s + " [" + kind + "] ===");
    const r = cp.spawnSync(process.execPath, [s], { stdio: "inherit" });
    if (r.status !== 0) {
      const record = s + " (exit " + r.status + ")";
      if (kind === "evidence_only") failedEvidence.push(record);
      else failedGating.push(record);
    }
  }

  console.log("");
  if (failedEvidence.length) {
    console.log("EVIDENCE-ONLY suite(s) reported findings (logged, does NOT gate merge):");
    for (const f of failedEvidence) console.log("  " + f);
  }
  if (unknownWarned.length) {
    console.log("Suite(s) absent from " + args.manifest + " (treated as gating, fail-safe):");
    for (const f of unknownWarned) console.log("  " + f);
  }

  if (failedGating.length) {
  // Everything below goes to STDOUT, deliberately, even though it is failure
  // reporting and console.error would be the reflex.
  //
  // The evidence-only list above is written with console.log. When the gating
  // list went to stderr, the two streams interleaved unpredictably in the
  // captured CI log, so evidence-only suites appeared UNDER the "FAILED gating"
  // header. That produced a log which read as though tests/v040/** -- listed
  // plainly as evidence_only in ci-suite-manifest.json -- had been classified
  // as gating on macOS but not on Linux. Hours went into hunting a
  // classification bug that did not exist, including a full battery run against
  // two trees to compare them. There was never any inconsistency; there were
  // two streams. One stream, one ordering, no phantom.
    console.log("");
    console.log("FAILED gating suite(s):");
    for (const f of failedGating) console.log("  " + f);

    // Re-run each failure ONCE with output captured, purely to classify it as
    // broken vs flaky and to surface its FAIL lines somewhere readable. Only on
    // the failure path, so a green run pays nothing for this.
    const reruns = [];
    for (const f of failedGating) {
      const rel = f.split(" (exit")[0];
      console.log("");
      console.log("--- re-running " + rel + " once to classify broken vs flaky ---");
      const rr = cp.spawnSync(process.execPath, [rel], { encoding: "utf8" });
      const combined = (rr.stdout || "") + (rr.stderr || "");
      const lines = interestingLines(combined, 30);
      const inconclusive = inconclusiveLines(combined);
      reruns.push({
        suite: rel,
        status: rr.status,
        flaky: rr.status === 0,
        lines: lines,
        inconclusive: inconclusive,
      });
      console.log(rr.status === 0
        ? "    re-run PASSED -> FLAKY (a timing assumption), not a component regression"
        : "    re-run also failed (exit " + rr.status + ") -> reproducible");
      if (inconclusive) {
        console.log("    NOTE: this suite reported INCONCLUSIVE case(s) -- the harness could not");
        console.log("          establish preconditions. That is not a product finding; see below.");
      }
      if (lines) console.log(lines);
    }
    writeSummary(failedGating, reruns);
    process.exit(1);
  }

  console.log("");
  console.log("All gating suite(s) passed (" + suites.length + " discovered, " +
    failedEvidence.length + " evidence-only failure(s) logged above, non-gating).");
}

if (require.main === module) main();

module.exports = { discover, makeClassifier, interestingLines };
