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
      const lines = interestingLines((rr.stdout || "") + (rr.stderr || ""), 30);
      reruns.push({ suite: rel, status: rr.status, flaky: rr.status === 0, lines: lines });
      console.log(rr.status === 0
        ? "    re-run PASSED -> FLAKY (a timing assumption), not a component regression"
        : "    re-run also failed (exit " + rr.status + ") -> reproducible");
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
