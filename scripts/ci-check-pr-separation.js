#!/usr/bin/env node
/**
 * ci-check-pr-separation.js — trusted-workflow PR separation guard.
 *
 * A single PR must not mix:
 *   (a) evaluator/corpus files  — the machinery/data that SCORES candidates
 *       ("scripts/scenario.js", anything under "corpus/", anything under
 *       "scenarios/" [this repo's current on-disk corpus directory — see
 *       NOTE below])
 *   (b) behavior files          — the machinery/data being SCORED
 *       ("SKILL.md", anything under "references/", any other
 *       "scripts/*.js")
 *
 * Rationale (contracts/04-trust-boundary-matrix.md B17, contracts/11
 * "held-out eval deltas ... evaluator/corpus PRs separate from behavior
 * PRs"): a hostile contributor who can edit the evaluator/corpus in the
 * SAME PR as the behavior it grades could make the grader lie about the
 * behavior change. Splitting them into separate PRs means a human
 * reviewing a behavior PR is looking at an evaluator that was already
 * reviewed and merged on its own — the grader can't be doctored in the
 * same breath as the thing it grades.
 *
 * Contracts-only, tests-only, or docs-only PRs — i.e. any PR that touches
 * NEITHER category — always pass. Touching only ONE category also passes;
 * only a PR that touches AT LEAST ONE file in each category fails.
 *
 * NOTE on "corpus/" vs "scenarios/": contracts/11 names the evaluator
 * corpus glob as `corpus/**`. As of this writing there is no top-level
 * corpus/ directory in this repo — the scenario corpus scripts/scenario.js
 * actually reads from lives at scenarios/ (see tests/scenario/run-tests.js
 * REAL_CORPUS_DIR). Both globs are matched here so the guard is correct
 * against the CURRENT repo layout (scenarios/) and forward-compatible if a
 * corpus/ directory is introduced later per the contract text. Treating
 * only "corpus/" as evaluator-side while the real corpus lives under
 * "scenarios/" would leave the documented protection a no-op today, which
 * is a bigger problem than being slightly over-inclusive.
 *
 * Input (changed-file list for the PR — one relative path per line):
 *   - stdin (default) — e.g. `git diff --name-only <base> <head> | node
 *     scripts/ci-check-pr-separation.js`
 *   - --files <path>  — read the list from a file instead of stdin
 *     (this is what --selftest and other test harnesses use)
 *   - --base <ref>    — convenience mode: this script runs
 *     `git diff --name-only <ref>...HEAD` itself (repo root = cwd) and
 *     uses that output. No package deps — child_process is a Node
 *     builtin. Prefer the workflow computing the diff and piping it in
 *     (stdin/--files); --base is for local ad-hoc use.
 *
 * Output: JSON on stdout (schema_version, decision, matched files per
 * category). Prose on stderr. Exit 0 = no violation, 1 = separation
 * violation found, 2 = usage/input error.
 *
 * Zero runtime deps. CommonJS. Node >= 18. No clocks/randomness in the
 * decision path (paths in, decision out — pure function).
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const SCHEMA_VERSION = "1.0";

// --- classification -------------------------------------------------------

function normalizePath(p) {
  // git diff already emits forward-slash paths on every platform, but be
  // defensive against callers who hand us OS-native paths.
  return String(p).trim().replace(/\\/g, "/").replace(/^\.\//, "");
}

function isEvaluatorCorpus(p) {
  if (p === "scripts/scenario.js") return true;
  if (p === "corpus" || p.startsWith("corpus/")) return true;
  if (p === "scenarios" || p.startsWith("scenarios/")) return true;
  return false;
}

function isBehavior(p) {
  if (p === "SKILL.md") return true;
  if (p === "references" || p.startsWith("references/")) return true;
  if (p.startsWith("scripts/") && p.endsWith(".js") && p !== "scripts/scenario.js") {
    return true;
  }
  return false;
}

/**
 * Pure decision function: given a list of changed file paths, decide
 * whether this PR mixes evaluator/corpus files with behavior files.
 * Returns a plain object; never throws on well-formed string input.
 */
function classify(files) {
  const evaluatorCorpus = [];
  const behavior = [];
  const neutral = [];

  for (const raw of files) {
    if (raw === "" || raw == null) continue;
    const p = normalizePath(raw);
    if (p === "") continue;
    if (isEvaluatorCorpus(p)) evaluatorCorpus.push(p);
    else if (isBehavior(p)) behavior.push(p);
    else neutral.push(p);
  }

  const mixed = evaluatorCorpus.length > 0 && behavior.length > 0;

  return {
    schema_version: SCHEMA_VERSION,
    decision: mixed ? "reject" : "pass",
    reason: mixed
      ? "PR mixes evaluator/corpus files with behavior files — split into separate PRs (contracts/11, contracts/04 B17)."
      : "no evaluator/corpus + behavior mixing detected",
    files_total: evaluatorCorpus.length + behavior.length + neutral.length,
    evaluator_corpus_files: evaluatorCorpus,
    behavior_files: behavior,
    neutral_files: neutral,
  };
}

// --- input plumbing --------------------------------------------------------

function readStdin() {
  try {
    return fs.readFileSync(0, "utf8");
  } catch (e) {
    return "";
  }
}

function readFilesArg(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function gitDiffNameOnly(baseRef) {
  return execFileSync("git", ["diff", "--name-only", baseRef + "...HEAD"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

function linesOf(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

// --- selftest ---------------------------------------------------------------

function selftest() {
  let passed = 0;
  const failures = [];

  function assert(name, cond, detail) {
    if (cond) {
      passed++;
      process.stderr.write("  PASS  " + name + "\n");
    } else {
      failures.push(name + (detail ? " -- " + detail : ""));
      process.stderr.write("  FAIL  " + name + (detail ? " -- " + detail : "") + "\n");
    }
  }

  // 1. Mixing scenario.js with a behavior script fails.
  {
    const r = classify(["scripts/scenario.js", "scripts/gate.js"]);
    assert("mix: scenario.js + scripts/gate.js -> reject", r.decision === "reject");
  }

  // 2. Mixing corpus/** with SKILL.md fails.
  {
    const r = classify(["corpus/foo/bar.json", "SKILL.md"]);
    assert("mix: corpus/** + SKILL.md -> reject", r.decision === "reject");
  }

  // 3. Mixing scenarios/** (real on-disk corpus dir) with references/** fails.
  {
    const r = classify(["scenarios/pipeline-normal.json", "references/full-build-system.md"]);
    assert("mix: scenarios/** + references/** -> reject", r.decision === "reject");
  }

  // 4. Evaluator/corpus-only PR passes.
  {
    const r = classify(["scripts/scenario.js", "corpus/x.json", "scenarios/y.json"]);
    assert("evaluator/corpus-only -> pass", r.decision === "pass");
  }

  // 5. Behavior-only PR passes.
  {
    const r = classify(["SKILL.md", "references/foo.md", "scripts/gate.js"]);
    assert("behavior-only -> pass", r.decision === "pass");
  }

  // 6. Contracts-only PR passes.
  {
    const r = classify(["contracts/01-x.md", "contracts/02-y.md"]);
    assert("contracts-only -> pass", r.decision === "pass");
  }

  // 7. Tests-only PR passes (even though it touches tests/gate/... which
  //    superficially mentions "gate").
  {
    const r = classify(["tests/gate/grok/run-tests.js", "tests/verify/deepseek/run-tests.js"]);
    assert("tests-only -> pass", r.decision === "pass");
  }

  // 8. Docs-only PR passes.
  {
    const r = classify(["docs/notes.md", "README.md"]);
    assert("docs-only -> pass", r.decision === "pass");
  }

  // 9. Empty file list passes.
  {
    const r = classify([]);
    assert("empty list -> pass", r.decision === "pass");
  }

  // 10. Neutral files never trigger a violation on their own, even mixed
  //     with only one side.
  {
    const r1 = classify(["contracts/01-x.md", "scripts/scenario.js"]);
    const r2 = classify(["contracts/01-x.md", "SKILL.md"]);
    assert("neutral + evaluator-only -> pass", r1.decision === "pass");
    assert("neutral + behavior-only -> pass", r2.decision === "pass");
  }

  // 11. ci-check-pr-separation.js itself counts as "other scripts/*.js"
  //     (behavior side) — a PR touching it alongside corpus files fails.
  //     This is intentional: it is a script under scripts/ other than
  //     scenario.js, so it is treated the same as any other script.
  {
    const r = classify(["scripts/ci-check-pr-separation.js", "corpus/z.json"]);
    assert(
      "this script itself is behavior-side: mix with corpus/** -> reject",
      r.decision === "reject"
    );
  }

  // 12. Windows-style backslash paths normalize the same as forward-slash.
  {
    const r = classify(["scripts\\scenario.js", "scripts\\gate.js"]);
    assert("backslash paths normalize and still detect the mix", r.decision === "reject");
  }

  // 13. ./-prefixed and blank/whitespace-only lines are tolerated.
  {
    const r = classify(["./scripts/scenario.js", "  ", "", "corpus/a.json"]);
    assert(
      "./-prefix and blank lines tolerated, still evaluator-only -> pass",
      r.decision === "pass" && r.evaluator_corpus_files.length === 2
    );
  }

  // 14. A single evaluator file with nothing else passes.
  {
    const r = classify(["scripts/scenario.js"]);
    assert("scenario.js alone -> pass", r.decision === "pass");
  }

  // 15. ci-templates/ and .github/workflows/ (this lane's own files) are
  //     neutral — a PR touching only CI plumbing never trips the guard.
  {
    const r = classify([".github/workflows/ci.yml", "ci-templates/gitlab-ci.yml"]);
    assert("CI-plumbing-only -> pass", r.decision === "pass");
  }

  process.stderr.write("\nselftest: " + passed + " passed, " + failures.length + " failed\n");
  if (failures.length > 0) {
    process.stderr.write("failures: " + failures.join("; ") + "\n");
  }
  return failures.length === 0;
}

// --- CLI ---------------------------------------------------------------

function usage() {
  process.stderr.write(
    "Usage: git diff --name-only <base> <head> | node scripts/ci-check-pr-separation.js\n" +
      "       node scripts/ci-check-pr-separation.js --files <path-to-newline-list>\n" +
      "       node scripts/ci-check-pr-separation.js --base <git-ref>   (runs git diff itself)\n" +
      "       node scripts/ci-check-pr-separation.js --selftest\n"
  );
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    const ok = selftest();
    process.exit(ok ? 0 : 1);
    return;
  }

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
    return;
  }

  let raw;
  const filesIdx = args.indexOf("--files");
  const baseIdx = args.indexOf("--base");

  try {
    if (filesIdx !== -1 && args[filesIdx + 1]) {
      raw = readFilesArg(args[filesIdx + 1]);
    } else if (baseIdx !== -1 && args[baseIdx + 1]) {
      raw = gitDiffNameOnly(args[baseIdx + 1]);
    } else if (args.length === 0) {
      raw = readStdin();
    } else {
      usage();
      process.exit(2);
      return;
    }
  } catch (e) {
    process.stderr.write("ci-check-pr-separation: failed to read changed-file list: " + e.message + "\n");
    process.exit(2);
    return;
  }

  const files = linesOf(raw);
  const result = classify(files);

  process.stdout.write(JSON.stringify(result, null, 2) + "\n");

  if (result.decision === "reject") {
    process.stderr.write("\nci-check-pr-separation: REJECTED — " + result.reason + "\n");
    process.stderr.write("  evaluator/corpus files: " + JSON.stringify(result.evaluator_corpus_files) + "\n");
    process.stderr.write("  behavior files:         " + JSON.stringify(result.behavior_files) + "\n");
    process.stderr.write("  Split this PR: one PR for the evaluator/corpus change, a separate PR for the behavior change.\n");
    process.exit(1);
    return;
  }

  process.stderr.write("ci-check-pr-separation: pass (" + files.length + " changed file(s), no mixing)\n");
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = { classify, isEvaluatorCorpus, isBehavior, selftest };
