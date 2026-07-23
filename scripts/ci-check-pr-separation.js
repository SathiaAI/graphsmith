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
 * only a PR that touches AT LEAST ONE file in each category fails. An
 * EMPTY diff (nothing to separate) always passes.
 *
 * NOTE on "corpus/" vs "scenarios/": contracts/11 names the evaluator
 * corpus glob as `corpus/**`. As of this writing there is no top-level
 * corpus/ directory in this repo — the scenario corpus scripts/scenario.js
 * actually reads from lives at scenarios/ (see tests/scenario/run-tests.js
 * REAL_CORPUS_DIR). Both globs are matched here so the guard is correct
 * against the CURRENT repo layout (scenarios/) and forward-compatible if a
 * corpus/ directory is introduced later per the contract text.
 *
 * --- Trust boundary (v2 — CI-fix attempt 1) ---------------------------
 *
 * A hostile PR can edit THIS SCRIPT. If a workflow checks out the PR head
 * and then runs `node scripts/ci-check-pr-separation.js` from that
 * checkout, the PR author can simply patch the script to always exit 0
 * and the whole gate is a no-op. This script must therefore always be
 * INVOKED from a trusted base revision (e.g. `git show <base_sha>:scripts/
 * ci-check-pr-separation.js` piped to a temp file and executed from
 * there) — see .github/workflows/ci.yml's `pr-separation-guard` job for
 * the mechanics. This file cannot enforce that on its own; it is a
 * documented operational contract with the caller.
 *
 * --- Classifier hardening (v2) -----------------------------------------
 *
 * Every path is normalized before classification:
 *   - backslashes unified to forward slashes
 *   - "." segments and empty segments (from "//", leading "./", trailing
 *     "/") are collapsed, WHEREVER they occur in the path, not just at
 *     the front
 *   - sensitive prefixes/files are matched CASE-INSENSITIVELY
 *   - unicode is inspected under three normalization forms (NFC, NFKC,
 *     and diacritic-stripped NFD) — if an alternate form reveals a
 *     sensitive path that the primary NFC form disguises (fullwidth
 *     separators, combining-mark tricks), the path is treated as
 *     disguised
 *   - a bounded filesystem check resolves symlink aliases: if a
 *     currently-neutral-looking path resolves (relative to cwd) through a
 *     symlink onto a sensitive path, it is treated as disguised
 *
 * FAIL-CLOSED (the whole diff is rejected, independent of category mixing)
 * for any single changed-path entry that is:
 *   - carrying a NUL byte
 *   - carrying a literal ".." path segment anywhere (this is deliberately
 *     UNCONDITIONAL — even a lone ".." path with nothing to "mix" with is
 *     rejected, because collapsing ".." silently and then applying the
 *     ordinary mixing rule would let a single crafted path re-enter a
 *     sensitive directory in a way a reviewer's diff view would not show
 *     as a mix)
 *   - a disguised unicode/symlink alias onto a sensitive path (see above)
 *   - part of an unparseable tab-bearing status line (see rename handling)
 *
 * POSTURE — do not over-reach: a genuinely neutral, unrecognized path
 * (`docs/**`, `contracts/**`, an unrelated `mystery/payload.bin`) still
 * PASSES, and an EMPTY diff still PASSES. Only un-normalizable/disguised
 * paths are fail-closed; unknown-but-clean paths are not sensitive by
 * default.
 *
 * --- Rename handling (v2) ------------------------------------------------
 *
 * `git diff --name-only` drops rename SOURCE paths (only the destination
 * survives), which lets an evaluator/corpus file renamed into a neutral
 * path evade classification entirely. Callers should invoke this script
 * with `git diff --name-status --no-renames <base> <head>` (see
 * .github/workflows/ci.yml) so every rename is split by git itself into a
 * plain delete line + a plain add line — both paths, one per line, no
 * tuple parsing needed. This script ALSO defensively parses, in case a
 * caller does not pass --no-renames:
 *   - tab-separated `git diff --name-status` lines: "<status>\t<path>" or
 *     rename/copy tuples "<R|C><score>\t<old>\t<new>" (both old and new
 *     are classified)
 *   - porcelain `git status`-style rename lines: "R  <old> -> <new>"
 * A tab-bearing line that matches neither known encoding is fail-closed
 * (its meaning cannot be safely inferred).
 *
 * Input (changed-file list for the PR — one relative path/status-line per
 * line):
 *   - stdin (default) — e.g. `git diff --name-status --no-renames <base>
 *     <head> | node scripts/ci-check-pr-separation.js`
 *   - --files <path>  — read the list from a file instead of stdin
 *     (this is what --selftest and other test harnesses use)
 *   - --base <ref>    — convenience mode: this script runs
 *     `git diff --name-status --no-renames <ref>...HEAD` itself (repo
 *     root = cwd) and uses that output. No package deps — child_process
 *     is a Node builtin. Prefer the workflow computing the diff and
 *     piping it in (stdin/--files); --base is for local ad-hoc use.
 *
 * Output: JSON on stdout (schema_version, decision, matched files per
 * category, fault_paths on fail-closed). Prose on stderr. Exit 0 = no
 * violation, 1 = separation violation OR fail-closed, 2 = usage/input
 * error.
 *
 * Zero runtime deps. CommonJS. Node >= 18. The decision path is
 * deterministic given (files, cwd, filesystem-at-cwd) — the bounded
 * symlink-alias check is the only part that consults the filesystem, and
 * only for paths that would otherwise classify as neutral.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const SCHEMA_VERSION = "2.0";

// --- known-sensitive sets (matched case-insensitively) --------------------

const EVALUATOR_EXACT = ["scripts/scenario.js"];
const EVALUATOR_BARE_DIRS = ["corpus", "scenarios"];
const EVALUATOR_PREFIXES = ["corpus/", "scenarios/"];

const BEHAVIOR_EXACT = ["skill.md"];
const BEHAVIOR_BARE_DIRS = ["references"];
const BEHAVIOR_PREFIXES = ["references/"];

const COMBINING_MARKS_RE = /[̀-ͯ]/g;

/**
 * Classify an already slash-unified, dot-segment-cleaned, non-empty path
 * with no ".." segments. Returns 'evaluator' | 'behavior' | 'neutral'.
 */
function classifyCanonical(p) {
  const lower = p.toLowerCase();
  if (EVALUATOR_EXACT.includes(lower)) return "evaluator";
  if (EVALUATOR_BARE_DIRS.includes(lower)) return "evaluator";
  if (EVALUATOR_PREFIXES.some((pre) => lower.startsWith(pre))) return "evaluator";
  if (BEHAVIOR_EXACT.includes(lower)) return "behavior";
  if (BEHAVIOR_BARE_DIRS.includes(lower)) return "behavior";
  if (BEHAVIOR_PREFIXES.some((pre) => lower.startsWith(pre))) return "behavior";
  if (lower.startsWith("scripts/") && lower.endsWith(".js") && lower !== "scripts/scenario.js") {
    return "behavior";
  }
  return "neutral";
}

// --- path normalization -----------------------------------------------------

/**
 * Resolve a symlink alias, if any, along the leading segments of `cleanPath`
 * relative to `cwd`. Returns the effective path (relative to cwd, forward
 * slashes) if a symlink was found along the way, or null if there is no
 * symlink, the path (or a needed prefix) does not exist on disk, or
 * resolution escapes cwd. Never throws.
 */
function resolveSymlinkAlias(cleanPath, cwd) {
  try {
    const segs = cleanPath.split("/");
    let sawSymlink = false;
    let acc = cwd;
    let existingDepth = 0;
    for (let i = 0; i < segs.length; i++) {
      const next = path.join(acc, segs[i]);
      let st;
      try {
        st = fs.lstatSync(next);
      } catch (e) {
        break; // this prefix (or the file itself) doesn't exist on disk
      }
      existingDepth = i + 1;
      acc = next;
      if (st.isSymbolicLink()) {
        sawSymlink = true;
        break;
      }
    }
    if (!sawSymlink) return null;

    let real;
    try {
      real = fs.realpathSync(acc);
    } catch (e) {
      return null;
    }
    const remainder = segs.slice(existingDepth);
    const effective = remainder.length > 0 ? path.join(real, ...remainder) : real;
    const relative = path.relative(cwd, effective).split(path.sep).join("/");
    if (relative === "" || relative.startsWith("..")) return null;
    return relative;
  } catch (e) {
    return null;
  }
}

/**
 * Normalize + classify a single raw path. Returns:
 *   null                                    — blank after cleanup, skip
 *   { ok: false, reason, display }          — fail-closed, whole diff rejected
 *   { ok: true, category, display, canonical }
 */
function normalizeOne(raw, cwd) {
  if (String(raw).indexOf(" ") !== -1) {
    return { ok: false, reason: "path contains a NUL byte", display: raw };
  }
  const s = String(raw).trim();
  if (s === "") return null;

  const unified = s.replace(/\\/g, "/");
  const segments0 = unified.split("/");

  if (segments0.some((seg) => seg === "..")) {
    return {
      ok: false,
      reason: "path traverses via a '..' segment — treated as disguised/traversal and fail-closed unconditionally",
      display: raw,
    };
  }

  const cleanSegs = segments0.filter((seg) => seg.length > 0 && seg !== ".");
  if (cleanSegs.length === 0) return null;
  const cleanPath = cleanSegs.join("/");

  const nfc = cleanPath.normalize("NFC");
  const catPrimary = classifyCanonical(nfc);

  if (catPrimary === "neutral") {
    // Confusable-unicode check: does an alternate normalization reveal a
    // sensitive path that NFC disguises?
    const nfkc = cleanPath.normalize("NFKC");
    const catNfkc = classifyCanonical(nfkc);
    const stripped = cleanPath.normalize("NFD").replace(COMBINING_MARKS_RE, "").normalize("NFC");
    const catStripped = classifyCanonical(stripped);
    if (catNfkc !== "neutral" || catStripped !== "neutral") {
      const revealed = catNfkc !== "neutral" ? catNfkc : catStripped;
      return {
        ok: false,
        reason:
          "path normalizes differently under NFKC/diacritic-stripping than under NFC, revealing a disguised " +
          revealed +
          " path",
        display: raw,
      };
    }

    // Symlink-alias check: does this neutral-looking path resolve through a
    // symlink onto a sensitive path?
    const resolved = resolveSymlinkAlias(cleanPath, cwd);
    if (resolved !== null) {
      const catResolved = classifyCanonical(resolved.normalize("NFC"));
      if (catResolved !== "neutral") {
        return {
          ok: false,
          reason: "path resolves through a symlink onto a sensitive (" + catResolved + ") path: " + resolved,
          display: raw,
        };
      }
    }
  }

  return { ok: true, category: catPrimary, display: raw, canonical: nfc };
}

// --- changed-file line expansion (git diff --name-status / rename forms) --

const STATUS_TAB_RE = /^([AMDTU]|[RC]\d{0,3})\t(.+)$/;
const PORCELAIN_RENAME_RE = /^[RC]\d{0,3}\s+(.+?)\s+->\s+(.+)$/;

/**
 * Expand one raw input line into 0+ candidate paths. Handles plain
 * `--name-only` lines (pass through unchanged), `--name-status` lines
 * ("<status>\t<path>" or "<R|C><score>\t<old>\t<new>"), and porcelain
 * `git status`-style rename lines ("R  <old> -> <new>"). Returns
 * { paths: string[], malformed: boolean }.
 */
function expandLine(line) {
  if (line.indexOf("\t") !== -1) {
    const m = STATUS_TAB_RE.exec(line);
    if (m) {
      const parts = m[2].split("\t");
      if (parts.length === 2) return { paths: [parts[0], parts[1]], malformed: false };
      if (parts.length === 1) return { paths: [parts[0]], malformed: false };
    }
    return { paths: [], malformed: true };
  }
  const rm = PORCELAIN_RENAME_RE.exec(line);
  if (rm) return { paths: [rm[1], rm[2]], malformed: false };
  return { paths: [line], malformed: false };
}

// --- classification ---------------------------------------------------------

/**
 * Given a list of changed-file lines (raw, one per line, any of the
 * supported encodings above), decide whether this PR mixes evaluator/
 * corpus files with behavior files, or must be fail-closed as
 * un-normalizable/disguised. Consults the filesystem at process.cwd() only
 * for the bounded symlink-alias check on otherwise-neutral paths.
 */
function classify(files) {
  const evaluatorCorpus = [];
  const behavior = [];
  const neutral = [];
  const faults = [];
  const cwd = process.cwd();

  for (const rawLine of files) {
    if (rawLine == null) continue;
    const trimmedLine = String(rawLine).trim();
    if (trimmedLine === "") continue;

    const expanded = expandLine(trimmedLine);
    if (expanded.malformed) {
      faults.push({
        path: trimmedLine,
        reason: "unrecognized status-line format (contains a tab but does not match a known git status/rename encoding)",
      });
      continue;
    }

    for (const onePath of expanded.paths) {
      const result = normalizeOne(onePath, cwd);
      if (result === null) continue;
      if (!result.ok) {
        faults.push({ path: result.display, reason: result.reason });
        continue;
      }
      if (result.category === "evaluator") evaluatorCorpus.push(result.canonical);
      else if (result.category === "behavior") behavior.push(result.canonical);
      else neutral.push(result.canonical);
    }
  }

  if (faults.length > 0) {
    return {
      schema_version: SCHEMA_VERSION,
      decision: "reject",
      fail_closed: true,
      reason:
        "fail-closed: " +
        faults.length +
        " changed path(s) could not be safely classified (un-normalizable, disguised, or traversal-bearing) — see fault_paths",
      fault_paths: faults,
      files_total: evaluatorCorpus.length + behavior.length + neutral.length + faults.length,
      evaluator_corpus_files: evaluatorCorpus,
      behavior_files: behavior,
      neutral_files: neutral,
    };
  }

  const mixed = evaluatorCorpus.length > 0 && behavior.length > 0;

  return {
    schema_version: SCHEMA_VERSION,
    decision: mixed ? "reject" : "pass",
    fail_closed: false,
    reason: mixed
      ? "PR mixes evaluator/corpus files with behavior files — split into separate PRs (contracts/11, contracts/04 B17)."
      : "no evaluator/corpus + behavior mixing detected",
    fault_paths: [],
    files_total: evaluatorCorpus.length + behavior.length + neutral.length,
    evaluator_corpus_files: evaluatorCorpus,
    behavior_files: behavior,
    neutral_files: neutral,
  };
}

function isEvaluatorCorpus(p) {
  const r = normalizeOne(p, process.cwd());
  return !!r && r.ok && r.category === "evaluator";
}

function isBehavior(p) {
  const r = normalizeOne(p, process.cwd());
  return !!r && r.ok && r.category === "behavior";
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

function gitDiffNameStatus(baseRef) {
  // --no-renames: git itself splits every rename into a plain delete line
  // + a plain add line, so both the old (sensitive-source) and new paths
  // always reach the classifier without any tuple-parsing on our side.
  return execFileSync("git", ["diff", "--name-status", "--no-renames", baseRef + "...HEAD"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

function linesOf(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.replace(/\s+$/, "").replace(/^[ \t]+(?=\S)/, (m) => (text.indexOf("\t") === -1 ? "" : m)))
    .map((l) => l)
    .filter((l) => l.trim().length > 0 || l.indexOf("\t") !== -1);
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

  // 9. Empty file list passes (POSTURE: empty diff is nothing to separate).
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

  // 16. Unknown, genuinely-neutral paths pass (POSTURE: do not over-reach
  //     and block normal docs/unrelated PRs just because a path is unfamiliar).
  {
    const r = classify(["mystery/payload.bin", "foo/bar.baz"]);
    assert("unknown-but-clean paths -> pass", r.decision === "pass");
  }

  // 17. Mid-path and repeated "." / "//" segments collapse correctly
  //     (not just a leading "./").
  {
    const r1 = classify(["scripts//scenario.js", "SKILL.md"]);
    const r2 = classify(["scripts/./scenario.js", "SKILL.md"]);
    const r3 = classify(["scripts///scenario.js", "SKILL.md"]);
    const r4 = classify(["././scripts/scenario.js", "SKILL.md"]);
    assert("double-slash mid-path collapses -> reject", r1.decision === "reject");
    assert("./ mid-path collapses -> reject", r2.decision === "reject");
    assert("triple-slash mid-path collapses -> reject", r3.decision === "reject");
    assert("repeated leading ./ collapses -> reject", r4.decision === "reject");
  }

  // 18. Any ".." segment fail-closes the WHOLE diff unconditionally, even
  //     when the resolved path alone would not otherwise mix (this is the
  //     "dual-meaning" case: a single dot-dot path with nothing else).
  {
    const r1 = classify(["corpus/../scripts/gate.js"]);
    const r2 = classify(["scenarios/../SKILL.md", "scripts/scenario.js"]);
    const r3 = classify(["../../scripts/scenario.js", "SKILL.md"]);
    const r4 = classify(["./references/../scenarios/x.json"]);
    assert("single dot-dot-traversal path alone -> fail-closed", r1.decision !== "pass" && r1.fail_closed === true);
    assert("dot-dot reclassification -> fail-closed", r2.decision !== "pass");
    assert("double dot-dot prefix -> fail-closed", r3.decision !== "pass" && r3.fail_closed === true);
    assert("single dot-dot dir mid-path, alone -> fail-closed", r4.decision !== "pass" && r4.fail_closed === true);
  }

  // 19. Case-variant sensitive paths are matched case-insensitively (so
  //     they classify correctly and mix, rather than silently passing as
  //     neutral).
  {
    const r1 = classify(["Scripts/Scenario.js", "SKILL.md"]);
    const r2 = classify(["Corpus/a.json", "SKILL.md"]);
    const r3 = classify(["Scenarios/a.json", "SKILL.md"]);
    const r4 = classify(["References/a.md", "scripts/scenario.js"]);
    assert("case-variant scripts/scenario.js -> reject", r1.decision === "reject");
    assert("case-variant corpus/ -> reject", r2.decision === "reject");
    assert("case-variant scenarios/ -> reject", r3.decision === "reject");
    assert("case-variant references/ -> reject", r4.decision === "reject");
  }

  // 20. Trailing slash on an exact sensitive file, or on a bare sensitive
  //     dir, still classifies correctly (directory-form trailing slashes on
  //     genuinely neutral/single-category dirs still pass — no over-reach).
  {
    const r1 = classify(["scripts/scenario.js/", "SKILL.md"]);
    const r2 = classify(["corpus/a.json", "scenarios/"]);
    const r3 = classify(["references/", "scripts/scenario.js"]);
    assert("trailing slash on exact sensitive file -> reject", r1.decision === "reject");
    assert("trailing slash on bare evaluator dir, single-category -> pass", r2.decision === "pass");
    assert("trailing slash on bare behavior dir -> reject (mixes)", r3.decision === "reject");
  }

  // 21. Unicode confusables: a fullwidth solidus or combining/precomposed
  //     accent that disguises a sensitive path under NFC must still be
  //     caught (via NFKC-fold / diacritic-stripping) and fail-closed.
  {
    const r1 = classify(["scripts／scenario.js", "SKILL.md"]);
    const r2 = classify(["scénarios/a.json", "SKILL.md"]);
    const r3 = classify(["scénarios/a.json", "SKILL.md"]);
    assert("fullwidth-solidus disguise -> fail-closed", r1.decision !== "pass");
    assert("combining-mark disguise -> fail-closed", r2.decision !== "pass");
    assert("precomposed-accent disguise -> fail-closed", r3.decision !== "pass");
  }

  // 22. NUL bytes anywhere in a path fail-close unconditionally.
  {
    const r1 = classify(["scripts/scenario.js .md", "SKILL.md"]);
    const r2 = classify(["scenarios/a.json /payload", "SKILL.md"]);
    assert("NUL byte mid/late in path -> fail-closed", r1.decision !== "pass" && r1.fail_closed === true);
    assert("NUL byte early in path -> fail-closed", r2.decision !== "pass" && r2.fail_closed === true);
  }

  // 23. Rename handling: both plain two-line renames and raw
  //     `--name-status` tuples/porcelain rename lines reach the classifier
  //     with BOTH the old (source) and new (destination) path.
  {
    const r1 = classify(["scripts/scenario.js", "scripts/gate.js"]);
    const r2 = classify(["R100\tscripts/scenario.js\tscripts/gate.js"]);
    const r3 = classify(["R050\tscripts/gate.js\tcorpus/gate.json"]);
    const r4 = classify(["R  scripts/gate.js -> corpus/gate.json"]);
    assert("plain rename pair (two lines) -> reject", r1.decision === "reject");
    assert("--name-status R-tuple (tab) old+new both reach classifier -> reject", r2.decision === "reject");
    assert("--name-status R-tuple, other combo -> reject", r3.decision === "reject");
    assert("porcelain 'R  old -> new' rename line parsed -> reject", r4.decision === "reject");
  }

  // 24. An unrecognized tab-bearing line (doesn't match any known git
  //     status/rename encoding) is fail-closed rather than silently
  //     treated as one bogus neutral path.
  {
    const r = classify(["Z999\tnonsense\tformat\textra"]);
    assert("unparseable tab-bearing status line -> fail-closed", r.decision !== "pass" && r.fail_closed === true);
  }

  // 25. Symlink alias onto a sensitive path: a currently-neutral-looking
  //     path that resolves (relative to cwd) through a real symlink onto
  //     corpus/ or references/ is disguised and must fail-closed.
  {
    const os = require("os");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "gs-ci-selftest-sym-"));
    const prevCwd = process.cwd();
    try {
      const corpusDir = path.join(root, "corpus");
      const refsDir = path.join(root, "references");
      fs.mkdirSync(corpusDir);
      fs.mkdirSync(refsDir);
      let corpusLinked = false;
      let refsLinked = false;
      try {
        fs.symlinkSync(corpusDir, path.join(root, "eval-alias"), "junction");
        corpusLinked = true;
      } catch (e) {
        process.stderr.write("  SKIP  symlink-alias-to-corpus -- platform denied symlink/junction: " + (e.code || e.message) + "\n");
      }
      try {
        fs.symlinkSync(refsDir, path.join(root, "refs-link"), "junction");
        refsLinked = true;
      } catch (e) {
        process.stderr.write("  SKIP  symlink-alias-to-references -- platform denied symlink/junction: " + (e.code || e.message) + "\n");
      }
      process.chdir(root);
      if (corpusLinked) {
        const r = classify(["eval-alias/a.json", "SKILL.md"]);
        assert("symlink alias to corpus/ -> fail-closed", r.decision !== "pass");
      }
      if (refsLinked) {
        const r = classify(["refs-link/a.md", "scripts/scenario.js"]);
        assert("symlink alias to references/ -> fail-closed", r.decision !== "pass");
      }
    } finally {
      process.chdir(prevCwd);
      try {
        fs.rmSync(root, { recursive: true, force: true });
      } catch (e) {}
    }
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
    "Usage: git diff --name-status --no-renames <base> <head> | node scripts/ci-check-pr-separation.js\n" +
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
      raw = gitDiffNameStatus(args[baseIdx + 1]);
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
    process.stderr.write(
      "\nci-check-pr-separation: REJECTED" + (result.fail_closed ? " (fail-closed)" : "") + " — " + result.reason + "\n"
    );
    if (result.fail_closed) {
      process.stderr.write("  fault paths: " + JSON.stringify(result.fault_paths) + "\n");
    } else {
      process.stderr.write("  evaluator/corpus files: " + JSON.stringify(result.evaluator_corpus_files) + "\n");
      process.stderr.write("  behavior files:         " + JSON.stringify(result.behavior_files) + "\n");
      process.stderr.write("  Split this PR: one PR for the evaluator/corpus change, a separate PR for the behavior change.\n");
    }
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
