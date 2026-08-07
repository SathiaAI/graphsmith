#!/usr/bin/env node
"use strict";

/* tests/postmortem/cr18-out-resolve/run-tests.js -- CR-18 follow-up regression
 * coverage for `graphsmith postmortem --out`'s path.resolve() hardening
 * (CodeRabbit PR #24, ast-grep detect-non-literal-fs-filename / CWE-22 note
 * nested inside graphsmith-cli.js:89's "durable workflow manager" comment).
 *
 * This is a standalone sibling of tests/postmortem/run-tests.js rather than
 * an addition to that file. It exists only because the CR-18 assertions
 * could not be reliably appended to the 80KB+ run-tests.js file through the
 * available push tooling in the authoring session (repeated content
 * transmission failures, each caught by mandatory post-push verification
 * before landing on the branch -- see the branch's commit history around
 * 2026-08-06/07 for the corrected-and-reverted attempts). This file follows
 * the exact same report()/PASS-FAIL-SKIP/exit-1-on-failure contract as its
 * sibling and is discovered the same way (scripts/ci-run-suites.js's literal
 * "run-tests.js" filename walk; tests/postmortem/ is not yet listed in
 * ci-suite-manifest.json either, so both suites rely on the same fail-safe
 * gating behavior -- no new inconsistency introduced).
 *
 * --out is now resolved via path.resolve() before use -- both the canonical
 * static-analysis mitigation for this CWE and a real usability fix, since it
 * makes the write destination unambiguous regardless of the CLI's cwd. A
 * relative --out value must resolve against the process's actual cwd (not
 * get written somewhere unexpected), and ".." segments must collapse the way
 * path.resolve() collapses them.
 */

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const FIXTURES = path.join(__dirname, "..", "fixtures");
const CLI = path.join(REPO, "scripts", "graphsmith-cli.js");

let passed = 0;
let failed = 0;
let skipped = 0;

function report(name, ok, detail) {
  if (ok === true) {
    console.log(`PASS: ${name}`);
    passed++;
  } else if (ok === false) {
    console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`);
    failed++;
  } else {
    console.log(`UNAVAILABLE: ${name}${detail ? " -- " + detail : ""}`);
    skipped++;
  }
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(require("os").tmpdir(), `gs-postmortem-${label}-`));
}

function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best-effort */
  }
}

function groupCr18OutResolve() {
  console.log("\n=== GROUP 18: CR-18 --out path.resolve() hardening ===");

  const ccPath = path.join(FIXTURES, "claude-code-normal.jsonl");
  const dir = tmpDir("cr18-out-resolve");
  try {
    const relOut = cp.spawnSync(process.execPath, [CLI, "postmortem", ccPath, "--out", "report.md"], { encoding: "utf8", cwd: dir });
    const expectedPath = path.join(dir, "report.md");
    report("18.1 CR-18: relative --out path is written relative to the CLI's cwd", relOut.status === 0 && fs.existsSync(expectedPath));
    report(
      "18.2 CR-18: the confirmation message on stderr reports the resolved absolute path, not the raw relative string",
      new RegExp(expectedPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(relOut.stderr),
      relOut.stderr
    );

    const subDir = path.join(dir, "sub");
    fs.mkdirSync(subDir);
    const upOut = cp.spawnSync(process.execPath, [CLI, "postmortem", ccPath, "--out", "../escaped.md"], { encoding: "utf8", cwd: subDir });
    const expectedUpPath = path.join(dir, "escaped.md");
    report("18.3 CR-18: '..' segments in --out collapse via path.resolve (no double-relative artifacts)", upOut.status === 0 && fs.existsSync(expectedUpPath));
  } finally {
    cleanup(dir);
  }
}

function main() {
  groupCr18OutResolve();

  console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped/unavailable`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
