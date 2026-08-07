#!/usr/bin/env node
"use strict";

/* tests/postmortem/codex-command-output-failed/run-tests.js -- ground-truth
 * regression coverage for scripts/postmortem-codex.js#commandOutputFailed().
 *
 * WHY THIS FILE EXISTS: postmortem-codex.js's own header comment flags this
 * function as "ADAPTED from mindwalk's internal/adapter/codex/adapter.go ...
 * neither this build nor the design doc's research verified it against a
 * REAL Codex session log". Two independent adversarial reviewers (Grok and
 * Qwen3-Coder-Plus, Lane E/F review 2026-08-06) both flagged this
 * unverified-against-real-output status as worth closing before this ships
 * more broadly.
 *
 * HONEST SCOPE: no live ~/.codex/sessions/*.jsonl file exists anywhere in
 * this build environment to test against -- this is NOT a literal live
 * session capture. What IS available, and what this suite actually checks,
 * is mindwalk's OWN Go test corpus for the exact function this was ported
 * from: /internal/adapter/codex/adapter_test.go#TestCommandOutputFailedVariants
 * (MIT, cosmtrek/mindwalk). That corpus is the closest available ground
 * truth -- mindwalk's authors built it against real Codex exec_command/
 * apply_patch output shapes, not the JS port's own logic, so a bug specific
 * to the JS port (as opposed to a shared misunderstanding of Codex's output
 * format) would show up here. Every case below is transcribed verbatim from
 * that Go test's `tests` table (lines 409-429 as of this build), output
 * strings and expected booleans unchanged. All 15/15 pass against the JS
 * port as of this commit -- zero discrepancies found, so this is a
 * confirmation, not a fix. If a real Codex session log ever becomes
 * available, it should still be spot-checked against this function directly
 * (this suite doesn't replace that, it only closes the "never checked
 * against ANY external reference" gap).
 */

const { commandOutputFailed } = require("../../../scripts/postmortem-codex.js");

let passed = 0;
let failed = 0;

function report(name, ok, detail) {
  if (ok) {
    console.log(`PASS: ${name}`);
    passed++;
  } else {
    console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`);
    failed++;
  }
}

// Transcribed verbatim from mindwalk's adapter_test.go#TestCommandOutputFailedVariants.
const MINDWALK_CASES = [
  { output: "Process exited with code 1", want: true, note: "bare exit-code trailer, nonzero" },
  { output: "Exit code: 2", want: true, note: "bare exit-code trailer, alternate phrasing" },
  { output: '{"output":"ok","metadata":{"exit_code":0}}', want: false, note: "JSON envelope, metadata.exit_code 0" },
  { output: '{"output":"failed","metadata":{"exit_code":1}}', want: true, note: "JSON envelope, metadata.exit_code nonzero" },
  { output: '{"output":"failed","exit_code":3}', want: true, note: "JSON envelope, top-level exit_code nonzero" },
  { output: '{"output":"Exit code: 1","metadata":{"exit_code":0}}', want: false, note: "metadata.exit_code 0 wins even though the embedded text looks like a failing trailer" },
  { output: "Script completed\nWall time 0.1 seconds\nOutput:\nExit code: 1", want: false, note: "'Script completed' status line short-circuits before the trailing exit-code text is ever reached" },
  { output: "Script running with cell ID 28\nExit code: 1", want: false, note: "'Script running' status line short-circuits the same way" },
  { output: "Script failed\nExit code: 0", want: true, note: "'Script failed' status line wins even though the trailer claims exit code 0" },
  { output: "plain output", want: false, note: "no envelope, no status line, no exit-code trailer, no abort marker -> false" },
  { output: '{"message":"Wait timed out after 20000ms","timed_out":true}', want: true, note: "JSON envelope, timed_out true" },
  { output: '{"message":"still running","timed_out":false}', want: false, note: "JSON envelope, timed_out false -- falls through the rest of the checks and still resolves false" },
  { output: "apply_patch verification failed: Failed to find expected lines in a.go", want: true, note: "apply_patch verification-failed prefix" },
  { output: "Wall time: 8.9 seconds\naborted by user", want: true, note: "'aborted by user' as a genuine status line" },
  { output: "Wall time: 8.9 seconds\nOutput:\naborted by user", want: false, note: "'aborted by user' appearing INSIDE captured stdout (after the Output: marker) must not trigger a false abort" },
];

function groupMindwalkCorpus() {
  console.log("\n=== GROUP 1: mindwalk's own TestCommandOutputFailedVariants corpus, transcribed verbatim ===");
  for (const { output, want, note } of MINDWALK_CASES) {
    const got = commandOutputFailed(output);
    report(`1.x commandOutputFailed(${JSON.stringify(output)}) === ${want} (${note})`, got === want, `got ${got}`);
  }
}

function main() {
  groupMindwalkCorpus();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
