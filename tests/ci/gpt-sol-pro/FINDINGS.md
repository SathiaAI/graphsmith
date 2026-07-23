# GPT-sol-pro CI Test-Amend Findings

Scope: `.plans/tasks/A-ci-test-amend.md`, limited to `tests/ci/gpt-sol-pro/`. The harness uses OS temp directories, zero-dependency CommonJS, synthetic changed-file lists, parsed JSON/YAML source, and child-process exit codes. It does not use Git, packages, a network, or the GitHub API.

## Executive Verdict

No real un-fixed CI defect remains in this lane. The amended suite exits 0 with **47 PASS, 0 FAIL, 1 justified SKIP**.

## Dispositions

### F1: Trusted-base guard execution — FIXED

The PR-separation job no longer executes the guard from the PR workspace. The audit confirms the workflow extracts and runs the checker from the trusted base revision.

### F2: Ambiguous classifier input — FIXED / TEST-AMENDED

All real disguised-sensitive evasions remain strict and pass fail-closed checks: repeated `./`, `..` reclassification, dual-meaning traversal, trailing separator, case variant, fullwidth separator, non-NFC combining path, NUL-bearing path, rename status tuple, and symlink alias to a sensitive root.

The genuinely neutral unknown-file case is **TEST-AMENDED** to assert PASS. A neutral-only change has no evaluator/behavior categories to separate.

### F3: Empty diff — TEST-AMENDED

The empty-diff case now asserts PASS. An empty changed-file set contains no evaluator/behavior mix for the separation guard to reject.

### F4: Rename source classification — FIXED

The workflow's diff plumbing preserves both sides of a rename by using base-trusted `git diff --name-status --no-renames`. Explicit old/new sensitive paths reject, and an unparsed rename-status tuple fails closed.

### F5: Evidence-only review harnesses — FIXED / TEST-AMENDED

The stale file-existence assertion was replaced with the adjudicated B3 guarantee. The test parses `ci-suite-manifest.json` and the suite runner embedded in `.github/workflows/ci.yml`, then executes that runner against temp fixtures. It verifies from process exit codes that:

- All four one-shot review harness families are explicitly covered by `evidence_only` prefixes.
- An evidence-only suite exiting non-zero does not flip the CI gate.
- A `gating_suites` suite exiting non-zero flips the CI gate.
- A suite absent from both manifest lists is warned and treated as gating.

The warning assertion uses a preloaded probe that records `console.warn` calls as JSON; it does not infer a verdict from log text.

### F6: Graphlint in the 3-OS Phase A matrix — DEFERRED(phase)

Graphlint is an adjudicated Phase B component. It was removed from the expected Phase A component list and is reported as `SKIPPED` with reason `phase-b-component`. Graphlint remains self-tested and dogfooded in the existing two-OS `verify` job and can join the Phase A list when onboarded.

### F7: Publish concurrency — FIXED

`publish.yml` now has top-level concurrency with `cancel-in-progress: true`.

### F8: GitLab omission declarations — FIXED

The GitLab template audit finds no silently omitted GitHub checks and confirms the template remains explicitly unwired.

## Verification

Command: `node tests/ci/gpt-sol-pro/run-tests.js`

Result: `SUMMARY\tPASS=47\tFAIL=0\tSKIPPED=1`

The single skip is justified as `phase-b-component`; every other case passes. No case reports a real un-fixed CI defect.

## Operational Limits

This local audit cannot verify branch-protection required-check configuration, fork approval policy, token issuance, action provenance, runner-image behavior, cancellation timing, or repository administration settings. Those controls require GitHub-side evidence and are not harness failures.
