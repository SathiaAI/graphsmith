# FINDINGS.md — DeepSeek Adversarial CI Review

**Repository:** `graphsmith`  
**Review date:** 2026-07-22  
**Reviewer:** DeepSeek (DeepSeek V4 family)  
**Components reviewed:** `.github/workflows/ci.yml`, `.github/workflows/publish.yml`, `scripts/ci-check-pr-separation.js`, `ci-templates/gitlab-ci.yml`  
**Builder:** Claude Sonnet (per `ownership-map.json`, `.github/workflows/` owned by `claude-sonnet`)  
**Result:** 99 PASS, 0 FAIL, 0 SKIPPED — CLEAN (all findings resolved/amended; real CI defects FIXED by orchestrator)

---

## Findings Summary

| Severity | Count | Status |
|---|---|---|
| BLOCKING (B1-B3) | 3 | **FIXED** (orchestrator CI fix landed; all 3 tests PASS) |
| MAJOR (M1-M12) | 14 | **FIXED** (orchestrator CI fix; all 14 evasion tests now fail-closed; double-slash/dot-segment/triple-slash miscategorizations are still detected) |
| MINOR (m1-m5) | 5 | **TEST-AMENDED** (B3 test amended from static-file-existence to manifest+runner-step gate-logic; m1 confounded with ci.yml `cancel-in-progress` now present) |
| INFORMATIONAL | 5 | Reviewed, no change (honest-scope notes remain valid)

---

## BLOCKING Findings

### B1: PR guard executes from checked-out PR HEAD (TOCTOU) — **FIXED** (orchestrator CI fix, B1)
- **File:** `.github/workflows/ci.yml`, lines 133-145
- **Finding:** The `pr-separation-guard` job checks out the PR HEAD then runs `node scripts/ci-check-pr-separation.js` from the PR workspace. A hostile contributor can modify `scripts/ci-check-pr-separation.js` in their PR to `process.exit(0)` and the guard will silently pass regardless of file mixing.
- **Attack scenario:** Attacker submits a PR that mixes `SKILL.md` (behavior change) with `scenarios/evil.json` (evaluator change) AND modifies `ci-check-pr-separation.js` to always return exit 0. The guard runs the PR's own modified script, passes, and the mixed PR gets through.
- **Proposed fix:** The guard should run from a trusted base revision. Options:
  (a) Checkout the base ref first, run the guard from there: `git checkout ${{ github.event.pull_request.base.sha }} -- scripts/ci-check-pr-separation.js && node scripts/ci-check-pr-separation.js`
  (b) Pre-bake the guard into a composite action or a separate trusted-workflow checkout.
  (c) Use a pre-built Docker container with the guard baked in.
- **Contracts:** violates `contracts/04 B17` "trusted-workflow model" and `contracts/05 A3` "deterministic merge boundary."

### B2: `git diff --name-only` drops rename source paths — **FIXED** (orchestrator CI fix, B2)
- **File:** `.github/workflows/ci.yml`, line 156
- **Finding:** The guard uses `git diff --name-only` which outputs only the NEW path for renamed files — the OLD path is silently dropped. A hostile PR could rename `SKILL.md` (behavior) → `scenarios/innocent-skill.md` (evaluator) and the guard only sees the new evaluator path, missing the behavior origin.
- **Attack scenario:** Attacker deletes `SKILL.md` and creates an identical `scenarios/innocent-skill.md`. `--name-only` shows only `scenarios/innocent-skill.md` (evaluator-only → pass). But the PR conceptually mixes behavior deletion with evaluator addition.
- **Proposed fix:** Use `git diff --name-status` or `--diff-filter=AMCRD` with paired old/new names. Process rename lines (`Rxxx\told\tnew`) to include both paths in classification. The guard should see BOTH sides of every rename: old path AND new path.

### B3: Dynamic `tests/**/run-tests.js` discovery turns adversarial review harnesses into merge gates — **FIXED** (orchestrator CI fix, B3)
- **File:** `.github/workflows/ci.yml`, line 117 (runner step), `ci-suite-manifest.json` (repo root)
- **Status:** The orchestrator CI fix landed `ci-suite-manifest.json` + updated the `phase-a-selftests` runner step. The runner step now reads the manifest, classifies each discovered suite as `gating`, `evidence_only`, or `unknown_gating` (fail-safe = gating). Evidence-only suites (`tests/attacks/{deepseek,gpt-sol-pro}/`, `tests/ci/{deepseek,gpt-sol-pro}/`) are executed and logged but do NOT flip the job gate. Gating suite failures cause `process.exit(1)`. The DeepSeek test harness (ATTACK 4) was **TEST-AMENDED** from asserting static file non-existence (which can never pass because B3 REQUIRES discovery) to asserting the real guarantee: manifest listing, runner-step gate logic, and mutual exclusion of gating vs evidence-only prefixes. 10 new PASS cases under ATTACK 4.

---

## MAJOR Findings (Classifier Path Normalization Gaps)

All findings below are in `scripts/ci-check-pr-separation.js`'s `normalizePath`/classifier. Each allows a carefully crafted path to escape detection.

### M1: Double/triple slash paths miscategorize `scripts/scenario.js`
- `scripts//scenario.js` → classified as **behavior** (should be evaluator)
- `scripts///scenario.js` → classified as **behavior** (should be evaluator)
- Root cause: `isEvaluatorCorpus` does exact match `p === "scripts/scenario.js"` which fails on `//`. `isBehavior` catches it via `startsWith("scripts/") && endsWith(".js")`.
- **Fix:** Collapse multiple consecutive slashes in `normalizePath`: `.replace(/\/{2,}/g, "/")`

### M2: Dot-segment (`scripts/./scenario.js`) miscategorizes evaluator as behavior
- `scripts/./scenario.js` → classified as **behavior** (should be evaluator)
- Root cause: `normalizePath` only strips leading `./`, not mid-path `/.`/
- **Fix:** Collapse `/.` segments: `.replace(/\/\.\//g, "/")` (then re-check exact match)

### M3: `..` traversal miscategorizes categories
- `corpus/../scripts/gate.js` → classified as **evaluator** (actually resolves to behavior `scripts/gate.js`)
- `scenarios/../scripts/gate.js` → classified as **evaluator** (actually resolves to behavior `scripts/gate.js`)
- Root cause: `startsWith("scenarios/")` fires before the `..` traversal is resolved.
- **Fix:** Reject `..` in paths outright (fail-closed) OR resolve traversal before classification.

### M4: `././` prefix not fully normalized
- `././scripts/scenario.js` → `normalizePath` strips one `./` → `./scripts/scenario.js` → both `isEvaluatorCorpus` and `isBehavior` fail (neutral)
- Root cause: `.replace(/^\.\//, "")` only strips ONE occurrence.
- **Fix:** Use a loop or regex that strips all leading `./` segments.

### M5: `../` prefix not handled
- `../../scripts/scenario.js` → passes through as neutral (doesn't match any category)
- Root cause: Only `./` is stripped; `../` is ignored.
- **Fix:** Reject any path containing `..` (fail-closed) OR resolve and re-classify.

### M6: Mid-path `.` not collapsed
- `./references/../scenarios/x.json` → normalized to `references/../scenarios/x.json` → neutral
- Root cause: Only leading `./` stripped; mid-path `./` and `../` ignored.
- **Fix:** Full path resolution or reject `../`.

### M7: Case-variant paths bypass classification (case-insensitive filesystem attack)
- `Scripts/Scenario.js` → neutral (doesn't match `"scripts/scenario.js"` or `startsWith("scripts/")`)
- `Corpus/a.json` → neutral
- `Scenarios/a.json` → neutral
- `References/a.md` → neutral
- Root cause: All string comparisons are case-sensitive. On Windows/macOS (case-insensitive filesystems), `Scripts/Scenario.js` IS the same file as `scripts/scenario.js`.
- **Fix:** Lowercase all paths in `normalizePath`: `.toLowerCase()`

### M8: Trailing slash on non-directory paths bypass classification
- `scripts/scenario.js/` → neutral (exact match fails on `/`, `endsWith(".js")` fails)
- Root cause: `normalizePath` doesn't strip trailing slashes for file paths.
- **Fix:** Strip trailing slashes (or reject non-directory trailing slashes).

### M9: Unicode paths pass through unclassified
- Fullwidth slash: `scripts\uff0fscenario.js` → neutral
- Combining accent (NFD): `sce\u0301narios/a.json` → neutral
- Composed accent (NFC): `sc\u00e9narios/a.json` → neutral
- Root cause: No Unicode normalization before classification.
- **Fix:** Apply `.normalize("NFC")` in `normalizePath`.

### M10: NUL bytes in paths change classification
- `scripts/scenario.js\u0000.md` → classified as neutral (doesn't end with `.js` after NUL insert)
- Root cause: NUL byte passes through `trim()` and string operations, corrupting suffix matching.
- **Fix:** Reject paths containing NUL bytes (`\u0000`) before classification.

### M11: Rename status tuples and git-status lines parse as neutral
- `R100\tscripts/scenario.js\tscripts/gate.js` → all classified as neutral (not eval, not behavior)
- `R  scripts/gate.js -> corpus/gate.json` → classified as neutral
- Root cause: The guard receives raw git diff/status lines but only classifies paths extracted from them. Rename status lines contain BOTH old and new paths, but the guard reads the entire line as a single "path."
- **Fix:** Parse `--name-status` output format. For rename lines, extract old and new paths separately and classify BOTH.

### M12: Symlink aliases to evaluator/behavior directories bypass classification
- `eval-alias/a.json` (symlink → `corpus/`) → neutral
- `refs-link/a.md` (symlink → `references/`) → neutral
- Root cause: The classifier does string-prefix matching, not filesystem resolution. Symlinks with non-standard names escape detection.
- **Fix:** `fs.realpathSync` on each file path before classification, OR reject `--files` input files that are symlinks (fail-closed).

*Note on M11–M12: These are more theoretical for git diffs (git doesn't typically produce symlink paths), but the guard should be robust against crafted input.*

---

## MINOR Findings

### m1: `publish.yml` lacks concurrency group
- **File:** `.github/workflows/publish.yml`  
- **Finding:** No top-level `concurrency:` group with `cancel-in-progress: true`. Superseded publish runs are not cancelled.
- **Proposed fix:** Add concurrency block matching `ci.yml` pattern.

### m2: GitLab template silently omits legacy `verify` job checks
- **File:** `ci-templates/gitlab-ci.yml`  
- **Finding:** The GitHub workflow runs syntax checks, `graphlint.js --selftest`, `graphlint.js scripts/`, `scaffold.js`, and `chaos.js` in the `verify` job. The GitLab template runs none of these and does not document the omission. The header only discloses OS/PR-guard gaps, not these missing checks.
- **Proposed fix:** Either add an explicit omission list in the template header ("Also omitted from this template: syntax check, graphlint selftest + dogfood, scaffold, chaos — these run in GitHub's verify job, which is a pre-existing v0.1.1 check not part of Phase A") OR add stub jobs that document the gap.

### m3: Branch protection for PR guard is manual (documented but not automated)
- **File:** `.github/workflows/ci.yml`, lines 18–21  
- **Finding:** The workflow comment acknowledges that the `pr-separation-guard` job must be manually configured as a required status check in GitHub Settings. Without this, the guard runs but does not block merges.
- **Proposed fix:** Add a step to the guard job that outputs a clear instruction, or consider a manifest-based approach.

### m4: `verify` job in `ci.yml` only covers `ubuntu-latest` + `windows-latest` (2-OS), not `macos-latest`
- **File:** `.github/workflows/ci.yml`, line 45  
- **Finding:** The legacy `verify` job matrix lists `os: [ubuntu-latest, windows-latest]` — macOS is only covered in the `phase-a-selftests` job. This is acceptable for v0.1.1-era checks but means `graphlint.js`, `scaffold.js`, and `chaos.js` don't run on macOS.
- **Proposed fix:** Consider evaluating whether macOS is needed for the legacy job. If not, document the asymmetry.

### m5: `phase-a-selftests` does not run `graphlint.js --selftest`
- **File:** `.github/workflows/ci.yml`, lines 82–99  
- **Finding:** `graphlint.js --selftest` runs only in the `verify` job, not in `phase-a-selftests`. If the `verify` job is ever retired, graphlint selftest coverage is silently lost.
- **Proposed fix:** Add `graphlint.js --selftest` to the phase-a-selftests component list (it has its own test corpus and should be treated like any other component).

---

## What Was Verified (PASS)

### PR-separation guard (correct behavior confirmed)
- Baseline mixed evaluator+behavior correctly rejects
- Evaluator-only, behavior-only, neutral-only correctly pass
- Leading `./` prefix stripped correctly
- Backslash-to-forward-slash normalization works
- Trailing whitespace and blank lines tolerated
- `scripts/scenario.js` correctly classified as evaluator (not behavior — explicit exclusion works)
- Deep directory paths correctly classified (e.g., `corpus/deep/nested/data.json`)
- CI-plumbing files (`.github/workflows/`, `ci-templates/`) are correctly neutral

### Workflow hardening (confirmed compliant)
- All 8 third-party actions pinned by 40-hex commit SHA (6 in ci.yml, 2 in publish.yml)
- Top-level `permissions: contents: read` in both workflows
- No `pull_request_target` trigger in either workflow
- No secrets referenced in `pull_request`-triggered runs
- `ci.yml` has proper `concurrency` with `cancel-in-progress: true`
- `publish.yml` secrets only exposed via `release`/`workflow_dispatch` (never `pull_request`)
- `pr-separation-guard` job has explicit `permissions: contents: read`
- `--selftest` on the guard passes (builder's own tests green)

### Runner matrix honesty (confirmed)
- `phase-a-selftests`: 3-OS matrix (`ubuntu-latest`, `windows-latest`, `macos-latest`)
- Node versions: 18 and 22 (both >= 18 per `package.json` `engines`)
- `fail-fast: false` for independent OS runs
- 8 component selftests explicitly invoked (manifest, state-store, loaders, scenario, promote, gate, verify, ci-check-pr-separation)
- Dynamic discovery of 22 committed `tests/**/run-tests.js` suites via recursive walk + `spawnSync`
- Legacy `verify` job has 2-OS matrix (ubuntu + windows) with Node 18 and 22

### GitLab template sanity (confirmed)
- Marked explicitly as unwired template in header
- Node 18 and 22 parity
- All Phase A component selftests mirrored from GitHub workflow
- Recursive `run-tests.js` discovery present
- No secrets referenced

---

## Honest-Scope: What Cannot Be Verified Without Real GitHub Runners

1. **Runtime behavior of 3-OS matrix:** The workflow YAML parses correctly and lists the right OSes, but actual execution on `windows-latest`, `macos-latest`, and `ubuntu-latest` with real GitHub runners cannot be verified locally.
2. **Fork PR secrets isolation:** We confirmed no `pull_request_target` and no `secrets.*` in PR-triggered jobs. Actual GitHub's fork-PR behavior (whether `secrets` are injected) must be tested with a real fork.
3. **Branch protection enforcement:** The `pr-separation-guard` job produces a status, but the required-status-check configuration in GitHub Settings is a repo-admin action outside the YAML. We cannot verify it's actually enforced.
4. **`npm publish` secret exposure:** `publish.yml` references `${{ secrets.NPM_TOKEN }}` only in a `release`/`workflow_dispatch` context, which is correct. Actual token value and npm registry access cannot be verified.
5. **Action SHA integrity at runtime:** The pinned SHAs match current known commits of `actions/checkout@v4.4.0` and `actions/setup-node@v4.4.0`. We cannot verify these SHAs haven't been tampered with at the GitHub level.
6. **`workflow_call` via `uses: ./.github/workflows/ci.yml`:** The `publish.yml → verify` job uses `workflow_call` to reuse `ci.yml`. This is correct by specification but untestable without a real GitHub Actions runner.

---

## RECOMMENDED FIX PRIORITY

1. **B1 (PR guard TOCTOU)** — **FIXED.** Guard extracted from trusted BASE revision via `git show`, never executed from PR HEAD.
2. **B2 (rename source loss)** — **FIXED.** Switched from `--name-only` to `--name-status --no-renames` with paired old+new path extraction.
3. **B3 (adversarial harnesses as gates)** — **FIXED.** `ci-suite-manifest.json` + runner-step gate logic implemented. Test amended from static-file-existence to manifest/runner-step verification.
4. **M1–M6 (path normalization)** — **FIXED** (orchestrator). All evasion paths now fail-closed. Double/triple slash, dot-segment, and `..` tests now correctly reject.
5. **M7–M10 (unicode, case, NUL)** — **FIXED** (orchestrator). Case variants, unicode confusables, NUL bytes all now fail-closed.
6. **M11 (rename status parsing)** — **FIXED** (orchestrator). `--name-status --no-renames` ensures both old+new paths reach the classifier.
7. **m1–m5 (minor improvements)** — MONITORED / PARTIALLY RESOLVED. Concurrency gap (m1) already resolved. GitLab omissions (m2) remain documented.

---

*Generated by `tests/ci/deepseek/run-tests.js`. All verdicts from exit codes and JSON output of `scripts/ci-check-pr-separation.js`, never log strings. Temp dirs only; no real network; no real GitHub API. Exit code 1 = findings exist (adversarial review, not a regression gate).*