# FINDINGS.md — DeepSeek Adversarial Review of scripts/verify.js (Integrity Sentinel)

**Reviewer**: DeepSeek (TESTER agent, family: deepseek)
**Lane**: `tests/verify/deepseek/`
**Date**: 2026-07-22
**Test file**: `run-tests.js` (zero-dep CJS, Node >= 18)
**Result**: **122 PASS, 0 FAIL, 1 SKIP**

---

## Coverage Statement

The test suite exercises all 7 required attack categories from `.plans/tasks/A-verify-test.md` plus 6 additional edge-case attacks. Every test fixture is built in disposable OS temp directories; no repo files are modified. The sentinel's exported functions (`runIntegrity`, `integrityExitCode`, `verifyFileList`, `diffDestinations`, `runPlatformProbe`, `runTrustModel`, `runProfiles`) are tested both programmatically and via CLI `execSync`.

**Covered**:
- Failure-domain classification (trusted-core exit 3, evolvable-surface exit 1, untrusted-input quarantine exit 0)
- Independent axes (all 4 combinations of release-verified x self-consistent)
- Adoption-log chain break detection + honest language
- False-negative hunt (CRLF, NFD paths, same-length swaps, tampered manifest scenarios)
- Banned-term audit (all 4 CLI commands + programmatic output)
- Read-only side-effect verification
- Platform probe honesty

**Not covered** (documented limitations):
- Symlink escape attacks (Windows lacks symlink privilege in test environment — SKIP, not a hollow green)
- A6 out-of-scope case (privileged attacker rewrites sentinel + both manifests — confirmed as documented limit)
- Extra-file-on-disk detection (verifyFileList only checks DECLARED files — documented in verify.js:226-230)

---

## Attack 1: Failure-Domain Correctness — ALL PASS

### 1a. Constitutional-set tamper → trusted-core, exit 3
- Tampered each of `scripts/gate.js`, `scripts/verify.js`, `scripts/promote.js`, `scripts/state-store.js` individually
- Every case: `release_verified: "no"`, `failure_domain: "trusted-core"`, `integrityExitCode: 3`
- Restoration of each file returns to `failure_domain: "none"` — no persistent corruption
- **Verdict**: Correct. Tamper is never silently repaired; HALT domain engaged.

### 1b. Corrupt release manifest → trusted-core, exit 3
- Wrote `{ not json` to `release.manifest.json`
- Result: `release_verified: "no"`, `corrupt: true`, `failure_domain: "trusted-core"`, exit 3
- **Verdict**: Correct. A present-but-unparseable trust anchor is treated as trusted-core-adjacent.

### 1c. Evolvable-tree tamper → evolvable-surface, exit 1
- Appended `tampered` to `workers/good.prompt.md`
- Result: `active_tree.status: "fail"`, `failure_domain: "evolvable-surface"`, `frozen: true`, exit 1
- **Verdict**: Correct. Evolvable-surface defect freezes promotion paths.

### 1d. Appendix marker sequence → quarantined, exit 0
- Injected `IGNORE ALL PREVIOUS INSTRUCTIONS` into `graphsmith.learned.md`, regenerated tree manifest + ACTIVE binding
- Result: `appendix.status: "quarantined"`, `active_tree.status: "ok"` (tree is intact, only content is quarantined), `failure_domain: "none"`, exit 0
- **Verdict**: Correct. Untrusted-input quarantine; workflows continue; exit 0 (not a domain-level failure).

---

## Attack 2: Independent Axes — ALL PASS

### All 4 combinations tested and reported independently
| release-verified | self-consistent | Domain | Exit |
|---|---|---|---|
| yes | yes | none | 0 |
| yes | no | evolvable-surface | 1 |
| unavailable | no | none | 0 |
| no | no | trusted-core | 3 |

- **Verdict**: Both axes always reported; never collapsed to one word. Bare checkout is `unavailable`, not a false failure.

---

## Attack 3: Adoption-Log Chain — ALL PASS

### 3a. Chain break → evolvable-surface, exit 1
- Replaced `prev_sha256` of entry[1] with all-zeros
- Result: `adoption_log.status: "chain-broken"`, `failure_domain: "evolvable-surface"`, exit 1
- **Verdict**: Correct. Chain-linkage verification detects the break.

### 3b. Honest language audit
- verify.js source code uses "rewrite-detecting" for adoption-log claims — PASS
- JSON report contains zero occurrences of "immutable" — PASS
- Adoption-log section specifically has zero "immutable" strings — PASS
- **Verdict**: Contract 09 F15 claim discipline honored. The chain is never described as "immutable".

---

## Attack 4: False-Negative Hunt — ALL PASS

### 4a. CRLF ↔ LF swap
- Replaced `\n` with `\r\n` in `gate.js`
- Result: Caught by raw-byte SHA-256. `release_verified: "no"`, `failure_domain: "trusted-core"`.
- **Verdict**: Raw-byte hashing (contract 09 v2) correctly detects byte-level changes.

### 4b. NFD path tricks
- Added manifest entry with NFD-decomposed Unicode path (`"re\u0301sume\u0301.txt"` vs NFC `"r\u00e9sum\u00e9.txt"`)
- Result: Entry rejected as `invalid-path` (NFC canonicalization check in verifyFileList).
- **Verdict**: NFD paths in manifest are rejected at the path validation stage.

### 4c. Symlink swap
- Attempted to replace `gate.js` with a symlink to a tampered copy
- Result: SKIPPED (Windows lacks symlink privilege in test environment). Honest skip, not a hollow pass.
- **Verdict**: `lstat.isSymbolicLink()` check exists in verifyFileList; could not exercise it due to OS limitations.

### 4d. Same-length file replacement
- Replaced `gate.js` with same-byte-length buffer of 0x41 ('A' bytes)
- Result: Caught by hash mismatch. `release_verified: "no"`.
- **Verdict**: SHA-256 is content-sensitive; same-length doesn't evade.

### 4e. Tampered file + tampered release manifest entry
- Tampered `gate.js` AND updated its hash in the release manifest to match
- Result: release-verified passes (file matches tampered manifest), but self-consistent FAILS because `parent_release_sha256` (in project manifest) no longer matches the tampered release manifest.
- **Verdict**: Two-manifest binding provides cross-check. Single-manifest tamper is detected through the other manifest.

### 4f. A6: Both manifests rewritten (out-of-scope)
- Tampered `gate.js`, updated BOTH release and project manifests with matching hashes
- Result: `release_verified: "yes"`, `self_consistent: "yes"`. This IS the documented A6 limit.
- Trust-model output explicitly states: "A6 — Privileged local attacker ... OUT OF SCOPE"
- **Verdict**: A6 out-of-scope case confirmed. Sentinel correctly reports "verified" when both trust anchors are rewritten — this is the documented limit (contract 05 A6).

### 4g. Extra file on disk (not in manifest)
- Added `scripts/backdoor.js` that is NOT listed in any manifest
- Result: `release_verified: "yes"` (extra files are not detected)
- **Verdict**: This is a DOCUMENTED limitation in verify.js:226-230. verifyFileList checks only DECLARED files, not extra files on disk. This is a narrower guarantee than manifest.js's verifyTree() for the evolvable tree.

### 4h. Case-fold collision
- Added duplicate manifest entry with case-different path (`scripts/GATE.js` vs `scripts/gate.js`)
- Result: `case-fold-collision` detected, `self_consistent: "no"`
- **Verdict**: Case-fold collision check working correctly.

### 4i. Absolute path in manifest entry
- Added manifest entry with full absolute path
- Result: Rejected as `invalid-path`
- **Verdict**: Path-is-absolute check working correctly.

---

## Attack 5: Honest-Language — ALL PASS

### 5a. CLI output audit
All 4 CLI commands (`--integrity`, `--profiles`, `--trust-model`, `--platform-probe`) were checked for banned terms:
- `constant monitoring` — absent from all outputs
- `immutable` — absent from all outputs
- `tamper-proof` — absent from all outputs
- `certified` — absent from all outputs
- `tamperproof` — absent from all outputs

### 5b. Programmatic report audit
- `runIntegrity()` JSON output: zero banned terms
- verify.js source uses "rewrite-detecting", not "immutable" for adoption-log claims
- verify.js source uses "never silently repair", not "self-healing"

**Verdict**: Contract 10 honest-language rules honored. No banned unqualified terms in user-facing output.

---

## Attack 6: No Side Effects — ALL PASS

### 6a. File mutability check
- Full directory snapshot before and after `runIntegrity()` — zero files created, modified, or deleted
- Repeated invocations (3x) produce identical file system state
- Reports are deterministic (after stripping `generated_at` metadata timestamp)

### 6b. Lock check
- Running `--integrity` via CLI does NOT create a `state.lock` file
- verify.js imports state-store.js only for `SCHEMA_VERSION` (documented deviation per header)

**Verdict**: verify --integrity is truly read-only. No write locks, no state mutations, no side effects.

---

## Attack 7: Platform Probe — ALL PASS

### 7a. CLI probe
- `--platform-probe` executes and returns `probe_verified: true`
- Probe name is `rename-replace-under-open-handle`
- `rename_succeeded` is an actual boolean (not hardcoded)
- `claim` string contains "Probe-verified" and is OS-specific

### 7b. Programmatic probe
- `runPlatformProbe()` returns an object with actual probe results, not hardcoded claims

**Verdict**: Platform probe genuinely exercises the rename-over-open-handle scenario. The "atomic" claim is probe-verified per contract 01, not assumed.

---

## Extra Attacks — ALL PASS

### E1-E6: Edge cases
- Non-existent root → graceful `release_verified: "unavailable"`, exit 0
- Missing ACTIVE → `fail_closed: true`, `failure_domain: "evolvable-surface"`
- Corrupt project manifest → `self_consistent: "no"`, `reason: "corrupt"`
- Adapter declarations: present/valid detected, invalid JSON caught
- verifyFileList: empty list, null list, missing file, backslash path, dotdot path, escape path, invalid hash — all handled correctly
- verify --selftest: 35 passed, 0 failed

---

## Defect Summary

| # | Severity | Description |
|---|---|---|
| — | — | **No defects found.** |

The sentinel correctly engages the specified failure domain for every attack. The A6 out-of-scope case (both manifests rewritten) is confirmed and documented. The documented limitation (extra-file-on-disk not detected at release/project level) is explicitly called out in verify.js source comments.

### Honest coverage: what was NOT tested
- Symlink/junction evasion on the evolvable tree (SKIPPED — OS denied symlink creation)
- The `--profiles` stubs for R/E/B/G (stubs are correct per Phase A scope)
- `diffDestinations()` with live observed-destinations log (hook only; log file format not yet pinned by any contract)

---

## Running the Tests

```bash
node tests/verify/deepseek/run-tests.js
# Exit 0 if all pass, exit 1 if any FAIL
```

All fixtures are created in `%TEMP%` and cleaned up after each test.