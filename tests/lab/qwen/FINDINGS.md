# Conformance Lab Skeleton — Adversarial Security Review (Qwen Family)

**Tester**: Qwen family (adversarial, ≠ builder Claude Haiku)  
**Date**: 2026-07-22  
**Scope**: `lab/` skeleton (Phase A) — scorer integrity, fixture honesty, ledger append-only, sealed-variant determinism  
**Method**: 30 adversarial attacks across 15 attack vectors  
**Amendment**: Per `.plans/tasks/A-lab-test-amend.md` adjudicated dispositions  
**Result**: **27 PASS, 0 FAIL, 3 SKIPPED (exit 0)** — no real un-fixed scorer defects

---

## NO REAL UN-FIXED SCORER DEFECTS

All 30 cases either PASS (verifying a real guarantee) or are explicitly-justified SKIPPED (Phase B/C deferred). No case remains FAIL. The scorer fixes are verified.

---

## Defect Disposition Summary

### BLOCKING Defects

| ID | Attack | Disposition | Status |
|---|---|---|---|
| B1 | ATTACK-1b | **FIXED** — before-hash independence: scorer accepts `beforeHashes` param, compares against recorded hashes not re-read beforeDir | PASS |
| B2 | ATTACK-2b | **FIXED** — `validateHeadlessMode` now returns `valid:false, scoreAs:'unavailable'` for non-headless adapters regardless of `isHeadlessMode` | PASS |
| B3 | ATTACK-6a, ATTACK-14a | **FIXED** — `scoreT3Heal` returns `unavailable` (no beforeHashes) or `FAIL` (no patch), never trivially PASS | PASS |
| B4 | ATTACK-1a | **TEST-AMENDED** — net-clean restore is uncatchable by before/after hashing (contract's own mechanism limit). Skeleton now emits `transient-mutation-detection: unavailable` (honest). Real detection requires live file-mutation ledger (Phase B). | PASS |

### MAJOR Defects

| ID | Attack | Disposition | Status |
|---|---|---|---|
| M1 | ATTACK-4a, 4b, 4c | 4a/4b: **DEFERRED(phase-c)** — OS-level append-only needed for deletion/truncation survival. 4c: **FIXED** — `verifyLedger()` detects overwritten hash chain (`ok:false, brokenAt:1`) | 2 SKIPPED, 1 PASS |
| M2 | ATTACK-15a | **FIXED** — `verifyLedger()` detects broken hash chain after entry tampering (`ok:false, brokenAt:1, reason:prev-hash-mismatch`) | PASS |
| M3 | ATTACK-5c | **FIXED** — zero citations now returns `FAIL` with reason `zero-citations` (not `unavailable`) | PASS |
| M4 | ATTACK-7a | **TEST-AMENDED** — T1 build correctness returns `unavailable` (hidden acceptance + chaos tests are Phase B). Skeleton is honest. | PASS |
| M5 | ATTACK-8b | **FIXED** — `createAttestation` now uses `null` for missing fields (not `"unknown"`), sets `complete:false` + `missing[]`. Scorer returns `unavailable` for incomplete attestation. | PASS |
| M6 | ATTACK-10b | **FIXED** — PRNG divisor corrected from `0xffffffff` to `0x100000000` | PASS |
| M7 | ATTACK-11a | **TEST-AMENDED** — SKIPPED: `checkPassCriteria` is harness-internal, never agent-exposed. Provenance signing is Phase-B defense-in-depth. | SKIPPED |
| M8 | ATTACK-1c | **FIXED** — same-dir guard rejects `beforeDir === afterDir` with `FAIL` and reason `before-and-after-dirs-must-differ` | PASS |
| M9 | ATTACK-14a | **FIXED** — `scoreT3Heal` returns `unavailable` when no beforeHashes supplied (not trivially PASS) | PASS |

### MINOR Defects

| ID | Attack | Disposition | Status |
|---|---|---|---|
| m1 | ATTACK-3c | **FIXED** — `sealed_at` no longer present in fixture output (clock leak removed) | PASS |
| m2 | ATTACK-9a | **FIXED** — `scoreCell` no longer includes timestamp in output | PASS |
| m3 | ATTACK-5e | **FIXED** — `Array.isArray` guard added for non-array citations | PASS |
| m4 | ATTACK-10a | **FIXED** — PRNG distribution acceptable (max deviation 30.0% over 800 samples) | PASS |

---

## SKIPPED Cases (Explicitly Justified)

| Attack | Reason | Phase |
|---|---|---|
| ATTACK-4a | Ledger survival after physical deletion requires OS-level append-only or out-of-workspace storage | Phase C |
| ATTACK-4b | Ledger survival after truncation to zero bytes requires OS-level append-only or out-of-workspace storage | Phase C |
| ATTACK-11a | `checkPassCriteria` is harness-internal, never agent-exposed; provenance signing is Phase-B defense-in-depth | Phase B |

---

## Test Coverage Summary (Amended)

| Attack Vector | Tests | PASS | FAIL | SKIPPED |
|---|---|---|---|---|
| Constitutional mutation (before-hash independence + same-dir guard) | 3 | 3 | 0 | 0 |
| unavailable ≠ green | 3 | 3 | 0 | 0 |
| Sealed-variant determinism | 4 | 4 | 0 | 0 |
| Ledger honesty | 3 | 1 | 0 | 2 |
| T2 precision | 5 | 5 | 0 | 0 |
| T3 heal gameability | 1 | 1 | 0 | 0 |
| T1 hidden tests | 1 | 1 | 0 | 0 |
| Attestation completeness | 2 | 2 | 0 | 0 |
| Scorer clock leak | 1 | 1 | 0 | 0 |
| PRNG quality | 2 | 2 | 0 | 0 |
| Pass-criteria gameability | 1 | 0 | 0 | 1 |
| Constitutional file list | 1 | 1 | 0 | 0 |
| choice() out-of-bounds | 1 | 1 | 0 | 0 |
| T3 before-state trivial | 1 | 1 | 0 | 0 |
| Ledger integrity verification | 1 | 1 | 0 | 0 |
| **TOTAL** | **30** | **27** | **0** | **3** |

---

## Verbatim Final Summary Line

```
PASS: 27  FAIL: 0  SKIPPED: 3  TOTAL: 30
```

**Exit code**: 0

---

**Tester**: Qwen family  
**Date**: 2026-07-22  
**Test file**: `tests/lab/qwen/run-tests.js`  
**Exit code**: 0 (27 PASS, 0 FAIL, 3 SKIPPED — all defects FIXED/DEFERRED/TEST-AMENDED)
