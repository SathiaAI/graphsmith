# FINDINGS.md — promote.js Adversarial Test (deepseek family)

## Summary

**Suite:** `tests/promote/deepseek/run-tests.js`
**Result:** 56 PASS, 0 FAIL, 0 SKIPPED
**Prod defects found:** 0 BLOCKING, 0 MAJOR, 3 MINOR
**Test defects found:** 1 (crash-WINDOW_FINAL boundary — fixed)

---

## Attack 1: Crash/Recovery Matrix

**Coverage:** 16 test cases covering every INTENT-without-DONE boundary across the full promotion lifecycle (TX_BEGIN → TX_DONE), plus the invariant that ACTIVE always resolves to exactly old-tree or new-tree.

| Boundary | Method | Verdict |
|---|---|---|
| before-swap (built-in `__test_crash_at`) | crash + recover | PASS |
| after-swap (built-in `__test_crash_at`) | crash + recover | PASS |
| after-manifest (built-in `__test_crash_at`) | crash + recover | PASS |
| TX_BEGIN → STAGE_DONE | manual journal | PASS (clean rollback, no adoption entries) |
| STAGE_DONE → VALIDATED | manual journal | PASS (rollback-before-visible-log, staged tree cleaned) |
| LOG_APPEND_INTENT → LOG_APPEND_DONE | manual journal | PASS (forward: committing entry appended, full promote completed) |
| LOG_APPEND_DONE → WINDOW_PENDING | manual journal | PASS (forward to effective) |
| SWAP_INTENT → SWAP_DONE | manual journal | PASS (forward: swap applied, window admitted + finalized) |
| OUTCOME_APPEND_INTENT → OUTCOME_APPEND_DONE | manual journal | PASS (forward: terminal entry appended, manifest anchored) |
| OUTCOME_APPEND_DONE → MANIFEST_INTENT | manual journal | PASS (forward: manifest written) |
| MANIFEST_INTENT → MANIFEST_DONE | manual journal | PASS (forward complete) |
| WINDOW_FINAL → TX_DONE | manual journal | PASS (idempotent TX_DONE appended) |

**ACTIVE invariant:** Every recovered state has a well-formed ACTIVE pointer pointing to either the original tree or the new staged tree. Verified across all boundary configurations.

**Defects:** None. Recovery correctly classifies all on-disk states by inspection (active identity hash, adoption-log head, manifest head), never by assuming a torn record. Roll-forward is applied only where safe; ambiguous states produce HALT with evidence.

---

## Attack 2: Torn Journal Tail

**Coverage:** 3 test cases.

1. Torn half-line appended to a completed journal → `parseJsonl` correctly breaks before the torn record; all valid records are returned.
2. Unfinished tx (TX_BEGIN only) after a torn tail → recovery classifies by the valid records and aborts cleanly.
3. Recovery on a completed journal with a torn suffix → returns CLEAN (no unfinished transactions to act on).

**Defects:** None. The `parseJsonl` torn-tail guard (`!raw.endsWith("\n")` break on last invalid JSON line) works correctly.

---

## Attack 3: CAS / Hostile Mutation

**Coverage:** 4 test cases.

1. **Pre-BEGIN stale expectation:** Wrong `expected_active_sha` → `STALE_PROPOSAL` clean abort (not HALT).
2. **Post-BEGIN hostile mutation:** ACTIVE mutated between TX_BEGIN and recovery to a third (neither old nor new) value → recovery HALT with "unclassifiable identity" evidence.
3. **HALT exit code mapping:** `promote.js:823` maps `HALT` → exit code 3 (verified structurally).
4. **Clean abort pre-BEGIN:** stale proposal before journal entry → clean abort without side effects.

**Defects:** None. The code distinguishes stale pre-BEGIN expectations (clean ABORT) from post-BEGIN hostile mutations (HALT with evidence), matching contract 01's invariant 2.

---

## Attack 4: Adoption-log Chain Integrity

**Coverage:** 3 test cases.

1. **Happy path:** Chain is hash-linked (`prev_sha256` → `entry_sha256`), seq increments, terminal entry status is "effective", manifest `adoption_log_head` anchors the terminal entry.
2. **Abort path:** Post-LOG abort produces terminal "aborted" entry; manifest anchor matches.
3. **Tamper detection:** Corrupted `entry_sha256` in adoption-log → next promote detects chain break via `adoptionEntries()` and throws `HALT`.

**Defects:** None. The chain is append-only, hash-linked, and tamper-detectable.

---

## Attack 5: Rollback (doc/knob vs code/migration)

**Coverage:** 6 test cases.

1. **Doc rollback byte-exact restore:** Content `"alpha\n"` → changed → rolled back → `"alpha\n"` verified byte-identical and tree identity matches original.
2. **Code rollback refused:** Kind `"code"` → `FORWARD_RECOVERY_REQUIRED`.
3. **Migration rollback refused:** Kind `"migration"` → `FORWARD_RECOVERY_REQUIRED`.
4. **Non-pre-authorized refused:** `reversible: false` / `auto_rollback_eligible: false` → `FORWARD_RECOVERY_REQUIRED`.
5. **Unknown txid refused:** Random txid → `ROLLBACK_NOT_FOUND`.

**Defects:** None. Doc/knob rollback restores the exact original tree; code/migration is correctly refused with a human-forward-recovery message.

---

## Attack 6: GC + Universal Registry

**Coverage:** 4 test cases.

1. **Live-lease tree survives promotion:** Register a reader on the current tree → promote → tree still exists (live registration prevents GC).
2. **Previous tree retained after deregistration:** Deregister reader → tree still exists (it's the rollback-eligible previous tree).
3. **Heartbeat mechanism:** `heartbeatRun()` extends lease; verified available.
4. **Sweep expired runs:** `sweepExpired()` API verified.

**Limitation:** The GC implementation in `promote.js` is a contract 01 requirement but the current `promote()` function does not directly call GC logic — it delegates to the state-store for window and registry management. Actual tree-deletion GC is described in the contract but `promote()` itself does not invoke tree GC during the transaction. This follows contract 01's statement that "GC (on a later promotion, under the promotion lock, never inside the committing transaction)" but no explicit GC invocation was observed in the promote() flow.

**Defects:** MINOR — GC of orphaned trees is documented in the contract but no code path in `promote()` calls tree-deletion GC. The state-store handles registry sweep, but actual tree directory deletion during promotion was not observed. Recommended: document whether GC is implemented in a separate pipeline module or needs to be added.

---

## Attack 7: Gate-4 Coupling

**Coverage:** 4 test cases.

1. **Crash after MANIFEST, before WINDOW_FINAL:** Recovery finalizes the window (no adopted-tree-without-window state).
2. **Window finalized after recovery:** Verified window state is OBSERVING after recovery.
3. **NO_WINDOW precondition:** promote succeeds when initial window state is NO_WINDOW.
4. **WINDOW_EXISTS block:** Promote refuses when an active window (ADMITTED/OBSERVING) exists.

**Defects:** None. Gate-4 window admission is correctly coupled inside the promotion transaction. Crash after SWAP but before WINDOW_FINAL → recovery finalizes the window. Promote enforces the NO_WINDOW precondition.

---

## Attack 8: Disk Discipline

**Coverage:** 3 test cases.

1. **Free-space check path exists:** `diskPreflight()` verifies same-volume via `statSync().dev` comparison and `statfsSync` availability.
2. **Abandoned staging tree cleanup:** Crash after STAGE_DONE creates a staged tree → recovery deletes it (fs.rmSync).
3. **Staged tree cleanup verified:** Confirmed the staged tree directory is absent after recovery rollback.

**Defects:** MINOR — The free-space check is correctly implemented but the test cannot exhaust disk space on the test platform. The code path's existence was verified structurally but not exercised end-to-end with actual disk exhaustion. Recommended: a Docker-based CI test with a tmpfs mount of fixed size would provide full coverage.

---

## Attack 9: Platform Honesty (Same-volume / Unprovable-FS)

**Coverage:** 2 test cases.

1. **Same-volume promote succeeds:** Both source and evo directory are on the same device → promote succeeds.
2. **Code path verification:** `diskPreflight()` enforces same-volume via `stat.dev` comparison and `statfsSync` availability check; throws `PLATFORM_REFUSED` when unprovable.

**Defects:** MINOR — The `statfsSync` unavailability path (`PLATFORM_REFUSED`) cannot be tested on Node >= 18.15 (which always has statfsSync). The test verifies the code structure but not the actual failure path. On older Node versions (< 18.15) this code path would trigger. Recommended: a conditional test in CI that checks behavior on an older Node version or a mock injection point for filesystem functions.

---

## Additional Attacks (beyond required 9)

**Coverage:** 12 additional test cases.

| Test | Focus | Verdict |
|---|---|---|
| Invalid packet detection | Missing fingerprint → INVALID_PACKET | PASS |
| Clean state recovery | No unfinished transactions → CLEAN | PASS |
| Double recovery idempotent | Crash + recover + recover → CLEAN | PASS |
| Source tree path | `source_tree` parameter exercised | PASS |
| Window open blocks promote | Active OBSERVING window → WINDOW_EXISTS | PASS |
| Negative window_n | -5 normalizes to default 5 | PASS |
| Zero window_n | 0 normalizes to default 5 | PASS |
| Path traversal edit | `../../etc/passwd` → INVALID_PACKET | PASS |
| Nonexistent edit target | File not in tree → VALIDATION_FAILED | PASS |
| Unknown txid rollback | Random txid → ROLLBACK_NOT_FOUND | PASS |
| Missing manifest halts recovery | Deleted manifest during unfinished tx → CORRUPT_STATE | PASS |
| Consecutive promotions blocked | Window open prevents second promote → WINDOW_EXISTS | PASS |

---

## Test Suite Defects Found and Fixed

### DEFECT D1 (TEST): crash-WINDOW_FINAL boundary constructs inconsistent state
**Severity:** N/A (test bug, not production)
**Status:** FIXED

The original `crash-WINDOW_FINAL` test constructed a journal missing `SWAP_INTENT` and `OUTCOME_APPEND_INTENT` records while having the project manifest already pointing to a terminal entry hash not present in the adoption log. Recovery correctly HALTed on the unclassifiable manifest head. Fixed by adding the missing journal records and writing the effective entry to the adoption log.

---

## Honest Coverage Statement — What Was NOT Tested

1. **Actual SIGKILL / process crash:** All crash boundaries are simulated via manual journal construction or the built-in `__test_crash_at` mechanism. No actual process-kill-and-restart cycle was performed. The idempotency of recovery is tested, but not under genuine OS-level process failure.
2. **Filesystem-level rename atomicity:** The test runs on Windows/NTFS. Actual `MoveFileEx` replace-under-open-handle semantics were not probed.
3. **Disk exhaustion end-to-end:** The `DISK_RESERVE` code path exists but was not triggered with a full disk.
4. **statfsSync unavailability path:** Not testable on Node >= 18.15.
5. **Multi-process concurrency:** All tests run in a single process. Hostile cross-process mutations during promotion were simulated via state manipulation between calls, not through actual concurrent writers.
6. **Tree GC deletion during promotion:** The contract describes GC of orphaned trees during later promotions, but no code path invokes it during the promotion transaction itself. This may be implemented in a separate module.
7. **Large file / huge tree performance:** Not tested; the fixture uses 2 small files.
8. **Network filesystem / FAT volume:** The same-volume check is tested structurally but not against actual network mounts.
9. **Rollback through Gate-4 ROLLING_BACK path:** The `rollback()` function with `rollback_of` parameter is tested for doc/knob, but the full Gate-4 hard-failure-triggered auto-rollback cycle was not exercised.
10. **Human acknowledgement of rollback families:** Not tested (requires the rollback-families ledger interaction).