# FINDINGS.md — deepseek family adversarial test of `scripts/state-store.js`

## Suite summary
**run-tests.js** — zero-dep CJS, 12 attack test cases across 8 required categories + 4 additional. 12 PASS, 0 FAIL, 0 SKIPPED.

## Attack-by-attack results

### 1. Lock: steal / refuse / token mismatch
- **Steal expired lease:** Created a fake lock file with a dead pid (99999) and mtime set 5s in the past. `_acquireLock()` correctly unlinked the expired lock and acquired a fresh one. PASS.
- **Refuse fresh active lock:** Created a fake lock with our own pid and current mtime. `_acquireLock()` threw `LOCKED` — refused correctly. PASS.
- **Owner-token mismatch on release:** After acquiring a valid lock, called `_releaseLock()` with 32 zeroes. Threw `LOCK_OWNER_MISMATCH`. PASS.
- **Owner-token mismatch on renew:** Called `_renewLock()` with 32 zeroes. Threw `LOCK_OWNER_MISMATCH`. PASS.

### 2. Pid-reuse + TEST_MODE guard
- **Alive-pid stale lease stealable:** Fake lock with our PID, mtime 5s old (>>40ms lease). `_acquireLock()` stole it because `age > leaseMs` took precedence over the alive pid check. PASS.
- **Fresh heartbeat refused:** Fake lock with our PID, mtime current. `_acquireLock()` threw `LOCKED`. PASS.
- **TEST_MODE requirement:** Verified with `GRAPHSMITH_TEST_MODE` unset: env var `GRAPHSMITH_LEASE_MS=100` had no effect (store used default 30000); constructor option `leaseMs: 123` also ignored (store used 30000). With `GRAPHSMITH_TEST_MODE=1`, the 40/5 values were honored. PASS.

### 3. Crash recovery (mid-mutation)
- Spawned a child process that sets `_testing.crashNextMutationAfter(1)`, then calls `store.runRegistry.register(...)`. The simulated crash throws `SIMULATED_CRASH` after the journal INTENT is written but before MUTATION_DONE.
- A fresh store instance opens the same state dir; `_recoverJournal()` inspects the orphaned INTENT, verifies the before-hash match, and rolls forward the effects (atomic replace of window.json + registry.jsonl).
- Verified: (a) the run `run-crash-recover` was recovered in the registry list; (b) `state_rev > 0` monotonic; (c) journal contains `MUTATION_DONE`; (d) window slot was rolled forward. PASS.

### 4. Alpha ledger
- Reserved 3 slots on `corpus-x`. Slots allocated as 1, 2, 3. PASS.
- 4th reservation on same corpus threw `ALPHA_EXHAUSTED`. PASS.
- Family collision (same family for a different reservation) threw `ALPHA_FAMILY_CONSUMED`. PASS.
- After a new store instance (simulating crash), reservations persisted (all 3 still present). PASS.
- After completing reservation 1, the COMPLETED record was written and retrievable. PASS.
- 4th reservation still refused after completion (slot consumed permanently). PASS.

### 5. Run registry
- Registered two runs on different trees; re-registration idempotency confirmed (`existing: true`). PASS.
- Re-registration on different tree threw `RUN_CONFLICT`. PASS.
- Heartbeat succeeded; heartbeat on unknown run threw `RUN_NOT_FOUND`. PASS.
- Deregistration with `completed_pass` disposition worked. PASS.
- After 60ms sleep (lease=40ms), sweep removed expired run; registry JSONL contains `EXPIRED` record naming the swept run. PASS.
- After sweep, `list()` returned empty. PASS.

### 6. Window slots
- Admitted window with n=3, registered 3 runs — all observed (got slots). 4th run got `slot: null`. PASS.
- Window `active` and `admitted` counts == 3. PASS.
- Attempt to close window with active slots threw `WINDOW_ACTIVE`. PASS.
- Disposed run with `completed_soft_wobble` — FLAG bit set on window. PASS.
- Disposed run with `abandoned` — FLAG bit set. PASS.
- Closed window with `flagged` outcome — state became `CLOSED_FLAGGED`. PASS.
- Second window with 1 slot and active run: close refused (`WINDOW_ACTIVE`). PASS.

### 7. Concurrency
- 2 child processes, each doing 10 register+deregister pairs (40 total lock cycles), with random 2-10ms backoff on lock contention (60 retry attempts per operation).
- 0 errors reported. Both workers completed all 20 total operations. PASS.
- Post-mortem: registry JSONL and state-journal JSONL both parseable — no corrupt JSON. PASS.

### 8. Schema validation
- Exercised all record-producing methods (window admit/finalize, run register/heartbeat/deregister, alpha reserve, anchor set, rejected push, rollback append).
- Validated every written JSONL file and window.json against `schemas/state-store.schema.json` with a minimal inline validator.
- Checked: `additionalProperties: false` (no unknown keys), required fields, enum values, pattern constraints (owner_token hex), type matching.
- Verified a corrupt window.json with an extra `unknown_field` key is flagged by the validator. PASS.

### 9. state_rev monotonicity (additional)
- Tracked `state_rev` across admit → finalize → register × 2 → deregister. Value strictly non-decreasing and reached ≥ 3. PASS.

### 10. Disposition mapping (additional)
- Disposed with `{ hard_failure: true }` — disposition resolved to `completed_hard_fail`. Window state transitioned to `ROLLING_BACK`. PASS.

### 11. Wall-clock cap (additional)
- Window admitted with `max_window_wall_time_ms: 200`. After 300ms sleep, sweep expired detected wall-time expiry, closed window as `CLOSED_FLAGGED` with `close_reason: "max_window_wall_time"`. PASS.

### 12. Run anchors (additional)
- Set anchor with `chain_head` and `expected_terminal_status`. Retrieved correctly. Unknown run returned `null`. Second anchor for same run returned the latest. PASS.

## Honest coverage statement — what was NOT tested

| Area | Reason not tested |
|---|---|
| Real kill -9 / power-loss crash | Test uses `_testing.crashNextMutationAfter()` which simulates a crash at a controlled point — always between journal INTENT and first effect. Real crashes can occur at any instruction boundary, including mid-`fs.writeSync` or mid-`fsyncSync`. Not reproducible with a pure JS harness. |
| Torn journal tail (partial write) | `parseJsonLines` already handles this by discarding the last line if the file doesn't end with `\n`. Tested implicitly (empty journal recovery works), but a deliberately half-written JSON line with mid-byte truncation was not injected. |
| Ambiguous recovery (mid-file-replace with unverifiable hash) | The `HALT` path in `_recoverJournal` (before-hash doesn't match either before or after) was not triggered because the test only simulates clean INTENT→crash→recovery. |
| Hostile mutator (A1 threat class) | Contract 01 specifies detect-and-HALT, not prevention. A hostile process that writes directly to `.graphsmith/state/` files outside the store was not simulated — this is a system-level attack, not an API-level one. |
| Rejected buffer cap-100 | The `pushRejected` method stores at most 100 entries (`records.slice(-100)`). Tested only with 1 push; the 101st-push eviction was not verified. |
| Rollback families `humanAck` | Tested `appendRollback` but not the `ackRollback` flow (ack removes entry from `listRollbacks()` result). |
| Oscillation fingerprint guard | Contract 02 requires admission comparison against the last 5 adoptions for rolled-back fingerprints. The state-store itself does not implement this check (it's a caller responsibility), so it wasn't tested here. |
| `status()` method | Not explicitly tested; covered indirectly through `getWindow()` and `listRuns()` tests. |
| Singleton API vs constructor API parity | Only the constructor-based API was tested. The module-exported singleton functions (`module.exports.register`, etc.) use a global `process.cwd()` store and were not tested independently. |
| Disk-full / quota scenarios | The `_atomicReplace` cleanup on rename failure and the preflight free-space check (contract 01 §Disk discipline) were not triggered. |
| Unicode / non-ASCII run IDs | All test run IDs used ASCII alphanumerics. Non-BMP characters, zero-width joiners, and bidirectional override characters in run IDs were not tested. |
| Large payloads | Window.json with hundreds of slots and a very large journal were not benchmarked or stress-tested. |
| Cross-OS portability | All tests run on Windows. `_atomicReplace`'s `dirFd.fsyncSync` has platform-specific error suppression (`EINVAL`, `EISDIR`, `EPERM` on win32) that was not verified on Linux/macOS. |
| Temporal edge: heartbeat fires during `_releaseLock` TOCTOU | The heartbeat interval is `unref`'d and cleared before release. A race where the heartbeat fires between `clearInterval` and `fs.unlinkSync` in `_unlinkLockIfOwner` is theoretically possible but was not reproduced. |

## Test suite structure
```
tests/state-store/deepseek/
  run-tests.js    # zero-dep CJS test runner (12 cases)
  FINDINGS.md     # this file
```

All state created in `os.tmpdir()` subdirectories (pattern `gs-ds-ss-*`). Nothing written to the repo's `.graphsmith/`. No files outside this lane were modified.