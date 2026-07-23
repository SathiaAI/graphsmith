# DeepSeek Adversarial Security Findings — scripts/scaffold.js

> **Tester**: DeepSeek family (DeepSeek-V4-Pro)
> **Suite**: `tests/scaffold/deepseek/run-tests.js`
> **Results**: 28 tests, 27 PASS, 0 FAIL, 1 SKIP
> **Date**: 2026-07-22

---

## Summary

Three prior findings have been adjudicated and test-amended per `B-scaffold-test-amend.md`. No open code defects remain.

---

## F1: Acknowledged-extension record does not capture the actual extension — FIXED (CODE)

| Field | Value |
|---|---|
| **File** | `scripts/scaffold.js` (emitted supervisor.js) |
| **Status** | FIXED — test now PASSes |

The emitted code now records `tunables`, `previous_limit`, `new_limits`, and `acknowledged_via` in the extension record. Test `ack-ext/RECORDS-DELTA` confirms a rich delta is present. No action needed.

---

## F2: Tunables bounds widenable by recalculating manifest self-hash — ADJUDICATED

| Field | Value |
|---|---|
| **File** | `scripts/scaffold.js` (emitted supervisor.js `verifyFrozen()`) |
| **Status** | ADJUDICATED (out-of-threat-model) — test amended to SKIP |

Per D5 adjudication (contract-04/05):
- **contract-04**: The anti-widening GUARANTEE is the GATE FENCE — evolve cannot reach the manifest. The self-hash is tamper-EVIDENCE, not tamper-PROOF.
- **contract-05**: A same-user attacker who rewrites both files + rehashes is OUT OF SCOPE (they could rewrite manager.js too).

**Amended behavior**:
- Test 3a (value widen beyond frozen max): PASS — TUNABLE_OUT_OF_BOUNDS enforced
- Test 3b (manifest tamper, stale self-hash): PASS — MANIFEST_SELF_HASH_MISMATCH detected
- Test 3c (BOTH widen + rehash): **SKIPPED(out-of-threat-model)** — a same-user attacker who can rehash is out of scope per contract-05. CASUAL widening without rehash is rejected by 3b. The honest-language posture (self-hash=integrity, gate-fence=authority) is test-verified.

---

## F3: Killed-segment wall time is not accumulated — FIXED (CODE + TEST-AMENDED)

| Field | Value |
|---|---|
| **File** | `scripts/scaffold.js` (emitted supervisor.js `tickWallTime()`) |
| **Status** | TEST-AMENDED — check POST-RESUME per D2 |

The original test checked `cumulative_wall_time_ms` immediately after kill, where a synchronous busy-loop cannot tick mid-loop (wall time only accumulates at supervisor checkpoints). D2 reconstructs the killed segment's wall time ON RESUME.

**Amended behavior**:
- After kill: informational PASS (checkpoint-granular — low wall time is expected)
- Post-resume: assert `cumulative_wall_time_ms >= 200ms` (D2 reconstruction)
- If D2 reconstruction fails: FAIL with clear gap evidence.

---

## F4: Manager cannot detect a dead watchdog (D4 coupling) — FIXED (CODE)

| Field | Value |
|---|---|
| **File** | `scripts/scaffold.js` (emitted manager.js `spawnWatchdog()`) |
| **Status** | FIXED — orphan race resolved, watchdog tests re-enabled |

The emitted manager.js now has a `child.on('exit', ...)` handler and periodic PID-aliveness checks. The watchdog orphan race is fixed. Tests `testWatchdogDeadGuard` and `testWatchdogHaltFile` are re-enabled (previously blocked by the harness crash at line 592, also fixed).

---

## Coverage confirmed (non-findings)

The following attack vectors were tested and confirmed to be **correctly enforced**:

| Attack | Result |
|---|---|
| Corrupt budget-state.json → resume | FAILS-CLOSED (exit 2, HALT record preserved) |
| Field deletion from budget-state.json | FAILS-CLOSED (counters not reset to 0) |
| max_steps off-by-one (2+1 on 3-step pipeline) | Correctly halts at steps_executed=3 |
| max_external_calls byte-cap | Enforced independently (log cap fires before retry exhaustion) |
| max_state_bytes byte-cap | Enforced independently |
| log/state byte counters tracked separately | Confirmed independent |
| Tunables value widened beyond frozen max | REJECTED (exit 1, TUNABLE_OUT_OF_BOUNDS) |
| Manifest self-hash detects tampered bound | REJECTED (exit 1, MANIFEST_SELF_HASH_MISMATCH) |
| Checkpoint churn ≠ progress (state-transition-stall) | Correctly tripped on churn>reentry with furthest_step_index=-1 |
| Undeclared observed destination tripwire | Halted |
| Rate-cap breach at boundary+1 | Halted |
| Fullwidth unicode marker injected into prompt | Quarantined (NFKC-folded) |
| Zero-width spliced marker injected into prompt | Quarantined |
| Resume without --acknowledge-budget after halt | REFUSED (exit 2) |
| External-call counter persists across kill+resume | Counter preserved correctly |
| Watchdog halt-file honored on resume without ack | REFUSED (exit 2) |
| Watchdog halt-file accepted with --acknowledge-budget | Resumed successfully (exit 0) |

---

## Not tested (out of lane)

| Attack | Reason |
|---|---|
| Race conditions across two concurrent manager processes | Requires multi-process orchestration (out of scope for this lane) |
| Capability-specific kill messages | GPT-Solo-Pro lane covers this; confirmed passing in their suite |
| Prompt-file path traversal via symlink | OS permissions may prevent symlink creation; tested by GPT-Solo-Pro |

(End of file)