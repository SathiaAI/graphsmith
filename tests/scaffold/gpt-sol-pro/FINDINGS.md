# Scaffold Behavioral Adversarial Findings

Tester lane: `tests/scaffold/gpt-sol-pro/`

Target: `scripts/scaffold.js` emitted projects, exercised only in OS temporary directories. Every behavioral case invokes emitted `manager.js` as a real child process. Verdicts use child exit status and files under the temporary emitted project's `.runs/<runId>/`; stdout/stderr strings are not pass criteria.

## Final Verdict

No real unfixed scaffold defect was found in this amended lane.

Three consecutive verification runs exited `0` with:

```text
SUMMARY total=44 pass=44 fail=0 skipped=0
```

## Adjudicated Findings

### GS-SCAF-01: FIXED - corrupt budget state fails closed

The amended test confirms that corrupt `budget-state.json` is refused rather than replaced with fresh totals.

### GS-SCAF-02: FIXED - killed wall-time is reconstructed on resume

The test now inspects post-resume state. A real killed segment pushes `cumulative_wall_time_ms` over the limit and persists a `max_wall_time_ms` HALT with `reconstructed_killed_segment: true`.

### GS-SCAF-03: FIXED - acknowledgement records the approved extension

The acknowledgement record contains the rule, affected tunable, previous limit, and new limit.

### GS-SCAF-04: FIXED - log-budget HALT is terminal

The real-manager log-byte case exits nonzero with an on-disk `max_log_bytes` HALT; it is not suppressed or overwritten by retry handling.

### GS-SCAF-05: FIXED - state-budget HALT is terminal

The real-manager checkpoint case exits nonzero with an on-disk `max_state_bytes` HALT; it is not converted into a retry-budget failure.

### GS-SCAF-06: FIXED - disk-budget HALT is terminal

The real-manager artifact case exits nonzero with an on-disk `max_disk_mb` HALT; it is not converted into a retry-budget failure.

### GS-SCAF-07: TEST-AMENDED - acknowledgement and persistent step reentry

Persistent step-attempt accounting is by design. Each acknowledgement assertion now uses its own fresh scaffolded project and run ID, and acknowledgement cases widen `max_retries_per_step` before re-entering the interrupted step. The tests still require preserved external-call totals and an auditable extension record.

### GS-SCAF-08: TEST-AMENDED - idempotent capability wording

The idempotent capability case now requires `kind: "safe-to-resume-assumed"` plus the safety-critical substrings `recorded idempotency key` and `safe ASSUMING the remote honors the declared key`. It no longer treats em-dash versus ASCII hyphens or terminal punctuation as a behavioral failure.

## Flake Amendments

- `resume/counter does not reset`, `resume/ack records the actual extension`, `resume/ack can complete after unrelated retry cap is widened`, and `resume/ack resumes, preserves totals, and records event` each use a fresh emitted project and unique run ID.
- Crash/resume setup acknowledges any fail-closed watchdog marker before driving the separately asserted supervisor state transition. The later `resume/refused without --acknowledge-budget` verdict still verifies byte-for-byte refusal of an unresolved supervisor budget HALT.
- The killed-wall-time case waits long enough to exceed its configured wall-time ceiling, resumes, and checks reconstructed cumulative state rather than inspecting immediately after process kill.

## Coverage

- Every requested budget: boundary plus one for steps, retries, wall time, total/per-destination/per-effect external calls, allowlist, estimated cost, disk, memory, log, state, subprocess count/lifetime, and output tokens.
- Two-effect race, process kill plus resume, resume without acknowledgement, acknowledged resume, corrupt budget state, and killed wall-time segment.
- Frozen tunable value bounds and manifest self-hash.
- All four tripwires, including fake checkpoint churn.
- Capability decision objects for read-only/no-intent, local-transactional, idempotent-by-key, status-checkable resolved/unresolved, and none.
- Oversize, invalid UTF-8, non-NFC, marker-injected, and traversal prompt cases.

## Honest Limits

- This is the dispatched GPT-sol-pro behavioral set. The separate watchdog dead-guard/security integration set is not duplicated here.
- Memory enforcement is a process self-check, not an OS containment proof; the test drives heap use past the minimum bound and invokes the emitted supervisor through a real manager.
- Subprocess count/lifetime APIs are exercised from an emitted worker through the real manager. The manager's watchdog spawn itself is not charged through those APIs.
