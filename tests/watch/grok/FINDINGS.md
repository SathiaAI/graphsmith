# FINDINGS — scripts/watch.js adversarial review (Grok lane)

**Target:** `scripts/watch.js` (Claude Haiku builder)  
**Lane:** `tests/watch/grok/` only — no `scripts/` modifications  
**Platform:** win32 · Node v24.18.0  
**Method:** real CLI children (`spawn`/`spawnSync`) in TEMP project roots; require() for pure helpers. Verdicts from exit codes, pid liveness, recursive dir SHA-256, stdout/stderr.  
**Run:** `node tests/watch/grok/run-tests.js` → **9 PASS / 4 FAIL / 0 SKIP** (exit 1)

Zero-finding reviews are INVALID. Four defects confirmed by on-disk state / process behavior.

---

## Summary

| ID | Attack | Result | Severity |
|----|--------|--------|----------|
| A1 | READ-ONLY: full run-dir + `.graphsmith` tree hash before/after CLI render | PASS | — |
| A2 | **Budget usage vs limits + tripwire render** | **FAIL** | **BLOCKING** |
| A3 | Halt state + window/canary render; hash stable | PASS | — |
| A4 | Capability kill message classes (8 variants incl. missing/corrupt) | PASS | — |
| A4b | **Kill emits capability message when PID missing** | **FAIL** | **MAJOR** |
| A5 | Process-group kill: children die, no orphans | PASS (`taskkill /T /F`) | — |
| A6 | No network (`http`/`https`/`net`/`dns`/`fetch`) | PASS | — |
| A7 | Missing/corrupt run-state fails gracefully | PASS | — |
| A8 | **`local-transactional` "inspected" truth claim** | **FAIL** | **BLOCKING** |
| A9 | **Continuous tail survives + re-polls budget** | **FAIL** | **BLOCKING** |
| A10 | `--selftest` + exports surface | PASS (self-graded; not sole proof) | — |
| A11 | `killProcessGroup` rejects invalid PIDs | PASS | — |
| A12 | `--kill-run` does not mutate run-state hash | PASS | — |

---

## Defects

### D1 — Budget render omits limits and tripwires ("usage vs limits" is a lie)  
**Severity: BLOCKING** · Evidence: A2

**Contract (file header):** *polls and displays … budget usage vs limits, tripwire state …*

**Attack:** Feed `budget-state.json` with both usage counters and a full `limits` object plus `tripwires[]`, then call `renderBudgetSummary` and CLI watch.

**Observed:**
- Usage fields render (`steps_executed=42`, wall ms, cost, etc.)
- `limits.max_steps=100`, `max_wall_time_ms=60000`, `max_est_cost_usd=10` **never appear**
- No remaining/vs/usage-ratio cues
- `tripwires` (`armed` / `tripped`) **never appear**
- Only halt blob is special-cased; unbound tripwire array is ignored

**Why wrong:** Operators cannot see headroom or pre-halt tripwire state. Header advertises "usage vs limits"; implementation is usage-only.

**Root cause:** `renderBudgetSummary` prints a fixed list of usage counters; never reads `budgetState.limits` or `budgetState.tripwires`.

**Fix:** For each known limit key, print `used / limit` (and % if numeric). Render tripwire (and halted) sections from on-disk fields. If the schema differs, document the canonical shape and still refuse to claim "vs limits" without printing both sides.

---

### D2 — Continuous watch exits after first frame (`poller.unref()`)  
**Severity: BLOCKING** · Evidence: A9

**Attack:** Start `node scripts/watch.js <runId>` (no kill). After ~600ms rewrite `budget-state.json` to `steps_executed=99`. Observe ≥1.2s.

**Observed:**
- Process exit after **~34ms**, `timedOut=false`
- Never re-rendered `99`
- Hash of run-state unchanged (read path OK) but **tail is not a tail**

**Why wrong:** Product is a "local terminal tail" with `DEFAULT_REFRESH_INTERVAL_MS = 500`. `setInterval(...); poller.unref()` means the timer does not keep the event loop alive. After `main()` resolves, Node exits immediately; second+ frames never run.

**Root cause (`main` watch branch):**
```js
const poller = setInterval(() => { ... }, DEFAULT_REFRESH_INTERVAL_MS);
poller.unref();
```

**Fix:** Do not `unref` the live-tail poller (or only unref when an explicit `--once` mode is requested). For `--once`, print one frame and exit 0 without an interval. Optional: SIGINT handler to clear interval cleanly.

---

### D3 — `local-transactional` claims "inspected" with zero inspection  
**Severity: BLOCKING** · Evidence: A8

**Attack:** `deriveKillMessage({ capability: "local-transactional", effect_id: "write-cfg" })`.

**Observed message:**
```text
safe to resume (local effect "write-cfg", inspected)
```

API surface is capability JSON only — no marker path, journal path, or landed/not-landed result.

**Why wrong:** Contract 06 / capability kill tree: **"inspected" is a truth claim** that the local effect was examined (landed or not). Hardcoding the token from the capability *label* fabricates safety. Operator may resume on false assurance (same class of defect previously filed against `watchdog.js`).

**Fix:**
1. Require an inspection locus on the capability record (or sibling file).
2. Perform deterministic inspect before emitting safe-to-resume; record evidence.
3. If inspect impossible → `reconciliation-required`. **Never** print `inspected` without a successful inspect result.

---

### D4 — `--kill-run` drops capability message when PID cannot be resolved  
**Severity: MAJOR** · Evidence: A4b

**Attack:** Valid run dir + capability `none` + **no** `.manager.lock`. CLI `--kill-run`.

**Observed stderr only:**
```text
Error: cannot determine manager PID for kill operation
Expected .manager.lock file in run directory.
```
Non-zero exit (good) but **no** capability-derived kill message.

**Code order:**
1. `deriveKillMessage(capabilityData)` ✓ (result discarded if no PID)
2. Resolve PID from lock
3. On missing PID → `return` **before** `console.log(killMessage)`

**Why wrong:** Kill UX is supposed to tell the operator the resume/reconciliation posture for the *in-flight effect*. Missing PID is common (crashed manager, cleaned lock); failing closed on kill is correct, but **suppressing the already-derived message** forces a second tool/read. Cap posture is independent of kill success.

**Fix:** Always print `Kill message (capability-derived):` + message on the kill path, including when PID is missing or `killProcessGroup` fails. Exit non-zero as today.

---

## What held

| Property | Evidence |
|----------|----------|
| READ-ONLY render | A1: recursive SHA-256 of run dir and full `.graphsmith` tree identical before/after CLI watch |
| READ-ONLY kill | A12: run-dir hash unchanged across successful `--kill-run` |
| Halt rendering | A3: `HALTED` + rule + kind from budget-state |
| Window / canary | A3: `renderWindowSummary` shows window_id, slots, Flagged yes |
| Capability classes (when kill completes) | A4: read-only / null → no-external-effects-in-flight; local-transactional → safe-to-resume; idempotent-by-key → safe-to-resume-assumed (ASSUMING); status-checkable + none → reconciliation-required; missing/corrupt cap file → reconciliation-required (fail-closed, better than early watchdog) |
| Process-group kill | A5: manager + child dead after kill; no orphans (win32 `taskkill /PID … /T /F`) |
| No network | A6: static scan + runtime probe during watch/kill |
| Corrupt/missing state | A7: missing run → exit 1; corrupt budget JSON → no crash, hash stable; usage → exit 2 |
| Invalid PID helper | A11: rejects ≤0 / non-integer |

---

## Selftest gap

`--selftest` reports **pass (10 tests)** while A2/A8/A9 fail against the real contract. Selftest only hashes a single budget file after calling `renderBudgetSummary` in-process, never:

- drives CLI watch against `.graphsmith/runs/<id>`
- asserts limits/tripwires present
- asserts continuous poll
- asserts kill-message emission when lock missing
- challenges the `"inspected"` token

Treat selftest as smoke only; this suite is the adversarial gate.

---

## Reproduction

```bash
node tests/watch/grok/run-tests.js
```

Artifact: `tests/watch/grok/last-run.json`

---

## Verdict

**FAIL** — watch is a safe read-only snapshot helper with correct capability *class* mapping (when kill succeeds) and solid fail-closed corrupt-state behavior, but it does **not** implement a continuous tail, does **not** render budget limits/tripwires as advertised, overclaims local-transactional inspection, and hides kill posture when the manager PID is unknown.
