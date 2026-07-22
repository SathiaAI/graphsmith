# FINDINGS — scripts/watchdog.js adversarial review (Grok lane)

**Target:** `scripts/watchdog.js` (Qwen builder)  
**Lane:** `tests/watchdog/grok/` only — no `scripts/` modifications  
**Platform:** win32 · Node v24.18.0  
**Method:** real child processes; verdicts from exit codes, pid liveness, halt-file JSON, on-disk state/journal. Log strings ignored.  
**Run:** `node tests/watchdog/grok/run-tests.js` → **18 PASS / 5 FAIL / 0 SKIP** (exit 1)

Zero-finding reviews are INVALID. Five defects confirmed by process state.

---

## Summary

| ID | Attack | Result | Severity |
|----|--------|--------|----------|
| A1 | Blocked event-loop kill within budget | PASS | — |
| A2 | Watchdog not starved by target spin | PASS | — |
| A3 | Process-tree kill leaves no orphans | PASS (win32 `taskkill /T /F`) | — |
| A4 | Capability kill messages (7 variants) | PASS for declared JSON shapes | — |
| A4b | **Missing capability file fail-safe** | **FAIL** | **BLOCKING** |
| A4c | **Corrupt capability JSON fail-safe** | **FAIL** | **BLOCKING** |
| A4d | Stale in-flight cap not cleared | PASS | — |
| A4e | **local-transactional "inspected" lie** | **FAIL** | **BLOCKING** |
| A5 | Chaos resume ≥5 kill points | PASS (6/6 consistent) | — |
| A6 | **Forged advancing heartbeat starves kill** | **FAIL** | **BLOCKING** |
| A6b | Single forged high counter then stale | PASS | — |
| A6c | Partial/garbage heartbeat | PASS | — |
| A7a/b | Budget just-under / just-over | PASS | — |
| A8 | **Watchdog self-crash → unguarded run** | **FAIL** | **MAJOR** |
| A9/A10 | Usage exit 2 / dead-pid exit 1 | PASS | — |

---

## Defects

### D1 — Missing capability file fail-opens to "no external effects in flight"  
**Severity: BLOCKING** · Evidence: A4b  

**Attack:** Spawn manager that never creates `--capability-file`. Force sync spin. Watchdog kills and writes halt evidence.

**Observed (process/disk):**
- watchdog exit code `3` (HALT) ✓  
- `halt.kill_message === "no external effects in flight"`  
- `halt.capability_at_kill === null`

**Why wrong:** Contract 06 default posture: *every unresolved intent is "reconciliation required" until a rule affirmatively upgrades it*. A **missing** capability file means completion is **unknown** — not proven empty. Emitting the green-path "no external effects" message is a false calm; operator may resume without reconciliation.

**Root cause** (`deriveKillMessage`):
```js
if (!capabilityData || !capabilityData.capability) {
  return "no external effects in flight";
}
```
Collapses three distinct states into one green message:
1. file missing / unreadable  
2. JSON parse failure (see D2)  
3. intentional `{ "capability": null }` (only this should be green)

**Fix:** Distinguish presence:
- `capability-file` absent or unparseable → `"reconciliation required (capability state unknown)"`  
- parseable `{ capability: null }` → `"no external effects in flight"`  
Optionally require the manager to create the file before spawn and treat absence as hard fail at watchdog start (exit 1) in addition to fail-closed kill message if a race deletes it.

---

### D2 — Corrupt capability JSON also fail-opens  
**Severity: BLOCKING** · Evidence: A4c  

**Attack:** Capability path exists with body `{not-json`. Manager spins.  

**Observed:** `kill_message === "no external effects in flight"` (same as D1).

**Why wrong:** Same as D1 — unknown ≠ none. Hostile or partial writers can force the green class by truncating the file mid-write (TOCTOU / crash during write).

**Fix:** `readJsonFile` failure path must not call the null-capability green branch. Return explicit unknown → reconciliation. Prefer atomic replace for capability updates on the manager side (temp + rename) so readers never see partial JSON; watchdog still fail-closed on parse error.

---

### D3 — `local-transactional` claims "inspected" without inspecting anything  
**Severity: BLOCKING** · Evidence: A4e  

**Attack:** Declare `{ capability: "local-transactional", effect_id: "write-cfg" }`, block, capture halt JSON.

**Observed:**
- `kill_message = 'safe to resume (local effect "write-cfg", inspected)'`  
- Halt object fields present: `halt`, `pid`, `budget_ms`, `elapsed_ms`, `last_heartbeat`, `kill_message`, `killed_at_mono_ms`, `kill_delivered`, `capability_at_kill`, `effect_id_at_kill`  
- **No** `inspected` / `local_inspection` / `landed` / marker path / journal verdict field of any kind.

**Why wrong:** Contract 06 § kill/resume derivation step 2: *local state inspected (transaction either landed or didn't) → "safe to resume (local effect, inspected)."* The **"inspected"** token is a **truth claim**. Hardcoding it from the capability label alone is a false "safe to resume" when landed/not-landed was never determined — exactly the false assurance the task forbids.

**Root cause:** `deriveKillMessage` case `local-transactional` templates the contract phrase without reading any inspection convention.

**Fix:**
1. Require capability payload (or sibling path arg) to carry inspection locus (`marker_path` / journal path per contract).  
2. Before emitting safe-to-resume, perform the deterministic inspect; record `{ landed: true|false|unknown, evidence: ... }` on halt file.  
3. `landed` known → safe-to-resume with proof; `unknown` → reconciliation required. **Never** print "inspected" without a successful inspect result on the halt record.

---

### D4 — Heartbeat counter is forgeable; external writer defeats blocked-loop detection  
**Severity: BLOCKING** · Evidence: A6  

**Attack:** Victim does ~3 real heartbeats then hard-spins (cannot write). Concurrent **forger** process increments the same heartbeat file every 30ms. Budget 500ms. Wait 6s.

**Observed:**
- Victim pid still alive after >> budget  
- No halt file (watchdog never crossed elapsed > budget because `lastChangeMonoMs` kept refreshing)  
- Watchdog did not exit 3 within timeout  

**Why wrong:** The documented liveness signal is "incrementing counter in heartbeat-file." Any process that can write that path (sibling worker, compromised adapter, stray test harness, multi-writer bug) can keep a **deadlocked** event loop "alive" forever. The watched `--pid` is never bound to the writer identity.

**Root cause:** Poll logic trusts any counter delta:
```js
if (counter !== null && !isNaN(counter) && counter !== lastCounter) {
  lastCounter = counter;
  lastChangeMonoMs = nowMono;
}
```

**Fix (pick ≥1, prefer defense-in-depth):**
1. **PID-scoped heartbeat:** contents must be JSON `{ "pid": <manager_pid>, "n": <mono counter>, "mono_ms": <hrtime> }` and pid must match `--pid` or update is ignored.  
2. **HMAC or locked file:** manager holds exclusive lock / writes side-channel only it owns.  
3. **Dual signal:** require both counter advance **and** OS-level CPU-time / getrusage delta on the pid; if pid CPU stalls while file advances → treat as forge / still kill.  
4. **Directory permissions:** heartbeat path in a mode-0700 dir owned by manager user with no cross-writer. (Helps; not sufficient alone on shared runners.)

---

### D5 — Watchdog self-crash leaves blocked run with no supervisor signal  
**Severity: MAJOR** · Evidence: A8  

**Attack:** Start live manager + watchdog; `taskkill` the watchdog mid-watch; manager enters hard spin; observe.

**Observed:**
- After watchdog death + >1.5s (and budget 400ms): victim **still alive**  
- **No** halt file  
- Interface supplies no reverse channel for manager/orchestrator to learn the guard died  

**Why wrong:** Plan §7 success condition depends on the watchdog as the only stopper for a fully blocked loop. If the guard dies (OOM, kill, bug), the blocked run escapes with zero evidence. Scaffold/manager cannot currently `wait` on watchdog exterior to this interface.

**Fix:**
1. Document and implement **mandatory** supervisor: parent (scaffold) spawns both, `await`s watchdog.exit, and if watchdog exits 0 without manager exit or exits nonzero without `halt-file`, force tree-kill manager + write local HALT `reason: watchdog_died`.  
2. Optional: watchdog writes a **guard-heartbeat** file; manager/supervisor polls it when not blocked; on missed guard-beat after manager's own I/O resumes → refuse to start new effects and loud-halt.  
3. Exit codes already exist (0/1/2/3) — bind them to scaffold enforcement; do not leave them advisory.

---

## What held (attacks that failed to break the watchdog)

| Property | Evidence |
|----------|----------|
| Kill fires under hard sync spin | A1: exit=3, `elapsed_ms` just over budget (~500 on 500ms budget), manager pid dead |
| Own process/timer not delayed by target CPU hog | A2: kill under 60s spin, elapsed≈426 on 400ms budget |
| Windows process-tree cleanup | A3: 2 children spawned; after kill neither pid alive, child marker not live |
| Declared capability → correct message class | A4x: null/read-only/none/status-checkable/idempotent/unknown all match contract phrasing **when file is valid JSON** |
| Intentional null capability ≠ unknown (once distinguished… not yet for missing file) | null → no-effects (correct **if** file intentional) |
| Chaos-grade on-disk state after kill | A5: 6 kill points; state JSON parseable; completed[] unique; journal monotonic; resume prefix coherent |
| Budget floor (no false kill while beating) | A7a: exit 0 when manager clean-exits under 80ms heartbeats vs 600ms budget |
| Budget ceiling (kill after stall) | A7b: elapsed 377 > 350 |
| Stale high single-shot counter | A6b: does not permanently grant liveness |
| Garbage heartbeat text | A6c: eventually kills |
| CLI contract | A9 exit 2; A10 dead pid exit 1 |

---

## Cross-platform honesty

| Path | This run (win32) | Unix note |
|------|------------------|-----------|
| Tree kill | Proven via `taskkill /PID /T /F` | Uses `kill(-pid, SIGKILL)`; requires target as process-group leader (`detached`/setsid). **Not proven here** — mark Unix orphan property `unverified on this host` if only win32 CI. |
| pid liveness | `process.kill(pid, 0)` | same |
| Orphan enum | WMIC ParentProcessId walk | `ps --ppid` — different tool, same claim |

No property was marked green without a local proof. Unix process-group leader assumption is a residual risk for non-detached managers (watchdog falls back to single-pid kill in catch).

---

## Coverage statement (honest)

**Covered exhaustively against real processes:** blocked-loop kill timing, cross-process starvation immunity, win32 tree kill, all 5 contract capability classes + unknown, missing/corrupt capability, forge counter, stale/partial heartbeat, budget boundaries, multi-point resume consistency, watchdog death, CLI exits.

**Not covered (out of lane or needs scaffold):**  
- full `state-store.js` lease/journal integration (used lightweight temp state/journal mimicking resume invariants; did not open repo `.graphsmith/`)  
- scaffold.js dual-spawn supervisor behavior (interface gap called out in D5; scaffold not authorized to edit)  
- Linux/macOS process-group orphan matrix  
- 20 random kill points (did 6 distinct capability/beat combinations; invariant is the same)  

**Bottom line:** Kill engine and declared-message switch largely work. **Fail-open on unknown capability state, unlabeled "inspected" safe-to-resume, forgeable heartbeat, and guard-death silence are BLOCKING/MAJOR and must ship fixed before this watchdog is trusted as the SECURITY-tier stopper.**

---

## Fixes priority (for builder, not applied)

1. **D1+D2** — fail-closed deriveKillMessage on missing/corrupt; separate null-capability path  
2. **D3** — real local inspection or remove "safe/inspected" wording until inspect exists  
3. **D4** — bind heartbeat to pid (+ optional CPU accounting)  
4. **D5** — scaffold must supervise watchdog lifetime  

---

## How to re-run

```bash
node tests/watchdog/grok/run-tests.js
# exit 1 if any FAIL; JSON summary on stdout; last-run.json written beside this file
```

## Verbatim last run (summary)

```
total: 23
passed: 18
failed: 5
skipped: 0
FAIL A4b-missing-capability-file-fail-safe
FAIL A4c-corrupt-capability-json-fail-safe
FAIL A4e-local-transactional-claims-inspected-without-inspection
FAIL A6-forged-heartbeat-counter-while-blocked
FAIL A8-watchdog-self-crash-no-manager-notice-channel
```
