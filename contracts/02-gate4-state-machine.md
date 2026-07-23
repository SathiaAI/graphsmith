# Contract 02 — Gate-4 Observation Window (v2 — durable store + CAS)
Status: DRAFT v2 (post-panel-pass-1: GPT-6/7/8, DeepSeek-2/6). Operational canary, NOT a statistical gate (F9).

## Durable store (owned by `scripts/state-store.js` — the single writer for ALL `.graphsmith/state/`, contract 11; P2-GPT-2)
`.graphsmith/state/window.json` + `window-journal.jsonl` (fsync'd). **All window mutations are serialized under the state-store owner-token lock (single writer)** — "CAS" here means the cooperative expected-`state_rev` verification that single writer performs before each journaled mutation, never a lock-free conditional rename (P2-GPT-2 wording fix; contract 01 §Concurrency claims applies verbatim). Crashed mutations recover by inspect-and-roll-forward.

## Run registration (v3 — universal registry, slot accounting: P2-GPT-13, Gemini-2, DeepSeek-2)
- ALL managed runs register in the universal run registry (contract 01 §GC) with lease + heartbeat. A registering run is additionally an **OBSERVED run** iff a window is OBSERVING ∧ its `tree_id` == the window's adopted tree ∧ an admitted slot is free; the same serialized mutation claims the slot. No double-counting, no ambiguous Nth run.
- The window tracks slots separately: `admitted` (claimed), `active`, and per-slot **terminal disposition** ∈ {completed_pass, completed_hard_fail, completed_soft_wobble, abandoned, superseded}. A window may reach CLOSED_* only when every admitted slot has a terminal disposition.
- **Abandoned runs** (registry lease expired without deregistration — crash/OOM/power): swept by the next state-store operation or `watch`; disposition `abandoned` sets the FLAG bit and the slot is NOT refilled. Cause is unknown (adoption vs infrastructure), so abandonment NEVER auto-rolls-back and never silently passes: a window containing any `abandoned` slot closes as **CLOSED_FLAGGED → human review**. (Recorded divergence: pass-2 Gemini proposed treating abandonment as a HARD auto-rollback trigger; rejected as thrash-prone on infra flakes — auto-rollback stays reserved for evidenced hard failures, F9-consistent.)
- **Window wall-clock cap** (DeepSeek-2): `max_window_wall_time` (tunable, bounds frozen; default 7 days) → CLOSED_FLAGGED with evidence. No window blocks the pipeline forever.
- During ROLLING_BACK: new run starts are refused; in-flight runs complete on pinned trees, marked `superseded` at rollback commit.

## States
| State | Notes |
|---|---|
| NO_WINDOW | admission allowed (under the promotion lock — no admission race) |
| ADMITTED → OBSERVING | window record: adoption txid, candidate-semantic fingerprint, N (default 5), baseline metric snapshot from the Gate-3 packet, triggers armed |
| OBSERVING [+ FLAG] | FLAG is an orthogonal durable bit on the window (GPT-7), never a state that loses the run counter |
| ROLLING_BACK | entered by exactly one winner: the trigger transition is a CAS op; losers see the rev change and stand down. Executes the pre-authorized inverse via contract 01 (promotion lock + CAS on ACTIVE) |
| CLOSED_PASS / CLOSED_ROLLED_BACK / CLOSED_FLAGGED | terminal; back to NO_WINDOW. HALT_HUMAN if the inverse transaction itself fails (CAS/verify) — evidence preserved |

Crash recovery: window-journal walked under the promotion lock; every op idempotent; a window found mid-ROLLING_BACK on restart resumes the inverse transaction via contract 01 recovery.

## Triggers (deterministic; HARD > SOFT precedence — GPT-7)
| Trigger | Class | Action |
|---|---|---|
| Hard-invariant failure in an observed run (the run's own evidence records it) | HARD | ROLLING_BACK (if auto-rollback-eligible per Gate 3) else HALT_HUMAN |
| Budget breach / tripwire HALT in an observed run | HARD | same |
| SOFT wobble: the predeclared primary metric of an observed run < `baseline_metric` recorded in the adoption packet (exact arithmetic on recorded evidence; missing metric value ⇒ FLAG) | SOFT | set FLAG bit; window continues; human review at close. NEVER auto-rollback |
Both classes observable in one run: HARD wins. Trigger evaluation happens at run completion during its deregistration CAS.

## Thrash guard (GPT-8, DeepSeek-6)
- **Candidate-semantic fingerprint** (shared definition, used here, in the rejected buffer, and in contract 03 families): `sha256(schema_version + normalize(sorted [file, anchor, op] targets) + normalize(payload))`, `v1`. Distinct from contract 07's event fingerprint.
- Rolled-back fingerprints persist in `.graphsmith/state/rollback-families.jsonl` — **append-only and uncapped, independent of the cap-100 rejected buffer**; cleared per-entry only by explicit human acknowledgement (recorded).
- Oscillation: admission compares against the last 5 adoptions; a fingerprint (or a family member per contract 03's family rule) matching any rolled-back entry in that horizon requires human ack to admit.

## Data boundary
Observations are evidence for humans (evidence.jsonl). They never become proposal/training input automatically. Superseded-run results are excluded from all later analysis.
