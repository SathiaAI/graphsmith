# Contract 02 — Gate-4 Observation Window (v2 — durable store + CAS)
Status: DRAFT v2 (post-panel-pass-1: GPT-6/7/8, DeepSeek-2/6). Operational canary, NOT a statistical gate (F9).

## Durable store (owned by `scripts/window-store.js` — its own lane, contract 11)
`.graphsmith/state/window.json` + `window-journal.jsonl` (fsync'd). Every mutation is CAS on a monotonic `state_rev`: read rev → journal intent{rev, op} → atomic file replace {rev+1} → journal done. A lost CAS retries on the fresh state; a crashed mutation recovers by inspect-and-roll-forward (same discipline as contract 01).

## Run registration (closes the observation races — GPT-6, DeepSeek-2)
- Every managed run start REGISTERS: CAS-append `{run_id, tree_id (its pinned snapshot), started}` to the window store when a window is OBSERVING. Registration decides eligibility once, atomically: a run is an OBSERVED run iff it registered while `observed_count < N` and its `tree_id` == the window's adopted tree; the same CAS increments `observed_count`. No double-counting, no ambiguous Nth run.
- During ROLLING_BACK: **new run starts are refused** ("rollback in progress — retry shortly"); in-flight registered runs complete on their pinned trees and are marked `superseded` at rollback commit.

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
