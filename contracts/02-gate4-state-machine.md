# Contract 02 — Gate-4 Observation Window (operational canary, NOT a statistical gate)
Status: DRAFT. Implements plan §4 Gate 4 (fixes F7/F8/F9, Gemini-3, unanimous serialization fix).

## States
| State | Meaning | Transitions |
|---|---|---|
| NO_WINDOW | no adoption under observation | Gate-3 apply (contract 01 DONE) → ADMITTED |
| ADMITTED | window record written: adoption txid, fingerprint, N (default 5), triggers armed | first eligible run starts → OBSERVING |
| OBSERVING | counting the next N runs; each run pins its config/prompt snapshot at start (in-flight runs undisturbed — loads happen at run start only) | see triggers |
| CLOSED_PASS | N runs, no trigger | → NO_WINDOW |
| ROLLING_BACK | hard trigger fired; executing the Gate-3 pre-authorized inverse via contract 01 (takes promotion lock, CAS-checks live head) | success → CLOSED_ROLLED_BACK; CAS/verify failure → HALT + human |
| CLOSED_ROLLED_BACK | inverse applied byte-exact; fingerprint buffered against re-proposal | → NO_WINDOW |
| FLAGGED | statistical wobble observed | window completes normally; human reviews; NEVER auto-rollback |

## Serialization (unanimous pass-2 fix)
- ONE active window per project. `promote` refuses admission while state ≠ NO_WINDOW / CLOSED_*: "an observation window is open (adoption <txid>, run k of N)."
- The window state file lives inside the promotion-protected area; admission check happens under the promotion lock (no admission race).

## Triggers (deterministic, manager-observed)
| Trigger | Class | Action |
|---|---|---|
| Hard-invariant failure in any observed run | HARD | auto-ROLLBACK |
| Budget breach / tripwire HALT in an observed run (contract 06/§7) | HARD | auto-ROLLBACK |
| Primary-endpoint wobble vs pre-adoption evidence (any decline short of hard failure) | SOFT | FLAG only |
Auto-rollback eligibility is checked at Gate 3, not here: only reversible document/knob changes carry a pre-authorized inverse; anything else records trigger + HALTs for human forward-recovery.

## Drain semantics
Runs in flight at rollback keep their pinned snapshots to completion; their results are marked `window: superseded` and excluded from any later analysis. New runs after rollback load the restored tree.

## Thrash guard
- Rolled-back fingerprints enter the rejected buffer (cap 100, semantic fingerprints — plan §3.4); automatic re-proposal refused.
- After any rollback, admission requires the NEXT adoption to be a different fingerprint family (no A→rollback→A′ oscillation without human ack).

## Data boundary
Gate-4 observations are evidence for the human, recorded in evidence.jsonl. They NEVER become proposal/training input automatically (plan §4, OpenAI MISSING fix).
