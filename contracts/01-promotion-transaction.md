# Contract 01 — Promotion Transaction Protocol (normative state machine)
Status: DRAFT. Implements plan §3.1 (pass-2 fix F3). Every adoption of evolvable-surface change — and every Gate-4 rollback (which is a pre-authorized inverse transaction, never a second path, I2/F11) — executes exactly this machine.

## Reused v0.1.1 primitives (grounded)
- Durable atomic write: temp + fsync + rename [KnoSky: scripts/scaffold.js:116-126].
- Lease-lock with heartbeat + pid-reuse defense: [KnoSky: scripts/scaffold.js:64-113] — same semantics, promotion-scoped (`.graphsmith/promotion/.lock`), env overrides `GRAPHSMITH_LEASE_MS`/`GRAPHSMITH_HEARTBEAT_MS` honored.
- Write-ahead intent → effect → completion, fsync'd appends: [KnoSky: scripts/scaffold.js:237-267] — generalized to the transaction journal.

## Files
```
.graphsmith/promotion/.lock            # lease-lock (one transaction per project, ever)
.graphsmith/promotion/journal.jsonl    # fsync'd append-only transition records
.graphsmith/promotion/staging-<txid>/  # complete next tree, SAME filesystem as target (verified)
.graphsmith/promotion/retired-<txid>/  # displaced tree, GC'd only after VERIFIED
```
`txid` = `sha256(candidate_fingerprint + manifest_head)[:16]` — deterministic, so a crashed transaction re-run resumes the SAME txid (idempotent, SKILL.md rule 3).

## States and transitions
| State | Entry action (journaled BEFORE acting, fsync'd) | Exit condition | Failure → |
|---|---|---|---|
| IDLE | — | promotion requested with Gate-3 packet | — |
| LEASED | acquire lease-lock; record `expected_head` (current manifest head hash) | lock held | ABORT (lock unavailable → refuse loudly) |
| STAGED | build complete next tree in `staging-<txid>/`; verify same-filesystem (`fs.stat().dev` equality; fail-closed if unprovable) | staging complete | ABORT |
| VALIDATED | re-verify: staged-tree hashes match candidate declaration; parent path identities canonical (realpath, symlink/junction refusal, case-fold, NFC — plan §3.1); sentinel PASS on staged tree; CAS pre-check: live head == `expected_head` | all checks pass | ABORT |
| COMMITTED | two-phase swap with journal record between renames: (1) `rename(current → retired-<txid>)`, (2) `rename(staging-<txid> → current)` | both renames journaled complete | RECOVERY |
| VERIFIED | re-open committed tree; full re-hash vs manifest; write new manifest head (atomic write) | verification pass | RECOVERY (restore retired tree by inverse two-phase swap) |
| DONE | GC `retired-<txid>/`; append adoption-log entry (contract 09); release lock | — | — |

## Crash recovery (on any start: read journal, resume or roll back — never guess)
| Journal shows | Recovery action |
|---|---|
| LEASED/STAGED incomplete | delete staging dir, release lock → IDLE (nothing visible changed) |
| VALIDATED, no COMMIT intent | same as above |
| COMMIT intent, rename (1) done, (2) not | complete rename (2) if staging tree verifies, else restore rename (1) inverse; journal each |
| COMMIT complete, VERIFIED incomplete | run verification; pass → DONE; fail → inverse swap, restore retired |
| VERIFIED, DONE incomplete | re-run GC + adoption-log append (both idempotent) |
Ambiguous journal (torn tail line) → treat last record as absent (JSONL torn-tail rule; the fsync ordering makes intent-before-effect reliable — same argument as [KnoSky: scripts/scaffold.js:239-244]).

## Platform atomicity notes (per-OS, published in the property matrix)
- POSIX: `rename(2)` atomic same-filesystem — both phases atomic.
- Windows/NTFS: `fs.renameSync` file rename atomic; DIRECTORY rename is atomic-in-practice but can fail transiently on open handles (AV/indexer). Mitigation: bounded retry with backoff on `EPERM/EBUSY`, journal before/after each attempt; if rename (2) ultimately fails, recovery restores rename (1). Property matrix reports Windows as "atomic swap with journaled two-phase recovery," never "atomic."
- Unprovable filesystem (network mounts, FAT): refuse at LEASED (fail-closed) with plain-English explanation.

## Invariants (mutation-tested in Phase A)
1. No path writes to `current` except the two-phase swap.
2. CAS: any observed head ≠ `expected_head` at VALIDATED or during rollback → ABORT, human message.
3. Lock held from LEASED through DONE; heartbeat renewed; stolen-lease recovery follows journal, not assumption.
4. Rollback = a new transaction whose staged tree is the Gate-3 pre-authorized inverse; allowed only for reversible document/knob changes with compatible schemas (plan §4 F8); code/migrations → human forward-recovery.
5. Concurrent mutator during any state (TOCTOU harness): worst outcome is ABORT with evidence — never a corrupt adoption.
