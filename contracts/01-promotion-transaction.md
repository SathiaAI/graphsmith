# Contract 01 — Promotion Transaction Protocol (v3 — pointer-swap + honest concurrency claims)
Status: DRAFT v3 (pass-2 fixes: P2-GPT-1/3/4/5/11/12, P2-Gemini-1, P2-DeepSeek-1). Implements plan §3.1 (F3). Every adoption — and every Gate-4 rollback (a pre-authorized inverse transaction, never a second path, I2/F11) — executes exactly this machine.

## Concurrency claims (honest — P2-GPT-1)
The word "CAS" in this contract means **cooperative expected-state verification under the single-writer owner-token lock** — all GraphSmith writers serialize on the lock and re-verify expected state before each effect. It is NOT a hardware/filesystem conditional write. A **hostile same-user mutator** racing the transaction (threat class A1) is handled by **detect-and-HALT**: post-commit re-open/re-hash verification, sentinel boundary checks, and mutation tests covering a hostile write in EVERY interval (validate→log→swap→manifest→done). The guarantee against A1 is detection with evidence, never prevention — consistent with contract 05.

## Topology (the pass-1 redesign)
Directories are never swapped. The evolvable surface is materialized as immutable **versioned trees**; a single small **pointer file** names the active tree; commit = one journaled pointer-file replace.
```
.graphsmith/state/                    # STABLE — never inside any swap
  promotion.lock                      # lease-lock (owner token; see Locking)
  journal.jsonl                       # fsync'd append-only typed transition records
  adoption-log.jsonl                  # hash-chained, append-only (contract 09)
  project.manifest.json               # CAS target (contract 09)
  window.json (+ journal)             # Gate-4 store (contract 02, owned by window-store)
  rollback-families.jsonl, rejected-buffer.jsonl
  run-registry.jsonl                  # UNIVERSAL reader registry (P2: all three reviewers) — see GC
  run-anchors.jsonl                   # per-run log-chain heads + expected terminal status (contract 07)
  alpha-ledger.jsonl                  # contract 03
.graphsmith/evolvable/
  ACTIVE                              # pointer file: { schema_version, txid, tree, tree_manifest_sha256 }
  v-<treehash>/                       # immutable tree: learned.md, workers/*.prompt.md, tunables.json, …
    tree.manifest.json                # closed schema (P2-GPT-11): {schema_version, files:[{path, sha256, bytes}]} —
                                      # COMPLETE inventory; loaders/recovery reject extra or missing files
```
Canonical location note (P2-GPT-5): `project.manifest.json` and `adoption-log.jsonl` live under `.graphsmith/state/` — contract 09 refers to THESE paths; any other path reference is an error.
All `.graphsmith/state/` writes go through ONE module: `scripts/state-store.js` (single writer, owner-token lock, journaled revisions — contract 11 lane).
- **Trees are immutable once VALIDATED**: created by staging, never modified after; readers can't observe a half-written active tree.
- **Loaders (constitutional) resolve the evolvable surface ONLY through ACTIVE**, read once at run start (the Gate-4 snapshot pin = the tree id). Missing/corrupt ACTIVE → refuse to start, fail-closed, print `graphsmith promote --recover`. Convenience copies at project paths are non-authoritative; divergence is a sentinel warning, never an input.
- **No window without a live tree**: readers see the old tree until the instant the pointer replace lands, the new tree after. (Resolves DeepSeek-1/GPT-1.)
- Reused v0.1.1 primitives: durable atomic file write (temp+fsync+rename) [KnoSky: scripts/scaffold.js:116-126]; write-ahead intent→effect→completion [KnoSky: scripts/scaffold.js:237-267].

## Locking (hardened per GPT-5)
Lease + heartbeat semantics from [KnoSky: scripts/scaffold.js:64-113], with: (a) lock content = `{ pid, proc_start_hint, owner_token: random128 }`; renew/release/steal verify `owner_token` (compare-before-write) — pid-reuse cannot renew another owner's lease; (b) promotion lease/heartbeat bounds are frozen in the release manifest; `GRAPHSMITH_LEASE_MS`/`GRAPHSMITH_HEARTBEAT_MS` are honored ONLY when `GRAPHSMITH_TEST_MODE=1` (a mode the sentinel reports and CI forbids in release jobs); (c) recovery acquires the lease BEFORE reading the journal.

## Journal (closed record schema — DeepSeek-3, P2-GPT-4; every record fsync'd before its effect; ships as `schemas/promotion-journal.schema.json`)
Happy path: `TX_BEGIN{txid, expected_active_sha, expected_log_head}` → `STAGE_DONE{tree, tree_manifest_sha}` → `VALIDATED` → `LOG_APPEND_INTENT{entry_sha}` → `LOG_APPEND_DONE` → `WINDOW_PENDING{window_id}` (Gate-4 admission coupled INSIDE this transaction — P2-GPT-3) → `SWAP_INTENT{from_tree, to_tree}` → `SWAP_DONE{observed_active_sha}` → `MANIFEST_INTENT{new_head_sha}` → `MANIFEST_DONE` → `WINDOW_FINAL{window_id}` → `TX_DONE`.
Non-happy records (also closed schema): `TX_ABORT{reason, compensating_entry_sha?}` · `RECOVERY_BEGIN{observed_state}` · `RECOVERY_STEP{action}` · `RECOVERY_DONE{outcome}`. Legal-transition table ships with the schema; recovery classifies EVERY prefix, including abort-after-log-append-before-swap (which appends the compensating `aborted` entry, contract 09).
`txid = sha256(candidate_fingerprint + expected_active_sha)[:16]` — deterministic; re-running a crashed transaction resumes the SAME txid.

## Gate-4 coupling (P2-GPT-3)
Window admission is INSIDE this transaction: the pending window record is durably created (state-store, same lock) BEFORE the pointer swap and finalized before lock release. `promote.js` itself enforces the NO_WINDOW precondition — the serialization rule cannot be bypassed by calling promote directly. Crash anywhere → the promotion+admission pair recovers as ONE state machine: a swap without a finalized window is completed forward (window finalized) or the whole transaction is inverted; a run starting in any gap either sees (old tree, no window) or (new tree, window pending/open) — the registry (below) plus WINDOW_PENDING ordering makes an adopted-tree-but-unobserved run impossible.

## Transitions
1. **LEASED** — acquire lock; record TX_BEGIN with CAS expectations (current ACTIVE content hash + adoption-log head).
2. **STAGED** — build `v-<treehash>/` (complete evolvable tree); verify same-volume as ACTIVE (see Platform); hash every file.
3. **VALIDATED** — staged tree hashes match the Gate-3 packet; canonical-path audit (realpath, symlink/junction refusal, NFC, case-fold collision refusal); sentinel PASS on staged tree; **CAS check**: live ACTIVE hash == expected, log head == expected; else ABORT.
4. **LOG APPEND** — append the adoption entry (status `committing`, carries txid) to the hash chain. Aborts after this point append a compensating `aborted` entry — the chain is append-only, never rewritten (GPT-2).
5. **SWAP** — journaled pointer replace: write `ACTIVE.tmp` (fsync) → rename over `ACTIVE`. Idempotent: re-execution writes identical content.
6. **MANIFEST** — project manifest updated (new tree, `adoption_log_head = entry_sha`) via atomic file write.
7. **TX_DONE** — release lock.

## GC + universal run registry (P2: Gemini-1, DeepSeek-1, GPT-11 — the pass-2 convergent fix)
- **EVERY managed run** (windowed or not) registers `{run_id, tree_id, lease}` in `run-registry.jsonl` at start and deregisters at exit — lease + heartbeat semantics identical to the v0.1.1 run lock [KnoSky: scripts/scaffold.js:64-113]; a crashed run's registration expires with its lease.
- GC (on a later promotion, under the promotion lock, never inside the committing transaction): delete only trees that are (a) not ACTIVE, (b) not the rollback-eligible previous tree, (c) older than the last 2, AND (d) have zero live-lease registrations. Expired-lease registrations are swept with a journal record.
- **Disk discipline (P2-GPT-12):** preflight free-space reserve before STAGED (≥ 2× staged-tree bytes + journal headroom) else refuse; recovery deletes abandoned staging trees (typed lifecycle records); journals/logs compact via an anchored checkpoint entry that preserves chain verification; quota policy always preserves ACTIVE + rollback-eligible trees.

## Crash recovery (inspect-and-roll-forward; lease first; itself journaled and idempotent)
For every INTENT-without-DONE boundary, recovery **inspects filesystem identities** rather than assuming (Gemini-2/GPT-3): log tail contains `entry_sha`? → LOG_APPEND happened. `ACTIVE` content == to_tree pointer? → swap happened. Manifest head == new_head? → manifest written. Roll FORWARD from the first effect not yet observed (all effects idempotent); if TX never reached LOG_APPEND_INTENT, roll BACK (delete staged tree, append nothing, release lock — nothing visible changed). Torn journal tail = record absent; the inspection rule still classifies the on-disk state. Recovery under recovery is safe: every recovery step is the same idempotent effect + journal pattern. Unknown/ambiguous state that inspection cannot classify → **HALT with evidence** (never guess) — the same posture as the v0.1.1 unresolved-side-effect halt [KnoSky: scripts/scaffold.js:252-259].

## Platform honesty (GPT-4)
- Claims are per-file-rename only; no directory-rename claims exist in this design.
- Language: "journaled pointer swap with inspect-and-roll-forward recovery" — the word "atomic" appears only in per-OS property-matrix rows that a **platform probe** (Phase A CI: rename-replace-under-open-handle probe, crash harness) has actually established. Windows/NTFS rename-replace uses MoveFileEx-replace semantics — reported as probe-verified behavior, with bounded EPERM/EBUSY retry + journal.
- Same-volume verification: volume identity via Node file stats where provable; **unprovable filesystem (network mount, FAT, unknown) → refuse promotion at LEASED, fail-closed**, plain-English explanation.

## Invariants (each mutation-tested per-transition, not just kill-sprayed — GPT-3)
1. Nothing writes `ACTIVE` except step 5; nothing modifies a tree after VALIDATED.
2. CAS violation anywhere → ABORT + evidence; concurrent-mutator TOCTOU harness worst outcome = clean ABORT.
3. Lock held LEASED→TX_DONE; owner-token verified on renew/release/steal.
4. Rollback = new transaction whose staged tree is the Gate-3 pre-authorized inverse; doc/knob + compatible schemas only (F8); code/migrations/external effects → human forward-recovery.
5. A reader (run start) sees exactly one of: old tree or new tree — never neither, never a mix. During Gate-4 ROLLING_BACK, new run starts are refused (contract 02).
6. The retired (previous) tree exists until its rollback eligibility lapses.
