# FINDINGS — scripts/promote.js (tester family: grok)

Adversarial suite: `tests/promote/grok/run-tests.js`  
Victim: `scripts/promote.js` (builder: GPT-5.6-sol).  
Lane only. Temp project dirs only. Verdicts from on-disk ACTIVE / trees / journals / manifests / windows — not log-string greps.

## Run (verbatim)

```
PASS	01-happy-path-effective-anchor	txid=f4158fbf3f930928 tree=v-14d17f8187e0d7eeb28cdcab8ba56d3aedf86b40af51cd1d52fd09c2748a31d3
PASS	02-crash-recover-before-swap	ACTIVE=v-29ae9f396c7866a57ff662de03f03ff6cf56b7ae4b42e5c0f4f3f3796e042b9a window=OBSERVING
PASS	02-crash-recover-after-swap	ACTIVE=v-53f64b9fd77c38d62e027e56700f67919995efee8841ed3a6825a52d86215752 window=OBSERVING
PASS	02-crash-recover-after-manifest	ACTIVE=v-abb36bec32e06f61fddccdcb59e055ffd28e7a0fa714e08d7429ff67c7c51414 window=OBSERVING
PASS	03-intent-boundary-before-LOG_APPEND	ACTIVE=v-3ce7ea4f6eeff108b002b798deb251e38100cadae8c547cf64f0f39f907f1e18 win=NO_WINDOW rec=RECOVERED
PASS	03-intent-boundary-LOG_APPEND_INTENT-without-DONE	ACTIVE=v-792e38a5fadd8cb3ec924aef4fcf103ad5295f255e3417a707c7197b1dd9104d win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-LOG_APPEND_DONE-before-WINDOW	ACTIVE=v-964a5e332d4bda0648c879616e374edaa06cf6c0c8fe4ba04cc3262db366705b win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-SWAP_INTENT-without-DONE	ACTIVE=v-9b1006fcda4959ea9c7fdd53146ffe4f840ecd812efd7f2584ff19722f4f15e3 win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-SWAP_DONE-before-OUTCOME	ACTIVE=v-f33261bd16581cf102a6004a9ab9604043525c6f037763989e89860d3a4b291e win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-OUTCOME_INTENT-without-DONE	ACTIVE=v-ddeabb52af7ac200458178570a4350a4038708a6b42f20d579e1098b349f4f52 win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-MANIFEST_INTENT-without-DONE	ACTIVE=v-5343cf18a072dbd88d4f90e0e26a2dc7cf13485543231c6578ecf3378c0453eb win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-MANIFEST_DONE-before-WINDOW_FINAL	ACTIVE=v-6957eb5cafd5eaf16cf66cc6f4eca7956b1d408d17266f2ebe474b3987da64cd win=OBSERVING rec=RECOVERED
PASS	03-intent-boundary-before-STAGE_DONE	ACTIVE=v-3ce7ea4f6eeff108b002b798deb251e38100cadae8c547cf64f0f39f907f1e18 win=NO_WINDOW rec=RECOVERED
FAIL	04-torn-journal-tail-inspect-not-parse	recover threw on torn tail: CORRUPT_STATE Corrupt JSONL at …/journal.jsonl:8: Expected ':' after property name in JSON at position 84 (line 1 column 85)
PASS	05-stale-pre-BEGIN-clean-ABORT	STALE_PROPOSAL
PASS	06-hostile-post-BEGIN-HALT-exit3	HALT evidence=true mutated=true begin=true ACTIVE=v-abababababababababababababababababababababababababababababababab
PASS	07-adoption-log-terminal-anchor-and-chain	effective_head_ok abort_head_ok done=DONE
PASS	08-rollback-doc-byte-exact	restored tree=v-3ce7ea4f6eeff108b002b798deb251e38100cadae8c547cf64f0f39f907f1e18
PASS	09-rollback-code-FORWARD_RECOVERY	code+migration refused
FAIL	10-GC-live-lease-tree-survives	tree survived but promote.js has NO GC/live-lease coupling (null implementation); trees=…
PASS	11-gate4-swap-without-WINDOW_FINAL-recovers	finalized window OBSERVING on v-f96ada4c5acd9aeade4953431d0d75f2606453a77eee422cd9ab77588be5d96d
PASS	12-promote-refuses-open-window-NO_WINDOW	WINDOW_EXISTS
PASS	13-preflight-free-space-refusal	DISK_RESERVE
FAIL	14-abandoned-staging-cleaned-on-recover	.staging dirs remain: .staging-2d506b155c5fad2e
PASS	15-unprovable-or-cross-volume-refuse	PLATFORM_REFUSED
PASS	16-missing-statfs-fail-closed	PLATFORM_REFUSED
PASS	17-double-recover-idempotent	r1=RECOVERED r2=CLEAN
PASS	18-unfinished-tx-blocks-new-promote	RECOVERY_REQUIRED
PASS	19-ACTIVE-never-missing-during-built-in-crashes	all crash points pure
FAIL	20-manifest-update-omits-tree-field	updateProjectManifest only sets adoption_log_head; no new tree identity written (contract 01 §Transitions.6)
PASS	21-adoption-chain-break-HALT	HALT
PASS	22-spawn-child-SIGKILL-mid-promote	recover=RECOVERED ACTIVE=v-af389ca1b2c4689d504cb1e9b4a3a8d700acb6f22bf3882df1a5d175e22688b4
---
TOTAL	PASS=28	FAIL=4	SKIPPED=0
```

Exit code: **1** (any FAIL).

---

## Attack matrix → result

| # | Attack | Result | Notes |
|---|--------|--------|-------|
| 1 | Crash/recovery at every intent-without-done boundary | **PASS** (9 rewind + 3 builtin) | Roll-back before LOG; roll-forward after. ACTIVE always pure old or pure new. |
| 2 | Torn journal tail | **FAIL / BLOCKING** | See D1 |
| 3a | Pre-BEGIN stale expected_active_sha | **PASS** | `STALE_PROPOSAL`, no TX_BEGIN |
| 3b | Post-BEGIN hostile ACTIVE mutation | **PASS** | `HALT` + evidence; CLI maps HALT→exit 3 |
| 4 | Adoption-log terminal anchor + hash chain | **PASS** | effective after promote; aborted after abort; head matches |
| 5a | Doc rollback byte-exact | **PASS** | PRIOR tree id + learned.md bytes |
| 5b | Code/migration rollback refuse | **PASS** | `FORWARD_RECOVERY_REQUIRED` + human-forward-recovery text |
| 6 | GC + live-lease reader | **FAIL / BLOCKING** | See D2 |
| 7a | Crash after SWAP before WINDOW_FINAL | **PASS** | recover → OBSERVING |
| 7b | Promote while window open | **PASS** | `WINDOW_EXISTS` |
| 8a | Free-space preflight | **PASS** | `DISK_RESERVE` via stubbed `statfsSync` |
| 8b | Abandoned `.staging-*` on recover | **FAIL / MAJOR** | See D3 |
| 9 | Same-volume / unprovable FS | **PASS** | `PLATFORM_REFUSED` (dev mismatch + missing statfs) |
| + | Double recover / unfinished blocks / SIGKILL child | **PASS** | |
| + | Manifest records new tree | **FAIL / MINOR** | See D4 |
| + | Broken adoption chain | **PASS** | `HALT` |

---

## Defects

### D1 — Torn journal tail becomes unrecoverable CORRUPT_STATE **[BLOCKING]**

**Evidence:** case `04-torn-journal-tail-inspect-not-parse`.  
After `after-swap` crash, last journal line half-written (no trailing `\n`). Contract 01: *“Torn journal tail = record absent; the inspection rule still classifies the on-disk state.”*

`parseJsonl` alone *would* skip the torn last line. But `recover()` immediately `journalRecord(RECOVERY_BEGIN)` via `appendDurable`, which `writeSync`s the next JSON line **directly onto the torn bytes** (no leading `\n` seal, no truncate of the partial record). The glued line is no longer a “last torn line without newline” — it ends with `\n` after the recovery record — so subsequent parses throw `CORRUPT_STATE` and recovery aborts.

**Proposed fix:** Before any journal append (or at recover entry): if file non-empty and last byte ≠ `0x0A`, either (a) truncate back-to last `\n` (treat partial as absent), or (b) write a single `\n` repair only after verifying the prefix parses. Do not append JSON onto a non-terminated tail. Same discipline for adoption-log appends.

### D2 — Promotion GC + universal registry coupling is unimplemented **[BLOCKING]**

**Evidence:** case `10-GC-live-lease-tree-survives`; `scripts/promote.js` has zero references to `run-registry`, live-lease GC predicates, “last 2”, or rollback-eligible retention.

Contract 01 §GC: on a later promotion under the lock, delete trees only if not ACTIVE, not rollback-eligible previous, older than last 2, **and** zero live-lease registrations.

A fake long-lease registration on the prior tree “survives” only because **nothing is ever GC’d**. There is no positive proof of the quarantine.

**Proposed fix:** After successful TX_DONE (or as a post-commit step still under the lock, never mid-commit): list `v-*` trees; query state-store run-registry for live leases; retain ACTIVE + previous (rollback-eligible) + any live-leased tree_ids + last-2 policy; delete the rest; journal GC actions. Sweep expired registry leases first (state-store already can).

### D3 — Recover does not delete abandoned `.staging-*` trees **[MAJOR]**

**Evidence:** case `14-abandoned-staging-cleaned-on-recover`. Planted `.staging-<txid>/` + `TX_BEGIN` only. Recover emits `TX_ABORT` for the tx but leaves `.staging-*` on disk.

Contract 01 §Disk discipline: *“recovery deletes abandoned staging trees (typed lifecycle records)”*.

Recover only `rmSync`s `staged.tree` (`v-…`) when `STAGE_DONE` was journaled and ACTIVE ≠ that tree — never scans `.staging-*`.

**Proposed fix:** On recover (and promote catch paths): under evolvable/, remove any `.staging-*` not owned by an in-flight non-terminal tx that still needs it; journal `RECOVERY_STEP{action:"rm-abandoned-staging"}`.

### D4 — `updateProjectManifest` never writes tree identity **[MINOR]**

**Evidence:** case `20-manifest-update-omits-tree-field`; source:

```js
function updateProjectManifest(paths, pointer, head) {
  const manifest = readProjectManifest(paths);
  manifest.adoption_log_head = head;
  return manifest;
}
```

Contract 01 §Transitions step 6: *“project manifest updated (new tree, adoption_log_head = entry_sha)”*. Contract 09’s project-manifest shape does not define a `tree` field (ACTIVE holds the tree), so severity is MINOR / wording drift — but the transition text is not implemented if “new tree” was intentional.

**Proposed fix:** Either add an explicit `active_tree` / `active_txid` field to project manifest (schema + writers + sentinel) or reword contract 01 step 6 to “anchors terminal adoption entry only; tree is ACTIVE”.

---

## What passed (worth keeping)

- Full intent/DONE crash matrix via journal rewind + test-mode crash points: inspect-and-roll-forward is largely correct **when the journal is well-terminated**.
- Gate-4 coupling: post-SWAP pre-WINDOW_FINAL → recover finalizes to OBSERVING; promote enforces NO_WINDOW/`WINDOW_EXISTS`.
- CAS honesty: pre-BEGIN stale → clean ABORT; post-BEGIN hostile pointer rewrite → HALT hollow of silent overwrite.
- Adoption ledger: committing→effective/aborted, hash-linked, manifest head tracks terminal.
- Rollback: doc byte-exact via prior `source_tree`; code/migration hard-refuse with forward-recovery language.
- Disk/platform preflights exist and fire under stubs.
- SIGKILL child at LOG_APPEND_DONE + lease steal + recover left pure ACTIVE.

---

## Coverage / NOT tested

- Real cross-volume mounts (SMB/FAT); only `stat.dev` / deleted `statfsSync` stubs.
- Concurrent two-process writersholding distinct OS handles racing `ACTIVE` rename (simulated single-process hostile write vs true multi-proc TOCTOU).
- Power-loss between `fsync` of ACTIVE.tmp and rename (OS/page-cache bench).
- Sentinel PASS on staged tree (promote trusts `verifyTree` inventory only; no sentinel binary invoked).
- Journal compaction / adoption-log checkpoint anchors.
- Rollback during `ROLLING_BACK` races with observer slot disposal (Gate-4, mostly state-store lane).
- Legal-transition table enforcement against adversarial journal record order (schema ships `x-legal-transitions`; promote does not validate transitions).
- Windows MoveFileEx EPERM/EBUSY path under real open-handle holders.
- Quota policy preserving ACTIVE+rollback-eligible under intentional disk full mid-tree materialize (only preflight covered).
- Identity collision on pre-existing `v-<sha>` with divergent content after STAGE (rarer path logs HALT in code; not mutation-tested匀 here).

---

## Honest summary

`promote.js`’s happy path, most roll-forward/back boundaries, Gate-4 window pairing, CAS HALT posture, rollback refusal, and platform/disk preflights are real and suite-proven on disk. A **zero-defect** review is invalid: torn-tail recover is self-corrupting (**D1 BLOCKING**), GC is a pure no-op (**D2 BLOCKING**), staging GC is incomplete (**D3 MAJOR**), and manifest “new tree” language is dead (**D4 MINOR**). Fix D1 before any crash-harness claim on journal durability; fix D2 before any disk-reclaim claim involving live readers.
