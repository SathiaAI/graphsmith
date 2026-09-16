# C2 — Canonical Chain Validity

> **Status:** binding design contract for PR #33's crash-recovery/idempotency
> follow-up work. Referenced by commit 1 (lease keepalive scope), commit 3 (chain
> validator + `readChainTail`), commit 4 (`reconcileHead` + append-time check), and
> the existing status/health walk (`checks/register-gateway-sessions.js`). Locked by
> the 2026-09-15 fix-round panel (see
> `claude/graphsmith-fix-round-plan-round1-2026-09-15.md` in the GraphSmith project),
> including Paul's 2026-09-15 binding decisions on startup posture and mid-run
> lagging HEAD referenced throughout. Do not reopen without a new decision record.

This contract defines **one** canonical notion of "is the gateway-session chain
valid," to be used identically by three call sites that must never quietly diverge
on the definition of "valid":

1. **Startup reconciliation** (`chain.reconcileHead`, commit 4) — runs once, after
   `writerClaim.acquire()`, before the heartbeat starts and before anything else can
   append.
2. **The append-time check** (inside `chain.appendSession` /
   `chain.repairMissingChainEntry`, commit 4) — runs on the hot append path, cheap,
   checking only the tail against HEAD.
3. **The status/health walk** (`checks/register-gateway-sessions.js`'s
   `walkGatewaySessions`, existing) — runs periodically (currently piggybacked on
   the ~10s status-write timer) and reports operator-facing evidence.

Hash-and-link verification alone (each entry's `entry_sha256` recomputes, and each
entry's `prev_entry_sha256` matches the prior entry's `entry_sha256`) is **not
sufficient** to call a chain valid — a chain can be internally hash-consistent while
still containing sequence gaps, duplicate sequence numbers, a wrong genesis, or an
invalid interior shape. The validator below is the full check; no call site is
permitted to reimplement a subset of it under its own logic.

## 1. The canonical structural validator

Given `chain` (the ordered array of parsed `gateway-session-entry` records read from
`chain.jsonl`, schema `schemas/gateway-session-entry.schema.json`) and `head` (the
parsed contents of `HEAD.json`, or `null` if the file does not exist), a chain is
**valid** iff all of the following hold:

- **Per-record schema.** Every entry has exactly the five required fields
  (`schema_version`, `seq`, `bundle_id`, `prev_entry_sha256`, `entry_sha256`), no
  extra fields, `schema_version` equal to the current schema version, `bundle_id` a
  non-empty string, `prev_entry_sha256` either `null` or a 64-hex-char string, and
  `entry_sha256` a 64-hex-char string. (Mirrors `chain.js#entryShapeOk` and
  `register-gateway-sessions.js#entryShapeOk`, which must stay byte-for-byte
  identical checks — see §5.)
- **Valid integer seqs.** Every `seq` is a positive integer (`Number.isInteger`,
  `>= 1`). A non-integer, negative, zero, or non-numeric `seq` fails the record's
  own shape check above and is never reached by the contiguity check below.
- **Correct genesis seq and prev.** `chain[0].seq === 1` and
  `chain[0].prev_entry_sha256 === null`. Both conditions are required
  independently: a first entry with `seq > 1` and `prev_entry_sha256 === null`
  passes every other check (it hash-recomputes correctly, and there is no prior
  entry for a link check to compare against) while still being exactly the
  "missing genesis prefix" failure mode (e.g. a `chain.jsonl` truncated from the
  front) this rule exists to catch.
- **Contiguity.** For every `i > 0`, `chain[i].seq === chain[i-1].seq + 1`. A gap
  (e.g. seq 5 then seq 7) is reported as a **sequence gap**, distinct from a broken
  link, so an operator can tell "something was deleted" from "something was
  tampered with."
- **Uniqueness.** Contiguity from a fixed genesis already implies no two entries
  share a `seq` in a well-formed chain; an implementation that checks contiguity
  incrementally (as `register-gateway-sessions.js` does today) gets uniqueness for
  free and does not need a separate pass. An implementation must not weaken this by
  checking hash links alone.
- **Correct link hashes.** For every `i > 0`, `chain[i].prev_entry_sha256 ===
  chain[i-1].entry_sha256`. A mismatch is a **broken/mutated link**, distinct from a
  sequence gap.
- **Correct entry hashes.** For every entry, recomputing `entry_sha256` from its
  own other fields (`chain.js#computeEntrySha256`) reproduces the stored
  `entry_sha256`. A mismatch is a **TAMPERED entry**, distinct from a sequence gap,
  even when it happens to also break the next entry's link.
- **HEAD correctness.** `head` is present, shape-valid, and `head.seq ===
  tail.seq && head.bundle_id === tail.bundle_id && head.entry_sha256 ===
  tail.entry_sha256`, where `tail` is `chain[chain.length - 1]`. Divergence here
  is handled by the explicit cases in §2, not folded into a single boolean.

A validator that reports **valid** must have executed every one of the above
checks over the **entire** chain, not merely re-verified hashes locally around a
single edited record. This is what makes `chain[HEAD.seq - 1]` safe to index by any
caller afterward: a chain that has passed this whole validator cannot contain gaps
or duplicate seqs, so `seq - 1` really is that entry's array position.

## 2. Explicit behavior for each named state

Every call site listed above must implement — or delegate to a single shared
function that implements — exactly this behavior for each state. "Refuse" means:
throw/report failure and take no chain-mutating action; do not guess a repair.

| # | State | Behavior |
|---|---|---|
| 1 | **Both `chain.jsonl` and `HEAD.json` absent.** | Not a failure. This is the genesis-of-genesis state (no session has ever been appended). Reconciliation and the append-time check both short-circuit and perform **zero disk writes**. The status walk reports `not-applicable` ("empty gateway-session log — nothing to verify"), not `verified` and not `failed`. |
| 2 | **Empty chain with `HEAD.json` present.** | Refuse. `HEAD.json` names a tail but `chain.jsonl` has no entries to be that tail — this is incomplete/corrupt state (e.g. the chain file was lost or replaced), never treated as "empty chain, fine." |
| 3 | **`HEAD.json` malformed (unparseable JSON, or parses but fails `headShapeOk`).** | Refuse, **unless** the chain independently and fully validates (per §1) and the *lagging-HEAD* condition in row 7 below applies — a syntactically broken `HEAD.json` with a fully verified chain is one of the ways the lagging-HEAD case can present after a crash mid-write, and reconciliation must attempt that repair before giving up. If the chain itself does not fully validate, or `HEAD.json`'s content (once parsed) does not point at a genuine ancestor of the tail, refuse. |
| 4 | **`HEAD.json` missing entirely (distinct from malformed).** | Same disposition as row 3: reconciliation treats it as the lagging-HEAD case and attempts to rebuild `HEAD` from the verified tail; the append-time check and status walk refuse (they do not repair; only reconciliation, under the exclusive lease, is permitted to write `HEAD`). |
| 5 | **Equal `seq` with differing hash** (two entries, or `HEAD` and the entry it claims to be, share a `seq` but not an `entry_sha256`). | Refuse as a **fork**, always — this is never the lagging-HEAD case (row 7) and must never be auto-repaired. A fork means two candidate histories exist for the same position; picking one silently is exactly the split-brain outcome this contract exists to prevent. |
| 6 | **Invalid genesis** (`chain[0].seq !== 1`, or `chain[0].prev_entry_sha256 !== null`, or an otherwise malformed first record). | Refuse. Per §1, this is checked as a compound condition, not "hash recomputes so it's fine." |
| 7 | **Mid-run lagging HEAD: chain tail exactly one step ahead of a HEAD that is a genuine, hash-verified ancestor of that tail** (`tail.seq === head.seq + 1 && tail.prev_entry_sha256 === head.entry_sha256`, with the rest of the chain fully valid per §1). | **This is not corruption.** It is the signature of a crash between `appendSession`'s chain-append step and its HEAD-update step (or, at startup, the equivalent state found during reconciliation). Per Paul's 2026-09-15 decision: **auto-catch-up** — advance `HEAD` in place to the verified tail, emit a loud anomaly recording that the catch-up happened, and continue. This applies identically whether the state is found by the append-time check mid-run or by `reconcileHead` at startup. Anything worse than this exact single-step, hash-matching lag (multi-step lag, HEAD *ahead* of the tail, or a lag where the claimed ancestor does not actually hash-link to the tail) is **not** this case — it falls through to refuse-and-latch. |
| 8 | **Malformed interior record** (any entry other than the physical last line fails its shape check, or fails to `JSON.parse` at all). | Refuse, always, as chain corruption. Only the **final** record gets the torn-record accommodation in row 9 — an interior record can only be malformed through data loss or tampering, never through an in-flight crash (a crash can only ever be caught mid-write on the line being written *last*; every earlier line already completed its own open/write/fsync/close cycle before the process could move on to appending the next one). |
| 9 | **A torn/unparseable FINAL record.** | **Not corruption; the on-disk-tear counterpart of row 7, and must not be treated as unrecoverable.** A crash during `chain.jsonl`'s own append (as opposed to the later HEAD-update step covered by row 7) can leave a truncated, non-JSON-parseable last line. The last **complete** record — i.e. the one before the torn tail — is authoritative. Under the exclusive writer-claim lease, and only under that lease, isolate or truncate the torn final record and proceed as if the chain's tail were the last complete record. This determination must use a real, enforced `MAX_ENTRY_BYTES` bound when scanning backward/growing a read window to find the last complete line — not an assumption that entries are "typically" some size. A file with no newline boundary found within the capped window must fail closed (refuse) rather than fall back to reading the entire file into memory. This accommodation applies during startup reconciliation exactly as it would mid-run; there is no separate "torn tail is fine at startup but not mid-run" rule. |

## 3. Two failure classes stay distinct everywhere

Every message and every anomaly/evidence string produced by any of the three call
sites must make it possible for an operator to tell these two classes apart, per
row 5 vs. row 7/9 above:

- **Structural/integrity failure** (fork, tamper, sequence gap, invalid genesis,
  malformed interior record, HEAD ahead of a verified tail, or any lag that does
  not satisfy the exact single-step/hash-matching test in row 7): **refuse and
  latch.** This is genuine corruption or an adversarial condition; no call site
  repairs it silently, and it does not self-heal without an operator action
  (restore from backup, truncate at the last known-good entry, or manually rebuild
  `HEAD` — see the recovery runbook this contract's commits must ship alongside it,
  per Paul's startup-posture decision below).
- **Lagging-pointer / torn-tail catch-up** (rows 1, 3, 4, 7, 9 as scoped above):
  **repair and continue, loudly.** This is the expected shape of "the process died
  between two of its own writes," which the write ordering in `chain.js`'s own
  header comment exists specifically to make detectable-and-recoverable rather than
  silently accepted.

Conflating these two — treating every divergence as unrecoverable corruption, or
treating every divergence as silently fine — was independently flagged by every
reviewer of the pre-panel draft as the central defect to avoid.

## 4. Startup posture on a genuine structural-failure verdict

Per Paul's binding 2026-09-15 decision: when reconciliation (or the walk it runs
before the heartbeat starts) reaches a **structural/integrity failure** verdict
(§3, first bullet) at startup, the gateway must:

1. **Hard-fail startup.** Stop accepting new sessions / do not start the service.
   Nothing runs on top of confirmed corruption.
2. **Surface it loudly, not silently.** Emit a structured top-level error, exit
   with a clear non-zero exit code, and write a diagnostic artifact to disk (a
   status file does not require a running gateway).
3. **Point directly at the recovery runbook** (restore from backup /
   truncate-at-last-known-good / rebuild `HEAD` from the verified tail) so the
   diagnostic always ends in a concrete next step — never a stopped process with no
   documented way out.
4. **Release the writer-claim lease** on every initialization failure path, so a
   subsequent operator-run recovery command is not itself blocked by a lease this
   failed startup is still holding.

This posture applies only to a genuine structural-failure verdict. The
lagging-pointer/torn-tail states in §2 are, by definition, resolved by
reconciliation itself before this posture would ever trigger — they are not
"structural corruption" and must never route through this hard-fail path.

## 5. One implementation, not three copies

`chain.reconcileHead`, the append-time check inside `chain.appendSession` /
`chain.repairMissingChainEntry`, and `checks/register-gateway-sessions.js`'s
`walkGatewaySessions` must all call into the **same** structural-validation logic
for the checks in §1 (shared code, or, at minimum, provably identical hand-rolled
copies with a test that fails if they diverge — this codebase's own established
convention, per `chain.js#entryShapeOk` and
`register-gateway-sessions.js#entryShapeOk` already being intentionally-duplicated
but must-stay-identical). A commit that changes what "valid" means at one call site
without changing it identically at the other two violates this contract.

The three call sites differ only in **what they do with the verdict**:
reconciliation may repair (rows 1/3/4/7/9) and writes `HEAD`; the append-time check
never writes `HEAD` outside of `appendSession`'s own normal flow and, on rows 7/9,
performs the same in-place advance under the same lease; the status walk only
reports evidence and never writes anything.

## 6. Admission latch (commit 6)

`chain.getChainIntegrityFailure(): {status, class, reason, at} | null` is the single,
process-local surface every genuine structural failure this contract's detectors
(reconciliation and the append-time check, §1/§5) latch into. Deliberately a
detail-object accessor, never a bare `(): boolean` -- a boolean cannot carry the
diagnostic reason a human needs to act on.

**Primary enforcement point: session admission.** `GatewayProxy#openConnection`
consults `getChainIntegrityFailure()` first, before its existing
writer-claim-lost/draining check, and refuses every new session the instant it is
non-null. This is **belt-and-braces on top of the append-time check** (§1/§5), which
remains the primary correctness guarantee -- even a session that somehow got admitted
would still have its own eventual `chain.appendSession` refused. Refusing at
admission is what makes a **runtime** transition into failure behave identically to
detecting it at startup: nothing separate has to "notice" the latch and call a
stop-accepting method: the very next `openConnection` call already sees it.

**`recoverCrashedSessions` aborts immediately once latched.** If an earlier
connection's own repair path (`verifyAndRepairBundleCollision` ->
`checkHeadAgainstTailOrRepair`) latches a genuine failure partway through startup
recovery's per-connection loop, every connection not yet processed is guaranteed to
hit the identical failure the moment its own `chain.appendSession` runs -- the
corruption is a property of the shared chain, not of any one connection's WAL.
Continuing to parse and replay their WALs (with attendant fsyncs and lease renewals)
only to rediscover the same already-known failure is pure waste; this function checks
the latch once per loop iteration and stops instead, leaving their WAL/intent state
untouched for the next restart (or an explicit `recovery-abandon`).

**Classification, not a one-off exception list.** A failure only latches when it is
genuinely structural/content-level per §1/§3's own taxonomy (fork, tamper, sequence
gap, invalid genesis, malformed interior record, a lag worse than the single-step
case, or a tail `readChainTail` could open and read but that does not parse/shape-
check). An **operational** failure never latches:

- `readChainTail` failing to even **open** `chain.jsonl` with `EACCES`/`EPERM` (a
  misapplied or in-progress commit-2 group-readable chmod pass, or an operator's own
  filesystem-permission change) is refused for that one append
  (`GATEWAY_CHAIN_TAIL_UNREADABLE_OPERATIONAL`) but does **not** engage the latch --
  a permission problem says nothing about the chain's own integrity.
- `checks/register-gateway-sessions.js`'s own periodic status walk (run roughly every
  `STATUS_WRITE_INTERVAL_MS` by `gateway.js#writeStatusFile`) reports
  `session_chain_integrity` as **evidence only** and never writes to the latch at all,
  per §5's "one authoritative structural validator" contract -- its own missing-
  bundle-file finding (an operator archiving/moving a sealed bundle) is exactly the
  false positive this rule exists to keep out of the latch.

**Known limitation, stated here and in the written `gateway-status.json` itself**
(`session_chain_integrity_cadence_note`): because the status walk never latches, its
~10s cadence is not what stops admission on any finding. A HEAD/tail **pointer**
divergence is instead caught immediately by the append-time check. Mid-chain
**interior** corruption -- an entry whose own hash no longer recomputes, a sequence
gap, or a broken link, where HEAD and the chain's own tail already agree -- is
structurally invisible to that O(1), tail-only check; the status walk's own evidence
field may show it, but nothing currently *acts* on that evidence mid-run. Detecting
**and stopping admission for** that class depends on `reconcileHead`'s full walk
running again at the next startup (which hard-fails per §4), or on an explicit,
separately-scheduled deep walk that does not exist in this build.

## Summary (for code comments)

> Per `docs/contracts/chain-validity.md` (C2): one structural validator (seqs,
> genesis, contiguity, uniqueness, schema, link+entry hashes) used identically by
> reconciliation, the append-time check, and the status walk. A single-step,
> hash-matching HEAD lag (or its torn-final-record counterpart) is not corruption —
> auto-catch-up under the lease with a loud anomaly. Everything else refuses and
> latches. Structural failure at startup hard-fails loudly with a runbook pointer,
> per Paul's 2026-09-15 decision. The latch (`chain.getChainIntegrityFailure()`) is
> enforced primarily at session ADMISSION (`GatewayProxy#openConnection`), belt-and-
> braces on top of the append-time check; classified, not a one-off list -- an
> EACCES/EPERM opening chain.jsonl, or the status walk's own missing-bundle finding,
> is OPERATIONAL and never latches.
