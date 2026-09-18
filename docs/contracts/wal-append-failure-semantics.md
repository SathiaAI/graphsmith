# C1 — WAL Append-Failure Semantics

> **Status:** binding design contract for PR #33's crash-recovery/idempotency follow-up
> work. Referenced by commit 1 (lease keepalive), commit 5 (sampling `CALL_RESULT`
> fail-closed), and any future code that calls `recovery.appendWalEvent` or reads a
> connection WAL. Locked by the 2026-09-15 fix-round panel (see
> `claude/graphsmith-fix-round-plan-round1-2026-09-15.md` in the GraphSmith project);
> do not reopen items 1-5 below without a new decision record.

This contract governs `scripts/gateway/recovery.js#appendWalEvent` (and its private
helpers `appendDurableLine`/`writeFullySync`) and every caller of it. It exists
because the original PR #33 follow-up plan modeled a WAL append failure as "nothing
was written" and built retry/recovery logic on that assumption; three independent
reviewers (Fable, GPT-6 Astra, Grok-4.6) found the assumption false and cross-agreed
on why. This document is the corrected model.

## 1. A throw from `appendWalEvent` means UNKNOWN persistence, not absence

`appendWalEvent` is `ensureDir` → `openSync(path, "a", 0o600)` → `writeFullySync`
(loops `writeSync` until every byte is written) → `fsyncSync` → `closeSync` →
`fsyncDir`. A caller that catches a throw from this call **must not** assume the
event was not durably recorded. Exactly three outcomes are possible, and they are
indistinguishable from the caller's stack frame alone:

1. **Nothing was written.** The `openSync` or the first `writeSync` failed before
   any bytes landed (e.g. `ENOSPC`, `EROFS` at open time).
2. **A torn/partial line was written.** `writeFullySync`'s own truncate-on-stall
   path (see its header comment in `recovery.js`) tries to undo a partial write by
   `ftruncateSync`-ing back to the pre-append size, but that truncate is itself a
   filesystem call and can fail (the exact failure mode this contract exists to
   cover). A torn line can therefore remain on disk after the throw.
3. **The line was written completely, and a later step failed.** `fsyncSync` (data)
   or the caller's own subsequent `fsyncDir` can throw *after* `writeFullySync` has
   already returned successfully and the complete line is sitting in the file
   (possibly not yet durable across a real crash, but present and syntactically
   valid to any reader that opens the file right now).

Because outcome 3 is possible, **a "failed append" and "the event was not recorded"
are not the same fact.** Any code that decides what to tell a downstream caller, or
what to write into an in-memory session record, must say "not confirmed durable,"
never "not recorded" or "discarded."

## 2. On any append failure, the connection's WAL is poisoned in memory

The moment `appendWalEvent` throws for a given `connectionId`, that connection's
in-memory session state must be marked **poisoned** (a boolean or reason string on
the session record is sufficient) and **every subsequent call to
`appendWalEvent` for that same connection must be refused before it touches the
filesystem** — the caller should treat the refusal exactly like a second append
failure (see §3), without re-attempting the write.

Rationale: per §1 outcome 2, the file may already end in an unterminated, torn JSON
line. `readWalEvents`' replay contract (`recovery.js`, see its header comment) is
"stop at the first line that fails to `JSON.parse`, keep everything before it" —
which exists precisely because a crash can only tear the *last* line in flight.
That contract silently assumes nothing is ever appended to the file again after a
tear. If a second, unrelated append is allowed to proceed on a torn WAL, its bytes
concatenate directly onto the torn line, and the result is a single malformed line
that swallows both the original partial content and the new event — the new event
is now unparseable too, and is lost to replay along with everything the caller
believed it just durably recorded. Poisoning the connection converts "silently lose
a real event" into "loudly refuse further writes on this connection," which is the
correct fail-closed direction.

The poison flag is in-memory only and connection-scoped. It is not written to disk,
does not affect any other connection's WAL, and clears when the connection is
closed/reopened (a new connection gets a fresh WAL file and a fresh poison state).

## 3. No best-effort second append after a possible tear

Do not attempt a second, best-effort `appendWalEvent` call to record an error
result (or anything else) after the first append for that event already failed —
neither immediately, nor later on the same poisoned connection. This reverses an
earlier draft of the plan, which proposed a best-effort second append "for the
error CALL_RESULT" so that in-memory state and on-disk replay state would agree.

Two independent, cross-confirmed failure modes make that unsafe:

- **Concatenation onto a torn line** (§2): the second append can land directly
  after an unterminated line from the first attempt, corrupting both.
- **Two conflicting terminal records for the same correlation key.** If the first
  append actually completed (§1 outcome 3) and only a later fsync step threw, a
  second append for the *same logical event* — even an "error" record instead of
  the original "success" record — creates two `CALL_RESULT` lines on disk for one
  correlation key: one recording success, one recording failure. Replay then has
  two candidate terminal records for the same call, and which one "wins" was left
  unspecified by the earlier draft. §4 defines that resolution rule now, but the
  conflict itself is avoidable simply by never attempting the second write.

The correct sequence when an append fails is: mark the connection poisoned (§2),
record the caller-facing outcome (e.g. a JSON-RPC error to the downstream caller)
and the in-memory session state, and stop. Do not touch the WAL again for that
connection.

## 4. Replay conflict rule for terminal records

`readWalEvents` can, despite §2-3, still encounter two `CALL_RESULT` events for the
same correlation key on legitimate historical WALs (e.g. a build that predates this
contract, or any other path that ever produced a duplicate before this rule
existed). Replay must resolve that deterministically:

> **First complete `CALL_RESULT` per correlation key wins.** Every later
> `CALL_RESULT` for the same correlation key is treated as a duplicate: it is not
> applied to the replayed session state, and it is recorded as an anomaly (not
> silently dropped and not silently preferred over the first one).

"Complete" here means the record parsed successfully as JSON and passed its own
shape check — i.e. it is one of the events `readWalEvents` returns at all (a torn
line never reaches this rule because it stops the read before ever producing an
event for that line, per its own stop-at-first-bad-line contract).

This rule must be implemented once, in whatever function replays a connection's WAL
into session state, and covered by a test that constructs exactly this state (two
complete `CALL_RESULT` events for one correlation key) and asserts: the replayed
session reflects the first one, the second is present in the anomaly list, and
replay does not throw.

## 5. `discarded_result_sha256`: exact attempted bytes, or omit the field

When code records that a result could not be durably written (e.g. the sampling
`CALL_RESULT` fail-closed path), it may attach a `discarded_result_sha256` field so
a later auditor can correlate "the agent produced X" with "the gateway withheld X."
That field is only trustworthy under one rule:

> **Hash the exact serialized buffer that was attempted for the WAL append** (the
> same `Buffer`/string passed to `writeFullySync`/`appendDurableLine`), **or omit
> the field entirely.** Never hash a fresh `JSON.stringify(resultObject)` call made
> after the fact for the sole purpose of populating this field.

Rationale: `JSON.stringify` output depends on object key insertion order, which is
not guaranteed to be stable across two separate serializations of "the same"
logical object (a field added, reordered, or populated by a different code path on
a retry can silently change the byte string while the object's meaning is
unchanged). A digest computed from a *second*, independent serialization is
therefore not a reliable commitment to what was actually attempted on disk — it can
disagree with the real attempted bytes for reasons that have nothing to do with the
result's content. If the exact attempted buffer is not available in scope where the
digest is computed, the field must be left off the record rather than populated
with a digest of something else. A missing field is honest; a digest of the wrong
bytes is not.

## Summary (for code comments)

> Per `docs/contracts/wal-append-failure-semantics.md` (C1): a WAL append throw
> means unknown persistence, not absence. Poison the connection on failure; never
> retry. Replay keeps the first complete terminal record per correlation key.
> `discarded_result_sha256` hashes the exact attempted buffer or is omitted.
