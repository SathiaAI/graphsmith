#!/usr/bin/env node
/* GraphSmith reconciled-mode primitive (scripts/reconcile.js) — Lane A,
 * v0.5.0 Wave 1.
 *
 * Deterministic, zero-LLM, zero-dependency CommonJS, Node >= 18. No network
 * calls, no clock/randomness in any DECISION path (crypto.randomBytes is used
 * only to name a scratch temp file, never read back into a pass/fail branch;
 * Atomics.wait is used only for an opt-in, env-var-gated test stall — see
 * TEST-ONLY HOOK below, same posture as tests/_harness/deadline.js's
 * GRAPHSMITH_DEADLINE_SCALE).
 *
 * WHAT THIS IS
 *
 * schemas/host-adapter.schema.json's `placementMode: "reconciled"` names this
 * file directly: "the generator's rendered output for this adapter MUST be
 * handed to Lane A's reconciler and never written directly... Lane A's
 * reconciler currently assumes the target file supports HTML-comment markers
 * (<!-- -->) for its begin/end delimited block." This module is that
 * reconciler. It places one already-rendered block of text (produced by Lane
 * D from canonical SKILL.md — this file never reads SKILL.md and has no
 * opinion about how the block was rendered) into a single target file,
 * without disturbing anything else the target file may contain.
 *
 * It is a REUSABLE PRIMITIVE, not an AGENTS.md-specific tool: `blockId`
 * scopes each call to one marker-delimited region, so AGENTS.md, a future
 * CLAUDE.md, and .github/copilot-instructions.md (both v0.5.0 launch
 * reconciled targets per .plans/v0.5.0/WAVE-0-CANONICAL-SOURCE.md) all go
 * through this same function, and in principle several distinct blocks
 * (different blockIds) can coexist in one file without colliding.
 *
 * Ported from, and generalized beyond, microsoft/clarity-agent's
 * src/clarity_agent/setup/snippet.py `ensure_agents_md` (verified against
 * that source directly, not its README — see
 * claude/graphsmith-clarity-agent-oss-extraction-2026-07-30.md): a
 * marker-delimited begin/end block, a versioned meta header, and a four-way
 * state machine — file absent -> write; file present with no complete marker
 * pair for this blockId -> append; block present and byte-identical (body +
 * schema version) -> no-op; block present but drifted (hand edit, layout
 * change, or schema bump) -> splice only the marker-bounded region, leaving
 * everything else in the file untouched. clarity-agent keeps its version/mode
 * fields in a separate hidden `<!-- clarity-meta ... -->` comment; this
 * module folds the single field it actually needs (schema_version) into the
 * begin marker's own attributes instead, which removes a second marker line
 * to keep in sync and removes a second place drift could hide.
 *
 * MARKER FORMAT (HTML comments; see host-adapter.schema.json's documented
 * bound — this is known NOT to work for a target that cannot host an HTML
 * comment, e.g. JSON/TOML/YAML; no such target exists among v0.5.0's
 * reconciled adapters, and extending past Markdown requires a schema change
 * first, not a silent guess here):
 *
 *   <!-- graphsmith:begin id="<blockId>" schema_version="<N>" -->
 *   ...renderedBlock, verbatim, exactly one trailing newline...
 *   <!-- graphsmith:end id="<blockId>" -->
 *
 * Both marker lines must appear alone on their own line (anchored at column
 * 0) with this exact literal text and nothing else on the line. That is what
 * keeps a marker-LOOKALIKE string inside a user's own prose ("for example,
 * `<!-- graphsmith:begin id="x" schema_version="1" -->` mid-sentence") from
 * being misparsed as a real marker: an exact, whole-line, anchored match is
 * required, not a substring scan.
 *
 * SCHEMA-VERSION COMPATIBILITY (the "old reconciler vs. newer-spliced file,
 * and the reverse" adversarial case)
 *
 * `schemaVersion` is a property of the CALL (the version of the marker/body
 * contract the caller's renderedBlock conforms to), not of this file's own
 * released version — that is what lets one deployed reconcile.js serve a
 * caller asking for schema_version "1" today and "2" once a future format
 * change ships, and lets a test exercise both directions without needing two
 * copies of this module. Comparison is a plain integer compare of the
 * version already recorded in the file's begin marker against the version
 * the current call is asking for:
 *
 *   - recorded version <= call's version -> compatible; splice/no-op as
 *     normal, and the marker is re-stamped with the call's version.
 *   - recorded version >  call's version -> the file was already written by
 *     a LATER-schema reconciler than the one making this call. Silently
 *     overwriting it would mean guessing at a body format this call does not
 *     understand. Refused, no write, `reason: "future-schema-version"`.
 *
 * SYMLINK POLICY
 *
 * "resolve-once-trust-forever" is named in the Lane A brief as a known bug
 * class on this project. This function does not resolve a symlinked target
 * at all: `fs.lstatSync` on the target path (never `fs.statSync`, which
 * would follow it) is the only inspection performed, and a symlink at that
 * path is refused outright before anything is read or written -- not
 * followed, not written through, not silently replaced. This is a stricter
 * property than "the write cannot escape the tree" (which the atomic
 * temp-file-then-rename below would also give for free, since POSIX rename()
 * never follows a symlink at its destination path): a legitimate symlinked
 * target is left completely alone rather than being silently unlinked and
 * replaced by a plain file.
 *
 * ATOMICITY
 *
 * Every write in this module goes through atomicWriteFileSync(): write the
 * COMPLETE new file content to a scratch temp file in the same directory,
 * fsync it, then a single fs.renameSync() onto the real target path. A
 * process killed before the rename leaves the original target file (or its
 * absence) completely untouched; a same-filesystem rename is a single atomic
 * directory-entry update at the OS level and cannot itself produce a
 * half-written target. There is never a window where the target path holds
 * partial content.
 *
 * CONCURRENCY (two DIFFERENT blockIds racing on one file)
 *
 * Atomicity alone does not stop data loss: two concurrent reconcile() calls
 * against the same targetPath -- even for different blockIds, which the
 * module's own contract says "can coexist in one file without colliding" --
 * each read the file once, each compute a COMPLETE new file content
 * unaware of the other, and a plain atomic rename is a pure last-write-wins:
 * whichever rename lands second silently discards the other call's block,
 * with no error.
 *
 * REVISION HISTORY OF THIS FIX, stated honestly because the first attempt
 * was wrong and it matters why: the original version of this module tried
 * to solve this with optimistic concurrency control alone -- no lock, just
 * a `verifyUnchanged` callback re-checking the target's on-disk state
 * immediately before the install (rename/link), throwing
 * ConcurrentModificationError on mismatch so reconcile()'s retry loop could
 * re-read and retry. An independent, non-Anthropic three-model adversarial
 * review (Z.ai GLM-5.2, Google Gemini-3-Flash-Preview, DeepSeek-V4-Pro; see
 * claude/graphsmith-v0.5.0-wave1-status-and-adversarial-findings-2026-08-01.md,
 * "NEW: Lane A/D concurrency fix is incomplete", 2026-08-04) found, and a
 * standalone reproduction script confirmed, that this was still broken:
 * `verifyUnchanged()` and the subsequent rename/link are two separate
 * syscalls, not one atomic unit, so two concurrent writers can BOTH call
 * `verifyUnchanged()` and BOTH get `true` (because neither has installed
 * yet, so the file each of them reads is still the original), and then
 * both install -- the second one silently discarding the first, with the
 * first writer's `atomicWriteFileSync()` call returning a completely
 * normal, no-error, successful byte count. The OCC approach reduced the
 * probability of the original bug (a large window -> a few-syscalls-wide
 * window) without eliminating it, and no "tighten the check further"
 * variant of a check-then-act pattern can eliminate it -- that is a
 * structural property of check-then-act, not a bug in one particular
 * implementation of it.
 *
 * THE ACTUAL FIX: a real mutex. `reconcile()` acquires an exclusive,
 * sibling lock file (targetPath + LOCK_SUFFIX) via the SAME atomic
 * test-and-set primitive `atomicWriteFileSync`'s `createOnly` path already
 * relies on elsewhere in this file (`fs.openSync(lockPath, "wx")`, which
 * fails with EEXIST if another holder already has it) BEFORE doing
 * anything else, and holds it for the ENTIRE read-decide-write critical
 * section, releasing it in a `finally` no matter how that section exits.
 * With the lock held, nothing else using this module can even read
 * targetPath's state until the lock is released, so there is no window --
 * of any width -- for two callers to both act on a stale read. The
 * `verifyUnchanged` CAS check described below is retained as a defensive
 * invariant assertion (it should now always pass, since only the lock
 * holder can be touching targetPath), not as the primary safety mechanism.
 *
 * Two new failure modes come with a real lock, handled explicitly rather
 * than ignored: (1) a process that dies while holding the lock would
 * deadlock every future caller forever -- handled by lock staleness: a
 * lock file older than LOCK_STALE_MS is assumed abandoned and forcibly
 * reclaimed (see acquireLock() below for the exact mechanism and its own
 * revision history); (2) legitimate contention under load -- handled by a
 * bounded retry-with-backoff acquire loop (LOCK_ACQUIRE_MAX_ATTEMPTS),
 * throwing a loud, explicit LockAcquisitionError rather than hanging
 * forever if it's exhausted.
 *
 * SECOND REVISION (2026-08-04, same day, second pass): the first version of
 * (1) above -- unlink the stale lock, then re-create -- was found, by the
 * same three-model adversarial review process applied to the lock fix
 * itself, to have the identical check-then-act shape as the ORIGINAL bug
 * this whole lock exists to close (see claude/graphsmith-v0.5.0-wave1-
 * status-and-adversarial-findings-2026-08-01.md, "NEW #2"). acquireLock()'s
 * own docstring below documents the three-layer fix (atomic-rename reclaim,
 * verify-after-acquire, verify-before-commit) in full; the property it
 * provides is deliberately weaker than "two callers can never simultaneously
 * believe they hold the lock" (nothing without a heartbeat can guarantee
 * that) and instead is the property that actually matters: at most one
 * caller's WRITE to targetPath, per acquisition, ever commits. A caller
 * whose lock is reclaimed always finds out before it writes (LockLostError),
 * never after.
 *
 * `atomicWriteFileSync()` accepts an optional `verifyUnchanged` callback
 * that runs immediately before the install (after the new content is
 * already fsynced, and after the `verifyLockHeld` check below) and
 * re-checks that the target's on-disk state still matches what this call
 * read at the START of its attempt. If it does not, the install is skipped
 * and a ConcurrentModificationError is thrown instead of overwriting;
 * reconcile()'s retry loop catches that, re-reads the now-current file,
 * recomputes the block placement against the fresh content, and retries,
 * up to MAX_CONCURRENT_ATTEMPTS times. With the lock now serializing every
 * caller, this should never actually fire from another graphsmith-reconcile
 * caller; it remains as a loud, "fail rather than guess" invariant check,
 * same posture as the future-schema-version refusal above. `verifyLockHeld`
 * is the LAYER 3 check from acquireLock()'s docstring -- checked first, and
 * throws the distinct LockLostError (not caught/retried by reconcile(),
 * unlike ConcurrentModificationError) if this call's lock was reclaimed out
 * from under it.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { writeReport } = require("./write-report.js");

// The default schema_version a caller gets if it does not pass one. Bump
// this, and document why, only when the marker/body CONTRACT itself changes
// in a way an old reconciler could not safely splice over (see the
// SCHEMA-VERSION COMPATIBILITY note above). It is NOT this file's package
// version and NOT GraphSmith's release version — those change for reasons
// unrelated to this one narrow contract.
const DEFAULT_SCHEMA_VERSION = "1";

// Bounded retry budget for the optimistic-concurrency-control loop (see the
// CONCURRENCY note above): 1 initial attempt + up to 6 retries. Comfortably
// inside the "small bounded retry count" this is meant to be -- each retry
// only fires when another process/thread's write is caught landing between
// this attempt's read and its rename, which real contention resolves in one
// or two retries in practice. Exhausting the budget means something is
// writing to targetPath continuously/pathologically fast; reconcile() fails
// loud in that case rather than looping forever or guessing.
const MAX_CONCURRENT_ATTEMPTS = 7;

// Sibling lock file suffix (see CONCURRENCY note above). A dotfile with the
// same "graphsmith-reconcile" prefix atomicWriteFileSync()'s scratch temp
// files use, so a `.graphsmith-reconcile-lock.<basename>` next to a target
// file is immediately recognizable as this module's own bookkeeping if a
// developer ever spots one on disk.
const LOCK_SUFFIX_PREFIX = ".graphsmith-reconcile-lock.";

// A lock file older than this is assumed to belong to a process that died
// (crashed, was SIGKILLed, or the machine lost power) while holding it,
// rather than one that is still legitimately working -- this repo's own
// CI jobs and local `reconcile()` calls complete in well under a second
// even under heavy load, so 30s is a wide margin, not a tight guess.
// Overridable via GRAPHSMITH_RECONCILE_LOCK_STALE_MS, same posture as
// GRAPHSMITH_DEADLINE_SCALE (tests/_harness/deadline.js) and the two
// TEST-ONLY stall hooks below: a test that deliberately SIGKILLs a
// lock-holding child (a SIGKILL skips this module's `finally` release,
// same as it skips any other JS cleanup) needs staleness to kick in on a
// test-appropriate timescale, not production's 30s. Normal runs never set
// this and get the safe default.
const DEFAULT_LOCK_STALE_MS = 30000;
function lockStaleMs() {
  const raw = process.env.GRAPHSMITH_RECONCILE_LOCK_STALE_MS;
  if (!raw) return DEFAULT_LOCK_STALE_MS;
  const ms = Number(raw);
  return Number.isFinite(ms) && ms > 0 ? ms : DEFAULT_LOCK_STALE_MS;
}

// Bounded retry-with-backoff budget for ACQUIRING the lock (distinct from
// MAX_CONCURRENT_ATTEMPTS, which bounds retries of the read-decide-write
// body once the lock is already held). 40 attempts at a ~15ms base delay
// covers real contention (this repo's own concurrent-caller tests run
// several reconcile() calls back-to-back against the same file) well
// within a second, while still failing loud instead of hanging forever if
// something is holding the lock pathologically long.
const LOCK_ACQUIRE_MAX_ATTEMPTS = 40;
const LOCK_ACQUIRE_RETRY_MS = 15;

const BLOCK_ID_RE = /^[a-z][a-z0-9-]*$/; // same shape as host-adapter.schema.json's `id`
const SCHEMA_VERSION_RE = /^[0-9]+$/;

// A line terminator that recognizes "\r\n" and "\n" (bare "\n" and CRLF).
// DOCUMENTED, BOUNDED GAP (contract-10-style honest language, not a silent
// overclaim): a lone "\r" with no following "\n" (classic pre-OS-X Mac line
// endings) will not be recognized as a line boundary by JavaScript regex
// "^"/"$" under the "m" flag, so a marker line terminated only by a bare "\r"
// will not be detected as a marker. Every reconciled-mode adapter target in
// this project is a plain UTF-8 Markdown file GraphSmith itself renders with
// "\n" or accepts as ordinary "\n"/"\r\n" text from a user's editor; a
// lone-"\r" file has not been observed and is not claimed to be handled.
const LINE_END = "(?:\\r\\n|\\n|$)";

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Guards against the CONTENT-EMBEDS-A-MARKER case, distinct from the
// marker-lookalike-in-surrounding-prose case the exact anchored beginRegex/
// endRegex above already handle safely. A caller's renderedBlock is not
// under this module's control (it is Lane D's rendered output) and could
// itself contain a line that is, verbatim, `<!-- graphsmith:begin ... -->`
// or `<!-- graphsmith:end ... -->` -- for example because SKILL.md
// documents this exact marker format elsewhere in the canonical source, and
// a future edit echoes that documentation into a rendered block. If such a
// line were embedded as-is, a later findBlock() scan over the FILE (which
// has no way to distinguish "a real delimiter" from "delimiter-shaped text
// that happens to be this block's own body") could match that lookalike
// line as the closing marker instead of the real one, silently truncating
// the block and orphaning everything after it on every subsequent
// reconcile call. Anchored the same way beginRegex/endRegex are (line
// start, "m" flag) but deliberately broader than either -- ANY blockId,
// ANY schema_version, begin OR end -- because a lookalike for a different
// id is exactly as corrupting to a naive scanner as one for this call's own
// id.
const MARKER_LOOKALIKE_RE = /^<!-- graphsmith:(?:begin|end)\b.*$/m;

/**
 * Refuse loudly (never guess, never silently corrupt) if `body` contains a
 * line that could be mistaken for a real graphsmith marker once embedded.
 * This is the same posture as Lane D's generator refusing to embed a raw
 * newline in a YAML frontmatter scalar: fail at the point where the caller
 * can actually do something about it (fix the canonical source), not later
 * when a naive marker scan silently truncates the block.
 */
function assertNoMarkerLookalike(body) {
  const m = MARKER_LOOKALIKE_RE.exec(body);
  if (m) {
    throw new TypeError(
      "reconcile: renderedBlock contains a line that looks like a graphsmith " +
        `marker (${JSON.stringify(m[0])}) and cannot be safely embedded as block ` +
        "body content -- a future marker scan could match this lookalike line " +
        "instead of the real begin/end delimiter and silently truncate the block. " +
        "Refusing to write anything; fix the rendered block so no line at column 0 " +
        'starts with "<!-- graphsmith:begin" or "<!-- graphsmith:end".'
    );
  }
}

function assertValidBlockId(blockId) {
  if (typeof blockId !== "string" || !BLOCK_ID_RE.test(blockId)) {
    throw new TypeError(`reconcile: blockId must match ${BLOCK_ID_RE} (got ${JSON.stringify(blockId)})`);
  }
}

function assertValidSchemaVersion(schemaVersion) {
  if (typeof schemaVersion !== "string" || !SCHEMA_VERSION_RE.test(schemaVersion)) {
    throw new TypeError(`reconcile: schemaVersion must be a non-negative integer string (got ${JSON.stringify(schemaVersion)})`);
  }
}

function beginRegex(blockId) {
  return new RegExp(`^<!-- graphsmith:begin id="${escapeRegExp(blockId)}" schema_version="([0-9]+)" -->[ \\t]*${LINE_END}`, "m");
}

function endRegex(blockId) {
  return new RegExp(`^<!-- graphsmith:end id="${escapeRegExp(blockId)}" -->[ \\t]*${LINE_END}`, "m");
}

function beginLine(blockId, schemaVersion) {
  return `<!-- graphsmith:begin id="${blockId}" schema_version="${schemaVersion}" -->\n`;
}

function endLine(blockId) {
  return `<!-- graphsmith:end id="${blockId}" -->\n`;
}

/** Ensure renderedBlock ends with exactly one trailing newline, so a block
 * this module writes and later re-extracts round-trips to the identical
 * string regardless of whether the caller's renderedBlock already had one. */
function normalizeBody(renderedBlock) {
  if (typeof renderedBlock !== "string") {
    throw new TypeError(`reconcile: renderedBlock must be a string (got ${typeof renderedBlock})`);
  }
  return renderedBlock.endsWith("\n") ? renderedBlock : renderedBlock + "\n";
}

function buildBlock(blockId, schemaVersion, body) {
  assertNoMarkerLookalike(body);
  return beginLine(blockId, schemaVersion) + body + endLine(blockId);
}

/**
 * Find the first COMPLETE begin/end marker pair for `blockId` in `raw`
 * (already BOM-stripped). Returns null when there is no complete pair --
 * that covers "no markers at all", "a lookalike string that doesn't match
 * the exact anchored format", and the malformed "a begin marker with no
 * matching end, or two begins before one end" cases alike. All of those are
 * treated identically and safely: as "append a fresh block", never as
 * "guess how to repair the existing one". Nothing already in the file is
 * ever deleted by that fallback.
 */
function findBlock(raw, blockId) {
  const bre = beginRegex(blockId);
  const beginMatch = bre.exec(raw);
  if (!beginMatch) return null;

  const bodyStart = beginMatch.index + beginMatch[0].length;
  const tail = raw.slice(bodyStart);

  const ere = endRegex(blockId);
  const endMatch = ere.exec(tail);
  if (!endMatch) return null; // begin with no matching end -> not a valid block

  // Reject ambiguity: a second begin for this same id appearing before the
  // end we just found means the file is already malformed for this blockId
  // (e.g. a half-applied hand edit). Fail open to "no valid block" rather
  // than guess which begin the end belongs to.
  const secondBegin = bre.exec(tail.slice(0, endMatch.index));
  if (secondBegin) return null;

  const bodyEnd = bodyStart + endMatch.index;
  const blockEnd = bodyStart + endMatch.index + endMatch[0].length;

  return {
    blockStart: beginMatch.index,
    blockEnd,
    schemaVersion: beginMatch[1],
    body: raw.slice(bodyStart, bodyEnd),
  };
}

// ---------------------------------------------------------------------------
// TEST-ONLY HOOK: an opt-in, env-var-gated synchronous stall inserted between
// "the new complete content is fsynced to a scratch temp file" and "the
// rename that makes it visible at the target path". Exists so a test can
// deterministically kill this process mid-operation and assert the target
// path was never left partially written -- reproducing a real SIGKILL
// without relying on timing luck. Inert unless GRAPHSMITH_RECONCILE_TEST_
// STALL_MS is set to a positive number, exactly the posture
// tests/_harness/deadline.js documents for its own env-var knob: normal runs
// never read this and are unaffected. Atomics.wait is the same synchronous-
// sleep primitive scripts/write-report.js already uses for its EAGAIN
// backoff, not a novel mechanism introduced here.
// ---------------------------------------------------------------------------
function testStallBeforeRenameIfRequested() {
  syncSleepFromEnv("GRAPHSMITH_RECONCILE_TEST_STALL_MS");
}

// Same synchronous-sleep primitive, factored out so the new lock-hold test
// hook (below) can reuse it without duplicating the SharedArrayBuffer +
// Atomics.wait dance. Still the same mechanism scripts/write-report.js
// already uses for its own EAGAIN backoff -- not novel.
function syncSleep(ms) {
  const ia = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(ia, 0, 0, ms);
}

function syncSleepFromEnv(envVar) {
  const raw = process.env[envVar];
  if (!raw) return;
  const ms = Number(raw);
  if (!Number.isFinite(ms) || ms <= 0) return;
  syncSleep(ms);
}

// ---------------------------------------------------------------------------
// TEST-ONLY HOOK #2: an opt-in, env-var-gated synchronous stall inserted
// immediately AFTER the lock is acquired and BEFORE it is released. Exists
// so a test can deterministically prove the lock actually excludes a second
// caller (start process A, let it acquire and stall while holding the
// lock, start process B and confirm B blocks/retries until A's stall ends
// and A releases) rather than relying on OS scheduling luck to even attempt
// to produce contention. Inert unless
// GRAPHSMITH_RECONCILE_TEST_LOCK_HOLD_MS is set to a positive number; same
// posture as TEST-ONLY HOOK #1 above.
// ---------------------------------------------------------------------------
function testStallWhileHoldingLockIfRequested() {
  syncSleepFromEnv("GRAPHSMITH_RECONCILE_TEST_LOCK_HOLD_MS");
}

/**
 * Thrown by atomicWriteFileSync() when its `verifyUnchanged` callback
 * reports that targetPath's on-disk state moved between this call's read
 * and its rename -- i.e. another process/thread won the race. With the
 * lock (below) now serializing every caller, this is retained as a "fail
 * loud rather than silently guess" invariant check, not the primary
 * safety mechanism -- see the CONCURRENCY note in the module docstring for
 * why OCC alone was not sufficient. A distinct class (rather than a plain
 * Error) so that catch site can't accidentally swallow an unrelated error
 * from the same try block.
 */
class ConcurrentModificationError extends Error {}

/**
 * Thrown by acquireLock() when LOCK_ACQUIRE_MAX_ATTEMPTS is exhausted
 * without acquiring targetPath's lock -- i.e. some other process has held
 * it continuously, and not staled out, for the entire retry budget. A
 * distinct class so callers can tell "I could not even start" apart from
 * ConcurrentModificationError ("I started, then lost a race") and from
 * reconcile()'s own retry-budget-exhausted Error.
 */
class LockAcquisitionError extends Error {}

/**
 * Thrown by reconcile() when the lock this call was holding is discovered,
 * at the last possible checkpoint immediately before the target file's
 * write commits, to no longer belong to this call -- see LAYER 3 in
 * acquireLock()'s docstring below. Deliberately NOT caught by reconcile()'s
 * own ConcurrentModificationError retry loop: retrying would mean doing
 * more work while not holding the lock, which is exactly the unsafe
 * behavior this class exists to prevent. A distinct class from both
 * LockAcquisitionError ("I could never even start") and
 * ConcurrentModificationError ("the target's content moved under a
 * same-lock-holder's own retry, not a lock-ownership problem").
 */
class LockLostError extends Error {}

function lockPathFor(targetPath) {
  const dir = path.dirname(targetPath);
  return path.join(dir, `${LOCK_SUFFIX_PREFIX}${path.basename(targetPath)}`);
}

// A short random token, unique per acquireLock() call, written into the
// lock file's own content alongside pid/timestamp. Identity by CONTENT
// (this exact token), not by path or pid: a path can be reoccupied by an
// unrelated holder, and a pid can be reused by the OS after the original
// process exits -- neither is safe to treat as "still means the same
// holder" the way a fresh random token is. See LAYER 2/3 below for why
// this needs to survive a re-read, not just a one-time compare.
function lockOwnershipToken() {
  return crypto.randomBytes(12).toString("hex");
}

function lockContentFor(token) {
  return `pid=${process.pid} acquired=${Date.now()} token=${token}\n`;
}

/** Re-read lockPath RIGHT NOW and confirm it still carries `token` --
 * the single primitive LAYER 2 and LAYER 3 below both build on. Treats any
 * read failure (lock gone, directory gone, permission changed mid-run) the
 * same as "not ours anymore": false, never throws -- a lock this call
 * cannot even confirm it holds is not safely held. */
function lockCurrentlyOwnedByToken(lockPath, token) {
  let current;
  try {
    current = fs.readFileSync(lockPath, "utf8");
  } catch (_) {
    return false;
  }
  return current.indexOf(`token=${token}`) !== -1;
}

/**
 * Acquire an exclusive, cross-process mutex on `targetPath`. Blocks (via
 * bounded synchronous retry-with-backoff, not a busy-spin) until acquired,
 * a stale lock is reclaimed, or LOCK_ACQUIRE_MAX_ATTEMPTS is exhausted.
 *
 * REVISION HISTORY, stated honestly because the first version of this
 * function was itself wrong and it matters why (same posture as the
 * module-level CONCURRENCY note above, applied one level deeper): the
 * first lock-based fix reclaimed a stale lock via `fs.unlinkSync(lockPath)`
 * followed by a fresh `wx`-create, guarded only by a per-call
 * "attempted reclaim once" flag. An independent, non-Anthropic three-model
 * adversarial review (Z.ai GLM-5.2, Google Gemini-3-Flash-Preview,
 * DeepSeek-V4-Pro; see claude/graphsmith-v0.5.0-wave1-status-and-
 * adversarial-findings-2026-08-01.md, "NEW #2", 2026-08-04) found, and this
 * project reproduced directly against the real shipped code, that this was
 * itself the SAME check-then-act shape as the ORIGINAL bug the whole lock
 * exists to close: caller A's `statSync` (deciding a lock is stale) and
 * caller A's later `unlinkSync` are two separate syscalls, so a different,
 * genuinely live caller B could reclaim that exact same stale lock and
 * create its own fresh one in between -- and A's unlink would then delete
 * B's live lock, not the stale one A inspected, letting both A and B
 * believe they held the lock simultaneously.
 *
 * THE FIX, in three layers, none sufficient alone:
 *
 * LAYER 1 -- reclaim via atomic RENAME, never unlink-then-create. A
 * reclaimer writes ITS OWN lock content (with a fresh, unique per-call
 * token -- see lockOwnershipToken()) to a private scratch file, then
 * `fs.renameSync(scratch, lockPath)`. POSIX rename onto an existing path is
 * a single atomic directory-entry swap: there is categorically no instant
 * where lockPath is absent for a third caller's `wx`-create to slip into.
 * This alone makes the ORIGINAL reproduced bug (a live caller's lock
 * deleted by an unlink race) structurally impossible -- this module now
 * never unlinks a lock file it does not itself currently own.
 *
 * LAYER 2 -- verify-after-acquire. Immediately after EITHER a fresh
 * `wx`-create OR a reclaim-rename succeeds, re-read the lock file
 * (lockCurrentlyOwnedByToken) and confirm it still carries the token this
 * call just wrote. If not, some other caller's rename landed in the -- now
 * syscall-adjacent, not multi-step -- gap between our write and our read;
 * loop and retry from fresh state rather than proceed believing we hold
 * something we do not.
 *
 * LAYER 3 -- verify-before-commit, implemented in reconcile()/
 * attemptReconcile()/atomicWriteFileSync() below, not in this function:
 * a SEPARATE re-check of token ownership immediately before the actual
 * write to targetPath commits, catching the one case Layers 1-2 cannot --
 * a reclaimer legitimately, by this module's own staleness rules, taking
 * over LATER, mid-critical-section, if this call's hold genuinely outlives
 * the staleness threshold. Nothing without a heartbeat can PREVENT that
 * from happening. What Layer 3 guarantees instead is the property that
 * actually matters: the caller whose lock was reclaimed out from under it
 * always finds out BEFORE its write commits (throwing LockLostError), so
 * at most one caller's write per acquisition ever lands on disk. See
 * reconcile() and atomicWriteFileSync() below.
 *
 * Returns `{ lockPath, token }`. Pass both to releaseLock(); pass `token`
 * through to the write path for Layer 3.
 */
function acquireLock(targetPath) {
  const lockPath = lockPathFor(targetPath);
  const dir = path.dirname(targetPath);
  const token = lockOwnershipToken();
  const ownContent = lockContentFor(token);
  let attemptedStaleReclaimThisRound = false;

  for (let attempt = 1; attempt <= LOCK_ACQUIRE_MAX_ATTEMPTS; attempt++) {
    fs.mkdirSync(dir, { recursive: true });
    try {
      const fd = fs.openSync(lockPath, "wx", 0o644);
      try {
        fs.writeSync(fd, Buffer.from(ownContent, "utf8"));
      } finally {
        fs.closeSync(fd);
      }
      // LAYER 2 (create path): a reclaimer's rename could in principle land
      // in the gap between our write+close and this read -- vanishingly
      // narrow (adjacent syscalls, nothing else runs in between), but
      // checked, not assumed.
      if (lockCurrentlyOwnedByToken(lockPath, token)) {
        return { lockPath, token }; // acquired
      }
      continue; // lost it already -- retry from scratch, do not assume ownership
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      // Someone else holds it (or held it and is gone). Check staleness.
      let lockStat = null;
      try {
        lockStat = fs.statSync(lockPath);
      } catch (_) {
        // Lock vanished between our failed create and this stat (the
        // holder just released it, or another reclaimer's rename already
        // ran) -- loop straight back around to retry the create, no sleep
        // needed, this is the common fast-path case under contention.
        continue;
      }
      const ageMs = Date.now() - lockStat.mtimeMs;
      if (ageMs > lockStaleMs() && !attemptedStaleReclaimThisRound) {
        attemptedStaleReclaimThisRound = true; // at most one reclaim attempt per stale sighting, not a tight loop
        // LAYER 1: reclaim via atomic rename, never unlink. Write our own
        // content to a private scratch file first, then atomically swap it
        // onto lockPath -- whatever is currently there (the stale lock we
        // inspected, or -- if we are wrong -- a live caller's lock) is
        // replaced in one directory-entry update; lockPath is never absent.
        const scratchPath = `${lockPath}.reclaim.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
        try {
          const scratchFd = fs.openSync(scratchPath, "wx", 0o644);
          try {
            fs.writeSync(scratchFd, Buffer.from(ownContent, "utf8"));
            fs.fsyncSync(scratchFd);
          } finally {
            fs.closeSync(scratchFd);
          }
          fs.renameSync(scratchPath, lockPath);
        } catch (e2) {
          try {
            fs.unlinkSync(scratchPath);
          } catch (_) {
            /* best-effort cleanup; original error is what matters */
          }
          throw e2;
        }
        // LAYER 2 (reclaim path): confirm our rename is what is actually
        // there now -- another caller's reclaim-rename of the SAME
        // just-inspected stale lock could have landed first.
        if (lockCurrentlyOwnedByToken(lockPath, token)) {
          return { lockPath, token }; // acquired
        }
        continue; // someone else's rename won the reclaim race; retry from scratch
      }
      syncSleep(LOCK_ACQUIRE_RETRY_MS);
    }
  }
  throw new LockAcquisitionError(
    `reconcile: could not acquire lock for ${targetPath} after ${LOCK_ACQUIRE_MAX_ATTEMPTS} attempts ` +
      `(~${LOCK_ACQUIRE_MAX_ATTEMPTS * LOCK_ACQUIRE_RETRY_MS}ms) -- another process/thread has held ` +
      `${lockPath} continuously and it never staled out (< ${lockStaleMs()}ms old on every check)`
  );
}

/** Release a lock acquired by acquireLock(). Only unlinks if `token` (the
 * exact token this call was given by acquireLock()) still owns the lock
 * file right now -- if a reclaimer legitimately (by this module's own
 * staleness rules) took over mid-hold, unlinking unconditionally here
 * would delete the NEW owner's live lock instead of this call's own
 * already-lost one. `token` is optional (omit to force an unconditional
 * unlink, e.g. test/operator cleanup of a lock this caller never itself
 * held) -- callers inside this module always pass it. Best-effort either
 * way: a failed read/unlink here (lock already gone) is not this call's
 * failure to report. */
function releaseLock(lockPath, token) {
  if (token !== undefined && !lockCurrentlyOwnedByToken(lockPath, token)) {
    return; // no longer ours -- nothing to release, see doc above
  }
  try {
    fs.unlinkSync(lockPath);
  } catch (_) {
    /* best-effort, see doc above */
  }
}

/**
 * Write `content` to `targetPath` atomically: full content to a scratch temp
 * file in the same directory, fsync, then a single rename (or, for
 * `createOnly`, a single link) onto the target. Never opens `targetPath`
 * itself for writing, so a symlink or any other existing object at that
 * path is replaced as a whole name-table entry (POSIX rename semantics),
 * never written through.
 *
 * `verifyLockHeld`, if given, is called with no arguments FIRST, before
 * `verifyUnchanged` -- this is LAYER 3 from acquireLock()'s docstring: the
 * last possible checkpoint proving this call's cross-process lock is still
 * actually held before its write commits. If it returns false, the install
 * is skipped, the scratch temp file is cleaned up, and LockLostError is
 * thrown -- deliberately NOT the same class as ConcurrentModificationError,
 * since reconcile()'s retry loop must not retry a call that no longer holds
 * the lock (see LockLostError's own doc comment).
 *
 * `verifyUnchanged`, if given, is called with no arguments immediately
 * before the install (same point as the TEST-ONLY stall hook above, and
 * after the stall hook if both are active). If it returns false, the
 * install is skipped, the scratch temp file is cleaned up, and a
 * ConcurrentModificationError is thrown instead -- see the CONCURRENCY note
 * in the module docstring.
 *
 * `createOnly`, if true, installs via `fs.linkSync(tmpPath, targetPath)`
 * instead of `fs.renameSync`. Unlike rename (which always succeeds and
 * silently REPLACES an existing destination), link() is an atomic
 * test-and-set at the OS level: it fails with EEXIST if targetPath now
 * exists, with no gap for a second, equally-fast concurrent creator to slip
 * through between a check and the install the way a `verifyUnchanged`
 * read-then-write pair unavoidably has one. This closes the one case
 * (both callers racing to CREATE the same absent target) where that narrow
 * general-purpose gap was observed to be reachable in practice; the two
 * dangling directory entries link() leaves behind (tmpPath and targetPath,
 * same inode) are reconciled by unlinking tmpPath once link() succeeds.
 */
function atomicWriteFileSync(targetPath, content, verifyUnchanged, createOnly, verifyLockHeld) {
  const dir = path.dirname(targetPath);
  const tmpPath = path.join(
    dir,
    `.graphsmith-reconcile.${path.basename(targetPath)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  const buf = Buffer.from(content, "utf8");
  const fd = fs.openSync(tmpPath, "wx", 0o644);
  try {
    let off = 0;
    while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    testStallBeforeRenameIfRequested();
    // LAYER 3 (see acquireLock()'s docstring): checked first, before the
    // target-content CAS below -- if the lock itself is gone, there is no
    // point asking whether the target's content is still what we expect.
    if (verifyLockHeld && !verifyLockHeld()) {
      throw new LockLostError(
        `reconcile: the lock for ${targetPath} was lost before this write could commit -- another caller ` +
          "reclaimed it while this call was still active (see LAYER 3 in acquireLock()'s docstring); aborting " +
          "without writing rather than committing under a lock this call no longer holds"
      );
    }
    if (verifyUnchanged && !verifyUnchanged()) {
      throw new ConcurrentModificationError(`reconcile: concurrent modification detected for ${targetPath}`);
    }
    if (createOnly) {
      try {
        fs.linkSync(tmpPath, targetPath);
      } catch (e) {
        if (e.code === "EEXIST") {
          throw new ConcurrentModificationError(`reconcile: concurrent modification detected for ${targetPath}`);
        }
        throw e;
      }
      // link() succeeded -- targetPath is correctly installed. tmpPath is now
      // a second directory entry for the SAME inode; remove it best-effort.
      // A failure here is a cleanliness issue only, never a correctness one,
      // so it must not be reported as this call's own failure.
      try {
        fs.unlinkSync(tmpPath);
      } catch (_) {
        /* best-effort */
      }
    } else {
      fs.renameSync(tmpPath, targetPath);
    }
  } catch (e) {
    try {
      fs.unlinkSync(tmpPath);
    } catch (_) {
      /* best-effort cleanup (already gone in the createOnly success path,
       * or never existed to begin with on some other failure); the
       * original error is the one that matters */
    }
    throw e;
  }
  return buf.length;
}

function baseResult(status, targetPath, blockId, schemaVersion, extra) {
  return Object.assign(
    {
      status, // "created" | "appended" | "unchanged" | "spliced" | "refused"
      path: targetPath,
      blockId,
      schemaVersion,
    },
    extra || {}
  );
}

/**
 * Place `renderedBlock` into `targetPath` under marker `blockId`, per the
 * four-way state machine documented at the top of this file.
 *
 * @param {string} targetPath absolute or relative path to the surface file
 *   (e.g. "AGENTS.md", ".github/copilot-instructions.md")
 * @param {string} renderedBlock the already-rendered block text (Lane D's
 *   output). This function does not transform it beyond ensuring exactly one
 *   trailing newline.
 * @param {object} options
 * @param {string} options.blockId stable id for this block, e.g. an adapter
 *   id (`^[a-z][a-z0-9-]*$`). Scopes marker matching so multiple distinct
 *   blocks can coexist in one file.
 * @param {string} [options.schemaVersion] non-negative integer string; the
 *   schema version of the marker/body contract this call's renderedBlock
 *   conforms to. Defaults to DEFAULT_SCHEMA_VERSION.
 * @returns {object} a result with at least {status, path, blockId,
 *   schemaVersion}; `status: "refused"` results also carry `reason` and
 *   never write anything.
 * @throws {LockAcquisitionError} if the cross-process lock on targetPath
 *   cannot be acquired within LOCK_ACQUIRE_MAX_ATTEMPTS -- see the
 *   CONCURRENCY note in the module docstring. Nothing is read or written in
 *   that case.
 * @throws {LockLostError} if this call's lock is discovered, immediately
 *   before the write commits, to have been reclaimed by another caller --
 *   see LAYER 3 in acquireLock()'s docstring. Nothing is written in that
 *   case; the caller lost the lock, not the race to write with it held.
 * @throws {Error} if MAX_CONCURRENT_ATTEMPTS is exhausted because the
 *   verifyUnchanged invariant check keeps failing after the lock is already
 *   held (should not happen in practice -- see CONCURRENCY note). Nothing
 *   is left partially written in that case; the target is exactly as some
 *   attempt left it.
 */
function reconcile(targetPath, renderedBlock, options) {
  if (typeof targetPath !== "string" || targetPath.length === 0) {
    throw new TypeError("reconcile: targetPath must be a non-empty string");
  }
  const opts = options || {};
  const blockId = opts.blockId;
  assertValidBlockId(blockId);
  const schemaVersion = opts.schemaVersion == null ? DEFAULT_SCHEMA_VERSION : String(opts.schemaVersion);
  assertValidSchemaVersion(schemaVersion);
  const desiredBody = normalizeBody(renderedBlock); // validates renderedBlock is a string too

  // Acquire the cross-process mutex BEFORE reading anything -- see the
  // CONCURRENCY note in the module docstring for why the OCC-only approach
  // this replaced was insufficient. Held for the entire read-decide-write
  // critical section below, released in `finally` no matter how it exits.
  const { lockPath, token } = acquireLock(targetPath);
  try {
    testStallWhileHoldingLockIfRequested();
    for (let attempt = 1; attempt <= MAX_CONCURRENT_ATTEMPTS; attempt++) {
      try {
        return attemptReconcile(targetPath, blockId, schemaVersion, desiredBody, lockPath, token);
      } catch (e) {
        if (!(e instanceof ConcurrentModificationError)) throw e;
        // With the lock held, another graphsmith-reconcile caller cannot be
        // mid-write here -- this invariant check firing would mean
        // targetPath moved under an actor OUTSIDE this module's lock
        // discipline. Loop around and recompute from fresh state anyway,
        // rather than assume that can't happen. (LockLostError is a
        // different class and is NOT caught here -- see its own doc.)
      }
    }
    throw new Error(
      `reconcile: exceeded ${MAX_CONCURRENT_ATTEMPTS} retries due to concurrent modification of ${targetPath} ` +
        "even while holding the reconcile lock -- something outside this module's lock discipline is writing " +
        "to this target"
    );
  } finally {
    releaseLock(lockPath, token);
  }
}

/**
 * One attempt at the four-way state machine: read targetPath's current
 * state, decide created/appended/unchanged/spliced/refused, and (for the
 * three write outcomes) install the new content with a CAS check against
 * this SAME attempt's snapshot immediately before the rename. Throws
 * ConcurrentModificationError -- caught and retried by reconcile() above --
 * if that check fails; never partially writes. `lockPath`/`token` identify
 * the cross-process lock this attempt is running under (from acquireLock())
 * and are threaded into every atomicWriteFileSync() call's `verifyLockHeld`
 * -- LAYER 3, see acquireLock()'s docstring -- so a lock reclaimed mid-hold
 * is caught immediately before commit rather than after.
 */
function attemptReconcile(targetPath, blockId, schemaVersion, desiredBody, lockPath, token) {
  const verifyLockHeld = () => lockCurrentlyOwnedByToken(lockPath, token);
  let lst = null;
  try {
    lst = fs.lstatSync(targetPath);
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }

  if (lst) {
    if (lst.isSymbolicLink()) {
      return baseResult("refused", targetPath, blockId, schemaVersion, { reason: "symlink-refused" });
    }
    if (!lst.isFile()) {
      return baseResult("refused", targetPath, blockId, schemaVersion, { reason: "target-not-a-file" });
    }
  }

  // ---- STATE: absent -> write ----
  if (!lst) {
    const dir = path.dirname(targetPath);
    fs.mkdirSync(dir, { recursive: true });
    const content = buildBlock(blockId, schemaVersion, desiredBody);
    // createOnly: true -- targetPath must still be absent when this
    // installs, or a concurrent call (possibly for a different blockId)
    // created it first and this write would silently discard that call's
    // block. Uses fs.linkSync's atomic EEXIST-on-conflict semantics rather
    // than a separate lstat-then-rename check, which would leave a real
    // (if narrow) gap for two equally-fast concurrent creators -- see
    // atomicWriteFileSync's `createOnly` doc above.
    const bytesWritten = atomicWriteFileSync(targetPath, content, null, /* createOnly */ true, verifyLockHeld);
    return baseResult("created", targetPath, blockId, schemaVersion, { bytesWritten });
  }

  // Confirmed finding (2026-08-04 adversarial review, GLM-5.2 + Gemini-3-
  // Flash-Preview independently, reproduced by this project directly): lst
  // above proves the target existed at THAT instant, but an actor outside
  // this module's lock discipline (a human `rm`, an unrelated tool) could
  // still delete it in the gap before this read. Previously this threw an
  // uncaught, non-retried ENOENT straight out of attemptReconcile(),
  // crashing the whole reconcile() call instead of gracefully falling back
  // to the same "absent -> create" path a fresh attempt would take. Now
  // handled explicitly: caught, and re-dispatched to the exact same create
  // logic used when lst was null from the start, rather than guessing at
  // stale content or leaving the caller to deal with a raw fs error.
  let rawWithBom;
  try {
    rawWithBom = fs.readFileSync(targetPath, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    const dir = path.dirname(targetPath);
    fs.mkdirSync(dir, { recursive: true });
    const content = buildBlock(blockId, schemaVersion, desiredBody);
    const bytesWritten = atomicWriteFileSync(targetPath, content, null, /* createOnly */ true, verifyLockHeld);
    return baseResult("created", targetPath, blockId, schemaVersion, { bytesWritten });
  }
  const hasBom = rawWithBom.charCodeAt(0) === 0xfeff;
  const bom = hasBom ? String.fromCharCode(0xfeff) : "";
  const raw = hasBom ? rawWithBom.slice(1) : rawWithBom;

  // CAS check for the two write outcomes below (appended, spliced): the
  // full file content (BOM included) must still be byte-identical to
  // rawWithBom, captured above, right before the rename. Any divergence --
  // a concurrent call's own write, the file being deleted, replaced by a
  // symlink, etc. -- fails the check and triggers a retry from fresh state.
  const verifyUnchanged = () => {
    let current;
    try {
      current = fs.readFileSync(targetPath, "utf8");
    } catch (_) {
      return false;
    }
    return current === rawWithBom;
  };

  const found = findBlock(raw, blockId);

  // ---- STATE: present, no complete marker pair for this blockId -> append ----
  if (!found) {
    const blockText = buildBlock(blockId, schemaVersion, desiredBody);
    // Preserve every existing byte; only decide how much separation to add
    // before the new block. Trim trailing blank lines/whitespace from the
    // existing content's end, then join with exactly one blank line, unless
    // the file was empty.
    const trimmedRaw = raw.replace(/[ \t\r\n]+$/, "");
    const newRaw = trimmedRaw.length === 0 ? blockText : `${trimmedRaw}\n\n${blockText}`;
    const bytesWritten = atomicWriteFileSync(targetPath, bom + newRaw, verifyUnchanged, false, verifyLockHeld);
    return baseResult("appended", targetPath, blockId, schemaVersion, { bytesWritten });
  }

  const foundVersionNum = Number(found.schemaVersion);
  const callVersionNum = Number(schemaVersion);

  // ---- REFUSAL: file already carries a block from a schema newer than this
  // call understands. Splicing over it would mean guessing at a body format
  // this call was never told about. ----
  if (foundVersionNum > callVersionNum) {
    return baseResult("refused", targetPath, blockId, schemaVersion, {
      reason: "future-schema-version",
      foundSchemaVersion: found.schemaVersion,
    });
  }

  // ---- STATE: present, block current (same version, byte-identical body) -> no-op ----
  if (foundVersionNum === callVersionNum && found.body === desiredBody) {
    return baseResult("unchanged", targetPath, blockId, schemaVersion, { bytesWritten: 0 });
  }

  // ---- STATE: present, block drifted (older version, or same version but
  // different body -- a schema bump or a hand edit inside the markers) ->
  // splice only the marker-bounded region in place. ----
  const blockText = buildBlock(blockId, schemaVersion, desiredBody);
  const newRaw = raw.slice(0, found.blockStart) + blockText + raw.slice(found.blockEnd);
  const bytesWritten = atomicWriteFileSync(targetPath, bom + newRaw, verifyUnchanged, false, verifyLockHeld);
  return baseResult("spliced", targetPath, blockId, schemaVersion, {
    bytesWritten,
    previousSchemaVersion: found.schemaVersion,
  });
}

// ---------------------------------------------------------------------------
// CLI (secondary surface; the exported `reconcile` function is the primary
// one Lane D's generator calls in-process). Reads the rendered block from a
// file or stdin so this can be exercised/spot-checked without writing a
// throwaway Node script.
// ---------------------------------------------------------------------------

function readAllStdinSync() {
  const chunks = [];
  const buf = Buffer.alloc(65536);
  for (;;) {
    let n;
    try {
      n = fs.readSync(0, buf, 0, buf.length, null);
    } catch (e) {
      if (e.code === "EAGAIN") continue;
      if (e.code === "EOF") break;
      throw e;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buf.slice(0, n)));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--target" && argv[i + 1]) out.target = argv[++i];
    else if (argv[i] === "--block-id" && argv[i + 1]) out.blockId = argv[++i];
    else if (argv[i] === "--schema-version" && argv[i + 1]) out.schemaVersion = argv[++i];
    else if (argv[i] === "--input" && argv[i + 1]) out.input = argv[++i];
  }
  return out;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  try {
    if (!opts.target || !opts.blockId || !opts.input) {
      process.stderr.write(
        "Usage: node scripts/reconcile.js --target <path> --block-id <id> --input <file|-> [--schema-version <n>]\n"
      );
      process.exit(2);
      return;
    }
    const renderedBlock = opts.input === "-" ? readAllStdinSync() : fs.readFileSync(opts.input, "utf8");
    const result = reconcile(opts.target, renderedBlock, {
      blockId: opts.blockId,
      schemaVersion: opts.schemaVersion,
    });
    writeReport(JSON.stringify(result, null, 2) + "\n");
    process.exit(result.status === "refused" ? 1 : 0);
  } catch (e) {
    process.stderr.write(`Error: ${e && e.message ? e.message : String(e)}\n`);
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  DEFAULT_SCHEMA_VERSION,
  DEFAULT_LOCK_STALE_MS,
  reconcile,
  ConcurrentModificationError,
  LockAcquisitionError,
  LockLostError,
  // Exported for white-box testing, same convention as scripts/verify.js
  // exporting its own internal helpers (sha256Hex, verifyFileList, ...).
  findBlock,
  buildBlock,
  normalizeBody,
  atomicWriteFileSync,
  lockPathFor,
  lockCurrentlyOwnedByToken,
  acquireLock,
  releaseLock,
};
