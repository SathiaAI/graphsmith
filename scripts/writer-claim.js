#!/usr/bin/env node
/* GraphSmith's writer-claim: a standing, process-lifetime claim to be the single
 * attesting writer for a state directory.
 *
 * This is a SEPARATE mechanism from state-store.js's `state.lock` -- deliberately not a
 * reuse of it. `state.lock` is a per-transaction lease, held only for the duration of
 * one mutation's critical section and released immediately after. A writer-claim is
 * held for the whole life of the process, checked once at startup and renewed on a
 * slow heartbeat independent of `state.lock`'s renewal, so that a process doing no
 * mutations for an extended period does not appear to have abandoned its writer
 * status (FR-2). It reuses `state-store.js`'s already-adversarially-reviewed atomic
 * file-creation/overwrite primitives and pid-liveness check (NFR-2) rather than
 * inventing new ones, at this coarser scope.
 *
 * See .plans/v0.5.0/GATEWAY-MULTI-INSTANCE-HANDOFF.md, TRD FR-1..FR-4 / NFR-1..NFR-3 /
 * AC-1..AC-4, schema §8.2 (mirrored exactly in schemas/state-store.schema.json's
 * `writerClaim` $def) for the full design this file implements (Phase 0 only).
 *
 * THE CROSS-HOST DESIGN CHOICE, STATED PLAINLY (danger 2 in the handoff doc, §4):
 *
 * `state.lock`'s staleness check compares `Date.now()` on THIS host against an mtime
 * the OS wrote -- meaningful only because both are the same host's clock. If two
 * instances are pointed at the same state directory over shared/networked storage
 * (NFS, a shared volume -- a plausible operator shortcut), that comparison becomes
 * meaningless: a PID that is "alive" on host B says nothing about a process on host A,
 * and cross-host clock skew can trivially exceed any tolerance tuned for one machine's
 * filesystem-timestamp granularity.
 *
 * So this mechanism does NOT attempt cross-host staleness arithmetic at all. A claim
 * record carries the host that wrote it (`host_id`); when a claim's `host_id` differs
 * from the acquiring process's own host, acquisition refuses UNCONDITIONALLY --
 * regardless of the claim's apparent age -- rather than guess whether it is stale under
 * a clock relationship that cannot be trusted (AC-2). Same-host staleness (crash
 * recovery on a restart of the SAME machine) is still supported, using the claim
 * record's own self-reported `renewed_at` field (not a filesystem mtime) plus a local
 * pid-liveness check, mirroring the two-gate + future-mtime-tolerance pattern
 * `state-store.js`'s `_acquireLock` already carries -- retargeted at a self-reported
 * timestamp instead of an OS-written one, and behind its own, separately-scoped
 * tolerance constant (never `LOCK_CLOCK_SKEW_TOLERANCE_MS` unchanged; see the buildplan
 * doc §3 for why reusing that constant here would be wrong).
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { writeReport } = require("./write-report.js");
const stateStore = require("./state-store.js");

const SCHEMA_VERSION = "1.0";
const CLAIM_FILE = "writer-claim.json";
const CLAIM_DEF = "writerClaim";

/* Independent of state-store.js's DEFAULT_HEARTBEAT_MS (FR-2: "independent of the
 * existing per-mutation state.lock renewal"). */
const DEFAULT_HEARTBEAT_MS = 15000;
/* A same-host claim is considered abandoned after this many missed heartbeats without
 * a renewal. Not shared with state-store.js's DEFAULT_LEASE_MS -- this budget is about
 * "has this writer stopped heartbeating", not about a mutation's lease. */
const DEFAULT_MISSED_HEARTBEATS_STALE = 3;
/* Tolerance for a same-host claim's self-reported `renewed_at` sitting slightly ahead
 * of this host's own clock (filesystem-timestamp-granularity-equivalent for a value
 * this process itself will have written moments earlier). Deliberately a DIFFERENT
 * constant from state-store.js's LOCK_CLOCK_SKEW_TOLERANCE_MS -- that one is scoped in
 * its own comment to local filesystem mtime granularity, not to be reused unchanged
 * for a different clock relationship (buildplan doc §3). This one governs only
 * same-host renewed_at comparisons, never a cross-host one -- cross-host always
 * refuses unconditionally, see the module header. */
const CLAIM_CLOCK_SKEW_TOLERANCE_MS = 5000;

function fail(message, code = "WRITER_CLAIM_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function randomToken() {
  return crypto.randomBytes(16).toString("hex");
}

function defaultHostId() {
  const name = os.hostname();
  /* Fail closed (NFR-1), not "unknown-host": CodeRabbit review (PR #27) found that a
   * shared literal fallback converts the cross-host refusal in decideOnExisting into
   * same-host staleness arithmetic whenever os.hostname() is empty on two different
   * hosts that share a state directory -- record.host_id !== ctx.localHostId becomes
   * false for both, so a foreign live claim becomes stealable once its self-reported
   * renewed_at looks stale, instead of being refused unconditionally per AC-2. There is
   * no safe synthetic host_id to invent here that couldn't collide the same way, so this
   * throws and asks the caller to supply one explicitly instead. */
  if (typeof name !== "string" || name.length === 0) {
    throw fail(
      "Cannot determine this host's identity (os.hostname() returned no usable value). " +
      "A writer-claim cannot be acquired safely without a host_id, because the AC-2 " +
      "cross-host refusal depends on it being a reliable, distinguishing signal -- a " +
      "shared placeholder would make two different hosts with unset hostnames look like " +
      "the same host. Pass an explicit { hostId } instead.",
      "WRITER_CLAIM_NO_HOST_ID"
    );
  }
  return name;
}

function claimPath(stateDir) {
  return path.join(stateDir, CLAIM_FILE);
}

/* Read + schema-validate the claim on disk, or null if there is none. Any parse/schema
 * failure is reported as CORRUPT_CLAIM rather than swallowed -- NFR-1 fail-closed: an
 * ambiguous claim record must never be treated as "no claim, safe to acquire". */
function readClaimFile(stateDir) {
  const target = claimPath(stateDir);
  let raw;
  try { raw = fs.readFileSync(target, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
  let record;
  try { record = JSON.parse(raw); }
  catch (error) { throw fail(`Invalid JSON in ${CLAIM_FILE}: ${error.message}`, "CORRUPT_CLAIM"); }
  try { return stateStore.validateNamedRecord(record, CLAIM_DEF, CLAIM_FILE); }
  catch (error) { throw fail(`Invalid ${CLAIM_FILE}: ${error.message}`, "CORRUPT_CLAIM"); }
}

/* The acquisition decision for an OBSERVED existing claim record, isolated as a pure
 * function so it can be pinned by tests without spinning up real processes or files.
 * Returns { outcome: "own" | "steal" | "refuse", code?, detail? }. */
function decideOnExisting(record, ctx) {
  if (record.host_id !== ctx.localHostId) {
    /* CodeRabbit review (PR #27, follow-up round): this cross-host gate (AC-2) must run
     * BEFORE the instance_id branch below, not after it. instance_id is caller-supplied
     * (options.instanceId), so it can coincide across two hosts sharing a state
     * directory (NFS, a shared volume) -- by accident or by a malicious/misconfigured
     * caller. record.pid is also meaningless across hosts (see module header): a
     * foreign host's pid number is essentially never a live local process, so
     * stateStore.pidAlive(record.pid) reliably reads as "not alive" for a foreign
     * claim. With the instance_id branch checked first, that combination -- matching
     * instance_id + a foreign pid this host can't see as alive -- fell through to
     * "own", silently adopting the foreign host's claim_token and producing exactly
     * the two-attesting-writer condition this module exists to prevent, defeating the
     * AC-2 unconditional-refusal guarantee entirely. Checking host_id first makes that
     * unreachable: no combination of instance_id or pid can ever bypass this refusal.
     * No staleness arithmetic is attempted for a foreign host either -- see the module
     * header for why. */
    return { outcome: "refuse", code: "WRITER_CLAIM_FOREIGN_HOST" };
  }

  if (record.instance_id === ctx.localInstanceId) {
    /* CodeRabbit review (PR #27): instanceId is caller-supplied (options.instanceId),
     * so two DIFFERENT live processes started with the same explicit instanceId both
     * reach this branch. Treating that as the idempotent same-process re-acquire path
     * lets the second process adopt the first's claim_token and act as attesting
     * writer too -- the exact two-writer condition this module exists to prevent. The
     * record's pid distinguishes them: a foreign, live pid under a matching
     * instance_id is a real conflict, not a re-acquire. Both records are already known
     * same-host here (the host_id gate above ran first), so pid-liveness is a
     * meaningful signal at this point. */
    if (record.pid !== ctx.localPid && stateStore.pidAlive(record.pid)) {
      return { outcome: "refuse", code: "WRITER_CLAIM_HELD" };
    }
    return { outcome: "own" };
  }

  const age = ctx.now - record.renewed_at;   // > 0 => renewed_at is in the past (normal)
  const future = age < 0;                     // renewed_at sits ahead of local now
  const ownerAlive = stateStore.pidAlive(record.pid);

  // Owner death is decisive at any offset, mirroring state-store.js's own hard-won
  // fix for the "future mtime wedges a dead owner forever" defect.
  if (future && !ownerAlive) return { outcome: "steal" };
  if (future && age < -ctx.skewToleranceMs) return { outcome: "refuse", code: "WRITER_CLAIM_CLOCK_SKEW" };

  const unrenewed = age > ctx.staleAfterMs;
  if (ownerAlive && !unrenewed) return { outcome: "refuse", code: "WRITER_CLAIM_HELD" };
  if (!ownerAlive && !unrenewed) return { outcome: "refuse", code: "WRITER_CLAIM_HELD" };
  return { outcome: "steal" };
}

function refusalMessage(record, code, localHostId) {
  const ageDescr = `pid ${record.pid}`;
  if (code === "WRITER_CLAIM_FOREIGN_HOST") {
    return (
      `Refusing to start: GraphSmith enforces exactly one attesting writer per state ` +
      `directory (single-writer constraint). The writer-claim at this state directory ` +
      `was written by host "${record.host_id}", not this host ("${localHostId}") -- the ` +
      `claim is held by instance ${record.instance_id} on a DIFFERENT host. This can ` +
      `mean genuine multi-instance operation (not supported in this version) or two ` +
      `instances pointed at the same state directory over shared/networked storage, ` +
      `under which mtime/wall-clock staleness cannot be trusted across hosts. Refusing ` +
      `unconditionally rather than guess.`
    );
  }
  if (code === "WRITER_CLAIM_CLOCK_SKEW") {
    return (
      `Refusing to start: the writer-claim at this state directory names instance ` +
      `${record.instance_id} on this same host ("${localHostId}"), renewed at a time ` +
      `that is in the FUTURE relative to this process's clock, beyond the tolerance for ` +
      `ordinary timestamp granularity. This is a CLOCK SKEW, not a busy writer: check ` +
      `for a backward time correction or a resumed VM. Refusing while ${ageDescr} is ` +
      `still observably alive rather than risk two writers.`
    );
  }
  return (
    `Refusing to start: GraphSmith enforces exactly one attesting writer per state ` +
    `directory (single-writer constraint). A live, actively-renewed writer-claim is ` +
    `already held by instance ${record.instance_id} on host "${record.host_id}" (${ageDescr}). ` +
    `This is NOT a generic lock-contention error -- another GraphSmith writer instance ` +
    `is already attesting for this state directory. If that instance is not actually ` +
    `running, stop it, or remove the claim file after confirming no writer holds it.`
  );
}

class WriterClaim {
  constructor(stateDir, options = {}) {
    /* Same breadcrumb StateStore writes as the FIRST statement of its own constructor,
     * before any validation -- and for the same reason: a source scan for `new
     * WriterClaim(` cannot see through the worker script this mechanism's own
     * shared-storage suite spawns. See state-store.js's recordLeaseClockConstruction --
     * this is a SEPARATE mechanism from StateStore (see the module header above) that
     * never constructs one, so StateStore's breadcrumb is structurally blind to this
     * class; reusing the function gives this class the identical proof rather than a
     * second, divergent one. Ordering matters: adversarial review (correctness-2) found
     * that recording this after instanceId validation meant an invalid-instanceId
     * construction left no breadcrumb at all, contradicting that invariant -- so this
     * must run before any throw in this constructor, exactly as StateStore does. */
    stateStore.recordLeaseClockConstruction(options.clock);

    if (typeof stateDir !== "string" || stateDir.length === 0) throw fail("stateDir must be a non-empty string", "INVALID_ARGUMENT");
    this.stateDir = stateDir;
    this.path = claimPath(stateDir);
    this.hostId = typeof options.hostId === "string" && options.hostId.length > 0 ? options.hostId : defaultHostId();
    this.instanceId = options.instanceId || randomToken();
    if (!/^[a-f0-9]{32}$/.test(this.instanceId)) throw fail("instanceId must be a 32-hex-char token", "INVALID_ARGUMENT");

    /* Runtime enforcement, matching StateStore's own gate exactly (see
     * state-store.js's constructor) -- resolved by adversarial review as: this
     * mechanism should REFUSE an implicit wall clock under the same env var, not
     * merely observe it. A source scan for `new WriterClaim(` cannot see through the
     * worker scripts this file's own shared-storage suite spawns, so this throws on
     * the executed path instead. Off unless the env var is set, so production
     * (deliberately) still defaults to the wall clock untouched. */
    if (process.env.GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK === "1" && !options.clock) {
      throw fail(
        "WriterClaim was constructed without an explicit lease clock while " +
        "GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK=1. Lease-dependent tests must choose " +
        "their own instants (tests/_harness/clock.js -> createManualClock) rather than " +
        "race real elapsed time. If this construction genuinely needs the wall clock, " +
        "pass { clock: stateStore.systemLeaseClock() } explicitly so the choice is visible.",
        "LEASE_CLOCK_REQUIRED"
      );
    }
    /* Unconditional, matching StateStore's own equivalent check exactly (see
     * state-store.js's constructor): a TRUTHY but malformed explicit clock (e.g. `{}`)
     * must not be silently swapped for the wall clock, in this branch or the flagged one
     * above -- adversarial review (correctness-1) found the previous ternary here did
     * exactly that, so GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK=1 could be bypassed by
     * passing any truthy non-clock value. */
    const clock = options.clock || { now: () => Date.now() };
    if (typeof clock.now !== "function") throw fail("clock.now must be a function", "BAD_LEASE_CLOCK");
    this.clock = clock;
    this.heartbeatMs = positiveInteger(options.heartbeatMs, DEFAULT_HEARTBEAT_MS);
    this.staleAfterMs = positiveInteger(options.staleAfterMs, this.heartbeatMs * DEFAULT_MISSED_HEARTBEATS_STALE);
    this.skewToleranceMs = positiveInteger(options.skewToleranceMs, CLAIM_CLOCK_SKEW_TOLERANCE_MS);
    this._claimToken = null;
    this._timer = null;
    this._lastHeartbeatError = null;
    // Optional: see startHeartbeat()'s doc comment. Also settable after construction.
    this.onClaimLost = typeof options.onClaimLost === "function" ? options.onClaimLost : null;
  }

  _readObserved() {
    return readClaimFile(this.stateDir);
  }

  /* CodeRabbit review (PR #27): this.clock accepts any object with a `now` function, and
   * the raw return value used to go straight into claimed_at/renewed_at. A fractional,
   * negative, or non-integer instant fails validateNamedRecord's schema check and
   * surfaces as CORRUPT_CLAIM -- misdiagnosing a bad clock as a damaged claim file on
   * disk, when the file is fine. scripts/state-store.js already rejects this at the
   * source with BAD_LEASE_CLOCK precisely to avoid that misdiagnosis; this mirrors it. */
  _now() {
    const t = this.clock.now();
    if (!Number.isSafeInteger(t) || t < 0) {
      throw fail(
        `clock.now() returned ${JSON.stringify(t)}; a claim instant must be a non-negative ` +
        "safe integer of epoch milliseconds",
        "BAD_CLAIM_CLOCK"
      );
    }
    return t;
  }

  _writeNewClaim(now) {
    const token = randomToken();
    const record = {
      schema_version: SCHEMA_VERSION,
      host_id: this.hostId,
      instance_id: this.instanceId,
      pid: process.pid,
      claimed_at: now,
      renewed_at: now,
      claim_token: token,
    };
    stateStore.validateNamedRecord(record, CLAIM_DEF, CLAIM_FILE);
    stateStore.atomicCreateExclusive(this.path, JSON.stringify(record));
    return { record, token };
  }

  _unlinkIfToken(expectedToken) {
    let fd;
    try { fd = fs.openSync(this.path, "r"); }
    catch (error) { if (error.code === "ENOENT") return false; throw error; }
    try {
      const current = stateStore.validateNamedRecord(JSON.parse(fs.readFileSync(fd, "utf8")), CLAIM_DEF, CLAIM_FILE);
      if (current.claim_token !== expectedToken) return false;
      /* Same TOCTOU class as renew() below (Codex/CodeRabbit, PR #27): the token check
       * above is against content read via `fd`, but unlinkSync operates on whatever is
       * CURRENTLY at `this.path` -- if a contender unlinked and recreated the claim in
       * between, an unconditional unlinkSync-by-path would delete that contender's new,
       * legitimate claim instead of the stale one we actually verified. Compare the
       * still-open fd's inode identity against what unlink would remove immediately
       * before removing it; a mismatch means the path no longer refers to the record we
       * checked, so this stops and reports "nothing to remove" rather than deleting
       * whatever is there now. */
      const heldInode = fs.fstatSync(fd);
      let onPath;
      try { onPath = fs.lstatSync(this.path); }
      catch (error) { if (error.code === "ENOENT") return false; throw error; }
      if (onPath.dev !== heldInode.dev || onPath.ino !== heldInode.ino) return false;
      fs.unlinkSync(this.path);
      return true;
    } finally { fs.closeSync(fd); }
  }

  /* NFR-1 (fail-closed), FR-1 (refuse-with-named-identity), FR-3 (host/instance
   * identity), AC-1/AC-2/AC-3. Bounded retry covers the residual race window between a
   * competing acquirer's EEXIST and this process's read of what landed (same shape as
   * state-store.js's `_acquireLock`), NOT unbounded contention -- a writer-claim is
   * acquired once at startup, not per-mutation. */
  acquire() {
    fs.mkdirSync(this.stateDir, { recursive: true });
    const ATTEMPTS = 8;
    for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
      const now = this._now();
      try {
        const { token } = this._writeNewClaim(now);
        this._claimToken = token;
        return this.status();
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        let observed;
        try { observed = this._readObserved(); }
        catch (readError) {
          if (readError.code === "CORRUPT_CLAIM") {
            // Fail-closed (NFR-1): an unreadable/invalid claim is an unresolved
            // conflict, never treated as "no claim, safe to acquire".
            throw fail(
              `Refusing to start: ${this.path} exists but is not a valid writer-claim ` +
              `record (${readError.message}). Treated as an unresolved conflicting claim ` +
              `-- remove the file only after confirming no writer process is using it.`,
              "WRITER_CLAIM_AMBIGUOUS");
          }
          throw readError;
        }
        if (!observed) continue;   // claim vanished between EEXIST and read; retry
        const decision = decideOnExisting(observed, {
          localHostId: this.hostId,
          localInstanceId: this.instanceId,
          localPid: process.pid,
          now: this._now(),
          staleAfterMs: this.staleAfterMs,
          skewToleranceMs: this.skewToleranceMs,
        });
        if (decision.outcome === "own") {
          this._claimToken = observed.claim_token;
          return this.status();
        }
        if (decision.outcome === "refuse") {
          throw fail(refusalMessage(observed, decision.code, this.hostId), decision.code);
        }
        try { this._unlinkIfToken(observed.claim_token); }
        catch (error) { if (error.code !== "ENOENT") throw error; }
        continue;
      }
    }
    throw fail("Could not acquire writer-claim after bounded contention", "WRITER_CLAIM_CONTENTION");
  }

  /* FR-2: periodic heartbeat, independent of state-store.js's per-mutation state.lock
   * renewal. Rewrites `renewed_at` (the claim record is self-describing, so -- unlike
   * state.lock's mtime-touch renewal -- there is a field to update, not just a
   * timestamp to bump).
   *
   * Codex review (PR #27) found a real TOCTOU race in the previous version: the
   * token check was read via one fd, then the write went through
   * atomicOverwriteFile's own separate open-by-path, decoupled from that check. If an
   * owner missed staleAfterMs and resumed while a contender was taking over, the
   * contender could unlink the stale claim and acquire a new one in that gap, and this
   * process's unconditional rename-based overwrite would then replace the contender's
   * VALID claim with the stale owner's record -- both processes then believe they are
   * the sole attesting writer. Fix: keep ONE fd open from the token check through to
   * the write (mirroring state-store.js's own _renewLock, which does the same for its
   * mtime-only renewal). If the path gets unlinked+recreated underneath us between open
   * and write, this fd still refers to the OLD, now-orphaned inode -- the write lands
   * there, invisible to anyone reading the live path, instead of clobbering the new
   * owner's claim; a later status() call on this instance then correctly reports the
   * claim as lost rather than silently believing the stale renewal "worked".
   *
   * KNOWN, DISCLOSED LIMITATION (CodeRabbit review, PR #27, follow-up round): the
   * ftruncateSync/writeSync/fsyncSync sequence below is not itself crash-atomic. A
   * process killed (SIGKILL, power loss) in the narrow window after ftruncateSync but
   * before the write completes leaves the claim file on disk at 0 bytes. The NEXT
   * acquire() attempt -- by this or any instance -- then reads that as invalid JSON,
   * classifies it CORRUPT_CLAIM, and (fail-closed, NFR-1) refuses unconditionally as
   * WRITER_CLAIM_AMBIGUOUS rather than treating it as reclaimable, exactly like any
   * other corrupt claim file. Recovery is the same as for any WRITER_CLAIM_AMBIGUOUS
   * refusal (see that error's own message): after confirming no writer process is
   * actually using this state directory, remove the claim file by hand and retry.
   * This trades a rare, manual-recovery availability edge case for keeping the
   * TOCTOU-safety fix above (a single fd held across the whole check-then-write,
   * never rebinding the path via rename mid-renewal) -- switching back to a
   * rename-based atomic write here would reopen exactly the TOCTOU race that fix
   * closes. Not engineered further here because Phase 0 does not yet wire
   * WriterClaim into any production entry point (see the startHeartbeat() doc
   * comment above and KNOWN-LIMITATIONS.md); a guarded auto-recovery path is real
   * follow-up work once there is an actual caller and operational surface to design
   * it against, not something to build speculatively ahead of that. */
  renew() {
    if (!this._claimToken) throw fail("No writer-claim held by this instance", "WRITER_CLAIM_NOT_HELD");
    const now = this._now();
    let fd;
    try { fd = fs.openSync(this.path, "r+"); }
    catch (error) {
      if (error.code === "ENOENT") {
        throw fail("Lost the writer-claim: the claim file is gone. Refusing to continue renewing.", "WRITER_CLAIM_LOST");
      }
      throw error;
    }
    try {
      let current;
      try { current = stateStore.validateNamedRecord(JSON.parse(fs.readFileSync(fd, "utf8")), CLAIM_DEF, CLAIM_FILE); }
      catch (error) { throw fail(`Invalid ${CLAIM_FILE}: ${error.message}`, "CORRUPT_CLAIM"); }
      if (current.claim_token !== this._claimToken) {
        throw fail(
          `Lost the writer-claim: it is now held by instance ${current.instance_id} on host ` +
          `"${current.host_id}". Refusing to continue renewing -- another writer has taken over.`,
          "WRITER_CLAIM_LOST");
      }
      const updated = { ...current, renewed_at: now };
      stateStore.validateNamedRecord(updated, CLAIM_DEF, CLAIM_FILE);
      const content = JSON.stringify(updated);
      fs.ftruncateSync(fd, 0);
      fs.writeSync(fd, content, 0, "utf8");
      fs.fsyncSync(fd);
      return updated;
    } finally {
      fs.closeSync(fd);
    }
  }

  /* CodeRabbit review (PR #27) found two problems here, both left the module silently
   * pretending to be the sole attesting writer after it no longer was:
   *
   * (1) WRITER_CLAIM_LOST was swallowed. `catch (error) { this._lastHeartbeatError =
   *     error; }` stored it and nothing read `_lastHeartbeatError` -- when another
   *     writer took over, this process learned nothing and kept operating as if it
   *     still held the claim. Fixed: a lost claim now stops the timer, clears the
   *     in-memory token (so status()/renew() correctly report/refuse from here on),
   *     and either calls an operator-supplied `onClaimLost` callback or, if none was
   *     given, rethrows inside the timer callback -- which surfaces as an uncaught
   *     exception rather than a silent no-op, matching this codebase's stated
   *     "halt loudly with an unresolved-side-effect state instead of silently
   *     continuing" convention (see promote.js/state-store.js coding guidelines).
   *
   * (2) setInterval renewal only runs when the event loop is free -- a caller doing
   *     long synchronous work while holding this claim can starve the heartbeat past
   *     staleAfterMs, exactly the failure mode state-store.js's own lock renewal
   *     (_assertStillOwned) was hardened against by making renewal synchronous at
   *     durable writes. WriterClaim has NOT had the equivalent fix applied, because
   *     Phase 0 does not yet wire this claim into any long-running synchronous
   *     operation (no production entry point calls acquire()/startHeartbeat() as of
   *     this PR -- see KNOWN-LIMITATIONS.md). This is disclosed here rather than
   *     silently left implicit: whichever change wires WriterClaim into a real process
   *     lifecycle must either keep every synchronous critical section well under
   *     staleAfterMs, or add a synchronous renewal call at the boundaries of any long
   *     synchronous phase, mirroring state-store.js's fix, before relying on this
   *     heartbeat alone for correctness. */
  startHeartbeat() {
    if (this._timer) return this._timer;
    this._timer = setInterval(() => {
      try { this.renew(); this._lastHeartbeatError = null; }
      catch (error) {
        this._lastHeartbeatError = error;
        if (error.code === "WRITER_CLAIM_LOST") {
          this.stopHeartbeat();
          this._claimToken = null;
          if (typeof this.onClaimLost === "function") this.onClaimLost(error);
          else throw error;   // unhandled: halt loudly rather than keep writing
        }
      }
    }, this.heartbeatMs);
    if (typeof this._timer.unref === "function") this._timer.unref();
    return this._timer;
  }

  stopHeartbeat() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }

  release() {
    this.stopHeartbeat();
    if (!this._claimToken) return false;
    /* CodeRabbit review (PR #27): the previous `finally { this._claimToken = null; }`
     * cleared the token even when _unlinkIfToken THREW (e.g. a corrupt claim file, or
     * an unlinkSync failure). That left the claim file on disk while this process
     * discarded the only token that could renew or remove it -- renew()/release() then
     * both refuse, and status() reports claimed:false/held_by_this_instance:false with
     * no hint of the orphan, blocking a restart until staleAfterMs elapses.
     * state-store.js's own _releaseLock documents and fixes the identical defect by
     * clearing the held token only after the release is verified; mirrored here. */
    const released = this._unlinkIfToken(this._claimToken);
    this._claimToken = null;
    return released;
  }

  /* FR-4/NFR-5: an operator-visible health-check field. Always reads fresh from disk
   * rather than trusting in-memory state, so a claim lost out-of-band (AC-4, e.g. the
   * file removed underneath a running process) is reported, not assumed. */
  status() {
    const now = this.clock.now();
    let observed = null;
    let readError = null;
    try { observed = this._readObserved(); }
    catch (error) { readError = error; }

    if (readError) {
      return {
        schema_version: SCHEMA_VERSION,
        claimed: false,
        held_by_this_instance: false,
        lost: Boolean(this._claimToken),
        host_id: this.hostId,
        instance_id: this.instanceId,
        error: { code: readError.code || "WRITER_CLAIM_ERROR", message: readError.message },
      };
    }
    if (!observed) {
      return {
        schema_version: SCHEMA_VERSION,
        claimed: false,
        held_by_this_instance: false,
        lost: Boolean(this._claimToken),
        host_id: this.hostId,
        instance_id: this.instanceId,
      };
    }
    const heldByThis = Boolean(this._claimToken) && observed.claim_token === this._claimToken;
    return {
      schema_version: SCHEMA_VERSION,
      claimed: true,
      held_by_this_instance: heldByThis,
      lost: Boolean(this._claimToken) && !heldByThis,
      host_id: observed.host_id,
      instance_id: observed.instance_id,
      claimed_at: observed.claimed_at,
      renewed_at: observed.renewed_at,
      age_ms: now - observed.renewed_at,
    };
  }
}

/* Read-only status check, usable without ever attempting to acquire -- e.g. from a
 * health-check endpoint that only wants to report, not become the writer. */
function readStatus(stateDir, options = {}) {
  return new WriterClaim(stateDir, options).status();
}

module.exports = {
  SCHEMA_VERSION,
  CLAIM_FILE,
  WriterClaim,
  claimPath,
  readStatus,
  decideOnExisting,   // exported for direct, deterministic unit testing of the decision table
  DEFAULT_HEARTBEAT_MS,
  DEFAULT_MISSED_HEARTBEATS_STALE,
  CLAIM_CLOCK_SKEW_TOLERANCE_MS,
};

function selftest() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-writer-claim-"));
  const tests = [];
  try {
    const clock = { _t: 1_700_000_000_000, now() { return this._t; }, advance(ms) { this._t += ms; } };

    const a = new WriterClaim(root, { hostId: "host-a", instanceId: "a".repeat(32), clock, heartbeatMs: 100 });
    a.acquire();
    tests.push({ name: "acquire-writes-valid-claim", status: "pass" });

    const b = new WriterClaim(root, { hostId: "host-a", instanceId: "b".repeat(32), clock, heartbeatMs: 100 });
    let refused = null;
    try { b.acquire(); } catch (error) { refused = error.code; }
    if (refused !== "WRITER_CLAIM_HELD") throw new Error(`expected WRITER_CLAIM_HELD, got ${refused}`);
    tests.push({ name: "second-same-host-instance-refused", status: "pass" });

    const c = new WriterClaim(root, { hostId: "host-b", instanceId: "c".repeat(32), clock, heartbeatMs: 100 });
    let foreign = null;
    try { c.acquire(); } catch (error) { foreign = error.code; }
    if (foreign !== "WRITER_CLAIM_FOREIGN_HOST") throw new Error(`expected WRITER_CLAIM_FOREIGN_HOST, got ${foreign}`);
    tests.push({ name: "foreign-host-refused-unconditionally", status: "pass" });

    a.renew();
    const statusA = a.status();
    if (!statusA.claimed || !statusA.held_by_this_instance) throw new Error("status did not report normal ownership");
    tests.push({ name: "status-reports-normal-ownership", status: "pass" });

    fs.unlinkSync(a.path);
    const lostStatus = a.status();
    if (lostStatus.claimed || !lostStatus.lost) throw new Error("status did not report mid-run claim loss");
    tests.push({ name: "status-reports-mid-run-loss", status: "pass" });

    return { schema_version: SCHEMA_VERSION, status: "pass", tests };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  const command = process.argv[2];
  try {
    if (command === "status") {
      writeReport(JSON.stringify(readStatus(path.join(process.cwd(), ".graphsmith", "state"))) + "\n");
    } else if (command === "--selftest") {
      writeReport(JSON.stringify(selftest()) + "\n");
    } else {
      console.error("Usage: node scripts/writer-claim.js status|--selftest");
      process.exitCode = 2;
    }
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}
