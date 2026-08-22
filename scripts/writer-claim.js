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
  return typeof name === "string" && name.length > 0 ? name : "unknown-host";
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
  if (record.instance_id === ctx.localInstanceId) return { outcome: "own" };

  if (record.host_id !== ctx.localHostId) {
    // Cross-host signal (AC-2): refuse unconditionally, regardless of apparent age.
    // No staleness arithmetic is attempted -- see the module header for why.
    return { outcome: "refuse", code: "WRITER_CLAIM_FOREIGN_HOST" };
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
    if (typeof stateDir !== "string" || stateDir.length === 0) throw fail("stateDir must be a non-empty string", "INVALID_ARGUMENT");
    this.stateDir = stateDir;
    this.path = claimPath(stateDir);
    this.hostId = typeof options.hostId === "string" && options.hostId.length > 0 ? options.hostId : defaultHostId();
    this.instanceId = options.instanceId || randomToken();
    if (!/^[a-f0-9]{32}$/.test(this.instanceId)) throw fail("instanceId must be a 32-hex-char token", "INVALID_ARGUMENT");
    /* Same breadcrumb StateStore writes at construction, and for the same reason: a
     * source scan for `new WriterClaim(` cannot see through the worker script this
     * mechanism's own shared-storage suite spawns. See state-store.js's
     * recordLeaseClockConstruction -- this is a SEPARATE mechanism from StateStore (see
     * the module header above) that never constructs one, so StateStore's breadcrumb is
     * structurally blind to this class; reusing the function gives this class the
     * identical proof rather than a second, divergent one. */
    stateStore.recordLeaseClockConstruction(options.clock);
    this.clock = options.clock && typeof options.clock.now === "function" ? options.clock : { now: () => Date.now() };
    this.heartbeatMs = positiveInteger(options.heartbeatMs, DEFAULT_HEARTBEAT_MS);
    this.staleAfterMs = positiveInteger(options.staleAfterMs, this.heartbeatMs * DEFAULT_MISSED_HEARTBEATS_STALE);
    this.skewToleranceMs = positiveInteger(options.skewToleranceMs, CLAIM_CLOCK_SKEW_TOLERANCE_MS);
    this._claimToken = null;
    this._timer = null;
    this._lastHeartbeatError = null;
  }

  _readObserved() {
    return readClaimFile(this.stateDir);
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
      const now = this.clock.now();
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
          now: this.clock.now(),
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
   * renewal. Rewrites `renewed_at` via an unconditional atomic overwrite (the claim
   * record is self-describing, so -- unlike state.lock's mtime-touch renewal -- there
   * is a field to update, not just a timestamp to bump). */
  renew() {
    if (!this._claimToken) throw fail("No writer-claim held by this instance", "WRITER_CLAIM_NOT_HELD");
    let current;
    try {
      const fd = fs.openSync(this.path, "r");
      try { current = stateStore.validateNamedRecord(JSON.parse(fs.readFileSync(fd, "utf8")), CLAIM_DEF, CLAIM_FILE); }
      finally { fs.closeSync(fd); }
    } catch (error) {
      if (error.code === "ENOENT") {
        throw fail("Lost the writer-claim: the claim file is gone. Refusing to continue renewing.", "WRITER_CLAIM_LOST");
      }
      throw error;
    }
    if (current.claim_token !== this._claimToken) {
      throw fail(
        `Lost the writer-claim: it is now held by instance ${current.instance_id} on host ` +
        `"${current.host_id}". Refusing to continue renewing -- another writer has taken over.`,
        "WRITER_CLAIM_LOST");
    }
    const updated = { ...current, renewed_at: this.clock.now() };
    stateStore.validateNamedRecord(updated, CLAIM_DEF, CLAIM_FILE);
    stateStore.atomicOverwriteFile(this.path, JSON.stringify(updated), this.stateDir);
    return updated;
  }

  startHeartbeat() {
    if (this._timer) return this._timer;
    this._timer = setInterval(() => {
      try { this.renew(); this._lastHeartbeatError = null; }
      catch (error) { this._lastHeartbeatError = error; }
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
    let released = false;
    try { released = this._unlinkIfToken(this._claimToken); }
    finally { this._claimToken = null; }
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
