#!/usr/bin/env node
"use strict";

/**
 * scripts/writer-claim.js -- gateway-integration writer-claim mechanism (Phase 0,
 * FR-1..FR-4 of .plans/v0.5.0/GATEWAY-MULTI-INSTANCE-HANDOFF.md).
 *
 * Establishes and maintains a single-writer claim over a GraphSmith state directory,
 * distinguishing HOST identity (host_id) from PROCESS identity (instance_id) from
 * OS-level liveness (pid) -- three separate signals, because none of them alone is
 * trustworthy across every deployment shape this mechanism has to survive:
 *
 *   - pid alone (what state.lock's owner_token+pid already does) is meaningless across
 *     hosts: two different machines can both have a live pid 4821.
 *   - a bare hostname is not enough either -- see defaultHostId()'s fail-closed guard
 *     below for why an EMPTY hostname specifically must never be papered over with a
 *     shared placeholder.
 *   - mtime/wall-clock comparison across hosts cannot be trusted (danger 2, handoff
 *     doc §4) -- that is exactly why decideOnExisting() below treats a foreign host_id
 *     as an unconditional refusal, never attempting staleness arithmetic against it.
 *
 * This module is intentionally independent of scripts/state-store.js's own lock
 * mechanism (state.lock, per-mutation): a writer-claim answers "is this instance THE
 * writer for this whole gateway session," not "do I hold the lock for one mutation."
 * Both can co-exist; FR-1 requires the writer-claim to be acquired before any MCP
 * session for attestation is accepted, upstream of any individual mutation's lock.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const stateStore = require("./state-store.js");

const CLAIM_FILE = "writer-claim.json";
const SCHEMA_VERSION = "1.0";
const CLAIM_DEF = "writerClaim";
const DEFAULT_HEARTBEAT_MS = 5000;
const DEFAULT_STALE_AFTER_MS = DEFAULT_HEARTBEAT_MS * 3;
const CLAIM_CLOCK_SKEW_TOLERANCE_MS = 5000;

function fail(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function claimPath(root) {
  return path.join(root, CLAIM_FILE);
}

function randomHex32() {
  return crypto.randomBytes(16).toString("hex");
}

function defaultHostId() {
  const name = os.hostname();
  /* Fail closed (NFR-1), not "unknown-host": a shared placeholder for every host whose
   * os.hostname() returns empty would make two DIFFERENT hosts in that state look
   * identical to decideOnExisting()'s host_id comparison, defeating the entire point of
   * AC-2's cross-host refusal for exactly the hosts least able to identify themselves. */
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

/**
 * Pure decision function over an existing on-disk claim record: given the record and a
 * context describing the local caller, return the outcome. Exported so the clock-skew
 * decision table can be pinned directly (see tests/state-store/writer-claim/run-tests.js),
 * mirroring how scripts/state-store.js exposes its own gate logic for the same reason.
 *
 * @param {object} record validated writerClaim record
 * @param {{localHostId:string, localInstanceId:string, localPid?:number, now:number, staleAfterMs:number, skewToleranceMs:number}} ctx
 * @returns {{outcome:"own"|"steal"|"refuse", code?:string}}
 */
function decideOnExisting(record, ctx) {
  if (record.instance_id === ctx.localInstanceId) {
    // CodeRabbit review (PR #27): matching instance_id alone used to be treated as
    // "this is me, re-acquiring my own claim" unconditionally. Two independent live
    // processes given the SAME caller-supplied instanceId (e.g. a misconfigured
    // deployment reusing a fixed value) would then both silently "own" the claim.
    // A foreign, LIVE pid on a matching instance_id is a genuine conflict, not an
    // idempotent re-acquire; a foreign but DEAD pid (a crashed process's leftover
    // record under the same instanceId) must still be re-ownable.
    if (record.pid !== ctx.localPid && stateStore.pidAlive(record.pid)) {
      return { outcome: "refuse", code: "WRITER_CLAIM_HELD" };
    }
    return { outcome: "own" };
  }
  if (record.host_id !== ctx.localHostId) {
    // AC-2: a foreign host_id refuses UNCONDITIONALLY -- no staleness arithmetic is
    // attempted at all once host_id differs, regardless of how the injected clock skew
    // makes the claim's apparent age look, and regardless of pid liveness (meaningless
    // across hosts). This is the single highest-priority scenario per the handoff doc.
    return { outcome: "refuse", code: "WRITER_CLAIM_FOREIGN_HOST" };
  }

  // Same host from here on: pid liveness is decisive, then self-reported renewed_at
  // staleness (never OS mtime -- see module header).
  if (!stateStore.pidAlive(record.pid)) {
    return { outcome: "steal" };
  }
  const age = ctx.now - record.renewed_at;
  if (age > ctx.staleAfterMs) {
    return { outcome: "steal" };
  }
  if (Math.abs(age) > ctx.skewToleranceMs && age < 0) {
    return { outcome: "refuse", code: "WRITER_CLAIM_CLOCK_SKEW" };
  }
  return { outcome: "refuse", code: "WRITER_CLAIM_HELD" };
}

/**
 * Read the current claim status without acquiring or mutating anything. Safe to call
 * from any instance, including one that does not hold the claim (AC-4 health-check
 * surface).
 */
function readStatus(root, opts) {
  opts = opts || {};
  const clock = stateStore.validateLeaseClock(opts.clock, { requireExplicit: false });
  const p = claimPath(root);
  let raw;
  try {
    raw = fs.readFileSync(p, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      return { claimed: false };
    }
    throw error;
  }
  let record;
  try {
    record = stateStore.validateNamedRecord(JSON.parse(raw), CLAIM_DEF, CLAIM_FILE);
  } catch (error) {
    return { claimed: false, error: fail(`Invalid ${CLAIM_FILE}: ${error.message}`, "CORRUPT_CLAIM") };
  }
  const now = clock.now();
  return {
    claimed: true,
    host_id: record.host_id,
    instance_id: record.instance_id,
    pid: record.pid,
    claimed_at: record.claimed_at,
    renewed_at: record.renewed_at,
    age_ms: now - record.renewed_at,
  };
}

class WriterClaim {
  constructor(root, options) {
    options = options || {};
    this.root = root;
    this.path = claimPath(root);
    this.hostId = options.hostId || defaultHostId();
    this.heartbeatMs = options.heartbeatMs || DEFAULT_HEARTBEAT_MS;
    this.staleAfterMs = options.staleAfterMs || DEFAULT_STALE_AFTER_MS;
    this.onClaimLost = typeof options.onClaimLost === "function" ? options.onClaimLost : null;
    this.clock = stateStore.validateLeaseClock(options.clock, { requireExplicit: true });
    const instanceId = options.instanceId || randomHex32();
    if (!/^[a-f0-9]{32}$/.test(instanceId)) {
      throw fail(`instanceId must be a 32-char lowercase hex string, got '${instanceId}'`, "INVALID_ARGUMENT");
    }
    this.instanceId = instanceId;
    this._claimToken = null;
    this._timer = null;
    this._lastHeartbeatError = null;
  }

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

  acquire() {
    fs.mkdirSync(this.root, { recursive: true });
    const now = this._now();
    let existing = null;
    try {
      const raw = fs.readFileSync(this.path, "utf8");
      try {
        existing = stateStore.validateNamedRecord(JSON.parse(raw), CLAIM_DEF, CLAIM_FILE);
      } catch (error) {
        throw fail(
          `Invalid ${CLAIM_FILE}: ${error.message}. Refusing to acquire over an ambiguous claim state -- ` +
          `a corrupt claim file could be masking a live writer.`,
          "WRITER_CLAIM_AMBIGUOUS"
        );
      }
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== undefined) {
        // Rethrow validation failures (WRITER_CLAIM_AMBIGUOUS) or any unexpected error;
        // only a missing file falls through to "no existing claim".
        if (error.code !== "ENOENT") throw error;
      } else if (error.code === undefined) {
        throw error;
      }
    }

    if (existing) {
      const ctx = {
        localHostId: this.hostId,
        localInstanceId: this.instanceId,
        localPid: process.pid,
        now,
        staleAfterMs: this.staleAfterMs,
        skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
      };
      const decision = decideOnExisting(existing, ctx);
      if (decision.outcome === "refuse") {
        if (decision.code === "WRITER_CLAIM_FOREIGN_HOST") {
          throw fail(
            `Writer-claim is held by a different host: host "${existing.host_id}" (this host is ` +
            `"${this.hostId}"). Refusing to acquire -- cross-host claim contention cannot be resolved by ` +
            `clock comparison alone (mtime/wall-clock skew across hosts is not trustworthy).`,
            decision.code
          );
        }
        if (decision.code === "WRITER_CLAIM_CLOCK_SKEW") {
          throw fail(
            `Writer-claim's last renewal (${existing.renewed_at}) appears to be in the future relative ` +
            `to this instance's clock (${now}), beyond the ${CLAIM_CLOCK_SKEW_TOLERANCE_MS}ms tolerance. ` +
            `Refusing to steal -- this looks like clock skew, not an abandoned claim.`,
            decision.code
          );
        }
        throw fail(
          `Writer-claim is already held by instance ${existing.instance_id} (pid ${existing.pid}) on this ` +
          `host. This is a single-writer constraint (FR-1): only one instance may hold the gateway ` +
          `writer-claim at a time.`,
          decision.code
        );
      }
      // "own" or "steal": proceed to (re)write the claim below.
    }

    const claimToken = randomHex32();
    const record = {
      schema_version: SCHEMA_VERSION,
      host_id: this.hostId,
      instance_id: this.instanceId,
      pid: process.pid,
      claimed_at: now,
      renewed_at: now,
      claim_token: claimToken,
    };
    stateStore.validateNamedRecord(record, CLAIM_DEF, CLAIM_FILE);
    stateStore.atomicOverwriteFile(this.path, JSON.stringify(record));
    this._claimToken = claimToken;
    return record;
  }

  renew() {
    if (!this._claimToken) throw fail("No writer-claim held by this instance", "WRITER_CLAIM_NOT_HELD");
    const now = this._now();
    let fd;
    try {
      fd = fs.openSync(this.path, "r+");
    } catch (error) {
      if (error.code === "ENOENT") {
        throw fail("Lost the writer-claim: the claim file is gone. Refusing to continue renewing.", "WRITER_CLAIM_LOST");
      }
      throw error;
    }
    try {
      let current;
      try {
        current = stateStore.validateNamedRecord(JSON.parse(fs.readFileSync(fd, "utf8")), CLAIM_DEF, CLAIM_FILE);
      } catch (error) {
        throw fail(`Invalid ${CLAIM_FILE}: ${error.message}`, "CORRUPT_CLAIM");
      }
      if (current.claim_token !== this._claimToken) {
        throw fail(
          `Lost the writer-claim: it is now held by instance ${current.instance_id} on host ` +
          `"${current.host_id}". Refusing to continue renewing -- another writer has taken over.`,
          "WRITER_CLAIM_LOST"
        );
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

  /**
   * Start a periodic heartbeat renewing this claim every heartbeatMs. Errors surface via
   * the `onClaimLost` constructor option (if given), or are rethrown to crash loudly.
   *
   * KNOWN, DISCLOSED LIMITATION (not fixed here -- Phase 0 does not yet wire WriterClaim
   * into any long-running synchronous production path, so there is no real call site to
   * fix against): a long synchronous block of work in this process can starve this
   * timer, delaying renewal past staleAfterMs and letting another instance legitimately
   * steal the claim out from under still-alive work. Fixing this speculatively (e.g. via
   * a worker thread or a different scheduling primitive) ahead of a real, wired-in use
   * case would be exactly the kind of premature complexity this repo's "minimum code
   * that solves the problem" discipline warns against.
   */
  startHeartbeat() {
    if (this._timer) return this._timer;
    this._timer = setInterval(() => {
      try {
        this.renew();
        this._lastHeartbeatError = null;
      } catch (error) {
        this._lastHeartbeatError = error;
        if (error.code === "WRITER_CLAIM_LOST") {
          this.stopHeartbeat();
          this._claimToken = null;
          if (typeof this.onClaimLost === "function") {
            this.onClaimLost(error);
          } else {
            throw error;
          }
        }
      }
    }, this.heartbeatMs);
    if (typeof this._timer.unref === "function") this._timer.unref();
    return this._timer;
  }

  stopHeartbeat() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  _unlinkIfToken(expectedToken) {
    let fd;
    try {
      fd = fs.openSync(this.path, "r");
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
    try {
      const current = stateStore.validateNamedRecord(JSON.parse(fs.readFileSync(fd, "utf8")), CLAIM_DEF, CLAIM_FILE);
      if (current.claim_token !== expectedToken) return false;
      const heldInode = fs.fstatSync(fd);
      let onPath;
      try {
        onPath = fs.lstatSync(this.path);
      } catch (error) {
        if (error.code === "ENOENT") return false;
        throw error;
      }
      if (onPath.dev !== heldInode.dev || onPath.ino !== heldInode.ino) return false;
      fs.unlinkSync(this.path);
      return true;
    } finally {
      fs.closeSync(fd);
    }
  }

  release() {
    this.stopHeartbeat();
    if (!this._claimToken) return false;
    const released = this._unlinkIfToken(this._claimToken);
    this._claimToken = null;
    return released;
  }

  status() {
    const s = readStatus(this.root, { clock: this.clock });
    if (!s.claimed) {
      return {
        claimed: false,
        lost: this._claimToken !== null,
        held_by_this_instance: false,
        error: s.error || null,
      };
    }
    const heldByThis = s.instance_id === this.instanceId && this._claimToken !== null;
    return {
      claimed: true,
      lost: false,
      held_by_this_instance: heldByThis,
      host_id: s.host_id,
      instance_id: s.instance_id,
      pid: s.pid,
      age_ms: s.age_ms,
    };
  }
}

function selftest() {
  const os_ = require("os");
  const tmp = fs.mkdtempSync(path.join(os_.tmpdir(), "gs-writer-claim-selftest-"));
  const checks = [];
  const check = (name, cond) => checks.push({ name, pass: !!cond });
  try {
    const clock = { now: () => Date.now() };
    const a = new WriterClaim(tmp, { hostId: "h", instanceId: "a".repeat(32), clock });
    a.acquire();
    check("acquire writes a claim file", fs.existsSync(claimPath(tmp)));
    const b = new WriterClaim(tmp, { hostId: "h", instanceId: "b".repeat(32), clock });
    let refused = false;
    try { b.acquire(); } catch (e) { refused = e.code === "WRITER_CLAIM_HELD"; }
    check("second instance refused", refused);
    a.renew();
    check("renew succeeds", true);
    const released = a.release();
    check("release removes the claim", released && !fs.existsSync(claimPath(tmp)));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  const pass = checks.every((c) => c.pass);
  console.log(JSON.stringify({ status: pass ? "pass" : "fail", checks }));
  process.exit(pass ? 0 : 1);
}

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    selftest();
  }
}

module.exports = {
  WriterClaim,
  decideOnExisting,
  claimPath,
  readStatus,
  CLAIM_CLOCK_SKEW_TOLERANCE_MS,
};
