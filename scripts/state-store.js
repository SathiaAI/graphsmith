#!/usr/bin/env node
/* GraphSmith's single writer for .graphsmith/state/. All mutations use an
 * owner-token lease and an fsync'd intent -> atomic replace -> done journal. */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const { writeReport } = require("./write-report.js");
const os = require("os");
const path = require("path");
const STATE_SCHEMA = require("../schemas/state-store.schema.json");

const SCHEMA_VERSION = "1.0";
const DEFAULT_LEASE_MS = 30000;
/* How far a lock's mtime may sit AHEAD of this host's clock before the age is treated as
 * unusable rather than as freshness. See the skew gate in `_acquireLock`. Not tunable:
 * it separates "filesystem timestamp granularity" from "the clock moved", and neither of
 * those is a per-deployment preference. */
const LOCK_CLOCK_SKEW_TOLERANCE_MS = 5000;
const DEFAULT_HEARTBEAT_MS = 5000;
const DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const ALPHA = 0.05 / 3;
const TERMINAL_DISPOSITIONS = new Set([
  "completed_pass", "completed_hard_fail", "completed_soft_wobble", "abandoned", "superseded",
]);
const FILES = Object.freeze({
  window: "window.json",
  registry: "run-registry.jsonl",
  anchors: "run-anchors.jsonl",
  alpha: "alpha-ledger.jsonl",
  rejected: "rejected-buffer.jsonl",
  rollback: "rollback-families.jsonl",
});

function fail(message, code = "STATE_STORE_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw fail(`${name} must be a non-empty string`, "INVALID_ARGUMENT");
  return value;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function stableId(parts) {
  return sha256(parts.map((part) => String(part)).join("\0")).slice(0, 24);
}

function schemaErrors(value, schema, location = "$", root = STATE_SCHEMA) {
  if (schema.$ref) {
    const target = schema.$ref.split("/").slice(1).reduce((current, part) => current[part.replace(/~1/g, "/").replace(/~0/g, "~")], root);
    return schemaErrors(value, target, location, root);
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((candidate) => schemaErrors(value, candidate, location, root).length === 0).length;
    return matches === 1 ? [] : [`${location} must match exactly one record schema (matched ${matches})`];
  }
  if (Object.prototype.hasOwnProperty.call(schema, "const") && value !== schema.const) return [`${location} must equal ${JSON.stringify(schema.const)}`];
  if (schema.enum && !schema.enum.some((candidate) => candidate === value)) return [`${location} has an unsupported value`];

  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const matchesType = types.some((type) => {
      if (type === "null") return value === null;
      if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
      if (type === "array") return Array.isArray(value);
      if (type === "integer") return Number.isSafeInteger(value);
      if (type === "number") return typeof value === "number" && Number.isFinite(value);
      return typeof value === type;
    });
    if (!matchesType) return [`${location} must be ${types.join(" or ")}`];
  }

  const errors = [];
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) errors.push(`${location} is too short`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${location} has an invalid format`);
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${location} is below its minimum`);
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) errors.push(`${location} is below its exclusive minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${location} is above its maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${location} has too few items`);
    if (schema.items) value.forEach((item, index) => errors.push(...schemaErrors(item, schema.items, `${location}[${index}]`, root)));
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const key of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) errors.push(`${location}.${key} is required`);
    }
    const properties = schema.properties || {};
    for (const [key, child] of Object.entries(value)) {
      if (Object.prototype.hasOwnProperty.call(properties, key)) errors.push(...schemaErrors(child, properties[key], `${location}.${key}`, root));
      else if (schema.additionalProperties === false) errors.push(`${location}.${key} is not allowed`);
    }
  }
  return errors;
}

function validateStateRecord(record, context) {
  const errors = schemaErrors(record, STATE_SCHEMA);
  if (errors.length) throw fail(`Invalid state record in ${context}: ${errors[0]}`, "CORRUPT_STATE");
  return record;
}

function parseStateJson(raw, context) {
  let record;
  try { record = JSON.parse(raw); }
  catch (error) { throw fail(`Invalid JSON in ${context}: ${error.message}`, "CORRUPT_STATE"); }
  return validateStateRecord(record, context);
}

function parseJsonLines(raw, file) {
  if (!raw) return [];
  const lines = raw.split("\n");
  const records = [];
  for (let index = 0; index < lines.length; index++) {
    if (!lines[index]) continue;
    let record;
    try {
      record = JSON.parse(lines[index]);
    } catch (error) {
      const isTornTail = index === lines.length - 1 && !raw.endsWith("\n");
      if (isTornTail) break;
      throw fail(`Corrupt JSONL record in ${file} at line ${index + 1}: ${error.message}`, "CORRUPT_STATE");
    }
    records.push(validateStateRecord(record, `${file} at line ${index + 1}`));
  }
  return records;
}

function jsonLines(records) {
  return records.length === 0 ? "" : `${records.map((record) => JSON.stringify(validateStateRecord(record, "JSONL write"))).join("\n")}\n`;
}

function defaultWindow() {
  return { schema_version: SCHEMA_VERSION, state_rev: 0, state: "NO_WINDOW", flag: false, window: null };
}

function parseWindow(raw) {
  if (!raw) return defaultWindow();
  try {
    return parseStateJson(raw, FILES.window);
  } catch (error) {
    throw fail(`Corrupt ${FILES.window}: ${error.message}`, "CORRUPT_STATE");
  }
}

function validateStateContent(file, content) {
  if (file === FILES.window) parseWindow(content);
  else parseJsonLines(content, file);
  return content;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/* LEASE TIME vs OPERATIONAL TIME -- the distinction this seam exists to preserve.
 *
 * A lease is a PRODUCT budget whose only meaning is arithmetic: given a stored
 * `lease_expires_at` and a current instant, is this run still live. Tests of that
 * arithmetic do not need a real clock; they need to CHOOSE the instant. Six
 * separate defects on this branch came from tests that instead raced real elapsed
 * time against ~200ms-per-operation Windows I/O and reported losing the race as a
 * product defect -- one of them accusing a fail-closed refusal of letting a window
 * close over active slots. See KNOWN-LIMITATIONS and the branch history.
 *
 * So `leaseNow()` is injectable. What is NOT injectable, and must never be:
 *
 *   - lock staleness (`Date.now() - observed.stat.mtimeMs`): compares against an
 *     mtime the OPERATING SYSTEM wrote. A frozen clock there makes every lock look
 *     infinitely stale or never stale -- silently testing a different product. That
 *     comparison is wall-clock and therefore NOT monotone; the skew gate in
 *     `_acquireLock` is what keeps a backward correction from wedging the store.
 *
 * `proc_start_hint` USED to be listed here as a third real-clock site. It is no longer
 * written. It was never read by any product code, and leaving a dead identity field in a
 * lock record is worse than having none: the next reader infers a PID-reuse defence that
 * does not exist. PID reuse is already bounded -- a reused pid can only cause a REFUSAL,
 * never a false steal, and that refusal self-heals once the lock goes unrenewed.
 *
 * It is still ACCEPTED by the schema (removed from `required`, kept in `properties`).
 * That is deliberate and not tidiness-aversion: the lock schema is
 * `additionalProperties: false`, so hard-removing the property would make every lock file
 * written by a previous version fail validation as CORRUPT_STATE -- and CORRUPT_STATE in
 * the acquire path is unrecoverable by the tool itself. Deleting the field outright would
 * have shipped a self-inflicted upgrade outage of exactly the kind the skew gate above
 * exists to prevent. Verified by writing a legacy lock and upgrading against both variants.
 *
 * Injecting one global clock over both is the obvious mistake here, and it is worse
 * than the bug it would fix: it would turn the lock protocol into a no-op while every
 * test still passed. Lease time is chosen; operational time is observed.
 */
/* ONE definition, tagged. There were two -- this one untagged and a tagged copy in
 * tests/_harness/clock.js -- so a caller passing THIS one was recorded as an untagged
 * "custom" clock and would fail the determinism gate for doing the right thing. Two
 * near-identical helpers differing only in a metadata field is a foot-gun, not a choice. */
function systemLeaseClock() {
  return { __leaseClockKind: "system", now: () => Date.now() };
}

const REQUIRE_EXPLICIT_CLOCK_ENV = "GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK";
const LEASE_CLOCK_AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";
/* Provenance is a property of the clock OBJECT, so it is measured once and remembered.
 * WeakMap so a clock that goes out of scope is not retained by the audit. */
const CLOCK_PROVENANCE = new WeakMap();

class StateStore {
  constructor(projectRoot = process.cwd(), options = {}) {
    this.projectRoot = path.resolve(projectRoot);
    this.stateDir = path.join(this.projectRoot, ".graphsmith", "state");
    this.lockPath = path.join(this.stateDir, "state.lock");
    this.journalPath = path.join(this.stateDir, "state-journal.jsonl");
    const testMode = process.env.GRAPHSMITH_TEST_MODE === "1";

    /* Runtime enforcement, not a lint. A source scan for `new StateStore(` cannot see
     * through aliasing, helper factories, or a store constructed inside a spawned
     * worker written to a temp file -- all three of which this repo's suites do. This
     * throws on the executed path instead, so a test that relies on wall-clock lease
     * time cannot pass anywhere, including the Windows-only cases a Linux audit is
     * structurally blind to. Off unless the env var is set, so production is untouched. */
    /* AUDIT BREADCRUMB, written BEFORE the refusal below and never conditional on it.
     *
     * The first version of the determinism sweep detected wall-clock construction by
     * grepping the target's output for the refusal message. An adversarial review broke
     * that in one line: tests/state-store/grok has a case whose catch block treats ANY
     * throw as its success signal, so the refusal was swallowed, the suite exited 0, and
     * the sweep reported "no wall-clock lease construction on any executed path" while a
     * wall-clock store was being built on that very path. A detector a `catch` can defeat
     * is not a detector.
     *
     * So the record is written here, at construction, where no downstream handler can
     * intercept it -- and it records the KIND of clock rather than merely its presence,
     * because an inline `{ now: () => Date.now() }` satisfies a presence check while
     * reintroducing the exact race. Append-only and best-effort: this must never be able
     * to fail a run it is only observing. Inert unless the env var is set. */
    const auditPath = process.env[LEASE_CLOCK_AUDIT_ENV];
    if (auditPath) {
      /* The first frame OUTSIDE this file. Taking a fixed stack index named the local
       * factory every time -- `at createStore (state-store.js:...)` for all nine
       * constructions -- which is an inventory that cannot tell you where to look. */
      /* TWO frames outside this file, not one.
       *
       * One frame collapses every caller of a test-local factory to the factory itself --
       * a hole an adversarial review named after the equivalent hole inside this file was
       * fixed. With the caller recorded too, a NEW caller of an existing real-clock factory
       * is a new site rather than an invisible reuse. */
      let site = "(no stack)";
      let caller = "";
      try {
        const here = path.basename(__filename);
        const external = String(new Error().stack || "").split("\n").slice(1)
          .filter((f) => f.indexOf(here) === -1);
        site = String(external[0] || "").trim();
        caller = String(external[1] || "").trim();
      } catch (e) { /* best effort */ }
      /* PROVENANCE IS OBSERVED, NOT DECLARED.
       *
       * The first version recorded `options.clock.__leaseClockKind`, i.e. a string the
       * caller supplies. An adversarial review pointed out that
       * `{ __leaseClockKind: "manual", now: () => Date.now() }` then passes every check
       * while being exactly the wall-clock race the seam exists to remove -- the tag is
       * an assertion, not evidence.
       *
       * So the clock is MEASURED: read it, burn a little real time, read it again. A
       * chosen clock does not move on its own; a wall clock does. A forged tag cannot
       * lie about that. The tag is still recorded, and a disagreement between claim and
       * behaviour is itself reportable. */
      /* MEASURED ONCE PER CLOCK OBJECT, not once per construction.
       *
       * The first version measured on every construction. A clock's nature does not change
       * between constructions, so that bought nothing -- and it cost a 2ms busy-wait plus a
       * file append EVERY time. A windows run of the deepseek suite builds 126 stores, many
       * of them inside a two-process lock-contention loop that is timing-sensitive by
       * design, so ~250ms of injected busy-waiting landed inside the very thing being
       * measured. The suite then failed under the audit while passing without it, and the
       * gate correctly reported "this is NOT a clock finding" without being able to say
       * that the AUDIT was the difference.
       *
       * An observer that changes the observed is the same defect class this whole gate
       * exists to catch, one level out. Caching by object identity removes it: 126
       * measurements become one per distinct clock. */
      let advancedUnderRealTime = null;
      if (options.clock && typeof options.clock.now === "function") {
        if (CLOCK_PROVENANCE.has(options.clock)) {
          advancedUnderRealTime = CLOCK_PROVENANCE.get(options.clock);
        } else {
          try {
            const a = options.clock.now();
            const until = Date.now() + 2;
            while (Date.now() < until) { /* burn real time, no yield: the clock must not
                                          * advance because we waited politely */ }
            advancedUnderRealTime = options.clock.now() !== a;
          } catch (e) { advancedUnderRealTime = null; }
          try { CLOCK_PROVENANCE.set(options.clock, advancedUnderRealTime); } catch (e) { /* non-object clock */ }
        }
      }
      const claimed = options.clock
        ? (typeof options.clock.now !== "function" ? "malformed" : (options.clock.__leaseClockKind || "custom"))
        : "wall";
      /* Observed wins. "manual" is only granted to a clock that demonstrably did not move. */
      const kind = claimed === "wall" || claimed === "malformed" ? claimed
        : advancedUnderRealTime === true ? "system"
          : advancedUnderRealTime === false ? (claimed === "system" ? "system-frozen" : "manual")
            : "custom";
      const line = JSON.stringify({
        explicit: Boolean(options.clock),
        kind, claimed, advancedUnderRealTime,
        site: site.slice(0, 240),
        caller: caller.slice(0, 240),
        pid: process.pid,
      }) + "\n";
      /* FAIL CLOSED. This was best-effort, and the gate then treated a partial audit as
       * complete evidence: one dropped append among twenty made the other nineteen
       * certify the run. A missing record is indistinguishable from no construction, so
       * in audit mode an unrecordable construction has to stop the run. Audit mode is
       * opt-in and never on in production. */
      fs.appendFileSync(auditPath, line);
    }

    if (process.env[REQUIRE_EXPLICIT_CLOCK_ENV] === "1" && !options.clock) {
      throw fail(
        "StateStore was constructed without an explicit lease clock while " +
        REQUIRE_EXPLICIT_CLOCK_ENV + "=1. Lease-dependent tests must choose their own " +
        "instants (tests/_harness/clock.js -> createManualClock) rather than race real " +
        "elapsed time. If this construction genuinely needs the wall clock, pass " +
        "{ clock: systemLeaseClock() } explicitly so the choice is visible.",
        "LEASE_CLOCK_REQUIRED"
      );
    }
    const clock = options.clock || systemLeaseClock();
    if (typeof clock.now !== "function") throw fail("clock.now must be a function", "BAD_LEASE_CLOCK");
    /* An instant must be a non-negative safe integer, not merely finite. A fractional or
     * negative value reaches the schema and surfaces as CORRUPT_STATE -- a bad clock
     * misdiagnosed as on-disk corruption, which in this repo is the HALT-class signal that
     * sends an operator to inspect state files that are fine. Rejecting it here names the
     * actual fault. (An adversarial review demonstrated both, plus a single 1e15 reading
     * driving an OBSERVING window to CLOSED_FLAGGED through the wall-time cap.) */
    this.leaseNow = () => {
      const t = clock.now();
      if (!Number.isSafeInteger(t) || t < 0) {
        throw fail(`clock.now() returned ${JSON.stringify(t)}; a lease instant must be a ` +
          "non-negative safe integer of epoch milliseconds", "BAD_LEASE_CLOCK");
      }
      return t;
    };
    /* The instant is validated; the SUM was not. A large leaseMs plus a large instant can
     * leave the safe-integer range and serialise without error, producing a record that
     * later reads as expired decades ago. */
    this._leaseExpiryFrom = (now) => {
      const expiry = now + this.leaseMs;
      if (!Number.isSafeInteger(expiry)) {
        throw fail(`lease expiry ${expiry} (now ${now} + leaseMs ${this.leaseMs}) is outside ` +
          "the safe-integer range", "BAD_LEASE_CLOCK");
      }
      return expiry;
    };
    this.leaseMs = testMode
      ? positiveInteger(options.leaseMs || process.env.GRAPHSMITH_LEASE_MS, DEFAULT_LEASE_MS)
      : DEFAULT_LEASE_MS;
    this.heartbeatMs = testMode
      ? positiveInteger(options.heartbeatMs || process.env.GRAPHSMITH_HEARTBEAT_MS, DEFAULT_HEARTBEAT_MS)
      : DEFAULT_HEARTBEAT_MS;
    if (this.heartbeatMs >= this.leaseMs) this.heartbeatMs = Math.max(1, Math.floor(this.leaseMs / 3));
    this._crashAfterEffects = 0;
    this._heldOwnerToken = null;

    this.window = {
      get: () => this.getWindow(),
      admitPending: (tx) => this.admitPending(tx),
      finalize: (windowId) => this.finalizeWindow(windowId),
      observeSlot: (runId, treeId) => this.observeSlot(runId, treeId),
      dispose: (runId, result) => this.disposeSlot(runId, result),
      close: (windowId, outcome) => this.closeWindow(windowId, outcome),
    };
    this.runRegistry = {
      register: (runId, treeId) => this.registerRun(runId, treeId),
      deregister: (runId, result) => this.deregisterRun(runId, result),
      heartbeat: (runId) => this.heartbeatRun(runId),
      sweepExpired: () => this.sweepExpired(),
      get: (runId) => this.getRun(runId),
      list: () => this.listRuns(),
    };
    this.runAnchors = {
      setAnchor: (runId, anchor) => this.setAnchor(runId, anchor),
      getAnchor: (runId) => this.getAnchor(runId),
    };
    this.alphaLedger = {
      reserve: (reservation) => this.reserveAlpha(reservation),
      complete: (reservationId, outcome) => this.completeAlpha(reservationId, outcome),
      list: (corpusState) => this.listAlpha(corpusState),
    };
    this.rejectedBuffer = {
      push: (entry) => this.pushRejected(entry),
      list: () => this.listRejected(),
    };
    this.rollbackFamilies = {
      append: (entry) => this.appendRollback(entry),
      list: () => this.listRollbacks(),
      humanAck: (fingerprint, acknowledgement) => this.ackRollback(fingerprint, acknowledgement),
    };
    this._testing = {
      acquireLock: () => this._acquireLock(),
      releaseLock: (ownerToken) => this._releaseLock(ownerToken),
      crashNextMutationAfter: (count) => { this._crashAfterEffects = positiveInteger(count, 1); },
    };
  }

  _path(file) {
    if (!Object.values(FILES).includes(file)) throw fail(`Unowned state file: ${file}`, "INVALID_STATE_PATH");
    return path.join(this.stateDir, file);
  }

  _ensureStateDir() {
    fs.mkdirSync(this.stateDir, { recursive: true });
  }

  _read(file) {
    try { return fs.readFileSync(this._path(file), "utf8"); }
    catch (error) { if (error.code === "ENOENT") return ""; throw error; }
  }

  _appendDurable(filePath, record) {
    validateStateRecord(record, path.basename(filePath));
    const fd = fs.openSync(filePath, "a");
    try {
      fs.writeSync(fd, `${JSON.stringify(record)}\n`);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
  }

  _atomicReplace(file, content) {
    validateStateContent(file, content);
    const target = this._path(file);
    const temporary = `${target}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
    const fd = fs.openSync(temporary, "wx");
    try {
      fs.writeSync(fd, content);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    try {
      fs.renameSync(temporary, target);
      try {
        const dirFd = fs.openSync(this.stateDir, "r");
        try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
      } catch (error) {
        if (process.platform !== "win32" && !["EINVAL", "EISDIR", "EPERM"].includes(error.code)) throw error;
      }
    } catch (error) {
      try { fs.unlinkSync(temporary); } catch {}
      throw error;
    }
  }

  // The lock must never be OBSERVABLE in a half-formed state. The historical
  // `openSync(lockPath, "wx")` + `writeSync` pair made the file exist before its
  // content did, so a competing acquirer that hit EEXIST and read it saw "" (or a
  // truncated record) and the store reported CORRUPT_STATE for what was only an
  // ordinary acquisition race. Writing to a temp file and hard-LINKING it into
  // place keeps the exclusive-create contract -- link() fails EEXIST when the
  // lock is held, exactly as "wx" did -- while making the record atomically
  // visible, fully formed. Filesystems without hard links fall back to the old
  // two-step create; _acquireLock's retry below covers that residual window.
  _createLockFile(record) {
    const payload = JSON.stringify(record);
    const temporary = `${this.lockPath}.new-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
    const writeTo = (target, flag) => {
      const fd = fs.openSync(target, flag);
      try { fs.writeSync(fd, payload); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    };
    writeTo(temporary, "wx");
    try {
      fs.linkSync(temporary, this.lockPath);
    } catch (error) {
      try { fs.unlinkSync(temporary); } catch (cleanupError) { /* best effort */ }
      if (["EPERM", "ENOSYS", "EXDEV", "EOPNOTSUPP", "ENOTSUP"].includes(error.code)) {
        writeTo(this.lockPath, "wx");   // no hard links here; EEXIST still propagates
        return;
      }
      throw error;                      // EEXIST -> the caller's contention path
    }
    try { fs.unlinkSync(temporary); } catch (error) { /* the lock keeps the inode */ }
  }

  _readLock() {
    try {
      const record = parseStateJson(fs.readFileSync(this.lockPath, "utf8"), path.basename(this.lockPath));
      return { record, stat: fs.statSync(this.lockPath) };
    } catch (error) {
      if (error.code === "ENOENT") return null;
      if (error.code === "CORRUPT_STATE") throw error;
      throw fail(`Unreadable state lock: ${error.message}`, "CORRUPT_STATE");
    }
  }

  /* Liveness for lock ownership. Two corrections, both found by adversarial review with
   * working reproductions:
   *
   *   EPERM means ALIVE, not dead. A bare `catch { return false }` conflated "no such
   *   process" with "cannot determine". A lock held by another USER was therefore reported
   *   as ownerless and stolen -- demonstrated cross-uid on a lock 107ms old against a
   *   30s lease, i.e. the freshness of the lock could not save it.
   *
   *   A ZOMBIE is DEAD for this purpose. kill(pid, 0) succeeds on a process that has
   *   exited but not been reaped, so an unreaped owner looked alive. That is not academic
   *   here: scripts/watchdog.js SIGKILLs runs, and a killed child whose parent has not
   *   reaped it is exactly a zombie. Treating it as alive makes crash recovery fail in
   *   the one scenario the product itself manufactures. Only /proc can tell us, so this
   *   is a Linux-only refinement; elsewhere the lease fallback covers it.
   *
   * ESRCH from a DIFFERENT PID NAMESPACE is indistinguishable from a genuinely absent
   * process and this cannot fix that. It is why the lease remains a second gate rather
   * than this being the sole authority. */
  _pidAlive(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try {
      process.kill(pid, 0);
    } catch (error) {
      if (error.code === "EPERM") return true;   // exists, we may not signal it
      return false;                               // ESRCH, or a platform that cannot say
    }
    try {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const close = stat.lastIndexOf(")");
      if (close !== -1 && stat.slice(close + 2).split(" ")[0] === "Z") return false;
    } catch (error) { /* no /proc: signal 0 is the best answer available */ }
    return true;
  }

  _unlinkLockIfOwner(ownerToken) {
    const fd = fs.openSync(this.lockPath, "r");
    try {
      const raw = fs.readFileSync(fd, "utf8");
      const current = parseStateJson(raw, path.basename(this.lockPath));
      if (current.owner_token !== ownerToken) return false;
      fs.unlinkSync(this.lockPath);
      return true;
    } finally { fs.closeSync(fd); }
  }

  _acquireLock() {
    this._ensureStateDir();
    const ATTEMPTS = 8;
    let unreadableLock = null;
    for (let attempt = 0; attempt < ATTEMPTS; attempt++) {
      const ownerToken = crypto.randomBytes(16).toString("hex");
      const record = {
        schema_version: SCHEMA_VERSION,
        pid: process.pid,
        owner_token: ownerToken,
      };
      validateStateRecord(record, path.basename(this.lockPath));
      try {
        this._createLockFile(record);
        /* NO setInterval here any more.
         *
         * There was one, renewing the lock's mtime every heartbeatMs. It could never fire:
         * `_operation` and every caller of `_testing.acquireLock` (promote.js holds the lock
         * across an entire fsync-heavy adoption transaction) are FULLY SYNCHRONOUS, so the
         * event loop is blocked for the whole critical section and `clearInterval` runs in
         * the `finally` before the timer could ever run. Reproduced: 300ms lease, 800ms of
         * synchronous work, lock mtime unchanged (delta 0ms), a second store ACQUIRED the
         * lock while the first still held it, and the owner's release then failed
         * LOCK_OWNER_MISMATCH.
         *
         * A timer that cannot fire is worse than no timer: it tells a reader the lock is
         * kept fresh when nothing keeps it fresh. Renewal is now explicit and synchronous,
         * at the durable writes in `_commit`, where the time actually goes. */
        this._heldOwnerToken = ownerToken;
        return { ownerToken, heartbeat: null };
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        // A lock file that EXISTS but does not parse is either being BORN (the
        // window _createLockFile closes, still reachable via its no-hard-link
        // fallback) or genuinely damaged (a crash between create and write).
        // Those are indistinguishable in any single observation -- only
        // PERSISTENCE tells them apart. Reporting CORRUPT_STATE on the first
        // sight, as this did, turned an ordinary acquisition race into "your
        // state store is corrupt" and aborted a healthy operation. Retry within
        // the bounded loop; if it is still unreadable after every attempt, it is
        // reported as corruption below. It is never silently stolen: the steal
        // path needs the owner_token that an unparseable lock cannot supply.
        let observed;
        try {
          observed = this._readLock();
        } catch (readError) {
          if (readError.code !== "CORRUPT_STATE") throw readError;
          unreadableLock = readError;
          // Outlast a write window without busy-spinning: 8 x 2ms >> the
          // microseconds between creating the file and its content landing.
          try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2); } catch (waitError) { /* best effort */ }
          continue;
        }
        unreadableLock = null;
        if (!observed) continue;
        /* TWO GATES, and the renewal above is what makes the second one mean something.
         *
         * The original defect: `age > leaseMs || !pidAlive` stole a lock from a live owner
         * purely because its mtime was old -- and with the renewal timer unable to fire,
         * "old mtime" was simply "a transaction longer than leaseMs". Two writers then
         * entered _commit and recovery reached AMBIGUOUS_RECOVERY. promote.js holds this
         * lock across an entire fsync-heavy adoption, so it was reachable in production.
         *
         * The first attempt at a fix deleted the age gate entirely, leaving _pidAlive as
         * the sole authority. Adversarial review demolished that: a crashed owner in a PID
         * namespace leaves a lock whose pid is the NEXT run's own pid, so the store bricked
         * permanently after any container crash -- including `status` and `sweep`, the two
         * commands an operator would use to diagnose it. Trading split-brain for a brick is
         * not a fix.
         *
         * Both gates, in the right order:
         *   owner observably alive AND the lock is being renewed  -> refuse. This is the
         *     long-transaction case, and it is now safe BECAUSE _commit renews at every
         *     durable step: a working owner's mtime cannot go stale.
         *   otherwise, once the lock has gone unrenewed for longer than the lease -> steal.
         *     A stale mtime now means "this owner has made no progress", not "this owner
         *     started a while ago", which is the fact the steal actually needs. Zombies,
         *     stopped processes, foreign namespaces and reused pids all self-heal here.
         *
         * What this still does NOT cover, stated rather than papered over: a holder that
         * does long work WITHOUT touching the store renews nothing, so a sufficiently long
         * non-store phase can still be stolen from. The durable answer is an OS-level lock
         * whose lifetime is tied to the owner's file descriptor rather than to an mtime and
         * a pid. Node exposes no such primitive at zero dependencies (no `fs.flock`, no
         * `fcntl`, no `O_EXLOCK` on any supported platform), so it is recorded as a
         * limitation in KNOWN-LIMITATIONS.md rather than tracked as pending work.
         *
         * THIRD GATE, and it exists because `age` is a WALL-CLOCK subtraction.
         *
         * `Date.now() - mtimeMs` silently assumes the mtime is in the past. It is not
         * always: a backward NTP correction, a VM resuming from suspend, a network
         * filesystem whose server clock leads ours, or a restored backup that preserved
         * mtimes all leave a lock whose mtime is in the FUTURE. `age` then goes negative,
         * `unrenewed` is false, and BOTH gates below refuse -- forever, for the whole
         * duration of the skew, even when the owning pid is long dead. Reproduced: a lock
         * owned by a dead pid with an mtime 24h ahead wedged the store for 24h, reporting
         * "renewed -3599995ms ago ... that owner is alive and making progress".
         *
         * That is not a slow acquisition, it is an outage: `_operation` takes this lock for
         * EVERY store call including reads (`window.get`), and promote's `recover()` -- the
         * command an operator would reach for -- takes it too. The repair path is blocked
         * by the fault it repairs.
         *
         * A future mtime does not mean "freshly renewed". It means the mtime is unusable as
         * an elapsed-time source, and the decision has to fall to the only other evidence
         * available: is the owning process observably alive? Dead owner -> steal, which is
         * what a dead owner has always deserved. Live owner -> still refuse, but say
         * "clock skew" so an operator can see what they are looking at instead of reading a
         * negative age. Same defect class as the other nine: a wall-clock subtraction used
         * as a proxy for "this owner has made no progress". */
        const age = Date.now() - observed.stat.mtimeMs;
        const ownerAlive = this._pidAlive(observed.record.pid);
        /* NOT `age < 0`. A strict sign test makes the gate fire on filesystem timestamp
         * granularity rather than on a clock correction: a filesystem that rounds mtime up
         * (FAT32 stores 2-second granularity; HFS+ 1 second) can hand back a mtime very
         * slightly ahead of the writer's own `Date.now()`, and a strict test would then
         * report LOCK_CLOCK_SKEW for ordinary, healthy contention on every acquire. That
         * would be a worse bug than the one being fixed, and it would only appear on the
         * platforms hardest for us to reproduce.
         *
         * Measured on Linux across 3000 freshly-created locks via the real acquire path:
         * minimum observed age 0.117ms, never negative. The tolerance exists for the
         * platforms and filesystems that measurement does NOT cover.
         *
         * The constant has to clear the coarsest granularity we could plausibly land on
         * (2s) with margin, while staying far below any real correction -- NTP steps, VM
         * resume and cross-host clock disagreement are seconds to hours. Inside the
         * tolerance nothing changes: `unrenewed` is false for a small age, so the two
         * original gates decide exactly as they did before, and the state self-heals as
         * real time passes. */
        const future = age < 0;
        /* OWNER DEATH IS DECISIVE, AND THE TOLERANCE MUST NOT OVERRIDE IT.
         *
         * The first version of this gate applied the tolerance to both branches:
         * `skewed = age < -TOLERANCE`, and anything inside the band fell through to the two
         * original gates. For a DEAD owner that reproduced the exact wedge this gate exists
         * to remove -- a negative age is never `> leaseMs`, so `unrenewed` stayed false and
         * the second gate refused. Measured, dead pid, 30s lease, 5s tolerance:
         *
         *   mtime  -60000ms -> ACQUIRED      mtime   +4999ms -> LOCKED   <-- wedged
         *   mtime      +0ms -> LOCKED        mtime  +20000ms -> ACQUIRED
         *   mtime   +1000ms -> LOCKED        mtime +86400000ms -> ACQUIRED
         *
         * A bounded wedge (skew + lease, ~35s) rather than the original unbounded one, but
         * the same defect, and the refusal message promised "stealable as soon as that pid
         * exits" -- which was false inside the band. Found by two independent reviewers on
         * the shipped diff, not by this file's own tests, which never pinned a dead owner
         * inside the tolerance.
         *
         * So the tolerance is now DIAGNOSTIC ONLY, and only for a live owner: it decides
         * whether a future mtime is worth naming as clock skew or is just filesystem
         * timestamp granularity. It never decides whether a dead owner's lock survives. */
        if (future && !ownerAlive) {
          requiredString(observed.record.owner_token, "state.lock owner_token");
          try {
            if (!this._unlinkLockIfOwner(observed.record.owner_token)) continue;
          } catch (stealError) {
            if (stealError.code === "ENOENT") continue;
            throw stealError;
          }
          continue;
        }
        if (future && age < -LOCK_CLOCK_SKEW_TOLERANCE_MS) {
          throw fail(
            `State store lock at ${this.lockPath} has an mtime ${Math.round(-age)}ms in the FUTURE, so ` +
            "its age cannot be used to decide staleness. Refusing while the named pid " +
            `${observed.record.pid} is still observably alive. This is a CLOCK SKEW, not a ` +
            "busy store: check for a backward time correction, a resumed VM, or a network " +
            "filesystem whose server clock leads this host. The lock becomes stealable as " +
            "soon as that pid exits.",
            "LOCK_CLOCK_SKEW");
        }
        const unrenewed = age > this.leaseMs;
        if (ownerAlive && !unrenewed) {
          throw fail(
            `State store is locked by pid ${observed.record.pid} (renewed ${age}ms ago, ` +
            `lease ${this.leaseMs}ms). That owner is alive and making progress.`,
            "LOCKED");
        }
        if (!ownerAlive && !unrenewed) {
          throw fail(
            `State store lock at ${this.lockPath} names pid ${observed.record.pid}, which is ` +
            `not observable, but the lock was renewed only ${age}ms ago (lease ` +
            `${this.leaseMs}ms). Refusing to steal a lock that is still being kept fresh: ` +
            "the owner may simply be invisible from here (another user, another PID " +
            "namespace). It becomes stealable once it goes unrenewed.",
            "LOCKED");
        }
        requiredString(observed.record.owner_token, "state.lock owner_token");
        try {
          if (!this._unlinkLockIfOwner(observed.record.owner_token)) continue;
        } catch (stealError) {
          if (stealError.code === "ENOENT") continue;
          throw stealError;
        }
      }
    }
    // Persisted across every attempt: this is real, and it is reported as such.
    if (unreadableLock)
      throw fail(`State lock ${this.lockPath} existed but never became readable across ${ATTEMPTS} attempts (${unreadableLock.message}). A crash between creating and writing the lock leaves exactly this; remove the file after confirming no run holds it.`, "CORRUPT_STATE");
    throw fail("Could not acquire state-store lock after bounded contention", "LOCK_CONTENTION");
  }

  /* Renew the lock AND prove we still own it, synchronously, at the points where the time
   * actually goes. Replaces the timer that could never fire.
   *
   * The second half matters more than the first: if the lock is gone or now belongs to
   * someone else, this run has been superseded and must stop BEFORE writing anything more.
   * Previously that was discovered at release, after the writes had already landed. */
  _assertStillOwned(context) {
    const ownerToken = this._heldOwnerToken;
    if (!ownerToken) return;   // no lock held by this instance: nothing to assert
    try {
      this._renewLock(ownerToken);
    } catch (error) {
      if (error.code === "LOCK_OWNER_MISMATCH" || error.code === "ENOENT") {
        throw fail(
          `Lost the state-store lock during ${context}: it is ${error.code === "ENOENT" ? "gone" : "now held by another owner"}. ` +
          "Refusing to continue writing -- two writers in the same mutation is how the " +
          "journal becomes ambiguous. Re-run the operation.",
          "LOCK_LOST");
      }
      throw error;
    }
  }

  _renewLock(ownerToken) {
    const fd = fs.openSync(this.lockPath, "r+");
    try {
      const current = parseStateJson(fs.readFileSync(fd, "utf8"), path.basename(this.lockPath));
      if (current.owner_token !== ownerToken) throw fail("Refusing to renew a lock owned by another token", "LOCK_OWNER_MISMATCH");
      const now = new Date();
      fs.futimesSync(fd, now, now);
    } finally { fs.closeSync(fd); }
  }

  _releaseLock(ownerToken) {
    let current;
    try { current = this._readLock(); }
    catch (error) { throw error; }
    if (!current) return false;
    if (current.record.owner_token !== ownerToken) throw fail("Refusing to release a lock owned by another token", "LOCK_OWNER_MISMATCH");
    if (!this._unlinkLockIfOwner(ownerToken)) throw fail("Lock owner changed during release", "LOCK_OWNER_MISMATCH");
    /* Cleared only AFTER the release is verified. It was cleared on ENTRY, so a release
     * that THREW still disarmed _assertStillOwned -- and promote.js swallows release
     * failures, so a run whose lock had been taken carried on committing with the guard
     * silently off. Found by adversarial review with a working reproduction. */
    if (this._heldOwnerToken === ownerToken) this._heldOwnerToken = null;
    return true;
  }

  _journalRecords() {
    let raw = "";
    try { raw = fs.readFileSync(this.journalPath, "utf8"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    return parseJsonLines(raw, path.basename(this.journalPath));
  }

  _nextRevision() {
    return this._journalRecords().reduce((max, record) => Math.max(max, Number.isSafeInteger(record.state_rev) ? record.state_rev : 0), 0) + 1;
  }

  _recoverJournal() {
    /* Roll-forward rewrites whole state files from a journal that may have been written by
     * ANOTHER process, and appends MUTATION_DONE. It had no ownership check at all -- the
     * most dangerous write path in the file was the one the new guard did not cover, which
     * an adversarial review demonstrated by rolling another writer's mutation forward with
     * no lock held. It is called first inside _operation and directly by promote.js. */
    this._assertStillOwned("journal recovery");
    const records = this._journalRecords();
    const completed = new Set(records.filter((record) => record.record_type === "MUTATION_DONE").map((record) => record.mutation_id));
    for (const intent of records) {
      if (intent.record_type !== "MUTATION_INTENT" || completed.has(intent.mutation_id)) continue;
      for (const effect of intent.effects) {
        const current = this._read(effect.file);
        const currentHash = sha256(current);
        if (currentHash === effect.after_sha256) continue;
        if (currentHash !== effect.before_sha256) {
          throw fail(`HALT: journal recovery found ambiguous ${effect.file} for mutation ${intent.mutation_id}`, "AMBIGUOUS_RECOVERY");
        }
        const intended = Buffer.from(effect.content_base64, "base64").toString("utf8");
        if (sha256(intended) !== effect.after_sha256) throw fail(`HALT: corrupt journal payload for ${intent.mutation_id}`, "CORRUPT_JOURNAL");
        this._atomicReplace(effect.file, intended);
      }
      this._appendDurable(this.journalPath, {
        schema_version: SCHEMA_VERSION,
        record_type: "MUTATION_DONE",
        mutation_id: intent.mutation_id,
        state_rev: intent.state_rev,
      });
    }
  }

  _commit(builders) {
    const stateRev = this._nextRevision();
    const effects = builders.map(({ file, make }) => {
      const before = this._read(file);
      const after = make(before, stateRev);
      if (typeof after !== "string") throw fail(`Mutation builder for ${file} did not return serialized content`, "INVALID_MUTATION");
      validateStateContent(file, after);
      return {
        file,
        before_sha256: sha256(before),
        after_sha256: sha256(after),
        content_base64: Buffer.from(after, "utf8").toString("base64"),
        after,
      };
    });
    if (effects.every((effect) => effect.before_sha256 === effect.after_sha256)) return stateRev - 1;
    const mutationId = `${stateRev}-${stableId(effects.map((effect) => `${effect.file}:${effect.after_sha256}`))}`;
    this._assertStillOwned("the pre-intent check of a mutation");
    this._appendDurable(this.journalPath, {
      schema_version: SCHEMA_VERSION,
      record_type: "MUTATION_INTENT",
      mutation_id: mutationId,
      state_rev: stateRev,
      effects: effects.map(({ after, ...effect }) => effect),
    });
    let applied = 0;
    for (const effect of effects) {
      /* Before EVERY effect, not once per transaction. This is what makes the lock's mtime
       * mean "this owner is making progress" rather than "this owner started recently", and
       * it is the granularity at which a lost lock is detected. */
      this._assertStillOwned(`writing ${effect.file}`);
      if (effect.before_sha256 !== effect.after_sha256) this._atomicReplace(effect.file, effect.after);
      applied++;
      if (this._crashAfterEffects && applied >= this._crashAfterEffects) {
        this._crashAfterEffects = 0;
        throw fail("Simulated crash after journaled effect", "SIMULATED_CRASH");
      }
    }
    this._assertStillOwned("completing a mutation");
    this._appendDurable(this.journalPath, {
      schema_version: SCHEMA_VERSION,
      record_type: "MUTATION_DONE",
      mutation_id: mutationId,
      state_rev: stateRev,
    });
    return stateRev;
  }

  _operation(fn, sweep = true) {
    const lock = this._acquireLock();
    try {
      this._recoverJournal();
      if (sweep) this._sweepExpiredLocked();
      return fn();
    } finally {
      clearInterval(lock.heartbeat);
      try { this._releaseLock(lock.ownerToken); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  }

  _registryState(records) {
    const active = new Map();
    for (const record of records) {
      if (record.record_type === "REGISTERED") active.set(record.run_id, clone(record));
      else if (record.record_type === "HEARTBEAT" && active.has(record.run_id)) {
        /* A heartbeat RENEWS a lease; it must never revoke one. This was an unconditional
         * overwrite, so a wall clock stepping backward (NTP correction) across a heartbeat
         * wrote an EARLIER expiry than the one it replaced, and a live, heartbeating run
         * was then swept as `abandoned` -- which also sets the window FLAG bit. Reproduced
         * by an adversarial review on the default clock.
         *
         * Math.max also makes replay safe: a delayed or duplicated heartbeat record can no
         * longer shorten a newer lease. It does not weaken "expire promptly" -- it grants
         * no time beyond a deadline the store had already issued. */
        const current = active.get(record.run_id);
        current.lease_expires_at = Math.max(current.lease_expires_at, record.lease_expires_at);
      }
      else if (record.record_type === "DEREGISTERED" || record.record_type === "EXPIRED") active.delete(record.run_id);
    }
    return active;
  }

  _terminalize(windowRecord, runId, disposition) {
    if (!windowRecord.window) return false;
    const slot = windowRecord.window.slots.find((candidate) => candidate.run_id === runId);
    if (!slot || slot.status === "terminal") return false;
    slot.status = "terminal";
    slot.disposition = disposition;
    windowRecord.window.active = Math.max(0, windowRecord.window.active - 1);
    if (disposition === "abandoned" || disposition === "completed_soft_wobble") windowRecord.flag = true;
    if (disposition === "completed_hard_fail") windowRecord.state = "ROLLING_BACK";
    return true;
  }

  _sweepExpiredLocked() {
    const registryRaw = this._read(FILES.registry);
    const registryRecords = parseJsonLines(registryRaw, FILES.registry);
    const active = this._registryState(registryRecords);
    const now = this.leaseNow();
    const expired = [...active.values()].filter((record) => record.lease_expires_at <= now).sort((a, b) => a.run_id.localeCompare(b.run_id));
    const windowRaw = this._read(FILES.window);
    const windowRecord = parseWindow(windowRaw);
    let wallExpired = false;
    if (windowRecord.window && ["ADMITTED", "OBSERVING"].includes(windowRecord.state)) {
      wallExpired = now - windowRecord.window.created_at >= windowRecord.window.max_window_wall_time_ms;
    }
    if (expired.length === 0 && !wallExpired) return [];
    this._commit([
      {
        file: FILES.registry,
        make: (raw, rev) => {
          const records = parseJsonLines(raw, FILES.registry);
          for (const record of expired) records.push({
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "EXPIRED", run_id: record.run_id,
          });
          return jsonLines(records);
        },
      },
      {
        file: FILES.window,
        make: (raw, rev) => {
          const value = parseWindow(raw);
          let changed = false;
          for (const record of expired) changed = this._terminalize(value, record.run_id, "abandoned") || changed;
          if (wallExpired && value.window && ["ADMITTED", "OBSERVING"].includes(value.state)) {
            for (const slot of value.window.slots) {
              if (slot.status === "active") { slot.status = "terminal"; slot.disposition = "superseded"; }
            }
            value.flag = true;
            value.state = "CLOSED_FLAGGED";
            value.window.active = 0;
            value.window.close_reason = "max_window_wall_time";
            changed = true;
          }
          if (changed) value.state_rev = rev;
          return changed ? JSON.stringify(value) : raw;
        },
      },
    ]);
    return expired.map((record) => record.run_id);
  }

  getWindow() {
    return this._operation(() => clone(parseWindow(this._read(FILES.window))));
  }

  admitPending(tx) {
    if (!tx || typeof tx !== "object") throw fail("tx is required", "INVALID_ARGUMENT");
    return this._operation(() => {
      let result;
      this._commit([{
        file: FILES.window,
        make: (raw, rev) => {
          const current = parseWindow(raw);
          if (!["NO_WINDOW", "CLOSED_PASS", "CLOSED_ROLLED_BACK", "CLOSED_FLAGGED"].includes(current.state)) {
            throw fail(`Cannot admit a window while state is ${current.state}`, "WINDOW_EXISTS");
          }
          if (tx.expected_state_rev !== undefined && tx.expected_state_rev !== current.state_rev) throw fail("Window state_rev expectation failed", "CAS_MISMATCH");
          const windowId = requiredString(tx.window_id || tx.windowId || tx.txid, "window_id");
          const n = positiveInteger(tx.n || tx.N, 5);
          result = {
            schema_version: SCHEMA_VERSION,
            state_rev: rev,
            state: "ADMITTED",
            flag: false,
            window: {
              window_id: windowId,
              adoption_txid: requiredString(tx.adoption_txid || tx.txid || windowId, "adoption_txid"),
              candidate_fingerprint: requiredString(tx.candidate_fingerprint || tx.fingerprint, "candidate_fingerprint"),
              tree_id: requiredString(tx.tree_id || tx.treeId, "tree_id"),
              n,
              baseline_metric: tx.baseline_metric === undefined ? null : clone(tx.baseline_metric),
              created_at: this.leaseNow(),
              max_window_wall_time_ms: positiveInteger(tx.max_window_wall_time_ms, DEFAULT_WINDOW_MS),
              admitted: 0,
              active: 0,
              slots: [],
            },
          };
          return JSON.stringify(result);
        },
      }]);
      return clone(result);
    });
  }

  finalizeWindow(windowId) {
    requiredString(windowId, "windowId");
    return this._operation(() => {
      let result;
      this._commit([{
        file: FILES.window,
        make: (raw, rev) => {
          const value = parseWindow(raw);
          if (!value.window || value.window.window_id !== windowId) throw fail("Unknown window", "WINDOW_NOT_FOUND");
          if (value.state === "OBSERVING") { result = value; return raw; }
          if (value.state !== "ADMITTED") throw fail(`Cannot finalize window in ${value.state}`, "INVALID_WINDOW_STATE");
          value.state = "OBSERVING";
          value.state_rev = rev;
          result = value;
          return JSON.stringify(value);
        },
      }]);
      return clone(result);
    });
  }

  _observe(value, runId, treeId) {
    if (!value.window || value.state !== "OBSERVING" || value.window.tree_id !== treeId) return null;
    const existing = value.window.slots.find((slot) => slot.run_id === runId);
    if (existing) return existing;
    if (value.window.slots.length >= value.window.n) return null;
    const slot = { slot_id: value.window.slots.length + 1, run_id: runId, status: "active", disposition: null };
    value.window.slots.push(slot);
    value.window.admitted++;
    value.window.active++;
    return slot;
  }

  observeSlot(runId, treeId) {
    requiredString(runId, "runId"); requiredString(treeId, "treeId");
    return this._operation(() => {
      let result = null;
      this._commit([{
        file: FILES.window,
        make: (raw, rev) => {
          const value = parseWindow(raw);
          const before = value.window ? value.window.slots.length : 0;
          result = this._observe(value, runId, treeId);
          if (!result || (value.window && value.window.slots.length === before)) return raw;
          value.state_rev = rev;
          return JSON.stringify(value);
        },
      }]);
      return result ? clone(result) : null;
    });
  }

  _disposition(result) {
    if (result && TERMINAL_DISPOSITIONS.has(result.disposition)) return result.disposition;
    if (result && (result.hard_failure || result.budget_breach || result.tripwire)) return "completed_hard_fail";
    if (result && result.soft_wobble) return "completed_soft_wobble";
    return "completed_pass";
  }

  disposeSlot(runId, result = {}) {
    requiredString(runId, "runId");
    const disposition = this._disposition(result);
    return this._operation(() => {
      let changed = false;
      this._commit([{
        file: FILES.window,
        make: (raw, rev) => {
          const value = parseWindow(raw);
          changed = this._terminalize(value, runId, disposition);
          if (!changed) return raw;
          value.state_rev = rev;
          return JSON.stringify(value);
        },
      }]);
      return { run_id: runId, disposition, changed };
    });
  }

  closeWindow(windowId, outcome) {
    requiredString(windowId, "windowId");
    return this._operation(() => {
      let result;
      this._commit([{
        file: FILES.window,
        make: (raw, rev) => {
          const value = parseWindow(raw);
          if (!value.window || value.window.window_id !== windowId) throw fail("Unknown window", "WINDOW_NOT_FOUND");
          const slots = value.window.slots;
          if (!slots.every((slot) => slot.status === "terminal")) throw fail("Cannot close while admitted slots are active", "WINDOW_ACTIVE");
          const hard = slots.some((slot) => slot.disposition === "completed_hard_fail");
          if (!hard && slots.length < value.window.n && outcome !== "flagged") throw fail("Cannot pass an incompletely admitted window", "WINDOW_INCOMPLETE");
          if (outcome === "rolled_back") value.state = "CLOSED_ROLLED_BACK";
          else if (outcome === "halt_human") value.state = "HALT_HUMAN";
          else if (outcome === "flagged" || value.flag) value.state = "CLOSED_FLAGGED";
          else if (hard) value.state = "ROLLING_BACK";
          else value.state = "CLOSED_PASS";
          value.state_rev = rev;
          result = value;
          return JSON.stringify(value);
        },
      }]);
      return clone(result);
    });
  }

  registerRun(runId, treeId) {
    requiredString(runId, "runId"); requiredString(treeId, "treeId");
    return this._operation(() => {
      const registryRaw = this._read(FILES.registry);
      const active = this._registryState(parseJsonLines(registryRaw, FILES.registry));
      if (active.has(runId)) {
        const existing = active.get(runId);
        if (existing.tree_id !== treeId) throw fail("runId is already registered to another tree", "RUN_CONFLICT");
        return { registration: clone(existing), slot: null, existing: true };
      }
      const leaseExpiresAt = this._leaseExpiryFrom(this.leaseNow());
      let registration;
      let slot = null;
      this._commit([
        {
          file: FILES.registry,
          make: (raw, rev) => {
            const records = parseJsonLines(raw, FILES.registry);
            registration = {
              schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "REGISTERED",
              run_id: runId, tree_id: treeId, lease_expires_at: leaseExpiresAt,
            };
            records.push(registration);
            return jsonLines(records);
          },
        },
        {
          file: FILES.window,
          make: (raw, rev) => {
            const value = parseWindow(raw);
            slot = this._observe(value, runId, treeId);
            if (!slot) return raw;
            value.state_rev = rev;
            return JSON.stringify(value);
          },
        },
      ]);
      return { registration: clone(registration), slot: slot ? clone(slot) : null, existing: false };
    });
  }

  heartbeatRun(runId) {
    requiredString(runId, "runId");
    return this._operation(() => {
      const active = this._registryState(parseJsonLines(this._read(FILES.registry), FILES.registry));
      if (!active.has(runId)) throw fail("Run is not registered", "RUN_NOT_FOUND");
      let record;
      this._commit([{
        file: FILES.registry,
        make: (raw, rev) => {
          const records = parseJsonLines(raw, FILES.registry);
          record = {
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "HEARTBEAT", run_id: runId,
            lease_expires_at: this._leaseExpiryFrom(this.leaseNow()),
          };
          records.push(record);
          return jsonLines(records);
        },
      }]);
      return clone(record);
    });
  }

  deregisterRun(runId, result = {}) {
    requiredString(runId, "runId");
    return this._operation(() => {
      const active = this._registryState(parseJsonLines(this._read(FILES.registry), FILES.registry));
      if (!active.has(runId)) return { deregistered: false, disposition: null };
      const disposition = this._disposition(result);
      this._commit([
        {
          file: FILES.registry,
          make: (raw, rev) => {
            const records = parseJsonLines(raw, FILES.registry);
            records.push({
              schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "DEREGISTERED",
              run_id: runId, result: clone(result),
            });
            return jsonLines(records);
          },
        },
        {
          file: FILES.window,
          make: (raw, rev) => {
            const value = parseWindow(raw);
            if (!this._terminalize(value, runId, disposition)) return raw;
            value.state_rev = rev;
            return JSON.stringify(value);
          },
        },
      ]);
      return { deregistered: true, disposition };
    });
  }

  sweepExpired() {
    return this._operation(() => this._sweepExpiredLocked(), false);
  }

  listRuns() {
    return this._operation(() => [...this._registryState(parseJsonLines(this._read(FILES.registry), FILES.registry)).values()].map(clone));
  }

  getRun(runId) {
    requiredString(runId, "runId");
    return this.listRuns().find((record) => record.run_id === runId) || null;
  }

  setAnchor(runId, anchor) {
    requiredString(runId, "runId");
    if (!anchor || typeof anchor !== "object") throw fail("anchor is required", "INVALID_ARGUMENT");
    return this._operation(() => {
      let record;
      this._commit([{
        file: FILES.anchors,
        make: (raw, rev) => {
          const records = parseJsonLines(raw, FILES.anchors);
          record = {
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "ANCHOR_SET", run_id: runId,
            chain_head: requiredString(anchor.chain_head || anchor.chainHead, "chain_head"),
            expected_terminal_status: requiredString(anchor.expected_terminal_status || anchor.expectedTerminalStatus, "expected_terminal_status"),
          };
          records.push(record);
          return jsonLines(records);
        },
      }]);
      return clone(record);
    });
  }

  getAnchor(runId) {
    requiredString(runId, "runId");
    return this._operation(() => {
      const records = parseJsonLines(this._read(FILES.anchors), FILES.anchors).filter((record) => record.run_id === runId);
      return records.length ? clone(records[records.length - 1]) : null;
    });
  }

  reserveAlpha(input) {
    if (!input || typeof input !== "object") throw fail("reservation is required", "INVALID_ARGUMENT");
    const corpusState = requiredString(input.corpus_state || input.corpusState, "corpus_state");
    const splitHash = requiredString(input.split_hash || input.splitHash, "split_hash");
    const fingerprint = requiredString(input.fingerprint, "fingerprint");
    const family = requiredString(input.family, "family");
    return this._operation(() => {
      const records = parseJsonLines(this._read(FILES.alpha), FILES.alpha);
      const reservations = records.filter((record) => record.record_type === "RESERVED" && record.corpus_state === corpusState);
      const exact = reservations.find((record) => record.split_hash === splitHash && record.fingerprint === fingerprint && record.family === family);
      if (exact) return clone(exact);
      if (reservations.some((record) => record.family === family)) throw fail("Candidate family already consumed a slot for this corpus state", "ALPHA_FAMILY_CONSUMED");
      const used = new Set(reservations.map((record) => record.alpha_slot));
      const alphaSlot = [1, 2, 3].find((slot) => !used.has(slot));
      if (!alphaSlot) throw fail("All alpha slots are consumed for this corpus state", "ALPHA_EXHAUSTED");
      let reservation;
      this._commit([{
        file: FILES.alpha,
        make: (raw, rev) => {
          const current = parseJsonLines(raw, FILES.alpha);
          reservation = {
            schema_version: SCHEMA_VERSION,
            state_rev: rev,
            record_type: "RESERVED",
            reservation_id: stableId([corpusState, splitHash, fingerprint, family]),
            corpus_state: corpusState,
            split_hash: splitHash,
            fingerprint,
            family,
            alpha_slot: alphaSlot,
            alpha: ALPHA,
          };
          current.push(reservation);
          return jsonLines(current);
        },
      }]);
      return clone(reservation);
    });
  }

  completeAlpha(reservationId, outcome) {
    requiredString(reservationId, "reservationId");
    return this._operation(() => {
      const records = parseJsonLines(this._read(FILES.alpha), FILES.alpha);
      if (!records.some((record) => record.record_type === "RESERVED" && record.reservation_id === reservationId)) throw fail("Unknown alpha reservation", "RESERVATION_NOT_FOUND");
      const prior = records.find((record) => record.record_type === "COMPLETED" && record.reservation_id === reservationId);
      if (prior) return clone(prior);
      let completion;
      this._commit([{
        file: FILES.alpha,
        make: (raw, rev) => {
          const current = parseJsonLines(raw, FILES.alpha);
          completion = {
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "COMPLETED",
            reservation_id: reservationId, outcome: outcome === undefined ? null : clone(outcome),
          };
          current.push(completion);
          return jsonLines(current);
        },
      }]);
      return clone(completion);
    });
  }

  listAlpha(corpusState) {
    return this._operation(() => parseJsonLines(this._read(FILES.alpha), FILES.alpha)
      .filter((record) => corpusState === undefined || record.corpus_state === corpusState)
      .map(clone));
  }

  pushRejected(entry) {
    if (!entry || typeof entry !== "object") throw fail("entry is required", "INVALID_ARGUMENT");
    const fingerprint = requiredString(entry.fingerprint, "fingerprint");
    return this._operation(() => {
      let record;
      this._commit([{
        file: FILES.rejected,
        make: (raw, rev) => {
          const records = parseJsonLines(raw, FILES.rejected);
          record = {
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "REJECTED",
            fingerprint, value: entry.value === undefined ? clone(entry) : clone(entry.value),
          };
          records.push(record);
          return jsonLines(records.slice(-100));
        },
      }]);
      return clone(record);
    });
  }

  listRejected() {
    return this._operation(() => parseJsonLines(this._read(FILES.rejected), FILES.rejected).map(clone));
  }

  appendRollback(entry) {
    if (!entry || typeof entry !== "object") throw fail("entry is required", "INVALID_ARGUMENT");
    const fingerprint = requiredString(entry.fingerprint, "fingerprint");
    return this._operation(() => {
      let record;
      this._commit([{
        file: FILES.rollback,
        make: (raw, rev) => {
          const records = parseJsonLines(raw, FILES.rollback);
          record = {
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "ROLLBACK_RECORDED",
            fingerprint, family: typeof entry.family === "string" ? entry.family : "",
            evidence: entry.evidence === undefined ? null : clone(entry.evidence),
          };
          records.push(record);
          return jsonLines(records);
        },
      }]);
      return clone(record);
    });
  }

  ackRollback(fingerprint, acknowledgement = null) {
    requiredString(fingerprint, "fingerprint");
    return this._operation(() => {
      const records = parseJsonLines(this._read(FILES.rollback), FILES.rollback);
      if (!records.some((record) => record.record_type === "ROLLBACK_RECORDED" && record.fingerprint === fingerprint)) throw fail("Unknown rollback fingerprint", "ROLLBACK_NOT_FOUND");
      const prior = records.find((record) => record.record_type === "HUMAN_ACK" && record.fingerprint === fingerprint);
      if (prior) return clone(prior);
      let record;
      this._commit([{
        file: FILES.rollback,
        make: (raw, rev) => {
          const current = parseJsonLines(raw, FILES.rollback);
          record = {
            schema_version: SCHEMA_VERSION, state_rev: rev, record_type: "HUMAN_ACK",
            fingerprint, acknowledgement: acknowledgement === undefined ? null : clone(acknowledgement),
          };
          current.push(record);
          return jsonLines(current);
        },
      }]);
      return clone(record);
    });
  }

  listRollbacks() {
    return this._operation(() => {
      const records = parseJsonLines(this._read(FILES.rollback), FILES.rollback);
      const acknowledged = new Set(records.filter((record) => record.record_type === "HUMAN_ACK").map((record) => record.fingerprint));
      return records.filter((record) => record.record_type === "ROLLBACK_RECORDED" && !acknowledged.has(record.fingerprint)).map(clone);
    });
  }

  status() {
    return this._operation(() => ({
      schema_version: SCHEMA_VERSION,
      window: clone(parseWindow(this._read(FILES.window))),
      runs: [...this._registryState(parseJsonLines(this._read(FILES.registry), FILES.registry)).values()].map(clone),
      alpha_reservations: parseJsonLines(this._read(FILES.alpha), FILES.alpha).filter((record) => record.record_type === "RESERVED").length,
      rejected_count: parseJsonLines(this._read(FILES.rejected), FILES.rejected).length,
      rollback_families_unacknowledged: (() => {
        const records = parseJsonLines(this._read(FILES.rollback), FILES.rollback);
        const ack = new Set(records.filter((record) => record.record_type === "HUMAN_ACK").map((record) => record.fingerprint));
        return records.filter((record) => record.record_type === "ROLLBACK_RECORDED" && !ack.has(record.fingerprint)).length;
      })(),
    }));
  }
}

function createStore(projectRoot, options) {
  return new StateStore(projectRoot, options);
}

let defaultStore;
function singleton() {
  if (!defaultStore) defaultStore = createStore(process.cwd());
  return defaultStore;
}

const api = {
  SCHEMA_VERSION,
  StateStore,
  createStore,
  status: () => singleton().status(),
  admitPending: (tx) => singleton().admitPending(tx),
  finalize: (windowId) => singleton().finalizeWindow(windowId),
  register: (runId, treeId) => singleton().registerRun(runId, treeId),
  deregister: (runId, result) => singleton().deregisterRun(runId, result),
  window: {
    get: () => singleton().getWindow(),
    admitPending: (tx) => singleton().admitPending(tx),
    finalize: (windowId) => singleton().finalizeWindow(windowId),
    observeSlot: (runId, treeId) => singleton().observeSlot(runId, treeId),
    dispose: (runId, result) => singleton().disposeSlot(runId, result),
    close: (windowId, outcome) => singleton().closeWindow(windowId, outcome),
  },
  runRegistry: {
    register: (runId, treeId) => singleton().registerRun(runId, treeId),
    deregister: (runId, result) => singleton().deregisterRun(runId, result),
    heartbeat: (runId) => singleton().heartbeatRun(runId),
    sweepExpired: () => singleton().sweepExpired(),
  },
  runAnchors: {
    setAnchor: (runId, anchor) => singleton().setAnchor(runId, anchor),
    getAnchor: (runId) => singleton().getAnchor(runId),
  },
  alphaLedger: {
    reserve: (reservation) => singleton().reserveAlpha(reservation),
    complete: (reservationId, outcome) => singleton().completeAlpha(reservationId, outcome),
  },
  rejectedBuffer: {
    push: (entry) => singleton().pushRejected(entry),
    list: () => singleton().listRejected(),
  },
  rollbackFamilies: {
    append: (entry) => singleton().appendRollback(entry),
    list: () => singleton().listRollbacks(),
    humanAck: (fingerprint, acknowledgement) => singleton().ackRollback(fingerprint, acknowledgement),
  },
};

/* Exported so tests use the SAME real clock the product uses, rather than a second
 * near-identical copy that differs only in a metadata tag. */
api.systemLeaseClock = systemLeaseClock;

module.exports = api;

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function selftest() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-state-store-"));
  const previousTestMode = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  const tests = [];
  try {
    const store = createStore(root, { leaseMs: 40, heartbeatMs: 10 });

    store._ensureStateDir();
    const staleToken = crypto.randomBytes(16).toString("hex");
    fs.writeFileSync(store.lockPath, JSON.stringify({
      schema_version: SCHEMA_VERSION, pid: process.pid, proc_start_hint: "selftest-stale", owner_token: staleToken,
    }));
    const old = new Date(Date.now() - 1000);
    fs.utimesSync(store.lockPath, old, old);
    const stolen = store._testing.acquireLock();
    let mismatchRefused = false;
    try { store._testing.releaseLock("0".repeat(32)); }
    catch (error) { mismatchRefused = error.code === "LOCK_OWNER_MISMATCH"; }
    store._testing.releaseLock(stolen.ownerToken);
    clearInterval(stolen.heartbeat);
    if (!mismatchRefused) throw new Error("owner-token mismatch was not refused");
    tests.push({ name: "expired-lock-steal-and-token-refusal", status: "pass" });

    // An EMPTY lock file is exactly what a competing acquirer used to observe
    // between `open(lockPath,"wx")` and the content write, and the store reported
    // it as CORRUPT_STATE on FIRST SIGHT -- an ordinary acquisition race dressed
    // up as state corruption, aborting a healthy operation. Two properties are
    // pinned here; the transient case itself is covered end-to-end by
    // tests/state-store/grok's two-process concurrency battery.
    {
      const raceStore = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
      raceStore._ensureStateDir();

      // (1) The lock is created fully formed, and leaves no temp file behind.
      const created = raceStore._testing.acquireLock();
      const lockRaw = fs.readFileSync(raceStore.lockPath, "utf8");
      if (!lockRaw || JSON.parse(lockRaw).owner_token !== created.ownerToken)
        throw new Error("lock file was not fully formed on creation");
      const strays = fs.readdirSync(raceStore.stateDir).filter((entry) => entry.includes(".lock.new-"));
      if (strays.length) throw new Error(`atomic lock create left temp file(s): ${strays.join(", ")}`);
      raceStore._testing.releaseLock(created.ownerToken);
      clearInterval(created.heartbeat);

      // (2) An unreadable lock is RETRIED across the whole budget, and only then
      // reported as corruption -- never condemned on the first observation.
      fs.writeFileSync(raceStore.lockPath, "");
      let condemned = null;
      let message = "";
      try { raceStore._testing.acquireLock(); }
      catch (error) { condemned = error.code; message = error.message; }
      try { fs.unlinkSync(raceStore.lockPath); } catch (error) { /* cleanup */ }
      if (condemned !== "CORRUPT_STATE")
        throw new Error(`a permanently unreadable lock must report CORRUPT_STATE, got ${condemned}`);
      if (!/never became readable across \d+ attempts/.test(message))
        throw new Error(`an unreadable lock must be retried before it is condemned, got: ${message}`);
      tests.push({ name: "lock-created-atomically-unreadable-lock-retried-then-condemned", status: "pass" });
    }

    store.window.admitPending({ txid: "tx-selftest", fingerprint: "fp-selftest", tree_id: "tree-selftest", n: 1 });
    store.window.finalize("tx-selftest");
    store._testing.crashNextMutationAfter(1);
    let simulated = false;
    try { store.runRegistry.register("run-recover", "tree-selftest"); }
    catch (error) { simulated = error.code === "SIMULATED_CRASH"; }
    if (!simulated) throw new Error("journal tear was not simulated");
    const recovered = createStore(root, { leaseMs: 40, heartbeatMs: 10 });
    const recoveredWindow = recovered.window.get();
    if (!recoveredWindow.window.slots.some((slot) => slot.run_id === "run-recover")) throw new Error("journal did not roll forward window slot");
    tests.push({ name: "journal-inspect-and-roll-forward", status: "pass" });

    const first = recovered.alphaLedger.reserve({ corpus_state: "corpus-a", split_hash: "split-a", fingerprint: "fp-a", family: "family-a" });
    const restarted = createStore(root, { leaseMs: 40, heartbeatMs: 10 });
    const second = restarted.alphaLedger.reserve({ corpus_state: "corpus-a", split_hash: "split-b", fingerprint: "fp-b", family: "family-b" });
    if (first.alpha_slot !== 1 || second.alpha_slot !== 2) throw new Error("crashed reservation did not remain consumed");
    tests.push({ name: "alpha-reservation-crash-persistence", status: "pass" });

    restarted.runRegistry.register("run-expire", "other-tree");
    sleep(60);
    const swept = restarted.runRegistry.sweepExpired();
    if (!swept.includes("run-expire") || restarted.runRegistry.list().some((run) => run.run_id === "run-expire")) throw new Error("expired registry lease was not swept");
    tests.push({ name: "registry-lease-sweep", status: "pass" });

    const windowPath = restarted._path(FILES.window);
    const validWindowRaw = fs.readFileSync(windowPath, "utf8");
    const hostileWindow = JSON.parse(validWindowRaw);
    hostileWindow.unexpected_hostile_key = true;
    fs.writeFileSync(windowPath, JSON.stringify(hostileWindow));
    let windowRejected = false;
    try { restarted.window.get(); }
    catch (error) { windowRejected = error.code === "CORRUPT_STATE"; }
    fs.writeFileSync(windowPath, validWindowRaw);

    const registryPath = restarted._path(FILES.registry);
    const validRegistryRaw = fs.readFileSync(registryPath, "utf8");
    const registryLines = validRegistryRaw.trimEnd().split("\n");
    const hostileRegistry = JSON.parse(registryLines[0]);
    hostileRegistry.unexpected_hostile_key = true;
    registryLines[0] = JSON.stringify(hostileRegistry);
    fs.writeFileSync(registryPath, `${registryLines.join("\n")}\n`);
    let jsonlRejected = false;
    try { restarted.runRegistry.list(); }
    catch (error) { jsonlRejected = error.code === "CORRUPT_STATE"; }
    fs.writeFileSync(registryPath, validRegistryRaw);
    if (!windowRejected || !jsonlRejected) throw new Error("unknown state-record keys were not rejected on read");
    tests.push({ name: "schema-rejects-hostile-keys-on-read", status: "pass" });

    return { schema_version: SCHEMA_VERSION, status: "pass", tests };
  } finally {
    if (previousTestMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = previousTestMode;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  const command = process.argv[2];
  try {
    if (command === "status") writeReport(JSON.stringify(createStore(process.cwd()).status()) + "\n");
    else if (command === "sweep") writeReport(JSON.stringify({ schema_version: SCHEMA_VERSION, swept: createStore(process.cwd()).sweepExpired() }) + "\n");
    else if (command === "--selftest") writeReport(JSON.stringify(selftest()) + "\n");
    else {
      console.error("Usage: node scripts/state-store.js status|sweep|--selftest");
      process.exitCode = 2;
    }
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}
