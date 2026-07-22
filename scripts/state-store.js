#!/usr/bin/env node
/* GraphSmith's single writer for .graphsmith/state/. All mutations use an
 * owner-token lease and an fsync'd intent -> atomic replace -> done journal. */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SCHEMA_VERSION = "1.0";
const DEFAULT_LEASE_MS = 30000;
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

function parseJsonLines(raw, file) {
  if (!raw) return [];
  const lines = raw.split("\n");
  const records = [];
  for (let index = 0; index < lines.length; index++) {
    if (!lines[index]) continue;
    try {
      records.push(JSON.parse(lines[index]));
    } catch (error) {
      const isTornTail = index === lines.length - 1 && !raw.endsWith("\n");
      if (isTornTail) break;
      throw fail(`Corrupt JSONL record in ${file} at line ${index + 1}: ${error.message}`, "CORRUPT_STATE");
    }
  }
  return records;
}

function jsonLines(records) {
  return records.length === 0 ? "" : `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
}

function defaultWindow() {
  return { schema_version: SCHEMA_VERSION, state_rev: 0, state: "NO_WINDOW", flag: false, window: null };
}

function parseWindow(raw) {
  if (!raw) return defaultWindow();
  try {
    const value = JSON.parse(raw);
    if (value.schema_version !== SCHEMA_VERSION || !Number.isSafeInteger(value.state_rev)) throw new Error("invalid version or revision");
    return value;
  } catch (error) {
    throw fail(`Corrupt ${FILES.window}: ${error.message}`, "CORRUPT_STATE");
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

class StateStore {
  constructor(projectRoot = process.cwd(), options = {}) {
    this.projectRoot = path.resolve(projectRoot);
    this.stateDir = path.join(this.projectRoot, ".graphsmith", "state");
    this.lockPath = path.join(this.stateDir, "state.lock");
    this.journalPath = path.join(this.stateDir, "state-journal.jsonl");
    const testMode = process.env.GRAPHSMITH_TEST_MODE === "1";
    this.leaseMs = testMode
      ? positiveInteger(options.leaseMs || process.env.GRAPHSMITH_LEASE_MS, DEFAULT_LEASE_MS)
      : DEFAULT_LEASE_MS;
    this.heartbeatMs = testMode
      ? positiveInteger(options.heartbeatMs || process.env.GRAPHSMITH_HEARTBEAT_MS, DEFAULT_HEARTBEAT_MS)
      : DEFAULT_HEARTBEAT_MS;
    if (this.heartbeatMs >= this.leaseMs) this.heartbeatMs = Math.max(1, Math.floor(this.leaseMs / 3));
    this._crashAfterEffects = 0;

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
    const fd = fs.openSync(filePath, "a");
    try {
      fs.writeSync(fd, `${JSON.stringify(record)}\n`);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
  }

  _atomicReplace(file, content) {
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

  _readLock() {
    try {
      const record = JSON.parse(fs.readFileSync(this.lockPath, "utf8"));
      return { record, stat: fs.statSync(this.lockPath) };
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw fail(`Unreadable state lock: ${error.message}`, "CORRUPT_LOCK");
    }
  }

  _pidAlive(pid) {
    if (!Number.isSafeInteger(pid) || pid < 1) return false;
    try { process.kill(pid, 0); return true; } catch { return false; }
  }

  _unlinkLockIfOwner(ownerToken) {
    const fd = fs.openSync(this.lockPath, "r");
    try {
      const raw = fs.readFileSync(fd, "utf8");
      const current = JSON.parse(raw);
      if (current.owner_token !== ownerToken) return false;
      fs.unlinkSync(this.lockPath);
      return true;
    } finally { fs.closeSync(fd); }
  }

  _acquireLock() {
    this._ensureStateDir();
    for (let attempt = 0; attempt < 8; attempt++) {
      const ownerToken = crypto.randomBytes(16).toString("hex");
      const record = {
        schema_version: SCHEMA_VERSION,
        pid: process.pid,
        proc_start_hint: `${process.pid}:${Math.floor(Date.now() - process.uptime() * 1000)}`,
        owner_token: ownerToken,
      };
      try {
        const fd = fs.openSync(this.lockPath, "wx");
        try { fs.writeSync(fd, JSON.stringify(record)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
        const heartbeat = setInterval(() => {
          try { this._renewLock(ownerToken); } catch {}
        }, this.heartbeatMs);
        heartbeat.unref();
        return { ownerToken, heartbeat };
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        const observed = this._readLock();
        if (!observed) continue;
        const age = Date.now() - observed.stat.mtimeMs;
        const expired = age > this.leaseMs || !this._pidAlive(observed.record.pid);
        if (!expired) throw fail(`State store is actively locked by pid ${observed.record.pid}`, "LOCKED");
        requiredString(observed.record.owner_token, "state.lock owner_token");
        try {
          if (!this._unlinkLockIfOwner(observed.record.owner_token)) continue;
        } catch (stealError) {
          if (stealError.code === "ENOENT") continue;
          throw stealError;
        }
      }
    }
    throw fail("Could not acquire state-store lock after bounded contention", "LOCK_CONTENTION");
  }

  _renewLock(ownerToken) {
    const fd = fs.openSync(this.lockPath, "r+");
    try {
      const current = JSON.parse(fs.readFileSync(fd, "utf8"));
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
    this._appendDurable(this.journalPath, {
      schema_version: SCHEMA_VERSION,
      record_type: "MUTATION_INTENT",
      mutation_id: mutationId,
      state_rev: stateRev,
      effects: effects.map(({ after, ...effect }) => effect),
    });
    let applied = 0;
    for (const effect of effects) {
      if (effect.before_sha256 !== effect.after_sha256) this._atomicReplace(effect.file, effect.after);
      applied++;
      if (this._crashAfterEffects && applied >= this._crashAfterEffects) {
        this._crashAfterEffects = 0;
        throw fail("Simulated crash after journaled effect", "SIMULATED_CRASH");
      }
    }
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
      else if (record.record_type === "HEARTBEAT" && active.has(record.run_id)) active.get(record.run_id).lease_expires_at = record.lease_expires_at;
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
    const now = Date.now();
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
              created_at: Date.now(),
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
      const leaseExpiresAt = Date.now() + this.leaseMs;
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
            lease_expires_at: Date.now() + this.leaseMs,
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
    if (command === "status") console.log(JSON.stringify(createStore(process.cwd()).status()));
    else if (command === "sweep") console.log(JSON.stringify({ schema_version: SCHEMA_VERSION, swept: createStore(process.cwd()).sweepExpired() }));
    else if (command === "--selftest") console.log(JSON.stringify(selftest()));
    else {
      console.error("Usage: node scripts/state-store.js status|sweep|--selftest");
      process.exitCode = 2;
    }
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}
