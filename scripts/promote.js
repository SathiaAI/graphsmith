#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { generate, verifyTree } = require("./manifest.js");
const { validateActivePointer } = require("./loaders.js");
const { createStore } = require("./state-store.js");

const SCHEMA_VERSION = "1.0";
const TERMINAL = new Set(["TX_DONE", "TX_ABORT"]);
const HASH_RE = /^[0-9a-f]{64}$/;
const KIND = new Set(["doc", "knob", "code", "migration"]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function failure(message, code = "PROMOTION_ERROR", evidence) {
  const error = new Error(message);
  error.code = code;
  if (evidence !== undefined) error.evidence = evidence;
  return error;
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw failure(`${name} must be a non-empty string`, "INVALID_PACKET");
  return value;
}

function locations(root) {
  const state = path.join(root, ".graphsmith", "state");
  const evolvable = path.join(root, ".graphsmith", "evolvable");
  return {
    root, state, evolvable,
    active: path.join(evolvable, "ACTIVE"),
    journal: path.join(state, "journal.jsonl"),
    adoption: path.join(state, "adoption-log.jsonl"),
    projectManifest: path.join(state, "project.manifest.json"),
  };
}

function readFile(file, encoding = null) {
  try { return fs.readFileSync(file, encoding || undefined); }
  catch (error) { if (error.code === "ENOENT") return encoding ? "" : Buffer.alloc(0); throw error; }
}

function parseJson(raw, label) {
  try { return JSON.parse(raw); }
  catch (error) { throw failure(`Invalid JSON in ${label}: ${error.message}`, "CORRUPT_STATE"); }
}

function parseJsonl(file) {
  const raw = readFile(file, "utf8");
  if (!raw) return [];
  const lines = raw.split("\n");
  const records = [];
  for (let index = 0; index < lines.length; index++) {
    if (!lines[index]) continue;
    try { records.push(JSON.parse(lines[index])); }
    catch (error) {
      if (index === lines.length - 1 && !raw.endsWith("\n")) break;
      throw failure(`Corrupt JSONL at ${file}:${index + 1}: ${error.message}`, "CORRUPT_STATE");
    }
  }
  return records;
}

function fsyncDirectory(directory) {
  try {
    const fd = fs.openSync(directory, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (error) {
    if (process.platform !== "win32" && !["EINVAL", "EISDIR", "EPERM"].includes(error.code)) throw error;
  }
}

function appendDurable(file, record) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let separator = "";
  try {
    const stat = fs.statSync(file);
    if (stat.size > 0) {
      const readFd = fs.openSync(file, "r");
      const last = Buffer.alloc(1);
      try { fs.readSync(readFd, last, 0, 1, stat.size - 1); }
      finally { fs.closeSync(readFd); }
      if (last[0] !== 0x0a) separator = "\n";
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const fd = fs.openSync(file, "a");
  try { fs.writeSync(fd, `${separator}${JSON.stringify(record)}\n`); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

function atomicReplace(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  const fd = fs.openSync(temporary, "w");
  try { fs.writeSync(fd, content); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  let lastError;
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      fs.renameSync(temporary, file);
      fsyncDirectory(path.dirname(file));
      return;
    } catch (error) {
      lastError = error;
      if (!["EPERM", "EBUSY", "EACCES"].includes(error.code)) break;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5 * (attempt + 1));
    }
  }
  try { fs.unlinkSync(temporary); } catch {}
  throw lastError;
}

function journalRecord(paths, txid, recordType, fields = {}) {
  appendDurable(paths.journal, { schema_version: SCHEMA_VERSION, record_type: recordType, txid, ...fields });
}

function recordsFor(paths, txid) {
  return parseJsonl(paths.journal).filter((record) => record.txid === txid);
}

function lastRecord(records, type) {
  for (let index = records.length - 1; index >= 0; index--) if (records[index].record_type === type) return records[index];
  return null;
}

function activeIdentity(paths) {
  const raw = readFile(paths.active);
  if (!raw.length) throw failure(`Missing ACTIVE pointer at ${paths.active}`, "CORRUPT_STATE");
  const pointer = parseJson(raw.toString("utf8"), paths.active);
  const schemaError = validateActivePointer(pointer);
  if (schemaError || pointer.schema_version !== SCHEMA_VERSION) throw failure(`Invalid ACTIVE pointer: ${schemaError || "unsupported schema_version"}`, "CORRUPT_STATE");
  return { raw, sha: sha256(raw), pointer };
}

function adoptionEntries(paths) {
  const entries = parseJsonl(paths.adoption);
  let previous = null;
  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    const claimed = entry.entry_sha256;
    const body = { ...entry };
    delete body.entry_sha256;
    if (entry.schema_version !== SCHEMA_VERSION || entry.seq !== index + 1 || entry.prev_sha256 !== previous || sha256(JSON.stringify(body)) !== claimed) {
      throw failure(`Adoption-log chain verification failed at sequence ${index + 1}`, "HALT", { entry });
    }
    previous = claimed;
  }
  return entries;
}

function logHead(paths) {
  const entries = adoptionEntries(paths);
  return entries.length ? entries[entries.length - 1].entry_sha256 : null;
}

function readProjectManifest(paths) {
  const raw = readFile(paths.projectManifest, "utf8");
  if (!raw) throw failure(`Missing project manifest at ${paths.projectManifest}`, "CORRUPT_STATE");
  const manifest = parseJson(raw, paths.projectManifest);
  if (manifest.kind !== "project" || manifest.schema_version !== SCHEMA_VERSION) throw failure("Invalid project manifest identity", "CORRUPT_STATE");
  return manifest;
}

function pointerBytes(pointer) {
  return Buffer.from(`${JSON.stringify(pointer, null, 2)}\n`, "utf8");
}

function normalizePacket(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw failure("packet must be an object", "INVALID_PACKET");
  const packet = JSON.parse(JSON.stringify(input));
  delete packet.project_root;
  delete packet.__test_crash_at;
  delete packet.__test_abort_after_log;
  if (packet.fingerprint === undefined) packet.fingerprint = packet.candidate_fingerprint;
  if (packet.evidence_ref === undefined) packet.evidence_ref = packet.evidence;
  if (packet.edits === undefined && Array.isArray(packet.diff)) packet.edits = packet.diff;
  if (packet.auto_rollback_eligible === undefined) packet.auto_rollback_eligible = packet.autoRollbackEligible;
  delete packet.candidate_fingerprint;
  delete packet.evidence;
  delete packet.diff;
  delete packet.autoRollbackEligible;
  requiredString(packet.fingerprint, "packet.fingerprint");
  if (!HASH_RE.test(packet.fingerprint)) throw failure("packet.fingerprint must be 64 lowercase hex characters", "INVALID_PACKET");
  if (!KIND.has(packet.kind)) throw failure("packet.kind must be doc, knob, code, or migration", "INVALID_PACKET");
  requiredString(packet.evidence_ref, "packet.evidence_ref");
  if (!packet.human || typeof packet.human !== "object") throw failure("packet.human is required", "INVALID_PACKET");
  requiredString(packet.human.name, "packet.human.name");
  requiredString(packet.human.decision, "packet.human.decision");
  requiredString(packet.human.ts, "packet.human.ts");
  if (!Array.isArray(packet.edits) && typeof packet.source_tree !== "string") {
    throw failure("packet must provide edits[] or source_tree", "INVALID_PACKET");
  }
  return packet;
}

function canonicalRelative(value) {
  requiredString(value, "edit.file");
  const normalized = value.replace(/\\/g, "/").normalize("NFC");
  if (path.posix.isAbsolute(normalized) || normalized.split("/").some((part) => !part || part === "." || part === "..")) {
    throw failure(`Unsafe edit path: ${value}`, "INVALID_PACKET");
  }
  return normalized;
}

function applyEdits(treeDir, edits) {
  for (const edit of edits) {
    if (!edit || typeof edit !== "object") throw failure("Each edit must be an object", "INVALID_PACKET");
    if (edit.schema_version !== SCHEMA_VERSION) throw failure("Each TypedEdit must carry schema_version 1.0", "INVALID_PACKET");
    requiredString(edit.schema_ref, "edit.schema_ref");
    const relative = canonicalRelative(edit.file);
    const file = path.join(treeDir, ...relative.split("/"));
    const relCheck = path.relative(treeDir, file);
    if (path.isAbsolute(relCheck) || relCheck.startsWith(`..${path.sep}`)) throw failure(`Edit escapes staged tree: ${relative}`, "INVALID_PACKET");
    const operation = edit.op;
    if (!["replace", "insert", "delete", "set-knob"].includes(operation)) throw failure(`Unsupported edit op: ${operation}`, "INVALID_PACKET");
    if (operation === "set-knob") {
      const object = parseJson(readFile(file, "utf8"), relative);
      const keys = requiredString(edit.anchor, "edit.anchor").split(".");
      let cursor = object;
      for (let index = 0; index < keys.length - 1; index++) {
        if (!cursor[keys[index]] || typeof cursor[keys[index]] !== "object") throw failure(`Knob anchor not found: ${edit.anchor}`, "VALIDATION_FAILED");
        cursor = cursor[keys[index]];
      }
      if (!Object.prototype.hasOwnProperty.call(cursor, keys[keys.length - 1])) throw failure(`Knob anchor not found: ${edit.anchor}`, "VALIDATION_FAILED");
      cursor[keys[keys.length - 1]] = edit.payload;
      fs.writeFileSync(file, `${JSON.stringify(object, null, 2)}\n`);
      continue;
    }
    const before = readFile(file, "utf8");
    if (!before && !fs.existsSync(file)) throw failure(`Edit target does not exist: ${relative}`, "VALIDATION_FAILED");
    const anchor = requiredString(edit.anchor, "edit.anchor");
    const first = before.indexOf(anchor);
    if (first < 0 || before.indexOf(anchor, first + anchor.length) >= 0) throw failure(`Edit anchor must occur exactly once in ${relative}`, "VALIDATION_FAILED");
    const payload = edit.payload === undefined ? "" : String(edit.payload);
    let after;
    if (operation === "replace") after = before.slice(0, first) + payload + before.slice(first + anchor.length);
    else if (operation === "insert") after = before.slice(0, first + anchor.length) + payload + before.slice(first + anchor.length);
    else after = before.slice(0, first) + before.slice(first + anchor.length);
    fs.writeFileSync(file, after);
  }
}

function rejectLinks(directory, base = directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) throw failure(`Symlink/junction refused: ${path.relative(base, full)}`, "VALIDATION_FAILED");
    if (stat.isDirectory()) rejectLinks(full, base);
  }
}

function treeBytes(directory) {
  let total = 0;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) total += treeBytes(full);
    else if (entry.isFile()) total += fs.statSync(full).size;
  }
  return total;
}

function diskPreflight(paths, source) {
  const sourceStat = fs.statSync(source);
  const evolvableStat = fs.statSync(paths.evolvable);
  if (sourceStat.dev !== evolvableStat.dev) throw failure("Cannot prove staging and ACTIVE are on the same filesystem volume", "PLATFORM_REFUSED");
  if (typeof fs.statfsSync !== "function") throw failure("This Node/filesystem cannot prove free-space reserve", "PLATFORM_REFUSED");
  const free = fs.statfsSync(paths.evolvable);
  const required = treeBytes(source) * 2 + 1024 * 1024;
  if (Number(free.bavail) * Number(free.bsize) < required) throw failure(`Insufficient free-space reserve: need at least ${required} bytes`, "DISK_RESERVE");
}

function stageTree(paths, packet, txid, currentPointer) {
  if (packet.source_tree) {
    const tree = canonicalRelative(packet.source_tree);
    if (!/^v-[0-9a-f]{8,64}$/.test(tree)) throw failure("packet.source_tree is not a versioned tree id", "INVALID_PACKET");
    const treeDir = path.join(paths.evolvable, tree);
    const manifestPath = path.join(treeDir, "tree.manifest.json");
    const verification = verifyTree(manifestPath, treeDir);
    if (!verification.ok) throw failure("source_tree failed closed-inventory verification", "VALIDATION_FAILED", verification);
    const manifestSha = sha256(readFile(manifestPath));
    return { tree, treeDir, manifestSha };
  }

  const source = path.join(paths.evolvable, currentPointer.tree);
  rejectLinks(source);
  diskPreflight(paths, source);
  const temporary = path.join(paths.evolvable, `.staging-${txid}`);
  fs.rmSync(temporary, { recursive: true, force: true });
  fs.cpSync(source, temporary, { recursive: true, errorOnExist: true, force: false });
  fs.rmSync(path.join(temporary, "tree.manifest.json"), { force: true });
  applyEdits(temporary, packet.edits);
  rejectLinks(temporary);
  const manifest = generate("tree", { rootDir: temporary });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  fs.writeFileSync(path.join(temporary, "tree.manifest.json"), manifestBytes);
  const manifestSha = sha256(manifestBytes);
  const tree = `v-${manifestSha}`;
  const treeDir = path.join(paths.evolvable, tree);
  if (fs.existsSync(treeDir)) {
    const verification = verifyTree(path.join(treeDir, "tree.manifest.json"), treeDir);
    if (!verification.ok || sha256(readFile(path.join(treeDir, "tree.manifest.json"))) !== manifestSha) {
      throw failure(`Existing immutable tree identity collision at ${tree}`, "HALT");
    }
    fs.rmSync(temporary, { recursive: true, force: true });
  } else {
    fs.renameSync(temporary, treeDir);
    fsyncDirectory(paths.evolvable);
  }
  return { tree, treeDir, manifestSha };
}

function buildEntry(paths, packet, txid, status, previous) {
  const entry = {
    schema_version: SCHEMA_VERSION,
    seq: adoptionEntries(paths).length + 1,
    txid,
    status,
    fingerprint: packet.fingerprint,
    kind: packet.kind,
    evidence_ref: packet.evidence_ref,
    human: packet.human,
    prev_sha256: previous,
  };
  entry.entry_sha256 = sha256(JSON.stringify(entry));
  return entry;
}

function appendEntry(paths, entry) {
  const current = adoptionEntries(paths);
  if (current.some((item) => item.entry_sha256 === entry.entry_sha256)) return;
  const head = current.length ? current[current.length - 1].entry_sha256 : null;
  if (entry.seq !== current.length + 1 || entry.prev_sha256 !== head) throw failure("Adoption-log append expectation mismatch", "HALT", { expected_head: head, entry });
  appendDurable(paths.adoption, entry);
  if (logHead(paths) !== entry.entry_sha256) throw failure("Post-append adoption-log verification failed", "HALT");
}

function expectedState(paths, activeSha, head, phase) {
  const observedActive = activeIdentity(paths).sha;
  const observedHead = logHead(paths);
  if (observedActive !== activeSha || observedHead !== head) {
    throw failure(`HALT: unexpected mutation after TX_BEGIN at ${phase}`, "HALT", {
      expected_active_sha: activeSha, observed_active_sha: observedActive,
      expected_log_head: head, observed_log_head: observedHead,
    });
  }
}

function acquire(root) {
  const store = createStore(root);
  const lock = store._testing.acquireLock();
  let sweptLeaseIds;
  try {
    store._recoverJournal();
    sweptLeaseIds = store._sweepExpiredLocked();
  } catch (error) {
    clearInterval(lock.heartbeat);
    try { store._testing.releaseLock(lock.ownerToken); } catch {}
    throw error;
  }
  return { store, lock, sweptLeaseIds };
}

function release(store, lock) {
  clearInterval(lock.heartbeat);
  store._testing.releaseLock(lock.ownerToken);
}

function readWindow(store) {
  const raw = store._read("window.json");
  return raw ? parseJson(raw, "window.json") : { schema_version: SCHEMA_VERSION, state_rev: 0, state: "NO_WINDOW", flag: false, window: null };
}

function admitWindow(store, packet, txid, tree) {
  let result;
  store._commit([{
    file: "window.json",
    make: (raw, rev) => {
      const current = raw ? parseJson(raw, "window.json") : { schema_version: SCHEMA_VERSION, state_rev: 0, state: "NO_WINDOW", flag: false, window: null };
      if (packet.rollback_of) {
        if (!current.window || current.window.adoption_txid !== packet.rollback_of || !["OBSERVING", "ROLLING_BACK", "ADMITTED"].includes(current.state)) {
          throw failure("Rollback requires the matching live Gate-4 window", "WINDOW_MISMATCH");
        }
        current.state = "ROLLING_BACK";
        current.state_rev = rev;
        result = current;
        return JSON.stringify(current);
      }
      if (!["NO_WINDOW", "CLOSED_PASS", "CLOSED_ROLLED_BACK", "CLOSED_FLAGGED"].includes(current.state)) {
        throw failure(`Cannot promote while Gate-4 window is ${current.state}`, "WINDOW_EXISTS");
      }
      result = {
        schema_version: SCHEMA_VERSION, state_rev: rev, state: "ADMITTED", flag: false,
        window: {
          window_id: txid, adoption_txid: txid, candidate_fingerprint: packet.fingerprint, tree_id: tree,
          n: Number.isSafeInteger(packet.window_n) && packet.window_n > 0 ? packet.window_n : 5,
          baseline_metric: packet.baseline_metric === undefined ? null : packet.baseline_metric,
          created_at: Date.now(),
          max_window_wall_time_ms: Number.isSafeInteger(packet.max_window_wall_time_ms) && packet.max_window_wall_time_ms > 0 ? packet.max_window_wall_time_ms : 7 * 24 * 60 * 60 * 1000,
          admitted: 0, active: 0, slots: [],
        },
      };
      return JSON.stringify(result);
    },
  }]);
  return result;
}

function finalizeWindow(store, packet, txid) {
  let result;
  store._commit([{
    file: "window.json",
    make: (raw, rev) => {
      const current = parseJson(raw, "window.json");
      if (!current.window) throw failure("Pending window disappeared", "HALT");
      if (packet.rollback_of) {
        if (current.window.adoption_txid !== packet.rollback_of) throw failure("Rollback window identity changed", "HALT");
        for (const slot of current.window.slots) {
          if (slot.status === "active") { slot.status = "terminal"; slot.disposition = "superseded"; }
        }
        current.window.active = 0;
        current.state = "CLOSED_ROLLED_BACK";
      } else {
        if (current.window.window_id !== txid) throw failure("Pending window identity changed", "HALT");
        current.state = "OBSERVING";
      }
      current.state_rev = rev;
      result = current;
      return JSON.stringify(current);
    },
  }]);
  return result;
}

function updateProjectManifest(paths, pointer, head) {
  const manifest = readProjectManifest(paths);
  manifest.adoption_log_head = head;
  manifest.active_tree = pointer.tree;
  manifest.active_tree_manifest_sha256 = pointer.tree_manifest_sha256;
  return manifest;
}

function manifestMatches(manifest, pointer, head) {
  return manifest.adoption_log_head === head &&
    manifest.active_tree === pointer.tree &&
    manifest.active_tree_manifest_sha256 === pointer.tree_manifest_sha256;
}

function completedTreeHistory(paths) {
  const records = parseJsonl(paths.journal);
  const completed = new Set(records.filter((record) => record.record_type === "TX_DONE").map((record) => record.txid));
  const history = [];
  for (const record of records) {
    if (record.record_type !== "STAGE_DONE" || !completed.has(record.txid)) continue;
    if (history.length === 0) history.push(record.from_pointer.tree);
    if (history[history.length - 1] !== record.tree) history.push(record.tree);
  }
  return history;
}

function rollbackEligiblePrevious(paths, activePointer) {
  const records = recordsFor(paths, activePointer.txid);
  const begin = lastRecord(records, "TX_BEGIN");
  const staged = lastRecord(records, "STAGE_DONE");
  if (!begin || !staged || !lastRecord(records, "TX_DONE")) return null;
  const packet = begin.packet;
  return ["doc", "knob"].includes(packet.kind) && packet.reversible === true && packet.auto_rollback_eligible === true
    ? staged.from_pointer.tree : null;
}

function garbageCollect(paths, store, sweptLeaseIds) {
  const active = activeIdentity(paths).pointer;
  const history = completedTreeHistory(paths);
  const older = new Set(history.slice(0, Math.max(0, history.length - 2)));
  const protectedTrees = new Set([active.tree, rollbackEligiblePrevious(paths, active)].filter(Boolean));
  const registryRecords = store._registryState(store._read("run-registry.jsonl").split("\n").filter(Boolean).map((line) => parseJson(line, "run-registry.jsonl")));
  for (const registration of registryRecords.values()) protectedTrees.add(registration.tree_id);
  const deletedTreeIds = [];
  for (const entry of fs.readdirSync(paths.evolvable, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^v-[0-9a-f]{8,64}$/.test(entry.name) || !older.has(entry.name) || protectedTrees.has(entry.name)) continue;
    fs.rmSync(path.join(paths.evolvable, entry.name), { recursive: true, force: true });
    deletedTreeIds.push(entry.name);
  }
  if (deletedTreeIds.length) fsyncDirectory(paths.evolvable);
  if (sweptLeaseIds.length || deletedTreeIds.length) {
    const evidence = JSON.stringify({ swept_lease_ids: sweptLeaseIds, deleted_tree_ids: deletedTreeIds });
    journalRecord(paths, active.txid, "RECOVERY_STEP", { action: `GC_SWEEP ${evidence}` });
  }
  return { sweptLeaseIds, deletedTreeIds };
}

function maybeCrash(input, point) {
  if (process.env.GRAPHSMITH_TEST_MODE === "1" && input && input.__test_crash_at === point) {
    throw failure(`Simulated crash at ${point}`, "SIMULATED_CRASH");
  }
}

function abortVisible(paths, packet, txid, committing, reason) {
  const terminal = buildEntry(paths, packet, txid, "aborted", committing.entry_sha256);
  journalRecord(paths, txid, "OUTCOME_APPEND_INTENT", { terminal_entry_sha: terminal.entry_sha256, entry: terminal });
  appendEntry(paths, terminal);
  journalRecord(paths, txid, "OUTCOME_APPEND_DONE", { terminal_entry_sha: terminal.entry_sha256, status: "aborted" });
  const active = activeIdentity(paths).pointer;
  const manifest = updateProjectManifest(paths, active, terminal.entry_sha256);
  journalRecord(paths, txid, "MANIFEST_INTENT", { new_head_sha: terminal.entry_sha256, manifest });
  atomicReplace(paths.projectManifest, `${JSON.stringify(manifest, null, 2)}\n`);
  journalRecord(paths, txid, "MANIFEST_DONE", { new_head_sha: terminal.entry_sha256 });
  journalRecord(paths, txid, "TX_ABORT", { reason, compensating_entry_sha: terminal.entry_sha256 });
  return { txid, state: "ABORTED" };
}

function promote(input) {
  const root = path.resolve(input && input.project_root ? input.project_root : process.cwd());
  const paths = locations(root);
  const packet = normalizePacket(input);
  fs.mkdirSync(paths.state, { recursive: true });
  fs.mkdirSync(paths.evolvable, { recursive: true });

  const { store, lock, sweptLeaseIds } = acquire(root);
  let txid;
  let phase = "LEASED";
  let committing = null;
  try {
    const unfinished = unfinishedTransactions(paths);
    if (unfinished.length) throw failure(`Unfinished transaction ${unfinished[0]} requires recover() before a new promotion`, "RECOVERY_REQUIRED");
    const active = activeIdentity(paths);
    const head = logHead(paths);
    const projectManifest = readProjectManifest(paths);
    if (projectManifest.adoption_log_head !== head) throw failure("Project manifest does not anchor the adoption-log tail", "CORRUPT_STATE");
    if (input.expected_active_sha && input.expected_active_sha !== active.sha) throw failure("Stale proposal: expected ACTIVE hash mismatch", "STALE_PROPOSAL");
    if (Object.prototype.hasOwnProperty.call(input, "expected_log_head") && input.expected_log_head !== head) throw failure("Stale proposal: expected adoption-log head mismatch", "STALE_PROPOSAL");
    const window = readWindow(store);
    if (!packet.rollback_of && !["NO_WINDOW", "CLOSED_PASS", "CLOSED_ROLLED_BACK", "CLOSED_FLAGGED"].includes(window.state)) {
      throw failure(`Cannot promote while Gate-4 window is ${window.state}`, "WINDOW_EXISTS");
    }
    garbageCollect(paths, store, sweptLeaseIds);
    txid = sha256(packet.fingerprint + active.sha).slice(0, 16);
    journalRecord(paths, txid, "TX_BEGIN", { expected_active_sha: active.sha, expected_log_head: head, packet });
    phase = "BEGUN";

    const staged = stageTree(paths, packet, txid, active.pointer);
    const toPointer = { schema_version: SCHEMA_VERSION, txid, tree: staged.tree, tree_manifest_sha256: staged.manifestSha };
    journalRecord(paths, txid, "STAGE_DONE", {
      tree: staged.tree, tree_manifest_sha: staged.manifestSha, from_pointer: active.pointer, to_pointer: toPointer,
    });
    phase = "STAGED";
    const verification = verifyTree(path.join(staged.treeDir, "tree.manifest.json"), staged.treeDir);
    if (!verification.ok) throw failure("Staged tree verification failed", "VALIDATION_FAILED", verification);
    expectedState(paths, active.sha, head, "validate");
    journalRecord(paths, txid, "VALIDATED");
    phase = "VALIDATED";

    committing = buildEntry(paths, packet, txid, "committing", head);
    journalRecord(paths, txid, "LOG_APPEND_INTENT", { entry_sha: committing.entry_sha256, entry: committing });
    expectedState(paths, active.sha, head, "log-append");
    appendEntry(paths, committing);
    journalRecord(paths, txid, "LOG_APPEND_DONE", { entry_sha: committing.entry_sha256, status: "committing" });
    phase = "LOGGED";
    if (process.env.GRAPHSMITH_TEST_MODE === "1" && input.__test_abort_after_log) {
      return abortVisible(paths, packet, txid, committing, "selftest requested post-log abort");
    }

    const pending = admitWindow(store, packet, txid, staged.tree);
    const windowId = pending.window.window_id;
    journalRecord(paths, txid, "WINDOW_PENDING", { window_id: windowId });
    phase = "WINDOW_PENDING";
    maybeCrash(input, "before-swap");
    expectedState(paths, active.sha, committing.entry_sha256, "swap");
    journalRecord(paths, txid, "SWAP_INTENT", { from_tree: active.pointer.tree, to_tree: staged.tree, to_pointer: toPointer });
    const toBytes = pointerBytes(toPointer);
    atomicReplace(paths.active, toBytes);
    const observedActiveSha = sha256(toBytes);
    if (activeIdentity(paths).sha !== observedActiveSha) throw failure("Post-swap ACTIVE verification failed", "HALT");
    journalRecord(paths, txid, "SWAP_DONE", { observed_active_sha: observedActiveSha });
    phase = "SWAPPED";
    maybeCrash(input, "after-swap");

    const effective = buildEntry(paths, packet, txid, "effective", committing.entry_sha256);
    journalRecord(paths, txid, "OUTCOME_APPEND_INTENT", { terminal_entry_sha: effective.entry_sha256, entry: effective });
    expectedState(paths, observedActiveSha, committing.entry_sha256, "outcome-append");
    appendEntry(paths, effective);
    journalRecord(paths, txid, "OUTCOME_APPEND_DONE", { terminal_entry_sha: effective.entry_sha256, status: "effective" });
    phase = "OUTCOME";
    const manifest = updateProjectManifest(paths, toPointer, effective.entry_sha256);
    journalRecord(paths, txid, "MANIFEST_INTENT", { new_head_sha: effective.entry_sha256, manifest });
    atomicReplace(paths.projectManifest, `${JSON.stringify(manifest, null, 2)}\n`);
    if (!manifestMatches(readProjectManifest(paths), toPointer, effective.entry_sha256)) throw failure("Post-manifest verification failed", "HALT");
    journalRecord(paths, txid, "MANIFEST_DONE", { new_head_sha: effective.entry_sha256 });
    phase = "MANIFEST";
    maybeCrash(input, "after-manifest");
    const finalWindow = finalizeWindow(store, packet, txid);
    journalRecord(paths, txid, "WINDOW_FINAL", { window_id: windowId, state: finalWindow.state });
    journalRecord(paths, txid, "TX_DONE", { state: "DONE" });
    return { txid, state: "DONE" };
  } catch (error) {
    if (txid && error.code !== "SIMULATED_CRASH" && error.code !== "HALT" && ["BEGUN", "STAGED", "VALIDATED"].includes(phase)) {
      const staged = lastRecord(recordsFor(paths, txid), "STAGE_DONE");
      if (staged && activeIdentity(paths).pointer.tree !== staged.tree) fs.rmSync(path.join(paths.evolvable, staged.tree), { recursive: true, force: true });
      journalRecord(paths, txid, "TX_ABORT", { reason: error.message });
    } else if (txid && error.code !== "SIMULATED_CRASH" && error.code !== "HALT" && phase === "LOGGED" && committing) {
      return abortVisible(paths, packet, txid, committing, error.message);
    }
    throw error;
  } finally {
    release(store, lock);
  }
}

function unfinishedTransactions(paths) {
  const groups = new Map();
  for (const record of parseJsonl(paths.journal)) {
    if (!groups.has(record.txid)) groups.set(record.txid, []);
    groups.get(record.txid).push(record);
  }
  return [...groups].filter(([, records]) => records.some((record) => record.record_type === "TX_BEGIN") && !records.some((record) => TERMINAL.has(record.record_type))).map(([txid]) => txid);
}

function recoveryHalt(paths, txid, message, evidence) {
  journalRecord(paths, txid, "RECOVERY_DONE", { outcome: "halt" });
  throw failure(`HALT: ${message}`, "HALT", evidence);
}

function repairTornJournal(paths) {
  const raw = readFile(paths.journal, "utf8");
  if (!raw || raw.endsWith("\n")) return null;
  const lineStart = raw.lastIndexOf("\n") + 1;
  const finalLine = raw.slice(lineStart);
  try { JSON.parse(finalLine); return null; }
  catch {}
  atomicReplace(paths.journal, raw.slice(0, lineStart));
  return { truncated_bytes: Buffer.byteLength(finalLine), truncated_prefix: finalLine };
}

function cleanupAbandonedStaging(paths) {
  const fallbackTxid = activeIdentity(paths).pointer.txid;
  for (const entry of fs.readdirSync(paths.evolvable, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith(".staging-")) continue;
    fs.rmSync(path.join(paths.evolvable, entry.name), { recursive: true, force: true });
    const candidate = entry.name.slice(".staging-".length);
    const txid = /^[0-9a-f]{16}$/.test(candidate) ? candidate : fallbackTxid;
    journalRecord(paths, txid, "RECOVERY_STEP", { action: `remove-abandoned-staging:${entry.name}` });
  }
  fsyncDirectory(paths.evolvable);
}

function recover(projectRoot = process.cwd()) {
  const root = path.resolve(projectRoot);
  const paths = locations(root);
  const { store, lock } = acquire(root);
  const outcomes = [];
  try {
    const tornTail = repairTornJournal(paths);
    for (const txid of unfinishedTransactions(paths)) {
      let records = recordsFor(paths, txid);
      const begin = lastRecord(records, "TX_BEGIN");
      const staged = lastRecord(records, "STAGE_DONE");
      const logIntent = lastRecord(records, "LOG_APPEND_INTENT");
      const outcomeIntent = lastRecord(records, "OUTCOME_APPEND_INTENT");
      const observed = {
        active_sha: activeIdentity(paths).sha,
        log_head: logHead(paths),
        manifest_head: readProjectManifest(paths).adoption_log_head,
      };
      if (tornTail) observed.truncated_journal_tail = tornTail;
      journalRecord(paths, txid, "RECOVERY_BEGIN", { observed_state: observed });
      if (!staged || !logIntent) {
        if (staged && activeIdentity(paths).pointer.tree !== staged.tree) fs.rmSync(path.join(paths.evolvable, staged.tree), { recursive: true, force: true });
        journalRecord(paths, txid, "RECOVERY_STEP", { action: "rollback-before-visible-log" });
        journalRecord(paths, txid, "TX_ABORT", { reason: "recovery rolled back transaction before LOG_APPEND_INTENT" });
        journalRecord(paths, txid, "RECOVERY_DONE", { outcome: "aborted" });
        outcomes.push({ txid, state: "ABORTED" });
        continue;
      }

      const oldActiveSha = begin.expected_active_sha;
      const toActiveSha = sha256(pointerBytes(staged.to_pointer));
      const activeSha = activeIdentity(paths).sha;
      if (![oldActiveSha, toActiveSha].includes(activeSha)) recoveryHalt(paths, txid, "ACTIVE has an unclassifiable identity", { oldActiveSha, toActiveSha, activeSha });
      let head = logHead(paths);
      const allowedHeads = [begin.expected_log_head, logIntent.entry_sha];
      if (outcomeIntent) allowedHeads.push(outcomeIntent.terminal_entry_sha);
      if (!allowedHeads.includes(head)) recoveryHalt(paths, txid, "adoption log has an unclassifiable head", { allowedHeads, head });
      const manifestHead = readProjectManifest(paths).adoption_log_head;
      if (![begin.expected_log_head, outcomeIntent && outcomeIntent.terminal_entry_sha].includes(manifestHead)) {
        recoveryHalt(paths, txid, "project manifest has an unclassifiable head", { manifestHead });
      }
      const treeDir = path.join(paths.evolvable, staged.tree);
      const verified = verifyTree(path.join(treeDir, "tree.manifest.json"), treeDir);
      if (!verified.ok || sha256(readFile(path.join(treeDir, "tree.manifest.json"))) !== staged.tree_manifest_sha) {
        recoveryHalt(paths, txid, "staged immutable tree failed verification", verified);
      }
      if (head === begin.expected_log_head) {
        appendEntry(paths, logIntent.entry);
        journalRecord(paths, txid, "RECOVERY_STEP", { action: "append-committing-entry" });
        if (!lastRecord(records, "LOG_APPEND_DONE")) journalRecord(paths, txid, "LOG_APPEND_DONE", { entry_sha: logIntent.entry_sha, status: "committing" });
        head = logIntent.entry_sha;
      }

      if (outcomeIntent && outcomeIntent.entry.status === "aborted") {
        if (head === logIntent.entry_sha) appendEntry(paths, outcomeIntent.entry);
        const activePointer = activeIdentity(paths).pointer;
        const manifest = updateProjectManifest(paths, activePointer, outcomeIntent.terminal_entry_sha);
        if (!lastRecord(records, "MANIFEST_INTENT")) journalRecord(paths, txid, "MANIFEST_INTENT", { new_head_sha: outcomeIntent.terminal_entry_sha, manifest });
        if (!manifestMatches(readProjectManifest(paths), activePointer, outcomeIntent.terminal_entry_sha)) atomicReplace(paths.projectManifest, `${JSON.stringify(manifest, null, 2)}\n`);
        journalRecord(paths, txid, "MANIFEST_DONE", { new_head_sha: outcomeIntent.terminal_entry_sha });
        journalRecord(paths, txid, "TX_ABORT", { reason: "recovered compensating abort", compensating_entry_sha: outcomeIntent.terminal_entry_sha });
        journalRecord(paths, txid, "RECOVERY_DONE", { outcome: "aborted" });
        outcomes.push({ txid, state: "ABORTED" });
        continue;
      }

      let pending = lastRecord(records, "WINDOW_PENDING");
      if (!pending) {
        const value = admitWindow(store, begin.packet, txid, staged.tree);
        pending = { window_id: value.window.window_id };
        journalRecord(paths, txid, "WINDOW_PENDING", { window_id: pending.window_id });
        journalRecord(paths, txid, "RECOVERY_STEP", { action: "admit-pending-window" });
      }
      if (!lastRecord(records, "SWAP_INTENT")) {
        journalRecord(paths, txid, "SWAP_INTENT", { from_tree: staged.from_pointer.tree, to_tree: staged.tree, to_pointer: staged.to_pointer });
      }
      if (activeIdentity(paths).sha === oldActiveSha) {
        atomicReplace(paths.active, pointerBytes(staged.to_pointer));
        journalRecord(paths, txid, "RECOVERY_STEP", { action: "replace-active-pointer" });
      }
      if (!lastRecord(recordsFor(paths, txid), "SWAP_DONE")) journalRecord(paths, txid, "SWAP_DONE", { observed_active_sha: toActiveSha });

      records = recordsFor(paths, txid);
      let terminal = lastRecord(records, "OUTCOME_APPEND_INTENT");
      if (!terminal) {
        const entry = buildEntry(paths, begin.packet, txid, "effective", logIntent.entry_sha);
        terminal = { terminal_entry_sha: entry.entry_sha256, entry };
        journalRecord(paths, txid, "OUTCOME_APPEND_INTENT", terminal);
      }
      head = logHead(paths);
      if (head === logIntent.entry_sha) appendEntry(paths, terminal.entry);
      else if (head !== terminal.terminal_entry_sha) recoveryHalt(paths, txid, "terminal adoption outcome is ambiguous", { head });
      if (!lastRecord(recordsFor(paths, txid), "OUTCOME_APPEND_DONE")) {
        journalRecord(paths, txid, "OUTCOME_APPEND_DONE", { terminal_entry_sha: terminal.terminal_entry_sha, status: "effective" });
      }
      records = recordsFor(paths, txid);
      let manifestIntent = lastRecord(records, "MANIFEST_INTENT");
      const manifest = updateProjectManifest(paths, staged.to_pointer, terminal.terminal_entry_sha);
      if (!manifestIntent) {
        manifestIntent = { new_head_sha: terminal.terminal_entry_sha, manifest };
        journalRecord(paths, txid, "MANIFEST_INTENT", manifestIntent);
      }
      if (!manifestMatches(readProjectManifest(paths), staged.to_pointer, terminal.terminal_entry_sha)) {
        atomicReplace(paths.projectManifest, `${JSON.stringify(manifest, null, 2)}\n`);
        journalRecord(paths, txid, "RECOVERY_STEP", { action: "replace-project-manifest" });
      }
      if (!lastRecord(recordsFor(paths, txid), "MANIFEST_DONE")) journalRecord(paths, txid, "MANIFEST_DONE", { new_head_sha: terminal.terminal_entry_sha });
      if (!lastRecord(recordsFor(paths, txid), "WINDOW_FINAL")) {
        const finalWindow = finalizeWindow(store, begin.packet, txid);
        journalRecord(paths, txid, "WINDOW_FINAL", { window_id: pending.window_id, state: finalWindow.state });
      }
      journalRecord(paths, txid, "TX_DONE", { state: "DONE" });
      journalRecord(paths, txid, "RECOVERY_DONE", { outcome: "done" });
      outcomes.push({ txid, state: "DONE" });
    }
    cleanupAbandonedStaging(paths);
    return { state: outcomes.length ? "RECOVERED" : "CLEAN", transactions: outcomes };
  } finally {
    release(store, lock);
  }
}

function rollback(txidOrInverse) {
  let input;
  if (typeof txidOrInverse === "string") {
    const root = process.cwd();
    const paths = locations(root);
    const prior = recordsFor(paths, txidOrInverse);
    const begin = lastRecord(prior, "TX_BEGIN");
    const staged = lastRecord(prior, "STAGE_DONE");
    if (!begin || !staged || !lastRecord(prior, "TX_DONE")) throw failure(`Unknown or incomplete transaction: ${txidOrInverse}`, "ROLLBACK_NOT_FOUND");
    if (!["doc", "knob"].includes(begin.packet.kind) || begin.packet.reversible !== true || begin.packet.auto_rollback_eligible !== true) {
      throw failure("Rollback refused for code, migration, or non-pre-authorized change; preserve evidence and perform human forward-recovery", "FORWARD_RECOVERY_REQUIRED");
    }
    input = {
      project_root: root,
      fingerprint: sha256(`rollback:${txidOrInverse}:${staged.from_pointer.tree}`),
      kind: begin.packet.kind,
      evidence_ref: begin.packet.evidence_ref,
      human: { name: begin.packet.human.name, decision: `pre-authorized rollback of ${txidOrInverse}`, ts: begin.packet.human.ts },
      source_tree: staged.from_pointer.tree,
      reversible: false,
      auto_rollback_eligible: false,
      rollback_of: txidOrInverse,
    };
  } else {
    input = { ...txidOrInverse };
    if (!["doc", "knob"].includes(input.kind) || input.reversible !== true || input.auto_rollback_eligible !== true) {
      throw failure("Rollback refused for code, migration, or non-pre-authorized change; preserve evidence and perform human forward-recovery", "FORWARD_RECOVERY_REQUIRED");
    }
    input.rollback_of = requiredString(input.rollback_of, "inverse.rollback_of");
    if (!Array.isArray(input.edits) && Array.isArray(input.inverse)) input.edits = input.inverse;
  }
  return promote(input);
}

function createFixture(root) {
  const paths = locations(root);
  fs.mkdirSync(paths.state, { recursive: true });
  fs.mkdirSync(paths.evolvable, { recursive: true });
  const seed = path.join(paths.evolvable, "seed");
  fs.mkdirSync(seed);
  fs.writeFileSync(path.join(seed, "graphsmith.learned.md"), "alpha\n");
  fs.writeFileSync(path.join(seed, "tunables.json"), "{\n  \"limit\": 1\n}\n");
  const manifest = generate("tree", { rootDir: seed });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  fs.writeFileSync(path.join(seed, "tree.manifest.json"), manifestBytes);
  const tree = `v-${sha256(manifestBytes)}`;
  fs.renameSync(seed, path.join(paths.evolvable, tree));
  const pointer = { schema_version: SCHEMA_VERSION, txid: "0".repeat(16), tree, tree_manifest_sha256: sha256(manifestBytes) };
  fs.writeFileSync(paths.active, pointerBytes(pointer));
  fs.writeFileSync(paths.projectManifest, `${JSON.stringify({
    schema_version: SCHEMA_VERSION, kind: "project", generated_at: "selftest", parent_release_sha256: null,
    adoption_log_head: null, active_tree: tree, active_tree_manifest_sha256: sha256(manifestBytes), files: [], workflow_manifests: [],
  }, null, 2)}\n`);
  return { paths, tree };
}

function testPacket(root, suffix, extra = {}) {
  return {
    project_root: root,
    fingerprint: sha256(`selftest:${suffix}`),
    kind: "doc",
    evidence_ref: `selftest:${suffix}`,
    human: { name: "selftest", decision: "approve", ts: "2000-01-01T00:00:00.000Z" },
    edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "graphsmith.learned.md", anchor: "alpha", op: "replace", payload: suffix }],
    reversible: true,
    auto_rollback_eligible: true,
    window_n: 1,
    ...extra,
  };
}

function selftest() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-promote-selftest-"));
  const priorMode = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  const tests = [];
  const check = (name, condition) => {
    if (!condition) throw new Error(`selftest failed: ${name}`);
    tests.push({ name, status: "pass" });
  };
  try {
    const closeWindow = (root) => {
      const store = createStore(root);
      const lock = store._testing.acquireLock();
      try {
        store._commit([{
          file: "window.json",
          make: (raw, rev) => {
            const current = parseJson(raw, "window.json");
            current.state = "CLOSED_PASS";
            current.state_rev = rev;
            return JSON.stringify(current);
          },
        }]);
      } finally {
        clearInterval(lock.heartbeat);
        store._testing.releaseLock(lock.ownerToken);
      }
    };
    const happyRoot = path.join(base, "happy");
    createFixture(happyRoot);
    const happy = promote(testPacket(happyRoot, "happy"));
    check("happy-path-adoption", happy.state === "DONE" && adoptionEntries(locations(happyRoot)).at(-1).status === "effective");
    const happyPaths = locations(happyRoot);
    check("manifest-carries-tree-identity", manifestMatches(readProjectManifest(happyPaths), activeIdentity(happyPaths).pointer, logHead(happyPaths)));

    for (const point of ["before-swap", "after-swap", "after-manifest"]) {
      const root = path.join(base, point);
      createFixture(root);
      let crashed = false;
      try { promote(testPacket(root, point, { __test_crash_at: point })); }
      catch (error) { crashed = error.code === "SIMULATED_CRASH"; }
      const recovered = recover(root);
      const paths = locations(root);
      check(`kill-and-recover-${point}`, crashed && recovered.transactions[0].state === "DONE" && readProjectManifest(paths).adoption_log_head === logHead(paths));
    }

    const tornRoot = path.join(base, "torn-tail");
    createFixture(tornRoot);
    let tornCrashed = false;
    try { promote(testPacket(tornRoot, "torn-tail", { __test_crash_at: "after-swap" })); }
    catch (error) { tornCrashed = error.code === "SIMULATED_CRASH"; }
    const tornPaths = locations(tornRoot);
    const journalRaw = readFile(tornPaths.journal, "utf8");
    const completeEnd = journalRaw.lastIndexOf("\n", journalRaw.length - 2) + 1;
    const finalLine = journalRaw.slice(completeEnd).replace(/\n$/, "");
    fs.writeFileSync(tornPaths.journal, journalRaw.slice(0, completeEnd) + finalLine.slice(0, Math.max(1, Math.floor(finalLine.length / 2))));
    const tornRecovered = recover(tornRoot);
    const recoveryBegin = parseJsonl(tornPaths.journal).find((record) => record.record_type === "RECOVERY_BEGIN");
    check("torn-tail-recovery-rolls-forward", tornCrashed && tornRecovered.transactions[0].state === "DONE" && recoveryBegin.observed_state.truncated_journal_tail.truncated_bytes > 0);

    const stagingRoot = path.join(base, "abandoned-staging");
    const stagingFixture = createFixture(stagingRoot);
    const stagingTxid = sha256("abandoned-staging").slice(0, 16);
    const stagingPaths = locations(stagingRoot);
    const stagingDir = path.join(stagingPaths.evolvable, `.staging-${stagingTxid}`);
    fs.mkdirSync(stagingDir);
    fs.writeFileSync(path.join(stagingDir, "partial"), "partial");
    journalRecord(stagingPaths, stagingTxid, "TX_BEGIN", {
      expected_active_sha: activeIdentity(stagingPaths).sha, expected_log_head: null,
      packet: testPacket(stagingRoot, "abandoned-staging"),
    });
    recover(stagingRoot);
    check("recover-removes-abandoned-staging", !fs.existsSync(stagingDir) && stagingFixture.tree === activeIdentity(stagingPaths).pointer.tree);

    const gcRoot = path.join(base, "gc");
    const gcFixture = createFixture(gcRoot);
    promote(testPacket(gcRoot, "gc1"));
    const gcPaths = locations(gcRoot);
    const treeB = activeIdentity(gcPaths).pointer.tree;
    closeWindow(gcRoot);
    promote(testPacket(gcRoot, "gc2", { edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "graphsmith.learned.md", anchor: "gc1", op: "replace", payload: "gc2" }] }));
    closeWindow(gcRoot);
    createStore(gcRoot, { leaseMs: 60 * 60 * 1000, heartbeatMs: 1000 }).runRegistry.register("live-seed-reader", gcFixture.tree);
    promote(testPacket(gcRoot, "gc3", { edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "graphsmith.learned.md", anchor: "gc2", op: "replace", payload: "gc3" }] }));
    closeWindow(gcRoot);
    promote(testPacket(gcRoot, "gc4", { edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "graphsmith.learned.md", anchor: "gc3", op: "replace", payload: "gc4" }] }));
    check("gc-deletes-orphan-spares-live-lease", !fs.existsSync(path.join(gcPaths.evolvable, treeB)) && fs.existsSync(path.join(gcPaths.evolvable, gcFixture.tree)));

    const abortRoot = path.join(base, "abort");
    createFixture(abortRoot);
    const aborted = promote(testPacket(abortRoot, "abort", { __test_abort_after_log: true }));
    const abortPaths = locations(abortRoot);
    check("terminal-abort-is-manifest-anchored", aborted.state === "ABORTED" && adoptionEntries(abortPaths).at(-1).status === "aborted" && readProjectManifest(abortPaths).adoption_log_head === logHead(abortPaths));

    const rollbackRoot = path.join(base, "rollback");
    const fixture = createFixture(rollbackRoot);
    const adopted = promote(testPacket(rollbackRoot, "changed"));
    const previousCwd = process.cwd();
    process.chdir(rollbackRoot);
    let rolledBack;
    try { rolledBack = rollback(adopted.txid); } finally { process.chdir(previousCwd); }
    const restored = activeIdentity(locations(rollbackRoot));
    check("doc-knob-rollback-byte-exact", rolledBack.state === "DONE" && restored.pointer.tree === fixture.tree && readFile(path.join(rollbackRoot, ".graphsmith", "evolvable", fixture.tree, "graphsmith.learned.md"), "utf8") === "alpha\n");

    return { schema_version: SCHEMA_VERSION, status: "pass", tests };
  } finally {
    if (priorMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = priorMode;
    fs.rmSync(base, { recursive: true, force: true });
  }
}

module.exports = { promote, rollback, recover, SCHEMA_VERSION };

if (require.main === module) {
  const [command, argument] = process.argv.slice(2);
  try {
    let result;
    if (command === "promote" && argument) result = promote(parseJson(fs.readFileSync(path.resolve(argument), "utf8"), argument));
    else if (command === "rollback" && argument) result = rollback(argument);
    else if (command === "recover") result = recover();
    else if (command === "--selftest") result = selftest();
    else {
      process.stderr.write("Usage: node scripts/promote.js promote <packet.json> | rollback <txid> | recover | --selftest\n");
      process.exitCode = 2;
    }
    if (result) process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error.code || "ERROR"}: ${error.message}\n`);
    if (error.evidence !== undefined) process.stderr.write(`${JSON.stringify(error.evidence)}\n`);
    process.exitCode = error.code === "HALT" ? 3 : error.code === "INVALID_PACKET" ? 2 : 1;
  }
}
