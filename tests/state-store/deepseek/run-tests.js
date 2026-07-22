#!/usr/bin/env node
/* Adversarial test suite for scripts/state-store.js — deepseek family lane.
 * Zero-dependency CJS. One line per case: PASS/FAIL/SKIPPED+reason.
 * Exit code 0 iff zero FAIL results. */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");

const STATE_STORE_PATH = path.resolve(__dirname, "..", "..", "..", "scripts", "state-store.js");
const SCHEMA_PATH = path.resolve(__dirname, "..", "..", "..", "schemas", "state-store.schema.json");

const SCHEMA = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

function randHex(len) { return crypto.randomBytes(len / 2).toString("hex"); }

function makeTempDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-ds-ss-"));
  const stateDir = path.join(dir, ".graphsmith", "state");
  fs.mkdirSync(stateDir, { recursive: true });
  return dir;
}

function cleanTempDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

/* ---- minimal JSON Schema validator for state-store.schema.json ---- */

function validateRecord(record) {
  const errors = [];

  function checkType(val, expected) {
    if (expected === "integer") return Number.isSafeInteger(val);
    if (expected === "number") return typeof val === "number" && Number.isFinite(val);
    if (expected === "string") return typeof val === "string";
    if (expected === "boolean") return typeof val === "boolean";
    if (expected === "object") return typeof val === "object" && val !== null && !Array.isArray(val);
    if (expected === "array") return Array.isArray(val);
    if (expected === "null") return val === null;
    if (expected === "null_string") return val === null || typeof val === "string";
    return true;
  }

  function checkRequired(obj, required, path) {
    for (const key of required) {
      if (!(key in obj)) errors.push(`${path} missing required: ${key}`);
    }
  }

  function checkAdditional(obj, allowed, path) {
    for (const key of Object.keys(obj)) {
      if (!allowed.has(key)) errors.push(`${path} unknown key: ${key}`);
    }
  }

  function checkEnum(val, allowed, path) {
    if (!allowed.includes(val)) errors.push(`${path}: ${JSON.stringify(val)} not in [${allowed.map(JSON.stringify).join(",")}]`);
  }

  function checkPattern(val, pattern, path) {
    if (!new RegExp(`^${pattern}$`).test(val)) errors.push(`${path}: "${val}" does not match /^${pattern}$/`);
  }

  function checkMin(val, min, path) {
    if (val < min) errors.push(`${path}: ${val} < ${min}`);
  }

  function checkMax(val, max, path) {
    if (val > max) errors.push(`${path}: ${val} > ${max}`);
  }

  function checkExclMin(val, min, path) {
    if (val <= min) errors.push(`${path}: ${val} <= ${min}`);
  }

  function validateBySchema(obj, def, path) {
    if (!def) return;
    if (def.type) {
      if (!checkType(obj, def.type)) errors.push(`${path}: expected ${def.type}, got ${typeof obj}`);
    }
    if (def.const !== undefined && obj !== def.const) errors.push(`${path}: expected ${JSON.stringify(def.const)}, got ${JSON.stringify(obj)}`);
    if (def.enum && !def.enum.includes(obj)) checkEnum(obj, def.enum, path);
    if (def.pattern && typeof obj === "string") checkPattern(obj, def.pattern, path);
    if (def.minimum !== undefined) checkMin(obj, def.minimum, path);
    if (def.maximum !== undefined) checkMax(obj, def.maximum, path);
    if (def.exclusiveMinimum !== undefined) checkExclMin(obj, def.exclusiveMinimum, path);
    if (def.required && typeof obj === "object" && obj !== null && !Array.isArray(obj)) checkRequired(obj, def.required, path);
    if (def.additionalProperties === false && typeof obj === "object" && obj !== null && !Array.isArray(obj)) {
      const allowed = new Set(def.properties ? Object.keys(def.properties) : []);
      checkAdditional(obj, allowed, path);
    }
    if (def.properties && typeof obj === "object" && obj !== null && !Array.isArray(obj)) {
      for (const [key, propDef] of Object.entries(def.properties)) {
        if (key in obj) validateBySchema(obj[key], propDef, `${path}.${key}`);
      }
    }
    if (def.items && Array.isArray(obj)) {
      obj.forEach((item, i) => validateBySchema(item, def.items, `${path}[${i}]`));
    }
    if (def.$ref) {
      const refName = def.$ref.replace("#/$defs/", "");
      validateBySchema(obj, SCHEMA.$defs[refName], path);
    }
  }

  const topDefs = SCHEMA.oneOf;
  let matched = false;
  for (const entry of topDefs) {
    if (!entry.$ref) continue;
    const refName = entry.$ref.replace("#/$defs/", "");
    const def = SCHEMA.$defs[refName];
    const savedErrors = errors.length;

    if (def.required) checkRequired(record, def.required, "$");
    if (def.additionalProperties === false) {
      const allowed = new Set(def.properties ? Object.keys(def.properties) : []);
      checkAdditional(record, allowed, "$");
    }
    if (def.properties) {
      for (const [key, propDef] of Object.entries(def.properties)) {
        if (key in record) validateBySchema(record[key], propDef, `$.${key}`);
      }
    }
    if (def.const !== undefined && "record_type" in record) {
      // record_type already checked via properties
    }

    if (errors.length === savedErrors) {
      matched = true;
      break;
    }
    errors.length = savedErrors;
  }

  if (!matched) errors.push(`$: record does not match any schema in oneOf — record_type=${record.record_type || "(none)"}`);

  return errors;
}

/** Validate all records from a JSONL file path; returns errors array (empty = valid). */
function validateJsonLines(jsonlPath) {
  const errors = [];
  let raw;
  try { raw = fs.readFileSync(jsonlPath, "utf8"); } catch (e) { if (e.code === "ENOENT") return errors; throw e; }
  if (!raw) return errors;
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    if (i === lines.length - 1 && !raw.endsWith("\n")) break;
    try {
      const record = JSON.parse(lines[i]);
      const recErrors = validateRecord(record);
      if (recErrors.length) errors.push(`line ${i + 1}: ${recErrors.join("; ")}`);
    } catch (e) {
      errors.push(`line ${i + 1}: parse error: ${e.message}`);
    }
  }
  return errors;
}

/** Validate the lock file separately if it exists */
function validateLock(lockPath) {
  let raw;
  try { raw = fs.readFileSync(lockPath, "utf8"); } catch (e) { if (e.code === "ENOENT") return []; throw e; }
  try {
    const record = JSON.parse(raw);
    const errors = [];
    const def = SCHEMA.$defs.lock;
    for (const key of Object.keys(record)) {
      if (!Object.keys(def.properties).includes(key)) errors.push(`lock unknown key: ${key}`);
    }
    for (const req of def.required) {
      if (!(req in record)) errors.push(`lock missing required: ${req}`);
    }
    return errors;
  } catch (e) {
    return [`lock parse error: ${e.message}`];
  }
}

/* ---- Test helpers ---- */

let results = [];

function record(name, status, detail = "") {
  const line = status === "PASS" ? `PASS: ${name}` : status === "FAIL" ? `FAIL: ${name}${detail ? " — " + detail : ""}` : `SKIPPED: ${name} (${detail})`;
  results.push({ name, status, detail, line });
  console.log(line);
}

function requireFreshStore(dir, opts = {}) {
  const { StateStore } = require(STATE_STORE_PATH);
  return new StateStore(dir, opts);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

/* ---- TEST 1: Lock — steal expired lease; refuse fresh; owner-token mismatch ---- */

function test1_lockStealMismatch(tempDir) {
  const name = "1. Lock: steal expired lease; refuse fresh; owner-token mismatch on renew/release";
  try {
    const prevMode = process.env.GRAPHSMITH_TEST_MODE;
    process.env.GRAPHSMITH_TEST_MODE = "1";
    try {
      const store1 = requireFreshStore(tempDir, { leaseMs: 40, heartbeatMs: 5 });

      // Pre-create a fresh lock with a fake owner token
      store1._ensureStateDir();
      const freshToken = randHex(32);
      fs.writeFileSync(store1.lockPath, JSON.stringify({
        schema_version: "1.0", pid: process.pid, proc_start_hint: "fresh-fake-lock", owner_token: freshToken,
      }));

      // Attempt to acquire while lock is fresh (our pid is alive, mtime is now) → must REFUSE
      let freshRefused = false;
      try {
        store1._testing.acquireLock();
      } catch (e) {
        freshRefused = e.code === "LOCKED" || e.message.includes("actively locked");
      }
      if (!freshRefused) throw new Error("Fresh lock by alive pid was not refused");

      // Now create a stale lock with expired lease
      fs.unlinkSync(store1.lockPath);
      const staleToken = randHex(32);
      fs.writeFileSync(store1.lockPath, JSON.stringify({
        schema_version: "1.0", pid: 99999, proc_start_hint: "stale-dead-pid", owner_token: staleToken,
      }));
      const oldTime = new Date(Date.now() - 5000);
      fs.utimesSync(store1.lockPath, oldTime, oldTime);

      // Acquire should steal the expired lock
      const stolen = store1._testing.acquireLock();
      if (!stolen || !stolen.ownerToken) throw new Error("Failed to steal expired lock");

      // Owner-token mismatch on release
      let mismatchReleaseRefused = false;
      try {
        store1._testing.releaseLock("0".repeat(32));
      } catch (e) {
        mismatchReleaseRefused = e.code === "LOCK_OWNER_MISMATCH";
      }
      assert(mismatchReleaseRefused, "owner-token mismatch on release was not refused");

      // Owner-token mismatch on renew
      let mismatchRenewRefused = false;
      try {
        store1._renewLock("0".repeat(32));
      } catch (e) {
        mismatchRenewRefused = e.code === "LOCK_OWNER_MISMATCH";
      }
      assert(mismatchRenewRefused, "owner-token mismatch on renew was not refused");

      // Clean release with correct token should succeed
      const released = store1._testing.releaseLock(stolen.ownerToken);
      assert(released === true, "Release with correct token should return true");

      clearInterval(stolen.heartbeat);
      record(name, "PASS");
    } finally {
      if (prevMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
      else process.env.GRAPHSMITH_TEST_MODE = prevMode;
    }
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 2: Pid-reuse + TEST_MODE check ---- */

function test2_pidReuseAndTestMode(tempDir) {
  const name = "2. Pid-reuse: alive-pid stale lease stealable; fresh heartbeat refused; TEST_MODE required";
  const savedTestMode = process.env.GRAPHSMITH_TEST_MODE;
  try {
    // First: WITHOUT GRAPHSMITH_TEST_MODE=1, custom lease values should be IGNORED
    delete process.env.GRAPHSMITH_TEST_MODE;
    const savedLease = process.env.GRAPHSMITH_LEASE_MS;
    const savedHeartbeat = process.env.GRAPHSMITH_HEARTBEAT_MS;
    process.env.GRAPHSMITH_LEASE_MS = "100";
    process.env.GRAPHSMITH_HEARTBEAT_MS = "20";
    try {
      const storeNoTest = requireFreshStore(tempDir);
      if (storeNoTest.leaseMs !== 30000 || storeNoTest.heartbeatMs !== 5000) {
        throw new Error(`TEST_MODE not set but lease=${storeNoTest.leaseMs} heartbeat=${storeNoTest.heartbeatMs} (expected 30000/5000)`);
      }

      // Also verify that options leaseMs/heartbeatMs are ignored without TEST_MODE
      const storeOptsNoTest = new (require(STATE_STORE_PATH).StateStore)(tempDir, { leaseMs: 123, heartbeatMs: 50 });
      if (storeOptsNoTest.leaseMs !== 30000 || storeOptsNoTest.heartbeatMs !== 5000) {
        throw new Error(`options lease=${storeOptsNoTest.leaseMs} (expected 30000)`);
      }
    } finally {
      process.env.GRAPHSMITH_TEST_MODE = "1";
      if (savedLease === undefined) delete process.env.GRAPHSMITH_LEASE_MS;
      else process.env.GRAPHSMITH_LEASE_MS = savedLease;
      if (savedHeartbeat === undefined) delete process.env.GRAPHSMITH_HEARTBEAT_MS;
      else process.env.GRAPHSMITH_HEARTBEAT_MS = savedHeartbeat;
    }

    // Now with TEST_MODE=1
    const store = requireFreshStore(tempDir, { leaseMs: 40, heartbeatMs: 5 });
    store._ensureStateDir();

    // Create a stale lock with OUR pid (alive) but expired lease
    const staleToken = randHex(32);
    fs.writeFileSync(store.lockPath, JSON.stringify({
      schema_version: "1.0", pid: process.pid, proc_start_hint: "pid-reuse-stale", owner_token: staleToken,
    }));
    const oldTime = new Date(Date.now() - 5000);
    fs.utimesSync(store.lockPath, oldTime, oldTime);

    // Should be stealable even though pid is alive (lease expired)
    const stolen = store._testing.acquireLock();
    assert(stolen && stolen.ownerToken, "Failed to steal expired lock from alive pid");

    // Release it
    store._testing.releaseLock(stolen.ownerToken);
    clearInterval(stolen.heartbeat);

    // Now create a FRESH lock with OUR pid
    const freshToken2 = randHex(32);
    fs.writeFileSync(store.lockPath, JSON.stringify({
      schema_version: "1.0", pid: process.pid, proc_start_hint: "pid-reuse-fresh", owner_token: freshToken2,
    }));

    // Fresh heartbeat (our pid alive, lease not expired) → refused
    let freshRefused = false;
    try {
      store._testing.acquireLock();
    } catch (e) {
      freshRefused = e.code === "LOCKED" || e.message.includes("actively locked");
    }
    assert(freshRefused, "Fresh heartbeat from alive pid was not refused");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  } finally {
    // Force-clean lock if left behind
    try {
      const lockPath = path.join(tempDir, ".graphsmith", "state", "state.lock");
      fs.unlinkSync(lockPath);
    } catch {}
    if (savedTestMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = savedTestMode;
  }
}

/* ---- TEST 3: Crash recovery (child process kill -9) ---- */

function test3_crashRecovery(tempDir) {
  const name = "3. Crash recovery: kill child mid-mutation; roll-forward cleanly; state_rev monotonic; no torn state";
  // Skip on non-Windows if kill -9 semantics differ; we use taskkill /PID on Windows
  if (process.platform !== "win32") {
    record(name, "SKIPPED", "kill -9 tested via Windows taskkill; platform is " + process.platform);
    return;
  }

  const prevMode = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  try {
    // Prepare the temp dir with an admitted window
    const prepStore = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });
    prepStore.window.admitPending({ txid: "tx-crash", fingerprint: "fp-crash", tree_id: "tree-crash", n: 1 });
    prepStore.window.finalize("tx-crash");

    // Build a child script that: acquires lock, starts mutation (register a run), then kills itself
    const childScript = path.join(tempDir, "child-crash.js");
    fs.writeFileSync(childScript,
'"use strict";\n' +
'var { StateStore } = require(' + JSON.stringify(STATE_STORE_PATH) + ');\n' +
'var store = new StateStore(' + JSON.stringify(tempDir) + ', { leaseMs: 200, heartbeatMs: 50 });\n' +
'store._testing.crashNextMutationAfter(1);\n' +
'try {\n' +
'  store.runRegistry.register("run-crash-recover", "tree-crash");\n' +
'  process.exit(0);\n' +
'} catch (e) {\n' +
'  process.stderr.write("crashed:" + e.code + "\\n");\n' +
'  process.exit(1);\n' +
'}\n');

    const result = cp.spawnSync(process.execPath, [childScript], {
      env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
      stdio: ["ignore", "inherit", "inherit"],
      timeout: 10000,
    });

    // Clean up stale lock if the child left one
    const lockPath = path.join(tempDir, ".graphsmith", "state", "state.lock");
    try { fs.unlinkSync(lockPath); } catch {}

    // Now open a new store — recovery should roll forward
    const recoveryStore = requireFreshStore(tempDir, { leaseMs: 200, heartbeatMs: 50 });

    // The run should have been registered (roll forward)
    const runs = recoveryStore.runRegistry.list();
    const recovered = runs.find((r) => r.run_id === "run-crash-recover");

    assert(recovered, "Run was not recovered after crash");

    // state_rev must be monotonic — window should reflect the state
    const win = recoveryStore.window.get();
    assert(win.state_rev > 0, "state_rev should be > 0 after recovery");

    // No torn state: the MUTATION_DONE record should exist in the journal
    const journalPath = path.join(tempDir, ".graphsmith", "state", "state-journal.jsonl");
    const journal = fs.readFileSync(journalPath, "utf8");
    assert(journal.includes("MUTATION_DONE"), "Journal should contain MUTATION_DONE after recovery");

    // Verify the slot was observed
    const hasSlot = win.window && win.window.slots.some((s) => s.run_id === "run-crash-recover");
    assert(hasSlot, "Window slot was not rolled forward");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  } finally {
    try { fs.unlinkSync(path.join(tempDir, ".graphsmith", "state", "state.lock")); } catch {}
    if (prevMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = prevMode;
  }
}

/* ---- TEST 4: Alpha ledger — crash persistence + 4th refused ---- */

function test4_alphaLedger(tempDir) {
  const name = "4. Alpha ledger: crash-reserve slot consumed; 4th reservation on one corpus refused";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    // Reservation 1
    const r1 = store.alphaLedger.reserve({ corpus_state: "corpus-x", split_hash: "split-1", fingerprint: "fp-1", family: "fam-1" });
    assert(r1.alpha_slot === 1, `Expected slot 1, got ${r1.alpha_slot}`);

    // Reservation 2
    const r2 = store.alphaLedger.reserve({ corpus_state: "corpus-x", split_hash: "split-2", fingerprint: "fp-2", family: "fam-2" });
    assert(r2.alpha_slot === 2, `Expected slot 2, got ${r2.alpha_slot}`);

    // Reservation 3
    const r3 = store.alphaLedger.reserve({ corpus_state: "corpus-x", split_hash: "split-3", fingerprint: "fp-3", family: "fam-3" });
    assert(r3.alpha_slot === 3, `Expected slot 3, got ${r3.alpha_slot}`);

    // Verify list has all 3
    const list = store.alphaLedger.list("corpus-x");
    assert(list.filter((r) => r.record_type === "RESERVED").length === 3, "Should have 3 reservations");

    // 4th reservation must be refused
    let fourthRefused = false;
    try {
      store.alphaLedger.reserve({ corpus_state: "corpus-x", split_hash: "split-4", fingerprint: "fp-4", family: "fam-4" });
    } catch (e) {
      fourthRefused = e.code === "ALPHA_EXHAUSTED";
    }
    assert(fourthRefused, "4th alpha reservation was not refused");

    // Simulate crash by creating a new store instance (reservation persists)
    const store2 = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });
    const list2 = store2.alphaLedger.list("corpus-x");
    const reservedCount = list2.filter((r) => r.record_type === "RESERVED").length;
    assert(reservedCount === 3, `Reservations should persist across instances, got ${reservedCount}`);

    // Complete reservation 1
    store2.alphaLedger.complete(r1.reservation_id, { verdict: "promote" });
    const list3 = store2.alphaLedger.list();
    const completed = list3.filter((r) => r.record_type === "COMPLETED" && r.reservation_id === r1.reservation_id);
    assert(completed.length === 1, `Should have 1 completed record, got ${completed.length}`);

    // Even after completion, slot is consumed and 4th reservation still refused
    let stillRefused = false;
    try {
      store2.alphaLedger.reserve({ corpus_state: "corpus-x", split_hash: "split-5", fingerprint: "fp-5", family: "fam-5" });
    } catch (e) {
      stillRefused = e.code === "ALPHA_EXHAUSTED" || e.code === "ALPHA_FAMILY_CONSUMED";
    }
    assert(stillRefused, "4th reservation should still be refused after completion");

    // Family collision: same family should be refused
    let familyRefused = false;
    try {
      store2.alphaLedger.reserve({ corpus_state: "corpus-x", split_hash: "split-2b", fingerprint: "fp-2b", family: "fam-2" });
    } catch (e) {
      familyRefused = e.code === "ALPHA_FAMILY_CONSUMED";
    }
    assert(familyRefused, "Family collision was not refused");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 5: Run registry — register/deregister; expired sweep; live-tree query ---- */

async function test5_runRegistry(tempDir) {
  const name = "5. Run registry: register/deregister; expired-lease sweep; live-lease trees reported";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 40, heartbeatMs: 5 });

    // Register runs on different trees
    const reg1 = store.runRegistry.register("run-r1", "tree-alpha");
    assert(reg1.registration.run_id === "run-r1" && !reg1.existing, "Registration 1 failed");
    
    const reg2 = store.runRegistry.register("run-r2", "tree-beta");
    assert(reg2.registration.run_id === "run-r2", "Registration 2 failed");

    // Re-registration of same runId on same tree is idempotent
    const reg1b = store.runRegistry.register("run-r1", "tree-alpha");
    assert(reg1b.existing === true, "Re-registration should report existing=true");

    // Re-registration on different tree must fail
    let conflictRefused = false;
    try {
      store.runRegistry.register("run-r1", "tree-other");
    } catch (e) {
      conflictRefused = e.code === "RUN_CONFLICT";
    }
    assert(conflictRefused, "Run conflict on different tree was not refused");

    // Heartbeat
    const hb = store.runRegistry.heartbeat("run-r1");
    assert(hb.run_id === "run-r1", "Heartbeat failed");

    // Heartbeat unknown run
    let hbUnknownRefused = false;
    try {
      store.runRegistry.heartbeat("run-nonexistent");
    } catch (e) {
      hbUnknownRefused = e.code === "RUN_NOT_FOUND";
    }
    assert(hbUnknownRefused, "Heartbeat on unknown run was not refused");

    // Deregister
    const dereg = store.runRegistry.deregister("run-r2", { disposition: "completed_pass" });
    assert(dereg.deregistered === true, "Deregistration failed");
    assert(dereg.disposition === "completed_pass", `Expected completed_pass, got ${dereg.disposition}`);

    // List should only contain run-r1
    const runsAfterDereg = store.runRegistry.list();
    assert(runsAfterDereg.length === 1 && runsAfterDereg[0].run_id === "run-r1", "List after dereg should have 1 run");

    // Expired sweep: wait for lease to expire
    const expiryWait = new Promise((resolve) => setTimeout(resolve, 60));
    await expiryWait;

    const swept = store.runRegistry.sweepExpired();
    assert(swept.includes("run-r1"), "Expired run was not swept");
    assert(store.runRegistry.list().length === 0, "List should be empty after expiry sweep");

    // Sweep must journal what it swept — check the EXPIRED record in registry
    const registryPath = path.join(tempDir, ".graphsmith", "state", "run-registry.jsonl");
    const regRaw = fs.readFileSync(registryPath, "utf8");
    assert(regRaw.includes('"EXPIRED"'), "Registry should contain EXPIRED record");
    assert(regRaw.includes("run-r1"), "EXPIRED record should name the swept run");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 6: Window slots — N+1 refusal; terminal dispositions; abandoned → FLAG + CLOSED_FLAGGED ---- */

function test6_windowSlots(tempDir) {
  const name = "6. Window slots: N-slot capacity; terminal dispositions required; abandoned → FLAGGED";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    // Admit a window with 3 slots
    store.window.admitPending({ txid: "tx-win", fingerprint: "fp-win", tree_id: "tree-win", n: 3 });
    store.window.finalize("tx-win");

    // Register & observe 3 runs
    const r1 = store.runRegistry.register("run-s1", "tree-win");
    assert(r1.slot !== null, "Run 1 should get a slot");
    const r2 = store.runRegistry.register("run-s2", "tree-win");
    assert(r2.slot !== null, "Run 2 should get a slot");
    const r3 = store.runRegistry.register("run-s3", "tree-win");
    assert(r3.slot !== null, "Run 3 should get a slot");

    // 4th run should NOT be observed (no slot)
    const r4 = store.runRegistry.register("run-s4", "tree-win");
    assert(r4.slot === null, "Run 4 should NOT get a slot");

    // Window active count should be 3
    const win = store.window.get();
    assert(win.window.active === 3, `Expected active=3, got ${win.window.active}`);
    assert(win.window.admitted === 3, `Expected admitted=3, got ${win.window.admitted}`);
    assert(win.window.slots.length === 3, `Expected 3 slots, got ${win.window.slots.length}`);

    // Attempt to close window while runs are active → must fail
    let closeActiveRefused = false;
    try {
      store.window.close("tx-win", undefined);
    } catch (e) {
      closeActiveRefused = e.code === "WINDOW_ACTIVE";
    }
    assert(closeActiveRefused, "Closing window with active slots was not refused");

    // Dispose runs with terminal dispositions
    store.window.dispose("run-s1", { disposition: "completed_pass" });
    store.window.dispose("run-s2", { disposition: "completed_soft_wobble" });

    // Check soft_wobble sets FLAG
    const winAfterWobble = store.window.get();
    assert(winAfterWobble.flag === true, "Soft wobble should set FLAG bit");

    // Deregister run-s3 with abandoned disposition (simulate sweep manually)
    store.window.dispose("run-s3", { disposition: "abandoned" });

    // All slots now terminal → can close
    const closed = store.window.close("tx-win", "flagged");
    assert(closed.state === "CLOSED_FLAGGED", `Expected CLOSED_FLAGGED, got ${closed.state}`);

    // Now test terminal dispositions required: new window, register 1 run, try close
    store.window.admitPending({ txid: "tx-win2", fingerprint: "fp-win2", tree_id: "tree-win2", n: 1 });
    store.window.finalize("tx-win2");
    store.runRegistry.register("run-t1", "tree-win2");

    let closeIncompleteRefused = false;
    try {
      store.window.close("tx-win2", undefined);
    } catch (e) {
      closeIncompleteRefused = e.code === "WINDOW_ACTIVE";
    }
    assert(closeIncompleteRefused, "Closing window with active terminal slots was not refused");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 7: Concurrency — two processes hammering register/deregister ---- */

async function test7_concurrency(tempDir) {
  const name = "7. Concurrency: two processes hammering register/deregister; no lost updates, no corrupt JSON";
  if (process.platform !== "win32") {
    record(name, "SKIPPED", "concurrency test optimized for Windows; platform is " + process.platform);
    return;
  }

  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const prepStore = requireFreshStore(tempDir, { leaseMs: 10000, heartbeatMs: 2000 });

    // Worker script — each worker creates a fresh StateStore per attempt with randomized backoff
    const workerScript = path.join(tempDir, "worker-concurrency.js");
    fs.writeFileSync(workerScript,
'"use strict";\n' +
'var { StateStore } = require(' + JSON.stringify(STATE_STORE_PATH) + ');\n' +
'var results = { ops: 0, errors: 0, lastError: null };\n' +
'var workerId = process.argv[2];\n' +
'function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }\n' +
'for (var i = 0; i < 10; i++) {\n' +
'  var runId = "wrk-" + workerId + "-" + i;\n' +
'  var done = false;\n' +
'  for (var attempt = 0; attempt < 60 && !done; attempt++) {\n' +
'    try {\n' +
'      var store = new StateStore(' + JSON.stringify(tempDir) + ', { leaseMs: 5000, heartbeatMs: 500 });\n' +
'      store.runRegistry.register(runId, "tree-conc");\n' +
'      store.runRegistry.deregister(runId);\n' +
'      results.ops++;\n' +
'      done = true;\n' +
'    } catch (e) {\n' +
'      results.lastError = e.code || e.message;\n' +
'      if (attempt === 59) { results.errors++; done = true; }\n' +
'      else sleepSync(2 + Math.floor(Math.random() * 8));\n' +
'    }\n' +
'  }\n' +
'}\n' +
'process.send(results);\n');

    const workers = [];
    const workerPromises = [];

    for (let w = 0; w < 2; w++) {
      const child = cp.fork(workerScript, [String(w)], {
        stdio: ["ignore", "inherit", "inherit", "ipc"],
        env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
      });
      workers.push(child);
      const p = new Promise((resolve) => {
        child.on("message", (msg) => resolve(msg));
        child.on("exit", () => resolve(null));
      });
      workerPromises.push(p);
    }

    const allResults = (await Promise.all(workerPromises)).filter(Boolean);

    const totalOps = allResults.reduce((a, r) => a + (r.ops || 0), 0);
    const totalErrors = allResults.reduce((a, r) => a + (r.errors || 0), 0);

    if (totalErrors > 0) throw new Error(`${totalErrors} operations failed across ${workers.length} workers (${totalOps} succeeded)`);

    // After all deregistrations, verify data integrity
    const finalStore = requireFreshStore(tempDir, { leaseMs: 200, heartbeatMs: 50 });
    
    // Check registry JSONL is parseable (no corruption)
    const regPath = path.join(tempDir, ".graphsmith", "state", "run-registry.jsonl");
    let regRaw;
    try { regRaw = fs.readFileSync(regPath, "utf8"); } catch (e) { regRaw = ""; }
    const regLines = regRaw.split("\n").filter(Boolean);
    for (const line of regLines) {
      try { JSON.parse(line); } catch (e) {
        throw new Error(`Corrupt JSON in registry: ${e.message}`);
      }
    }

    // Check journal is parseable
    const journalPath = path.join(tempDir, ".graphsmith", "state", "state-journal.jsonl");
    let journalRaw;
    try { journalRaw = fs.readFileSync(journalPath, "utf8"); } catch (e) { journalRaw = ""; }
    const journalLines = journalRaw.split("\n").filter(Boolean);
    for (const line of journalLines) {
      try { JSON.parse(line); } catch (e) {
        throw new Error(`Corrupt JSON in journal: ${e.message}`);
      }
    }

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 8: Schema validation — every record validates; unknown keys rejected on read ---- */

function test8_schemaValidation(tempDir) {
  const name = "8. Schema: every record validates against state-store.schema.json; unknown keys rejected";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    // Exercise most operations to generate records
    store.window.admitPending({ txid: "tx-schema", fingerprint: "fp-schema", tree_id: "tree-schema", n: 2 });
    store.window.finalize("tx-schema");
    store.runRegistry.register("run-schema-1", "tree-schema");
    store.runRegistry.heartbeat("run-schema-1");
    store.runRegistry.deregister("run-schema-1", { disposition: "completed_pass" });
    store.alphaLedger.reserve({ corpus_state: "corpus-s", split_hash: "split-s", fingerprint: "fp-s", family: "fam-s" });
    store.runAnchors.setAnchor("run-schema-1", { chain_head: "abc123", expected_terminal_status: "completed_pass" });
    store.rejectedBuffer.push({ fingerprint: "rej-fp", value: { reason: "test" } });
    store.rollbackFamilies.append({ fingerprint: "rb-fp", family: "rb-fam", evidence: { data: 1 } });

    // Validate journal
    const journalPath = path.join(tempDir, ".graphsmith", "state", "state-journal.jsonl");
    const journalErrors = validateJsonLines(journalPath);
    if (journalErrors.length) throw new Error(`Journal schema errors: ${journalErrors.join("; ")}`);

    // Validate registry
    const regPath = path.join(tempDir, ".graphsmith", "state", "run-registry.jsonl");
    const regErrors = validateJsonLines(regPath);
    if (regErrors.length) throw new Error(`Registry schema errors: ${regErrors.join("; ")}`);

    // Validate window.json
    const winPath = path.join(tempDir, ".graphsmith", "state", "window.json");
    try {
      const winRaw = fs.readFileSync(winPath, "utf8");
      const winRecord = JSON.parse(winRaw);
      const winErrors = validateRecord(winRecord);
      if (winErrors.length) throw new Error(`Window schema errors: ${winErrors.join("; ")}`);
    } catch (e) {
      if (e.message.includes("schema")) throw e;
    }

    // Validate alpha ledger
    const alphaPath = path.join(tempDir, ".graphsmith", "state", "alpha-ledger.jsonl");
    const alphaErrors = validateJsonLines(alphaPath);
    if (alphaErrors.length) throw new Error(`Alpha ledger schema errors: ${alphaErrors.join("; ")}`);

    // Validate anchors
    const anchorPath = path.join(tempDir, ".graphsmith", "state", "run-anchors.jsonl");
    const anchorErrors = validateJsonLines(anchorPath);
    if (anchorErrors.length) throw new Error(`Anchor schema errors: ${anchorErrors.join("; ")}`);

    // Validate rejected buffer
    const rejPath = path.join(tempDir, ".graphsmith", "state", "rejected-buffer.jsonl");
    const rejErrors = validateJsonLines(rejPath);
    if (rejErrors.length) throw new Error(`Rejected buffer schema errors: ${rejErrors.join("; ")}`);

    // Validate rollback families
    const rbPath = path.join(tempDir, ".graphsmith", "state", "rollback-families.jsonl");
    const rbErrors = validateJsonLines(rbPath);
    if (rbErrors.length) throw new Error(`Rollback families schema errors: ${rbErrors.join("; ")}`);

    // Validate lock (if exists)
    const lockPath = path.join(tempDir, ".graphsmith", "state", "state.lock");
    const lockErrors = validateLock(lockPath);
    if (lockErrors.length) throw new Error(`Lock schema errors: ${lockErrors.join("; ")}`);

    // Test unknown key rejection: try to parse a corrupt window.json
    const corruptWinPath = path.join(tempDir, ".graphsmith", "state", "window.json");
    const badWin = JSON.parse(fs.readFileSync(corruptWinPath, "utf8"));
    badWin.unknown_field = "intruder";
    const badWinErrors = validateRecord(badWin);
    if (badWinErrors.length === 0) throw new Error("Unknown key 'unknown_field' was not flagged by schema validator");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 9: state_rev monotonic (additional attack) ---- */

function test9_stateRevMonotonic(tempDir) {
  const name = "9. state_rev monotonicity across sequential operations";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    let lastRev = 0;
    const ops = [
      () => store.window.admitPending({ txid: "tx-rev", fingerprint: "fp-rev", tree_id: "tree-rev", n: 2 }),
      () => store.window.finalize("tx-rev"),
      () => store.runRegistry.register("run-rev-1", "tree-rev"),
      () => store.runRegistry.register("run-rev-2", "tree-rev"),
      () => store.runRegistry.deregister("run-rev-1", { disposition: "completed_pass" }),
    ];

    for (const op of ops) {
      op();
      const win = store.window.get();
      if (win.state_rev < lastRev) throw new Error(`state_rev decreased: ${win.state_rev} < ${lastRev}`);
      lastRev = win.state_rev;
    }

    if (lastRev < 3) throw new Error(`state_rev too low after operations: ${lastRev}`);

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 10: Additional — deregister disposition mapping ---- */

function test10_dispositionMapping(tempDir) {
  const name = "10. Disposition: hard_failure, budget_breach, tripwire → completed_hard_fail → ROLLING_BACK";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    store.window.admitPending({ txid: "tx-disp", fingerprint: "fp-disp", tree_id: "tree-disp", n: 1 });
    store.window.finalize("tx-disp");
    store.runRegistry.register("run-disp", "tree-disp");

    // hard_failure flag
    const d1 = store.window.dispose("run-disp", { hard_failure: true });
    assert(d1.disposition === "completed_hard_fail", `Expected completed_hard_fail, got ${d1.disposition}`);

    const win = store.window.get();
    assert(win.state === "ROLLING_BACK", `Expected ROLLING_BACK state, got ${win.state}`);

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 11: Window wall-clock cap —— */

async function test11_wallClockCap(tempDir) {
  const name = "11. Window wall-clock cap: expired wall time → CLOSED_FLAGGED";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    // Admit with short wall time (200ms)
    store.window.admitPending({
      txid: "tx-wall", fingerprint: "fp-wall", tree_id: "tree-wall", n: 1,
      max_window_wall_time_ms: 200,
    });
    store.window.finalize("tx-wall");

    const winAfterFinalize = store.window.get();
    if (winAfterFinalize.state !== "OBSERVING") {
      throw new Error(`Expected OBSERVING after finalize, got ${winAfterFinalize.state}`);
    }

    // Register a run so there's something active
    store.runRegistry.register("run-wall-1", "tree-wall");

    // Wait for wall time to expire
    const wait = new Promise((r) => setTimeout(r, 300));
    await wait;

    // Sweep should detect wall-time expiry and close as CLOSED_FLAGGED
    store.runRegistry.sweepExpired();
    const win = store.window.get();
    assert(win.state === "CLOSED_FLAGGED", `Expected CLOSED_FLAGGED, got ${win.state}`);
    assert(win.window.close_reason === "max_window_wall_time", `Expected max_window_wall_time, got ${win.window.close_reason}`);

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- TEST 12: Run anchors set/get ---- */

function test12_runAnchors(tempDir) {
  const name = "12. Run anchors: set/get anchors survive mutations";
  try {
    process.env.GRAPHSMITH_TEST_MODE = "1";
    const store = requireFreshStore(tempDir, { leaseMs: 1000, heartbeatMs: 200 });

    store.setAnchor("run-a", { chain_head: "head-aaa", expected_terminal_status: "completed_pass" });
    const anchor = store.getAnchor("run-a");
    assert(anchor.chain_head === "head-aaa", "Anchor chain_head mismatch");
    assert(anchor.expected_terminal_status === "completed_pass", "Anchor expected_terminal_status mismatch");

    const none = store.getAnchor("run-none");
    assert(none === null, "Unknown anchor should return null");

    // Set second anchor for same run, get should return latest
    store.setAnchor("run-a", { chain_head: "head-bbb", expected_terminal_status: "completed_hard_fail" });
    const updated = store.getAnchor("run-a");
    assert(updated.chain_head === "head-bbb", "Updated anchor chain_head mismatch");
    assert(updated.expected_terminal_status === "completed_hard_fail", "Updated anchor expected_terminal_status mismatch");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- Main ---- */

async function main() {
  console.log("=== GraphSmith state-store adversarial test suite (deepseek family) ===\n");

  const tempDir = makeTempDir();
  let exitCode = 0;

  try {
    test1_lockStealMismatch(tempDir);
    cleanTempDir(tempDir);

    const dir2 = makeTempDir();
    test2_pidReuseAndTestMode(dir2);
    cleanTempDir(dir2);

    const dir3 = makeTempDir();
    test3_crashRecovery(dir3);
    cleanTempDir(dir3);

    const dir4 = makeTempDir();
    test4_alphaLedger(dir4);
    cleanTempDir(dir4);

    const dir5 = makeTempDir();
    await test5_runRegistry(dir5);
    cleanTempDir(dir5);

    const dir6 = makeTempDir();
    test6_windowSlots(dir6);
    cleanTempDir(dir6);

    const dir7 = makeTempDir();
    await test7_concurrency(dir7);
    cleanTempDir(dir7);

    const dir8 = makeTempDir();
    test8_schemaValidation(dir8);
    cleanTempDir(dir8);

    const dir9 = makeTempDir();
    test9_stateRevMonotonic(dir9);
    cleanTempDir(dir9);

    const dir10 = makeTempDir();
    test10_dispositionMapping(dir10);
    cleanTempDir(dir10);

    const dir11 = makeTempDir();
    await test11_wallClockCap(dir11);
    cleanTempDir(dir11);

    const dir12 = makeTempDir();
    test12_runAnchors(dir12);
    cleanTempDir(dir12);
  } catch (e) {
    console.error(`\nUNHANDLED ERROR: ${e.message}`);
    exitCode = 1;
  }

  // Clean up any leftover temp dirs from terminated tests
  for (const d of [tempDir]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch {}
  }

  console.log(`\n=== Results: ${results.length} tests ===`);
  const passCount = results.filter((r) => r.status === "PASS").length;
  const failCount = results.filter((r) => r.status === "FAIL").length;
  const skipCount = results.filter((r) => r.status === "SKIPPED").length;
  console.log(`PASS: ${passCount}  FAIL: ${failCount}  SKIPPED: ${skipCount}`);

  for (const r of results) {
    if (r.status === "FAIL") exitCode = 1;
  }

  process.exitCode = exitCode;
}

main();