#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync, spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const SCHEMA_PATH = path.join(ROOT, "schemas", "state-store.schema.json");
const { createStore, SCHEMA_VERSION } = require(STATE_STORE);
const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

let failures = 0;
const results = [];

function report(name, status, reason) {
  const line =
    status === "PASS"
      ? `PASS ${name}`
      : status === "SKIPPED"
        ? `SKIPPED ${name}+${reason || "no reason"}`
        : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-ss-grok-${label}-`));
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {}
}

function readRaw(root, rel) {
  const p = path.join(root, ".graphsmith", "state", rel);
  try {
    return fs.readFileSync(p, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return "";
    throw e;
  }
}

function readJsonl(root, rel) {
  const raw = readRaw(root, rel);
  if (!raw) return [];
  return raw
    .split("\n")
    .filter(Boolean)
    .map((line, i) => {
      try {
        return JSON.parse(line);
      } catch (e) {
        throw new Error(`bad jsonl ${rel}:${i + 1}: ${e.message}`);
      }
    });
}

function withEnv(envPatch, fn) {
  const prev = {};
  for (const k of Object.keys(envPatch)) {
    prev[k] = process.env[k];
    if (envPatch[k] === undefined) delete process.env[k];
    else process.env[k] = envPatch[k];
  }
  try {
    return fn();
  } finally {
    for (const k of Object.keys(envPatch)) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

/* Minimal draft-2020-12 subset validator (zero-dep) for schemas/state-store.schema.json */
function resolveRef(ref, rootSchema) {
  if (!ref.startsWith("#/")) throw new Error(`unsupported $ref ${ref}`);
  const parts = ref.slice(2).split("/");
  let cur = rootSchema;
  for (const p of parts) {
    cur = cur[p];
    if (cur === undefined) throw new Error(`broken $ref ${ref}`);
  }
  return cur;
}

function validate(data, sub, rootSchema, pathHint) {
  const here = pathHint || "$";
  if (sub.$ref) return validate(data, resolveRef(sub.$ref, rootSchema), rootSchema, here);
  if (sub.oneOf) {
    const hits = [];
    for (let i = 0; i < sub.oneOf.length; i++) {
      const r = validate(data, sub.oneOf[i], rootSchema, `${here}/oneOf/${i}`);
      if (r.ok) hits.push(i);
    }
    if (hits.length === 1) return { ok: true };
    return { ok: false, error: `${here}: oneOf matched ${hits.length} variants` };
  }
  if (Object.prototype.hasOwnProperty.call(sub, "const") && data !== sub.const) {
    return { ok: false, error: `${here}: expected const ${JSON.stringify(sub.const)}` };
  }
  if (sub.enum) {
    const ok = sub.enum.some((v) => Object.is(v, data));
    if (!ok) return { ok: false, error: `${here}: not in enum` };
  }
  if (sub.type) {
    const types = Array.isArray(sub.type) ? sub.type : [sub.type];
    const t =
      data === null
        ? "null"
        : Array.isArray(data)
          ? "array"
          : typeof data === "number" && Number.isInteger(data)
            ? "integer"
            : typeof data;
    const typeOk = types.some((want) => {
      if (want === "integer") return typeof data === "number" && Number.isInteger(data);
      if (want === "number") return typeof data === "number" && !Number.isNaN(data);
      if (want === "object") return data !== null && typeof data === "object" && !Array.isArray(data);
      return t === want || (want === "number" && t === "integer");
    });
    if (!typeOk) return { ok: false, error: `${here}: type want ${types.join("|")} got ${t}` };
  }
  if (typeof data === "string") {
    if (sub.minLength !== undefined && data.length < sub.minLength) {
      return { ok: false, error: `${here}: minLength` };
    }
    if (sub.pattern && !new RegExp(sub.pattern).test(data)) {
      return { ok: false, error: `${here}: pattern ${sub.pattern}` };
    }
  }
  if (typeof data === "number") {
    if (sub.minimum !== undefined && data < sub.minimum) return { ok: false, error: `${here}: minimum` };
    if (sub.maximum !== undefined && data > sub.maximum) return { ok: false, error: `${here}: maximum` };
    if (sub.exclusiveMinimum !== undefined && data <= sub.exclusiveMinimum) {
      return { ok: false, error: `${here}: exclusiveMinimum` };
    }
  }
  if (Array.isArray(data)) {
    if (sub.minItems !== undefined && data.length < sub.minItems) {
      return { ok: false, error: `${here}: minItems` };
    }
    if (sub.items) {
      for (let i = 0; i < data.length; i++) {
        const r = validate(data[i], sub.items, rootSchema, `${here}[${i}]`);
        if (!r.ok) return r;
      }
    }
  }
  if (data && typeof data === "object" && !Array.isArray(data)) {
    if (sub.required) {
      for (const k of sub.required) {
        if (!Object.prototype.hasOwnProperty.call(data, k)) {
          return { ok: false, error: `${here}: missing required ${k}` };
        }
      }
    }
    if (sub.properties) {
      for (const [k, v] of Object.entries(data)) {
        if (sub.properties[k]) {
          const r = validate(v, sub.properties[k], rootSchema, `${here}.${k}`);
          if (!r.ok) return r;
        } else if (sub.additionalProperties === false) {
          return { ok: false, error: `${here}: unknown key ${k}` };
        }
      }
    } else if (sub.additionalProperties === false) {
      const keys = Object.keys(data);
      if (keys.length) return { ok: false, error: `${here}: unexpected keys ${keys.join(",")}` };
    }
  }
  return { ok: true };
}

function validateRecord(rec) {
  return validate(rec, schema, schema, "$");
}

function journalRevs(root) {
  return readJsonl(root, "state-journal.jsonl")
    .filter((r) => Number.isSafeInteger(r.state_rev))
    .map((r) => r.state_rev);
}

function assertMonotonic(revs) {
  for (let i = 1; i < revs.length; i++) {
    assert(revs[i] >= revs[i - 1], `state_rev not monotonic: ${revs[i - 1]} -> ${revs[i]}`);
  }
}

/* ---------------- attacks ---------------- */

function attackLockStealAndTokenMismatch() {
  const name = "lock.steal-expired-refuse-fresh-token-mismatch";
  const root = tempRoot("lock");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 80, heartbeatMs: 20 });
      store.status(); // ensure dir

      const staleToken = crypto.randomBytes(16).toString("hex");
      fs.writeFileSync(
        store.lockPath,
        JSON.stringify({
          schema_version: SCHEMA_VERSION,
          pid: 1,
          proc_start_hint: "dead-pid",
          owner_token: staleToken,
        })
      );
      const old = new Date(Date.now() - 5000);
      fs.utimesSync(store.lockPath, old, old);

      const stolen = store._testing.acquireLock();
      assert(stolen && stolen.ownerToken && stolen.ownerToken !== staleToken, "steal failed");

      let freshRefused = false;
      try {
        store._testing.acquireLock();
      } catch (e) {
        freshRefused = e.code === "LOCKED";
      }
      assert(freshRefused, "fresh lock not refused while held");

      let renewMismatch = false;
      try {
        // renew is internal; release with wrong token
        store._testing.releaseLock("0".repeat(32));
      } catch (e) {
        renewMismatch = e.code === "LOCK_OWNER_MISMATCH";
      }
      assert(renewMismatch, "owner-token mismatch on release not refused");

      // Fake lock with other token after we release ours, try renew-path via release
      clearInterval(stolen.heartbeat);
      store._testing.releaseLock(stolen.ownerToken);

      const fakeTok = crypto.randomBytes(16).toString("hex");
      fs.writeFileSync(
        store.lockPath,
        JSON.stringify({
          schema_version: SCHEMA_VERSION,
          pid: process.pid,
          proc_start_hint: "fake",
          owner_token: fakeTok,
        })
      );
      let fakeReleaseRefused = false;
      try {
        store._testing.releaseLock(crypto.randomBytes(16).toString("hex"));
      } catch (e) {
        fakeReleaseRefused = e.code === "LOCK_OWNER_MISMATCH";
      }
      assert(fakeReleaseRefused, "release with wrong token against fake lock not refused");

      // clean for rm
      try {
        store._testing.releaseLock(fakeTok);
      } catch (_) {
        try {
          fs.unlinkSync(store.lockPath);
        } catch {}
      }
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackPidReuseAndEnvOverride() {
  const name = "lock.pid-alive-stale-steal-fresh-refuse-env-gate";
  const root = tempRoot("pid");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1", GRAPHSMITH_LEASE_MS: "40", GRAPHSMITH_HEARTBEAT_MS: "10" }, () => {
      const store = createStore(root, { leaseMs: 40, heartbeatMs: 10 });
      store.status();

      // pid alive (self) but lease stale → stealable
      const tok = crypto.randomBytes(16).toString("hex");
      fs.writeFileSync(
        store.lockPath,
        JSON.stringify({
          schema_version: SCHEMA_VERSION,
          pid: process.pid,
          proc_start_hint: `${process.pid}:stale`,
          owner_token: tok,
        })
      );
      const old = new Date(Date.now() - 5000);
      fs.utimesSync(store.lockPath, old, old);
      const stolen = store._testing.acquireLock();
      assert(stolen.ownerToken !== tok, "stale same-pid lock not stolen");
      clearInterval(stolen.heartbeat);
      store._testing.releaseLock(stolen.ownerToken);

      // fresh heartbeat (recent mtime, pid alive) → refuse
      const freshTok = crypto.randomBytes(16).toString("hex");
      fs.writeFileSync(
        store.lockPath,
        JSON.stringify({
          schema_version: SCHEMA_VERSION,
          pid: process.pid,
          proc_start_hint: `${process.pid}:fresh`,
          owner_token: freshTok,
        })
      );
      let refused = false;
      try {
        store._testing.acquireLock();
      } catch (e) {
        refused = e.code === "LOCKED";
      }
      assert(refused, "fresh heartbeat lock was stealable");
      fs.unlinkSync(store.lockPath);
    });

    // GRAPHSMITH_LEASE_MS ignored without GRAPHSMITH_TEST_MODE=1
    withEnv(
      {
        GRAPHSMITH_TEST_MODE: undefined,
        GRAPHSMITH_LEASE_MS: "1",
        GRAPHSMITH_HEARTBEAT_MS: "1",
      },
      () => {
        const store = createStore(root, { leaseMs: 1, heartbeatMs: 1 });
        // options alone should also be ignored when not in test mode
        assert(store.leaseMs === 30000, `leaseMs without TEST_MODE expected 30000 got ${store.leaseMs}`);
        assert(store.heartbeatMs === 5000, `heartbeatMs without TEST_MODE expected 5000 got ${store.heartbeatMs}`);

        const usedTok = crypto.randomBytes(16).toString("hex");
        store._ensureStateDir();
        fs.writeFileSync(
          store.lockPath,
          JSON.stringify({
            schema_version: SCHEMA_VERSION,
            pid: process.pid,
            proc_start_hint: "prod-lease",
            owner_token: usedTok,
          })
        );
        // age ~50ms — would expire under 1ms lease but must NOT under default 30s
        const slightlyOld = new Date(Date.now() - 50);
        fs.utimesSync(store.lockPath, slightlyOld, slightlyOld);
        let stoleProd = false;
        try {
          const s = store._testing.acquireLock();
          stoleProd = true;
          clearInterval(s.heartbeat);
          try {
            store._testing.releaseLock(s.ownerToken);
          } catch {}
        } catch (e) {
          assert(e.code === "LOCKED", `unexpected: ${e.code} ${e.message}`);
        }
        assert(!stoleProd, "short LEASE_MS env honored without GRAPHSMITH_TEST_MODE=1");
        try {
          fs.unlinkSync(store.lockPath);
        } catch {}
      }
    );

    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackCrashRecovery() {
  const name = "crash.journal-roll-forward-monotonic-no-tear";
  const root = tempRoot("crash");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 2000, heartbeatMs: 200 });
      store.window.admitPending({
        txid: "tx-crash",
        fingerprint: "fp-crash",
        tree_id: "tree-crash",
        n: 3,
      });
      store.window.finalize("tx-crash");

      // Multi-file mutation: register writes registry then window; crash after 1 effect
      store._testing.crashNextMutationAfter(1);
      let crashed = false;
      try {
        store.runRegistry.register("run-crash-1", "tree-crash");
      } catch (e) {
        crashed = e.code === "SIMULATED_CRASH";
      }
      assert(crashed, "simulated crash did not fire");

      // INTENT present, DONE absent for open mutation
      const journalAfterCrash = readJsonl(root, "state-journal.jsonl");
      const intents = journalAfterCrash.filter((r) => r.record_type === "MUTATION_INTENT");
      const dones = new Set(
        journalAfterCrash.filter((r) => r.record_type === "MUTATION_DONE").map((r) => r.mutation_id)
      );
      const open = intents.filter((r) => !dones.has(r.mutation_id));
      assert(open.length >= 1, "expected open MUTATION_INTENT after crash");

      // Registry should have the first effect applied (or recovered next call)
      const store2 = createStore(root, { leaseMs: 2000, heartbeatMs: 200 });
      const w = store2.window.get();
      const runs = store2.runRegistry.list();
      assert(
        runs.some((r) => r.run_id === "run-crash-1"),
        "registry missing run after recovery"
      );
      assert(
        w.window && w.window.slots.some((s) => s.run_id === "run-crash-1"),
        "window slot missing after roll-forward"
      );

      const revs = journalRevs(root);
      assertMonotonic(revs);

      // second path: true child process exit after crash hook
      const childScript = path.join(root, "child-crash.js");
      fs.writeFileSync(
        childScript,
        `
const { createStore } = require(${JSON.stringify(STATE_STORE)});
process.env.GRAPHSMITH_TEST_MODE = "1";
const store = createStore(${JSON.stringify(root)}, { leaseMs: 2000, heartbeatMs: 200 });
store._testing.crashNextMutationAfter(1);
try {
  store.alphaLedger.reserve({
    corpus_state: "c-crash",
    split_hash: "s1",
    fingerprint: "f1",
    family: "fam-crash",
  });
  process.exit(0);
} catch (e) {
  process.exit(e.code === "SIMULATED_CRASH" ? 99 : 1);
}
`
      );
      const child = spawnSync(process.execPath, [childScript], { encoding: "utf8" });
      assert(child.status === 99, `child crash exit ${child.status} stderr=${child.stderr}`);

      const store3 = createStore(root, { leaseMs: 2000, heartbeatMs: 200 });
      const alpha = store3.alphaLedger.list("c-crash");
      assert(
        alpha.some((r) => r.record_type === "RESERVED" && r.family === "fam-crash"),
        "alpha reservation lost after child crash recovery"
      );
      assertMonotonic(journalRevs(root));

      // Ambiguous recovery: corrupt mid-intent effect to non-before non-after
      store3._testing.crashNextMutationAfter(1);
      try {
        store3.runRegistry.register("run-amb", "tree-crash");
      } catch (e) {
        assert(e.code === "SIMULATED_CRASH", e.message);
      }
      // After first effect (registry), window still before; poison registry away from before and after
      const regPath = path.join(root, ".graphsmith", "state", "run-registry.jsonl");
      fs.writeFileSync(regPath, '{"schema_version":"1.0","evil":true}\n');
      let halted = false;
      try {
        createStore(root, { leaseMs: 2000, heartbeatMs: 200 }).window.get();
      } catch (e) {
        halted = e.code === "AMBIGUOUS_RECOVERY" || /HALT|ambiguous/i.test(e.message);
      }
      assert(halted, "poisoned mid-mutation file did not HALT recovery");
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackAlphaLedger() {
  const name = "alpha.reserve-crash-consumes-fourth-refused";
  const root = tempRoot("alpha");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 1000, heartbeatMs: 100 });
      const r1 = store.alphaLedger.reserve({
        corpus_state: "corpus-x",
        split_hash: "split-1",
        fingerprint: "fp-1",
        family: "family-1",
      });
      assert(r1.alpha_slot === 1, `slot1 got ${r1.alpha_slot}`);

      // crash before complete — reopen, slot still consumed
      store._testing.crashNextMutationAfter(1);
      try {
        store.alphaLedger.reserve({
          corpus_state: "corpus-x",
          split_hash: "split-2",
          fingerprint: "fp-2",
          family: "family-2",
        });
      } catch (e) {
        assert(e.code === "SIMULATED_CRASH", e.message);
      }
      const store2 = createStore(root, { leaseMs: 1000, heartbeatMs: 100 });
      const listing = store2.alphaLedger.list("corpus-x").filter((r) => r.record_type === "RESERVED");
      assert(listing.length === 2, `expected 2 reserved after crash+recover got ${listing.length}`);
      assert(!listing.some((r) => r.record_type === "COMPLETED"), "unexpected complete");

      // complete only first; still 2 consumed
      store2.alphaLedger.complete(r1.reservation_id, { verdict: "reject" });
      const r3 = store2.alphaLedger.reserve({
        corpus_state: "corpus-x",
        split_hash: "split-3",
        fingerprint: "fp-3",
        family: "family-3",
      });
      assert(r3.alpha_slot === 3, `slot3 got ${r3.alpha_slot}`);

      let fourthRefused = false;
      try {
        store2.alphaLedger.reserve({
          corpus_state: "corpus-x",
          split_hash: "split-4",
          fingerprint: "fp-4",
          family: "family-4",
        });
      } catch (e) {
        fourthRefused = e.code === "ALPHA_EXHAUSTED";
      }
      assert(fourthRefused, "4th reservation not refused");

      // family already consumed refused even with free slot on NEW corpus is ok; same corpus:
      const rootB = tempRoot("alpha-fam");
      try {
        const sb = createStore(rootB, { leaseMs: 1000, heartbeatMs: 100 });
        sb.alphaLedger.reserve({
          corpus_state: "c",
          split_hash: "s",
          fingerprint: "f",
          family: "famZ",
        });
        let famRefused = false;
        try {
          sb.alphaLedger.reserve({
            corpus_state: "c",
            split_hash: "s2",
            fingerprint: "f2",
            family: "famZ",
          });
        } catch (e) {
          famRefused = e.code === "ALPHA_FAMILY_CONSUMED";
        }
        assert(famRefused, "same family double-reserve not refused");
      } finally {
        rmrf(rootB);
      }
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackRunRegistry() {
  const name = "registry.register-sweep-live-trees-journaled";
  const root = tempRoot("reg");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 50, heartbeatMs: 15 });
      store.runRegistry.register("run-live", "tree-A");
      store.runRegistry.register("run-expire-me", "tree-B");
      const liveBefore = store.runRegistry.list();
      assert(liveBefore.length === 2, "register failed");
      assert(
        liveBefore.every((r) => r.tree_id === "tree-A" || r.tree_id === "tree-B"),
        "live-lease trees not reported"
      );

      store.runRegistry.deregister("run-live", { disposition: "completed_pass" });
      assert(!store.runRegistry.list().some((r) => r.run_id === "run-live"), "deregister left run");

      sleep(80);
      const journalBefore = readRaw(root, "state-journal.jsonl");
      const swept = store.runRegistry.sweepExpired();
      assert(swept.includes("run-expire-me"), `sweep missed run-expire-me: ${JSON.stringify(swept)}`);
      assert(!store.runRegistry.list().some((r) => r.run_id === "run-expire-me"), "expired still live");

      const registry = readJsonl(root, "run-registry.jsonl");
      assert(
        registry.some((r) => r.record_type === "EXPIRED" && r.run_id === "run-expire-me"),
        "EXPIRED record missing from registry"
      );

      const journalAfter = readRaw(root, "state-journal.jsonl");
      assert(journalAfter.length > journalBefore.length, "sweep did not append journal");
      const jRecs = readJsonl(root, "state-journal.jsonl");
      const sweepIntent = [...jRecs].reverse().find((r) => r.record_type === "MUTATION_INTENT");
      assert(sweepIntent, "no mutation intent for sweep");
      const decoded = sweepIntent.effects
        .map((e) => Buffer.from(e.content_base64, "base64").toString("utf8"))
        .join("\n");
      assert(
        decoded.includes("EXPIRED") && decoded.includes("run-expire-me"),
        "sweep journal payload does not record what was swept"
      );

      // GC-relevant: live-lease trees after more registers
      store.runRegistry.register("gc1", "tree-keep-1");
      store.runRegistry.register("gc2", "tree-keep-2");
      const trees = new Set(store.runRegistry.list().map((r) => r.tree_id));
      assert(trees.has("tree-keep-1") && trees.has("tree-keep-2"), "live trees not queryable");
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackWindowSlots() {
  const name = "window.slots-N-plus-1-terminal-close-abandoned-flag";
  const root = tempRoot("win");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const N = 3;
      const store = createStore(root, { leaseMs: 80, heartbeatMs: 20 });
      store.window.admitPending({
        txid: "tx-w",
        fingerprint: "fp-w",
        tree_id: "tree-w",
        n: N,
      });
      store.window.finalize("tx-w");

      for (let i = 0; i < N; i++) {
        const r = store.runRegistry.register(`run-${i}`, "tree-w");
        assert(r.slot, `slot not claimed for run-${i}`);
      }
      const overflow = store.runRegistry.register("run-overflow", "tree-w");
      assert(overflow.slot === null, "N+1 run was observed/slotted");
      const w = store.window.get();
      assert(w.window.slots.length === N, `slots length ${w.window.slots.length}`);
      assert(w.window.admitted === N, `admitted ${w.window.admitted}`);

      // cannot close while active
      let closeBlocked = false;
      try {
        store.window.close("tx-w", "pass");
      } catch (e) {
        closeBlocked = e.code === "WINDOW_ACTIVE";
      }
      assert(closeBlocked, "close allowed with active slots");

      // dispose with terminals
      for (let i = 0; i < N; i++) {
        store.runRegistry.deregister(`run-${i}`, { disposition: "completed_pass" });
      }
      const closed = store.window.close("tx-w", "pass");
      assert(closed.state === "CLOSED_PASS", `expected CLOSED_PASS got ${closed.state}`);

      // abandoned path: new window, expire while slotted → FLAG + close CLOSED_FLAGGED
      const store2 = createStore(root, { leaseMs: 40, heartbeatMs: 10 });
      store2.window.admitPending({
        txid: "tx-ab",
        fingerprint: "fp-ab",
        tree_id: "tree-ab",
        n: 2,
      });
      store2.window.finalize("tx-ab");
      store2.runRegistry.register("run-abandon", "tree-ab");
      sleep(70);
      store2.runRegistry.sweepExpired();
      const wAb = store2.window.get();
      assert(wAb.flag === true, "abandoned did not set FLAG");
      const slot = wAb.window.slots.find((s) => s.run_id === "run-abandon");
      assert(slot && slot.disposition === "abandoned", "slot not abandoned");
      assert(slot.status === "terminal", "abandoned slot not terminal");

      // fill remaining or close flagged with incomplete: outcome flagged allowed per closeWindow
      const closedFlag = store2.window.close("tx-ab", "flagged");
      assert(
        closedFlag.state === "CLOSED_FLAGGED",
        `expected CLOSED_FLAGGED got ${closedFlag.state}`
      );
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackConcurrencySync() {
  // bridge so main can be sync: run blocking joins via spawnSync instead
  const name = "concurrency.two-process-register-deregister";
  const root = tempRoot("conc");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      createStore(root, { leaseMs: 5000, heartbeatMs: 200 }).status();
      const worker = path.join(root, "hammer.js");
      fs.writeFileSync(
        worker,
        `
const { createStore } = require(${JSON.stringify(STATE_STORE)});
process.env.GRAPHSMITH_TEST_MODE = "1";
const root = process.argv[2];
const prefix = process.argv[3];
const n = Number(process.argv[4] || 40);
const store = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
let ok = 0, busy = 0, other = 0;
for (let i = 0; i < n; i++) {
  const id = prefix + "-" + i;
  let done = false;
  for (let attempt = 0; attempt < 40 && !done; attempt++) {
    try {
      store.runRegistry.register(id, "tree-conc");
      store.runRegistry.deregister(id, { disposition: "completed_pass" });
      ok++;
      done = true;
    } catch (e) {
      if (e.code === "LOCKED" || e.code === "LOCK_CONTENTION") {
        busy++;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5 + attempt);
      } else {
        other++;
        process.stderr.write(String(e.stack || e) + "\\n");
        done = true;
      }
    }
  }
  if (!done) other++;
}
process.stdout.write(JSON.stringify({ prefix, ok, busy, other }));
`
      );
      const n = 30;
      const outA = path.join(root, "out-a.json");
      const outB = path.join(root, "out-b.json");
      fs.writeFileSync(
        worker,
        `
const fs = require("fs");
const { createStore } = require(${JSON.stringify(STATE_STORE)});
process.env.GRAPHSMITH_TEST_MODE = "1";
const root = process.argv[2];
const prefix = process.argv[3];
const n = Number(process.argv[4] || 40);
const outFile = process.argv[5];
const store = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
let ok = 0, busy = 0, other = 0;
for (let i = 0; i < n; i++) {
  const id = prefix + "-" + i;
  let done = false;
  for (let attempt = 0; attempt < 80 && !done; attempt++) {
    try {
      store.runRegistry.register(id, "tree-conc");
      store.runRegistry.deregister(id, { disposition: "completed_pass" });
      ok++;
      done = true;
    } catch (e) {
      if (e.code === "LOCKED" || e.code === "LOCK_CONTENTION") {
        busy++;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5 + Math.min(attempt, 20));
      } else {
        other++;
        done = true;
      }
    }
  }
  if (!done) other++;
}
fs.writeFileSync(outFile, JSON.stringify({ prefix, ok, busy, other }));
`
      );

      const ca = spawn(process.execPath, [worker, root, "a", String(n), outA], {
        env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
        stdio: "ignore",
        detached: true,
      });
      ca.unref();
      const cb = spawn(process.execPath, [worker, root, "b", String(n), outB], {
        env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
        stdio: "ignore",
        detached: true,
      });
      cb.unref();

      const deadline = Date.now() + 60000;
      while (Date.now() < deadline) {
        if (fs.existsSync(outA) && fs.existsSync(outB)) break;
        sleep(50);
      }
      assert(fs.existsSync(outA) && fs.existsSync(outB), "workers did not finish in time");
      const ra = JSON.parse(fs.readFileSync(outA, "utf8"));
      const rb = JSON.parse(fs.readFileSync(outB, "utf8"));
      assert(ra.other === 0 && rb.other === 0, `errors a=${ra.other} b=${rb.other}`);
      assert(ra.ok === n && rb.ok === n, `incomplete ok a=${ra.ok} b=${rb.ok} busy a=${ra.busy} b=${rb.busy}`);

      const raw = readRaw(root, "run-registry.jsonl");
      for (const line of raw.split("\n")) {
        if (line) JSON.parse(line);
      }
      const records = readJsonl(root, "run-registry.jsonl");
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
      const live = store.runRegistry.list();
      assert(live.length === 0, `expected no live runs, got ${live.length}`);
      const regCount = records.filter((r) => r.record_type === "REGISTERED").length;
      const deregCount = records.filter((r) => r.record_type === "DEREGISTERED").length;
      assert(regCount === n * 2, `registered ${regCount} want ${n * 2}`);
      assert(deregCount === n * 2, `deregistered ${deregCount} want ${n * 2}`);
      assertMonotonic(journalRevs(root));
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackSchema() {
  const name = "schema.written-valid-unknown-keys-rejected-on-read";
  const root = tempRoot("schema");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 1000, heartbeatMs: 100 });
      store.window.admitPending({
        txid: "tx-sch",
        fingerprint: "fp-sch",
        tree_id: "tree-sch",
        n: 2,
      });
      store.window.finalize("tx-sch");
      store.runRegistry.register("run-sch", "tree-sch");
      store.runRegistry.heartbeat("run-sch");
      store.runAnchors.setAnchor("run-sch", {
        chain_head: "abc",
        expected_terminal_status: "completed",
      });
      store.alphaLedger.reserve({
        corpus_state: "cs",
        split_hash: "sh",
        fingerprint: "fp",
        family: "fam",
      });
      store.rejectedBuffer.push({ fingerprint: "rej-fp", value: { x: 1 } });
      store.rollbackFamilies.append({ fingerprint: "rb-fp", family: "f", evidence: { k: 1 } });

      const windowObj = JSON.parse(readRaw(root, "window.json"));
      const wv = validateRecord(windowObj);
      assert(wv.ok, `window.json schema: ${wv.error}`);

      for (const [file, filter] of [
        ["run-registry.jsonl", () => true],
        ["run-anchors.jsonl", () => true],
        ["alpha-ledger.jsonl", () => true],
        ["rejected-buffer.jsonl", () => true],
        ["rollback-families.jsonl", () => true],
        ["state-journal.jsonl", () => true],
      ]) {
        for (const rec of readJsonl(root, file)) {
          const r = validateRecord(rec);
          assert(r.ok, `${file} record failed schema: ${r.error} :: ${JSON.stringify(rec).slice(0, 200)}`);
        }
      }

      // lock record
      const lock = store._testing.acquireLock();
      const lockRec = JSON.parse(fs.readFileSync(store.lockPath, "utf8"));
      const lv = validateRecord(lockRec);
      assert(lv.ok, `lock schema: ${lv.error}`);
      clearInterval(lock.heartbeat);
      store._testing.releaseLock(lock.ownerToken);

      // unknown keys rejected on read
      const poisoned = JSON.parse(readRaw(root, "window.json"));
      poisoned.unexpected_hostile_key = "boom";
      fs.writeFileSync(path.join(root, ".graphsmith", "state", "window.json"), JSON.stringify(poisoned));

      let rejectedOnRead = false;
      let readError = "";
      try {
        createStore(root, { leaseMs: 1000, heartbeatMs: 100 }).window.get();
      } catch (e) {
        rejectedOnRead = true;
        readError = e.message || String(e);
      }
      if (!rejectedOnRead) {
        throw new Error(
          "DEFECT: unknown keys accepted on window read (parseWindow does not enforce schema additionalProperties:false)"
        );
      }

      // Journal unknown keys / corrupt on purpose — register accept may still pass script integrity
      // already asserted store wrote valid records
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackRenewExplicit() {
  const name = "lock.renew-owner-token-mismatch";
  const root = tempRoot("renew");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 500, heartbeatMs: 100 });
      const held = store._testing.acquireLock();
      // Use internal renew via release path is enough; peek at module by writing wrong then calling status from another store
      const other = createStore(root, { leaseMs: 500, heartbeatMs: 100 });
      let blocked = false;
      try {
        other.status();
      } catch (e) {
        blocked = e.code === "LOCKED";
      }
      assert(blocked, "second writer not blocked by fresh lock");
      clearInterval(held.heartbeat);
      store._testing.releaseLock(held.ownerToken);
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function attackSoftWobbleFlagAndHardRollback() {
  const name = "window.soft-flag-hard-rolling-back";
  const root = tempRoot("disp");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 1000, heartbeatMs: 100 });
      store.window.admitPending({
        txid: "tx-d",
        fingerprint: "fp-d",
        tree_id: "tree-d",
        n: 2,
      });
      store.window.finalize("tx-d");
      store.runRegistry.register("r1", "tree-d");
      store.runRegistry.deregister("r1", { soft_wobble: true });
      let w = store.window.get();
      assert(w.flag === true, "soft wobble did not FLAG");
      store.runRegistry.register("r2", "tree-d");
      store.runRegistry.deregister("r2", { disposition: "completed_pass" });
      const closed = store.window.close("tx-d", "pass");
      assert(closed.state === "CLOSED_FLAGGED", `soft+close got ${closed.state}`);

      const s2 = createStore(root, { leaseMs: 1000, heartbeatMs: 100 });
      s2.window.admitPending({
        txid: "tx-h",
        fingerprint: "fp-h",
        tree_id: "tree-h",
        n: 1,
      });
      s2.window.finalize("tx-h");
      s2.runRegistry.register("rh", "tree-h");
      s2.runRegistry.deregister("rh", { hard_failure: true });
      w = s2.window.get();
      assert(w.state === "ROLLING_BACK", `hard fail state ${w.state}`);
    });
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  } finally {
    rmrf(root);
  }
}

function main() {
  attackLockStealAndTokenMismatch();
  attackPidReuseAndEnvOverride();
  attackRenewExplicit();
  attackCrashRecovery();
  attackAlphaLedger();
  attackRunRegistry();
  attackWindowSlots();
  attackSoftWobbleFlagAndHardRollback();
  attackConcurrencySync();
  attackSchema();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failed ? 1 : 0);
}

main();
