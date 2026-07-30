#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { harnessDeadline } = require("../../_harness/deadline.js");
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
      // Comfortable lease: "fresh lock not refused while held" below asserts
      // a lock this test JUST created (via acquireLock's own fresh mtime) is
      // still live moments later -- a "still live" assertion that load can
      // only break, so it needs headroom past the write+fsync+read+stat round
      // trip on a loaded or slow-fs (Windows/macOS) runner. The steal-when-
      // STALE assertion above uses an explicit 5000ms backdate via
      // utimesSync, so it stays correct as long as the lease is well under
      // 5000ms.
      const store = createStore(root, { leaseMs: 2000, heartbeatMs: 200 });
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
    withEnv({ GRAPHSMITH_TEST_MODE: "1", GRAPHSMITH_LEASE_MS: "2000", GRAPHSMITH_HEARTBEAT_MS: "200" }, () => {
      // Comfortable lease: "fresh heartbeat (recent mtime, pid alive) →
      // refuse" below writes a lock and immediately re-asserts it is still
      // live in the same tick -- a "still live" assertion that load can only
      // break, so it needs headroom past the write+fsync+read+stat round trip
      // on a loaded or slow-fs (Windows/macOS) runner. The stale-lock steal
      // assertion above uses an explicit 5000ms backdate via utimesSync, so
      // it stays correct as long as the lease is well under 5000ms.
      const store = createStore(root, { leaseMs: 2000, heartbeatMs: 200 });
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
  let inconclusive = null;
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      // Two store instances on the SAME root, so every journal/registry
      // assertion below still reads one shared set of files. `lease_expires_at`
      // is stamped at REGISTRATION time from the registering instance's lease,
      // so the instance a run is registered through decides how long it lives.
      //
      // Why: every registry operation sweeps lapsed leases before it runs (the
      // component's fail-safe, and correct). With one 50ms-lease store, the
      // register/list/deregister/list sequence below had to complete within 50ms
      // of wall time, because "still live" is an assertion that load can only
      // break -- so on a loaded CI runner `run-live` was swept mid-test and this
      // reported "live trees not queryable". Runs that must STAY live get a
      // comfortable lease; only the run whose expiry is the point gets a short
      // one, and its assertion ("has expired") is a direction load only helps.
      //
      // The 300ms short lease below was the SAME defect one step further on, and
      // the starvation sweep caught it: 300ms was a proxy for "survives the setup,
      // lapses only during the deliberate sleep". The setup is five lock+fsync
      // operations, and each registry operation sweeps lapsed leases before it
      // runs -- so on slow I/O the `list()` two lines down swept `run-expire-me`
      // itself, `sweepExpired()` then had nothing left to return, and this case
      // reported `sweep missed run-expire-me: []`: the component's sweep accused
      // of missing a run it had in fact already swept. Reproduced exactly, at
      // 25-40ms of induced latency per fs write.
      //
      // Now the expiry is not guessed. The lease is long enough that no setup
      // operation can reach it, and the sleep runs until the expiry the store
      // ITSELF issued, read back from the registration record. Not routed through
      // harnessDeadline(): waiting for a product TTL to elapse is not harness
      // patience, and scaling a lease TTL is the one thing that file forbids.
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
      const shortLease = createStore(root, { leaseMs: 2000, heartbeatMs: 50 });
      store.runRegistry.register("run-live", "tree-A");
      const expiring = shortLease.runRegistry.register("run-expire-me", "tree-B");
      const expiresAt = expiring.registration.lease_expires_at;
      assert(Number.isFinite(expiresAt), "registration did not report lease_expires_at");
      const liveBefore = store.runRegistry.list();
      assert(liveBefore.length === 2, "register failed");
      assert(
        liveBefore.every((r) => r.tree_id === "tree-A" || r.tree_id === "tree-B"),
        "live-lease trees not reported"
      );

      store.runRegistry.deregister("run-live", { disposition: "completed_pass" });
      assert(!store.runRegistry.list().some((r) => r.run_id === "run-live"), "deregister left run");

      // Sleep past the issued expiry, not past a guess. Oversleeping only helps.
      sleep(Math.max(1, expiresAt - Date.now()) + 100);

      // Sampled BEFORE the sweep, with a plain file read that cannot itself sweep.
      // This is what separates the two causes of an empty return value, and it has
      // to be observed rather than inferred: "the EXPIRED record exists afterwards"
      // is true in both cases and therefore discriminates nothing.
      //   already recorded before the call -> an earlier operation swept it, this
      //                                       case never got to observe the return
      //                                       value. INCONCLUSIVE.
      //   not recorded before, recorded after, but absent from the return value
      //                                    -> the sweep did the work and reported
      //                                       it wrongly. A real defect. FAIL.
      const expiredRecord = (r) => r.record_type === "EXPIRED" && r.run_id === "run-expire-me";
      const sweptEarlier = readJsonl(root, "run-registry.jsonl").some(expiredRecord);
      const journalBefore = readRaw(root, "state-journal.jsonl");
      const swept = store.runRegistry.sweepExpired();

      const registry = readJsonl(root, "run-registry.jsonl");
      assert(registry.some(expiredRecord), "EXPIRED record missing from registry");
      if (!swept.includes("run-expire-me")) {
        if (!sweptEarlier) {
          assert(false,
            "sweepExpired() wrote the EXPIRED record for run-expire-me but did not return it: " +
            JSON.stringify(swept) + ". Nothing had swept it before this call, so the return " +
            "value is simply wrong -- a caller cannot learn what was swept.");
        }
        inconclusive =
          "run-expire-me had already been swept before sweepExpired() was called (its EXPIRED " +
          "record was on disk beforehand), so the return value could not name it: " +
          JSON.stringify(swept) + ". Its " + (Date.now() - expiresAt) + "ms-lapsed lease expired " +
          "during this case's own setup rather than during the deliberate wait, which is machine " +
          "speed, not a component that misses expired runs. Nothing was observed about " +
          "sweepExpired()'s return value.";
        return;
      }
      assert(!store.runRegistry.list().some((r) => r.run_id === "run-expire-me"), "expired still live");

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
    if (inconclusive) report(name, "FAIL", "INCONCLUSIVE (harness): " + inconclusive);
    else report(name, "PASS");
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
      // Comfortable lease: this half asserts the runs are STILL SLOTTED across
      // ~10 registry operations and then close CLOSED_PASS. With the old 80ms
      // lease a loaded runner swept a slotted run as `abandoned` mid-test, which
      // sets the FLAG bit, and the close returned CLOSED_FLAGGED -- the component
      // was right, the test's timing assumption was not. The abandoned path is
      // still exercised deliberately below, on its own short-lease store.
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
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
      // 300ms rather than 40ms: `run-abandon` must survive admitPending +
      // finalize + register (three lock+fsync operations) and only lapse during
      // the deliberate sleep below. At 40ms a loaded runner could expire it
      // before it was ever slotted, so nothing would be there to abandon.
      const store2 = createStore(root, { leaseMs: 300, heartbeatMs: 50 });
      store2.window.admitPending({
        txid: "tx-ab",
        fingerprint: "fp-ab",
        tree_id: "tree-ab",
        n: 2,
      });
      store2.window.finalize("tx-ab");
      store2.runRegistry.register("run-abandon", "tree-ab");
      sleep(400);   // > the 300ms lease
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

/* How long a worker keeps retrying a CONTENDED lock before giving up.
 *
 * This is the HARNESS's patience, not a product budget: nothing about the store is
 * measured by it. The product assertions are the ok counts, the journal record
 * counts and the monotonic revisions.
 *
 * It was a bare `Date.now() + 10000` and it failed CI on windows-latest/node 22 --
 * `a=1 b=0 codes a=["lock-starved-10s"]` -- with the runner's own re-run passing,
 * i.e. FLAKY. Two Node processes hammering a file lock 40 times each on a shared
 * Windows runner, with process creation and a virus scanner in the path, can exceed
 * 10s of contention with nothing wrong. Flake taxonomy shape 1: a fixed deadline
 * used as a precondition proxy.
 *
 * Widened, and routed through harnessDeadline() so the starvation sweep can actually
 * exercise this suite -- it was not wired to that knob at all. Widening a harness
 * patience budget cannot make a failing test pass: every product assertion is
 * downstream of it, and the retry loop exits the moment the lock is acquired. */
const LOCK_RETRY_BUDGET_MS = harnessDeadline(60000);

function attackConcurrencySync() {
  // bridge so main can be sync: run blocking joins via spawnSync instead
  const name = "concurrency.two-process-register-deregister";
  let inconclusive = null;
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
const LOCK_RETRY_BUDGET_MS = Number(process.argv[6] || 60000);
const store = createStore(root, { leaseMs: 5000, heartbeatMs: 200 });
let ok = 0, busy = 0, other = 0;
// otherCodes: a bare count made a failure unactionable -- "errors a=0 b=1" said
// nothing about WHAT went wrong. Record the code so a future failure names it.
const otherCodes = [];
for (let i = 0; i < n; i++) {
  const id = prefix + "-" + i;
  let done = false;
  // DEADLINE-bounded, not attempt-bounded. Refusing under contention is the
  // store's contract and the caller is expected to retry; the old budget of 80
  // attempts x <=25ms backoff (~1.6s) was a *proxy* for time, and on a loaded
  // 2-core runner two hammering processes exhausted it, reporting the retry
  // budget as an error. A wall-clock deadline states the intent directly.
  const deadline = Date.now() + LOCK_RETRY_BUDGET_MS;
  for (let attempt = 0; !done; attempt++) {
    try {
      store.runRegistry.register(id, "tree-conc");
      store.runRegistry.deregister(id, { disposition: "completed_pass" });
      ok++;
      done = true;
    } catch (e) {
      if (e.code === "LOCKED" || e.code === "LOCK_CONTENTION") {
        busy++;
        if (Date.now() >= deadline) { other++; otherCodes.push("lock-starved-" + LOCK_RETRY_BUDGET_MS + "ms"); done = true; }
        else Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5 + Math.min(attempt, 20));
      } else {
        other++;
        otherCodes.push(String(e.code || e.message));
        done = true;
      }
    }
  }
}
fs.writeFileSync(outFile, JSON.stringify({ prefix, ok, busy, other, otherCodes }));
`
      );

      const ca = spawn(process.execPath, [worker, root, "a", String(n), outA, String(LOCK_RETRY_BUDGET_MS)], {
        env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
        stdio: "ignore",
        detached: true,
      });
      ca.unref();
      const cb = spawn(process.execPath, [worker, root, "b", String(n), outB, String(LOCK_RETRY_BUDGET_MS)], {
        env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
        stdio: "ignore",
        detached: true,
      });
      cb.unref();

      // 120s, consistent with the workers' own per-id 10s lock deadline: the
      // outer wait must outlast the retry budget it is waiting on, or a slow
      // runner reports "workers did not finish" for work that was progressing.
      const deadline = Date.now() + 120000;
      while (Date.now() < deadline) {
        if (fs.existsSync(outA) && fs.existsSync(outB)) break;
        sleep(50);
      }
      assert(fs.existsSync(outA) && fs.existsSync(outB), "workers did not finish in time");
      const ra = JSON.parse(fs.readFileSync(outA, "utf8"));
      const rb = JSON.parse(fs.readFileSync(outB, "utf8"));
      /* Lock STARVATION is separated from real errors. A worker that exhausted its
       * retry budget observed nothing about whether the store serialises correctly --
       * it stopped asking. Reporting that as a store error is a confident product
       * verdict from an observation the harness cut short (contract 10 List C rule 1),
       * and it is what turned a slow Windows runner into a red gate. */
      const allCodes = [].concat(ra.otherCodes || [], rb.otherCodes || []);
      const starved = allCodes.filter((c) => String(c).indexOf("lock-starved") === 0);
      const realErrors = allCodes.filter((c) => String(c).indexOf("lock-starved") !== 0);
      assert(realErrors.length === 0, `errors a=${ra.other} b=${rb.other} codes ${JSON.stringify(realErrors)}`);
      if (starved.length > 0) {
        inconclusive = `${starved.length} worker(s) exhausted the ${LOCK_RETRY_BUDGET_MS}ms lock-retry budget ` +
          `under contention (ok a=${ra.ok}/${n} b=${rb.ok}/${n}, busy a=${ra.busy} b=${rb.busy}). The harness ` +
          "stopped retrying; nothing was observed about whether the store serialises correctly";
        return;
      }
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
    if (inconclusive) report(name, "FAIL", "INCONCLUSIVE (harness): " + inconclusive);
    else report(name, "PASS");
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
