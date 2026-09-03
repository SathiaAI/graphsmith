#!/usr/bin/env node
"use strict";
/*
 * promote.js coverage-gap triage suite.
 *
 * Origin: round-7 systematic triage of promote.js's 884 non-selftest survived
 * mutants, using the same method as gate.js's round-6 triage (see
 * claude/graphsmith-mutation-gate-remediation-verify-2026-08-10.md for the
 * full method and this round's findings). Each test below closes ONE
 * confirmed real coverage gap -- a distinct branch, error code, or op that
 * tests/promote/{grok,deepseek,lock-scope} never exercised at all. This file
 * does not duplicate anything those suites already cover.
 *
 * A handful of gaps the triage identified are NOT attempted here and are
 * left for the record instead of faked:
 *   - installStaged's EXDEV cross-device-rename branch (line ~448-457):
 *     requires two real filesystem volumes; cannot be constructed portably.
 *   - admitWindow's own WINDOW_EXISTS re-check (line ~548-550): reachable
 *     only if window.json's state changes between refuseEarly's lock-held
 *     read and this _commit's own fresh read, which cannot happen while
 *     this process holds the sole state-store lock for the whole promotion.
 *     Likely defensive/equivalent code, same class as gate.js round 6's and
 *     state-store.js's own duplicate-check findings.
 *   - the `selftest` function's own internals (~133 survivors): test
 *     infrastructure, not product logic; deprioritized per the same
 *     reasoning applied to gate.js's and verify.js's selftest clusters.
 * See the project doc for the full gap inventory this round covered.
 *
 * Zero-dep CJS. EXIT 1 if any FAIL.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "../../..");
const PROMOTE_PATH = path.join(ROOT, "scripts", "promote.js");
const promoteModule = require(PROMOTE_PATH);
const { promote, rollback, recover, SCHEMA_VERSION } = promoteModule;
const { createFixture, testPacket } = promoteModule.__testing;

process.env.GRAPHSMITH_TEST_MODE = "1";

let failures = 0;
const results = [];

function report(name, status, reason) {
  const line = status === "PASS" ? `PASS\t${name}\t${reason || ""}` : `FAIL\t${name}\t${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

function sha256(data) {
  if (Buffer.isBuffer(data) || typeof data === "string") return crypto.createHash("sha256").update(data).digest("hex");
  return crypto.createHash("sha256").update(JSON.stringify(data)).digest("hex");
}

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-promote-triage-${label}-`));
}

function rmrf(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

function paths(root) {
  const state = path.join(root, ".graphsmith", "state");
  const evolvable = path.join(root, ".graphsmith", "evolvable");
  return {
    state, evolvable,
    active: path.join(evolvable, "ACTIVE"),
    journal: path.join(state, "journal.jsonl"),
    adoption: path.join(state, "adoption-log.jsonl"),
    projectManifest: path.join(state, "project.manifest.json"),
    window: path.join(state, "window.json"),
  };
}

function readActive(p) { return JSON.parse(fs.readFileSync(p.active, "utf8")); }
function readAdoption(p) {
  const raw = fs.existsSync(p.adoption) ? fs.readFileSync(p.adoption, "utf8") : "";
  return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
function readJournal(p) {
  const raw = fs.existsSync(p.journal) ? fs.readFileSync(p.journal, "utf8") : "";
  return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
function readManifest(p) { return JSON.parse(fs.readFileSync(p.projectManifest, "utf8")); }
function readWindow(p) { return fs.existsSync(p.window) ? JSON.parse(fs.readFileSync(p.window, "utf8")) : null; }
function lastOf(records, type) {
  for (let i = records.length - 1; i >= 0; i--) if (records[i].record_type === type) return records[i];
  return null;
}

function pointerBytes(pointer) {
  return Buffer.from(`${JSON.stringify(pointer, null, 2)}\n`, "utf8");
}

function closeWindow(root) {
  const { createStore } = require(path.join(ROOT, "scripts", "state-store.js"));
  const store = createStore(root);
  const lock = store._testing.acquireLock();
  try {
    store._commit([{
      file: "window.json",
      make: (raw, rev) => {
        const current = JSON.parse(raw);
        current.state = "CLOSED_PASS";
        current.state_rev = rev;
        return JSON.stringify(current);
      },
    }]);
  } finally {
    clearInterval(lock.heartbeat);
    store._testing.releaseLock(lock.ownerToken);
  }
}

/* ================================================================== */
/* attackApplyEditsSetKnob -- set-knob op is 100% untested (~29 mutants) */
/* ================================================================== */
function attackApplyEditsSetKnob() {
  try {
    const root = tempRoot("knob-flat");
    try {
      createFixture(root);
      const r = promote(testPacket(root, "knob-set", {
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "tunables.json", anchor: "limit", op: "set-knob", payload: 42 }],
      }));
      const p = paths(root);
      const active = readActive(p);
      const content = JSON.parse(fs.readFileSync(path.join(p.evolvable, active.tree, "tunables.json"), "utf8"));
      assert(r.state === "DONE" && content.limit === 42, `state=${r.state} limit=${content.limit}`);
      report("applyedits-01-set-knob-flat-anchor", "PASS", `limit=${content.limit}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-01-set-knob-flat-anchor", "FAIL", e.message); }

  try {
    const root = tempRoot("knob-nested");
    try {
      const fx = createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      const treeDir = path.join(p.evolvable, active.tree);
      fs.writeFileSync(path.join(treeDir, "tunables.json"), `${JSON.stringify({ group: { limit: 1 } }, null, 2)}\n`);
      const r = promote(testPacket(root, "knob-nested", {
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "tunables.json", anchor: "group.limit", op: "set-knob", payload: 99 }],
      }));
      const activeAfter = readActive(p);
      const content = JSON.parse(fs.readFileSync(path.join(p.evolvable, activeAfter.tree, "tunables.json"), "utf8"));
      assert(r.state === "DONE" && content.group.limit === 99, `state=${r.state} content=${JSON.stringify(content)}`);
      report("applyedits-02-set-knob-nested-anchor", "PASS", `group.limit=${content.group.limit}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-02-set-knob-nested-anchor", "FAIL", e.message); }

  try {
    const root = tempRoot("knob-missing");
    try {
      createFixture(root);
      let code = null;
      try {
        promote(testPacket(root, "knob-missing", {
          edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "tunables.json", anchor: "does_not_exist", op: "set-knob", payload: 1 }],
        }));
      } catch (e) { code = e.code; var msg = e.message; }
      assert(code === "VALIDATION_FAILED" && /Knob anchor not found/.test(msg || ""), `code=${code} msg=${msg}`);
      report("applyedits-03-set-knob-missing-final-key", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-03-set-knob-missing-final-key", "FAIL", e.message); }

  try {
    const root = tempRoot("knob-notobj");
    try {
      createFixture(root);
      let code = null; let msg = null;
      try {
        promote(testPacket(root, "knob-notobj", {
          edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "tunables.json", anchor: "limit.sub", op: "set-knob", payload: 1 }],
        }));
      } catch (e) { code = e.code; msg = e.message; }
      assert(code === "VALIDATION_FAILED" && /Knob anchor not found: limit\.sub/.test(msg || ""), `code=${code} msg=${msg}`);
      report("applyedits-04-set-knob-intermediate-not-object", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-04-set-knob-intermediate-not-object", "FAIL", e.message); }

  try {
    const root = tempRoot("knob-null-intermediate");
    try {
      createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      /* typeof null === "object", so a truthy-only check (mutating the
       * guard's OR into an AND) would let a null intermediate slip through
       * to the final hasOwnProperty(cursor, ...) call, which throws an
       * uncaught TypeError on a null receiver instead of the intended
       * VALIDATION_FAILED -- a distinct, strictly-checkable failure mode
       * the "not an object" case above (a plain number) cannot distinguish,
       * because that case's final hasOwnProperty check happens to produce
       * the SAME message either way. */
      fs.writeFileSync(path.join(p.evolvable, active.tree, "tunables.json"), `${JSON.stringify({ limit: null }, null, 2)}\n`);
      let code = null; let msg = null;
      try {
        promote(testPacket(root, "knob-null-intermediate", {
          edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "tunables.json", anchor: "limit.sub", op: "set-knob", payload: 1 }],
        }));
      } catch (e) { code = e.code; msg = e.message; }
      assert(code === "VALIDATION_FAILED" && /Knob anchor not found: limit\.sub/.test(msg || ""), `code=${code} msg=${msg}`);
      report("applyedits-04b-set-knob-null-intermediate-is-validation-not-typeerror", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-04b-set-knob-null-intermediate-is-validation-not-typeerror", "FAIL", e.message); }
}

/* ================================================================== */
/* attackApplyEditsInsertDelete -- insert/delete ops never exercised (~18) */
/* ================================================================== */
function attackApplyEditsInsertDelete() {
  try {
    const root = tempRoot("insert");
    try {
      createFixture(root);
      const r = promote(testPacket(root, "insert-op", {
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "graphsmith.learned.md", anchor: "alpha", op: "insert", payload: "-inserted" }],
      }));
      const p = paths(root);
      const active = readActive(p);
      const content = fs.readFileSync(path.join(p.evolvable, active.tree, "graphsmith.learned.md"), "utf8");
      assert(r.state === "DONE" && content === "alpha-inserted\n", `state=${r.state} content=${JSON.stringify(content)}`);
      report("applyedits-05-insert-op", "PASS", `content=${JSON.stringify(content)}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-05-insert-op", "FAIL", e.message); }

  try {
    const root = tempRoot("delete");
    try {
      createFixture(root);
      const r = promote(testPacket(root, "delete-op", {
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "selftest", file: "graphsmith.learned.md", anchor: "alpha", op: "delete" }],
      }));
      const p = paths(root);
      const active = readActive(p);
      const content = fs.readFileSync(path.join(p.evolvable, active.tree, "graphsmith.learned.md"), "utf8");
      assert(r.state === "DONE" && content === "\n", `state=${r.state} content=${JSON.stringify(content)}`);
      report("applyedits-06-delete-op", "PASS", `content=${JSON.stringify(content)}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-06-delete-op", "FAIL", e.message); }
}

/* ================================================================== */
/* attackApplyEditsMalformed -- malformed-edit guards untested (~15) */
/* ================================================================== */
function attackApplyEditsMalformed() {
  const cases = [
    { name: "applyedits-07-edit-not-an-object", edits: [42], want: /Each edit must be an object/ },
    { name: "applyedits-08-edit-wrong-schema-version", edits: [{ schema_version: "0.9", schema_ref: "x", file: "graphsmith.learned.md", anchor: "alpha", op: "replace", payload: "x" }], want: /TypedEdit must carry schema_version 1\.0/ },
    { name: "applyedits-09-edit-missing-schema-ref", edits: [{ schema_version: SCHEMA_VERSION, file: "graphsmith.learned.md", anchor: "alpha", op: "replace", payload: "x" }], want: /schema_ref must be a non-empty string/ },
    { name: "applyedits-10-edit-unsupported-op", edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "alpha", op: "frobnicate", payload: "x" }], want: /Unsupported edit op: frobnicate/ },
  ];
  for (const c of cases) {
    try {
      const root = tempRoot("malformed");
      try {
        createFixture(root);
        let code = null; let msg = null;
        try { promote(testPacket(root, "malformed", { edits: c.edits })); }
        catch (e) { code = e.code; msg = e.message; }
        assert(code === "INVALID_PACKET" && c.want.test(msg || ""), `code=${code} msg=${msg}`);
        report(c.name, "PASS", `code=${code}`);
      } finally { rmrf(root); }
    } catch (e) { report(c.name, "FAIL", e.message); }
  }
}

/* ================================================================== */
/* attackAnchorCount -- "must occur exactly once": both branches (~16) */
/* ================================================================== */
function attackAnchorCount() {
  try {
    const root = tempRoot("anchor-missing");
    try {
      createFixture(root);
      let code = null; let msg = null;
      try {
        promote(testPacket(root, "anchor-missing", {
          edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "not-present-anywhere", op: "replace", payload: "x" }],
        }));
      } catch (e) { code = e.code; msg = e.message; }
      assert(code === "VALIDATION_FAILED" && /Edit anchor must occur exactly once/.test(msg || ""), `code=${code} msg=${msg}`);
      report("applyedits-11-anchor-not-found", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-11-anchor-not-found", "FAIL", e.message); }

  try {
    const root = tempRoot("anchor-twice");
    try {
      createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      fs.writeFileSync(path.join(p.evolvable, active.tree, "graphsmith.learned.md"), "twice twice\n");
      let code = null; let msg = null;
      try {
        promote(testPacket(root, "anchor-twice", {
          edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "twice", op: "replace", payload: "once" }],
        }));
      } catch (e) { code = e.code; msg = e.message; }
      assert(code === "VALIDATION_FAILED" && /Edit anchor must occur exactly once/.test(msg || ""), `code=${code} msg=${msg}`);
      report("applyedits-12-anchor-occurs-twice", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-12-anchor-occurs-twice", "FAIL", e.message); }

  try {
    const root = tempRoot("edit-target-missing");
    try {
      createFixture(root);
      let code = null; let msg = null;
      try {
        promote(testPacket(root, "edit-target-missing", {
          edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "no-such-file.md", anchor: "x", op: "replace", payload: "y" }],
        }));
      } catch (e) { code = e.code; msg = e.message; }
      /* Distinct from applyedits-11: this is a file that does not exist in
       * the staged tree at all, not an anchor missing from an existing
       * file's content. */
      assert(code === "VALIDATION_FAILED" && /Edit target does not exist: no-such-file\.md/.test(msg || ""), `code=${code} msg=${msg}`);
      report("applyedits-13-edit-target-file-does-not-exist", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("applyedits-13-edit-target-file-does-not-exist", "FAIL", e.message); }
}

/* ================================================================== */
/* attackNormalizePacketGaps -- legacy aliases + shape guards (~40) */
/* ================================================================== */
function attackNormalizePacketGaps() {
  try {
    const root = tempRoot("np-null");
    try {
      createFixture(root);
      let code = null;
      try { promote(null); } catch (e) { code = e.code; }
      assert(code === "INVALID_PACKET", `code=${code}`);
      report("normalize-01-null-input", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-01-null-input", "FAIL", e.message); }

  try {
    const root = tempRoot("np-array");
    try {
      createFixture(root);
      let code = null;
      try { promote([1, 2, 3]); } catch (e) { code = e.code; }
      assert(code === "INVALID_PACKET", `code=${code}`);
      report("normalize-02-array-input", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-02-array-input", "FAIL", e.message); }

  try {
    const root = tempRoot("np-alias-fp");
    try {
      createFixture(root);
      const pkt = testPacket(root, "alias-fp");
      pkt.candidate_fingerprint = pkt.fingerprint;
      delete pkt.fingerprint;
      const r = promote(pkt);
      assert(r.state === "DONE", `state=${r.state}`);
      report("normalize-03-candidate_fingerprint-alias", "PASS", `state=${r.state}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-03-candidate_fingerprint-alias", "FAIL", e.message); }

  try {
    const root = tempRoot("np-alias-evidence");
    try {
      createFixture(root);
      const pkt = testPacket(root, "alias-evidence");
      pkt.evidence = pkt.evidence_ref;
      delete pkt.evidence_ref;
      const r = promote(pkt);
      assert(r.state === "DONE", `state=${r.state}`);
      report("normalize-04-evidence-alias", "PASS", `state=${r.state}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-04-evidence-alias", "FAIL", e.message); }

  try {
    const root = tempRoot("np-alias-diff");
    try {
      createFixture(root);
      const pkt = testPacket(root, "alias-diff");
      pkt.diff = pkt.edits;
      delete pkt.edits;
      const r = promote(pkt);
      assert(r.state === "DONE", `state=${r.state}`);
      report("normalize-05-diff-alias-for-edits", "PASS", `state=${r.state}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-05-diff-alias-for-edits", "FAIL", e.message); }

  try {
    const root = tempRoot("np-edits-not-clobbered-by-diff");
    try {
      createFixture(root);
      /* The alias only applies when edits is ABSENT. A packet that
       * legitimately sets edits AND (redundantly, incorrectly) also sets
       * diff must use the real edits, not have them silently replaced. */
      const pkt = testPacket(root, "edits-and-diff-both-present");
      pkt.diff = [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "should-not-be-used", op: "replace", payload: "wrong" }];
      const r = promote(pkt);
      const p = paths(root);
      const active = readActive(p);
      const content = fs.readFileSync(path.join(p.evolvable, active.tree, "graphsmith.learned.md"), "utf8");
      assert(r.state === "DONE" && content === "edits-and-diff-both-present\n",
        `state=${r.state} content=${JSON.stringify(content)} -- packet.diff must not override an already-present packet.edits`);
      report("normalize-05b-edits-not-clobbered-when-diff-also-present", "PASS", `content=${JSON.stringify(content)}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-05b-edits-not-clobbered-when-diff-also-present", "FAIL", e.message); }

  try {
    const root = tempRoot("np-alias-arb");
    try {
      createFixture(root);
      const pkt = testPacket(root, "alias-arb");
      pkt.autoRollbackEligible = true;
      delete pkt.auto_rollback_eligible;
      const first = promote(pkt);
      assert(first.state === "DONE", `promote state=${first.state}`);
      const previousCwd = process.cwd();
      process.chdir(root);
      let rolledBack;
      try { rolledBack = rollback(first.txid); } finally { process.chdir(previousCwd); }
      assert(rolledBack.state === "DONE", `rollback state=${rolledBack.state}`);
      report("normalize-06-autoRollbackEligible-alias-propagates-to-journal", "PASS", `rollback=${rolledBack.state}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-06-autoRollbackEligible-alias-propagates-to-journal", "FAIL", e.message); }

  try {
    const root = tempRoot("np-no-edits-no-tree");
    try {
      createFixture(root);
      const pkt = testPacket(root, "no-edits");
      delete pkt.edits;
      let code = null; let msg = null;
      try { promote(pkt); } catch (e) { code = e.code; msg = e.message; }
      assert(code === "INVALID_PACKET" && /must provide edits\[\] or source_tree/.test(msg || ""), `code=${code} msg=${msg}`);
      report("normalize-07-neither-edits-nor-source_tree", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-07-neither-edits-nor-source_tree", "FAIL", e.message); }

  try {
    const root = tempRoot("np-no-human");
    try {
      createFixture(root);
      const pkt = testPacket(root, "no-human");
      delete pkt.human;
      let code = null; let msg = null;
      try { promote(pkt); } catch (e) { code = e.code; msg = e.message; }
      assert(code === "INVALID_PACKET" && /packet\.human is required/.test(msg || ""), `code=${code} msg=${msg}`);
      report("normalize-08-missing-human", "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("normalize-08-missing-human", "FAIL", e.message); }
}

/* ================================================================== */
/* attackAdmitWindowGaps -- WINDOW_MISMATCH + n/wall-time defaults (~21) */
/* ================================================================== */
function attackAdmitWindowGaps() {
  try {
    const root = tempRoot("rollback-mismatch");
    try {
      createFixture(root);
      /* admitWindow's WINDOW_MISMATCH is thrown from inside store._commit()
       * while promote() is already past LOG_APPEND_DONE (phase "LOGGED"),
       * so promote()'s own catch converts it into a graceful compensating
       * abort via abortVisible() rather than propagating the throw -- the
       * caller sees an ABORTED result, not an exception. */
      const r = promote(testPacket(root, "fake-rollback", { rollback_of: "0123456789abcdef" }));
      const p = paths(root);
      const abortRec = readJournal(p).find((rec) => rec.record_type === "TX_ABORT" && rec.txid === r.txid);
      assert(r.state === "ABORTED" && abortRec && /Rollback requires the matching live Gate-4 window/.test(abortRec.reason || ""),
        `state=${r.state} abortReason=${abortRec && abortRec.reason}`);
      report("admitwindow-01-rollback_of-without-matching-window", "PASS", `reason=${abortRec.reason}`);
    } finally { rmrf(root); }
  } catch (e) { report("admitwindow-01-rollback_of-without-matching-window", "FAIL", e.message); }

  try {
    const root = tempRoot("window-defaults");
    try {
      createFixture(root);
      const pkt = testPacket(root, "window-defaults");
      delete pkt.window_n;
      const r = promote(pkt);
      const p = paths(root);
      const window = readWindow(p);
      assert(r.state === "DONE" && window && window.window.n === 5 && window.window.max_window_wall_time_ms === 7 * 24 * 60 * 60 * 1000,
        `state=${r.state} n=${window && window.window.n} wall=${window && window.window.max_window_wall_time_ms}`);
      report("admitwindow-02-window_n-and_wall_time-defaults", "PASS", `n=${window.window.n} wall=${window.window.max_window_wall_time_ms}`);
    } finally { rmrf(root); }
  } catch (e) { report("admitwindow-02-window_n-and_wall_time-defaults", "FAIL", e.message); }

  try {
    const root = tempRoot("window-explicit");
    try {
      createFixture(root);
      const pkt = testPacket(root, "window-explicit", { window_n: 12, max_window_wall_time_ms: 60000 });
      const r = promote(pkt);
      const p = paths(root);
      const window = readWindow(p);
      assert(r.state === "DONE" && window.window.n === 12 && window.window.max_window_wall_time_ms === 60000,
        `n=${window.window.n} wall=${window.window.max_window_wall_time_ms}`);
      report("admitwindow-03-window_n-and_wall_time-explicit-values-honored", "PASS", `n=${window.window.n} wall=${window.window.max_window_wall_time_ms}`);
    } finally { rmrf(root); }
  } catch (e) { report("admitwindow-03-window_n-and_wall_time-explicit-values-honored", "FAIL", e.message); }

  try {
    const root = tempRoot("wall-time-boundary");
    try {
      createFixture(root);
      /* A value that IS a safe integer but is NOT > 0 must still fall back
       * to the 7-day default -- both conditions have to hold, not just
       * isSafeInteger(). */
      const pkt = testPacket(root, "wall-time-boundary", { max_window_wall_time_ms: -50 });
      const r = promote(pkt);
      const window = readWindow(paths(root));
      assert(r.state === "DONE" && window.window.max_window_wall_time_ms === 7 * 24 * 60 * 60 * 1000,
        `state=${r.state} wall=${window && window.window.max_window_wall_time_ms}`);
      report("admitwindow-04-wall_time-negative-integer-still-falls-back-to-default", "PASS", `wall=${window.window.max_window_wall_time_ms}`);
    } finally { rmrf(root); }
  } catch (e) { report("admitwindow-04-wall_time-negative-integer-still-falls-back-to-default", "FAIL", e.message); }

  try {
    const root = tempRoot("rollback-mismatch-live-window");
    try {
      createFixture(root);
      /* The mismatch check ORs three clauses: no window, wrong owning
       * txid, or the wrong state. admitwindow-01 above hits it via "no
       * window at all" (current.window is null), which cannot distinguish
       * a mutant that turns the OR-chain into effectively an AND against
       * the state clause -- when a window genuinely exists, in a state
       * that WOULD otherwise be acceptable, but belongs to a different
       * transaction, this still must refuse. */
      const first = promote(testPacket(root, "live-window-owner"));
      assert(first.state === "DONE", `setup promote failed: ${first.state}`);
      /* Window is now ADMITTED (never closed) and owned by `first.txid`.
       * Ask for a rollback of a DIFFERENT, non-matching txid. The edit's
       * anchor must match what the FIRST promotion actually left in the
       * file ("live-window-owner", not testPacket's default "alpha") or
       * staging itself fails before ever reaching admitWindow. */
      const mismatchedTxid = `${first.txid.slice(0, -1)}${first.txid.slice(-1) === "0" ? "1" : "0"}`;
      const r = promote(testPacket(root, "live-window-mismatch", {
        rollback_of: mismatchedTxid,
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "live-window-owner", op: "replace", payload: "live-window-mismatch" }],
      }));
      const p = paths(root);
      const abortRec = readJournal(p).find((rec) => rec.record_type === "TX_ABORT" && rec.txid === r.txid);
      assert(r.state === "ABORTED" && abortRec && /Rollback requires the matching live Gate-4 window/.test(abortRec.reason || ""),
        `state=${r.state} abortReason=${abortRec && abortRec.reason}`);
      report("admitwindow-05-rollback_of-mismatched-txid-with-a-live-window-present", "PASS", `reason=${abortRec.reason}`);
    } finally { rmrf(root); }
  } catch (e) { report("admitwindow-05-rollback_of-mismatched-txid-with-a-live-window-present", "FAIL", e.message); }
}

/* ================================================================== */
/* attackInstallStagedGaps -- manifest-drift HALT + content-addressed collision (~ subset of 27) */
/* ================================================================== */
function attackInstallStagedGaps() {
  try {
    const name = "installstaged-01-manifest-tampered-between-verify-and-install-halts";
    const root = tempRoot("drift");
    try {
      createFixture(root);
      const preloadFile = path.join(root, "drift-preload.js");
      /* installStaged's own drift check reads tree.manifest.json (and hashes
       * it) BEFORE it calls fs.renameSync, so a renameSync hook fires too
       * late to touch what that read sees. It must land strictly between
       * stageUnlocked's manifest write (end of the unlocked phase) and
       * installStaged's own read (start of the locked phase). The first
       * fs.fsyncSync call after fs.cpSync captured the staging payload path
       * is a safe marker for that window: every write in between
       * (applyEdits, the manifest write, verifyTree's reads) uses
       * writeFileSync/readFileSync, never fsyncSync, so this is the first
       * durability sync after staging finishes -- reliably still inside the
       * "staged but not yet installed" gap. */
      fs.writeFileSync(preloadFile, `
        const fs = require("fs");
        const path = require("path");
        const realCp = fs.cpSync;
        let stagingPayload = null;
        fs.cpSync = function (src, dest, ...rest) {
          stagingPayload = dest;
          return realCp.call(this, src, dest, ...rest);
        };
        const realFsync = fs.fsyncSync;
        let tampered = false;
        fs.fsyncSync = function (fd) {
          if (!tampered && stagingPayload) {
            tampered = true;
            try { fs.appendFileSync(path.join(stagingPayload, "tree.manifest.json"), "\\n// tampered-manifest\\n"); } catch (e) {}
          }
          return realFsync.call(this, fd);
        };
      `);
      const driver = path.join(root, "drift-driver.js");
      fs.writeFileSync(driver, `
        const { promote, __testing } = require(${JSON.stringify(PROMOTE_PATH)});
        try { const r = promote(__testing.testPacket(${JSON.stringify(root)}, "drift")); console.log("STATE:" + r.state); }
        catch (e) { console.log("CODE:" + e.code + " MSG:" + e.message); }
      `);
      const r = require("child_process").spawnSync(process.execPath, ["--require", preloadFile, driver], {
        env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" }, timeout: 60000, encoding: "utf8",
      });
      const out = `${r.stdout || ""}`.trim();
      assert(/CODE:HALT MSG:Staged tree changed between verification and install/.test(out),
        `expected installStaged's own manifest-drift HALT, got ${JSON.stringify(out)} (stderr ${String(r.stderr || "").slice(0, 300)})`);
      report(name, "PASS", out);
    } finally { rmrf(root); }
  } catch (e) { report("installstaged-01-manifest-tampered-between-verify-and-install-halts", "FAIL", e.message); }

  try {
    const name = "installstaged-02-content-addressed-collision-reuses-existing-tree";
    const root = tempRoot("collision");
    try {
      createFixture(root);
      const p = paths(root);
      const edits = [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "alpha", op: "replace", payload: "collide" }];
      const first = promote(testPacket(root, "collide-1", { edits }));
      assert(first.state === "DONE", `first promote state=${first.state}`);
      const firstTree = readActive(p).tree;

      /* Roll all the way back so ACTIVE, and therefore the base every future
       * staging copies from, is byte-identical to the ORIGINAL fixture again. */
      const previousCwd = process.cwd();
      process.chdir(root);
      let rolledBack;
      try { rolledBack = rollback(first.txid); } finally { process.chdir(previousCwd); }
      assert(rolledBack.state === "DONE", `rollback state=${rolledBack.state}`);

      /* Same edits from the same base produce the SAME content-addressed tree
       * name -- which this promotion's staging will find already present on
       * disk from the first promotion (nothing ever deleted it). This is the
       * collision branch, reproduced deterministically with no monkeypatch. */
      const second = promote(testPacket(root, "collide-2", { edits }));
      assert(second.state === "DONE", `second promote state=${second.state}`);
      const secondTree = readActive(p).tree;
      assert(secondTree === firstTree, `expected the collision to republish the same tree id, got ${secondTree} vs ${firstTree}`);
      assert(fs.existsSync(path.join(p.evolvable, firstTree)), "the pre-existing tree directory was removed instead of reused");
      report(name, "PASS", `reused tree ${firstTree}`);
    } finally { rmrf(root); }
  } catch (e) { report("installstaged-02-content-addressed-collision-reuses-existing-tree", "FAIL", e.message); }
}

/* ================================================================== */
/* attackGarbageCollectGaps -- actual deletion + rollback-eligible protection (~ subset of 47) */
/* ================================================================== */
function attackGarbageCollectGaps() {
  try {
    const name = "gc-01-orphaned-tree-is-actually-deleted-from-disk";
    const root = tempRoot("gc-delete");
    try {
      const fx = createFixture(root);
      const p = paths(root);
      /* gc1: NOT reversible/auto_rollback_eligible, so its predecessor (the
       * seed tree) is not protected by rollbackEligiblePrevious. */
      promote(testPacket(root, "gc1", { reversible: false, auto_rollback_eligible: false }));
      closeWindow(root);
      const treeAfterGc1 = readActive(p).tree;
      promote(testPacket(root, "gc2", {
        reversible: false, auto_rollback_eligible: false,
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "gc1", op: "replace", payload: "gc2" }],
      }));
      closeWindow(root);
      /* A third promotion's garbageCollect runs BEFORE staging the third
       * tree, so it is the one that evaluates gc1's tree for deletion --
       * garbageCollect protects only the CURRENT active tree and the most
       * recent rollback-eligible predecessor, and gc1's tree is neither by
       * the time gc3 runs. */
      promote(testPacket(root, "gc3", {
        reversible: false, auto_rollback_eligible: false,
        edits: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "gc2", op: "replace", payload: "gc3" }],
      }));
      const seedGone = !fs.existsSync(path.join(p.evolvable, fx.tree));
      assert(seedGone, `seed tree ${fx.tree} should have been garbage-collected by the third promotion but still exists`);
      report(name, "PASS", `seed tree ${fx.tree} deleted`);
    } finally { rmrf(root); }
  } catch (e) { report("gc-01-orphaned-tree-is-actually-deleted-from-disk", "FAIL", e.message); }

  /* A second case attempting to prove rollbackEligiblePrevious's protection
   * saves a tree the natural "last 2 completed trees" window would not have
   * saved anyway was deliberately NOT written here. Working through every
   * reachable sequence (including one that goes through an object-form
   * rollback with reversible:true) shows the predecessor it computes -- the
   * tree immediately before whichever transaction is active AT THE MOMENT
   * a later promotion's garbageCollect runs -- is always exactly the
   * second-most-recent entry in completedTreeHistory, which
   * garbageCollect's own `history.slice(0, history.length - 2)` already
   * excludes from deletion regardless of any reversible flag. Its
   * observable contribution to which trees survive GC is provably always
   * redundant with the window it already applies; gc-01 above already
   * exercises the guard clauses that matter (begin/staged/TX_DONE
   * presence, packet.kind, reversible, auto_rollback_eligible) by
   * constructing exactly the non-reversible case whose predecessor the
   * window does NOT save. See the project doc for the full reasoning --
   * this is the same equivalent-code class as gate.js round 6's and
   * state-store.js's own duplicate-check findings. */
}

/* ================================================================== */
/* attackRecoverAbortedResume -- recover()'s "recovered compensating abort"
 * resume branch (lines ~1024-1035) has zero coverage: it is reachable only
 * by a crash INSIDE abortVisible, after OUTCOME_APPEND_INTENT is journaled
 * but before TX_ABORT lands, which no existing test constructs. (~26 mutants,
 * the single largest gap this triage found in promote.js.) */
/* ================================================================== */
function attackRecoverAbortedResume() {
  try {
    const name = "recover-01-resumes-a-crash-mid-abortVisible-and-completes-the-abort";
    const refRoot = tempRoot("abort-resume-ref");
    const root = tempRoot("abort-resume");
    try {
      createFixture(refRoot);
      const refPkt = testPacket(refRoot, "abort-resume", { __test_abort_after_log: true });
      const refResult = promote(refPkt);
      assert(refResult.state === "ABORTED", `reference abort did not land: ${refResult.state}`);
      const rp = paths(refRoot);
      const refJournal = readJournal(rp);
      const stageDoneRec = refJournal.find((r) => r.record_type === "STAGE_DONE");
      const logIntentRec = refJournal.find((r) => r.record_type === "LOG_APPEND_INTENT");

      const fx = createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      const activeSha = sha256(pointerBytes(active));
      const pkt = testPacket(root, "abort-resume", { __test_abort_after_log: true });
      const txid = sha256(pkt.fingerprint + activeSha).slice(0, 16);
      const stagedTree = stageDoneRec.tree;
      fs.cpSync(path.join(rp.evolvable, stagedTree), path.join(p.evolvable, stagedTree), { recursive: true });
      const toPointer = { schema_version: SCHEMA_VERSION, txid, tree: stagedTree, tree_manifest_sha256: stageDoneRec.tree_manifest_sha };

      const committingBase = {
        schema_version: SCHEMA_VERSION, seq: 1, txid, status: "committing",
        fingerprint: pkt.fingerprint, kind: pkt.kind, evidence_ref: pkt.evidence_ref, human: pkt.human, prev_sha256: null,
      };
      const committingSha = sha256(JSON.stringify(committingBase));
      const committing = { ...committingBase, entry_sha256: committingSha };
      fs.writeFileSync(p.adoption, `${JSON.stringify(committing)}\n`);

      const terminalBase = {
        schema_version: SCHEMA_VERSION, seq: 2, txid, status: "aborted",
        fingerprint: pkt.fingerprint, kind: pkt.kind, evidence_ref: pkt.evidence_ref, human: pkt.human, prev_sha256: committingSha,
      };
      const terminalSha = sha256(JSON.stringify(terminalBase));
      const terminal = { ...terminalBase, entry_sha256: terminalSha };

      /* Journal ends right after OUTCOME_APPEND_INTENT: exactly what a crash
       * inside abortVisible between that journalRecord() and the following
       * appendEntry() would leave behind. No SWAP_* records: abortVisible is
       * reached before the swap, so ACTIVE is still untouched. */
      const journalRecords = [
        { schema_version: SCHEMA_VERSION, record_type: "TX_BEGIN", txid, expected_active_sha: activeSha, expected_log_head: null, packet: pkt },
        { schema_version: SCHEMA_VERSION, record_type: "STAGE_DONE", txid, tree: stagedTree, tree_manifest_sha: stageDoneRec.tree_manifest_sha, from_pointer: active, to_pointer: toPointer },
        { schema_version: SCHEMA_VERSION, record_type: "VALIDATED", txid },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_INTENT", txid, entry_sha: committingSha, entry: committing },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_DONE", txid, entry_sha: committingSha, status: "committing" },
        { schema_version: SCHEMA_VERSION, record_type: "OUTCOME_APPEND_INTENT", txid, terminal_entry_sha: terminalSha, entry: terminal },
      ];
      fs.writeFileSync(p.journal, journalRecords.map((r) => `${JSON.stringify(r)}\n`).join(""));

      const recovered = recover(root);
      const adoptionAfter = readAdoption(p);
      const journalAfter = readJournal(p);
      const manifestAfter = readManifest(p);
      const activeAfter = readActive(p);
      const hasCompensatingAbort = journalAfter.some((r) => r.record_type === "TX_ABORT" && r.txid === txid && r.reason === "recovered compensating abort");

      assert(recovered.transactions[0].state === "ABORTED", `recover() reported ${recovered.transactions[0] && recovered.transactions[0].state}`);
      assert(adoptionAfter.length === 2 && adoptionAfter.at(-1).status === "aborted" && adoptionAfter.at(-1).entry_sha256 === terminalSha,
        `adoption log after recover: ${JSON.stringify(adoptionAfter)}`);
      assert(hasCompensatingAbort, "journal is missing the recovered-compensating-abort TX_ABORT record");
      assert(manifestAfter.adoption_log_head === terminalSha, `manifest head=${manifestAfter.adoption_log_head} expected=${terminalSha}`);
      assert(activeAfter.tree === fx.tree, `ACTIVE moved to ${activeAfter.tree} but an aborted transaction must never publish its staged tree`);
      report(name, "PASS", `txid=${txid} resumed and completed the abort`);
    } finally { rmrf(refRoot); rmrf(root); }
  } catch (e) { report("recover-01-resumes-a-crash-mid-abortVisible-and-completes-the-abort", "FAIL", e.message); }

  try {
    const name = "recover-02-halts-when-the-staged-tree-itself-is-corrupt";
    const refRoot = tempRoot("halt-staged-ref");
    const root = tempRoot("halt-staged");
    try {
      createFixture(refRoot);
      const refResult = promote(testPacket(refRoot, "halt-staged"));
      assert(refResult.state === "DONE", `reference promote failed: ${refResult.state}`);
      const rp = paths(refRoot);
      const refJournal = readJournal(rp);
      const stageDoneRec = refJournal.find((r) => r.record_type === "STAGE_DONE");

      const fx = createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      const activeSha = sha256(pointerBytes(active));
      const pkt = testPacket(root, "halt-staged");
      const txid = sha256(pkt.fingerprint + activeSha).slice(0, 16);
      fs.cpSync(path.join(rp.evolvable, stageDoneRec.tree), path.join(p.evolvable, stageDoneRec.tree), { recursive: true });
      /* Corrupt the staged (but not-yet-installed) tree's content so it no
       * longer matches its own manifest -- exactly the "crashed mid-copy,
       * left a half-written tree behind" scenario recover()'s own
       * closed-inventory check exists to catch. */
      fs.writeFileSync(path.join(p.evolvable, stageDoneRec.tree, "graphsmith.learned.md"), "corrupted-after-staging\n");
      const toPointer = { schema_version: SCHEMA_VERSION, txid, tree: stageDoneRec.tree, tree_manifest_sha256: stageDoneRec.tree_manifest_sha };
      /* recover()'s "!staged || !logIntent" early-rollback branch runs
       * BEFORE the staged-tree verification check, so a LOG_APPEND_INTENT
       * record (a visible, in-flight commit) must be present too, or this
       * simply rolls back cleanly without ever reaching the corruption
       * check this case targets. */
      const committingBase = {
        schema_version: SCHEMA_VERSION, seq: 1, txid, status: "committing",
        fingerprint: pkt.fingerprint, kind: pkt.kind, evidence_ref: pkt.evidence_ref, human: pkt.human, prev_sha256: null,
      };
      const committingSha = sha256(JSON.stringify(committingBase));
      const committing = { ...committingBase, entry_sha256: committingSha };
      const journalRecords = [
        { schema_version: SCHEMA_VERSION, record_type: "TX_BEGIN", txid, expected_active_sha: activeSha, expected_log_head: null, packet: pkt },
        { schema_version: SCHEMA_VERSION, record_type: "STAGE_DONE", txid, tree: stageDoneRec.tree, tree_manifest_sha: stageDoneRec.tree_manifest_sha, from_pointer: active, to_pointer: toPointer },
        { schema_version: SCHEMA_VERSION, record_type: "VALIDATED", txid },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_INTENT", txid, entry_sha: committingSha, entry: committing },
      ];
      fs.writeFileSync(p.journal, journalRecords.map((r) => `${JSON.stringify(r)}\n`).join(""));
      let code = null; let msg = null;
      try { recover(root); } catch (e) { code = e.code; msg = e.message; }
      assert(code === "HALT" && /staged immutable tree failed verification/.test(msg || ""), `code=${code} msg=${msg}`);
      report(name, "PASS", `code=${code}`);
    } finally { rmrf(refRoot); rmrf(root); }
  } catch (e) { report("recover-02-halts-when-the-staged-tree-itself-is-corrupt", "FAIL", e.message); }
}

/* ================================================================== */
/* attackRecoveryHaltMessages -- the three recoveryHalt() call sites, never
 * triggered by any existing test (~13 mutants across the three checks). */
/* ================================================================== */
function attackRecoveryHaltMessages() {
  function buildUnfinished(root, suffix) {
    const fx = createFixture(root);
    const p = paths(root);
    const active = readActive(p);
    const activeSha = sha256(pointerBytes(active));
    const pkt = testPacket(root, suffix);
    const txid = sha256(pkt.fingerprint + activeSha).slice(0, 16);
    return { fx, p, active, activeSha, pkt, txid };
  }

  try {
    const name = "recoveryhalt-01-unclassifiable-active-identity";
    const root = tempRoot("halt-active");
    try {
      const { p, active, activeSha, pkt, txid } = buildUnfinished(root, "halt-active");
      /* Fabricate a STAGE_DONE whose to_pointer hashes to something ACTIVE
       * will never equal, so neither oldActiveSha nor toActiveSha match the
       * real ACTIVE on disk once recover() reads it. */
      const bogusTree = "v-0000000000000000000000000000000000000000000000000000000000000000";
      const toPointer = { schema_version: SCHEMA_VERSION, txid, tree: bogusTree, tree_manifest_sha256: "0".repeat(64) };
      const journalRecords = [
        { schema_version: SCHEMA_VERSION, record_type: "TX_BEGIN", txid, expected_active_sha: activeSha, expected_log_head: null, packet: pkt },
        { schema_version: SCHEMA_VERSION, record_type: "STAGE_DONE", txid, tree: bogusTree, tree_manifest_sha: "0".repeat(64), from_pointer: active, to_pointer: toPointer },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_INTENT", txid, entry_sha: "1".repeat(64), entry: { entry_sha256: "1".repeat(64) } },
      ];
      fs.writeFileSync(p.journal, journalRecords.map((r) => `${JSON.stringify(r)}\n`).join(""));
      /* Also corrupt ACTIVE itself so its identity matches NEITHER the
       * begin-time sha nor the bogus to_pointer's sha -- the actual
       * "unclassifiable" condition. */
      fs.writeFileSync(p.active, pointerBytes({ schema_version: SCHEMA_VERSION, txid: "f".repeat(16), tree: "v-" + "a".repeat(64), tree_manifest_sha256: "a".repeat(64) }));
      let code = null; let msg = null;
      try { recover(root); } catch (e) { code = e.code; msg = e.message; }
      assert(code === "HALT" && /ACTIVE has an unclassifiable identity/.test(msg || ""), `code=${code} msg=${msg}`);
      /* recoveryHalt() also journals a RECOVERY_DONE{outcome:"halt"} record
       * before throwing -- a side effect the thrown message alone does not
       * pin. Checked here once for the shared helper function; the other
       * two recoveryHalt call sites below reuse the same function body. */
      const recDone = readJournal(p).find((r) => r.record_type === "RECOVERY_DONE" && r.txid === txid);
      assert(recDone && recDone.outcome === "halt", `RECOVERY_DONE record: ${JSON.stringify(recDone)}`);
      report(name, "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("recoveryhalt-01-unclassifiable-active-identity", "FAIL", e.message); }

  try {
    const name = "recoveryhalt-02-unclassifiable-adoption-log-head";
    const root = tempRoot("halt-loghead");
    try {
      const { p, active, activeSha, pkt, txid } = buildUnfinished(root, "halt-loghead");
      const fakeTree = "v-" + "b".repeat(64);
      const toPointer = { schema_version: SCHEMA_VERSION, txid, tree: fakeTree, tree_manifest_sha256: "b".repeat(64) };
      /* STAGE_DONE + LOG_APPEND_INTENT reference a committing entry, but the
       * adoption log on disk has a totally unrelated entry as its head --
       * neither expected_log_head, the committing entry's sha, nor (absent
       * outcomeIntent) anything else recover() would accept. */
      const entrySha = "c".repeat(64);
      const journalRecords = [
        { schema_version: SCHEMA_VERSION, record_type: "TX_BEGIN", txid, expected_active_sha: activeSha, expected_log_head: null, packet: pkt },
        { schema_version: SCHEMA_VERSION, record_type: "STAGE_DONE", txid, tree: fakeTree, tree_manifest_sha: "b".repeat(64), from_pointer: active, to_pointer: toPointer },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_INTENT", txid, entry_sha: entrySha, entry: { entry_sha256: entrySha } },
      ];
      fs.writeFileSync(p.journal, journalRecords.map((r) => `${JSON.stringify(r)}\n`).join(""));
      /* A properly self-consistent entry (real hash, correct seq/prev chain)
       * so adoptionEntries()'s own chain-integrity check passes cleanly --
       * it is simply not the head recover() expects for THIS transaction,
       * which is the "unclassifiable head" case, not a corrupt-chain case. */
      const unrelatedBase = {
        schema_version: SCHEMA_VERSION, seq: 1, txid: "f".repeat(16), status: "effective",
        fingerprint: "0".repeat(64), kind: "doc", evidence_ref: "unrelated", human: pkt.human, prev_sha256: null,
      };
      const unrelated = { ...unrelatedBase, entry_sha256: sha256(JSON.stringify(unrelatedBase)) };
      fs.writeFileSync(p.adoption, `${JSON.stringify(unrelated)}\n`);
      let code = null; let msg = null;
      try { recover(root); } catch (e) { code = e.code; msg = e.message; }
      assert(code === "HALT" && /adoption log has an unclassifiable head/.test(msg || ""), `code=${code} msg=${msg}`);
      report(name, "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("recoveryhalt-02-unclassifiable-adoption-log-head", "FAIL", e.message); }

  try {
    const name = "recoveryhalt-03-unclassifiable-project-manifest-head";
    const refRoot = tempRoot("halt-manifest-ref");
    const root = tempRoot("halt-manifest");
    try {
      /* Build a real STAGE_DONE + LOG_APPEND_INTENT/DONE via a reference
       * promotion so the adoption-log head check passes cleanly, then land
       * on the project-manifest check by giving the manifest a head that
       * matches neither begin.expected_log_head nor any outcomeIntent sha. */
      createFixture(refRoot);
      const refPkt = testPacket(refRoot, "halt-manifest");
      const refResult = promote(refPkt);
      assert(refResult.state === "DONE", `reference promote failed: ${refResult.state}`);
      const rp = paths(refRoot);
      const refJournal = readJournal(rp);
      const stageDoneRec = refJournal.find((r) => r.record_type === "STAGE_DONE");
      const logIntentRec = refJournal.find((r) => r.record_type === "LOG_APPEND_INTENT");

      const fx = createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      const activeSha = sha256(pointerBytes(active));
      const pkt = testPacket(root, "halt-manifest");
      const txid = sha256(pkt.fingerprint + activeSha).slice(0, 16);
      fs.cpSync(path.join(rp.evolvable, stageDoneRec.tree), path.join(p.evolvable, stageDoneRec.tree), { recursive: true });
      const toPointer = { schema_version: SCHEMA_VERSION, txid, tree: stageDoneRec.tree, tree_manifest_sha256: stageDoneRec.tree_manifest_sha };
      const committingBase = {
        schema_version: SCHEMA_VERSION, seq: 1, txid, status: "committing",
        fingerprint: pkt.fingerprint, kind: pkt.kind, evidence_ref: pkt.evidence_ref, human: pkt.human, prev_sha256: null,
      };
      const committingSha = sha256(JSON.stringify(committingBase));
      const committing = { ...committingBase, entry_sha256: committingSha };
      fs.writeFileSync(p.adoption, `${JSON.stringify(committing)}\n`);
      const journalRecords = [
        { schema_version: SCHEMA_VERSION, record_type: "TX_BEGIN", txid, expected_active_sha: activeSha, expected_log_head: null, packet: pkt },
        { schema_version: SCHEMA_VERSION, record_type: "STAGE_DONE", txid, tree: stageDoneRec.tree, tree_manifest_sha: stageDoneRec.tree_manifest_sha, from_pointer: active, to_pointer: toPointer },
        { schema_version: SCHEMA_VERSION, record_type: "VALIDATED", txid },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_INTENT", txid, entry_sha: committingSha, entry: committing },
        { schema_version: SCHEMA_VERSION, record_type: "LOG_APPEND_DONE", txid, entry_sha: committingSha, status: "committing" },
      ];
      fs.writeFileSync(p.journal, journalRecords.map((r) => `${JSON.stringify(r)}\n`).join(""));
      /* Project manifest's head matches NEITHER begin.expected_log_head
       * (null) NOR an outcomeIntent sha (there is none yet) -- unclassifiable. */
      const manifest = readManifest(p);
      manifest.adoption_log_head = "e".repeat(64);
      fs.writeFileSync(p.projectManifest, `${JSON.stringify(manifest, null, 2)}\n`);
      let code = null; let msg = null;
      try { recover(root); } catch (e) { code = e.code; msg = e.message; }
      assert(code === "HALT" && /project manifest has an unclassifiable head/.test(msg || ""), `code=${code} msg=${msg}`);
      report(name, "PASS", `code=${code}`);
    } finally { rmrf(refRoot); rmrf(root); }
  } catch (e) { report("recoveryhalt-03-unclassifiable-project-manifest-head", "FAIL", e.message); }
}

/* ================================================================== */
/* attackRollbackObjectForm -- rollback(inverse-object) success + refusal
 * paths (~ subset of 27) */
/* ================================================================== */
function attackRollbackObjectForm() {
  try {
    const name = "rollback-01-object-form-with-inverse-alias-succeeds";
    const root = tempRoot("rb-object");
    try {
      const fx = createFixture(root);
      const first = promote(testPacket(root, "rb-object", { reversible: true, auto_rollback_eligible: true }));
      assert(first.state === "DONE", `first promote state=${first.state}`);
      const previousCwd = process.cwd();
      process.chdir(root);
      let result;
      try {
        result = rollback({
          rollback_of: first.txid,
          fingerprint: sha256(`rollback-inverse:${first.txid}`),
          kind: "doc",
          reversible: true,
          auto_rollback_eligible: true,
          evidence_ref: "selftest:rb-object-inverse",
          human: { name: "selftest", decision: "approve", ts: "2000-01-01T00:00:00.000Z" },
          inverse: [{ schema_version: SCHEMA_VERSION, schema_ref: "x", file: "graphsmith.learned.md", anchor: "rb-object", op: "replace", payload: "alpha" }],
        });
      } finally { process.chdir(previousCwd); }
      const p = paths(root);
      const restored = readActive(p);
      assert(result.state === "DONE" && restored.tree === fx.tree, `rollback state=${result.state} restoredTree=${restored.tree} seedTree=${fx.tree}`);
      report(name, "PASS", `restored to seed tree ${fx.tree}`);
    } finally { rmrf(root); }
  } catch (e) { report("rollback-01-object-form-with-inverse-alias-succeeds", "FAIL", e.message); }

  try {
    const name = "rollback-02-object-form-refuses-non-reversible-kind";
    let code = null; let msg = null;
    try {
      rollback({ rollback_of: "0123456789abcdef", kind: "code", reversible: true, auto_rollback_eligible: true, edits: [] });
    } catch (e) { code = e.code; msg = e.message; }
    assert(code === "FORWARD_RECOVERY_REQUIRED" && /Rollback refused for code, migration/.test(msg || ""), `code=${code} msg=${msg}`);
    report(name, "PASS", `code=${code}`);
  } catch (e) { report("rollback-02-object-form-refuses-non-reversible-kind", "FAIL", e.message); }

  try {
    const name = "rollback-02b-object-form-refuses-reversible-false-even-with-doc-kind";
    let code = null; let msg = null;
    try {
      rollback({ rollback_of: "0123456789abcdef", kind: "doc", reversible: false, auto_rollback_eligible: true, edits: [] });
    } catch (e) { code = e.code; msg = e.message; }
    assert(code === "FORWARD_RECOVERY_REQUIRED", `code=${code} msg=${msg}`);
    report(name, "PASS", `code=${code}`);
  } catch (e) { report("rollback-02b-object-form-refuses-reversible-false-even-with-doc-kind", "FAIL", e.message); }

  try {
    const name = "rollback-02c-object-form-refuses-auto_rollback_eligible-false";
    let code = null; let msg = null;
    try {
      rollback({ rollback_of: "0123456789abcdef", kind: "doc", reversible: true, auto_rollback_eligible: false, edits: [] });
    } catch (e) { code = e.code; msg = e.message; }
    assert(code === "FORWARD_RECOVERY_REQUIRED", `code=${code} msg=${msg}`);
    report(name, "PASS", `code=${code}`);
  } catch (e) { report("rollback-02c-object-form-refuses-auto_rollback_eligible-false", "FAIL", e.message); }

  try {
    const name = "rollback-03-string-form-refuses-incomplete-transaction";
    const root = tempRoot("rb-incomplete");
    try {
      const fx = createFixture(root);
      const p = paths(root);
      const active = readActive(p);
      const activeSha = sha256(pointerBytes(active));
      const pkt = testPacket(root, "incomplete");
      const txid = sha256(pkt.fingerprint + activeSha).slice(0, 16);
      /* TX_BEGIN only, no STAGE_DONE/TX_DONE: an in-flight, never-finished
       * transaction. rollback(txid) must refuse it, not treat it as usable. */
      fs.writeFileSync(p.journal, `${JSON.stringify({ schema_version: SCHEMA_VERSION, record_type: "TX_BEGIN", txid, expected_active_sha: activeSha, expected_log_head: null, packet: pkt })}\n`);
      const previousCwd = process.cwd();
      process.chdir(root);
      let code = null;
      try { rollback(txid); } catch (e) { code = e.code; } finally { process.chdir(previousCwd); }
      assert(code === "ROLLBACK_NOT_FOUND", `code=${code}`);
      report(name, "PASS", `code=${code}`);
    } finally { rmrf(root); }
  } catch (e) { report("rollback-03-string-form-refuses-incomplete-transaction", "FAIL", e.message); }
}

/* ================================================================== */
function main() {
  console.log("promote.js coverage-gap triage suite");
  console.log("victim=" + PROMOTE_PATH);
  attackApplyEditsSetKnob();
  attackApplyEditsInsertDelete();
  attackApplyEditsMalformed();
  attackAnchorCount();
  attackNormalizePacketGaps();
  attackAdmitWindowGaps();
  attackInstallStagedGaps();
  attackGarbageCollectGaps();
  attackRecoverAbortedResume();
  attackRecoveryHaltMessages();
  attackRollbackObjectForm();

  const pass = results.filter((r) => r.status === "PASS").length;
  const fail = results.filter((r) => r.status === "FAIL").length;
  console.log("---");
  console.log(`TOTAL\tPASS=${pass}\tFAIL=${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main();
