#!/usr/bin/env node
"use strict";

/* tests/state-store/argument-aliases/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. Several public methods accept a
 * transaction/input object with TWO OR THREE alias spellings for the same field
 * (`tx.window_id || tx.windowId || tx.txid`, `anchor.chain_head || anchor.chainHead`,
 * `input.corpus_state || input.corpusState`, and similar). Every existing suite always
 * supplies only the LAST alias in each chain (`txid`, `chain_head`, `corpus_state`, ...), so
 * the earlier alternatives in each `||` chain have never been constructed as anything but
 * `undefined` -- a LogicalOperator or StringLiteral mutant on any of those earlier
 * alternatives has nothing to disagree with. This suite drives each alias explicitly.
 *
 * Also covers `_observe`'s three-part gate (window missing / wrong state / wrong tree_id)
 * and its idempotent re-observe branch, called through the public `observeSlot` directly
 * rather than only indirectly through `registerRun`'s own early-exit for a re-registration
 * (which never reaches `_observe`'s "already observed" branch at all). */

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const { createStore: rawCreateStore } = require(STATE_STORE);
const { createManualClock } = require("../../_harness/clock.js");

let failures = 0;
const results = [];

function report(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) report(name, "PASS"); else report(name, "FAIL", reason);
}

function tempRoot(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `gs-arg-alias-${label}-`)); }
function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
function withEnv(patch, fn) {
  const prev = {};
  for (const k of Object.keys(patch)) { prev[k] = process.env[k]; if (patch[k] === undefined) delete process.env[k]; else process.env[k] = patch[k]; }
  try { return fn(); } finally { for (const k of Object.keys(patch)) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; } }
}
function createStore(root, opts = {}) { return rawCreateStore(root, Object.assign({ clock: createManualClock() }, opts)); }

/* ---- admitPending: window_id (primary) vs windowId vs txid; adoption_txid vs txid vs
 * windowId; candidate_fingerprint vs fingerprint; tree_id vs treeId ---- */
function admitPendingPrimaryAliasSpellings() {
  const root = tempRoot("admit-aliases");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const result = store.window.admitPending({
        window_id: "w-primary",
        adoption_txid: "adopt-primary",
        candidate_fingerprint: "fp-primary",
        treeId: "tree-camel",
        n: 2,
      });
      check("admitPending-window_id-primary-alias-used", result.window.window_id === "w-primary",
        `expected window_id "w-primary" from the primary field name, got ${result.window.window_id}`);
      check("admitPending-adoption_txid-primary-alias-used", result.window.adoption_txid === "adopt-primary",
        `expected adoption_txid "adopt-primary", got ${result.window.adoption_txid}`);
      check("admitPending-candidate_fingerprint-primary-alias-used", result.window.candidate_fingerprint === "fp-primary",
        `expected candidate_fingerprint "fp-primary", got ${result.window.candidate_fingerprint}`);
      check("admitPending-treeId-camelCase-alias-used", result.window.tree_id === "tree-camel",
        `expected tree_id "tree-camel" via the treeId alias, got ${result.window.tree_id}`);

      // windowId (middle alias) specifically, with window_id absent.
      const store2 = createStore(tempRoot("admit-aliases-mid"), { leaseMs: 5000, heartbeatMs: 500 });
      const result2 = store2.window.admitPending({ windowId: "w-mid", fingerprint: "fp-mid", tree_id: "t-mid", n: 1 });
      check("admitPending-windowId-middle-alias-used", result2.window.window_id === "w-mid",
        `expected window_id "w-mid" via the windowId middle alias, got ${result2.window.window_id}`);
    });
  } catch (e) { report("admit-pending-primary-alias-spellings", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- setAnchor: chain_head vs chainHead; expected_terminal_status vs
 * expectedTerminalStatus ---- */
function setAnchorCamelCaseAliases() {
  const root = tempRoot("anchor-aliases");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const record = store.runAnchors.setAnchor("run-alias", { chainHead: "h-camel", expectedTerminalStatus: "completed_pass" });
      check("setAnchor-chainHead-camelCase-alias-used", record.chain_head === "h-camel",
        `expected chain_head "h-camel" via the chainHead alias, got ${record.chain_head}`);
      check("setAnchor-expectedTerminalStatus-camelCase-alias-used", record.expected_terminal_status === "completed_pass",
        `expected expected_terminal_status "completed_pass" via camelCase alias, got ${record.expected_terminal_status}`);
    });
  } catch (e) { report("set-anchor-camel-case-aliases", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- reserveAlpha: corpusState / splitHash camelCase aliases (corpus_state / split_hash
 * primary names are exercised by every other suite; the camelCase alternates never are) ---- */
function reserveAlphaCamelCaseAliases() {
  const root = tempRoot("alpha-aliases");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const reservation = store.alphaLedger.reserve({ corpusState: "corpus-camel", splitHash: "split-camel", fingerprint: "fp-camel", family: "fam-camel" });
      check("reserveAlpha-corpusState-camelCase-alias-used", reservation.corpus_state === "corpus-camel",
        `expected corpus_state "corpus-camel" via camelCase alias, got ${reservation.corpus_state}`);
      check("reserveAlpha-splitHash-camelCase-alias-used", reservation.split_hash === "split-camel",
        `expected split_hash "split-camel" via camelCase alias, got ${reservation.split_hash}`);
    });
  } catch (e) { report("reserve-alpha-camel-case-aliases", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- `_observe`'s three-part gate, exercised through observeSlot directly ---- */
function observeSlotGating() {
  const root = tempRoot("observe-gate");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });

      // (1) No window admitted at all -> null.
      check("observeSlot-no-window-returns-null", store.observeSlot("run-a", "tree-a") === null,
        "observeSlot against NO_WINDOW must return null");

      // (2) A window admitted but NOT yet finalized (still ADMITTED, not OBSERVING) -> null.
      store.window.admitPending({ txid: "tx-gate", fingerprint: "fp-gate", tree_id: "tree-gate", n: 3 });
      check("observeSlot-window-still-admitted-not-observing-returns-null",
        store.observeSlot("run-b", "tree-gate") === null,
        "observeSlot against a window that is ADMITTED but not yet finalized to OBSERVING must return null");

      store.window.finalize("tx-gate");

      // (3) OBSERVING, but the WRONG tree_id -> null.
      check("observeSlot-wrong-tree-id-returns-null",
        store.observeSlot("run-c", "some-other-tree") === null,
        "observeSlot for a tree_id that does not match the OBSERVING window's own tree_id must return null");

      // (4) OBSERVING, correct tree_id -> a real slot.
      const slot = store.observeSlot("run-d", "tree-gate");
      check("observeSlot-correct-state-and-tree-returns-a-slot", Boolean(slot) && slot.run_id === "run-d",
        `expected a real slot for run-d, got ${JSON.stringify(slot)}`);

      // (5) Idempotent re-observe: calling AGAIN for the SAME runId returns the SAME slot,
      // and does not bump admitted/active a second time.
      const before = store.window.get().window;
      const reobserved = store.observeSlot("run-d", "tree-gate");
      const after = store.window.get().window;
      check("observeSlot-idempotent-returns-same-slot-id", Boolean(reobserved) && reobserved.slot_id === slot.slot_id,
        `re-observing the same run must return the SAME slot_id, got ${JSON.stringify(reobserved)} vs original ${JSON.stringify(slot)}`);
      check("observeSlot-idempotent-does-not-double-admit",
        after.admitted === before.admitted && after.active === before.active,
        `re-observing an already-slotted run must not change admitted/active counts: before=${JSON.stringify(before)} after=${JSON.stringify(after)}`);
    });
  } catch (e) { report("observe-slot-gating", "FAIL", e.message); }
  finally { rmrf(root); }
}

function main() {
  admitPendingPrimaryAliasSpellings();
  setAnchorCamelCaseAliases();
  reserveAlphaCamelCaseAliases();
  observeSlotGating();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
