#!/usr/bin/env node
"use strict";

/* tests/state-store/journal-and-status/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. Two gaps:
 *
 *   - `_recoverJournal`'s CORRUPT_JOURNAL path (scripts/state-store.js:907) is distinct from
 *     AMBIGUOUS_RECOVERY (already covered by tests/state-store/grok's crash-recovery case):
 *     AMBIGUOUS_RECOVERY fires when the CURRENT on-disk file matches neither the intent's
 *     recorded before- nor after-hash; CORRUPT_JOURNAL fires when the intent's OWN payload
 *     (`content_base64`) does not hash to its OWN recorded `after_sha256` -- the journal
 *     entry contradicts itself, independent of what is on disk. Nothing constructs that.
 *
 *   - `status()` (scripts/state-store.js:1498-1511) is called throughout the other suites
 *     only to trigger directory creation as a side effect; nothing asserts its actual
 *     returned shape once every category it reports on (window, runs, alpha reservations,
 *     rejected count, unacknowledged rollback families) has real, non-empty data. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const { createStore: rawCreateStore, SCHEMA_VERSION } = require(STATE_STORE);
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

function tempRoot(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `gs-journal-status-${label}-`)); }
function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
function withEnv(patch, fn) {
  const prev = {};
  for (const k of Object.keys(patch)) { prev[k] = process.env[k]; if (patch[k] === undefined) delete process.env[k]; else process.env[k] = patch[k]; }
  try { return fn(); } finally { for (const k of Object.keys(patch)) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; } }
}
function createStore(root, opts = {}) { return rawCreateStore(root, Object.assign({ clock: createManualClock() }, opts)); }
function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }

/* ---- CORRUPT_JOURNAL: the intent's own content_base64 does not hash to its own
 * after_sha256 ---- */
function corruptJournalPayloadIsDetected() {
  const root = tempRoot("corrupt-journal");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store._ensureStateDir();
      // Establish a known, real window.json so this effect's `before_sha256` can genuinely
      // match the current on-disk content (required to reach the apply branch rather than
      // AMBIGUOUS_RECOVERY, which fires when neither before nor after matches).
      // window.json does not exist on disk until the first commit touches it; `_read`
      // returns "" for that case (matching what recovery's own `_read` will see), so that
      // is the "before" content this effect must claim to start from.
      const beforeContent = store._read("window.json");
      const beforeHash = sha256(beforeContent);

      // A self-contradictory MUTATION_INTENT: content_base64 decodes to something that does
      // NOT hash to its own recorded after_sha256. Constructed directly (bypassing _commit
      // entirely) since _commit always computes a consistent after_sha256 from what it
      // actually writes -- this journal-internal inconsistency can only arise from a
      // corrupted/tampered journal file, which is exactly the fault this test simulates.
      const mutationId = "mutation-corrupt-journal-1";
      const intentRecord = {
        schema_version: SCHEMA_VERSION,
        record_type: "MUTATION_INTENT",
        mutation_id: mutationId,
        state_rev: 999,
        effects: [{
          file: "window.json",
          before_sha256: beforeHash,
          after_sha256: "f".repeat(64), // deliberately does not match the payload below
          content_base64: Buffer.from(beforeContent, "utf8").toString("base64"),
        }],
      };
      const journalPath = path.join(root, ".graphsmith", "state", "state-journal.jsonl");
      fs.appendFileSync(journalPath, `${JSON.stringify(intentRecord)}\n`);

      let threw = null;
      try { createStore(root, { leaseMs: 5000, heartbeatMs: 500 }).window.get(); }
      catch (e) { threw = e; }
      check("corrupt-journal-payload-throws-corrupt-journal",
        Boolean(threw) && threw.code === "CORRUPT_JOURNAL",
        `a journal intent whose content_base64 does not hash to its own after_sha256 must throw CORRUPT_JOURNAL, got ${threw ? threw.code : "no error"}`);
      check("corrupt-journal-message-names-mutation-id",
        Boolean(threw) && threw.message.includes(mutationId),
        `expected the CORRUPT_JOURNAL message to name the mutation_id "${mutationId}", got ${threw && threw.message}`);
    });
  } catch (e) { report("corrupt-journal-payload-is-detected", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- status(): every field, with real non-empty data in every category ---- */
function statusReportsEveryCategoryAccurately() {
  const root = tempRoot("status-full");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });

      store.window.admitPending({ txid: "tx-status", fingerprint: "fp-status", tree_id: "t-status", n: 2 });
      store.window.finalize("tx-status");
      store.runRegistry.register("run-status-1", "t-status");
      store.runRegistry.register("run-status-2", "t-status");

      store.alphaLedger.reserve({ corpus_state: "cs-status", split_hash: "s1", fingerprint: "f1", family: "fam-status-1" });
      store.alphaLedger.reserve({ corpus_state: "cs-status", split_hash: "s2", fingerprint: "f2", family: "fam-status-2" });

      store.rejectedBuffer.push({ fingerprint: "rej-status-1", value: { a: 1 } });
      store.rejectedBuffer.push({ fingerprint: "rej-status-2", value: { a: 2 } });

      store.rollbackFamilies.append({ fingerprint: "rb-status-ack", family: "fam-rb-1", evidence: {} });
      store.rollbackFamilies.humanAck("rb-status-ack", { by: "tester" });
      store.rollbackFamilies.append({ fingerprint: "rb-status-open", family: "fam-rb-2", evidence: {} });

      const status = store.status();

      check("status-schema-version", status.schema_version === SCHEMA_VERSION, `expected schema_version ${SCHEMA_VERSION}, got ${status.schema_version}`);
      check("status-window-reflects-state", status.window.state === "OBSERVING" && status.window.window.tree_id === "t-status",
        `expected the admitted/finalized window reflected in status, got ${JSON.stringify(status.window)}`);
      check("status-runs-includes-both-registered-runs",
        Array.isArray(status.runs) && status.runs.length === 2 && status.runs.every((r) => r.tree_id === "t-status"),
        `expected 2 registered runs under t-status, got ${JSON.stringify(status.runs)}`);
      check("status-alpha-reservations-counts-only-reserved", status.alpha_reservations === 2,
        `expected alpha_reservations:2, got ${status.alpha_reservations}`);
      check("status-rejected-count-matches-pushed-entries", status.rejected_count === 2,
        `expected rejected_count:2, got ${status.rejected_count}`);
      check("status-rollback-families-unacknowledged-excludes-acked",
        status.rollback_families_unacknowledged === 1,
        `expected exactly 1 unacknowledged rollback family (the acked one excluded), got ${status.rollback_families_unacknowledged}`);
    });
  } catch (e) { report("status-reports-every-category-accurately", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- getRun(): an unknown runId returns null, not undefined or a throw ---- */
function getRunUnknownReturnsNull() {
  const root = tempRoot("get-run-unknown");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.runRegistry.register("run-known", "tree-known");
      check("get-run-unknown-returns-exactly-null", store.getRun("run-does-not-exist") === null,
        `getRun() for an unknown runId must return exactly null, got ${JSON.stringify(store.getRun("run-does-not-exist"))}`);
      check("get-run-known-still-returns-the-record", store.getRun("run-known") !== null && store.getRun("run-known").run_id === "run-known",
        "sanity: a known run must still be returned by getRun()");
    });
  } catch (e) { report("get-run-unknown-returns-null", "FAIL", e.message); }
  finally { rmrf(root); }
}

function main() {
  corruptJournalPayloadIsDetected();
  statusReportsEveryCategoryAccurately();
  getRunUnknownReturnsNull();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
