#!/usr/bin/env node
"use strict";

/* tests/state-store/idempotent-replays/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. Three of the ledger-style methods
 * have an explicit "I've already done this, return the cached result" fast path -- exact-
 * duplicate reservations in reserveAlpha (scripts/state-store.js:1358-1359), a second
 * completeAlpha for the same reservation_id (:1394-1395), and a second ackRollback for the
 * same fingerprint (:1471-1472). All three exist specifically so a retried caller (the
 * documented lock-contention retry pattern used throughout this codebase) never double-
 * commits. None of the three is exercised by calling the same operation twice with the same
 * identity -- every existing test either reserves/completes/acks something NEW each time, or
 * exercises only the REFUSAL paths (family already consumed, alpha exhausted, unknown
 * fingerprint). */

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

function tempRoot(label) { return fs.mkdtempSync(path.join(os.tmpdir(), `gs-idempotent-${label}-`)); }
function rmrf(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
function withEnv(patch, fn) {
  const prev = {};
  for (const k of Object.keys(patch)) { prev[k] = process.env[k]; if (patch[k] === undefined) delete process.env[k]; else process.env[k] = patch[k]; }
  try { return fn(); } finally { for (const k of Object.keys(patch)) { if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k]; } }
}
function createStore(root, opts = {}) { return rawCreateStore(root, Object.assign({ clock: createManualClock() }, opts)); }

function readJournalEntryCount(root) {
  const journalPath = path.join(root, ".graphsmith", "state", "state-journal.jsonl");
  try { return fs.readFileSync(journalPath, "utf8").split("\n").filter(Boolean).length; }
  catch (e) { if (e.code === "ENOENT") return 0; throw e; }
}

/* ---- reserveAlpha: an EXACT duplicate (same corpus_state, split_hash, fingerprint, family)
 * must return the cached reservation, not consume a second slot or write a second record. ---- */
function reserveAlphaExactDuplicateIsIdempotent() {
  const root = tempRoot("reserve-exact");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const input = { corpus_state: "corpus-dup", split_hash: "split-dup", fingerprint: "fp-dup", family: "fam-dup" };
      const first = store.alphaLedger.reserve(input);
      const journalCountAfterFirst = readJournalEntryCount(root);

      const second = store.alphaLedger.reserve({ ...input });
      check("reserve-alpha-exact-duplicate-returns-same-reservation-id",
        second.reservation_id === first.reservation_id && second.alpha_slot === first.alpha_slot,
        `an exact-duplicate reservation must return the SAME reservation, got first=${JSON.stringify(first)} second=${JSON.stringify(second)}`);

      const journalCountAfterSecond = readJournalEntryCount(root);
      check("reserve-alpha-exact-duplicate-does-not-append-journal",
        journalCountAfterSecond === journalCountAfterFirst,
        `a cached-duplicate reservation must not write a new journal entry: before=${journalCountAfterFirst} after=${journalCountAfterSecond}`);

      // A THIRD, genuinely new reservation (different family) must still take slot 2, not be
      // blocked by treating the duplicate as if it had consumed an extra slot.
      const third = store.alphaLedger.reserve({ corpus_state: "corpus-dup", split_hash: "split-3", fingerprint: "fp-3", family: "fam-3" });
      check("reserve-alpha-duplicate-did-not-burn-an-extra-slot", third.alpha_slot === 2,
        `expected the next genuinely new reservation to take slot 2 (the duplicate must not have consumed one), got slot ${third.alpha_slot}`);
    });
  } catch (e) { report("reserve-alpha-exact-duplicate-is-idempotent", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- completeAlpha: completing the SAME reservation_id twice returns the cached completion
 * record, not a second COMPLETED entry. ---- */
function completeAlphaDoubleCompleteIsIdempotent() {
  const root = tempRoot("complete-double");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      const reservation = store.alphaLedger.reserve({ corpus_state: "corpus-comp", split_hash: "s1", fingerprint: "f1", family: "fam-comp" });
      const first = store.alphaLedger.complete(reservation.reservation_id, { verdict: "promote" });
      const second = store.alphaLedger.complete(reservation.reservation_id, { verdict: "SOMETHING DIFFERENT" });

      check("complete-alpha-double-complete-returns-first-outcome-not-second",
        JSON.stringify(second.outcome) === JSON.stringify(first.outcome) && second.outcome.verdict === "promote",
        `a second complete() for the same reservation must return the CACHED first outcome, not process the new argument; ` +
        `first=${JSON.stringify(first.outcome)} second=${JSON.stringify(second.outcome)}`);

      const completedRecords = store.alphaLedger.list().filter((r) => r.record_type === "COMPLETED" && r.reservation_id === reservation.reservation_id);
      check("complete-alpha-double-complete-writes-only-one-record", completedRecords.length === 1,
        `expected exactly one COMPLETED record for this reservation, got ${completedRecords.length}`);
    });
  } catch (e) { report("complete-alpha-double-complete-is-idempotent", "FAIL", e.message); }
  finally { rmrf(root); }
}

/* ---- ackRollback: acknowledging the SAME fingerprint twice returns the cached HUMAN_ACK,
 * not a second one, and does not overwrite the recorded acknowledgement. ---- */
function ackRollbackDoubleAckIsIdempotent() {
  const root = tempRoot("ack-double");
  try {
    withEnv({ GRAPHSMITH_TEST_MODE: "1" }, () => {
      const store = createStore(root, { leaseMs: 5000, heartbeatMs: 500 });
      store.rollbackFamilies.append({ fingerprint: "fp-ack", family: "fam-ack", evidence: { e: 1 } });
      const first = store.rollbackFamilies.humanAck("fp-ack", { by: "alice" });
      const second = store.rollbackFamilies.humanAck("fp-ack", { by: "bob" });

      check("ack-rollback-double-ack-returns-first-acknowledgement-not-second",
        second.acknowledgement.by === "alice",
        `a second humanAck() for the same fingerprint must return the CACHED first acknowledgement, ` +
        `not the new one; first=${JSON.stringify(first.acknowledgement)} second=${JSON.stringify(second.acknowledgement)}`);

      const rollbackRaw = fs.readFileSync(path.join(root, ".graphsmith", "state", "rollback-families.jsonl"), "utf8");
      const ackRecords = rollbackRaw.split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.record_type === "HUMAN_ACK" && r.fingerprint === "fp-ack");
      check("ack-rollback-double-ack-writes-only-one-record", ackRecords.length === 1,
        `expected exactly one HUMAN_ACK record for this fingerprint, got ${ackRecords.length}`);

      // Once acknowledged, the fingerprint must not reappear in the unacknowledged list --
      // regardless of how many times it was acked.
      const unacked = store.rollbackFamilies.list();
      check("ack-rollback-acknowledged-fingerprint-excluded-from-unacked-list",
        !unacked.some((r) => r.fingerprint === "fp-ack"),
        `an acknowledged fingerprint must not appear in the unacknowledged rollback list, got ${JSON.stringify(unacked)}`);
    });
  } catch (e) { report("ack-rollback-double-ack-is-idempotent", "FAIL", e.message); }
  finally { rmrf(root); }
}

function main() {
  reserveAlphaExactDuplicateIsIdempotent();
  completeAlphaDoubleCompleteIsIdempotent();
  ackRollbackDoubleAckIsIdempotent();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
