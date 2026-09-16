#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/chain.js (SG-FR-5) + checks/register-gateway-
 * sessions.js (SG-FR-7). Covers Standalone Gateway TRD SS8 test plan items:
 *   7  ten sessions in sequence -> chain.jsonl has 10 correctly-linked entries, HEAD.json
 *      matches the tenth, the verifier reports the chain intact.
 *   8  a real, untouched chain from test fixture data verifies successfully (not only
 *      self-generated data).
 *   12 process killed mid-append (between the bundle write and HEAD.json update) ->
 *      restart's verifier detects the incomplete append and reports it explicitly.
 *   16 a middle chain entry is mutated -> verifier fails closed, names the broken link.
 *   17 a chain entry is deleted entirely (sequence gap) -> detected and reported,
 *      DISTINCT from a broken-hash-link failure.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const chain = require(path.join(ROOT, "scripts", "gateway", "chain.js"));
const session = require(path.join(ROOT, "scripts", "gateway", "session.js"));
const { walkGatewaySessions } = require(path.join(ROOT, "checks", "register-gateway-sessions.js"));

let failures = 0;
const results = [];
function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}
function check(name, cond, reason) {
  record(name, cond ? "PASS" : "FAIL", reason);
}

function freshDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-chain-${prefix}-`));
}
function makeKeys() {
  const kp = crypto.generateKeyPairSync("ed25519");
  return { privateKey: kp.privateKey, signer: "test-key", algo: "ed25519" };
}
function sealTrivialSession(connectionId, keys) {
  const s = session.createSession(connectionId);
  /* gsa-mcp-shim.js's bundle_id is a deterministic hash of {init, grantedTools, n}, not
   * of connectionId -- two "trivial" sessions with identical initialize/tools/calls
   * content would otherwise collide on bundle_id (a real, useful property being
   * exercised here: content-addressing means genuinely-identical sessions ARE the same
   * bundle). Varying clientInfo.name by connectionId gives each test session distinct
   * content so this suite can create many independent chain entries. */
  session.recordInitialize(s, { clientInfo: { name: `test-agent-${connectionId}`, version: "1.0" } });
  session.recordToolsList(s, []);
  return session.finalizeSession(s, keys);
}
function verifyDir(dir, extra) {
  return walkGatewaySessions({
    chain: chain.readChain(dir),
    head: chain.readHead(dir),
    computeEntrySha256: chain.computeEntrySha256,
    bundleExists: (id) => fs.existsSync(chain.bundlePath(dir, id)),
    ...extra,
  });
}

/* SS8 test 7 */
function tenSessionsInSequence() {
  const dir = freshDir("ten-sessions");
  const keys = makeKeys();
  const entries = [];
  for (let i = 0; i < 10; i++) {
    const sealed = sealTrivialSession(`conn-${i}`, keys);
    entries.push(chain.appendSession(dir, sealed));
  }
  check("ten-sessions-seq-1-through-10", entries.every((e, i) => e.seq === i + 1), JSON.stringify(entries.map((e) => e.seq)));
  check("ten-sessions-each-links-to-prior", entries.every((e, i) => i === 0 ? e.prev_entry_sha256 === null : e.prev_entry_sha256 === entries[i - 1].entry_sha256), "link chain broken");
  const head = chain.readHead(dir);
  check("head-matches-tenth-entry", head.seq === 10 && head.entry_sha256 === entries[9].entry_sha256, JSON.stringify(head));
  const result = verifyDir(dir);
  check("verifier-reports-chain-intact", result.status === "verified", JSON.stringify(result));
}

/* SS8 test 8: fixture data generated in ONE process/run, verified in a completely
 * separate call -- not the same in-memory objects the append path just produced. */
function fixtureDataVerifiesIndependently() {
  const dir = freshDir("fixture");
  const keys = makeKeys();
  for (let i = 0; i < 3; i++) chain.appendSession(dir, sealTrivialSession(`fixture-conn-${i}`, keys));
  // Re-read everything fresh from disk, as an independent verifier run would.
  const freshChain = JSON.parse(`[${fs.readFileSync(chain.chainPath(dir), "utf8").trim().split("\n").join(",")}]`);
  const freshHead = JSON.parse(fs.readFileSync(chain.headPath(dir), "utf8"));
  const result = walkGatewaySessions({
    chain: freshChain,
    head: freshHead,
    computeEntrySha256: chain.computeEntrySha256,
    bundleExists: (id) => fs.existsSync(chain.bundlePath(dir, id)),
  });
  check("independently-reread-fixture-verifies", result.status === "verified", JSON.stringify(result));
}

/* SS8 test 12: simulate a crash between the chain.jsonl append and the HEAD.json update
 * -- append the entry to chain.jsonl but do NOT update HEAD.json (this is exactly the
 * on-disk state a kill between those two steps leaves, per SS3.6's write ordering). */
function incompleteAppendDetected() {
  const dir = freshDir("incomplete-append");
  const keys = makeKeys();
  const entry1 = chain.appendSession(dir, sealTrivialSession("conn-a", keys));
  // Second session: write bundle + chain entry manually, WITHOUT updating HEAD.json,
  // to simulate the crash window.
  const sealed2 = sealTrivialSession("conn-b", keys);
  const bundleId2 = sealed2.bundle.manifest.bundle_id;
  fs.writeFileSync(chain.bundlePath(dir, bundleId2), JSON.stringify(sealed2.bundle));
  const partial = { schema_version: "1.0", seq: 2, bundle_id: bundleId2, prev_entry_sha256: entry1.entry_sha256 };
  const entry2 = { ...partial, entry_sha256: chain.computeEntrySha256(partial) };
  fs.appendFileSync(chain.chainPath(dir), JSON.stringify(entry2) + "\n");
  // HEAD.json still points at entry1 -- exactly the "stale head" incomplete-append shape.

  const result = verifyDir(dir);
  check("incomplete-append-detected-as-failed", result.status === "failed", JSON.stringify(result));
  check("incomplete-append-reason-names-incomplete-append", /incomplete append/.test(result.reason || ""), JSON.stringify(result));
}

/* SS8 test 16: mutate a middle entry's entry_sha256. */
function mutatedEntryDetected() {
  const dir = freshDir("mutated");
  const keys = makeKeys();
  for (let i = 0; i < 3; i++) chain.appendSession(dir, sealTrivialSession(`conn-${i}`, keys));
  const lines = fs.readFileSync(chain.chainPath(dir), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  lines[1].entry_sha256 = "f".repeat(64); // mutate the middle entry
  fs.writeFileSync(chain.chainPath(dir), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");

  const result = verifyDir(dir);
  check("mutated-middle-entry-fails-closed", result.status === "failed", JSON.stringify(result));
  check("mutated-entry-reason-names-tampered", /TAMPERED/.test(result.reason || ""), JSON.stringify(result));
}

/* SS8 test 17: delete an entire entry (sequence gap), distinct failure text from a
 * mutated/broken-link failure. */
function deletedEntryDetectedDistinctly() {
  const dir = freshDir("deleted");
  const keys = makeKeys();
  for (let i = 0; i < 5; i++) chain.appendSession(dir, sealTrivialSession(`conn-${i}`, keys));
  const lines = fs.readFileSync(chain.chainPath(dir), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  lines.splice(2, 1); // delete seq=3 entirely -> gap 2, 4, 5
  fs.writeFileSync(chain.chainPath(dir), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");

  const result = walkGatewaySessions({ chain: lines, head: null, computeEntrySha256: chain.computeEntrySha256 });
  check("deleted-entry-detected-as-failed", result.status === "failed", JSON.stringify(result));
  check("deleted-entry-reason-names-sequence-gap-distinctly", /SEQUENCE GAP/.test(result.reason || "") && !/TAMPERED/.test(result.reason || ""), JSON.stringify(result));
}

/* Board decision 2026-09-04, PR #29 review "require the verified chain to start at
 * sequence one": a chain whose surviving first entry has seq > 1 but an otherwise
 * self-consistent (recomputable, null-predecessor) hash must still be rejected --
 * distinct from deletedEntryDetectedDistinctly above, which deletes a MIDDLE entry and
 * leaves a real seq gap; this forges the FIRST entry to look like a legitimate root. */
function missingGenesisPrefixDetected() {
  const dir = freshDir("missing-genesis");
  const keys = makeKeys();
  for (let i = 0; i < 2; i++) chain.appendSession(dir, sealTrivialSession(`conn-${i}`, keys));
  const lines = fs.readFileSync(chain.chainPath(dir), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const forged = { ...lines[1], prev_entry_sha256: null };
  forged.entry_sha256 = chain.computeEntrySha256({ schema_version: forged.schema_version, seq: forged.seq, bundle_id: forged.bundle_id, prev_entry_sha256: forged.prev_entry_sha256 });

  const result = walkGatewaySessions({ chain: [forged], head: null, computeEntrySha256: chain.computeEntrySha256 });
  check("missing-genesis-prefix-detected-as-failed", result.status === "failed", JSON.stringify(result));
  check("missing-genesis-prefix-reason-names-seq-not-one", /seq=2, expected 1/.test(result.reason || ""), JSON.stringify(result));
}

function bundleIdCollisionRefused() {
  const dir = freshDir("collision");
  const keys = makeKeys();
  const sealed = sealTrivialSession("conn-x", keys);
  chain.appendSession(dir, sealed);
  let threw = null;
  try { chain.appendSession(dir, sealed); } catch (error) { threw = error; } // same bundle_id (deterministic from session content)
  check("bundle-id-collision-refused", threw && threw.code === "GATEWAY_BUNDLE_ID_COLLISION", threw && threw.code);
}

function emptyChainIsNotApplicable() {
  const dir = freshDir("empty");
  fs.mkdirSync(dir, { recursive: true });
  const result = verifyDir(dir);
  check("empty-chain-not-applicable", result.status === "not-applicable", JSON.stringify(result));
}

/* ==================================================================================
 * C2 (docs/contracts/chain-validity.md) -- commit 3: validateChain + readChainTail.
 * ================================================================================== */

function mkEntry(seq, prev, bundleId) {
  const partial = { schema_version: "1.0", seq, bundle_id: bundleId, prev_entry_sha256: prev };
  return { ...partial, entry_sha256: chain.computeEntrySha256(partial) };
}
function mkHeadFor(entry) {
  return { schema_version: "1.0", seq: entry.seq, bundle_id: entry.bundle_id, entry_sha256: entry.entry_sha256 };
}
function line(entry) {
  return JSON.stringify(entry);
}
function writeChainFile(dir, text) {
  fs.mkdirSync(chain.sessionsDir(dir), { recursive: true });
  fs.writeFileSync(chain.chainPath(dir), text);
}

/* ---- validateChain: rows 1/2 (empty states) ---- */

function validateChainEmptyGenesisIsNotAFailure() {
  const result = chain.validateChain([], null);
  check("validate-chain-empty-genesis-is-not-a-failure", result.status === "empty", JSON.stringify(result));
}

function validateChainEmptyWithHeadRefuses() {
  const e1 = mkEntry(1, null, "b1");
  const result = chain.validateChain([], mkHeadFor(e1));
  check("validate-chain-empty-with-head-refuses", result.status === "refuse" && result.class === "empty-chain-with-head", JSON.stringify(result));
}

/* ---- validateChain: rows 5/6/8 (structural/integrity failures -- refuse-and-latch) ---- */

function validateChainDetectsSequenceGap() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const e3 = mkEntry(3, e2.entry_sha256, "b3");
  const result = chain.validateChain([e1, e3], null); // e2 deleted -> gap
  check("validate-chain-detects-sequence-gap", result.status === "refuse" && result.class === "sequence-gap", JSON.stringify(result));
}

function validateChainDetectsDuplicateSeqAsFork() {
  const e1 = mkEntry(1, null, "b1");
  const e2a = mkEntry(2, e1.entry_sha256, "b2a");
  const e2b = mkEntry(2, e1.entry_sha256, "b2b"); // same seq, different bundle+hash
  const result = chain.validateChain([e1, e2a, e2b], null);
  check("validate-chain-detects-duplicate-seq-as-fork", result.status === "refuse" && result.class === "fork", JSON.stringify(result));
}

function validateChainDetectsTamperedEntry() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const tampered = { ...e2, entry_sha256: "9".repeat(64) };
  const result = chain.validateChain([e1, tampered], null);
  check("validate-chain-detects-tampered-entry", result.status === "refuse" && result.class === "tampered" && result.at === 1, JSON.stringify(result));
}

function validateChainDetectsBrokenLink() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, "d".repeat(64), "b2"); // internally hash-consistent, wrong link
  const result = chain.validateChain([e1, e2], null);
  check("validate-chain-detects-broken-link", result.status === "refuse" && result.class === "broken-link", JSON.stringify(result));
}

function validateChainDetectsInvalidGenesisSeq() {
  const forged = mkEntry(2, null, "b1"); // hash-consistent, but not seq=1
  const result = chain.validateChain([forged], null);
  check("validate-chain-detects-invalid-genesis-seq", result.status === "refuse" && result.class === "invalid-genesis", JSON.stringify(result));
}

function validateChainDetectsInvalidGenesisPrev() {
  const forged = mkEntry(1, "a".repeat(64), "b1"); // seq=1 but prev != null
  const result = chain.validateChain([forged], null);
  check("validate-chain-detects-invalid-genesis-prev", result.status === "refuse" && result.class === "invalid-genesis", JSON.stringify(result));
}

function validateChainRefusesMalformedInteriorRecordNotJustTheLast() {
  const e1 = mkEntry(1, null, "b1");
  const e3 = mkEntry(3, "irrelevant-since-interior-is-what-fails", "b3");
  // null in the MIDDLE (not the physical last position) must never get the
  // torn-tail accommodation -- always refuse, per C2 row 8.
  const result = chain.validateChain([e1, null, e3], null);
  check("validate-chain-refuses-malformed-interior-record", result.status === "refuse" && result.class === "malformed-interior" && result.at === 1, JSON.stringify(result));
}

/* ---- validateChain: row 7 (mid-run lagging HEAD, single-step, hash-verified) ---- */

function validateChainAutoAdvancesSingleStepLaggingHead() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const e3 = mkEntry(3, e2.entry_sha256, "b3");
  const result = chain.validateChain([e1, e2, e3], mkHeadFor(e2));
  check("validate-chain-auto-advances-single-step-lagging-head", result.status === "reconcilable" && result.headAction === "advance" && result.tail.seq === 3, JSON.stringify(result));
  check("validate-chain-single-step-lag-emits-a-loud-anomaly", typeof result.anomaly === "string" && result.anomaly.length > 0, JSON.stringify(result));
}

function validateChainRefusesMultiStepLaggingHead() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const e3 = mkEntry(3, e2.entry_sha256, "b3");
  const result = chain.validateChain([e1, e2, e3], mkHeadFor(e1)); // two steps behind
  check("validate-chain-refuses-multi-step-lagging-head", result.status === "refuse" && result.class === "multi-step-lag", JSON.stringify(result));
}

function validateChainRefusesHeadAheadOfTail() {
  const e1 = mkEntry(1, null, "b1");
  const fakeAhead = { schema_version: "1.0", seq: 2, bundle_id: "ghost", entry_sha256: "b".repeat(64) };
  const result = chain.validateChain([e1], fakeAhead);
  check("validate-chain-refuses-head-ahead-of-tail", result.status === "refuse" && result.class === "head-ahead-of-tail", JSON.stringify(result));
}

function validateChainRefusesHeadSameSeqDifferentHashAsFork() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const forkedHead = { schema_version: "1.0", seq: 2, bundle_id: "b2-other", entry_sha256: "c".repeat(64) };
  const result = chain.validateChain([e1, e2], forkedHead);
  check("validate-chain-refuses-head-same-seq-different-hash-as-fork", result.status === "refuse" && result.class === "fork", JSON.stringify(result));
}

function validateChainRefusesOneStepBackHeadThatIsNotAGenuineAncestor() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  // seq is exactly one behind tail (looks like row 7 at a glance) but its hash does
  // not actually match tail.prev_entry_sha256 -- must NOT auto-catch-up.
  const notAnAncestor = { schema_version: "1.0", seq: 1, bundle_id: "b1-impostor", entry_sha256: "e".repeat(64) };
  const result = chain.validateChain([e1, e2], notAnAncestor);
  check("validate-chain-refuses-one-step-back-head-that-is-not-a-genuine-ancestor", result.status === "refuse" && result.class === "head-not-ancestor", JSON.stringify(result));
}

/* ---- validateChain: rows 3/4 (HEAD absent/unusable -- rebuild from verified tail) ---- */

function validateChainRebuildsMissingHeadFromVerifiedTail() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const result = chain.validateChain([e1, e2], null);
  check("validate-chain-rebuilds-missing-head-from-verified-tail", result.status === "reconcilable" && result.headAction === "rebuild" && result.tail.seq === 2, JSON.stringify(result));
}

function validateChainDoesNotRebuildWhenTheChainItselfDoesNotValidate() {
  const e1 = mkEntry(1, null, "b1");
  // Shape-valid (64-hex prev), but wrong link AND a sequence gap -- HEAD being
  // absent must never bypass the structural walk and rebuild blindly.
  const e3 = mkEntry(3, "d".repeat(64), "b3");
  const result = chain.validateChain([e1, e3], null);
  check("validate-chain-does-not-rebuild-when-the-chain-itself-does-not-validate", result.status === "refuse", JSON.stringify(result));
}

/* ---- validateChain: row 9 (torn/unparseable FINAL record) ---- */

function validateChainTruncatesTornFinalRecordAndRebuildsHead() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  // `null` stands in for "this physical line could not be parsed at all" (per
  // validateChain's own documented input contract).
  const result = chain.validateChain([e1, e2, null], null);
  check("validate-chain-truncates-torn-final-record-and-rebuilds-head", result.status === "reconcilable" && result.truncatedTail === true && result.headAction === "rebuild" && result.tail.seq === 2, JSON.stringify(result));
}

function validateChainTornFinalRecordWithHeadAlreadyAtTheTruncatedTailStillReportsReconciliation() {
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  // HEAD already matches what the truncated chain's tail will be -- this must NOT
  // be silently reported as "valid" (nothing to do): the on-disk garbage still
  // needs isolating/truncating, so it must surface as a reconciliation action.
  const result = chain.validateChain([e1, e2, null], mkHeadFor(e2));
  check("validate-chain-torn-tail-with-head-already-consistent-still-reconciles-not-silently-valid", result.status === "reconcilable" && result.truncatedTail === true, JSON.stringify(result));
}

function validateChainTornSoleGenesisRecordWithNoHeadReconcilesToEmptyTail() {
  const result = chain.validateChain([null], null);
  check("validate-chain-torn-sole-genesis-record-with-no-head-reconciles-to-empty-tail", result.status === "reconcilable" && result.tail === null && result.truncatedTail === true, JSON.stringify(result));
}

function validateChainTornSoleRecordWithHeadPresentRefuses() {
  const ghostHead = { schema_version: "1.0", seq: 1, bundle_id: "ghost", entry_sha256: "f".repeat(64) };
  const result = chain.validateChain([null], ghostHead);
  check("validate-chain-torn-sole-record-with-head-present-refuses", result.status === "refuse", JSON.stringify(result));
}

function validateChainNeverConflatesTornTailWithInteriorCorruption() {
  // A shape-VALID final record whose hash simply does not recompute is TAMPERING,
  // not a torn write -- must be refused via the ordinary hash check, never given
  // the row-9 accommodation.
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const tamperedTail = { ...e2, entry_sha256: "7".repeat(64) };
  const result = chain.validateChain([e1, tamperedTail], null);
  check("validate-chain-never-conflates-a-tampered-tail-with-a-torn-tail", result.status === "refuse" && result.class === "tampered", JSON.stringify(result));
}

/* ---- readChainTail: absent / empty / corrupt stay three distinct outcomes ---- */

function readChainTailAbsentWhenFileDoesNotExist() {
  const dir = freshDir("tail-absent");
  fs.mkdirSync(dir, { recursive: true }); // no gateway-sessions/ dir at all
  const result = chain.readChainTail(dir);
  check("read-chain-tail-absent-when-file-does-not-exist", result.status === "absent", JSON.stringify(result));
}

function readChainTailEmptyWhenFileIsZeroBytes() {
  const dir = freshDir("tail-zero-bytes");
  writeChainFile(dir, "");
  const result = chain.readChainTail(dir);
  check("read-chain-tail-empty-when-file-is-zero-bytes", result.status === "empty", JSON.stringify(result));
}

function readChainTailEmptyWhenFileIsOnlyBlankLines() {
  const dir = freshDir("tail-blank-only");
  writeChainFile(dir, "\n\n\n");
  const result = chain.readChainTail(dir);
  check("read-chain-tail-empty-when-file-is-only-blank-lines", result.status === "empty", JSON.stringify(result));
}

function readChainTailSucceedsWithTrailingNewline() {
  const dir = freshDir("tail-trailing-nl");
  const e1 = mkEntry(1, null, "b1");
  writeChainFile(dir, line(e1) + "\n");
  const result = chain.readChainTail(dir);
  check("read-chain-tail-succeeds-with-trailing-newline", result.status === "ok" && result.hadTrailingNewline === true && result.entry.bundle_id === "b1", JSON.stringify(result));
}

function readChainTailSucceedsWithoutTrailingNewline() {
  const dir = freshDir("tail-no-trailing-nl");
  const e1 = mkEntry(1, null, "b1");
  writeChainFile(dir, line(e1)); // no trailing \n
  const result = chain.readChainTail(dir);
  check("read-chain-tail-succeeds-without-trailing-newline", result.status === "ok" && result.hadTrailingNewline === false && result.entry.bundle_id === "b1", JSON.stringify(result));
}

function readChainTailReturnsTheSameEntryRegardlessOfTrailingNewline() {
  const dir1 = freshDir("tail-nl-a");
  const dir2 = freshDir("tail-nl-b");
  const e1 = mkEntry(1, null, "same-content");
  writeChainFile(dir1, line(e1) + "\n");
  writeChainFile(dir2, line(e1));
  const r1 = chain.readChainTail(dir1);
  const r2 = chain.readChainTail(dir2);
  check("read-chain-tail-trailing-newline-does-not-change-the-parsed-entry", r1.status === "ok" && r2.status === "ok" && JSON.stringify(r1.entry) === JSON.stringify(r2.entry), JSON.stringify({ r1, r2 }));
}

function readChainTailSkipsBlankLinesBeforeTheLastEntry() {
  const dir = freshDir("tail-blank-between");
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  writeChainFile(dir, line(e1) + "\n\n" + line(e2) + "\n");
  const result = chain.readChainTail(dir);
  check("read-chain-tail-skips-blank-lines-before-the-last-entry", result.status === "ok" && result.entry.bundle_id === "b2", JSON.stringify(result));
}

function readChainTailFindsTheLastEntryWhenTheWindowStartsMidRecord() {
  const dir = freshDir("tail-mid-record");
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const e3 = mkEntry(3, e2.entry_sha256, "b3");
  writeChainFile(dir, line(e1) + "\n" + line(e2) + "\n" + line(e3) + "\n");
  // A tiny initial window guarantees the first read starts strictly inside e3's own
  // line (no newline visible), forcing at least one grow-and-retry before success.
  const result = chain.readChainTail(dir, { initialWindowBytes: 8 });
  check("read-chain-tail-finds-the-last-entry-when-the-window-starts-mid-record", result.status === "ok" && result.entry.bundle_id === "b3", JSON.stringify(result));
}

function readChainTailGrowsPastTheInitialWindowForAnOversizedFinalRecord() {
  const dir = freshDir("tail-oversized-final");
  const e1 = mkEntry(1, null, "b1");
  const bigBundleId = "b2-" + "x".repeat(9000); // final record now well over 8 KiB
  const e2 = mkEntry(2, e1.entry_sha256, bigBundleId);
  writeChainFile(dir, line(e1) + "\n" + line(e2) + "\n");
  const result = chain.readChainTail(dir); // default 8 KiB initial window
  check("read-chain-tail-grows-past-the-initial-window-for-an-oversized-final-record", result.status === "ok" && result.entry.bundle_id === bigBundleId, JSON.stringify({ status: result.status, matched: result.status === "ok" && result.entry.bundle_id === bigBundleId }));
}

function readChainTailFindsALargeFinalRecordWhenANewlineIsAlreadyInTheFirstWindow() {
  // Distinct from the grow case above: here the record is large but the FIRST read
  // already contains the newline that starts it (no growth needed) -- exercises the
  // "final record larger than the window, but the window still contains a newline"
  // boundary without conflating it with the retry path.
  const dir = freshDir("tail-large-first-window");
  const e1 = mkEntry(1, null, "b1");
  const bigBundleId = "b2-" + "y".repeat(4000); // large, but smaller than the window
  const e2 = mkEntry(2, e1.entry_sha256, bigBundleId);
  writeChainFile(dir, line(e1) + "\n" + line(e2) + "\n");
  const result = chain.readChainTail(dir); // default 8 KiB window comfortably covers this
  check("read-chain-tail-finds-a-large-final-record-already-inside-the-first-window", result.status === "ok" && result.entry.bundle_id === bigBundleId, JSON.stringify({ status: result.status }));
}

function readChainTailFailsClosedWhenNoNewlineIsFoundWithinTheCappedWindow() {
  const dir = freshDir("tail-uncapped");
  const e1 = mkEntry(1, null, "b1");
  const hugeBundleId = "z".repeat(5000); // final record itself exceeds the test's tiny cap
  const e2 = mkEntry(2, e1.entry_sha256, hugeBundleId);
  writeChainFile(dir, line(e1) + "\n" + line(e2)); // no trailing newline either
  const result = chain.readChainTail(dir, { initialWindowBytes: 64, maxEntryBytes: 512 });
  check("read-chain-tail-fails-closed-when-no-newline-boundary-is-found-within-the-capped-window", result.status === "corrupt", JSON.stringify(result));
  check("read-chain-tail-fail-closed-does-not-fall-back-to-an-earlier-valid-record", !(result.entry && result.entry.bundle_id === "b1"), JSON.stringify(result));
}

function readChainTailReportsCorruptForATruncatedFinalRecord() {
  const dir = freshDir("tail-truncated-final");
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  const full = line(e1) + "\n" + line(e2) + "\n";
  const tornPoint = full.length - 5; // cut the last record off mid-field
  writeChainFile(dir, full.slice(0, tornPoint));
  const result = chain.readChainTail(dir);
  check("read-chain-tail-reports-corrupt-for-a-truncated-final-record", result.status === "corrupt", JSON.stringify(result));
  check("read-chain-tail-truncated-final-record-does-not-silently-return-the-earlier-valid-entry", !(result.entry && result.entry.bundle_id === "b1"), JSON.stringify(result));
}

function readChainTailReportsCorruptForAMalformedFinalRecord() {
  const dir = freshDir("tail-malformed-final");
  const e1 = mkEntry(1, null, "b1");
  writeChainFile(dir, line(e1) + "\n" + "{not even close to json\n");
  const result = chain.readChainTail(dir);
  check("read-chain-tail-reports-corrupt-for-a-malformed-final-record", result.status === "corrupt", JSON.stringify(result));
}

function readChainTailReportsCorruptWhenTheFinalRecordFailsItsShapeCheck() {
  const dir = freshDir("tail-bad-shape-final");
  const e1 = mkEntry(1, null, "b1");
  const badShape = { schema_version: "1.0", seq: 2, bundle_id: "b2" }; // missing hash fields, but VALID json
  writeChainFile(dir, line(e1) + "\n" + JSON.stringify(badShape) + "\n");
  const result = chain.readChainTail(dir);
  check("read-chain-tail-reports-corrupt-when-the-final-record-fails-its-shape-check", result.status === "corrupt", JSON.stringify(result));
}

function readChainTailHandlesUtf8BoundariesSplitAcrossTheWindowEdge() {
  const dir = freshDir("tail-utf8-boundary");
  // Multi-byte bundle_id (emoji + accented chars are 2-4 byte UTF-8 sequences) on
  // the record BEFORE the last one, positioned so a small window's left edge is
  // very likely to land inside one of its multi-byte characters -- the last
  // entry's own content must still parse correctly regardless, because only bytes
  // strictly after the boundary newline are ever decoded.
  const e1 = mkEntry(1, null, "héllo-🎉-bündle-" + "€".repeat(40));
  const e2 = mkEntry(2, e1.entry_sha256, "plain-ascii-tail-résumé-日本語");
  writeChainFile(dir, line(e1) + "\n" + line(e2) + "\n");
  // Small window forced to start somewhere inside e1's multi-byte content.
  const result = chain.readChainTail(dir, { initialWindowBytes: 20 });
  check("read-chain-tail-handles-utf8-boundaries-split-across-the-window-edge", result.status === "ok" && result.entry.bundle_id === "plain-ascii-tail-résumé-日本語", JSON.stringify(result));
}

function readChainTailUtf8LastEntryItselfSurvivesGrowth() {
  const dir = freshDir("tail-utf8-last-entry-grows");
  const e1 = mkEntry(1, null, "b1");
  // The LAST entry itself contains multi-byte UTF-8 content and is large enough
  // that the window must grow at least once to capture all of it.
  const unicodeBundleId = "🎉-" + "日".repeat(3000);
  const e2 = mkEntry(2, e1.entry_sha256, unicodeBundleId);
  writeChainFile(dir, line(e1) + "\n" + line(e2) + "\n");
  const result = chain.readChainTail(dir, { initialWindowBytes: 64 });
  check("read-chain-tail-utf8-last-entry-itself-survives-growth", result.status === "ok" && result.entry.bundle_id === unicodeBundleId, JSON.stringify({ status: result.status }));
}

function readChainTailHandlesShortReads() {
  const dir = freshDir("tail-short-reads");
  const e1 = mkEntry(1, null, "b1");
  const e2 = mkEntry(2, e1.entry_sha256, "b2");
  writeChainFile(dir, line(e1) + "\n" + line(e2) + "\n");

  const realReadSync = fs.readSync;
  let calls = 0;
  fs.readSync = function shortReadingReadSync(fd, buffer, offset, length, position) {
    calls++;
    const cappedLength = Math.min(length, 3); // force many short reads, 3 bytes at a time
    return realReadSync(fd, buffer, offset, cappedLength, position);
  };
  let result;
  try {
    result = chain.readChainTail(dir);
  } finally {
    fs.readSync = realReadSync;
  }
  check("read-chain-tail-handles-short-reads", result.status === "ok" && result.entry.bundle_id === "b2", JSON.stringify(result));
  check("read-chain-tail-short-reads-actually-exercised-multiple-calls", calls > 1, `calls=${calls}`);
}

function readChainTailAbsentEmptyCorruptAreThreeDistinctOutcomes() {
  const absentDir = freshDir("distinct-absent");
  fs.mkdirSync(absentDir, { recursive: true });
  const emptyDir = freshDir("distinct-empty");
  writeChainFile(emptyDir, "");
  const corruptDir = freshDir("distinct-corrupt");
  writeChainFile(corruptDir, "{not json\n");

  const absent = chain.readChainTail(absentDir);
  const empty = chain.readChainTail(emptyDir);
  const corrupt = chain.readChainTail(corruptDir);
  const statuses = [absent.status, empty.status, corrupt.status];
  check("read-chain-tail-absent-empty-corrupt-are-three-distinct-outcomes", new Set(statuses).size === 3 && statuses.includes("absent") && statuses.includes("empty") && statuses.includes("corrupt"), JSON.stringify(statuses));
}

/* ==================================================================================
 * Round-1 fix-plan commit 4 -- reconcileHead (startup) + the classified append-time
 * HEAD/tail check (chain.appendSession / chain.repairMissingChainEntry). Constructs a
 * genuinely stale HEAD through the real public API (chain.appendSession + a targeted
 * HEAD.json overwrite mirroring exactly the crash window between chain.appendSession's
 * own step 2 (chain.jsonl append) and step 3 (HEAD.json update) -- never by disabling
 * the safety check itself.
 * ================================================================================== */

function makeStaleHeadFixture(dir, keys, n) {
  // Appends `n` real, distinct sessions, then rolls HEAD.json back to name an EARLIER
  // entry -- exactly the on-disk shape a crash between chain.appendSession's own
  // chain.jsonl-append and HEAD.json-update steps leaves behind, reproduced through the
  // real public API rather than by hand-crafting a chain.jsonl fixture.
  const entries = [];
  for (let i = 0; i < n; i++) {
    entries.push(chain.appendSession(dir, sealTrivialSession(`stale-head-${i}`, keys)));
  }
  return entries;
}

function appendTimeCheckAutoAdvancesASingleStepLaggingHead() {
  const dir = freshDir("append-time-single-lag");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 2);
  // Roll HEAD back to entry[0] -- exactly one step behind the real tail (entry[1]).
  fs.writeFileSync(chain.headPath(dir), JSON.stringify({ schema_version: entries[0].schema_version, seq: entries[0].seq, bundle_id: entries[0].bundle_id, entry_sha256: entries[0].entry_sha256 }));
  check("append-time-lag-fixture-head-still-stale", chain.readHead(dir).seq === 1, JSON.stringify(chain.readHead(dir)));

  const logs = [];
  const newEntry = chain.appendSession(dir, sealTrivialSession("stale-head-third", keys), { log: (l) => logs.push(l) });
  check("append-time-lag-auto-advance-new-entry-is-seq-3", newEntry.seq === 3, JSON.stringify(newEntry));
  check("append-time-lag-auto-advance-new-entry-links-to-entry2", newEntry.prev_entry_sha256 === entries[1].entry_sha256, JSON.stringify(newEntry));
  const headAfter = chain.readHead(dir);
  check("append-time-lag-auto-advance-head-ends-at-entry3", headAfter.seq === 3 && headAfter.bundle_id === newEntry.bundle_id, JSON.stringify(headAfter));
  check("append-time-lag-auto-advance-chain-has-exactly-3-entries-no-fork", chain.readChain(dir).length === 3, JSON.stringify(chain.readChain(dir).map((e) => e.seq)));
  const anomalyLog = logs.find((l) => l.includes("gateway_chain_head_lag_auto_advanced"));
  check("append-time-lag-auto-advance-logs-a-loud-anomaly", Boolean(anomalyLog), JSON.stringify(logs));
}

function appendTimeCheckRefusesATwoStepLaggingHead() {
  const dir = freshDir("append-time-two-step-lag");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 3);
  // Roll HEAD back TWO steps behind the real tail (entry[2]) -- not the auto-repairable
  // single-step case.
  fs.writeFileSync(chain.headPath(dir), JSON.stringify({ schema_version: entries[0].schema_version, seq: entries[0].seq, bundle_id: entries[0].bundle_id, entry_sha256: entries[0].entry_sha256 }));

  chain._resetChainIntegrityFailureForTests();
  let threw = null;
  try {
    chain.appendSession(dir, sealTrivialSession("two-step-lag-new", keys));
  } catch (error) {
    threw = error;
  }
  check("append-time-two-step-lag-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_HEAD_DIVERGED", threw ? `${threw.code}: ${threw.message}` : "did not throw");
  check("append-time-two-step-lag-chain-unchanged-no-fourth-entry", chain.readChain(dir).length === 3, JSON.stringify(chain.readChain(dir).map((e) => e.seq)));
  check("append-time-two-step-lag-head-untouched", chain.readHead(dir).seq === 1, JSON.stringify(chain.readHead(dir)));
  const latched = chain.getChainIntegrityFailure();
  check("append-time-two-step-lag-latches-the-integrity-failure", Boolean(latched) && latched.class === "multi-step-lag", JSON.stringify(latched));
}

function appendTimeCheckRefusesAForkedHead() {
  const dir = freshDir("append-time-fork");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 2);
  // A genuine fork: same seq/bundle_id as the real tail, but a bogus hash that does not
  // match anything actually in chain.jsonl.
  const forked = Object.assign({}, entries[1], { entry_sha256: "d".repeat(64) });
  fs.writeFileSync(chain.headPath(dir), JSON.stringify(forked));

  let threw = null;
  try {
    chain.appendSession(dir, sealTrivialSession("fork-new", keys));
  } catch (error) {
    threw = error;
  }
  check("append-time-fork-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_HEAD_DIVERGED", threw ? `${threw.code}: ${threw.message}` : "did not throw");
  check("append-time-fork-chain-unchanged", chain.readChain(dir).length === 2, JSON.stringify(chain.readChain(dir).map((e) => e.seq)));
}

function reconcileHeadEmptyChainIsANoOpWithZeroWrites() {
  const dir = freshDir("reconcile-empty");
  fs.mkdirSync(dir, { recursive: true }); // no gateway-sessions/ dir at all yet
  const result = chain.reconcileHead(dir);
  check("reconcile-empty-action-none", result.action === "none", JSON.stringify(result));
  check("reconcile-empty-writes-no-head-file", !fs.existsSync(chain.headPath(dir)), "HEAD.json was written for a genuinely empty chain");
  check("reconcile-empty-writes-no-chain-file", !fs.existsSync(chain.chainPath(dir)), "chain.jsonl was written for a genuinely empty chain");
}

function reconcileHeadRefusesAMultiStepLaggingHeadAtStartupToo() {
  // Round-1 fix-plan commit 4: multi-step lag is a REFUSE case per C2 row 7's own last
  // sentence, at BOTH call sites -- reconcileHead delegates entirely to the same
  // classifyHeadAgainstTail/validateChain classification the O(1) append-time check
  // uses, it does not get a weaker/more-permissive version just because it can afford a
  // full walk. Only an EXACT single-step, hash-matching lag ever auto-catches-up.
  const dir = freshDir("reconcile-multi-lag");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 4);
  fs.writeFileSync(chain.headPath(dir), JSON.stringify({ schema_version: entries[0].schema_version, seq: entries[0].seq, bundle_id: entries[0].bundle_id, entry_sha256: entries[0].entry_sha256 }));

  chain._resetChainIntegrityFailureForTests();
  let threw = null;
  try {
    chain.reconcileHead(dir);
  } catch (error) {
    threw = error;
  }
  check("reconcile-multi-step-lag-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE", threw ? `${threw.code}: ${threw.message}` : "did not throw");
  check("reconcile-multi-step-lag-head-untouched", chain.readHead(dir).bundle_id === entries[0].bundle_id, JSON.stringify(chain.readHead(dir)));
  const latched = chain.getChainIntegrityFailure();
  check("reconcile-multi-step-lag-latches-the-integrity-failure", Boolean(latched) && latched.class === "multi-step-lag", JSON.stringify(latched));
}

function reconcileHeadRebuildsFromAMalformedHeadFile() {
  const dir = freshDir("reconcile-malformed-head");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 2);
  fs.writeFileSync(chain.headPath(dir), "{not even close to json");

  const result = chain.reconcileHead(dir);
  check("reconcile-malformed-head-action-advanced", result.action === "advanced" && result.to.seq === 2, JSON.stringify(result));
  check("reconcile-malformed-head-rebuilt-correctly", chain.readHead(dir).bundle_id === entries[1].bundle_id, JSON.stringify(chain.readHead(dir)));
}

function reconcileHeadRefusesAGenuineFork() {
  const dir = freshDir("reconcile-fork");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 2);
  const forked = Object.assign({}, entries[1], { entry_sha256: "c".repeat(64) });
  fs.writeFileSync(chain.headPath(dir), JSON.stringify(forked));

  chain._resetChainIntegrityFailureForTests();
  let threw = null;
  try {
    chain.reconcileHead(dir);
  } catch (error) {
    threw = error;
  }
  check("reconcile-fork-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE", threw ? `${threw.code}: ${threw.message}` : "did not throw");
  check("reconcile-fork-head-untouched", chain.readHead(dir).entry_sha256 === "c".repeat(64), JSON.stringify(chain.readHead(dir)));
  const latched = chain.getChainIntegrityFailure();
  check("reconcile-fork-latches-the-integrity-failure", Boolean(latched) && latched.class === "fork", JSON.stringify(latched));
}

/* Round-1 fix-plan commit 6 (classified false positives): an OPERATIONAL failure
 * merely opening chain.jsonl (EACCES/EPERM -- exactly what a misapplied or
 * in-progress commit-2 group-readable chmod pass produces) must refuse THIS append
 * but must NOT engage the process-wide admission latch. Simulated via a targeted
 * fs.openSync patch (this sandbox runs as root, where a real chmod would not actually
 * deny the read) rather than real OS permissions -- mirrors tests/gateway/
 * startup-permissions/run-tests.js's own withPatched/codeError fault-injection style. */
function checkHeadAgainstTailOperationalPermissionFailureRefusesButDoesNotLatch() {
  const dir = freshDir("tail-eacces-operational");
  fs.mkdirSync(chain.sessionsDir(dir), { recursive: true });
  chain._resetChainIntegrityFailureForTests();

  const targetPath = chain.chainPath(dir);
  const originalOpenSync = fs.openSync;
  fs.openSync = function (p, ...rest) {
    if (p === targetPath) {
      const err = new Error("permission denied");
      err.code = "EACCES";
      throw err;
    }
    return originalOpenSync.apply(fs, [p, ...rest]);
  };
  let threw = null;
  try {
    chain.checkHeadAgainstTailOrRepair(dir, null, () => {});
  } catch (error) {
    threw = error;
  } finally {
    fs.openSync = originalOpenSync;
  }
  check(
    "tail-eacces-refuses-this-append-with-the-operational-code",
    threw !== null && threw.code === "GATEWAY_CHAIN_TAIL_UNREADABLE_OPERATIONAL",
    threw ? `${threw.code}: ${threw.message}` : "did not throw"
  );
  check("tail-eacces-does-not-latch-admission", chain.getChainIntegrityFailure() === null, JSON.stringify(chain.getChainIntegrityFailure()));
}

/* Companion regression lock: a non-permission open failure (anything other than
 * EACCES/EPERM) for the exact same "could not even open chain.jsonl" shape must still
 * refuse AND latch -- proves the operational carve-out above is narrowly scoped to
 * permission codes, not a general "any open failure is fine" loophole. */
function checkHeadAgainstTailGenuineUnreadableTailStillLatches() {
  const dir = freshDir("tail-genuine-unreadable");
  fs.mkdirSync(chain.sessionsDir(dir), { recursive: true });
  chain._resetChainIntegrityFailureForTests();

  const targetPath = chain.chainPath(dir);
  const originalOpenSync = fs.openSync;
  fs.openSync = function (p, ...rest) {
    if (p === targetPath) {
      const err = new Error("I/O error");
      err.code = "EIO";
      throw err;
    }
    return originalOpenSync.apply(fs, [p, ...rest]);
  };
  let threw = null;
  try {
    chain.checkHeadAgainstTailOrRepair(dir, null, () => {});
  } catch (error) {
    threw = error;
  } finally {
    fs.openSync = originalOpenSync;
  }
  check(
    "tail-eio-refuses-this-append-with-the-diverged-code",
    threw !== null && threw.code === "GATEWAY_CHAIN_HEAD_DIVERGED",
    threw ? `${threw.code}: ${threw.message}` : "did not throw"
  );
  const latched = chain.getChainIntegrityFailure();
  check("tail-eio-latches-admission", Boolean(latched) && latched.class === "tail-unreadable", JSON.stringify(latched));
  chain._resetChainIntegrityFailureForTests();
}

function reconcileHeadAheadRefuses() {
  const dir = freshDir("reconcile-head-ahead");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 1);
  const ahead = { schema_version: "1.0", seq: 5, bundle_id: "ghost", entry_sha256: "b".repeat(64) };
  fs.writeFileSync(chain.headPath(dir), JSON.stringify(ahead));

  let threw = null;
  try {
    chain.reconcileHead(dir);
  } catch (error) {
    threw = error;
  }
  check("reconcile-head-ahead-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE", threw ? `${threw.code}: ${threw.message}` : "did not throw");
}

function reconcileHeadRefusesWhenChainFailsStructuralValidation() {
  const dir = freshDir("reconcile-tampered");
  const keys = makeKeys();
  const entries = makeStaleHeadFixture(dir, keys, 2);
  // Tamper the interior (first) entry directly in chain.jsonl.
  const lines = fs.readFileSync(chain.chainPath(dir), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  lines[0].entry_sha256 = "9".repeat(64);
  fs.writeFileSync(chain.chainPath(dir), lines.map((e) => JSON.stringify(e)).join("\n") + "\n");

  let threw = null;
  try {
    chain.reconcileHead(dir);
  } catch (error) {
    threw = error;
  }
  check("reconcile-tampered-chain-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE", threw ? `${threw.code}: ${threw.message}` : "did not throw");
}

function reconcileHeadRefusesEmptyChainWithHeadPresent() {
  const dir = freshDir("reconcile-empty-with-head");
  fs.mkdirSync(chain.sessionsDir(dir), { recursive: true });
  fs.writeFileSync(chain.headPath(dir), JSON.stringify({ schema_version: "1.0", seq: 1, bundle_id: "ghost", entry_sha256: "a".repeat(64) }));
  // chain.jsonl itself does not exist -- HEAD.json names a tail that cannot possibly
  // exist. Zero entries, but NOT the empty-chain-is-fine case (C2 row 2).

  let threw = null;
  try {
    chain.reconcileHead(dir);
  } catch (error) {
    threw = error;
  }
  check("reconcile-empty-with-head-refuses", threw !== null && threw.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE", threw ? `${threw.code}: ${threw.message}` : "did not throw");
}

function main() {
  tenSessionsInSequence();
  fixtureDataVerifiesIndependently();
  incompleteAppendDetected();
  mutatedEntryDetected();
  deletedEntryDetectedDistinctly();
  missingGenesisPrefixDetected();
  bundleIdCollisionRefused();
  emptyChainIsNotApplicable();

  validateChainEmptyGenesisIsNotAFailure();
  validateChainEmptyWithHeadRefuses();
  validateChainDetectsSequenceGap();
  validateChainDetectsDuplicateSeqAsFork();
  validateChainDetectsTamperedEntry();
  validateChainDetectsBrokenLink();
  validateChainDetectsInvalidGenesisSeq();
  validateChainDetectsInvalidGenesisPrev();
  validateChainRefusesMalformedInteriorRecordNotJustTheLast();
  validateChainAutoAdvancesSingleStepLaggingHead();
  validateChainRefusesMultiStepLaggingHead();
  validateChainRefusesHeadAheadOfTail();
  validateChainRefusesHeadSameSeqDifferentHashAsFork();
  validateChainRefusesOneStepBackHeadThatIsNotAGenuineAncestor();
  validateChainRebuildsMissingHeadFromVerifiedTail();
  validateChainDoesNotRebuildWhenTheChainItselfDoesNotValidate();
  validateChainTruncatesTornFinalRecordAndRebuildsHead();
  validateChainTornFinalRecordWithHeadAlreadyAtTheTruncatedTailStillReportsReconciliation();
  validateChainTornSoleGenesisRecordWithNoHeadReconcilesToEmptyTail();
  validateChainTornSoleRecordWithHeadPresentRefuses();
  validateChainNeverConflatesTornTailWithInteriorCorruption();

  readChainTailAbsentWhenFileDoesNotExist();
  readChainTailEmptyWhenFileIsZeroBytes();
  readChainTailEmptyWhenFileIsOnlyBlankLines();
  readChainTailSucceedsWithTrailingNewline();
  readChainTailSucceedsWithoutTrailingNewline();
  readChainTailReturnsTheSameEntryRegardlessOfTrailingNewline();
  readChainTailSkipsBlankLinesBeforeTheLastEntry();
  readChainTailFindsTheLastEntryWhenTheWindowStartsMidRecord();
  readChainTailGrowsPastTheInitialWindowForAnOversizedFinalRecord();
  readChainTailFindsALargeFinalRecordWhenANewlineIsAlreadyInTheFirstWindow();
  readChainTailFailsClosedWhenNoNewlineIsFoundWithinTheCappedWindow();
  readChainTailReportsCorruptForATruncatedFinalRecord();
  readChainTailReportsCorruptForAMalformedFinalRecord();
  readChainTailReportsCorruptWhenTheFinalRecordFailsItsShapeCheck();
  readChainTailHandlesUtf8BoundariesSplitAcrossTheWindowEdge();
  readChainTailUtf8LastEntryItselfSurvivesGrowth();
  readChainTailHandlesShortReads();
  readChainTailAbsentEmptyCorruptAreThreeDistinctOutcomes();

  appendTimeCheckAutoAdvancesASingleStepLaggingHead();
  appendTimeCheckRefusesATwoStepLaggingHead();
  appendTimeCheckRefusesAForkedHead();
  checkHeadAgainstTailOperationalPermissionFailureRefusesButDoesNotLatch();
  checkHeadAgainstTailGenuineUnreadableTailStillLatches();
  reconcileHeadEmptyChainIsANoOpWithZeroWrites();
  reconcileHeadRefusesAMultiStepLaggingHeadAtStartupToo();
  reconcileHeadRebuildsFromAMalformedHeadFile();
  reconcileHeadRefusesAGenuineFork();
  reconcileHeadAheadRefuses();
  reconcileHeadRefusesWhenChainFailsStructuralValidation();
  reconcileHeadRefusesEmptyChainWithHeadPresent();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
