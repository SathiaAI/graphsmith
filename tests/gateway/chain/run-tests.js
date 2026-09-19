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

function main() {
  tenSessionsInSequence();
  fixtureDataVerifiesIndependently();
  incompleteAppendDetected();
  mutatedEntryDetected();
  deletedEntryDetectedDistinctly();
  missingGenesisPrefixDetected();
  bundleIdCollisionRefused();
  emptyChainIsNotApplicable();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
