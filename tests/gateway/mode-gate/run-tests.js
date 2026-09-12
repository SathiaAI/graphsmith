#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/mode-gate.js (SG-FR-1/SG-FR-2). Exercises every
 * fail-closed condition in the mode-selection contract TRD's SS7 table, plus SS8 test
 * plan item 15 (attach configured, standalone binary started anyway -> dormant, not an
 * error). See mode-gate.js's own header for why this validates against a PRIVATE,
 * transcribed copy of the mode-selection contract's schema rather than a real
 * schemas/mode-selection-contract.schema.json file (that file does not exist in this
 * repo as of this build -- a disclosed gap, not routed around). */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.resolve(__dirname, "../../..");
const modeGate = require(path.join(ROOT, "scripts", "gateway", "mode-gate.js"));
const { writeConfirmedMode } = require("../_fixtures/mode-file.js");

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

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-mode-${prefix}-`));
}

function expectCode(fn, expectedCode, name) {
  let threw = null;
  try { fn(); } catch (error) { threw = error; }
  check(name, threw && threw.code === expectedCode, `expected ${expectedCode}, got ${threw ? threw.code : "no error"}`);
}

/* SS7 condition 1: file missing. */
function missingFile() {
  const root = freshRoot("missing");
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_NOT_DECLARED", "missing-mode-file-refused");
}

/* SS7 condition 2: unreadable (not ENOENT -- e.g. a directory where a file is expected). */
function unreadableFile() {
  const root = freshRoot("unreadable");
  fs.mkdirSync(path.join(root, ".graphsmith"), { recursive: true });
  fs.mkdirSync(path.join(root, ".graphsmith", "gateway-mode.json")); // a directory, not a file
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_UNREADABLE", "unreadable-mode-file-refused");
}

/* SS7 condition 3: not valid JSON. */
function malformedJson() {
  const root = freshRoot("malformed");
  fs.mkdirSync(path.join(root, ".graphsmith"), { recursive: true });
  fs.writeFileSync(path.join(root, ".graphsmith", "gateway-mode.json"), "{not json");
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_MALFORMED", "malformed-json-refused");
}

/* SS7 condition 3 (schema-invalid variant): bad enum value for mode. */
function badEnum() {
  const root = freshRoot("bad-enum");
  fs.mkdirSync(path.join(root, ".graphsmith"), { recursive: true });
  fs.writeFileSync(path.join(root, ".graphsmith", "gateway-mode.json"), JSON.stringify({ schema_version: "1.0", mode: "sideways", confirmation: {} }));
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_INVALID", "bad-mode-enum-refused");
}

/* SS7 condition 4: confirmation block missing from an otherwise schema-valid record. */
function missingConfirmation() {
  const root = freshRoot("no-confirm");
  fs.mkdirSync(path.join(root, ".graphsmith"), { recursive: true });
  fs.writeFileSync(path.join(root, ".graphsmith", "gateway-mode.json"), JSON.stringify({ schema_version: "1.0", mode: "standalone" }));
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_NOT_CONFIRMED", "missing-confirmation-refused");
}

/* SS7 condition 5: confirmation_token present but does not recompute (tampered). */
function tamperedToken() {
  const root = freshRoot("tampered");
  writeConfirmedMode(root, "standalone", { badToken: "f".repeat(64) });
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_CONFIRMATION_MISMATCH", "tampered-token-refused");
}

/* SS7 condition 6: secret file missing while confirmation_token is present. */
function keyMissing() {
  const root = freshRoot("key-missing");
  writeConfirmedMode(root, "standalone");
  fs.unlinkSync(path.join(root, ".graphsmith", "state", "gateway-mode.key"));
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_KEY_MISSING", "missing-key-file-refused");
}

/* SS7 condition 7 / SS8 test 15: valid + confirmed, but the OTHER binary's mode. This
 * is the "dormant, not an error" case at the gateway.js layer -- here we confirm
 * mode-gate.js itself reports it as a distinct, catchable code. */
function wrongBinary() {
  const root = freshRoot("wrong-binary");
  writeConfirmedMode(root, "attach");
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_WRONG_BINARY", "attach-declared-refuses-standalone-binary");
}

/* Happy path: valid, confirmed, matching binary -> returns the record, does not throw. */
function happyPath() {
  const root = freshRoot("happy");
  const written = writeConfirmedMode(root, "standalone", { confirmedBy: "paul@example.com" });
  let result = null;
  let threw = null;
  try { result = modeGate.readGatewayMode(root, { expectedMode: "standalone" }); } catch (error) { threw = error; }
  check("happy-path-does-not-throw", threw === null, threw && threw.message);
  check("happy-path-returns-matching-record", result && result.mode === "standalone" && result.confirmation.confirmed_by === "paul@example.com", "record mismatch");
  void written;
}

/* A confirmation computed under a DIFFERENT secret must fail, even with a
 * well-formed 64-hex token (guards against "any hex64 string passes"). */
function foreignSecretRejected() {
  const root = freshRoot("foreign-secret");
  const record = writeConfirmedMode(root, "standalone");
  const wrongSecret = crypto.randomBytes(32);
  const forgedToken = modeGate.computeConfirmationToken(wrongSecret, record);
  const tampered = JSON.parse(fs.readFileSync(path.join(root, ".graphsmith", "gateway-mode.json"), "utf8"));
  tampered.confirmation.confirmation_token = forgedToken;
  fs.writeFileSync(path.join(root, ".graphsmith", "gateway-mode.json"), JSON.stringify(tampered));
  expectCode(() => modeGate.readGatewayMode(root, { expectedMode: "standalone" }), "GATEWAY_MODE_CONFIRMATION_MISMATCH", "foreign-secret-token-rejected");
}

function main() {
  missingFile();
  unreadableFile();
  malformedJson();
  badEnum();
  missingConfirmation();
  tamperedToken();
  keyMissing();
  wrongBinary();
  happyPath();
  foreignSecretRejected();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
