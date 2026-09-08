#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/mode-selection.js (Track 1.1, the mode-selection
 * contract -- TRD "GraphSmith Gateway Mode-Selection Contract -- TRD (Track 1.1)
 * -- Rev 3, final", Linear SAT-1095). Covers:
 *
 *   - schemas/mode-selection-contract.schema.json's validation rules (valid mode,
 *     invalid mode, missing confirmation vs. malformed confirmation, tampered
 *     patterns, unknown properties)
 *   - the TRD S3.2/S7 startup gate (readAndValidateGatewayMode): every fail-closed
 *     condition in S7's table, by its exact error code
 *   - statusReport: the non-throwing MS-FR-4 status surface, same conditions
 *   - the CLI's write behavior (writeGatewayMode): atomic full-record overwrite
 *     (never a partial carry-over of a prior confirmation's fields), correct HMAC
 *     computation (verified by an independent recomputation, not just the
 *     module's own round trip), and rejection of malformed/partial input
 *   - the pre-authorization artifact (createPreAuthorizationArtifact /
 *     verifyPreAuthorizationArtifact): valid round trip, expired, tampered,
 *     mode-mismatched, and malformed artifacts
 *
 * House style matches tests/state-store/atomic-primitives/run-tests.js:
 * check()/record() with PASS/FAIL lines and a final
 * `SUMMARY passed=N failed=N skipped=N` line.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../..");
const modeSelection = require(path.join(ROOT, "scripts", "mode-selection.js"));
const schemaValidate = require(path.join(ROOT, "scripts", "schema-validate.js"));

let failures = 0;
let skipped = 0;
const results = [];

function record(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : status === "SKIP" ? `SKIP ${name}` : `FAIL ${name} -- ${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
  if (status === "SKIP") skipped++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function skip(name, reason) {
  record(name, "SKIP", reason);
}

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-mode-selection-${prefix}-`));
}

function codeOf(fn) {
  try { fn(); return { threw: false, code: null }; }
  catch (error) { return { threw: true, code: error.code, message: error.message }; }
}

function validConfirmedRecord(overrides = {}) {
  const base = {
    schema_version: "1.0",
    mode: "standalone",
    confirmation: {
      confirmed_by: "paul@example.com",
      confirmed_at: 1_700_000_000_000,
      nonce: "a".repeat(32),
      confirmation_token: "b".repeat(64),
    },
  };
  return Object.assign(base, overrides);
}

/* ---- schema validation (schemas/mode-selection-contract.schema.json) ---- */

function schemaAcceptsAValidRecord() {
  const errors = schemaValidate.validate(validConfirmedRecord(), modeSelection.MODE_SCHEMA, "$");
  check("schema-accepts-valid-record", errors.length === 0, `unexpected errors: ${JSON.stringify(errors)}`);
}

function schemaRejectsInvalidModeEnum() {
  const record = validConfirmedRecord({ mode: "bogus-mode" });
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-invalid-mode-enum", errors.length > 0, "expected an enum violation for an unsupported mode value");
}

function schemaRejectsWrongSchemaVersion() {
  const record = validConfirmedRecord({ schema_version: "2.0" });
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-wrong-schema-version", errors.length > 0, "expected a const violation for schema_version");
}

function schemaRejectsMissingConfirmationEntirely() {
  const record = { schema_version: "1.0", mode: "standalone" };
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-record-with-no-confirmation-at-all", errors.length > 0, "expected a required-property violation for confirmation");
}

function schemaRejectsConfirmationMissingNonce() {
  const record = validConfirmedRecord();
  delete record.confirmation.nonce;
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-confirmation-missing-nonce", errors.length > 0, "expected a required-property violation for confirmation.nonce");
}

function schemaRejectsBadNoncePattern() {
  const record = validConfirmedRecord({ confirmation: { ...validConfirmedRecord().confirmation, nonce: "not-hex!" } });
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-bad-nonce-pattern", errors.length > 0, "expected a pattern violation for a non-hex nonce");
}

function schemaRejectsBadConfirmationTokenPattern() {
  const record = validConfirmedRecord();
  record.confirmation.confirmation_token = "too-short";
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-bad-confirmation-token-pattern", errors.length > 0, "expected a pattern violation for a short confirmation_token");
}

function schemaRejectsEmptyConfirmedBy() {
  const record = validConfirmedRecord();
  record.confirmation.confirmed_by = "";
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-empty-confirmed-by", errors.length > 0, "expected a minLength violation for an empty confirmed_by");
}

function schemaRejectsNegativeConfirmedAt() {
  const record = validConfirmedRecord();
  record.confirmation.confirmed_at = -1;
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-negative-confirmed-at", errors.length > 0, "expected a minimum violation for a negative confirmed_at");
}

function schemaRejectsUnknownTopLevelProperty() {
  const record = validConfirmedRecord({ extra_field: "not allowed" });
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-unknown-top-level-property", errors.length > 0, "expected additionalProperties:false to reject an unknown top-level field");
}

function schemaRejectsUnknownConfirmationProperty() {
  const record = validConfirmedRecord();
  record.confirmation.extra_field = "not allowed";
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-rejects-unknown-confirmation-property", errors.length > 0, "expected additionalProperties:false to reject an unknown confirmation field");
}

function schemaAcceptsOptionalPreAuthorizedFlag() {
  const record = validConfirmedRecord();
  record.confirmation.pre_authorized = true;
  const errors = schemaValidate.validate(record, modeSelection.MODE_SCHEMA, "$");
  check("schema-accepts-optional-pre-authorized-flag", errors.length === 0, `unexpected errors: ${JSON.stringify(errors)}`);
}

/* ---- startup gate: readAndValidateGatewayMode ---- */

function gateRefusesWhenFileMissing() {
  const root = freshRoot("missing");
  try {
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-missing-file-not-declared", result.threw && result.code === "GATEWAY_MODE_NOT_DECLARED", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnUnreadableFile() {
  const root = freshRoot("unreadable");
  try {
    // A directory in place of the file triggers EISDIR on read -- a real,
    // non-ENOENT read failure distinct from "missing".
    fs.mkdirSync(modeSelection.gatewayModePath(root), { recursive: true });
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-unreadable-file-not-conflated-with-missing", result.threw && result.code === "GATEWAY_MODE_UNREADABLE", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnMalformedJson() {
  const root = freshRoot("malformed-json");
  try {
    fs.mkdirSync(modeSelection.gatewayDir(root), { recursive: true });
    fs.writeFileSync(modeSelection.gatewayModePath(root), "{ this is not json");
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-malformed-json", result.threw && result.code === "GATEWAY_MODE_MALFORMED", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnSchemaInvalidRecord() {
  const root = freshRoot("schema-invalid");
  try {
    fs.mkdirSync(modeSelection.gatewayDir(root), { recursive: true });
    fs.writeFileSync(modeSelection.gatewayModePath(root), JSON.stringify(validConfirmedRecord({ mode: "not-a-real-mode" })));
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-schema-invalid-record", result.threw && result.code === "GATEWAY_MODE_INVALID", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnMissingConfirmationWithFriendlyCode() {
  const root = freshRoot("not-confirmed");
  try {
    fs.mkdirSync(modeSelection.gatewayDir(root), { recursive: true });
    fs.writeFileSync(modeSelection.gatewayModePath(root), JSON.stringify({ schema_version: "1.0", mode: "attach" }));
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-missing-confirmation-gets-not-confirmed-not-generic-invalid",
      result.threw && result.code === "GATEWAY_MODE_NOT_CONFIRMED", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnKeyMissingWhileTokenPresent() {
  const root = freshRoot("key-missing");
  try {
    // Write a fully schema-valid, confirmed record WITHOUT ever calling
    // writeGatewayMode/ensureSecret -- simulates the key file being absent
    // (e.g. deleted, or a copied gateway-mode.json without its key).
    fs.mkdirSync(modeSelection.gatewayDir(root), { recursive: true });
    fs.writeFileSync(modeSelection.gatewayModePath(root), JSON.stringify(validConfirmedRecord()));
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-key-missing-is-distinct-from-not-confirmed",
      result.threw && result.code === "GATEWAY_MODE_KEY_MISSING", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnTamperedHmac() {
  const root = freshRoot("tampered-hmac");
  try {
    modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "paul@example.com", confirmedAt: 1_700_000_000_000 });
    const target = modeSelection.gatewayModePath(root);
    const record = JSON.parse(fs.readFileSync(target, "utf8"));
    record.mode = "attach"; // flip the mode without recomputing the token
    fs.writeFileSync(target, JSON.stringify(record));
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root));
    check("gate-tampered-hmac-mismatch-detected",
      result.threw && result.code === "GATEWAY_MODE_CONFIRMATION_MISMATCH", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateAcceptsAGenuineRoundTrip() {
  const root = freshRoot("round-trip");
  try {
    const written = modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "ops@example.com", confirmedAt: 1_700_000_000_001 });
    const read = modeSelection.readAndValidateGatewayMode(root, { expectedMode: "attach" });
    check("gate-genuine-round-trip-returns-the-written-record",
      read.mode === "attach" && read.confirmation.confirmation_token === written.confirmation.confirmation_token,
      "read record did not match what writeGatewayMode wrote");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function gateRefusesOnWrongBinary() {
  const root = freshRoot("wrong-binary");
  try {
    modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "paul@example.com", confirmedAt: 1_700_000_000_002 });
    const result = codeOf(() => modeSelection.readAndValidateGatewayMode(root, { expectedMode: "attach" }));
    check("gate-wrong-binary-refused", result.threw && result.code === "GATEWAY_MODE_WRONG_BINARY", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

/* ---- statusReport: same conditions, non-throwing ---- */

function statusReportsNotDeclared() {
  const root = freshRoot("status-missing");
  try {
    const status = modeSelection.statusReport(root);
    check("status-not-declared", status.declared === false && status.ok === false && status.reason === "GATEWAY_MODE_NOT_DECLARED", JSON.stringify(status));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function statusReportsNotConfirmed() {
  const root = freshRoot("status-not-confirmed");
  try {
    fs.mkdirSync(modeSelection.gatewayDir(root), { recursive: true });
    fs.writeFileSync(modeSelection.gatewayModePath(root), JSON.stringify({ schema_version: "1.0", mode: "standalone" }));
    const status = modeSelection.statusReport(root);
    check("status-not-confirmed", status.declared === true && status.ok === false && status.reason === "GATEWAY_MODE_NOT_CONFIRMED", JSON.stringify(status));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function statusReportsHealthyConfirmedRecord() {
  const root = freshRoot("status-healthy");
  try {
    modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "paul@example.com", confirmedAt: 1_700_000_000_003 });
    const status = modeSelection.statusReport(root);
    check("status-healthy-record-ok-and-token-valid", status.ok === true && status.token_valid === true && status.mode === "standalone", JSON.stringify(status));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function statusReportsMismatchWithoutThrowing() {
  const root = freshRoot("status-mismatch");
  try {
    modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "ops@example.com", confirmedAt: 1_700_000_000_004 });
    const target = modeSelection.gatewayModePath(root);
    const record = JSON.parse(fs.readFileSync(target, "utf8"));
    record.confirmation.confirmed_by = "someone-else@example.com";
    fs.writeFileSync(target, JSON.stringify(record));
    const status = modeSelection.statusReport(root);
    check("status-mismatch-reported-not-thrown",
      status.ok === false && status.token_valid === false && status.reason === "GATEWAY_MODE_CONFIRMATION_MISMATCH", JSON.stringify(status));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

/* ---- writeGatewayMode: atomic overwrite, HMAC correctness, input rejection ---- */

function writeRejectsInvalidMode() {
  const root = freshRoot("write-bad-mode");
  try {
    const result = codeOf(() => modeSelection.writeGatewayMode(root, { mode: "bogus", confirmedBy: "x", confirmedAt: 1 }));
    check("write-rejects-invalid-mode", result.threw && result.code === "INVALID_ARGUMENT", `got ${JSON.stringify(result)}`);
    check("write-rejects-invalid-mode-leaves-no-file", !fs.existsSync(modeSelection.gatewayModePath(root)), "a rejected write should not create the file");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function writeRejectsEmptyConfirmedBy() {
  const root = freshRoot("write-bad-confirmed-by");
  try {
    const result = codeOf(() => modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "", confirmedAt: 1 }));
    check("write-rejects-empty-confirmed-by", result.threw && result.code === "INVALID_ARGUMENT", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function writeRejectsNonIntegerConfirmedAt() {
  const root = freshRoot("write-bad-confirmed-at");
  try {
    const result = codeOf(() => modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "x", confirmedAt: "not-a-number" }));
    check("write-rejects-non-integer-confirmed-at", result.threw && result.code === "INVALID_ARGUMENT", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function writeProducesACorrectlyComputedHmac() {
  const root = freshRoot("write-hmac");
  try {
    const record = modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "paul@example.com", confirmedAt: 1_700_000_000_005 });
    // Independent recomputation straight from the secret file on disk --
    // not via modeSelection.computeConfirmationToken alone (which would
    // just prove the module agrees with itself), but with a from-scratch
    // HMAC call using the exact TRD S5.1 formula.
    const secret = fs.readFileSync(modeSelection.gatewayModeKeyPath(root), "utf8").trim();
    const material = ["1.0", "attach", "paul@example.com", 1_700_000_000_005, record.confirmation.nonce].join("|");
    const expected = crypto.createHmac("sha256", secret).update(material).digest("hex");
    check("write-hmac-matches-independent-recomputation", record.confirmation.confirmation_token === expected,
      `expected ${expected}, got ${record.confirmation.confirmation_token}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function writeIsAFullOverwriteNotAPartialMerge() {
  const root = freshRoot("write-full-overwrite");
  try {
    modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "first@example.com", confirmedAt: 1, preAuthorized: true });
    const second = modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "second@example.com", confirmedAt: 2 });
    check("write-full-overwrite-does-not-carry-over-pre-authorized-flag",
      !second.confirmation.pre_authorized, `stale pre_authorized flag leaked across writes: ${JSON.stringify(second)}`);
    check("write-full-overwrite-does-not-carry-over-prior-confirmed-by",
      second.confirmation.confirmed_by === "second@example.com", JSON.stringify(second));
    const onDisk = JSON.parse(fs.readFileSync(modeSelection.gatewayModePath(root), "utf8"));
    check("write-full-overwrite-file-on-disk-matches-second-write", onDisk.confirmation.confirmed_by === "second@example.com", JSON.stringify(onDisk));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function writeReuseTheSameSecretAcrossCalls() {
  const root = freshRoot("write-secret-reuse");
  try {
    modeSelection.writeGatewayMode(root, { mode: "standalone", confirmedBy: "a@example.com", confirmedAt: 1 });
    const secretAfterFirst = fs.readFileSync(modeSelection.gatewayModeKeyPath(root), "utf8");
    modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "b@example.com", confirmedAt: 2 });
    const secretAfterSecond = fs.readFileSync(modeSelection.gatewayModeKeyPath(root), "utf8");
    check("write-reuses-the-same-deployment-secret-across-mode-changes", secretAfterFirst === secretAfterSecond,
      "the per-deployment secret must not be regenerated on every mode change");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function writtenFileValidatesAgainstTheRealShippedSchema() {
  const root = freshRoot("write-schema-conformance");
  try {
    modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "paul@example.com", confirmedAt: 1_700_000_000_006 });
    const onDisk = JSON.parse(fs.readFileSync(modeSelection.gatewayModePath(root), "utf8"));
    const errors = schemaValidate.validate(onDisk, modeSelection.MODE_SCHEMA, "$");
    check("written-file-validates-against-the-real-schema-file", errors.length === 0, `unexpected errors: ${JSON.stringify(errors)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

/* ---- pre-authorization artifact ---- */

function preAuthValidRoundTripSucceeds() {
  const root = freshRoot("preauth-ok");
  try {
    const now = 1_700_000_000_000;
    const artifact = modeSelection.createPreAuthorizationArtifact(root, { mode: "attach", authorizedBy: "ci@pipeline", authorizedAt: now, ttlMs: 3_600_000 });
    const verified = modeSelection.verifyPreAuthorizationArtifact(root, artifact, { mode: "attach", now: now + 1000 });
    check("preauth-valid-round-trip-verifies", verified.authorized_by === "ci@pipeline", JSON.stringify(verified));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function preAuthExpiredArtifactRefused() {
  const root = freshRoot("preauth-expired");
  try {
    const now = 1_700_000_000_000;
    const artifact = modeSelection.createPreAuthorizationArtifact(root, { mode: "standalone", authorizedBy: "ci@pipeline", authorizedAt: now, ttlMs: 1000 });
    const result = codeOf(() => modeSelection.verifyPreAuthorizationArtifact(root, artifact, { mode: "standalone", now: now + 2000 }));
    check("preauth-expired-artifact-refused", result.threw && result.code === "GATEWAY_MODE_PRE_AUTH_EXPIRED", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function preAuthTamperedHmacRefused() {
  const root = freshRoot("preauth-tampered");
  try {
    const now = 1_700_000_000_000;
    const artifact = modeSelection.createPreAuthorizationArtifact(root, { mode: "attach", authorizedBy: "ci@pipeline", authorizedAt: now, ttlMs: 3_600_000 });
    artifact.expires_at += 1_000_000; // extend expiry without recomputing the hmac
    const result = codeOf(() => modeSelection.verifyPreAuthorizationArtifact(root, artifact, { mode: "attach", now }));
    check("preauth-tampered-expiry-refused-by-hmac", result.threw && result.code === "GATEWAY_MODE_PRE_AUTH_TAMPERED", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function preAuthModeMismatchRefused() {
  const root = freshRoot("preauth-mode-mismatch");
  try {
    const now = 1_700_000_000_000;
    const artifact = modeSelection.createPreAuthorizationArtifact(root, { mode: "attach", authorizedBy: "ci@pipeline", authorizedAt: now, ttlMs: 3_600_000 });
    const result = codeOf(() => modeSelection.verifyPreAuthorizationArtifact(root, artifact, { mode: "standalone", now }));
    check("preauth-mode-mismatch-refused", result.threw && result.code === "GATEWAY_MODE_PRE_AUTH_MODE_MISMATCH", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function preAuthMalformedArtifactRefused() {
  const root = freshRoot("preauth-malformed");
  try {
    modeSelection.ensureSecret(root); // a deployment secret must exist for this to be a meaningful test
    const result = codeOf(() => modeSelection.verifyPreAuthorizationArtifact(root, { schema_version: "1.0", mode: "attach" }, { mode: "attach", now: 0 }));
    check("preauth-malformed-artifact-refused", result.threw && result.code === "GATEWAY_MODE_PRE_AUTH_INVALID", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function preAuthWrongSchemaVersionRefused() {
  const root = freshRoot("preauth-wrong-version");
  try {
    const now = 1_700_000_000_000;
    const artifact = modeSelection.createPreAuthorizationArtifact(root, { mode: "standalone", authorizedBy: "ci@pipeline", authorizedAt: now, ttlMs: 3_600_000 });
    artifact.schema_version = "9.9";
    const result = codeOf(() => modeSelection.verifyPreAuthorizationArtifact(root, artifact, { mode: "standalone", now }));
    check("preauth-wrong-schema-version-refused", result.threw && result.code === "GATEWAY_MODE_PRE_AUTH_INVALID", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function preAuthNoDeploymentSecretYetRefused() {
  const root = freshRoot("preauth-no-secret");
  try {
    // An artifact-shaped object presented against a deployment that has
    // never run any confirmation yet -- there is no secret to verify against.
    const now = 1_700_000_000_000;
    const artifact = { schema_version: "1.0", mode: "attach", authorized_by: "ci@pipeline", authorized_at: now, expires_at: now + 3_600_000, hmac: "c".repeat(64) };
    const result = codeOf(() => modeSelection.verifyPreAuthorizationArtifact(root, artifact, { mode: "attach", now }));
    check("preauth-no-deployment-secret-yet-refused", result.threw && result.code === "GATEWAY_MODE_KEY_MISSING", `got ${JSON.stringify(result)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

/* ---- describeCurrentMode: best-effort display helper, never throws ---- */

function describeCurrentModeReportsNoneWhenAbsent() {
  const root = freshRoot("describe-none");
  try {
    check("describe-current-mode-none-declared", modeSelection.describeCurrentMode(root) === "(none declared)", modeSelection.describeCurrentMode(root));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function describeCurrentModeReportsTheDeclaredMode() {
  const root = freshRoot("describe-declared");
  try {
    modeSelection.writeGatewayMode(root, { mode: "attach", confirmedBy: "x@example.com", confirmedAt: 1 });
    check("describe-current-mode-reports-declared-mode", modeSelection.describeCurrentMode(root) === "attach", modeSelection.describeCurrentMode(root));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function main() {
  schemaAcceptsAValidRecord();
  schemaRejectsInvalidModeEnum();
  schemaRejectsWrongSchemaVersion();
  schemaRejectsMissingConfirmationEntirely();
  schemaRejectsConfirmationMissingNonce();
  schemaRejectsBadNoncePattern();
  schemaRejectsBadConfirmationTokenPattern();
  schemaRejectsEmptyConfirmedBy();
  schemaRejectsNegativeConfirmedAt();
  schemaRejectsUnknownTopLevelProperty();
  schemaRejectsUnknownConfirmationProperty();
  schemaAcceptsOptionalPreAuthorizedFlag();

  gateRefusesWhenFileMissing();
  gateRefusesOnUnreadableFile();
  gateRefusesOnMalformedJson();
  gateRefusesOnSchemaInvalidRecord();
  gateRefusesOnMissingConfirmationWithFriendlyCode();
  gateRefusesOnKeyMissingWhileTokenPresent();
  gateRefusesOnTamperedHmac();
  gateAcceptsAGenuineRoundTrip();
  gateRefusesOnWrongBinary();

  statusReportsNotDeclared();
  statusReportsNotConfirmed();
  statusReportsHealthyConfirmedRecord();
  statusReportsMismatchWithoutThrowing();

  writeRejectsInvalidMode();
  writeRejectsEmptyConfirmedBy();
  writeRejectsNonIntegerConfirmedAt();
  writeProducesACorrectlyComputedHmac();
  writeIsAFullOverwriteNotAPartialMerge();
  writeReuseTheSameSecretAcrossCalls();
  writtenFileValidatesAgainstTheRealShippedSchema();

  preAuthValidRoundTripSucceeds();
  preAuthExpiredArtifactRefused();
  preAuthTamperedHmacRefused();
  preAuthModeMismatchRefused();
  preAuthMalformedArtifactRefused();
  preAuthWrongSchemaVersionRefused();
  preAuthNoDeploymentSecretYetRefused();

  describeCurrentModeReportsNoneWhenAbsent();
  describeCurrentModeReportsTheDeclaredMode();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main();
