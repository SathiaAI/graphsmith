#!/usr/bin/env node
/* GraphSmith standalone gateway -- mode-selection gate (SG-FR-1 / SG-FR-2).
 *
 * Implements the STANDALONE side of MS-FR-1 from the Gateway Mode-Selection Contract
 * TRD (.plans/v0.5.0/MODE-SELECTION-CONTRACT-TRD-2026-08-26.md, "Revision 3, final"):
 * before this process's own config is even read, .graphsmith/gateway-mode.json MUST be
 * read and validated against that contract's schema + HMAC-confirmation check, and the
 * process MUST refuse to start (fail-closed) on any of SS7's seven named conditions.
 *
 * A REAL GAP, DISCLOSED RATHER THAN ROUTED AROUND (see the build report for this
 * track): the mode-selection contract's own deliverable files --
 * schemas/mode-selection-contract.schema.json and the `graphsmith gateway mode set` CLI
 * that is the ONLY permitted writer of .graphsmith/gateway-mode.json -- do not exist
 * anywhere in this repository (confirmed: `git log --all` for either path returns zero
 * commits), despite Track 1.1 being described as CLOSED/already-built in this track's
 * kickoff brief and in the TRD's own header note ("this gateway's own config-write path
 * never has to touch mode-confirmation state" -- worded as though the reader path
 * already exists too). This module does NOT create schemas/mode-selection-contract.
 * schema.json or any CLI that writes gateway-mode.json -- per this track's explicit
 * instruction, that would be routing around a scoping problem rather than reporting it.
 * What it DOES do: transcribe the contract's SS5.1 schema (a small, frozen, "no open
 * questions remain" JSON literal, Revision 3, final) as a private constant below, purely
 * so SG-FR-1/SG-FR-2 have something concrete to validate against and can be tested now.
 * When Track 1.1's real schemas/mode-selection-contract.schema.json lands, swapping the
 * MODE_SELECTION_SCHEMA constant below for `require("../../schemas/mode-selection-
 * contract.schema.json")` is a one-line change -- the shape, field names, and error
 * codes here are transcribed verbatim from that contract's SS5.1/SS7, not invented.
 *
 * Zero-dependency (crypto.createHmac is stdlib, no new runtime dependency), Node >= 18.
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const GATEWAY_MODE_FILE = path.join(".graphsmith", "gateway-mode.json");
const GATEWAY_MODE_KEY_FILE = path.join(".graphsmith", "state", "gateway-mode.key");

/* Transcribed verbatim from the mode-selection contract TRD SS5.1 (Revision 3, final,
 * 2026-08-28) -- see this file's header comment for why this is a private copy rather
 * than a require() of a schema file that does not yet exist in this repo. */
const MODE_SELECTION_SCHEMA = Object.freeze({
  required: ["schema_version", "mode", "confirmation"],
  schema_version_const: "1.0",
  mode_enum: ["standalone", "attach"],
  confirmation_required: ["confirmed_by", "confirmed_at", "nonce", "confirmation_token"],
  nonce_pattern: /^[a-f0-9]{32}$/,
  confirmation_token_pattern: /^[a-f0-9]{64}$/,
});

function fail(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function readModeFile(root) {
  const target = path.join(root, GATEWAY_MODE_FILE);
  let raw;
  try {
    raw = fs.readFileSync(target, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      throw fail(
        `Refusing to start: ${GATEWAY_MODE_FILE} is missing. Run ` +
          "`graphsmith gateway mode set <standalone|attach>` to declare and confirm this " +
          "deployment's mode before starting the gateway.",
        "GATEWAY_MODE_NOT_DECLARED"
      );
    }
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE} could not be read: ${error.message}`, "GATEWAY_MODE_UNREADABLE");
  }
  let record;
  try {
    record = JSON.parse(raw);
  } catch (error) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE} is not valid JSON: ${error.message}`, "GATEWAY_MODE_MALFORMED");
  }
  return record;
}

/* Validates shape per SS5.1, but singles out "confirmation block missing from an
 * otherwise schema-valid record" as its own distinct, more actionable message (SS7
 * condition 4) rather than folding it into the generic "missing required field"
 * message a plain schema walk would produce for the same fact. */
function validateShape(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE} must contain a JSON object.`, "GATEWAY_MODE_INVALID");
  }
  if (record.schema_version !== MODE_SELECTION_SCHEMA.schema_version_const) {
    throw fail(
      `Refusing to start: ${GATEWAY_MODE_FILE}.schema_version must equal ` +
        `"${MODE_SELECTION_SCHEMA.schema_version_const}", got ${JSON.stringify(record.schema_version)}.`,
      "GATEWAY_MODE_INVALID"
    );
  }
  if (!MODE_SELECTION_SCHEMA.mode_enum.includes(record.mode)) {
    throw fail(
      `Refusing to start: ${GATEWAY_MODE_FILE}.mode must be one of ` +
        `${JSON.stringify(MODE_SELECTION_SCHEMA.mode_enum)}, got ${JSON.stringify(record.mode)}.`,
      "GATEWAY_MODE_INVALID"
    );
  }
  if (!Object.prototype.hasOwnProperty.call(record, "confirmation")) {
    throw fail(
      `Refusing to start: ${GATEWAY_MODE_FILE} declares mode "${record.mode}" but was never ` +
        "confirmed -- run `graphsmith gateway mode set` to confirm this change.",
      "GATEWAY_MODE_NOT_CONFIRMED"
    );
  }
  const confirmation = record.confirmation;
  if (!confirmation || typeof confirmation !== "object" || Array.isArray(confirmation)) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE}.confirmation must be an object.`, "GATEWAY_MODE_INVALID");
  }
  for (const key of MODE_SELECTION_SCHEMA.confirmation_required) {
    if (!Object.prototype.hasOwnProperty.call(confirmation, key)) {
      throw fail(`Refusing to start: ${GATEWAY_MODE_FILE}.confirmation is missing required field "${key}".`, "GATEWAY_MODE_INVALID");
    }
  }
  if (typeof confirmation.confirmed_by !== "string" || confirmation.confirmed_by.length === 0) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE}.confirmation.confirmed_by must be a non-empty string.`, "GATEWAY_MODE_INVALID");
  }
  if (!Number.isInteger(confirmation.confirmed_at) || confirmation.confirmed_at < 0) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE}.confirmation.confirmed_at must be a non-negative integer (epoch ms).`, "GATEWAY_MODE_INVALID");
  }
  if (typeof confirmation.nonce !== "string" || !MODE_SELECTION_SCHEMA.nonce_pattern.test(confirmation.nonce)) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE}.confirmation.nonce must be a 32-hex-char string.`, "GATEWAY_MODE_INVALID");
  }
  if (typeof confirmation.confirmation_token !== "string" || !MODE_SELECTION_SCHEMA.confirmation_token_pattern.test(confirmation.confirmation_token)) {
    throw fail(`Refusing to start: ${GATEWAY_MODE_FILE}.confirmation.confirmation_token must be a 64-hex-char string.`, "GATEWAY_MODE_INVALID");
  }
  return record;
}

function computeConfirmationToken(secret, record) {
  const material = [
    record.schema_version,
    record.mode,
    record.confirmation.confirmed_by,
    String(record.confirmation.confirmed_at),
    record.confirmation.nonce,
  ].join("|");
  return crypto.createHmac("sha256", secret).update(material, "utf8").digest("hex");
}

/* SS7 condition 5 (mismatch) vs condition 6 (secret file missing) are DISTINCT states,
 * deliberately not folded together -- condition 6 is "more serious" per the contract's
 * own table (never suggest re-running the confirmation CLI is sufficient, since the
 * record itself may be fine and only the key is gone). */
function verifyConfirmation(root, record) {
  const keyPath = path.join(root, GATEWAY_MODE_KEY_FILE);
  let secret;
  try {
    secret = fs.readFileSync(keyPath);
  } catch (error) {
    throw fail(
      `Refusing to start: ${record.mode} mode is declared and appears confirmed, but the ` +
        `deployment secret (${GATEWAY_MODE_KEY_FILE}) could not be read (${error.message}). ` +
        "A confirmation cannot be verified without it -- this is not the same as " +
        "'unconfirmed', and re-running the confirmation CLI will not fix a missing key file.",
      "GATEWAY_MODE_KEY_MISSING"
    );
  }
  const expected = computeConfirmationToken(secret, record);
  if (expected !== record.confirmation.confirmation_token) {
    throw fail(
      `Refusing to start: ${GATEWAY_MODE_FILE}'s mode value does not match its confirmation ` +
        "record (recomputed HMAC disagrees with confirmation_token) -- re-run " +
        "`graphsmith gateway mode set` to confirm this change.",
      "GATEWAY_MODE_CONFIRMATION_MISMATCH"
    );
  }
}

/**
 * Reads, schema-validates, and HMAC-verifies .graphsmith/gateway-mode.json per MS-FR-1,
 * then enforces SS7 condition 7 (wrong-binary) against `expectedMode`. Fails closed
 * (throws, never returns a partial/best-guess result) on every condition in SS7's table.
 *
 * @param {string} root project root (contains .graphsmith/)
 * @param {{ expectedMode: "standalone" | "attach" }} options
 * @returns {{ mode: string, confirmation: object }} the validated, confirmed record
 */
function readGatewayMode(root, options) {
  const expectedMode = options && options.expectedMode;
  if (expectedMode !== "standalone" && expectedMode !== "attach") {
    throw fail("readGatewayMode: options.expectedMode must be 'standalone' or 'attach'", "INVALID_ARGUMENT");
  }
  const raw = readModeFile(root);
  const record = validateShape(raw);
  verifyConfirmation(root, record);
  if (record.mode !== expectedMode) {
    throw fail(
      `Refusing to start: ${GATEWAY_MODE_FILE} declares mode "${record.mode}", but this is the ` +
        `${expectedMode} binary. Never running as the "wrong" mode for what is declared.`,
      "GATEWAY_MODE_WRONG_BINARY"
    );
  }
  return record;
}

module.exports = {
  GATEWAY_MODE_FILE,
  GATEWAY_MODE_KEY_FILE,
  MODE_SELECTION_SCHEMA,
  computeConfirmationToken,
  readGatewayMode,
};
