#!/usr/bin/env node
/* GraphSmith standalone gateway -- mode-selection gate (SG-FR-1 / SG-FR-2).
 *
 * Implements the STANDALONE side of MS-FR-1 from the Gateway Mode-Selection Contract
 * TRD (.plans/v0.5.0/MODE-SELECTION-CONTRACT-TRD-2026-08-26.md, "Revision 3, final"):
 * before this process's own config is even read, .graphsmith/gateway-mode.json MUST be
 * read and validated against that contract's schema + HMAC-confirmation check, and the
 * process MUST refuse to start (fail-closed) on any of SS7's seven named conditions.
 *
 * FOLLOW-UP (2026-09-02): this module originally carried a private, disclosed
 * transcription of the mode-selection contract's SS5.1 schema + SS7 validation logic
 * (see git history for the full rationale) because Track 1.1's real shared module,
 * scripts/mode-selection.js, hadn't landed on this branch yet. Track 1.1 is now merged
 * in (release/v0.5.0-candidate), so this module delegates directly to
 * scripts/mode-selection.js's readAndValidateGatewayMode/computeConfirmationToken
 * instead of re-validating the contract itself. No duplicated validation logic remains
 * here -- this file is now just the STANDALONE binary's thin call-in point.
 *
 * Zero-dependency (crypto.createHmac is stdlib, no new runtime dependency), Node >= 18.
 */
"use strict";

const path = require("path");
const modeSelection = require("../mode-selection.js");

/* Derived from the shared module's own path helpers (rather than re-declared as
 * separate string literals) so these two constants can never drift from what
 * scripts/mode-selection.js actually reads/writes. */
const GATEWAY_MODE_FILE = path.relative(".", modeSelection.gatewayModePath("."));
const GATEWAY_MODE_KEY_FILE = path.relative(".", modeSelection.gatewayModeKeyPath("."));

function fail(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

/**
 * Reads, schema-validates, and HMAC-verifies .graphsmith/gateway-mode.json per MS-FR-1,
 * then enforces SS7 condition 7 (wrong-binary) against `expectedMode`. Fails closed
 * (throws, never returns a partial/best-guess result) on every condition in SS7's table.
 * Thin wrapper around scripts/mode-selection.js's readAndValidateGatewayMode -- the
 * contract's validation logic lives there now, not here.
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
  return modeSelection.readAndValidateGatewayMode(root, { expectedMode });
}

module.exports = {
  GATEWAY_MODE_FILE,
  GATEWAY_MODE_KEY_FILE,
  computeConfirmationToken: modeSelection.computeConfirmationToken,
  readGatewayMode,
};
