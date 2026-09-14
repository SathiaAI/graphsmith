"use strict";
/* Shared test helper: writes a valid (or deliberately broken) .graphsmith/gateway-mode.json
 * + .graphsmith/state/gateway-mode.key pair into a fresh root directory, using the SAME
 * HMAC formula scripts/gateway/mode-gate.js verifies against -- this stands in for the
 * mode-selection contract's own confirmation CLI (Track 1.1's `graphsmith gateway mode
 * set`, scripts/mode-selection.js's writeGatewayMode/ensureSecret), now landed in this
 * repo. The deployment secret is written as a hex-encoded STRING (not raw bytes) because
 * that is the real, observable format ensureSecret() produces
 * (crypto.randomBytes(32).toString("hex")) and readSecret() expects (utf8 + trim) --
 * this fixture previously wrote raw random bytes, which only worked against mode-gate.js's
 * OLD private reader (an unencoded Buffer read with no format assumption); it does not
 * match the real confirmation CLI's on-disk format and was updated to match. */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { computeConfirmationToken } = require("../../../scripts/gateway/mode-gate.js");

function writeConfirmedMode(root, mode, options = {}) {
  fs.mkdirSync(path.join(root, ".graphsmith", "state"), { recursive: true });
  const secret = options.secret || crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(path.join(root, ".graphsmith", "state", "gateway-mode.key"), secret, "utf8");
  const record = {
    schema_version: "1.0",
    mode,
    confirmation: {
      confirmed_by: options.confirmedBy || "test-operator@example.com",
      confirmed_at: options.confirmedAt !== undefined ? options.confirmedAt : Date.now(),
      nonce: options.nonce || crypto.randomBytes(16).toString("hex"),
    },
  };
  record.confirmation.confirmation_token = options.badToken || computeConfirmationToken(secret, record);
  fs.writeFileSync(path.join(root, ".graphsmith", "gateway-mode.json"), JSON.stringify(record, null, 2));
  return record;
}

module.exports = { writeConfirmedMode };
