#!/usr/bin/env node
/* GraphSmith gateway mode-selection contract (Track 1.1) --
 * scripts/mode-selection.js.
 *
 * Implements the TRD "GraphSmith Gateway Mode-Selection Contract -- TRD
 * (Track 1.1) -- Rev 3, final" (Linear SAT-1095, document
 * 49e46a35-4c6f-4961-90af-576b712263e7, 2026-08-28), "Option C":
 *
 *   Mode selection lives in its OWN dedicated file, `.graphsmith/gateway-
 *   mode.json` -- a sibling to `.graphsmith/state/`, deliberately outside
 *   it -- whose content validates directly against this contract's own
 *   independently-owned schema, schemas/mode-selection-contract.schema.json,
 *   at the file's root. No wrapper envelope, no `$ref` embedding into
 *   either Track 1.2's or Track 1.3's own config schema. Neither track's
 *   own config file may reference or contain a mode field -- each reads
 *   this file independently at startup (TRD S3.1/S9).
 *
 * This file is the SOLE place this contract's logic lives. Track 1.2's
 * `scripts/gateway/mode-gate.js` and Track 1.3's `scripts/gsa-attach-
 * shim.js` each built a private, disclosed transcription of this contract
 * while it didn't exist yet (see the Track 1.1 dispatch, 2026-08-29); both
 * should import from here instead once merged -- see the module-level
 * `readAndValidateGatewayMode`/`statusReport` exports below, which are
 * exactly the two entry points each track's own startup gate and `status`
 * command need.
 *
 * The confirmation CLI (`graphsmith gateway mode set`, wired in
 * graphsmith-cli.js) is the ONLY code path that writes
 * `.graphsmith/gateway-mode.json` -- always a full atomic overwrite
 * (state-store.js's `atomicOverwriteFile`), never a partial edit (TRD S3.3,
 * MS-FR-3). Reader code (both tracks' own startup, and this file's own
 * `statusReport`) must never write this file.
 *
 * Zero-dependency CommonJS (MS-NFR-2): only Node's stdlib `crypto`/`fs`/
 * `path`, and this repo's own state-store.js (atomic-write primitives,
 * reused rather than reinvented per the same NFR-2 precedent
 * writer-claim.js already sets) and schema-validate.js (the repo's
 * existing hand-rolled JSON-Schema-2020-12-subset validator, extended by
 * this same change to add the two keywords this schema needs -- see that
 * file's own header).
 *
 * WHAT MS-FR-5 / SAT-1094 MEANS FOR THIS FILE: a confirmed mode switch
 * SHOULD append a MODE_CHANGED record to the new gateway-session chain
 * (Standalone Gateway TRD SG-FR-5) -- but that chain does not exist yet.
 * TRD S8 is explicit that this is BLOCKED on SG-FR-5, not to be built
 * ahead of it, and is tracked separately as SAT-1094. This file therefore
 * does NOT attempt any chain-audit write; `writeGatewayMode` returns the
 * written record so a FUTURE caller (once SG-FR-5 lands) can append the
 * MODE_CHANGED record itself, but no such append happens here. This is a
 * disclosed, temporary gap (TRD S8), not a silent one.
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const schemaValidate = require("./schema-validate.js");
const stateStore = require("./state-store.js");

const MODE_SCHEMA = require("../schemas/mode-selection-contract.schema.json");

const SCHEMA_VERSION = "1.0";
const MODES = Object.freeze(["standalone", "attach"]);
const GATEWAY_MODE_DIRNAME = ".graphsmith";
const GATEWAY_MODE_FILENAME = "gateway-mode.json";
const STATE_DIRNAME = "state";
const KEY_FILENAME = "gateway-mode.key";
const DEFAULT_PRE_AUTHORIZATION_TTL_MS = 24 * 60 * 60 * 1000; // 24h, TRD S3.3/S4 default

/* Same root schema as MODE_SCHEMA, except `confirmation` is not required --
 * used ONLY to recognize the specific "declared but never confirmed" shape
 * (TRD S7 condition 4) so it gets its own operator-facing message/code
 * (GATEWAY_MODE_NOT_CONFIRMED) rather than a generic "$.confirmation is
 * required" GATEWAY_MODE_INVALID. A record that fails even this relaxed
 * check falls through to full validation against MODE_SCHEMA, which is the
 * only schema this contract actually ships (schemas/mode-selection-
 * contract.schema.json is never altered by this precheck). */
const SCHEMA_VALID_WITHOUT_CONFIRMATION = Object.freeze({
  ...MODE_SCHEMA,
  required: ["schema_version", "mode"],
});

function fail(message, code = "GATEWAY_MODE_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function gatewayDir(rootDir) {
  return path.join(rootDir, GATEWAY_MODE_DIRNAME);
}

function gatewayModePath(rootDir) {
  return path.join(gatewayDir(rootDir), GATEWAY_MODE_FILENAME);
}

function gatewayStateDir(rootDir) {
  return path.join(gatewayDir(rootDir), STATE_DIRNAME);
}

function gatewayModeKeyPath(rootDir) {
  return path.join(gatewayStateDir(rootDir), KEY_FILENAME);
}

function validateModeSelectionRecord(record, context) {
  const errors = schemaValidate.validate(record, MODE_SCHEMA, "$");
  if (errors.length) throw fail(`Invalid gateway-mode record in ${context}: ${errors[0]}`, "GATEWAY_MODE_INVALID");
  return record;
}

/* HMAC-SHA256(secret, schema_version|mode|confirmed_by|confirmed_at|nonce),
 * hex -- TRD S5.1's confirmation_token formula, keyed OQ-4. `secret` is the
 * per-deployment key (see ensureSecret/readSecret), used directly as the
 * HMAC key material -- no decode/derive step, matching writer-claim.js's
 * own convention of using its 32-hex-char randomToken() values directly
 * rather than decoding them first. */
function computeConfirmationToken(secret, record) {
  const confirmation = record.confirmation || record; // accept either a full record or a bare {confirmed_by, confirmed_at, nonce}
  const material = [
    record.schema_version !== undefined ? record.schema_version : SCHEMA_VERSION,
    record.mode,
    confirmation.confirmed_by,
    confirmation.confirmed_at,
    confirmation.nonce,
  ].join("|");
  return crypto.createHmac("sha256", secret).update(material).digest("hex");
}

/* Generates the per-deployment secret on first use (TRD S4/MS-FR-3),
 * gitignored (.gitignore) and file-permission-restricted (chmod 0600,
 * best-effort on platforms without POSIX permission bits -- see
 * atomicOverwriteFile's own best-effort directory-fsync precedent in
 * state-store.js for the same "swallow on a platform that can't do this"
 * shape). Uses atomicCreateExclusive so a race between two concurrent
 * first-time `mode set` invocations can never produce two different
 * secrets -- the loser reads back the winner's secret instead. */
function ensureSecret(rootDir) {
  const keyPath = gatewayModeKeyPath(rootDir);
  fs.mkdirSync(gatewayStateDir(rootDir), { recursive: true });
  const candidate = crypto.randomBytes(32).toString("hex");
  try {
    stateStore.atomicCreateExclusive(keyPath, candidate);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = readSecret(rootDir);
    if (existing === null) throw error; // vanished between EEXIST and read -- surface the original error
    return existing;
  }
  try { fs.chmodSync(keyPath, 0o600); }
  catch (error) { if (process.platform !== "win32") throw error; }
  return candidate;
}

function readSecret(rootDir) {
  try {
    return fs.readFileSync(gatewayModeKeyPath(rootDir), "utf8").trim();
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw fail(`Cannot read the deployment's mode-confirmation key at ${gatewayModeKeyPath(rootDir)}: ${error.message}`, "GATEWAY_MODE_KEY_UNREADABLE");
  }
}

function readGatewayModeFile(rootDir) {
  const target = gatewayModePath(rootDir);
  let raw;
  try {
    raw = fs.readFileSync(target, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      throw fail(
        `Gateway mode is not declared (${target} does not exist). Run ` +
        `\`graphsmith gateway mode set <standalone|attach>\` to declare and confirm this ` +
        `deployment's mode before starting.`,
        "GATEWAY_MODE_NOT_DECLARED"
      );
    }
    throw fail(`Cannot read ${target}: ${error.message}`, "GATEWAY_MODE_UNREADABLE");
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw fail(`Invalid JSON in ${target}: ${error.message}`, "GATEWAY_MODE_MALFORMED");
  }
}

/* The full TRD S3.2/S7 startup gate: READ -> SCHEMA -> CONF -> (optional)
 * MATCH. Both Track 1.2's and Track 1.3's binaries call this before reading
 * their OWN config file (TRD S9). `options.expectedMode`, if given, also
 * performs TRD S7 condition 7 (GATEWAY_MODE_WRONG_BINARY) -- callers may
 * still choose to implement that check themselves instead (TRD S9: "still
 * implement your own GATEWAY_MODE_WRONG_BINARY check... rather than
 * trusting"); passing it here is a convenience, not a requirement. Every
 * failure throws a `fail()` Error whose `.code` is exactly one of the
 * GATEWAY_MODE_* codes in TRD S7's table -- callers should treat any thrown
 * error here as fail-closed: refuse to start, never proceed under an
 * assumed default. */
function readAndValidateGatewayMode(rootDir, options = {}) {
  const record = readGatewayModeFile(rootDir);

  if (record && typeof record === "object" && !Array.isArray(record) && !("confirmation" in record)) {
    const precheckErrors = schemaValidate.validate(record, SCHEMA_VALID_WITHOUT_CONFIRMATION, "$");
    if (precheckErrors.length === 0) {
      throw fail(
        "Gateway mode declared but never confirmed -- run `graphsmith gateway mode set` to confirm this change.",
        "GATEWAY_MODE_NOT_CONFIRMED"
      );
    }
  }

  validateModeSelectionRecord(record, gatewayModePath(rootDir));

  const secret = readSecret(rootDir);
  if (secret === null) {
    throw fail(
      `Cannot verify this deployment's mode confirmation: the confirmation key ` +
      `(${gatewayModeKeyPath(rootDir)}) is missing while a confirmation_token is present.`,
      "GATEWAY_MODE_KEY_MISSING"
    );
  }

  const recomputed = computeConfirmationToken(secret, record);
  if (recomputed !== record.confirmation.confirmation_token) {
    throw fail(
      "The mode value does not match its confirmation record -- re-run " +
      "`graphsmith gateway mode set` to confirm this change.",
      "GATEWAY_MODE_CONFIRMATION_MISMATCH"
    );
  }

  if (options.expectedMode && record.mode !== options.expectedMode) {
    throw fail(
      `This process is the "${options.expectedMode}" binary, but the confirmed gateway mode is ` +
      `"${record.mode}". Refusing to start as the wrong binary for the declared mode.`,
      "GATEWAY_MODE_WRONG_BINARY"
    );
  }

  return record;
}

/* Read-only, non-throwing status -- MS-FR-4 (`graphsmith gateway mode
 * status`): reports declared/mode/confirmed/by whom/when/pre-authorized/
 * whether the token currently recomputes correctly, without requiring a
 * running gateway process and without ever throwing. Mirrors writer-
 * claim.js's own readStatus() shape (a plain object, `ok`/`reason` instead
 * of a thrown error) for the same reason: a status command must always be
 * able to report, including reporting "broken". */
function statusReport(rootDir) {
  const target = gatewayModePath(rootDir);
  let raw;
  try {
    raw = fs.readFileSync(target, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return { declared: false, ok: false, reason: "GATEWAY_MODE_NOT_DECLARED" };
    return { declared: false, ok: false, reason: "GATEWAY_MODE_UNREADABLE", error: error.message };
  }

  let record;
  try {
    record = JSON.parse(raw);
  } catch (error) {
    return { declared: true, ok: false, reason: "GATEWAY_MODE_MALFORMED", error: error.message };
  }

  if (record && typeof record === "object" && !Array.isArray(record) && !("confirmation" in record)) {
    const precheckErrors = schemaValidate.validate(record, SCHEMA_VALID_WITHOUT_CONFIRMATION, "$");
    if (precheckErrors.length === 0) {
      return { declared: true, mode: record.mode, confirmed: false, ok: false, reason: "GATEWAY_MODE_NOT_CONFIRMED" };
    }
  }

  const schemaErrors = schemaValidate.validate(record, MODE_SCHEMA, "$");
  if (schemaErrors.length) {
    return { declared: true, ok: false, reason: "GATEWAY_MODE_INVALID", error: schemaErrors[0] };
  }

  const secret = readSecret(rootDir);
  if (secret === null) {
    return {
      declared: true,
      mode: record.mode,
      confirmed: true,
      confirmed_by: record.confirmation.confirmed_by,
      confirmed_at: record.confirmation.confirmed_at,
      pre_authorized: Boolean(record.confirmation.pre_authorized),
      token_valid: false,
      ok: false,
      reason: "GATEWAY_MODE_KEY_MISSING",
    };
  }

  const tokenValid = computeConfirmationToken(secret, record) === record.confirmation.confirmation_token;
  return {
    declared: true,
    mode: record.mode,
    confirmed: true,
    confirmed_by: record.confirmation.confirmed_by,
    confirmed_at: record.confirmation.confirmed_at,
    pre_authorized: Boolean(record.confirmation.pre_authorized),
    token_valid: tokenValid,
    ok: tokenValid,
    reason: tokenValid ? undefined : "GATEWAY_MODE_CONFIRMATION_MISMATCH",
  };
}

/* Best-effort, never throws -- used by the interactive `mode set` flow to
 * show "current mode -> target mode" (TRD S3.3's SHOW step) even when the
 * current file is absent, unreadable, or invalid. Never used for any
 * security-relevant decision -- readAndValidateGatewayMode/statusReport are
 * the authoritative readers. */
function describeCurrentMode(rootDir) {
  try {
    const record = JSON.parse(fs.readFileSync(gatewayModePath(rootDir), "utf8"));
    return typeof record === "object" && record !== null && typeof record.mode === "string" ? record.mode : "(invalid: no mode field)";
  } catch (error) {
    if (error.code === "ENOENT") return "(none declared)";
    return "(unreadable or invalid)";
  }
}

/* The sole writer of .graphsmith/gateway-mode.json (TRD S4/MS-FR-2/MS-FR-3):
 * always a full atomicOverwriteFile of the whole record, never a partial
 * edit. Only called from the confirmation CLI (graphsmith-cli.js's `gateway
 * mode set`), both the interactive and --use-pre-authorization paths. */
function writeGatewayMode(rootDir, { mode, confirmedBy, confirmedAt, preAuthorized = false }) {
  if (!MODES.includes(mode)) throw fail(`mode must be one of ${MODES.join(", ")}`, "INVALID_ARGUMENT");
  if (typeof confirmedBy !== "string" || confirmedBy.length === 0) throw fail("confirmedBy must be a non-empty string", "INVALID_ARGUMENT");
  if (!Number.isSafeInteger(confirmedAt) || confirmedAt < 0) throw fail("confirmedAt must be a non-negative safe integer", "INVALID_ARGUMENT");

  const dir = gatewayDir(rootDir);
  fs.mkdirSync(dir, { recursive: true });
  const secret = ensureSecret(rootDir);
  const nonce = crypto.randomBytes(16).toString("hex");

  const record = {
    schema_version: SCHEMA_VERSION,
    mode,
    confirmation: { confirmed_by: confirmedBy, confirmed_at: confirmedAt, nonce },
  };
  record.confirmation.confirmation_token = computeConfirmationToken(secret, record);
  if (preAuthorized) record.confirmation.pre_authorized = true;

  validateModeSelectionRecord(record, "confirmation write");
  stateStore.atomicOverwriteFile(gatewayModePath(rootDir), `${JSON.stringify(record, null, 2)}\n`, dir);
  return record;
}

/* The pre-authorization artifact (TRD S3.3/S4, OQ-3): produced only by an
 * interactive `--pre-authorize` run. NOT covered by schemas/mode-selection-
 * contract.schema.json (that schema governs gateway-mode.json's own
 * content only) -- the TRD describes this artifact's fields in prose (S4)
 * but does not give it a JSON Schema of its own, so this file validates its
 * shape directly rather than inventing an undocumented second schema file.
 * `hmac = HMAC-SHA256(secret, schema_version|mode|expires_at)` -- "an HMAC
 * over both [the target mode and the expiry timestamp]", per the TRD's own
 * wording; `authorized_by`/`authorized_at` are informational/audit fields,
 * not covered by the HMAC, since the TRD scopes the signed material to
 * exactly those two fields. */
function createPreAuthorizationArtifact(rootDir, { mode, authorizedBy, authorizedAt, ttlMs = DEFAULT_PRE_AUTHORIZATION_TTL_MS }) {
  if (!MODES.includes(mode)) throw fail(`mode must be one of ${MODES.join(", ")}`, "INVALID_ARGUMENT");
  if (typeof authorizedBy !== "string" || authorizedBy.length === 0) throw fail("authorizedBy must be a non-empty string", "INVALID_ARGUMENT");
  if (!Number.isSafeInteger(authorizedAt) || authorizedAt < 0) throw fail("authorizedAt must be a non-negative safe integer", "INVALID_ARGUMENT");
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw fail("ttlMs must be a positive safe integer", "INVALID_ARGUMENT");

  const secret = ensureSecret(rootDir);
  const expiresAt = authorizedAt + ttlMs;
  const hmac = crypto.createHmac("sha256", secret).update(`${SCHEMA_VERSION}|${mode}|${expiresAt}`).digest("hex");
  return {
    schema_version: SCHEMA_VERSION,
    mode,
    authorized_by: authorizedBy,
    authorized_at: authorizedAt,
    expires_at: expiresAt,
    hmac,
  };
}

/* Verifies a pre-authorization artifact against the deployment's own
 * secret (TRD S4/MS-FR-6): HMAC must recompute, the artifact's own `mode`
 * must match the mode being requested on this invocation (a tampered or
 * mismatched artifact must never be silently accepted for a different
 * mode than it was issued for), and it must not be expired. Any failure
 * throws -- MS-FR-6: "MUST refuse (not proceed with a warning) on any
 * mismatch or expiry." Never writes anything. */
function verifyPreAuthorizationArtifact(rootDir, artifact, { mode, now }) {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) {
    throw fail("Pre-authorization artifact is not a JSON object", "GATEWAY_MODE_PRE_AUTH_MALFORMED");
  }
  const { schema_version: schemaVersion, mode: artifactMode, authorized_by: authorizedBy, expires_at: expiresAt, hmac } = artifact;
  if (schemaVersion !== SCHEMA_VERSION) {
    throw fail(`Pre-authorization artifact has an unsupported schema_version (${JSON.stringify(schemaVersion)})`, "GATEWAY_MODE_PRE_AUTH_INVALID");
  }
  if (typeof artifactMode !== "string" || typeof authorizedBy !== "string" || !Number.isSafeInteger(expiresAt) || typeof hmac !== "string") {
    throw fail("Pre-authorization artifact is missing or has malformed required fields (mode/authorized_by/expires_at/hmac)", "GATEWAY_MODE_PRE_AUTH_INVALID");
  }
  if (artifactMode !== mode) {
    throw fail(`Pre-authorization artifact was issued for mode "${artifactMode}", not the requested "${mode}" -- refusing`, "GATEWAY_MODE_PRE_AUTH_MODE_MISMATCH");
  }

  const secret = readSecret(rootDir);
  if (secret === null) {
    throw fail("Cannot verify pre-authorization: no deployment confirmation key exists yet at " + gatewayModeKeyPath(rootDir), "GATEWAY_MODE_KEY_MISSING");
  }
  const recomputed = crypto.createHmac("sha256", secret).update(`${schemaVersion}|${artifactMode}|${expiresAt}`).digest("hex");
  if (recomputed !== hmac) {
    throw fail("Pre-authorization artifact failed HMAC verification -- refusing (tampered, forged, or signed by a different deployment)", "GATEWAY_MODE_PRE_AUTH_TAMPERED");
  }
  if (now >= expiresAt) {
    throw fail(`Pre-authorization artifact expired at ${new Date(expiresAt).toISOString()}`, "GATEWAY_MODE_PRE_AUTH_EXPIRED");
  }
  return artifact;
}

module.exports = {
  SCHEMA_VERSION,
  MODES,
  MODE_SCHEMA,
  GATEWAY_MODE_FILENAME,
  DEFAULT_PRE_AUTHORIZATION_TTL_MS,
  gatewayDir,
  gatewayModePath,
  gatewayStateDir,
  gatewayModeKeyPath,
  validateModeSelectionRecord,
  computeConfirmationToken,
  ensureSecret,
  readSecret,
  readAndValidateGatewayMode,
  statusReport,
  describeCurrentMode,
  writeGatewayMode,
  createPreAuthorizationArtifact,
  verifyPreAuthorizationArtifact,
};

function selftest() {
  const os = require("os");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-mode-selection-"));
  const tests = [];
  try {
    let threw = null;
    try { readAndValidateGatewayMode(root); } catch (error) { threw = error; }
    if (threw?.code !== "GATEWAY_MODE_NOT_DECLARED") throw new Error(`expected GATEWAY_MODE_NOT_DECLARED, got ${threw && threw.code}`);
    tests.push({ name: "missing-file-not-declared", status: "pass" });

    const written = writeGatewayMode(root, { mode: "standalone", confirmedBy: "paul@example.com", confirmedAt: 1_700_000_000_000 });
    const read = readAndValidateGatewayMode(root, { expectedMode: "standalone" });
    if (read.mode !== "standalone" || read.confirmation.confirmation_token !== written.confirmation.confirmation_token) {
      throw new Error("round trip did not return the record just written");
    }
    tests.push({ name: "round-trip-write-then-validate", status: "pass" });

    threw = null;
    try { readAndValidateGatewayMode(root, { expectedMode: "attach" }); } catch (error) { threw = error; }
    if (threw?.code !== "GATEWAY_MODE_WRONG_BINARY") throw new Error(`expected GATEWAY_MODE_WRONG_BINARY, got ${threw && threw.code}`);
    tests.push({ name: "wrong-binary-refused", status: "pass" });

    const status = statusReport(root);
    if (!status.ok || !status.token_valid) throw new Error("statusReport did not report a healthy confirmed record");
    tests.push({ name: "status-report-ok", status: "pass" });

    return { schema_version: SCHEMA_VERSION, status: "pass", tests };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    console.log(JSON.stringify(selftest()));
  } catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exitCode = 1;
  }
}
