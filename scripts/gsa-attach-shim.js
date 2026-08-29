#!/usr/bin/env node
/* GSA attach-mode shim -- scripts/gsa-attach-shim.js.
 *
 * FR-7 (Track 1.3), per .plans/v0.5.0/WRITER-CLAIM-TRD-HARDENING-2026-08-22.md §3.1 and
 * the mode-selection contract (.plans/v0.5.0/MODE-SELECTION-CONTRACT-TRD-2026-08-26.md,
 * "Rev 3", CLOSED). Attach mode means a shim EMBEDS into an enterprise's own,
 * already-running MCP gateway process -- this module is that shim: a library an external
 * process `require()`s, not a standalone server with its own process lifecycle (that is
 * Track 1.2's `gateway-config`/standalone-binary scope, out of scope here). It never
 * calls `process.exit()`, never installs its own signal handlers, and never runs an event
 * loop of its own -- every lifecycle decision belongs to the embedding gateway. See
 * docs/GSA-ATTACH-MODE-WIRING.md for the exact call sequence an embedding gateway is
 * expected to follow.
 *
 * What AttachModeShim.start() does, in order, matching FR-7(a)-(c) exactly:
 *   (a) validates .graphsmith/gateway-mode.json against the mode-selection contract's own
 *       schema (MS-FR-1, §5.1/§7 of the mode-selection TRD) -- BEFORE anything else --
 *       and refuses unless it is present, schema-valid, HMAC-confirmed, and declares
 *       mode: "attach". This mirrors §3.2's "Startup validation flow" exactly: mode
 *       selection is a standalone pre-flight gate, checked before the writer-claim gate.
 *   (b) calls WriterClaim.acquire() against .graphsmith/state -- FR-1's existing
 *       refuse-to-start behavior, unchanged, not reimplemented here.
 *   (c) calls WriterClaim.startHeartbeat() immediately after a successful acquire.
 * AttachModeShim.stop() calls WriterClaim.release() (and stops the heartbeat). Nothing in
 * this module ever calls `sealBoundaryBundle()` (scripts/gsa-mcp-shim.js) -- FR-7 is
 * explicit that call happens per observed MCP session, from wherever the embedding
 * gateway already calls it today; this module's whole job is the once-per-process
 * precondition around that existing call site, not a wrapper around it.
 *
 * OUT OF SCOPE here, deliberately, matching this track's build instructions: FR-8
 * (host-identity collision resistance -- defaultHostId() is used unmodified),
 * AC-5 (KNOWN-LIMITATIONS.md), FR-9/FR-10 (both explicitly deferred pending a real
 * caller -- this module reports itself as exactly that caller in FR-7's build note, but
 * building FR-9/FR-10 themselves is separately tracked).
 *
 * The gateway-mode.json validation below (readAndValidateGatewayMode) is a self-contained
 * implementation of the mode-selection contract's §5.1 schema and §7 fail-closed table.
 * It is deliberately NOT shared code from a Track-1.1-owned module -- none exists yet in
 * this repo (the mode-selection TRD's own status line: "DRAFT design, no code, no schema
 * files created in the repo") -- and per that contract's own §9, "[Track 1.3] should read
 * .graphsmith/gateway-mode.json independently, the same way Track 1.2 does". This also
 * means it deliberately does NOT add schemas/mode-selection-contract.schema.json: that
 * schema is independently owned by Track 1.1 per the contract's own §5.1 header, and is
 * not this track's file to create.
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { WriterClaim } = require("./writer-claim.js");

const MODE_FILE = "gateway-mode.json";
const KEY_FILE = "gateway-mode.key";
const SCHEMA_VERSION = "1.0";
const BINARY_MODE = "attach";

function fail(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/* §5.1's root schema: schema_version/mode/confirmation, additionalProperties: false.
 * Deliberately does NOT check confirmation's presence -- that gets its own error code
 * (§7 condition 4), checked separately by the caller so the operator-facing message can
 * name the actual problem instead of a generic schema failure. */
function validateRootShape(record) {
  if (!isPlainObject(record)) {
    throw fail(`${MODE_FILE} must contain a JSON object at its root`, "GATEWAY_MODE_INVALID");
  }
  const allowed = ["schema_version", "mode", "confirmation"];
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      throw fail(`${MODE_FILE} has an unexpected property "${key}" (additionalProperties: false)`, "GATEWAY_MODE_INVALID");
    }
  }
  if (record.schema_version !== SCHEMA_VERSION) {
    throw fail(`${MODE_FILE}.schema_version must be "${SCHEMA_VERSION}", got ${JSON.stringify(record.schema_version)}`, "GATEWAY_MODE_INVALID");
  }
  if (record.mode !== "standalone" && record.mode !== "attach") {
    throw fail(`${MODE_FILE}.mode must be "standalone" or "attach", got ${JSON.stringify(record.mode)}`, "GATEWAY_MODE_INVALID");
  }
}

/* §5.1's `confirmation` sub-schema. Called only once the block is known to be present
 * (§7 condition 4 is checked by the caller first). */
function validateConfirmationShape(confirmation) {
  if (!isPlainObject(confirmation)) {
    throw fail(`${MODE_FILE}.confirmation must be a JSON object`, "GATEWAY_MODE_INVALID");
  }
  const allowed = ["confirmed_by", "confirmed_at", "nonce", "confirmation_token", "pre_authorized"];
  for (const key of Object.keys(confirmation)) {
    if (!allowed.includes(key)) {
      throw fail(`${MODE_FILE}.confirmation has an unexpected property "${key}" (additionalProperties: false)`, "GATEWAY_MODE_INVALID");
    }
  }
  for (const required of ["confirmed_by", "confirmed_at", "nonce", "confirmation_token"]) {
    if (!(required in confirmation)) {
      throw fail(`${MODE_FILE}.confirmation is missing required field "${required}"`, "GATEWAY_MODE_INVALID");
    }
  }
  if (typeof confirmation.confirmed_by !== "string" || confirmation.confirmed_by.length < 1) {
    throw fail(`${MODE_FILE}.confirmation.confirmed_by must be a non-empty string`, "GATEWAY_MODE_INVALID");
  }
  if (!Number.isInteger(confirmation.confirmed_at) || confirmation.confirmed_at < 0) {
    throw fail(`${MODE_FILE}.confirmation.confirmed_at must be a non-negative integer (epoch ms)`, "GATEWAY_MODE_INVALID");
  }
  if (typeof confirmation.nonce !== "string" || !/^[a-f0-9]{32}$/.test(confirmation.nonce)) {
    throw fail(`${MODE_FILE}.confirmation.nonce must match ^[a-f0-9]{32}$`, "GATEWAY_MODE_INVALID");
  }
  if (typeof confirmation.confirmation_token !== "string" || !/^[a-f0-9]{64}$/.test(confirmation.confirmation_token)) {
    throw fail(`${MODE_FILE}.confirmation.confirmation_token must match ^[a-f0-9]{64}$`, "GATEWAY_MODE_INVALID");
  }
  if ("pre_authorized" in confirmation && typeof confirmation.pre_authorized !== "boolean") {
    throw fail(`${MODE_FILE}.confirmation.pre_authorized must be a boolean`, "GATEWAY_MODE_INVALID");
  }
}

/* MS-FR-1: validate .graphsmith/gateway-mode.json exactly per the mode-selection
 * contract's §3.2 startup-validation flow / §7 fail-closed table, in the same order:
 * missing -> unreadable -> malformed/invalid -> unconfirmed -> key-missing ->
 * HMAC-mismatch -> wrong-binary. Exported standalone (not only reachable through
 * AttachModeShim.start()) so the gate can be pinned by tests without touching
 * WriterClaim at all -- mirrors writer-claim.js exporting decideOnExisting for the same
 * reason. `graphsmithDir` is the `.graphsmith` directory itself (i.e. the parent of both
 * `gateway-mode.json` and `state/gateway-mode.key`), not the project root. */
function readAndValidateGatewayMode(graphsmithDir) {
  const modePath = path.join(graphsmithDir, MODE_FILE);
  let raw;
  try {
    raw = fs.readFileSync(modePath, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      throw fail(
        `Refusing to start: no gateway mode has been declared for this deployment ` +
        `(${modePath} does not exist). Run "graphsmith gateway mode set attach" before ` +
        `starting the attach-mode shim.`,
        "GATEWAY_MODE_NOT_DECLARED"
      );
    }
    throw fail(`Refusing to start: ${modePath} could not be read: ${error.message}`, "GATEWAY_MODE_UNREADABLE");
  }

  let record;
  try {
    record = JSON.parse(raw);
  } catch (error) {
    throw fail(`Refusing to start: ${modePath} is not valid JSON: ${error.message}`, "GATEWAY_MODE_MALFORMED");
  }

  validateRootShape(record);

  if (!("confirmation" in record)) {
    throw fail(
      `Refusing to start: gateway mode is declared (mode: "${record.mode}") but has never ` +
      `been confirmed -- run "graphsmith gateway mode set ${record.mode}" to confirm this ` +
      `deployment's mode.`,
      "GATEWAY_MODE_NOT_CONFIRMED"
    );
  }
  validateConfirmationShape(record.confirmation);

  const keyPath = path.join(graphsmithDir, "state", KEY_FILE);
  let secret;
  try {
    secret = fs.readFileSync(keyPath, "utf8").trim();
  } catch (error) {
    throw fail(
      `Refusing to start: a confirmation is present in ${modePath} but its signing key ` +
      `(${keyPath}) is missing or unreadable, so the confirmation cannot be verified. This ` +
      `is a distinct, more serious problem than "unconfirmed" -- re-running ` +
      `"graphsmith gateway mode set" alone will not fix a missing key file.`,
      "GATEWAY_MODE_KEY_MISSING"
    );
  }

  const { schema_version, mode, confirmation } = record;
  const message = [schema_version, mode, confirmation.confirmed_by, String(confirmation.confirmed_at), confirmation.nonce].join("|");
  const expectedToken = crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
  const actualToken = confirmation.confirmation_token;
  const tokensMatch =
    expectedToken.length === actualToken.length &&
    crypto.timingSafeEqual(Buffer.from(expectedToken, "utf8"), Buffer.from(actualToken, "utf8"));
  if (!tokensMatch) {
    throw fail(
      `Refusing to start: the mode value in ${modePath} does not match its confirmation ` +
      `record -- re-run "graphsmith gateway mode set ${mode}" to confirm this change.`,
      "GATEWAY_MODE_CONFIRMATION_MISMATCH"
    );
  }

  if (mode !== BINARY_MODE) {
    throw fail(
      `Refusing to start: ${modePath} declares and confirms mode "${mode}", but this is the ` +
      `${BINARY_MODE}-mode shim. Run the "${mode}" binary/process instead, or re-run ` +
      `"graphsmith gateway mode set ${BINARY_MODE}" if this deployment should switch modes.`,
      "GATEWAY_MODE_WRONG_BINARY"
    );
  }

  return record;
}

/* The shim itself. A thin, deliberately inert-until-called wrapper -- construction does
 * no I/O; only start()/stop() do. */
class AttachModeShim {
  /* Mirrors StateStore's own constructor shape (scripts/state-store.js) for consistency:
   * projectRoot defaults to process.cwd(), and .graphsmith/state is derived from it the
   * same way. options.hostId/instanceId/heartbeatMs/staleAfterMs/clock/onClaimLost pass
   * straight through to WriterClaim, unmodified -- this module adds no mode-awareness to
   * WriterClaim itself (mode-selection TRD §6: "1.2 and 1.3 must not ... make
   * writer-claim mode-aware; they compose by sequencing only"). */
  constructor(projectRoot = process.cwd(), options = {}) {
    this.projectRoot = path.resolve(projectRoot);
    this.graphsmithDir = path.join(this.projectRoot, ".graphsmith");
    this.stateDir = path.join(this.graphsmithDir, "state");
    this._claim = new WriterClaim(this.stateDir, {
      hostId: options.hostId,
      instanceId: options.instanceId,
      heartbeatMs: options.heartbeatMs,
      staleAfterMs: options.staleAfterMs,
      skewToleranceMs: options.skewToleranceMs,
      clock: options.clock,
      onClaimLost: options.onClaimLost,
    });
    this._modeRecord = null;
    this._started = false;
  }

  /* (a)+(b)+(c) in order. Throws (with a named .code, matching WriterClaim's own
   * fail-closed convention) on any failure -- it never calls process.exit() itself; see
   * docs/GSA-ATTACH-MODE-WIRING.md for why that decision belongs to the embedding
   * gateway, not this library. */
  start() {
    if (this._started) {
      throw fail("AttachModeShim.start() was already called on this instance", "ATTACH_SHIM_ALREADY_STARTED");
    }
    this._modeRecord = readAndValidateGatewayMode(this.graphsmithDir);   // (a) MS-FR-1
    const status = this._claim.acquire();                                // (b) FR-1
    this._claim.startHeartbeat();                                        // (c) FR-2
    this._started = true;
    return status;
  }

  /* Idempotent: safe to call from a signal handler even if start() never completed (e.g.
   * it threw before acquiring), and safe to call twice. Mirrors WriterClaim.release()'s
   * own idempotence. */
  stop() {
    this._started = false;
    return this._claim.release();
  }

  /* FR-4-equivalent surface for this shim: current mode-selection + writer-claim state,
   * useful for a health-check endpoint the embedding gateway already exposes. Never
   * throws; reflects "not started" honestly rather than reading stale state. */
  status() {
    return {
      started: this._started,
      mode: this._modeRecord ? this._modeRecord.mode : null,
      writerClaim: this._claim.status(),
    };
  }
}

module.exports = {
  AttachModeShim,
  readAndValidateGatewayMode,   // exported for direct, deterministic unit testing (see writer-claim.js's decideOnExisting)
  MODE_FILE,
  KEY_FILE,
  SCHEMA_VERSION,
  BINARY_MODE,
};
