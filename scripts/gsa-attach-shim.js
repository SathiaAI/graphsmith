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
 * The gateway-mode.json validation below (readAndValidateGatewayMode) is a thin
 * pass-through to the shared mode-selection module (scripts/mode-selection.js, Track
 * 1.1), which implements the mode-selection contract's §5.1 schema and §7 fail-closed
 * table. This file used to carry its own private, disclosed transcription of that same
 * logic (see git history) -- built before scripts/mode-selection.js existed in this repo
 * (the mode-selection TRD's own status line, at the time: "DRAFT design, no code, no
 * schema files created in the repo") -- but now that Track 1.1 has landed it, this file
 * defers to it instead, per that module's own header: "[Track 1.2's and Track 1.3's own
 * files] should import from here instead once merged". schemas/mode-selection-
 * contract.schema.json is likewise owned and shipped by Track 1.1, not this file.
 */
"use strict";

const path = require("path");
const { WriterClaim } = require("./writer-claim.js");
const modeSelection = require("./mode-selection.js");

const MODE_FILE = "gateway-mode.json";
const KEY_FILE = "gateway-mode.key";
const SCHEMA_VERSION = "1.0";
const BINARY_MODE = "attach";

/* Mirrors writer-claim.js's own private `fail()` helper (not exported from there, so
 * this file needs its own copy) -- a named .code alongside the Error, matching this
 * module's fail-closed convention. Previously missing entirely: `throw fail(...)` in
 * start()'s already-started guard below referenced an undefined `fail`, so a duplicate
 * start() call threw a bare ReferenceError instead of the intended
 * ATTACH_SHIM_ALREADY_STARTED-coded error. */
function fail(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

/* MS-FR-1: validate .graphsmith/gateway-mode.json exactly per the mode-selection
 * contract's §3.2 startup-validation flow / §7 fail-closed table, in the same order:
 * missing -> unreadable -> malformed/invalid -> unconfirmed -> key-missing ->
 * HMAC-mismatch -> wrong-binary. Exported standalone (not only reachable through
 * AttachModeShim.start()) so the gate can be pinned by tests without touching
 * WriterClaim at all -- mirrors writer-claim.js exporting decideOnExisting for the same
 * reason. `graphsmithDir` is the `.graphsmith` directory itself (i.e. the parent of both
 * `gateway-mode.json` and `state/gateway-mode.key`), not the project root -- this file's
 * own established convention (AttachModeShim already stores it as `this.graphsmithDir`,
 * and tests/gsa-attach-shim/run-tests.js's unit tests build one directly per case). The
 * shared module's own readAndValidateGatewayMode takes the project ROOT instead (it
 * derives `<root>/.graphsmith/...` itself), so this adapter recovers it via
 * path.dirname() -- safe because every caller in this codebase constructs `graphsmithDir`
 * as exactly `path.join(someRoot, ".graphsmith")`. `expectedMode` is always BINARY_MODE
 * ("attach") here, unconditionally: this file IS the attach-mode binary, so FR-7(a)'s
 * "declares mode: attach" check is not optional the way the shared module's own
 * `options.expectedMode` is for its other, mode-agnostic callers (e.g. `status`). */
function readAndValidateGatewayMode(graphsmithDir) {
  return modeSelection.readAndValidateGatewayMode(path.dirname(graphsmithDir), { expectedMode: BINARY_MODE });
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
    /* WriterClaim is NOT constructed here. CodeRabbit review: WriterClaim's own
     * constructor can throw synchronously (e.g. an invalid explicit `instanceId`, or
     * GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK=1 with no clock supplied) -- constructing
     * it eagerly in `new AttachModeShim(...)` let that throw escape before
     * gateway-mode.json was ever checked, violating this module's documented
     * mode-first startup ordering (see the header comment: mode selection is a
     * standalone pre-flight gate, checked BEFORE the writer-claim gate) and landing
     * outside the `try { shim.start() }` block docs/GSA-ATTACH-MODE-WIRING.md tells
     * integrators to wrap. Construction is deferred to start(), after (a) succeeds;
     * options are retained here so start() can build it lazily. */
    this._claimOptions = {
      hostId: options.hostId,
      instanceId: options.instanceId,
      heartbeatMs: options.heartbeatMs,
      staleAfterMs: options.staleAfterMs,
      skewToleranceMs: options.skewToleranceMs,
      clock: options.clock,
      onClaimLost: options.onClaimLost,
    };
    this._claim = null;
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
    if (!this._claim) this._claim = new WriterClaim(this.stateDir, this._claimOptions);
    const status = this._claim.acquire();                                // (b) FR-1
    this._claim.startHeartbeat();                                        // (c) FR-2
    this._started = true;
    return status;
  }

  /* Idempotent: safe to call from a signal handler even if start() never completed (e.g.
   * it threw before acquiring, or before gateway-mode.json validation even let a
   * WriterClaim get constructed), and safe to call twice. Mirrors WriterClaim.release()'s
   * own idempotence. */
  stop() {
    this._started = false;
    return this._claim ? this._claim.release() : false;
  }

  /* FR-4-equivalent surface for this shim: current mode-selection + writer-claim state,
   * useful for a health-check endpoint the embedding gateway already exposes. Never
   * throws; reflects "not started" honestly rather than reading stale state. */
  status() {
    return {
      started: this._started,
      mode: this._modeRecord ? this._modeRecord.mode : null,
      writerClaim: this._claim ? this._claim.status() : null,
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
