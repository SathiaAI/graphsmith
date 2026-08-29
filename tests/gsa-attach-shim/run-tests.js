#!/usr/bin/env node
/* Track 1.3 (attach mode) build test suite, per
 * .plans/v0.5.0/WRITER-CLAIM-TRD-HARDENING-2026-08-22.md §6's test plan for FR-7:
 *
 *   "an integration test spawning the wrapper as a real child process (mirroring
 *   tests/state-store/writer-claim-shared-storage/_worker.js's real-process pattern)
 *   that confirms (a) clean startup acquires the claim and the process stays up;
 *   (b) a second instance against the same directory exits non-zero with the FR-1
 *   refusal message; (c) SIGTERM triggers release() and the claim file is gone after
 *   exit."
 *
 * Also covers the mode-selection gate (MS-FR-1) this module's own
 * readAndValidateGatewayMode() implements, exported standalone specifically so it can
 * be pinned here without a real child process -- mirrors writer-claim.js's own
 * decideOnExisting() being exported and unit-tested the same way.
 */
"use strict";

const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../..");
const { readAndValidateGatewayMode } = require(path.join(ROOT, "scripts", "gsa-attach-shim.js"));
const { claimPath } = require(path.join(ROOT, "scripts", "writer-claim.js"));
const WORKER = path.join(__dirname, "_worker.js");

let failures = 0;
const results = [];

function record(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}`
    : status === "SKIPPED" ? `SKIPPED ${name}: ${reason || "unknown"}`
      : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function skip(name, reason) {
  record(name, "SKIPPED", reason);
}

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gsa-attach-shim-${prefix}-`));
}

/* Builds a schema-valid, correctly-HMAC-confirmed gateway-mode.json + its signing key,
 * exactly per the mode-selection contract's §5.1 formula:
 * HMAC-SHA256(secret, schema_version|mode|confirmed_by|confirmed_at|nonce). */
function writeValidGatewayMode(graphsmithDir, mode) {
  fs.mkdirSync(path.join(graphsmithDir, "state"), { recursive: true });
  const secret = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(path.join(graphsmithDir, "state", "gateway-mode.key"), secret);
  const confirmed_by = "test-harness";
  const confirmed_at = Date.now();
  const nonce = crypto.randomBytes(16).toString("hex");
  const message = ["1.0", mode, confirmed_by, String(confirmed_at), nonce].join("|");
  const confirmation_token = crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
  const record_ = {
    schema_version: "1.0",
    mode,
    confirmation: { confirmed_by, confirmed_at, nonce, confirmation_token },
  };
  fs.writeFileSync(path.join(graphsmithDir, "gateway-mode.json"), JSON.stringify(record_));
  return record_;
}

/* -----------------------------------------------------------------------------------
 * MS-FR-1 gate: direct unit tests against readAndValidateGatewayMode(), one real temp
 * .graphsmith/ dir per case, no WriterClaim or child process involved.
 * --------------------------------------------------------------------------------- */

function gatewayModeGateUnitTests() {
  {
    const graphsmithDir = path.join(freshRoot("gate-missing"), ".graphsmith");
    fs.mkdirSync(graphsmithDir, { recursive: true });
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-missing-file-refuses", code === "GATEWAY_MODE_NOT_DECLARED", `expected GATEWAY_MODE_NOT_DECLARED, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-malformed"), ".graphsmith");
    fs.mkdirSync(graphsmithDir, { recursive: true });
    fs.writeFileSync(path.join(graphsmithDir, "gateway-mode.json"), "{not valid json");
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-malformed-json-refuses", code === "GATEWAY_MODE_MALFORMED", `expected GATEWAY_MODE_MALFORMED, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-bad-enum"), ".graphsmith");
    fs.mkdirSync(graphsmithDir, { recursive: true });
    fs.writeFileSync(path.join(graphsmithDir, "gateway-mode.json"), JSON.stringify({ schema_version: "1.0", mode: "bogus", confirmation: {} }));
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-bad-mode-enum-refuses", code === "GATEWAY_MODE_INVALID", `expected GATEWAY_MODE_INVALID, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-extra-prop"), ".graphsmith");
    fs.mkdirSync(graphsmithDir, { recursive: true });
    fs.writeFileSync(path.join(graphsmithDir, "gateway-mode.json"), JSON.stringify({ schema_version: "1.0", mode: "attach", confirmation: {}, extra: true }));
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-additional-property-refuses", code === "GATEWAY_MODE_INVALID", `expected GATEWAY_MODE_INVALID, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-unconfirmed"), ".graphsmith");
    fs.mkdirSync(graphsmithDir, { recursive: true });
    fs.writeFileSync(path.join(graphsmithDir, "gateway-mode.json"), JSON.stringify({ schema_version: "1.0", mode: "attach" }));
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-missing-confirmation-refuses", code === "GATEWAY_MODE_NOT_CONFIRMED", `expected GATEWAY_MODE_NOT_CONFIRMED, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-key-missing"), ".graphsmith");
    writeValidGatewayMode(graphsmithDir, "attach");
    fs.unlinkSync(path.join(graphsmithDir, "state", "gateway-mode.key"));
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-missing-key-refuses", code === "GATEWAY_MODE_KEY_MISSING", `expected GATEWAY_MODE_KEY_MISSING, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-tampered"), ".graphsmith");
    writeValidGatewayMode(graphsmithDir, "attach");
    const modePath = path.join(graphsmithDir, "gateway-mode.json");
    const tampered = JSON.parse(fs.readFileSync(modePath, "utf8"));
    tampered.mode = "standalone"; // flip the mode without recomputing the HMAC
    fs.writeFileSync(modePath, JSON.stringify(tampered));
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-tampered-mode-refuses-mismatch", code === "GATEWAY_MODE_CONFIRMATION_MISMATCH", `expected GATEWAY_MODE_CONFIRMATION_MISMATCH, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-wrong-binary"), ".graphsmith");
    writeValidGatewayMode(graphsmithDir, "standalone");
    let code = null;
    try { readAndValidateGatewayMode(graphsmithDir); } catch (error) { code = error.code; }
    check("gate-standalone-mode-refuses-wrong-binary", code === "GATEWAY_MODE_WRONG_BINARY", `expected GATEWAY_MODE_WRONG_BINARY, got ${code}`);
  }
  {
    const graphsmithDir = path.join(freshRoot("gate-valid"), ".graphsmith");
    writeValidGatewayMode(graphsmithDir, "attach");
    let thrown = null;
    let result = null;
    try { result = readAndValidateGatewayMode(graphsmithDir); } catch (error) { thrown = error; }
    check("gate-valid-confirmed-attach-record-passes", thrown === null && result && result.mode === "attach",
      `expected a clean pass, got error=${thrown && thrown.code} result=${JSON.stringify(result)}`);
  }
}

/* -----------------------------------------------------------------------------------
 * Real child-process integration tests -- the FR-7 §6 test plan, verbatim.
 * --------------------------------------------------------------------------------- */

function spawnWorker(projectRoot) {
  const child = spawn(process.execPath, [WORKER, projectRoot], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  return { child, getStdout: () => stdout, getStderr: () => stderr };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForExit(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) { resolve(child.exitCode); return; }
    child.on("close", (code) => resolve(code));
  });
}

async function waitForLine(getStdout, predicate, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const lines = getStdout().split("\n").filter(Boolean);
    for (const line of lines) {
      let parsed;
      try { parsed = JSON.parse(line); } catch (error) { continue; }
      if (predicate(parsed)) return parsed;
    }
    await sleep(25);
  }
  return null;
}

async function cleanStartupAcquiresAndStaysUp_thenSigtermReleases() {
  const root = freshRoot("clean-start");
  writeValidGatewayMode(path.join(root, ".graphsmith"), "attach");
  const worker = spawnWorker(root);

  const started = await waitForLine(worker.getStdout, (o) => o.phase === "start");
  check("clean-start-reports-ok", Boolean(started) && started.ok === true,
    `worker did not report a successful start: stdout=${worker.getStdout()} stderr=${worker.getStderr()}`);

  const claim = claimPath(path.join(root, ".graphsmith", "state"));
  check("clean-start-claim-file-exists", fs.existsSync(claim), "writer-claim.json was not created after a successful start");

  await sleep(200); // give the worker a moment to actually be idling, not mid-exit
  check("clean-start-process-still-running", worker.child.exitCode === null, "worker process exited unexpectedly after a successful start");

  /* (c): SIGTERM triggers release() and the claim file is gone after exit.
   *
   * SKIPPED on win32, confirmed by direct local reproduction (not inferred from CI logs,
   * unlike the sibling skip in tests/state-store/writer-claim/run-tests.js): Node's
   * ChildProcess#kill("SIGTERM") on Windows calls TerminateProcess() unconditionally --
   * there are no real POSIX signals for it to deliver, so the child's own
   * process.on("SIGTERM", ...) handler never runs at all. Confirmed with a minimal
   * standalone probe (a child that only logs on SIGTERM and stays alive via an interval)
   * spawned and killed the same way this test does: the child exits with code=null,
   * signal="SIGTERM", and NEVER prints its handler's output. This is a real platform
   * gap in what this specific test technique can exercise on Windows, not a defect in
   * AttachModeShim.stop()/WriterClaim.release() themselves (both are plain synchronous
   * fs calls with no OS-signal dependency) -- CI's linux-based runners give this real
   * coverage; only the win32 leg of this specific test is skipped. */
  if (process.platform === "win32") {
    skip("sigterm-exits-zero", "Windows delivers SIGTERM to a child via TerminateProcess() -- the handler never runs (confirmed by direct local repro, see comment above)");
    skip("sigterm-reports-stop-ok", "see prior skip");
    skip("sigterm-claim-file-gone", "see prior skip");
    worker.child.kill(); // best-effort cleanup only; outcome not asserted on this platform
    await waitForExit(worker.child);
    return;
  }

  worker.child.kill("SIGTERM");
  const code = await waitForExit(worker.child);
  check("sigterm-exits-zero", code === 0, `expected exit code 0 after SIGTERM, got ${code}`);

  const stopped = await waitForLine(worker.getStdout, (o) => o.phase === "stop");
  check("sigterm-reports-stop-ok", Boolean(stopped) && stopped.ok === true && stopped.released === true,
    `worker did not report a successful stop/release: stdout=${worker.getStdout()}`);
  check("sigterm-claim-file-gone", !fs.existsSync(claim), "writer-claim.json still exists after SIGTERM release");
}

async function secondInstanceAgainstSameDirectoryRefused() {
  const root = freshRoot("second-instance");
  writeValidGatewayMode(path.join(root, ".graphsmith"), "attach");

  const first = spawnWorker(root);
  const firstStarted = await waitForLine(first.getStdout, (o) => o.phase === "start");
  check("second-instance-setup-first-started", Boolean(firstStarted) && firstStarted.ok === true,
    `first worker failed to start; cannot exercise contention: stdout=${first.getStdout()} stderr=${first.getStderr()}`);

  const second = spawnWorker(root);
  const secondCode = await waitForExit(second.child);
  check("second-instance-exits-nonzero", secondCode !== 0, `expected a non-zero exit code, got ${secondCode}`);

  const secondFailure = await waitForLine(second.getStdout, (o) => o.phase === "start" && o.ok === false);
  check("second-instance-reports-writer-claim-refusal-code",
    Boolean(secondFailure) && (secondFailure.code === "WRITER_CLAIM_HELD" || secondFailure.code === "WRITER_CLAIM_FOREIGN_HOST"),
    `expected a writer-claim refusal code, got ${JSON.stringify(secondFailure)}`);
  check("second-instance-refusal-names-single-writer-constraint",
    Boolean(secondFailure) && /single-writer constraint/.test(secondFailure.message || ""),
    `expected FR-1's refusal message to name the single-writer constraint, got ${secondFailure && secondFailure.message}`);

  first.child.kill("SIGTERM");
  await waitForExit(first.child);
}

async function main() {
  gatewayModeGateUnitTests();
  await cleanStartupAcquiresAndStaysUp_thenSigtermReleases();
  await secondInstanceAgainstSameDirectoryRefused();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main();
