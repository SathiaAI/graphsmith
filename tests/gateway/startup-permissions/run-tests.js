#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/startup-permissions.js -- the gateway's startup
 * permission-tightening pass (Paul's decision, 2026-09-15 fix round -- see
 * claude/graphsmith-fix-round-plan-round1-2026-09-15.md, "Access model": group-readable
 * state directories, 0750 dirs / 0640 files, NOT single-user 0700/0600).
 *
 * Covers:
 *   - the exact, explicit set of directories/files this pass targets (a drift/typo test:
 *     accidentally adding gateway-status.json, or dropping one of the real sensitive
 *     paths, should fail a test here, not be discovered in production).
 *   - real files produced by the REAL writer-claim.js/chain.js/recovery.js write paths
 *     (not hand-crafted fixtures) end up re-chmoded correctly, proving this module's
 *     path-builder calls actually line up with those modules' own.
 *   - a missing file/directory (a fresh deployment) is skipped silently, never an error.
 *   - the operator-facing gateway-status.json health file is NEVER touched by this pass,
 *     even though it lives directly inside the same state directory this pass tightens.
 *   - a real permission fault (EPERM/EIO, simulated) is surfaced, not swallowed.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const startupPermissions = require(path.join(ROOT, "scripts", "gateway", "startup-permissions.js"));
const recovery = require(path.join(ROOT, "scripts", "gateway", "recovery.js"));
const chain = require(path.join(ROOT, "scripts", "gateway", "chain.js"));
const { WriterClaim } = require(path.join(ROOT, "scripts", "writer-claim.js"));
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));

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
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-startup-permissions-${prefix}-`));
}
function mode(p) {
  return fs.statSync(p).mode & 0o777;
}
function withPatched(obj, key, replacement, fn) {
  const original = obj[key];
  obj[key] = replacement;
  try { return fn(); } finally { obj[key] = original; }
}
function withPlatform(value, fn) {
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value, configurable: true });
  try { return fn(); } finally { Object.defineProperty(process, "platform", original); }
}
function codeError(code, message) {
  return Object.assign(new Error(message || code), { code });
}
function makeClaimInstanceId() {
  return crypto.randomBytes(16).toString("hex");
}

/* ---- exact target-list tests: catches drift/typos in the sensitive-path lists ---- */

function sensitiveDirectoriesListIsExactlyTheDocumentedSet() {
  const dir = freshDir("dirs-list");
  const expected = [
    dir,
    chain.sessionsDir(dir),
    startupPermissions.sessionQuarantineDir(dir),
    recovery.recoveryDir(dir),
    recovery.activeDir(dir),
    recovery.intentsDir(dir),
    recovery.signaturesDir(dir),
  ].sort();
  const actual = startupPermissions.sensitiveDirectories(dir).slice().sort();
  check("sensitive-directories-list-matches-documented-set",
    JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function sensitiveFilesListNamesTheFixedFilesAndNeverHeadJsonTwice() {
  const dir = freshDir("files-list-fixed");
  fs.mkdirSync(chain.sessionsDir(dir), { recursive: true });
  // No HEAD.json/chain.jsonl on disk yet -- the fixed-name entries are still LISTED
  // (chmodPathOrFail's own ENOENT handling is what makes a missing one harmless), and
  // sessionsDir's own glob must never separately re-list HEAD.json as if it were a
  // sealed bundle.
  fs.writeFileSync(chain.headPath(dir), "{}");
  const files = startupPermissions.sensitiveFiles(dir);
  const headOccurrences = files.filter((f) => f === chain.headPath(dir)).length;
  check("sensitive-files-includes-writer-claim-path",
    files.includes(require(path.join(ROOT, "scripts", "writer-claim.js")).claimPath(dir)), JSON.stringify(files));
  check("sensitive-files-includes-chain-jsonl-path", files.includes(chain.chainPath(dir)), JSON.stringify(files));
  check("sensitive-files-includes-head-json-path", files.includes(chain.headPath(dir)), JSON.stringify(files));
  check("sensitive-files-lists-head-json-exactly-once-not-duplicated-via-sessions-glob",
    headOccurrences === 1, `expected exactly 1 occurrence of HEAD.json, got ${headOccurrences}`);
}

function sensitiveFilesNeverListsTheOperatorStatusFile() {
  const dir = freshDir("files-list-status-excluded");
  fs.mkdirSync(dir, { recursive: true });
  const statusPath = path.join(dir, "gateway-status.json");
  fs.writeFileSync(statusPath, "{}");
  const files = startupPermissions.sensitiveFiles(dir);
  check("sensitive-files-never-includes-gateway-status-json",
    !files.includes(statusPath), JSON.stringify(files));
}

/* ---- integration: real files produced by the real write paths ---- */

function tightenStateDirPermissionsRetrofitsEveryRealSensitivePathToTheAccessModel() {
  const dir = freshDir("real-files");

  // Real writer-claim.
  const claim = new WriterClaim(dir, { instanceId: makeClaimInstanceId() });
  claim.acquire();
  const claimPath = claim.path;
  fs.chmodSync(claimPath, 0o644); // simulate a claim written before this fix existed

  // Real chain: one sealed bundle -> chain.jsonl append -> HEAD.json.
  const sealed = { bundle: { manifest: { bundle_id: "bundle-real-1" }, contents: {} } };
  chain.appendSession(dir, sealed);
  fs.chmodSync(chain.bundlePath(dir, "bundle-real-1"), 0o644);
  fs.chmodSync(chain.chainPath(dir), 0o644);
  fs.chmodSync(chain.headPath(dir), 0o644);

  // A real quarantined sealed bundle, mirroring proxy.js#quarantineSealedBundle's own
  // write shape (this test writes it directly rather than importing proxy.js, keeping
  // this suite's dependency graph the same one-way shape as startup-permissions.js's
  // own -- see that module's header comment on why).
  const quarantineDir = startupPermissions.sessionQuarantineDir(dir);
  fs.mkdirSync(quarantineDir, { recursive: true });
  const quarantinedBundlePath = path.join(quarantineDir, "conn-1-123.json");
  fs.writeFileSync(quarantinedBundlePath, JSON.stringify({ sealed }), { flag: "wx" });
  fs.chmodSync(quarantinedBundlePath, 0o644);

  // Real WAL, intent, and signature records.
  recovery.appendWalEvent(dir, "conn-2", { type: "SESSION_START" });
  const walPath = recovery.walPath(dir, "conn-2");
  fs.chmodSync(walPath, 0o644);
  fs.chmodSync(recovery.activeDir(dir), 0o755);

  recovery.createIntentIfAbsent(dir, "gs_intent_1", { state: "dispatched" });
  const intentPath = recovery.intentPath(dir, "gs_intent_1");
  fs.chmodSync(intentPath, 0o644);
  fs.chmodSync(recovery.intentsDir(dir), 0o755);

  recovery.recordCompletedSignature(dir, "gs_sig_1", { completed_at: Date.now() });
  const signaturePath = recovery.signaturePath(dir, "gs_sig_1");
  fs.chmodSync(signaturePath, 0o644);
  fs.chmodSync(recovery.signaturesDir(dir), 0o755);

  // The one named exception: the operator health file, deliberately left at a normal,
  // pre-existing operator-readable mode.
  const statusPath = path.join(dir, "gateway-status.json");
  fs.writeFileSync(statusPath, "{}");
  fs.chmodSync(statusPath, 0o644);

  fs.chmodSync(chain.sessionsDir(dir), 0o755);
  fs.chmodSync(quarantineDir, 0o755);
  fs.chmodSync(recovery.recoveryDir(dir), 0o755);
  fs.chmodSync(dir, 0o755);

  const changed = startupPermissions.tightenStateDirPermissions(dir);

  check("real-writer-claim-file-tightened-to-0640", mode(claimPath) === 0o640, mode(claimPath).toString(8));
  check("real-bundle-file-tightened-to-0640", mode(chain.bundlePath(dir, "bundle-real-1")) === 0o640, "");
  check("real-chain-jsonl-tightened-to-0640", mode(chain.chainPath(dir)) === 0o640, "");
  check("real-head-json-tightened-to-0640", mode(chain.headPath(dir)) === 0o640, "");
  check("real-quarantined-bundle-tightened-to-0640", mode(quarantinedBundlePath) === 0o640, "");
  check("real-wal-file-tightened-to-0640", mode(walPath) === 0o640, "");
  check("real-intent-file-tightened-to-0640", mode(intentPath) === 0o640, "");
  check("real-signature-file-tightened-to-0640", mode(signaturePath) === 0o640, "");

  check("real-state-dir-tightened-to-0750", mode(dir) === 0o750, "");
  check("real-sessions-dir-tightened-to-0750", mode(chain.sessionsDir(dir)) === 0o750, "");
  check("real-quarantine-dir-tightened-to-0750", mode(quarantineDir) === 0o750, "");
  check("real-recovery-dir-tightened-to-0750", mode(recovery.recoveryDir(dir)) === 0o750, "");
  check("real-active-dir-tightened-to-0750", mode(recovery.activeDir(dir)) === 0o750, "");
  check("real-intents-dir-tightened-to-0750", mode(recovery.intentsDir(dir)) === 0o750, "");
  check("real-signatures-dir-tightened-to-0750", mode(recovery.signaturesDir(dir)) === 0o750, "");

  check("gateway-status-json-mode-untouched-by-this-pass", mode(statusPath) === 0o644,
    `expected the operator status file to be left at 0644, got ${mode(statusPath).toString(8)}`);
  check("gateway-status-json-not-reported-as-changed",
    !changed.files.includes(statusPath), JSON.stringify(changed.files));

  const uniqueFiles = new Set(changed.files);
  check("no-file-reported-as-changed-twice",
    uniqueFiles.size === changed.files.length,
    `duplicates in ${JSON.stringify(changed.files)}`);
}

/* ---- missing paths are ordinary, not a fault ---- */

function freshDeploymentWithNothingOnDiskYetDoesNotThrow() {
  const dir = freshDir("empty");
  fs.mkdirSync(dir, { recursive: true });
  let threw = null;
  let changed = null;
  try { changed = startupPermissions.tightenStateDirPermissions(dir); }
  catch (error) { threw = error; }
  check("empty-state-dir-does-not-throw", threw === null, threw && threw.message);
  check("empty-state-dir-still-tightens-the-state-dir-itself",
    changed && changed.dirs.includes(dir), JSON.stringify(changed));
  check("empty-state-dir-reports-no-files-changed",
    changed && changed.files.length === 0, JSON.stringify(changed));
  check("empty-state-dir-mode-is-0750", mode(dir) === 0o750, mode(dir).toString(8));
}

function partiallyPopulatedDeploymentSkipsWhatIsMissingAndTightensWhatExists() {
  const dir = freshDir("partial");
  // Only the writer-claim exists; nothing gateway-sessions/gateway-recovery related
  // has ever been created (no crash has ever happened on this deployment yet).
  const claim = new WriterClaim(dir, { instanceId: makeClaimInstanceId() });
  claim.acquire();
  fs.chmodSync(claim.path, 0o644);

  let threw = null;
  let changed = null;
  try { changed = startupPermissions.tightenStateDirPermissions(dir); }
  catch (error) { threw = error; }
  check("partial-deployment-does-not-throw", threw === null, threw && threw.message);
  check("partial-deployment-tightens-the-existing-claim-file",
    mode(claim.path) === 0o640, mode(claim.path).toString(8));
  check("partial-deployment-reports-only-the-existing-file",
    changed.files.length === 1 && changed.files[0] === claim.path, JSON.stringify(changed.files));
}

/* ---- a real permission fault is surfaced, not swallowed ---- */

function aRealChmodFailureAbortsTheWholePassRatherThanBeingSwallowed() {
  const dir = freshDir("real-fault");
  const claim = new WriterClaim(dir, { instanceId: makeClaimInstanceId() });
  claim.acquire();

  let threw = null;
  withPlatform("linux", () => {
    withPatched(fs, "chmodSync", (target, requestedMode) => {
      throw codeError("EACCES", "permission denied");
    }, () => {
      try { startupPermissions.tightenStateDirPermissions(dir); }
      catch (error) { threw = error; }
    });
  });
  check("real-chmod-failure-propagates-out-of-tightenStateDirPermissions",
    threw && threw.code === "STATE_STORE_CHMOD_FAILED",
    `expected STATE_STORE_CHMOD_FAILED, got ${threw ? threw.code : "no error"}`);
}

function main() {
  sensitiveDirectoriesListIsExactlyTheDocumentedSet();
  sensitiveFilesListNamesTheFixedFilesAndNeverHeadJsonTwice();
  sensitiveFilesNeverListsTheOperatorStatusFile();
  tightenStateDirPermissionsRetrofitsEveryRealSensitivePathToTheAccessModel();
  freshDeploymentWithNothingOnDiskYetDoesNotThrow();
  partiallyPopulatedDeploymentSkipsWhatIsMissingAndTightensWhatExists();
  aRealChmodFailureAbortsTheWholePassRatherThanBeingSwallowed();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
