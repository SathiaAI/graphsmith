#!/usr/bin/env node
"use strict";

/* Targeted regression tests for three state-store.js primitives that mutation testing
 * (round 7, 2026-08-22) found genuinely under-covered despite being exercised indirectly
 * by writer-claim.js's normal-path acquire()/renew() calls:
 *
 *   - atomicCreateExclusive: the hard-link-unsupported fallback (EPERM/ENOSYS/EXDEV/
 *     EOPNOTSUPP/ENOTSUP) and the boundary of that error-code list were never exercised --
 *     every test runs on a real filesystem where fs.linkSync just succeeds. Also, no test
 *     ever read back the file it wrote, so an emptied write path would have passed silently.
 *   - atomicOverwriteFile: the best-effort directory-fsync block (open dirPath, fsync,
 *     close, swallow-or-propagate on failure) has no observable side effect of its own --
 *     killing its mutants requires actually forcing that open to fail and checking whether
 *     the error propagates or is swallowed, which nothing did.
 *   - validateNamedRecord: the "unknown defName" branch and both error messages' exact
 *     text were untested -- every caller passes a known, valid defName ("writerClaim").
 *
 * These monkeypatch fs.linkSync/fs.openSync and process.platform for the duration of a
 * single call and restore them in `finally`, since state-store.js requires the real `fs`
 * module directly (no injected filesystem seam exists for these two primitives). */

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const stateStore = require(STATE_STORE);

let failures = 0;
const results = [];

function record(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

/* POSIX file-mode-bit assertions are meaningless on win32: fchmodSync/chmod are no-ops
 * there, so a freshly created file just keeps whatever default mode Windows reports,
 * never the exact 0640/0644 this codebase enforces on POSIX. Route every exact-mode
 * check through this helper instead of a bare check() so it skips (not fails) on win32,
 * matching the SKIP convention already used elsewhere in this test suite family
 * (tests/gateway/recovery/run-tests.js, tests/gateway/startup-permissions/run-tests.js). */
function checkPosixMode(name, actualMode, expectedMode, reason) {
  if (process.platform === "win32") {
    record(name, "SKIP", "POSIX file mode bits do not apply on win32");
    return;
  }
  check(name, actualMode === expectedMode, reason);
}

function freshDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-atomic-${prefix}-`));
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

/* process.umask() is PROCESS-GLOBAL, not per-call -- every test below that uses this
 * sets it, runs the assertion synchronously (no `await`, no callback, nothing that could
 * yield the event loop between the set and the restore), and restores the ORIGINAL value
 * in `finally` before returning. This file's own `main()` calls each test function to
 * completion, one at a time, in a single process -- there is no concurrent test that
 * could observe or race the umask while it is temporarily changed here. */
function withUmask(mask, fn) {
  const original = process.umask(mask);
  try { return fn(); } finally { process.umask(original); }
}

/* ---- atomicCreateExclusive ---- */

function atomicCreateExclusiveContentIsActuallyWritten() {
  const dir = freshDir("create-content");
  const target = path.join(dir, "record.json");
  stateStore.atomicCreateExclusive(target, "hello-atomic-payload");
  check("atomicCreateExclusive-writes-exact-payload",
    fs.readFileSync(target, "utf8") === "hello-atomic-payload",
    "file content did not match what was written");
}

function atomicCreateExclusiveClosesTheFileDescriptor() {
  const dir = freshDir("create-close-spy");
  const target = path.join(dir, "record.json");
  const closedFds = [];
  const originalCloseSync = fs.closeSync;
  fs.closeSync = (fd) => { closedFds.push(fd); return originalCloseSync(fd); };
  try {
    stateStore.atomicCreateExclusive(target, "close-spy-payload");
  } finally {
    fs.closeSync = originalCloseSync;
  }
  check("atomicCreateExclusive-closes-fd-in-finally", closedFds.length === 1,
    `expected exactly 1 closeSync call for the temp file's fd, got ${closedFds.length}`);
}

function atomicCreateExclusiveFallsBackWhenLinkUnsupported() {
  const dir = freshDir("create-fallback");
  const target = path.join(dir, "record.json");
  for (const code of ["EPERM", "ENOSYS", "EXDEV", "EOPNOTSUPP", "ENOTSUP"]) {
    fs.rmSync(target, { force: true });
    withPatched(fs, "linkSync", () => { throw codeError(code); }, () => {
      stateStore.atomicCreateExclusive(target, `payload-${code}`);
    });
    check(`atomicCreateExclusive-falls-back-on-${code}`,
      fs.readFileSync(target, "utf8") === `payload-${code}`,
      `fallback direct write did not happen or wrote the wrong content for ${code}`);
  }
}

function atomicCreateExclusiveUnlistedLinkErrorPropagates() {
  const dir = freshDir("create-propagate");
  const target = path.join(dir, "record.json");
  let threw = null;
  withPatched(fs, "linkSync", () => { throw codeError("EACCES", "permission denied"); }, () => {
    try { stateStore.atomicCreateExclusive(target, "payload"); }
    catch (error) { threw = error; }
  });
  check("atomicCreateExclusive-unlisted-link-error-propagates",
    threw && threw.code === "EACCES",
    `expected EACCES to propagate, got ${threw ? threw.code : "no error"}`);
  check("atomicCreateExclusive-unlisted-link-error-does-not-leave-target",
    !fs.existsSync(target),
    "a rethrown link error should not leave a target file behind");
}

/* ---- atomicOverwriteFile ---- */

function atomicOverwriteFileUsesReadOnlyFlagOnDirPath() {
  const dir = freshDir("overwrite-flag");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  let observedFlag = null;
  const originalOpenSync = fs.openSync;
  fs.openSync = (openPath, flag, ...rest) => {
    if (openPath === dir) observedFlag = flag;
    return originalOpenSync(openPath, flag, ...rest);
  };
  try {
    stateStore.atomicOverwriteFile(target, "new-content", dir);
  } finally {
    fs.openSync = originalOpenSync;
  }
  check("atomicOverwriteFile-dir-fsync-opens-with-r-flag", observedFlag === "r",
    `expected the directory to be opened with "r", got ${JSON.stringify(observedFlag)}`);
  check("atomicOverwriteFile-happy-path-still-writes-content",
    fs.readFileSync(target, "utf8") === "new-content",
    "content was not correctly renamed into place");
}

function atomicOverwriteFileSwallowsListedCodeOnAnyPlatform() {
  /* All three codes the fallback list names, not just one -- a StringLiteral mutant on
   * "EINVAL" or "EISDIR" specifically would survive a suite that only ever threw EPERM. */
  for (const code of ["EINVAL", "EISDIR", "EPERM"]) {
    const dir = freshDir(`overwrite-swallow-posix-${code}`);
    const target = path.join(dir, "record.json");
    fs.writeFileSync(target, "seed");
    let threw = null;
    withPlatform("linux", () => {
      const originalOpenSync = fs.openSync;
      fs.openSync = (openPath, ...rest) => {
        if (openPath === dir) throw codeError(code, `no permission to open dir (${code})`);
        return originalOpenSync(openPath, ...rest);
      };
      try {
        try { stateStore.atomicOverwriteFile(target, `swallowed-${code}`, dir); }
        catch (error) { threw = error; }
      } finally { fs.openSync = originalOpenSync; }
    });
    check(`atomicOverwriteFile-swallows-${code}-on-posix`, threw === null,
      `expected ${code} directory-fsync failure to be swallowed, but it threw: ${threw && threw.message}`);
    check(`atomicOverwriteFile-swallows-${code}-content-still-written`,
      fs.readFileSync(target, "utf8") === `swallowed-${code}`,
      "the rename must have already happened before the swallowed dir-fsync failure");
  }
}

function atomicOverwriteFileHappyPathActuallyFsyncsAndClosesDirFd() {
  const dir = freshDir("overwrite-dir-fsync-spy");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  const fsyncedFds = [];
  const closedFds = [];
  const originalFsyncSync = fs.fsyncSync;
  const originalCloseSync = fs.closeSync;
  fs.fsyncSync = (fd) => { fsyncedFds.push(fd); return originalFsyncSync(fd); };
  fs.closeSync = (fd) => { closedFds.push(fd); return originalCloseSync(fd); };
  try {
    stateStore.atomicOverwriteFile(target, "fsync-spy-content", dir);
  } finally {
    fs.fsyncSync = originalFsyncSync;
    fs.closeSync = originalCloseSync;
  }
  check("atomicOverwriteFile-dir-fd-is-fsynced", fsyncedFds.length >= 2,
    `expected at least 2 fsyncSync calls (temp file + directory), got ${fsyncedFds.length}`);
  check("atomicOverwriteFile-dir-fd-is-closed", closedFds.length >= 2,
    `expected at least 2 closeSync calls (temp file fd + directory fd), got ${closedFds.length}`);
}

function atomicOverwriteFileRenameFailureCleansUpTempFile() {
  const dir = freshDir("overwrite-rename-fails");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  let threw = null;
  const originalRenameSync = fs.renameSync;
  fs.renameSync = () => { throw codeError("EACCES", "rename denied"); };
  try {
    try { stateStore.atomicOverwriteFile(target, "never-lands", dir); }
    catch (error) { threw = error; }
  } finally { fs.renameSync = originalRenameSync; }
  check("atomicOverwriteFile-rename-failure-propagates", threw && threw.code === "EACCES",
    `expected the rename failure to propagate, got ${threw ? threw.code : "no error"}`);
  check("atomicOverwriteFile-rename-failure-cleans-up-temp-file",
    fs.readdirSync(dir).every((name) => !name.includes(".tmp-")),
    "a failed rename must still remove the temp file it created");
  check("atomicOverwriteFile-rename-failure-leaves-target-untouched",
    fs.readFileSync(target, "utf8") === "seed",
    "a failed rename must not have modified the pre-existing target content");
}

function atomicOverwriteFileUnlistedCodePropagatesOnPosixOnly() {
  const dir = freshDir("overwrite-propagate-posix");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  let threw = null;
  withPlatform("linux", () => {
    const originalOpenSync = fs.openSync;
    fs.openSync = (openPath, ...rest) => {
      if (openPath === dir) throw codeError("EACCES", "permission denied");
      return originalOpenSync(openPath, ...rest);
    };
    try {
      try { stateStore.atomicOverwriteFile(target, "should-not-land", dir); }
      catch (error) { threw = error; }
    } finally { fs.openSync = originalOpenSync; }
  });
  check("atomicOverwriteFile-unlisted-code-propagates-on-posix",
    threw && threw.code === "EACCES",
    `expected an unlisted dir-fsync error to propagate on a posix platform, got ${threw ? threw.code : "no error"}`);
  check("atomicOverwriteFile-propagated-error-leaves-no-temp-file",
    fs.readdirSync(dir).every((name) => !name.includes(".tmp-")),
    "a propagated dir-fsync error should still clean up the temp file");
}

function atomicOverwriteFileUnlistedCodeSwallowedOnWin32() {
  const dir = freshDir("overwrite-swallow-win32");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  let threw = null;
  withPlatform("win32", () => {
    const originalOpenSync = fs.openSync;
    fs.openSync = (openPath, ...rest) => {
      if (openPath === dir) throw codeError("EACCES", "permission denied");
      return originalOpenSync(openPath, ...rest);
    };
    try {
      try { stateStore.atomicOverwriteFile(target, "swallowed-on-win32", dir); }
      catch (error) { threw = error; }
    } finally { fs.openSync = originalOpenSync; }
  });
  check("atomicOverwriteFile-unlisted-code-swallowed-on-win32", threw === null,
    `expected any dir-fsync failure to be swallowed unconditionally on win32, but it threw: ${threw && threw.code}`);
  check("atomicOverwriteFile-win32-swallow-content-still-written",
    fs.readFileSync(target, "utf8") === "swallowed-on-win32",
    "the rename must have already happened before the swallowed dir-fsync failure");
}

/* ---- access-model defaults (Paul's decision, 2026-09-15 fix round -- see
 * claude/graphsmith-fix-round-plan-round1-2026-09-15.md, "Access model"): group-readable
 * (0750/0640), NOT single-user (0700/0600). These two functions are the ONLY ones that
 * create genuinely new files going forward; the retrofit of files that already exist on
 * disk is a separate startup pass (scripts/gateway/startup-permissions.js, tested in its
 * own suite). ---- */

function atomicCreateExclusiveDefaultModeIsGroupReadable() {
  const dir = freshDir("create-default-mode");
  const target = path.join(dir, "record.json");
  stateStore.atomicCreateExclusive(target, "payload");
  const mode = fs.statSync(target).mode & 0o777;
  checkPosixMode("atomicCreateExclusive-default-mode-is-0640", mode, 0o640,
    `expected the new access-model default 0640, got ${mode.toString(8)}`);
}

function atomicOverwriteFileDefaultModeIsGroupReadable() {
  const dir = freshDir("overwrite-default-mode");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  stateStore.atomicOverwriteFile(target, "new-content", dir);
  const mode = fs.statSync(target).mode & 0o777;
  checkPosixMode("atomicOverwriteFile-default-mode-is-0640", mode, 0o640,
    `expected the new access-model default 0640, got ${mode.toString(8)}`);
}

/* THE REQUIRED umask(0) CASE: proves fchmodSync is doing real, load-bearing work, not
 * merely riding along with whatever the ambient umask would have produced anyway. Under
 * umask 0, fs.openSync's own default mode (0666, unmasked) would leave the file WORLD
 * WRITABLE if this function only relied on the mode passed to open()/the process umask --
 * exactly the defect this test exists to catch. The access-model default (0640) can only
 * appear here because atomicCreateExclusive explicitly fchmodSync's the temp file
 * afterward, irrespective of umask. */
function atomicCreateExclusiveUmaskZeroStillProducesConfiguredMode() {
  const dir = freshDir("create-umask-zero");
  const target = path.join(dir, "record.json");
  withUmask(0, () => {
    stateStore.atomicCreateExclusive(target, "payload");
  });
  const mode = fs.statSync(target).mode & 0o777;
  checkPosixMode("atomicCreateExclusive-umask-0-still-yields-0640-not-0666", mode, 0o640,
    `expected 0640 regardless of umask 0 -- a result of 0666 here would mean fchmodSync ` +
    `is not actually running, only the ambient umask is -- got ${mode.toString(8)}`);
}

/* THE REQUIRED umask(022) / pre-existing-0644 CASE: proves atomicOverwriteFile's rename
 * delivers the NEW temp file's mode, not whatever mode the OLD target file already had.
 * Under umask 022, a temp file created with NO explicit mode would land at 0644 -- THE
 * SAME as the pre-existing target -- which would make this assertion pass even if the
 * rename silently preserved the old target's mode instead of replacing it. Choosing a
 * DIFFERENT default (0640) for the temp file is what makes "did the final mode come from
 * the rename's new inode, or survive from the old target" an observable, falsifiable
 * question rather than a coincidence of two paths agreeing on 0644. */
function atomicOverwriteFileRenameCarriesNewInodeModeOverPreExistingFile() {
  const dir = freshDir("overwrite-umask-022-preexisting");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  fs.chmodSync(target, 0o644);
  const preExistingMode = fs.statSync(target).mode & 0o777;
  withUmask(0o022, () => {
    stateStore.atomicOverwriteFile(target, "new-content", dir);
  });
  const mode = fs.statSync(target).mode & 0o777;
  checkPosixMode("atomicOverwriteFile-pre-existing-target-really-was-0644", preExistingMode, 0o644,
    `test setup invariant broken: expected the pre-existing target to be 0644, got ${preExistingMode.toString(8)}`);
  checkPosixMode("atomicOverwriteFile-rename-carries-new-inode-mode-not-preexisting-0644", mode, 0o640,
    `expected the post-rename target to carry the NEW temp file's mode (0640), not the ` +
    `pre-existing target's 0644 -- got ${mode.toString(8)}`);
  check("atomicOverwriteFile-rename-carries-new-inode-mode-content-still-correct",
    fs.readFileSync(target, "utf8") === "new-content",
    "content should still be correctly written despite the mode assertion");
}

function atomicCreateExclusiveModeNullOptsOutOfEnforcement() {
  const dir = freshDir("create-mode-null");
  const target = path.join(dir, "record.json");
  withUmask(0, () => {
    stateStore.atomicCreateExclusive(target, "payload", { mode: null });
  });
  const mode = fs.statSync(target).mode & 0o777;
  check("atomicCreateExclusive-mode-null-opts-out-of-enforcement", mode === 0o666,
    `expected { mode: null } to leave the raw, umask-governed default (0666 under umask ` +
    `0) untouched rather than enforce 0640, got ${mode.toString(8)}`);
}

function atomicOverwriteFileModeNullSkipsFchmodEnforcement() {
  const dir = freshDir("overwrite-mode-null");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  fs.chmodSync(target, 0o644);
  withUmask(0, () => {
    stateStore.atomicOverwriteFile(target, "new-content", dir, { mode: null });
  });
  const mode = fs.statSync(target).mode & 0o777;
  check("atomicOverwriteFile-mode-null-skips-fchmod-enforcement", mode === 0o666,
    `expected { mode: null } under umask 0 to leave the temp file's raw default (0666) ` +
    `rather than enforce 0640 -- got ${mode.toString(8)}`);
}

function atomicCreateExclusiveSurfacesRealChmodFailures() {
  const dir = freshDir("create-chmod-fails");
  const target = path.join(dir, "record.json");
  let threw = null;
  withPlatform("linux", () => {
    withPatched(fs, "fchmodSync", () => { throw codeError("EACCES", "no chmod for you"); }, () => {
      try { stateStore.atomicCreateExclusive(target, "payload"); }
      catch (error) { threw = error; }
    });
  });
  check("atomicCreateExclusive-real-chmod-failure-surfaces",
    threw && threw.code === "STATE_STORE_CHMOD_FAILED",
    `expected STATE_STORE_CHMOD_FAILED, got ${threw ? threw.code : "no error"}`);
}

function atomicCreateExclusiveSwallowsChmodFailureOnWin32() {
  const dir = freshDir("create-chmod-win32");
  const target = path.join(dir, "record.json");
  let threw = null;
  withPlatform("win32", () => {
    withPatched(fs, "fchmodSync", () => { throw codeError("EACCES", "no posix modes here"); }, () => {
      try { stateStore.atomicCreateExclusive(target, "payload"); }
      catch (error) { threw = error; }
    });
  });
  check("atomicCreateExclusive-chmod-failure-swallowed-on-win32", threw === null,
    `expected a win32 chmod failure to be swallowed, but it threw: ${threw && threw.code}`);
  check("atomicCreateExclusive-chmod-failure-swallowed-on-win32-content-still-written",
    fs.readFileSync(target, "utf8") === "payload",
    "content should still land despite the swallowed chmod failure");
}

function chmodPathOrFailSkipsMissingPathSilently() {
  const dir = freshDir("chmod-path-missing");
  const missing = path.join(dir, "does-not-exist.json");
  const result = stateStore.chmodPathOrFail(missing, 0o640);
  check("chmodPathOrFail-missing-path-returns-false-not-throw", result === false,
    `expected false for a missing path, got ${result}`);
}

function chmodPathOrFailSurfacesRealErrorOnPosix() {
  const dir = freshDir("chmod-path-real-error");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  let threw = null;
  withPlatform("linux", () => {
    withPatched(fs, "chmodSync", () => { throw codeError("EACCES", "denied"); }, () => {
      try { stateStore.chmodPathOrFail(target, 0o640); }
      catch (error) { threw = error; }
    });
  });
  check("chmodPathOrFail-real-error-surfaces",
    threw && threw.code === "STATE_STORE_CHMOD_FAILED",
    `expected STATE_STORE_CHMOD_FAILED, got ${threw ? threw.code : "no error"}`);
}

function chmodPathOrFailSwallowsOnWin32() {
  const dir = freshDir("chmod-path-win32");
  const target = path.join(dir, "record.json");
  fs.writeFileSync(target, "seed");
  let threw = null;
  let result;
  withPlatform("win32", () => {
    withPatched(fs, "chmodSync", () => { throw codeError("EACCES", "denied"); }, () => {
      try { result = stateStore.chmodPathOrFail(target, 0o640); }
      catch (error) { threw = error; }
    });
  });
  check("chmodPathOrFail-win32-swallowed-not-thrown", threw === null,
    `expected a win32 chmod failure to be swallowed, got ${threw && threw.code}`);
  check("chmodPathOrFail-win32-swallowed-returns-false", result === false,
    `expected false for a swallowed win32 chmod failure, got ${result}`);
}

/* ---- validateNamedRecord ---- */

function validateNamedRecordRejectsUnknownDefName() {
  let threw = null;
  try { stateStore.validateNamedRecord({}, "totallyBogusSchemaName123", "some-context"); }
  catch (error) { threw = error; }
  check("validateNamedRecord-unknown-defname-code",
    threw && threw.code === "INVALID_ARGUMENT",
    `expected INVALID_ARGUMENT, got ${threw ? threw.code : "no error"}`);
  check("validateNamedRecord-unknown-defname-message",
    threw && threw.message === "Unknown state schema definition: totallyBogusSchemaName123",
    `unexpected message: ${threw && threw.message}`);
}

function validateNamedRecordInvalidRecordMessageNamesDefAndContext() {
  let threw = null;
  try { stateStore.validateNamedRecord({ not: "a valid writer claim" }, "writerClaim", "my-context-marker"); }
  catch (error) { threw = error; }
  check("validateNamedRecord-invalid-record-code",
    threw && threw.code === "CORRUPT_STATE",
    `expected CORRUPT_STATE, got ${threw ? threw.code : "no error"}`);
  check("validateNamedRecord-invalid-record-message-names-def-and-context",
    threw && threw.message.startsWith("Invalid writerClaim record in my-context-marker:"),
    `unexpected message: ${threw && threw.message}`);
}

function main() {
  atomicCreateExclusiveContentIsActuallyWritten();
  atomicCreateExclusiveClosesTheFileDescriptor();
  atomicCreateExclusiveFallsBackWhenLinkUnsupported();
  atomicCreateExclusiveUnlistedLinkErrorPropagates();
  atomicOverwriteFileUsesReadOnlyFlagOnDirPath();
  atomicOverwriteFileSwallowsListedCodeOnAnyPlatform();
  atomicOverwriteFileHappyPathActuallyFsyncsAndClosesDirFd();
  atomicOverwriteFileRenameFailureCleansUpTempFile();
  atomicOverwriteFileUnlistedCodePropagatesOnPosixOnly();
  atomicOverwriteFileUnlistedCodeSwallowedOnWin32();
  atomicCreateExclusiveDefaultModeIsGroupReadable();
  atomicOverwriteFileDefaultModeIsGroupReadable();
  atomicCreateExclusiveUmaskZeroStillProducesConfiguredMode();
  atomicOverwriteFileRenameCarriesNewInodeModeOverPreExistingFile();
  atomicCreateExclusiveModeNullOptsOutOfEnforcement();
  atomicOverwriteFileModeNullSkipsFchmodEnforcement();
  atomicCreateExclusiveSurfacesRealChmodFailures();
  atomicCreateExclusiveSwallowsChmodFailureOnWin32();
  chmodPathOrFailSkipsMissingPathSilently();
  chmodPathOrFailSurfacesRealErrorOnPosix();
  chmodPathOrFailSwallowsOnWin32();
  validateNamedRecordRejectsUnknownDefName();
  validateNamedRecordInvalidRecordMessageNamesDefAndContext();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIP").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main();
