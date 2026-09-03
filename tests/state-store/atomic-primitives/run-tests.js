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
  validateNamedRecordRejectsUnknownDefName();
  validateNamedRecordInvalidRecordMessageNamesDefAndContext();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
