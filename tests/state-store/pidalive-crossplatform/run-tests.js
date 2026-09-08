#!/usr/bin/env node
"use strict";

/* tests/state-store/pidalive-crossplatform/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. pidAlive() (scripts/state-store.js:257-271)
 * has exactly one test suite today -- tests/state-store/pidalive-zombie/run-tests.js -- and that
 * whole suite `return`s before a single assertion runs unless process.platform === "linux". On
 * this Windows sandbox (and on any macOS runner) that means EVERY branch of pidAlive() is
 * completely unexercised by a dedicated test, including branches that have nothing to do with
 * real zombies or /proc:
 *
 *   - the `!Number.isSafeInteger(pid) || pid < 1` input guard
 *   - the EPERM-means-alive branch
 *   - the exact string-slicing arithmetic that reads the process-state field out of a
 *     /proc/<pid>/stat line
 *
 * None of that needs a real Linux zombie -- it needs a controlled `process.kill` and a controlled
 * `fs.readFileSync`, both of which are plain function calls this file can substitute for the
 * duration of one call. This suite is deliberately NOT platform-gated: every case here mocks its
 * own inputs, so it runs (and asserts something) identically on Windows, macOS and Linux, closing
 * the gap the zombie suite's platform guard leaves everywhere except real Linux hardware. */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));
const { pidAlive } = stateStore;

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

function codeError(code, message) {
  return Object.assign(new Error(message || code), { code });
}

/* Replaces process.kill for the duration of fn(); always restored, even on throw. Records
 * every (pid, signal) pair it was called with so a guard that should short-circuit BEFORE
 * calling process.kill at all can be proven not to have called it. */
function withMockedKill(impl, fn) {
  const original = process.kill;
  const calls = [];
  process.kill = (pid, signal) => { calls.push([pid, signal]); return impl(pid, signal); };
  try { return { result: fn(), calls }; }
  finally { process.kill = original; }
}

function withMockedReadFileSync(impl, fn) {
  const original = fs.readFileSync;
  const calls = [];
  fs.readFileSync = (...args) => { calls.push(args); return impl(...args); };
  try { return { result: fn(), calls }; }
  finally { fs.readFileSync = original; }
}

/* ---- the input guard: `!Number.isSafeInteger(pid) || pid < 1` ----
 *
 * Every case here proves the guard fires WITHOUT ever calling process.kill -- not merely
 * that the final return value happens to be false, which a broken guard could also produce
 * by accident via a thrown TypeError from a genuinely invalid process.kill() call. */

function invalidPidNeverCallsKill() {
  const cases = [
    ["zero", 0],
    ["negative", -5],
    ["fractional", 1.5],
    ["NaN", NaN],
    ["Infinity", Infinity],
    ["string", "123"],
    ["null", null],
    ["undefined", undefined],
  ];
  for (const [label, pid] of cases) {
    const { result, calls } = withMockedKill(
      () => { throw codeError("ESRCH"); },
      () => pidAlive(pid)
    );
    check(`invalid-pid-${label}-returns-false`, result === false, `pidAlive(${JSON.stringify(pid)}) returned ${result}`);
    check(`invalid-pid-${label}-never-calls-kill`, calls.length === 0,
      `the invalid-pid guard should reject ${JSON.stringify(pid)} before ever calling process.kill, but it was called ${calls.length} time(s): ${JSON.stringify(calls)}`);
  }
}

/* The exact boundary: pid 1 is the smallest VALID pid (`pid < 1` excludes 0 and negatives,
 * not 1 itself). A `pid <= 1` mutant would wrongly reject pid 1 before ever calling
 * process.kill; this proves pid 1 reaches process.kill. */
function pidOneIsValidAndReachesKill() {
  const { result, calls } = withMockedKill(
    () => { throw codeError("ESRCH"); },
    () => pidAlive(1)
  );
  check("pid-one-is-a-valid-pid-reaches-kill", calls.length === 1 && calls[0][0] === 1,
    `pidAlive(1) must call process.kill(1, ...) -- pid 1 is the smallest valid pid, not an invalid one; got ${calls.length} call(s)`);
  check("pid-one-esrch-returns-false", result === false, `expected false for an ESRCH pid 1, got ${result}`);
}

/* ---- EPERM: exists, we may not signal it -> alive ----
 *
 * The EPERM branch `return`s immediately -- it must never fall through to the /proc read at
 * all. Proven here by mocking fs.readFileSync to answer as if the SAME pid were a confirmed
 * zombie (state "Z"): if pidAlive still reports true, the EPERM branch never consulted /proc,
 * exactly as the code demands. If a mutant broke the early return, this mocked zombie stat
 * would flip the answer to false and the assertion would catch it. */
function epermMeansAliveAndNeverConsultsProc() {
  const { result, calls: killCalls } = withMockedKill(
    () => { throw codeError("EPERM"); },
    () => {
      const { result: inner, calls: readCalls } = withMockedReadFileSync(
        (target) => {
          if (String(target).includes("/proc/")) return "424242 (owned-by-other-user) Z 1 1 1\n";
          return fs.readFileSync.__original ? fs.readFileSync.__original(target) : "";
        },
        () => pidAlive(424242)
      );
      check("eperm-never-reads-proc", readCalls.length === 0,
        `EPERM must return before ever reading /proc -- it was read ${readCalls.length} time(s), and the mocked content claimed a zombie`);
      return inner;
    }
  );
  check("eperm-means-alive", result === true, `pidAlive() for an EPERM pid must report true (exists, we may not signal it), got ${result}`);
  check("eperm-kill-was-called-once", killCalls.length === 1, `expected exactly one process.kill call, got ${killCalls.length}`);
}

/* ---- ESRCH (or any non-EPERM kill failure): no such process -> dead, without touching /proc ---- */
function esrchMeansDeadWithoutProc() {
  const { result, calls: readCalls } = withMockedReadFileSync(
    () => { throw new Error("must not be called for an ESRCH pid"); },
    () => withMockedKill(() => { throw codeError("ESRCH"); }, () => pidAlive(999998)).result
  );
  check("esrch-means-dead", result === false, `pidAlive() for an ESRCH pid must report false, got ${result}`);
  check("esrch-never-reads-proc", readCalls.length === 0, "ESRCH is decisive on its own and must not fall through to a /proc read");
}

/* ---- the live-pid, /proc-based zombie check: exact string-slicing arithmetic ----
 *
 * kill(pid, 0) succeeds (process-table entry exists); fs.readFileSync is mocked to return a
 * synthetic /proc/<pid>/stat line, so the string-parsing arithmetic (lastIndexOf(")"), the
 * `+2` offset past ") ", and the exact literal "Z") is exercised deterministically on any
 * platform -- no real zombie or real /proc required. */
function killSucceedsThenProcStateDecides() {
  const LIVE_PID = 555555;

  function pidAliveWithStat(label, stat) {
    const { result, calls } = withMockedReadFileSync(
      (target, encoding) => {
        check(`proc-read-path-is-exact-${label}`,
          target === `/proc/${LIVE_PID}/stat` && encoding === "utf8",
          `expected readFileSync("/proc/${LIVE_PID}/stat", "utf8"), got ${JSON.stringify(target)}, ${JSON.stringify(encoding)}`);
        if (stat === null) { throw codeError("ENOENT"); }
        return stat;
      },
      () => withMockedKill(() => true, () => pidAlive(LIVE_PID)).result
    );
    return { result, calls };
  }

  check("proc-zombie-state-returns-false",
    pidAliveWithStat("zombie", "555555 (worker) Z 1 1 1").result === false,
    "a /proc stat line reporting state Z must be treated as dead");

  check("proc-sleeping-state-returns-true",
    pidAliveWithStat("sleeping", "555555 (worker) S 1 1 1").result === true,
    "a /proc stat line reporting a non-Z state must be treated as alive");

  check("proc-running-state-returns-true",
    pidAliveWithStat("running", "555555 (worker) R 1 1 1").result === true,
    "a /proc stat line reporting state R must be treated as alive");

  /* comm field containing literal parens: proves lastIndexOf(")"), not indexOf, is what
   * anchors the field boundary -- a naive first-paren search would misparse this. */
  check("proc-comm-with-embedded-parens-still-parses-zombie",
    pidAliveWithStat("parens-zombie", "555555 (weird)proc(name)) Z 1 1 1").result === false,
    "a comm field containing its own parentheses must not defeat the state-field anchor");
  check("proc-comm-with-embedded-parens-still-parses-alive",
    pidAliveWithStat("parens-alive", "555555 (weird)proc(name)) R 1 1 1").result === true,
    "a comm field containing its own parentheses must still report a live state correctly");

  /* Malformed line with no ")" at all: close === -1, the guard must short-circuit to the
   * do-nothing fallback (return true) rather than throw or misindex. */
  check("proc-malformed-no-closing-paren-falls-back-to-alive",
    pidAliveWithStat("malformed", "not a real stat line at all").result === true,
    "a stat line with no ')' must not throw, and must fall back to the documented true (best answer available)");

  /* /proc unreadable (ENOENT, matching a real non-Linux platform): falls back to true --
   * the documented cross-platform fallback, exercised directly rather than left implicit. */
  check("proc-unreadable-falls-back-to-alive",
    pidAliveWithStat("unreadable", null).result === true,
    'documented fallback: "no /proc: signal 0 is the best answer available"');
}

function main() {
  invalidPidNeverCallsKill();
  pidOneIsValidAndReachesKill();
  epermMeansAliveAndNeverConsultsProc();
  esrchMeansDeadWithoutProc();
  killSucceedsThenProcStateDecides();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
