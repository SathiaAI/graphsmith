#!/usr/bin/env node
"use strict";

/* tests/state-store/pidalive-zombie/run-tests.js
 *
 * Closes the one gap in pidAlive()'s coverage that matters for its actual job -- see
 * .plans/v0.5.0/PIDALIVE-ZOMBIE-TEST-TRD-2026-08-24.md for the full design. Every existing
 * test exercises pidAlive() (scripts/state-store.js:257-271) against live, non-zombie
 * processes only. Its /proc-based zombie-detection branch was proven REACHABLE by an earlier
 * Linux CI run, but never actually CHECKED against the input it exists to handle: a process
 * that has exited but not yet been reaped by its parent. "The code ran" and "the code was
 * checked against a real zombie" are different claims; only this file's test 2 establishes
 * the second one.
 *
 * Linux-only, explicitly. /proc does not exist on macOS or Windows, so pidAlive's
 * zombie-check branch is structurally unreachable there -- this file detects that and prints
 * an explicit skip (never a silent pass, never a failure).
 *
 * Fixture self-verification runs and can fail BEFORE any pidAlive assertion (test 1), so a
 * fixture that fails to produce a real zombie is never reported as "pidAlive works".
 */

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "../../..");
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));
const { pidAlive } = stateStore;

let passed = 0;
let failed = 0;
let skipped = 0;

function record(name, status, reason) {
  if (status === "PASS") {
    passed++;
    console.log(`PASS ${name}`);
  } else if (status === "SKIP") {
    skipped++;
    console.log(`SKIP ${name} - ${reason}`);
  } else {
    failed++;
    console.log(`FAIL ${name} - ${reason || "unknown"}`);
  }
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function skip(name, reason) {
  record(name, "SKIP", reason);
}

function summary() {
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failed ? 1 : 0);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* ---- fixture: a real, verified Linux zombie process (TRD §3.1, §4) ----
 *
 * TRD §3.1 suggests `sh -c '( exit 0 ) & echo $!; sleep 2'` "or equivalent". Measured on
 * this repo's target environments, that literal one-liner does NOT reliably produce a
 * lasting zombie: /bin/sh is dash on Debian/Ubuntu, and dash proactively reaps a background
 * job's exit status via its own SIGCHLD bookkeeping even in a non-interactive script, so the
 * child is often already gone (ENOENT on /proc/<pid>/stat) by the time this process reads
 * it -- confirmed empirically, not assumed. The equivalent this file uses instead is a
 * `python3 os.fork()` child that calls `os._exit(0)` immediately: nothing but this test's own
 * `dispose()` ever calls wait()/waitpid() on it, so it holds state Z in the process table
 * for the parent's whole sleep window. `dispose()` SIGKILLs the holding python3 parent, which
 * orphans the zombie to the namespace's reaper and lets the kernel reap it. */
function spawnZombie() {
  if (process.platform !== "linux") {
    throw new Error("spawnZombie() requires Linux (/proc); caller must check process.platform first");
  }
  return new Promise((resolve, reject) => {
    const pythonSource =
      "import os, sys, time\n" +
      "pid = os.fork()\n" +
      "if pid == 0:\n" +
      "    os._exit(0)\n" +
      "else:\n" +
      "    sys.stdout.write(str(pid) + chr(10))\n" +
      "    sys.stdout.flush()\n" +
      "    time.sleep(2)\n";
    const holder = spawn("python3", ["-c", pythonSource], { stdio: ["ignore", "pipe", "ignore"] });
    let buf = "";
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      holder.stdout.removeListener("data", onData);
      reject(new Error("timed out waiting for the zombie fixture to report a pid"));
    }, 5000);

    function onData(chunk) {
      if (settled) return;
      buf += chunk.toString("utf8");
      const match = buf.match(/(\d+)/);
      if (!match) return;
      settled = true;
      clearTimeout(timer);
      holder.stdout.removeListener("data", onData);
      const zombiePid = Number(match[1]);
      let disposed = false;
      resolve({
        pid: zombiePid,
        shellPid: holder.pid,
        dispose() {
          if (disposed) return;
          disposed = true;
          try { process.kill(holder.pid, "SIGKILL"); } catch (error) { /* already exited */ }
        },
      });
    }

    holder.stdout.on("data", onData);
    holder.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
  });
}

/* Reads /proc/<pid>/stat directly, bypassing pidAlive entirely -- used only to verify the
 * fixture itself (TRD §3.2), never as a substitute for the pidAlive assertions. */
function readProcState(pid) {
  const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = stat.lastIndexOf(")");
  if (close === -1) return null;
  return stat.slice(close + 2).split(" ")[0];
}

async function waitForGone(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (!fs.existsSync(`/proc/${pid}`)) return true;
    if (Date.now() >= deadline) return !fs.existsSync(`/proc/${pid}`);
    await sleep(50);
  }
}

/* There is an unavoidable race between fork() returning in the parent and the child
 * actually reaching os._exit(0) and the kernel marking it Z -- poll briefly rather than
 * assume either the first read or a fixed sleep lands in the right window. Returns the
 * last-observed {state, error} once state is "Z" or the timeout elapses. */
async function waitForZombieState(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastState = null;
  let lastError = null;
  for (;;) {
    lastState = null;
    lastError = null;
    try {
      lastState = readProcState(pid);
    } catch (error) {
      lastError = error;
    }
    if (lastState === "Z") return { state: lastState, error: lastError };
    if (Date.now() >= deadline) return { state: lastState, error: lastError };
    await sleep(20);
  }
}

/* A pid this large has no /proc entry and no process-table slot on any Linux system this
 * suite runs on (default pid_max is 4194304); kill(pid, 0) reports ESRCH for it exactly as
 * it would for a pid that once existed and has since been fully reaped. */
function unusedPid() {
  const candidate = 2 ** 31 - 2;
  if (fs.existsSync(`/proc/${candidate}`)) {
    throw new Error(`unexpected: /proc/${candidate} exists on this system, cannot use it as an unused-pid fixture`);
  }
  return candidate;
}

async function main() {
  if (process.platform !== "linux") {
    skip(
      "1-6. pidAlive zombie-detection suite",
      `not running on Linux (process.platform=${process.platform}); /proc does not exist, so ` +
      "pidAlive's zombie-detection branch (scripts/state-store.js:265-268) is structurally " +
      "unreachable here. This run provides no evidence either way about that branch."
    );
    return summary();
  }

  let zombie = null;
  try {
    zombie = await spawnZombie();

    /* 1. Fixture self-verification (TRD §3.2) -- must run and fail distinctly BEFORE any
     * pidAlive assertion, so a broken fixture is never reported as "pidAlive works". Polls
     * briefly (bounded, 1s) to cross the unavoidable fork()-return-vs-child-exits race rather
     * than reading once and assuming the timing worked out. */
    const { state: zombieState, error: readError } = await waitForZombieState(zombie.pid, 1000);
    const fixtureOk = zombieState === "Z";
    check(
      "1-fixture-self-check-produces-a-real-zombie",
      fixtureOk,
      readError
        ? `could not read /proc/${zombie.pid}/stat directly: ${readError.message}`
        : `fixture setup failed to produce a zombie -- /proc state was ${JSON.stringify(zombieState)}, expected "Z"`
    );

    if (!fixtureOk) {
      /* The fixture didn't do its job -- every downstream pidAlive assertion below would be
       * testing nothing. Fail them distinctly rather than silently skip them. */
      check("2-pidAlive-returns-false-for-a-verified-zombie", false,
        "not evaluated: fixture did not produce a verified zombie (see test 1)");
      check("3-fixture-pid-is-still-signal-visible", false,
        "not evaluated: fixture did not produce a verified zombie (see test 1)");
    } else {
      /* 2. The actual deliverable this TRD exists to close: pidAlive() must report a real
       * zombie as dead. */
      check(
        "2-pidAlive-returns-false-for-a-verified-zombie",
        pidAlive(zombie.pid) === false,
        `pidAlive(${zombie.pid}) did not return false for a confirmed zombie process`
      );

      /* 3. Confirms the fixture matches the real-world shape pidAlive expects -- a zombie is
       * still a live process-table entry, so kill(pid, 0) must not throw. Validates the
       * fixture's realism, not the code under test. */
      let killThrew = null;
      try { process.kill(zombie.pid, 0); } catch (error) { killThrew = error; }
      check(
        "3-fixture-pid-is-still-signal-visible",
        killThrew === null,
        `expected kill(${zombie.pid}, 0) not to throw for a zombie, but it threw ${killThrew && killThrew.code}`
      );
    }

    /* 4. Baseline control -- if this fails, the test environment itself is broken, not the
     * zombie-detection logic. */
    check(
      "4-pidAlive-returns-true-for-the-live-test-process",
      pidAlive(process.pid) === true,
      `pidAlive(${process.pid}) (this test's own live process) did not return true`
    );

    /* 5. Regression/boundary: a pid with no process-table entry at all must be reported dead
     * via the ESRCH path. */
    const gonePid = unusedPid();
    check(
      "5-pidAlive-returns-false-for-a-fully-reaped-pid",
      pidAlive(gonePid) === false,
      `pidAlive(${gonePid}) did not return false for a pid with no process table entry`
    );

    /* 6. The documented cross-platform fallback ("no /proc: signal 0 is the best answer
     * available") exercised deliberately, rather than left implicit. */
    const originalReadFileSync = fs.readFileSync;
    fs.readFileSync = (...args) => {
      if (typeof args[0] === "string" && args[0].startsWith("/proc/")) {
        throw Object.assign(new Error("simulated: no /proc access"), { code: "ENOENT" });
      }
      return originalReadFileSync(...args);
    };
    let fallbackResult;
    try {
      fallbackResult = pidAlive(process.pid);
    } finally {
      fs.readFileSync = originalReadFileSync;
    }
    check(
      "6-pidAlive-falls-back-to-signal-only-when-proc-unreadable",
      fallbackResult === true,
      `pidAlive(${process.pid}) did not fall back to true when /proc was unreadable ` +
      '(documented fallback: "no /proc: signal 0 is the best answer available")'
    );

    /* 7. (TRD §5, optional/lower-priority) A process whose /proc/<pid>/stat name field
     * contains a ")" would exercise the lastIndexOf(")") anchor under adversarial input.
     * Skipped: reliably constructing a process with a controlled /proc comm string needs
     * argv0/prctl(PR_SET_NAME) control that a plain shell fixture doesn't give us. */
    skip(
      "7-defensive-parenthesis-in-process-name",
      "not easily constructible from a POSIX shell fixture without native argv0/prctl control; " +
      "TRD marks this optional and lower-priority, not required to close the core gap"
    );
  } finally {
    if (zombie) zombie.dispose();
  }

  /* NFR (TRD §6): no leaked zombie or lingering shell process after the run -- checked, not
   * assumed. */
  if (zombie) {
    const shellGone = await waitForGone(zombie.shellPid, 5000);
    const zombieGone = await waitForGone(zombie.pid, 5000);
    check(
      "8-no-leaked-shell-process-after-run",
      shellGone,
      `parent shell pid ${zombie.shellPid} is still present under /proc after dispose()`
    );
    check(
      "9-no-leaked-zombie-after-run",
      zombieGone,
      `zombie pid ${zombie.pid} is still present under /proc after dispose() -- it should ` +
      "have been reaped once its parent exited"
    );
  }

  summary();
}

main().catch((error) => {
  console.error("FATAL", (error && error.stack) || error);
  process.exit(1);
});
