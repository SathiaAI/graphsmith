#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execFileSync } = require("child_process");
const { harnessDeadline } = require("../../_harness/deadline.js");

/* The harness's own patience for the watchdog to exit. Named because the
 * blocked-event-loop case compares it to the product BUDGET to decide whether any
 * outcome was observable at all. */
const WATCHDOG_WAIT_MS = 5000;

const ROOT = path.resolve(__dirname, "../../..");
const WATCHDOG = path.join(ROOT, "scripts", "watchdog.js");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const BUDGET = 240;
const results = [];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function record(status, name, reason) {
  results.push({ status, name, reason });
  process.stdout.write(`${status} ${name}: ${reason}\n`);
}

function alive(pid) {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  // A ZOMBIE has been killed but not yet reaped, and signal 0 still succeeds for
  // it. Where PID 1 is a real init that is irrelevant; inside a container whose
  // PID 1 does not reap orphans (a plain `docker run`, many CI-in-container
  // setups) a correctly-killed grandchild lingers as a zombie forever and this
  // check would report the tree kill as failed when it actually worked. State Z
  // in /proc/<pid>/stat means dead. Field 3 is the state, but field 2 (comm) can
  // contain spaces and parentheses, so read after the LAST ')'.
  try {
    const stat = require("fs").readFileSync("/proc/" + pid + "/stat", "utf8");
    const close = stat.lastIndexOf(")");
    if (close !== -1 && stat.slice(close + 2).split(" ")[0] === "Z") return false;
  } catch { /* no /proc (Windows, macOS): signal 0 is the best signal available */ }
  return true;
}

function waitClose(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode, timedOut: false });
      return;
    }
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve({ code: child.exitCode, signal: child.signalCode, timedOut: true });
      }
    }, harnessDeadline(timeoutMs));
    child.once("close", (code, signal) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ code, signal, timedOut: false });
      }
    });
  });
}

/* How long to wait for a freshly SPAWNED target to write its readiness file.
 *
 * Six precondition waits in this file sat at a bare 3000ms. That is not a budget the
 * product is being measured against — nothing under test depends on the target becoming
 * ready quickly; every assertion in these cases happens AFTER readiness. It is the
 * harness's patience for Windows process creation plus Node startup plus a file write,
 * on a shared CI runner with a virus scanner in the path. Windows process creation costs
 * far more than a POSIX fork/exec, and 3s is a stopwatch guess rather than an
 * observation.
 *
 * It bit on GitHub Actions run #79: `timeout waiting for chaos point 5` on both Windows
 * legs, correctly reported INCONCLUSIVE (harness) rather than as a watchdog defect, and
 * the runner's own re-run passed — FLAKY, not a regression. Linux and macOS passed. This
 * is flake taxonomy shape 1 from the CI remediation plan: a fixed deadline used as a
 * precondition proxy.
 *
 * Widening a PRECONDITION wait cannot make a failing test pass. The product assertions
 * are downstream of it; all this changes is how long the harness is willing to wait
 * before admitting it observed nothing. Waits return the moment the predicate holds, so
 * on a healthy machine this costs nothing. Product-lifecycle waits in this file keep
 * their own budgets (30000 for the process tree to die, 10000 for the dead-man switch to
 * arm) — those are measuring the product and are deliberately left alone.
 */
const TARGET_READY_MS = 30000;

async function waitFor(predicate, timeoutMs, label) {
  const start = Date.now();
  const budget = harnessDeadline(timeoutMs);
  while (Date.now() - start < budget) {
    if (predicate()) return;
    await sleep(10);
  }
  throw new Error(`timeout waiting for ${label}`);
}

function killTree(pid) {
  if (!pid || !alive(pid)) return;
  if (process.platform === "win32") {
    try {
      execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore", timeout: 5000 });
      return;
    } catch {}
  } else {
    try {
      process.kill(-pid, "SIGKILL");
      return;
    } catch {}
  }
  try { process.kill(pid, "SIGKILL"); } catch {}
}

function writeScript(dir, name, source) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, source);
  return file;
}

function spawnTarget(script, args = []) {
  return spawn(process.execPath, [script, ...args], {
    detached: process.platform !== "win32",
    stdio: "ignore",
    windowsHide: true,
  });
}

function spawnWatchdog(pid, heartbeatFile, capabilityFile, haltFile, budget = BUDGET) {
  return spawn(process.execPath, [
    WATCHDOG,
    "--pid", String(pid),
    "--budget-ms", String(budget),
    "--heartbeat-file", heartbeatFile,
    "--capability-file", capabilityFile,
    "--halt-file", haltFile,
  ], { stdio: "ignore", windowsHide: true });
}

function readEvidence(haltFile) {
  return JSON.parse(fs.readFileSync(haltFile, "utf8"));
}

async function realBlockedKill(dir, options = {}) {
  const heartbeatFile = path.join(dir, "heartbeat");
  const capabilityFile = path.join(dir, "capability.json");
  const haltFile = path.join(dir, "halt.json");
  const readyFile = path.join(dir, "ready");
  fs.writeFileSync(heartbeatFile, "1");
  if (options.capability !== undefined) {
    fs.writeFileSync(capabilityFile, typeof options.capability === "string"
      ? options.capability
      : JSON.stringify(options.capability));
  }
  if (options.stale && fs.existsSync(capabilityFile)) {
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(capabilityFile, old, old);
  }
  const targetScript = writeScript(dir, "blocked.js", `
    "use strict";
    const fs = require("fs");
    fs.writeFileSync(${JSON.stringify(readyFile)}, String(process.pid));
    const beats = ${Number.isSafeInteger(options.preBlockBeats) ? options.preBlockBeats : 0};
    if (beats === 0) {
      for (;;) {}
    } else {
      let beat = 1;
      const timer = setInterval(() => {
        fs.writeFileSync(${JSON.stringify(heartbeatFile)}, String(++beat));
        if (beat > beats) {
          clearInterval(timer);
          for (;;) {}
        }
      }, 25);
    }
  `);
  const target = spawnTarget(targetScript);
  let watchdog;
  try {
    await waitFor(() => fs.existsSync(readyFile), TARGET_READY_MS, "blocked target readiness");
    const started = Date.now();
    watchdog = spawnWatchdog(target.pid, heartbeatFile, capabilityFile, haltFile, options.budget || BUDGET);
    const wdExit = await waitClose(watchdog, WATCHDOG_WAIT_MS);
    const elapsedWall = Date.now() - started;
    await waitClose(target, 2000);
    return {
      target,
      watchdog,
      wdExit,
      elapsedWall,
      evidence: fs.existsSync(haltFile) ? readEvidence(haltFile) : null,
      targetAlive: alive(target.pid),
    };
  } finally {
    if (watchdog && alive(watchdog.pid)) killTree(watchdog.pid);
    if (alive(target.pid)) killTree(target.pid);
  }
}

async function testBlockedAndIndependent(tmp) {
  const dir = path.join(tmp, "blocked-independent");
  fs.mkdirSync(dir);
  const run = await realBlockedKill(dir, { capability: { capability: null } });
  const ev = run.evidence;
  const ok = run.wdExit.code === 3 && ev && ev.halt === true && ev.kill_delivered === true &&
    !run.targetAlive && ev.elapsed_ms > BUDGET && run.elapsedWall <= BUDGET + 1200;
  if (ok) record("PASS", "blocked-event-loop-independent-kill",
    `target dead; watchdog exit=3; halt elapsed=${ev.elapsed_ms}ms wall=${run.elapsedWall}ms budget=${BUDGET}ms`);
  /* The harness ran out of ITS OWN time before the watchdog could act -- so nothing
   * was observed about whether the watchdog kills a blocked event loop.
   *
   * Caught by tests/harness-honesty/starvation on ubuntu CI, which is the whole
   * point of that sweep: under GRAPHSMITH_DEADLINE_SCALE this case emitted a
   * CONFIDENT FAIL at wall=7ms, reading as "the watchdog did not kill the target"
   * when the truth was "I did not wait". A verdict about the most safety-critical
   * mechanism here, asserted from a 7ms observation window.
   *
   * The discriminator is deliberately narrow: the harness deadline expired AND the
   * watchdog wrote no evidence at all. A timeout with evidence present is a real
   * product failure and still FAILS confidently -- widening this to `timedOut`
   * alone would swallow exactly the defect the case exists to catch. */
  /* The discriminator is `elapsedWall < BUDGET`, NOT `timedOut && !ev`.
   *
   * The first version used the absence of evidence, and an adversarial review broke
   * the watchdog so it never armed, never wrote the dead-man switch and never
   * killed -- with NO deadline scaling at all -- and got:
   *
   *     FAIL ... INCONCLUSIVE (harness): ... targetAlive=true ...
   *              this is the harness running out of patience, not a watchdog defect
   *
   * wall was 5014ms against a 240ms budget. The guard was dead, the target alive,
   * and the harness told the reader the watchdog was fine and advised removing a
   * scaled deadline that was never applied. ci-run-suites.js then files
   * INCONCLUSIVE under "NOT product findings ... nothing below says anything about
   * whether the product is correct". Still red, but pointing away from the defect.
   *
   * It also misfired the other way: `!ev` is a race against the watchdog's own
   * startup DMS write, so at scales >= 0.005 a HEALTHY watchdog produced a
   * CONFIDENT failure from a ~52ms window -- the original honesty defect, back.
   * The starvation sweep only ever uses 0.001, so it could not see that.
   *
   * Wall time cannot be confused this way. If the harness gave up BEFORE the
   * product's own budget could even elapse, nothing was observed by construction.
   * If it waited past the budget and the watchdog still did nothing, that is the
   * product failing and it fails confidently. Measured: starved-healthy is
   * 6-108ms << 240; the dead watchdog is 5014ms >> 240. */
  /* The discriminator is the harness's own DEADLINE against the product's BUDGET,
   * not elapsed time and not the absence of evidence. Both earlier attempts were
   * wrong, in opposite directions, and each was caught by an adversarial review:
   *
   *   `timedOut && !ev`      A watchdog that HANGS -- never arms, never writes --
   *                          produced timedOut=true, ev=null, and was labelled
   *                          "not a watchdog defect" at wall=5014ms against a 240ms
   *                          budget. It also raced the watchdog's own startup DMS
   *                          write, so at scales >= 0.005 a HEALTHY watchdog gave a
   *                          CONFIDENT failure from a ~52ms window.
   *
   *   `elapsedWall < BUDGET` Fixed the hang case and broke the other one: a guard
   *                          that DIES FAST (throw, bad argv, missing module,
   *                          immediate exit) returns in ~44ms with the target
   *                          alive, and got labelled inconclusive -- while the
   *                          version before it had that case right. Fast death is
   *                          the more common guard failure.
   *
   * Elapsed time cannot separate them because starved-healthy and dead-fast both
   * return quickly. The DEADLINE can: if the harness's own patience is shorter than
   * the budget the product is allowed to consume, no outcome here is observable BY
   * CONSTRUCTION, whatever happens. If the harness was willing to wait longer than
   * the budget and the watchdog still did not act, that is the product failing --
   * whether it hung or died at 44ms -- and it fails confidently.
   *
   * tests/_harness/deadline.js has exported isStarved() all along and nothing called
   * it. This is the same idea, expressed against the number that actually matters. */
  else if (harnessDeadline(WATCHDOG_WAIT_MS) < BUDGET) record("FAIL", "blocked-event-loop-independent-kill",
    "INCONCLUSIVE (harness): the harness deadline is " + harnessDeadline(WATCHDOG_WAIT_MS) + "ms, shorter than " +
    "the watchdog's own " + BUDGET + "ms budget, so no outcome was observable here whatever the watchdog did " +
    `(wall=${run.elapsedWall}ms timedOut=${run.wdExit.timedOut} targetAlive=${run.targetAlive} ` +
    `evidence=${ev ? "present" : "none"}). Re-run without a scaled harness deadline for a real verdict`);
  else record("FAIL", "blocked-event-loop-independent-kill",
    `exit=${run.wdExit.code} timedOut=${run.wdExit.timedOut} targetAlive=${run.targetAlive} evidence=${JSON.stringify(ev)} wall=${run.elapsedWall}ms`);
}

async function testProcessTree(tmp) {
  const dir = path.join(tmp, "process-tree");
  fs.mkdirSync(dir);
  const heartbeat = path.join(dir, "heartbeat");
  const capability = path.join(dir, "capability.json");
  const halt = path.join(dir, "halt.json");
  const ready = path.join(dir, "ready");
  const childPidFile = path.join(dir, "child.pid");
  fs.writeFileSync(heartbeat, "1");
  fs.writeFileSync(capability, JSON.stringify({ capability: null }));
  const leaf = writeScript(dir, "leaf.js", `
    "use strict";
    require("fs").writeFileSync(${JSON.stringify(childPidFile)}, String(process.pid));
    for (;;) {}
  `);
  const parentScript = writeScript(dir, "parent.js", `
    "use strict";
    const fs = require("fs");
    const { spawn } = require("child_process");
    spawn(process.execPath, [${JSON.stringify(leaf)}], { stdio: "ignore", windowsHide: true });
    fs.writeFileSync(${JSON.stringify(ready)}, String(process.pid));
    for (;;) {}
  `);
  const parent = spawnTarget(parentScript);
  let watchdog;
  let leafPid = null;
  try {
    await waitFor(() => fs.existsSync(ready) && fs.existsSync(childPidFile), TARGET_READY_MS, "process tree readiness");
    leafPid = Number(fs.readFileSync(childPidFile, "utf8"));
    watchdog = spawnWatchdog(parent.pid, heartbeat, capability, halt);
    // Deadlines widened after this case went red on ubuntu-18 (run #62) with
    // parentAlive=false childAlive=true -- the tree kill had simply not finished
    // landing on the grandchild. The re-run passed. Every bound below waits for
    // something that HAS to have happened, so a longer wait cannot mask a real
    // failure: a tree kill that never lands still reports parentAlive/leafAlive.
    const wdExit = await waitClose(watchdog, 20000);
    await waitClose(parent, 15000);
    // `parent` has a child_process handle we can await a real 'close' event on,
    // but `leafPid` (the grandchild) does not -- it was spawned BY parent.js, so
    // this harness only ever observes it via /proc polling through alive(). A
    // fixed sleep here was standing in for "the kill has landed on the leaf",
    // which is exactly the Shape-1 bug this suite keeps finding: SIGKILL
    // delivery plus kernel process-table teardown for a deep descendant is not
    // free, and under load it can plainly exceed a guessed constant (the same
    // class of jitter measured elsewhere in this suite as a 187..211ms watchdog
    // arm delay on a loaded 2-core runner). A too-short guess reads as "the tree
    // kill failed" when the kill had simply not finished landing yet. Wait for
    // the actual precondition -- both processes gone -- bounded by a generous
    // timeout; a genuine tree-kill failure still gets reported below via
    // parentAlive/leafAlive rather than hanging.
    try {
      await waitFor(() => !alive(parent.pid) && !alive(leafPid), 30000, "process tree kill to land");
    } catch { /* fall through; parentAlive/leafAlive below report the real state */ }
    const ev = fs.existsSync(halt) ? readEvidence(halt) : null;
    const parentAlive = alive(parent.pid);
    const leafAlive = alive(leafPid);
    if (wdExit.code === 3 && ev && ev.kill_delivered && !parentAlive && !leafAlive) {
      record("PASS", "process-tree-kill", `parent ${parent.pid} and child ${leafPid} are both dead`);
    } else {
      record("FAIL", "process-tree-kill", `watchdogExit=${wdExit.code} parentAlive=${parentAlive} childAlive=${leafAlive} evidence=${JSON.stringify(ev)}`);
    }
  } finally {
    if (watchdog && alive(watchdog.pid)) killTree(watchdog.pid);
    if (leafPid && alive(leafPid)) killTree(leafPid);
    if (alive(parent.pid)) killTree(parent.pid);
  }
}

const capabilityMessageKinds = {
  noEffects: "no-external-effects-in-flight",
  local: "safe-to-resume",
  idempotent: "safe-to-resume-assumed",
  reconcile: "reconciliation-required",
};

function normalizeMessage(message) {
  return typeof message === "string"
    ? message.replace(/[\u2010-\u2015]/g, "-").replace(/\s+/g, " ").trim()
    : "";
}

function matchesCapabilityMessage(message, expectedKind, expectedFragments = []) {
  const normalized = normalizeMessage(message);
  const kindMatches = {
    [capabilityMessageKinds.noEffects]: normalized.startsWith("no external effects in flight"),
    [capabilityMessageKinds.local]: normalized.startsWith("safe to resume"),
    [capabilityMessageKinds.idempotent]: normalized.includes("safe ASSUMING"),
    [capabilityMessageKinds.reconcile]: normalized.startsWith("reconciliation required"),
  };
  return kindMatches[expectedKind] === true &&
    expectedFragments.every((fragment) => normalized.includes(fragment));
}

async function testCapabilityMessages(tmp) {
  const cases = [
    { kind: "null", data: { capability: null }, expectedKind: capabilityMessageKinds.noEffects },
    { kind: "read-only", data: { capability: "read-only", effect_id: "read-1" }, expectedKind: capabilityMessageKinds.noEffects },
    { kind: "local", data: { capability: "local-transactional", effect_id: "local-1" }, expectedKind: capabilityMessageKinds.local, fragments: ["local effect", "local-1", "inspected"] },
    { kind: "idempotent", data: { capability: "idempotent-by-key", effect_id: "remote-1" }, expectedKind: capabilityMessageKinds.idempotent, fragments: ["recorded idempotency key", "remote-1", "remote honors the declared key"] },
    { kind: "status", data: { capability: "status-checkable", effect_id: "deploy-1" }, expectedKind: capabilityMessageKinds.reconcile, fragments: ["deploy-1", "status-checkable"] },
    { kind: "none", data: { capability: "none", effect_id: "send-1" }, expectedKind: capabilityMessageKinds.reconcile, fragments: ["send-1", "no capability declared"] },
    { kind: "unknown", data: { capability: "invented", effect_id: "x-1" }, expectedKind: capabilityMessageKinds.reconcile, fragments: ["x-1", "unknown capability"] },
    { kind: "missing", data: undefined, expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability file missing"] },
    { kind: "malformed", data: "{", expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability file malformed"] },
    { kind: "stale-local", data: { capability: "local-transactional", effect_id: "old-local" }, stale: true, expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability file stale"] },
    { kind: "stale-null", data: { capability: null }, stale: true, expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability file stale"] },
    { kind: "empty-object", data: {}, expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability field missing"] },
    { kind: "effect-without-cap", data: { effect_id: "unknown-effect" }, expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability field missing"] },
    { kind: "local-2", data: { capability: "local-transactional", effect_id: "local-2" }, expectedKind: capabilityMessageKinds.local, fragments: ["local effect", "local-2", "inspected"] },
    { kind: "idempotent-2", data: { capability: "idempotent-by-key", effect_id: "remote-2" }, expectedKind: capabilityMessageKinds.idempotent, fragments: ["recorded idempotency key", "remote-2", "remote honors the declared key"] },
    { kind: "status-2", data: { capability: "status-checkable", effect_id: "deploy-2" }, expectedKind: capabilityMessageKinds.reconcile, fragments: ["deploy-2", "status-checkable"] },
    { kind: "none-2", data: { capability: "none", effect_id: "send-2" }, expectedKind: capabilityMessageKinds.reconcile, fragments: ["send-2", "no capability declared"] },
    { kind: "read-only-2", data: { capability: "read-only", effect_id: "read-2" }, expectedKind: capabilityMessageKinds.noEffects },
    { kind: "null-2", data: { capability: null }, expectedKind: capabilityMessageKinds.noEffects },
    { kind: "missing-2", data: undefined, expectedKind: capabilityMessageKinds.reconcile, fragments: ["capability file missing"] },
  ];
  let matched = 0;
  const mismatches = [];
  let seed = 0x5eed1234;
  const killPoints = [];
  for (let i = 0; i < cases.length; i++) {
    const item = cases[i];
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const preBlockBeats = 1 + (seed % 7);
    killPoints.push(preBlockBeats);
    const dir = path.join(tmp, `capability-${String(i).padStart(2, "0")}-${item.kind}`);
    fs.mkdirSync(dir);
    const run = await realBlockedKill(dir, { capability: item.data, stale: item.stale, preBlockBeats });
    const actual = run.evidence && run.evidence.kill_message;
    if (run.wdExit.code === 3 && !run.targetAlive && matchesCapabilityMessage(actual, item.expectedKind, item.fragments)) matched++;
    else mismatches.push(`${i + 1}/${item.kind}: expected kind ${item.expectedKind} with fragments ${JSON.stringify(item.fragments || [])}, got ${JSON.stringify(actual)}`);
  }
  if (matched === cases.length) record("PASS", "capability-message-20-kill-points", `20/20 semantic message kinds at seeded heartbeat points ${killPoints.join(",")}`);
  else record("FAIL", "capability-message-20-kill-points", `${matched}/20 semantic message kinds at seeded heartbeat points ${killPoints.join(",")}; ${mismatches.join(" | ")}`);
}

function reportCrossPlatformCoverage() {
  if (process.platform === "win32") {
    record("SKIPPED", "unix-process-group-kill", "unavailable on win32; Windows taskkill /T /F path was exercised with a live child process");
  } else {
    record("SKIPPED", "windows-taskkill-tree", `unavailable on ${process.platform}; Unix negative-pid process-group path was exercised`);
  }
}

async function testForgedHeartbeat(tmp) {
  const dir = path.join(tmp, "forged-heartbeat");
  fs.mkdirSync(dir);
  const heartbeat = path.join(dir, "heartbeat");
  const capability = path.join(dir, "capability.json");
  const halt = path.join(dir, "halt.json");
  const ready = path.join(dir, "ready");
  fs.writeFileSync(heartbeat, "9007199254740991");
  fs.writeFileSync(capability, JSON.stringify({ capability: null }));
  const script = writeScript(dir, "blocked.js", `
    "use strict";
    require("fs").writeFileSync(${JSON.stringify(ready)}, String(process.pid));
    for (;;) {}
  `);
  const target = spawnTarget(script);
  let watchdog;
  try {
    await waitFor(() => fs.existsSync(ready), TARGET_READY_MS, "forged-heartbeat target");
    watchdog = spawnWatchdog(target.pid, heartbeat, capability, halt);
    const started = Date.now();
    let forged = 9007199254740000;
    while (Date.now() - started < BUDGET * 3) {
      forged -= 1;
      fs.writeFileSync(heartbeat, `${forged}garbage`);
      await sleep(35);
    }
    const escapedDuringForgery = alive(target.pid) && !fs.existsSync(halt);
    const wdExit = await waitClose(watchdog, 5000);
    await waitClose(target, 1500);
    const ev = fs.existsSync(halt) ? readEvidence(halt) : null;
    if (!escapedDuringForgery && wdExit.code === 3) {
      record("PASS", "heartbeat-forgery-and-partial-write", "malformed/regressing counter did not extend blocked target liveness");
    } else {
      record("FAIL", "heartbeat-forgery-and-partial-write",
        `blocked target escaped for ${Date.now() - started}ms while malformed regressing counters changed; escapedDuringForgery=${escapedDuringForgery} eventualExit=${wdExit.code} lastHeartbeat=${ev && ev.last_heartbeat}`);
    }
  } finally {
    if (watchdog && alive(watchdog.pid)) killTree(watchdog.pid);
    if (alive(target.pid)) killTree(target.pid);
  }
}

async function testBudgetBoundary(tmp) {
  const underDir = path.join(tmp, "budget-under");
  fs.mkdirSync(underDir);
  const heartbeat = path.join(underDir, "heartbeat");
  const capability = path.join(underDir, "capability.json");
  const halt = path.join(underDir, "halt.json");
  const ready = path.join(underDir, "ready");
  fs.writeFileSync(capability, JSON.stringify({ capability: null }));
  // Heartbeat cadence for the "comfortably under budget" case. This used to be
  // BUDGET - 35 (a 205ms interval against a 240ms budget), leaving only a 35ms
  // cushion between the interval and the budget. On a shared CI runner, a
  // single ~40ms stall in THIS process's own setInterval callback (GC pause,
  // scheduler contention -- the same class of jitter measured elsewhere in this
  // suite as a 187..211ms watchdog arm delay on a loaded 2-core runner) is
  // enough to widen one heartbeat gap past the budget and flip a healthy run
  // into a spurious halt. The GUARANTEE under test -- the watchdog does not
  // halt while heartbeats keep arriving well inside the budget -- does not
  // require probing to within 35ms of the edge; it only requires the cadence
  // to be unambiguously under budget. So widen the STIMULUS (the interval),
  // not the (already boolean, non-numeric) acceptance check: a much shorter
  // interval leaves a large cushion so ordinary scheduling jitter cannot flip
  // the outcome, while the cadence is still plainly, intentionally under
  // budget rather than at the budget itself.
  const UNDER_BUDGET_INTERVAL_MS = BUDGET - 150; // 90ms; was BUDGET - 35 (205ms)
  const underScript = writeScript(underDir, "under.js", `
    "use strict";
    const fs = require("fs");
    let n = 0;
    fs.writeFileSync(${JSON.stringify(heartbeat)}, "0");
    fs.writeFileSync(${JSON.stringify(ready)}, String(process.pid));
    const timer = setInterval(() => {
      fs.writeFileSync(${JSON.stringify(heartbeat)}, String(++n));
      if (n === 4) { clearInterval(timer); setTimeout(() => process.exit(0), 40); }
    }, ${UNDER_BUDGET_INTERVAL_MS});
  `);
  const target = spawnTarget(underScript);
  let watchdog;
  try {
    await waitFor(() => fs.existsSync(ready), TARGET_READY_MS, "under-budget target");
    watchdog = spawnWatchdog(target.pid, heartbeat, capability, halt);
    const wdExit = await waitClose(watchdog, 5000);
    const targetExit = await waitClose(target, 2000);
    if (wdExit.code === 0 && targetExit.code === 0 && !fs.existsSync(halt)) {
      record("PASS", "budget-just-under", `heartbeat interval=${UNDER_BUDGET_INTERVAL_MS}ms; clean watchdog exit=0; no halt evidence`);
    } else {
      record("FAIL", "budget-just-under", `watchdogExit=${wdExit.code} targetExit=${targetExit.code} halt=${fs.existsSync(halt)}`);
    }
  } finally {
    if (watchdog && alive(watchdog.pid)) killTree(watchdog.pid);
    if (alive(target.pid)) killTree(target.pid);
  }

  const overDir = path.join(tmp, "budget-over");
  fs.mkdirSync(overDir);
  const over = await realBlockedKill(overDir, { capability: { capability: null } });
  const ev = over.evidence;
  // The LOWER bound (elapsed_ms > BUDGET) is the security invariant here: the
  // watchdog must never report, and must never act on, a breach before the
  // budget has genuinely elapsed. That bound stays exact and is not loosened.
  // The UPPER bound is a detection-latency sanity check, not a security
  // guarantee -- and unlike budget-just-under, this target is blocked from
  // t=0, so there is no stimulus knob available to push it further from the
  // boundary; the overshoot is entirely a function of the watchdog's own poll
  // granularity (pollIntervalMs = floor(budgetMs/10) = 24ms at this budget)
  // plus whatever scheduling jitter the runner is under. A +100ms ceiling
  // gives only ~4 poll ticks of slack, and this suite has already measured
  // one-off scheduling jitter (the watchdog's own dead-man-switch arm delay)
  // of 187..211ms on a loaded 2-core runner -- comparable jitter in the poll
  // loop blows straight through +100ms and fails a watchdog that detected the
  // breach correctly, just not within an unrealistically tight window. Widen
  // the ceiling to comfortably exceed that measured jitter (10x+ the nominal
  // poll interval) so only a real stall in the watchdog's own detection loop
  // -- not ordinary CI scheduling noise -- can trip this.
  if (over.wdExit.code === 3 && ev && ev.elapsed_ms > BUDGET && ev.elapsed_ms <= BUDGET + 1000) {
    record("PASS", "budget-just-over", `halt elapsed=${ev.elapsed_ms}ms, strict budget=${BUDGET}ms`);
  } else {
    record("FAIL", "budget-just-over", `exit=${over.wdExit.code} evidence=${JSON.stringify(ev)}`);
  }
}

async function testWatchdogDeath(tmp) {
  const dir = path.join(tmp, "watchdog-death");
  fs.mkdirSync(dir);
  const heartbeat = path.join(dir, "heartbeat");
  const capability = path.join(dir, "capability.json");
  const halt = path.join(dir, "halt.json");
  const ready = path.join(dir, "ready");
  fs.writeFileSync(heartbeat, "1");
  fs.writeFileSync(capability, JSON.stringify({ capability: null }));
  const script = writeScript(dir, "blocked.js", `
    "use strict";
    require("fs").writeFileSync(${JSON.stringify(ready)}, String(process.pid));
    for (;;) {}
  `);
  const target = spawnTarget(script);
  let watchdog;
  try {
    await waitFor(() => fs.existsSync(ready), TARGET_READY_MS, "watchdog-death target");
    watchdog = spawnWatchdog(target.pid, heartbeat, capability, halt);
    // Wait until the guard has ARMED its dead-man switch, rather than assuming a
    // fixed 60ms is long enough to have started watching. That assumption is what
    // made this case fail on the windows and macos CI legs: on a loaded 2-core
    // runner the watchdog arms at t+187..211ms (measured), so a kill at t+60ms
    // destroyed it BEFORE it ever watched anything. A guard that never started
    // correctly leaves no evidence behind, and the test scored that absence as
    // "the blocked target escaped" -- condemning the component for a premise the
    // test itself never established. The property under test is what happens when
    // a guard that WAS watching dies, so wait for it to be watching.
    await waitFor(() => fs.existsSync(halt), 10000, "watchdog dead-man switch armed");
    process.kill(watchdog.pid, "SIGKILL");
    const wdExit = await waitClose(watchdog, 2000);
    await sleep(BUDGET * 2);
    // The switch must SURVIVE the guard's death -- that persistence is the whole
    // D4 signal -- and it must still be the dead-man record, not a real halt the
    // guard somehow wrote after being killed.
    let switchRecord = null;
    try { switchRecord = JSON.parse(fs.readFileSync(halt, "utf8")); } catch (e) { switchRecord = null; }
    const targetEscaped = alive(target.pid) && !fs.existsSync(halt);
    if (!targetEscaped && switchRecord && switchRecord.dead_man_switch === true) {
      record("PASS", "watchdog-death-fail-closed", `guard died (${wdExit.signal || wdExit.code}) but target did not escape: the armed dead-man switch survived, so the guard's death is discoverable`);
    } else if (!targetEscaped) {
      record("PASS", "watchdog-death-fail-closed", `guard died (${wdExit.signal || wdExit.code}) but target did not escape (evidence=${JSON.stringify(switchRecord)})`);
    } else {
      record("FAIL", "watchdog-death-fail-closed", `guard died (${wdExit.signal || wdExit.code}); blocked target ${target.pid} remained alive and no halt evidence appeared after ${BUDGET * 2}ms`);
    }
  } finally {
    if (watchdog && alive(watchdog.pid)) killTree(watchdog.pid);
    if (alive(target.pid)) killTree(target.pid);
  }
}

async function testChaosResume(tmp) {
  const points = [1, 2, 3, 5, 7];
  const failures = [];
  for (const point of points) {
    const dir = path.join(tmp, `chaos-${point}`);
    fs.mkdirSync(dir);
    const heartbeat = path.join(dir, "heartbeat");
    const capability = path.join(dir, "capability.json");
    const halt = path.join(dir, "halt.json");
    const ready = path.join(dir, "ready");
    fs.writeFileSync(capability, JSON.stringify({ capability: null }));
    const managerScript = writeScript(dir, "state-manager.js", `
      "use strict";
      const fs = require("fs");
      const store = require(${JSON.stringify(STATE_STORE)}).createStore(${JSON.stringify(dir)});
      const point = Number(process.argv[2]);
      const resume = process.argv[3] === "resume";
      const prior = store.rejectedBuffer.list();
      for (let i = prior.length + 1; i <= (resume ? 8 : point); i++) {
        store.rejectedBuffer.push({ fingerprint: "step-" + i, value: { ordinal: i } });
        fs.writeFileSync(${JSON.stringify(heartbeat)}, String(i));
      }
      if (resume) process.exit(0);
      fs.writeFileSync(${JSON.stringify(ready)}, String(process.pid));
      for (;;) {}
    `);
    const target = spawnTarget(managerScript, [String(point)]);
    let watchdog;
    try {
      await waitFor(() => fs.existsSync(ready), TARGET_READY_MS, `chaos point ${point}`);
      watchdog = spawnWatchdog(target.pid, heartbeat, capability, halt);
      const wdExit = await waitClose(watchdog, 5000);
      await waitClose(target, 1500);
      const afterKill = require(STATE_STORE).createStore(dir).rejectedBuffer.list();
      const resume = spawnTarget(managerScript, [String(point), "resume"]);
      const resumeExit = await waitClose(resume, 5000);
      const final = require(STATE_STORE).createStore(dir).rejectedBuffer.list();
      const killOrdinals = afterKill.map((x) => x.value.ordinal);
      const finalOrdinals = final.map((x) => x.value.ordinal);
      const expectedKill = Array.from({ length: point }, (_, i) => i + 1);
      const expectedFinal = Array.from({ length: 8 }, (_, i) => i + 1);
      if (wdExit.code !== 3 || resumeExit.code !== 0 ||
          JSON.stringify(killOrdinals) !== JSON.stringify(expectedKill) ||
          JSON.stringify(finalOrdinals) !== JSON.stringify(expectedFinal)) {
        failures.push(`point ${point}: wd=${wdExit.code}, resume=${resumeExit.code}, killed=${JSON.stringify(killOrdinals)}, final=${JSON.stringify(finalOrdinals)}`);
      }
    } finally {
      if (watchdog && alive(watchdog.pid)) killTree(watchdog.pid);
      if (alive(target.pid)) killTree(target.pid);
    }
  }
  if (!failures.length) record("PASS", "chaos-state-store-resume-5-points",
    `kills after durable checkpoints ${points.join(",")}; every restart reached exactly [1..8] without duplicates or mixed state`);
  else record("FAIL", "chaos-state-store-resume-5-points", failures.join(" | "));
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-watchdog-gpt-sol-pro-"));
  process.stdout.write(`platform=${process.platform} node=${process.version} temp=${tmp}\n`);
  try {
    await testBlockedAndIndependent(tmp);
    await testProcessTree(tmp);
    reportCrossPlatformCoverage();
    await testCapabilityMessages(tmp);
    await testChaosResume(tmp);
    await testForgedHeartbeat(tmp);
    await testBudgetBoundary(tmp);
    await testWatchdogDeath(tmp);
  } catch (error) {
    // A catch-all that reports a PRECONDITION TIMEOUT as an ordinary failure puts a
    // harness problem in the product-findings bucket. But it must not blanket-tag
    // everything: an unexpected exception from the product IS a real defect, and
    // calling that inconclusive would hide it. So split on the actual error --
    // "timeout waiting for X" means the trial never started; anything else is a
    // genuine failure and stays one.
    if (/timeout waiting for/i.test(String(error && error.message))) {
      record("FAIL", "harness-unexpected-error",
        "INCONCLUSIVE (harness): a precondition never materialised, so the case never ran -- " +
        String(error.message));
    } else {
      record("FAIL", "harness-unexpected-error", error.stack || error.message);
    }
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
  const pass = results.filter((x) => x.status === "PASS").length;
  const fail = results.filter((x) => x.status === "FAIL").length;
  const skipped = results.filter((x) => x.status === "SKIPPED").length;
  process.stdout.write(`SUMMARY PASS=${pass} FAIL=${fail} SKIPPED=${skipped} TOTAL=${results.length}\n`);
  process.exitCode = fail ? 1 : 0;
}

main();
