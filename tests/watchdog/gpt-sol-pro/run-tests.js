#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execFileSync } = require("child_process");

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
    return true;
  } catch {
    return false;
  }
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
    }, timeoutMs);
    child.once("close", (code, signal) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ code, signal, timedOut: false });
      }
    });
  });
}

async function waitFor(predicate, timeoutMs, label) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
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
    await waitFor(() => fs.existsSync(readyFile), 3000, "blocked target readiness");
    const started = Date.now();
    watchdog = spawnWatchdog(target.pid, heartbeatFile, capabilityFile, haltFile, options.budget || BUDGET);
    const wdExit = await waitClose(watchdog, 5000);
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
    await waitFor(() => fs.existsSync(ready) && fs.existsSync(childPidFile), 3000, "process tree readiness");
    leafPid = Number(fs.readFileSync(childPidFile, "utf8"));
    watchdog = spawnWatchdog(parent.pid, heartbeat, capability, halt);
    const wdExit = await waitClose(watchdog, 5000);
    await waitClose(parent, 1500);
    await sleep(350);
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
    await waitFor(() => fs.existsSync(ready), 3000, "forged-heartbeat target");
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
  const underScript = writeScript(underDir, "under.js", `
    "use strict";
    const fs = require("fs");
    let n = 0;
    fs.writeFileSync(${JSON.stringify(heartbeat)}, "0");
    fs.writeFileSync(${JSON.stringify(ready)}, String(process.pid));
    const timer = setInterval(() => {
      fs.writeFileSync(${JSON.stringify(heartbeat)}, String(++n));
      if (n === 4) { clearInterval(timer); setTimeout(() => process.exit(0), 40); }
    }, ${BUDGET - 35});
  `);
  const target = spawnTarget(underScript);
  let watchdog;
  try {
    await waitFor(() => fs.existsSync(ready), 3000, "under-budget target");
    watchdog = spawnWatchdog(target.pid, heartbeat, capability, halt);
    const wdExit = await waitClose(watchdog, 5000);
    const targetExit = await waitClose(target, 2000);
    if (wdExit.code === 0 && targetExit.code === 0 && !fs.existsSync(halt)) {
      record("PASS", "budget-just-under", `heartbeat interval=${BUDGET - 35}ms; clean watchdog exit=0; no halt evidence`);
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
  if (over.wdExit.code === 3 && ev && ev.elapsed_ms > BUDGET && ev.elapsed_ms <= BUDGET + 100) {
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
    await waitFor(() => fs.existsSync(ready), 3000, "watchdog-death target");
    watchdog = spawnWatchdog(target.pid, heartbeat, capability, halt);
    await sleep(60);
    process.kill(watchdog.pid, "SIGKILL");
    const wdExit = await waitClose(watchdog, 2000);
    await sleep(BUDGET * 2);
    const targetEscaped = alive(target.pid) && !fs.existsSync(halt);
    if (!targetEscaped) {
      record("PASS", "watchdog-death-fail-closed", `guard died (${wdExit.signal || wdExit.code}) but target did not escape`);
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
      await waitFor(() => fs.existsSync(ready), 3000, `chaos point ${point}`);
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
    record("FAIL", "harness-unexpected-error", error.stack || error.message);
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
