#!/usr/bin/env node
/* Adversarial battery for scripts/watchdog.js — Grok lane.
 * Drive watchdog as a REAL child process. Verdicts from process state,
 * exit codes, and on-disk halt evidence only. Zero-dep CJS. Temp dirs only.
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, execSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const WATCHDOG = path.join(ROOT, "scripts", "watchdog.js");
const IS_WIN = process.platform === "win32";
const NODE = process.execPath;

const results = [];
let failures = 0;

function rec(name, status, reason, extra) {
  const row = { name, status, reason: reason || null };
  if (extra) row.extra = extra;
  results.push(row);
  const tag = status === "PASS" ? "PASS" : status === "SKIPPED" ? "SKIP" : "FAIL";
  process.stdout.write(`[${tag}] ${name}${reason ? " — " + reason : ""}\n`);
  if (status === "FAIL") failures++;
}

function monoMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function mkTmp(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-wd-grok-${label}-`));
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {}
}

function pidAlive(pid) {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function forceKillTree(pid) {
  if (!pid) return;
  try {
    if (IS_WIN) {
      try {
        execSync(`taskkill /PID ${pid} /T /F`, { stdio: "ignore", timeout: 5000 });
      } catch {
        try {
          process.kill(pid, "SIGKILL");
        } catch {}
      }
    } else {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        try {
          process.kill(pid, "SIGKILL");
        } catch {}
      }
    }
  } catch {}
}

function listDescendantPids(rootPid) {
  const out = new Set();
  try {
    if (IS_WIN) {
      const raw = execSync(
        `wmic process where (ParentProcessId=${rootPid}) get ProcessId /FORMAT:LIST`,
        { encoding: "utf8", timeout: 5000, windowsHide: true }
      );
      for (const m of raw.matchAll(/ProcessId=(\d+)/g)) {
        const p = parseInt(m[1], 10);
        if (p && p !== rootPid) {
          out.add(p);
          for (const c of listDescendantPids(p)) out.add(c);
        }
      }
    } else {
      const raw = execSync(`ps -o pid= --ppid ${rootPid}`, {
        encoding: "utf8",
        timeout: 5000,
      });
      for (const line of raw.split(/\s+/)) {
        const p = parseInt(line.trim(), 10);
        if (p && p !== rootPid) {
          out.add(p);
          for (const c of listDescendantPids(p)) out.add(c);
        }
      }
    }
  } catch {
    /* empty / tool missing */
  }
  return out;
}

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function writeMockManager(dir, body) {
  const p = path.join(dir, "mock-manager.js");
  fs.writeFileSync(p, body);
  return p;
}

function spawnWatchdog(opts) {
  const args = [
    WATCHDOG,
    "--pid",
    String(opts.pid),
    "--budget-ms",
    String(opts.budgetMs),
    "--heartbeat-file",
    opts.heartbeatFile,
    "--capability-file",
    opts.capabilityFile,
    "--halt-file",
    opts.haltFile,
  ];
  const child = spawn(NODE, args, {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => {
    stdout += d.toString();
  });
  child.stderr.on("data", (d) => {
    stderr += d.toString();
  });
  const done = new Promise((resolve) => {
    child.on("close", (code, signal) => {
      resolve({ code, signal, stdout, stderr, pid: child.pid });
    });
  });
  return { child, done };
}

function spawnManager(scriptPath, { detached } = { detached: !IS_WIN }) {
  const child = spawn(NODE, [scriptPath], {
    stdio: ["ignore", "pipe", "pipe"],
    detached: !!detached,
    windowsHide: true,
  });
  if (detached && child.pid && !IS_WIN) {
    try {
      child.unref();
    } catch {}
  }
  return child;
}

/* ── Attack harness helpers ─────────────────────────────────────────── */

async function runBlockedTarget({
  dir,
  budgetMs,
  capability,
  beatsBeforeBlock,
  heartbeatMs,
  spinMs,
  forgeCounter,
  children,
  writeCheckpointEachBeat,
  omitCapabilityFile,
  corruptCapability,
  freezeCapability,
}) {
  const heartbeatFile = path.join(dir, "heartbeat");
  const capabilityFile = path.join(dir, "capability.json");
  const haltFile = path.join(dir, "halt.json");
  const stateFile = path.join(dir, "state.json");
  const journalFile = path.join(dir, "journal.jsonl");
  const childMarker = path.join(dir, "child-alive");

  fs.writeFileSync(stateFile, JSON.stringify({ step: 0, completed: [], version: 1 }));
  fs.writeFileSync(journalFile, "");
  if (!omitCapabilityFile) {
    if (corruptCapability) {
      fs.writeFileSync(capabilityFile, "{not-json");
    } else {
      fs.writeFileSync(capabilityFile, JSON.stringify(capability));
    }
  }

  const rewriteCap = !(omitCapabilityFile || corruptCapability || freezeCapability);

  const script = `
"use strict";
const fs = require("fs");
const { spawn } = require("child_process");
const path = require("path");
const hb = ${JSON.stringify(heartbeatFile)};
const cap = ${JSON.stringify(capabilityFile)};
const stateFile = ${JSON.stringify(stateFile)};
const journalFile = ${JSON.stringify(journalFile)};
const childMarker = ${JSON.stringify(childMarker)};
const beatsBeforeBlock = ${Number(beatsBeforeBlock)};
const heartbeatMs = ${Number(heartbeatMs)};
const spinMs = ${Number(spinMs)};
const doChildren = ${!!children};
const writeCp = ${!!writeCheckpointEachBeat};
const forge = ${JSON.stringify(forgeCounter || null)};
let counter = 0;
const kids = [];
if (doChildren) {
  const kidCode = path.join(${JSON.stringify(dir)}, "orphan-kid.js");
  fs.writeFileSync(kidCode, [
    '"use strict";',
    'const fs=require("fs");',
    'const m=' + JSON.stringify(childMarker) + ';',
    'setInterval(()=>{ try{ fs.writeFileSync(m, String(process.pid)+" "+Date.now()); }catch{} }, 50);',
    'setTimeout(()=>{}, 120000);',
  ].join("\\n"));
  for (let i = 0; i < 2; i++) {
    const k = spawn(process.execPath, [kidCode], {
      stdio: "ignore",
      detached: ${IS_WIN ? "false" : "true"},
      windowsHide: true,
    });
    kids.push(k.pid);
    try { k.unref(); } catch {}
  }
  fs.writeFileSync(path.join(${JSON.stringify(dir)}, "child-pids.json"), JSON.stringify(kids));
}
const iv = setInterval(() => {
  counter++;
  const val = forge && forge.mode === "jump-high" ? forge.value + counter : counter;
  try { fs.writeFileSync(hb, String(val)); } catch {}
  if (writeCp) {
    try {
      const st = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      st.step = counter;
      st.completed.push("step-" + counter);
      fs.writeFileSync(stateFile, JSON.stringify(st));
      fs.appendFileSync(journalFile, JSON.stringify({ step: counter, at: Date.now() }) + "\\n");
    } catch {}
  }
  if (counter >= beatsBeforeBlock) {
    clearInterval(iv);
    ${
      rewriteCap
        ? `try {
      const c = ${JSON.stringify(capability)};
      fs.writeFileSync(cap, JSON.stringify(c));
    } catch {}`
        : ""
    }
    const end = Date.now() + spinMs;
    while (Date.now() < end) {
      /* hard sync spin — blocks event loop; no heartbeats */
      for (let i = 0; i < 1000; i++) Math.sqrt(i);
    }
  }
}, heartbeatMs);
`;
  const managerPath = writeMockManager(dir, script);
  const manager = spawnManager(managerPath, { detached: !IS_WIN });
  const managerPid = manager.pid;

  // Let a few heartbeats land
  await sleep(Math.max(80, heartbeatMs * Math.min(3, beatsBeforeBlock)));

  const t0 = monoMs();
  const wd = spawnWatchdog({
    pid: managerPid,
    budgetMs,
    heartbeatFile,
    capabilityFile,
    haltFile,
  });

  const wdResult = await Promise.race([
    wd.done,
    sleep(budgetMs + 8000).then(() => ({ code: -1, signal: null, stdout: "", stderr: "TEST_TIMEOUT", timedOut: true })),
  ]);
  const t1 = monoMs();

  // External cleanup if watchdog failed
  if (pidAlive(managerPid)) forceKillTree(managerPid);
  try {
    await Promise.race([
      new Promise((r) => manager.on("close", r)),
      sleep(2000),
    ]);
  } catch {}
  if (wd.child && pidAlive(wd.child.pid)) forceKillTree(wd.child.pid);

  // Collect child pids if any
  let childPids = [];
  try {
    childPids = JSON.parse(fs.readFileSync(path.join(dir, "child-pids.json"), "utf8"));
  } catch {}
  const orphans = childPids.filter((p) => pidAlive(p));
  // also check marker freshness
  let markerPidAlive = false;
  try {
    const m = fs.readFileSync(childMarker, "utf8").trim();
    const mp = parseInt(m.split(/\s+/)[0], 10);
    if (mp && pidAlive(mp)) markerPidAlive = true;
  } catch {}

  const halt = fs.existsSync(haltFile) ? readJson(haltFile) : null;
  const state = readJson(stateFile);
  let journalLines = [];
  try {
    journalLines = fs
      .readFileSync(journalFile, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  } catch {}

  // Ensure no leftover kids
  for (const p of childPids) forceKillTree(p);

  return {
    managerPid,
    wdResult,
    wallMs: t1 - t0,
    halt,
    state,
    journalLines,
    orphans,
    markerPidAlive,
    managerStillAlive: pidAlive(managerPid),
  };
}

/* ── Tests ──────────────────────────────────────────────────────────── */

async function testBlockedEventLoopKill() {
  const name = "A1-blocked-event-loop-kill-within-budget";
  const dir = mkTmp("a1");
  try {
    const budgetMs = 500;
    const r = await runBlockedTarget({
      dir,
      budgetMs,
      capability: { capability: null },
      beatsBeforeBlock: 4,
      heartbeatMs: 40,
      spinMs: 30000,
      writeCheckpointEachBeat: true,
    });
    if (r.managerStillAlive) {
      rec(name, "FAIL", `manager pid ${r.managerPid} still alive after budget`);
      return;
    }
    if (!r.halt || r.halt.halt !== true) {
      rec(name, "FAIL", "halt file missing or halt!==true", { halt: r.halt, code: r.wdResult.code });
      return;
    }
    if (r.wdResult.code !== 3) {
      rec(name, "FAIL", `watchdog exit code ${r.wdResult.code} expected 3 (HALT)`, {
        code: r.wdResult.code,
        stderr: r.wdResult.stderr,
      });
      return;
    }
    // wall clock from watchdog spawn → halt: must be within budget + generous poll slack
    // first heartbeats may still advance; kill timing measured vs last heartbeat inside halt
    if (typeof r.halt.elapsed_ms !== "number" || r.halt.elapsed_ms <= budgetMs) {
      // elapsed must exceed budget (breach)
      if (!(r.halt.elapsed_ms > budgetMs)) {
        rec(name, "FAIL", `elapsed_ms ${r.halt.elapsed_ms} did not exceed budget ${budgetMs}`);
        return;
      }
    }
    // Must not be extremely late (budget + 2.5s slack allows poll granularity)
    if (r.halt.elapsed_ms > budgetMs + 2500) {
      rec(name, "FAIL", `kill too late: elapsed_ms=${r.halt.elapsed_ms} budget=${budgetMs}`);
      return;
    }
    if (r.wallMs > budgetMs + 4000) {
      rec(name, "FAIL", `wall clock kill too slow: ${r.wallMs}ms`);
      return;
    }
    rec(name, "PASS", `killed pid=${r.managerPid} exit=3 elapsed=${r.halt.elapsed_ms}ms wall=${r.wallMs}ms`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testWatchdogNotStarved() {
  const name = "A2-watchdog-own-process-not-starved-by-spin";
  const dir = mkTmp("a2");
  try {
    const budgetMs = 400;
    // Target hogs CPU hard; watchdog is separate process so must still fire.
    const r = await runBlockedTarget({
      dir,
      budgetMs,
      capability: { capability: "read-only" },
      beatsBeforeBlock: 3,
      heartbeatMs: 30,
      spinMs: 60000,
    });
    if (r.managerStillAlive) {
      rec(name, "FAIL", "target still alive — watchdog starved or kill failed");
      return;
    }
    if (r.wdResult.code !== 3 || !r.halt || !r.halt.halt) {
      rec(name, "FAIL", "no HALT under CPU-spin target", { code: r.wdResult.code, halt: r.halt });
      return;
    }
    // Watchdog process is distinct: its pid != manager pid and halt was written
    if (r.halt.pid !== r.managerPid) {
      rec(name, "FAIL", `halt.pid ${r.halt.pid} != manager ${r.managerPid}`);
      return;
    }
    if (r.halt.elapsed_ms > budgetMs + 2500) {
      rec(name, "FAIL", `starvation-like delay: elapsed ${r.halt.elapsed_ms}ms`);
      return;
    }
    rec(name, "PASS", `separate-process kill under spin elapsed=${r.halt.elapsed_ms}ms`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testProcessTreeNoOrphans() {
  const name = "A3-process-tree-kill-no-orphans";
  const dir = mkTmp("a3");
  try {
    const budgetMs = 500;
    const r = await runBlockedTarget({
      dir,
      budgetMs,
      capability: { capability: null },
      beatsBeforeBlock: 4,
      heartbeatMs: 40,
      spinMs: 30000,
      children: true,
    });
    await sleep(300); // allow OS to reap
    // Re-check orphans after settle
    let childPids = [];
    try {
      childPids = JSON.parse(fs.readFileSync(path.join(dir, "child-pids.json"), "utf8"));
    } catch {}
    const still = childPids.filter((p) => pidAlive(p));
    if (r.managerStillAlive) {
      rec(name, "FAIL", "manager survived; cannot judge tree kill");
      for (const p of still) forceKillTree(p);
      return;
    }
    if (still.length > 0 || r.markerPidAlive) {
      rec(
        name,
        "FAIL",
        `orphaned children survived kill: pids=${JSON.stringify(still)} markerAlive=${r.markerPidAlive}`,
        { platform: process.platform }
      );
      for (const p of still) forceKillTree(p);
      return;
    }
    if (r.wdResult.code !== 3 || !r.halt) {
      rec(name, "FAIL", "watchdog did not HALT", { code: r.wdResult.code });
      return;
    }
    rec(name, "PASS", `tree clean after kill; children checked=${childPids.length}`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

/* Contract 06 expected classes:
 * - null / read-only → "no external effects in flight"
 * - local-transactional → must contain "safe to resume" AND imply inspected
 * - idempotent-by-key → idempotency key ASSUMING wording
 * - status-checkable / none / unknown / missing → "reconciliation required"
 * NEVER false safe-to-resume when completion unknown.
 */

const CAP_CASES = [
  {
    id: "null-inflight",
    capability: { capability: null },
    mustInclude: ["no external effects in flight"],
    mustNotInclude: ["safe to resume"],
    forbidSafe: true,
  },
  {
    id: "read-only",
    capability: { capability: "read-only", effect_id: "peek" },
    mustInclude: ["no external effects in flight"],
    mustNotInclude: ["safe to resume"],
    forbidSafe: true,
  },
  {
    id: "local-transactional",
    capability: { capability: "local-transactional", effect_id: "write-cfg" },
    mustInclude: ["safe to resume"],
    // contract: inspected — message should not bare-claim safe without inspection note
    requireInspectedClaim: true,
  },
  {
    id: "idempotent-by-key",
    capability: { capability: "idempotent-by-key", effect_id: "create-rec" },
    mustInclude: ["idempotency key", "ASSUMING"],
    mustNotInclude: [],
  },
  {
    id: "status-checkable",
    capability: { capability: "status-checkable", effect_id: "deploy" },
    mustInclude: ["reconciliation required"],
    mustNotInclude: ["safe to resume"],
    forbidSafe: true,
  },
  {
    id: "none",
    capability: { capability: "none", effect_id: "webhook" },
    mustInclude: ["reconciliation required"],
    mustNotInclude: ["safe to resume"],
    forbidSafe: true,
  },
  {
    id: "unknown-variant",
    capability: { capability: "totally-made-up", effect_id: "x" },
    mustInclude: ["reconciliation required"],
    mustNotInclude: ["safe to resume"],
    forbidSafe: true,
  },
];

async function testCapabilityMessages() {
  for (const c of CAP_CASES) {
    const name = `A4-cap-msg-${c.id}`;
    const dir = mkTmp(`a4-${c.id}`);
    try {
      const r = await runBlockedTarget({
        dir,
        budgetMs: 400,
        capability: c.capability,
        beatsBeforeBlock: 3,
        heartbeatMs: 35,
        spinMs: 20000,
      });
      if (!r.halt || r.wdResult.code !== 3) {
        rec(name, "FAIL", "no halt evidence", { code: r.wdResult.code, halt: r.halt });
        continue;
      }
      const msg = String(r.halt.kill_message || "");
      const missing = (c.mustInclude || []).filter((s) => !msg.includes(s));
      const banned = (c.mustNotInclude || []).filter((s) => msg.toLowerCase().includes(s.toLowerCase()));
      if (missing.length || banned.length) {
        rec(name, "FAIL", `message mismatch msg="${msg}" missing=${JSON.stringify(missing)} bannedHit=${JSON.stringify(banned)}`);
        continue;
      }
      if (c.requireInspectedClaim) {
        // Contract 06: local-transactional → safe ONLY after inspection.
        // If watchdog emits "safe to resume" without any inspection evidence field
        // or "inspected" wording tied to actual check, that's a defect when it
        // didn't inspect on-disk state. Here we only have the message; the code
        // path never inspects — flag if it claims safe.
        if (msg.includes("safe to resume") && !msg.toLowerCase().includes("inspect")) {
          rec(
            name,
            "FAIL",
            `local-transactional claims safe without inspected wording: "${msg}"`
          );
          continue;
        }
        // Even with "inspected" in the string, watchdog never verified markers —
        // probe: leave a contradiction marker and ensure it still claims safe
        // (second subcase below). For this case, presence of inspect word is OK for message shape.
      }
      if (c.forbidSafe && /safe to resume/i.test(msg)) {
        rec(name, "FAIL", `false safe-to-resume: "${msg}"`);
        continue;
      }
      rec(name, "PASS", `msg="${msg}"`);
    } catch (e) {
      rec(name, "FAIL", e.stack || e.message);
    } finally {
      rmrf(dir);
    }
  }
}

async function testMissingCapabilityFailSafe() {
  const name = "A4b-missing-capability-file-fail-safe";
  const dir = mkTmp("a4b");
  try {
    // Completion UNKNOWN when capability file is absent → must NOT be safe/no-effects.
    // Contract default posture: reconciliation required until affirmatively upgraded.
    const r = await runBlockedTarget({
      dir,
      budgetMs: 400,
      capability: { capability: "status-checkable", effect_id: "maybe" },
      beatsBeforeBlock: 3,
      heartbeatMs: 35,
      spinMs: 20000,
      omitCapabilityFile: true,
    });
    if (!r.halt || r.wdResult.code !== 3) {
      rec(name, "FAIL", "no halt", { code: r.wdResult.code });
      return;
    }
    const msg = String(r.halt.kill_message || "");
    const lower = msg.toLowerCase();
    if (lower.includes("safe to resume")) {
      rec(name, "FAIL", `BLOCKING false safe-to-resume on missing cap file: "${msg}"`);
      return;
    }
    // "no external effects in flight" is also a false green when completion is unknown
    if (lower.includes("no external effects")) {
      rec(
        name,
        "FAIL",
        `BLOCKING fail-open: missing capability treated as no-effects ("${msg}"); must be reconciliation-required`
      );
      return;
    }
    if (!lower.includes("reconciliation required")) {
      rec(name, "FAIL", `expected reconciliation required, got "${msg}"`);
      return;
    }
    rec(name, "PASS", `msg="${msg}"`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testCorruptCapabilityFailSafe() {
  const name = "A4c-corrupt-capability-json-fail-safe";
  const dir = mkTmp("a4c");
  try {
    const r = await runBlockedTarget({
      dir,
      budgetMs: 400,
      capability: { capability: "none", effect_id: "x" },
      beatsBeforeBlock: 3,
      heartbeatMs: 35,
      spinMs: 20000,
      corruptCapability: true,
    });
    if (!r.halt || r.wdResult.code !== 3) {
      rec(name, "FAIL", "no halt", { code: r.wdResult.code });
      return;
    }
    const msg = String(r.halt.kill_message || "");
    if (/safe to resume|no external effects/i.test(msg)) {
      rec(name, "FAIL", `corrupt capability fail-open: "${msg}"`);
      return;
    }
    if (!/reconciliation required/i.test(msg)) {
      rec(name, "FAIL", `expected reconciliation required, got "${msg}"`);
      return;
    }
    rec(name, "PASS", `msg="${msg}"`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testStaleCapabilityDuringBlock() {
  // Cap file written with in-flight effect, then loop blocks before clearing.
  // Message must reflect the in-flight capability, not invent "safe"/cleared.
  const name = "A4d-stale-inflight-capability-not-cleared";
  const dir = mkTmp("a4d");
  try {
    const r = await runBlockedTarget({
      dir,
      budgetMs: 400,
      capability: { capability: "none", effect_id: "sent-maybe" },
      beatsBeforeBlock: 2,
      heartbeatMs: 30,
      spinMs: 20000,
    });
    if (!r.halt || r.wdResult.code !== 3) {
      rec(name, "FAIL", "no halt");
      return;
    }
    const msg = String(r.halt.kill_message || "");
    if (!msg.includes("reconciliation required")) {
      rec(name, "FAIL", `in-flight none must reconcile, got "${msg}"`);
      return;
    }
    if (r.halt.capability_at_kill !== "none") {
      rec(name, "FAIL", `capability_at_kill=${r.halt.capability_at_kill} expected none`);
      return;
    }
    rec(name, "PASS", `msg="${msg}"`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testLocalTransactionalUninspected() {
  // Watchdog claims "inspected" but never checks marker/journal — adversarial proof.
  const name = "A4e-local-transactional-claims-inspected-without-inspection";
  const dir = mkTmp("a4e");
  try {
    const r = await runBlockedTarget({
      dir,
      budgetMs: 400,
      capability: { capability: "local-transactional", effect_id: "write-cfg" },
      beatsBeforeBlock: 3,
      heartbeatMs: 35,
      spinMs: 20000,
    });
    if (!r.halt || r.wdResult.code !== 3) {
      rec(name, "FAIL", "no halt");
      return;
    }
    const msg = String(r.halt.kill_message || "");
    // If message says safe/inspected, watchdog must have performed inspection.
    // Evidence: halted object has no inspection fields; on-disk markers weren't read.
    const claimedSafe = /safe to resume/i.test(msg);
    const claimsInspected = /inspect/i.test(msg);
    const hasInspectionEvidence =
      r.halt &&
      (Object.prototype.hasOwnProperty.call(r.halt, "local_inspection") ||
        Object.prototype.hasOwnProperty.call(r.halt, "inspected") ||
        Object.prototype.hasOwnProperty.call(r.halt, "landed"));
    if (claimedSafe && claimsInspected && !hasInspectionEvidence) {
      rec(
        name,
        "FAIL",
        `kill_message claims inspected ("${msg}") but halt evidence has no inspection result fields — false assurance`
      );
      return;
    }
    if (claimedSafe && !claimsInspected) {
      rec(name, "FAIL", `safe without inspected claim: "${msg}"`);
      return;
    }
    rec(name, "PASS", `msg="${msg}" evidence_ok=${!!hasInspectionEvidence}`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testChaosResumeManyPoints() {
  const name = "A5-chaos-grade-resume-5plus-kill-points";
  const points = 6;
  const pointResults = [];
  try {
    for (let i = 0; i < points; i++) {
      const dir = mkTmp(`a5-${i}`);
      try {
        const caps = [
          { capability: null },
          { capability: "read-only", effect_id: "r" },
          { capability: "local-transactional", effect_id: "lt" },
          { capability: "idempotent-by-key", effect_id: "ik" },
          { capability: "status-checkable", effect_id: "sc" },
          { capability: "none", effect_id: "n" },
        ];
        const r = await runBlockedTarget({
          dir,
          budgetMs: 350,
          capability: caps[i % caps.length],
          beatsBeforeBlock: 2 + (i % 4),
          heartbeatMs: 30,
          spinMs: 15000,
          writeCheckpointEachBeat: true,
        });
        if (!r.halt || r.wdResult.code !== 3) {
          pointResults.push({ i, ok: false, why: "no halt", code: r.wdResult.code });
          continue;
        }
        // State must be parseable and consistent (no mixed partial JSON, no dups)
        if (!r.state || !Array.isArray(r.state.completed)) {
          pointResults.push({ i, ok: false, why: "state unreadable/inconsistent" });
          continue;
        }
        const uniq = new Set(r.state.completed);
        if (uniq.size !== r.state.completed.length) {
          pointResults.push({ i, ok: false, why: "duplicate completed steps" });
          continue;
        }
        // Journal lines must parse; step numbers monotonic non-decreasing
        let mono = true;
        let prev = 0;
        for (const j of r.journalLines) {
          if (typeof j.step !== "number" || j.step < prev) {
            mono = false;
            break;
          }
          prev = j.step;
        }
        if (!mono) {
          pointResults.push({ i, ok: false, why: "journal not consistent" });
          continue;
        }
        // Resume simulation: restart from last checkpointed step — deterministic
        const resumeFrom = r.state.step;
        const resumed = {
          step: resumeFrom,
          completed: r.state.completed.slice(),
          version: r.state.version,
        };
        // "neither/mixed" guard: completed length must equal unique prefix of steps
        const prefixOk = resumed.completed.every((s, idx) => s === `step-${idx + 1}` || s.startsWith("step-"));
        if (!prefixOk) {
          pointResults.push({ i, ok: false, why: "resume prefix inconsistent" });
          continue;
        }
        pointResults.push({
          i,
          ok: true,
          steps: resumed.completed.length,
          msg: r.halt.kill_message,
          cap: r.halt.capability_at_kill,
        });
      } finally {
        rmrf(dir);
      }
    }
    const bad = pointResults.filter((p) => !p.ok);
    if (bad.length) {
      rec(name, "FAIL", `${bad.length}/${points} kill-points failed resume consistency`, { bad, pointResults });
      return;
    }
    if (pointResults.length < 5) {
      rec(name, "FAIL", `only ${pointResults.length} points executed`);
      return;
    }
    rec(name, "PASS", `${pointResults.length} kill-points resumed consistently`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  }
}

async function testForgedHeartbeatCounter() {
  const name = "A6-forged-heartbeat-counter-while-blocked";
  const dir = mkTmp("a6");
  try {
    const heartbeatFile = path.join(dir, "heartbeat");
    const capabilityFile = path.join(dir, "capability.json");
    const haltFile = path.join(dir, "halt.json");
    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: "none", effect_id: "forged" }));
    fs.writeFileSync(heartbeatFile, "1");

    // Victim: a few real beats then hard spin (cannot update heartbeat itself)
    const victimSrc = `
"use strict";
const fs = require("fs");
const hb = ${JSON.stringify(heartbeatFile)};
let c = 0;
const iv = setInterval(() => {
  c++;
  fs.writeFileSync(hb, String(c));
  if (c >= 3) {
    clearInterval(iv);
    const end = Date.now() + 60000;
    while (Date.now() < end) { for (let i=0;i<500;i++) Math.sqrt(i); }
  }
}, 40);
`;
    const vp = writeMockManager(dir, victimSrc);
    const victim = spawnManager(vp, { detached: !IS_WIN });
    await sleep(150);

    // External forger process keeps advancing the counter while victim is blocked
    const forgerSrc = `
"use strict";
const fs = require("fs");
const hb = ${JSON.stringify(heartbeatFile)};
let c = 1000;
const iv = setInterval(() => {
  c++;
  try { fs.writeFileSync(hb, String(c)); } catch {}
}, 30);
setTimeout(() => { clearInterval(iv); process.exit(0); }, 15000);
`;
    const fp = path.join(dir, "forger.js");
    fs.writeFileSync(fp, forgerSrc);
    const forger = spawn(NODE, [fp], { stdio: "ignore", windowsHide: true });

    const budgetMs = 500;
    const wd = spawnWatchdog({
      pid: victim.pid,
      budgetMs,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });
    const wdResult = await Promise.race([
      wd.done,
      sleep(6000).then(() => ({ code: -1, timedOut: true })),
    ]);

    // If forger can keep victim "alive" past 6s with vetoed heartbeats, watchdog is fogable
    const halt = readJson(haltFile);
    const victimAlive = pidAlive(victim.pid);

    forceKillTree(victim.pid);
    forceKillTree(forger.pid);
    if (wd.child && pidAlive(wd.child.pid)) forceKillTree(wd.child.pid);

    if (wdResult.timedOut || (victimAlive && !halt)) {
      rec(
        name,
        "FAIL",
        "forged advancing counter starved the kill — watchdog trusts counter value changes without proving the watched pid produced them"
      );
      return;
    }
    // If kill DID fire despite forger, that's PASS (binding to pid liveness beyond file content)
    if (halt && halt.halt && !pidAlive(victim.pid)) {
      rec(name, "PASS", "kill still fired despite external forged counters");
      return;
    }
    if (halt && halt.halt) {
      rec(name, "PASS", "halt written");
      return;
    }
    rec(name, "FAIL", `unexpected state code=${wdResult.code} alive=${victimAlive} halt=${!!halt}`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testStaleMtimeSingleWrite() {
  // One forged high counter write then silence — should still kill (counter not advancing)
  const name = "A6b-stale-after-single-forged-high-counter";
  const dir = mkTmp("a6b");
  try {
    const heartbeatFile = path.join(dir, "heartbeat");
    const capabilityFile = path.join(dir, "capability.json");
    const haltFile = path.join(dir, "halt.json");
    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));
    // Victim writes nothing after bootstrap: simulate blocked before any real hb by
    // writing a huge counter externally then stopping.
    fs.writeFileSync(heartbeatFile, "999999");
    const victimSrc = `
"use strict";
const end = Date.now() + 60000;
while (Date.now() < end) { for (let i=0;i<200;i++) Math.sqrt(i); }
`;
    const vp = writeMockManager(dir, victimSrc);
    const victim = spawnManager(vp, { detached: !IS_WIN });
    await sleep(50);
    const budgetMs = 400;
    const t0 = monoMs();
    const wd = spawnWatchdog({
      pid: victim.pid,
      budgetMs,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });
    const wdResult = await Promise.race([
      wd.done,
      sleep(5000).then(() => ({ code: -1, timedOut: true })),
    ]);
    const wall = monoMs() - t0;
    const halt = readJson(haltFile);
    forceKillTree(victim.pid);
    if (wd.child && pidAlive(wd.child.pid)) forceKillTree(wd.child.pid);

    if (wdResult.timedOut || !halt) {
      rec(name, "FAIL", "did not kill on stale high counter", { code: wdResult.code, wall });
      return;
    }
    if (wdResult.code !== 3) {
      rec(name, "FAIL", `exit ${wdResult.code} expected 3`);
      return;
    }
    rec(name, "PASS", `stale high counter killed elapsed=${halt.elapsed_ms} wall=${wall}`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testBudgetBoundaries() {
  // just-under: keep heartbeats flowing slightly faster than budget → must NOT halt
  {
    const name = "A7a-budget-just-under-no-kill";
    const dir = mkTmp("a7a");
    try {
      const budgetMs = 600;
      const heartbeatFile = path.join(dir, "heartbeat");
      const capabilityFile = path.join(dir, "capability.json");
      const haltFile = path.join(dir, "halt.json");
      fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));
      const src = `
"use strict";
const fs = require("fs");
const hb = ${JSON.stringify(heartbeatFile)};
let c = 0;
const iv = setInterval(() => {
  c++;
  fs.writeFileSync(hb, String(c));
}, 80);
setTimeout(() => { clearInterval(iv); process.exit(0); }, 1800);
`;
      const vp = writeMockManager(dir, src);
      const victim = spawnManager(vp, { detached: false });
      await sleep(60);
      const wd = spawnWatchdog({
        pid: victim.pid,
        budgetMs,
        heartbeatFile,
        capabilityFile,
        haltFile,
      });
      const wdResult = await wd.done;
      // Manager exits normally → watchdog exit 0, no halt file (or halt false)
      const halt = readJson(haltFile);
      if (wdResult.code === 3 || (halt && halt.halt === true)) {
        rec(name, "FAIL", `false kill under live heartbeats code=${wdResult.code} halt=${JSON.stringify(halt)}`);
      } else if (wdResult.code === 0 && !pidAlive(victim.pid)) {
        rec(name, "PASS", "manager exited clean; watchdog exit 0");
      } else {
        rec(name, "FAIL", `unexpected code=${wdResult.code} alive=${pidAlive(victim.pid)}`);
      }
      forceKillTree(victim.pid);
      if (wd.child && pidAlive(wd.child.pid)) forceKillTree(wd.child.pid);
    } catch (e) {
      rec(name, "FAIL", e.stack || e.message);
    } finally {
      rmrf(dir);
    }
  }

  // just-over: stop heartbeats just past budget → must kill
  {
    const name = "A7b-budget-just-over-kills";
    const dir = mkTmp("a7b");
    try {
      const budgetMs = 350;
      const r = await runBlockedTarget({
        dir,
        budgetMs,
        capability: { capability: null },
        beatsBeforeBlock: 2,
        heartbeatMs: 40,
        spinMs: 20000,
      });
      if (r.wdResult.code !== 3 || !r.halt) {
        rec(name, "FAIL", `expected HALT at just-over, code=${r.wdResult.code}`);
        return;
      }
      if (!(r.halt.elapsed_ms > budgetMs)) {
        rec(name, "FAIL", `elapsed ${r.halt.elapsed_ms} not > budget ${budgetMs}`);
        return;
      }
      // upper bound: poll slack budget/10 + some OS jitter
      if (r.halt.elapsed_ms > budgetMs + 2000) {
        rec(name, "FAIL", `kill overly late ${r.halt.elapsed_ms}ms`);
        return;
      }
      rec(name, "PASS", `elapsed=${r.halt.elapsed_ms} budget=${budgetMs}`);
    } catch (e) {
      rec(name, "FAIL", e.stack || e.message);
    } finally {
      rmrf(dir);
    }
  }
}

async function testWatchdogSelfCrash() {
  const name = "A8-watchdog-self-crash-no-manager-notice-channel";
  const dir = mkTmp("a8");
  try {
    // Interface has no reverse heartbeat / integrity channel from watchdog → manager.
    // Prove a dead watchdog leaves the blocked manager running with no halt file.
    const heartbeatFile = path.join(dir, "heartbeat");
    const capabilityFile = path.join(dir, "capability.json");
    const haltFile = path.join(dir, "halt.json");
    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: "none", effect_id: "z" }));
    const src = `
"use strict";
const fs = require("fs");
const hb = ${JSON.stringify(heartbeatFile)};
let c = 0;
const iv = setInterval(() => {
  c++;
  fs.writeFileSync(hb, String(c));
  if (c >= 4) {
    clearInterval(iv);
    const end = Date.now() + 8000;
    while (Date.now() < end) { for (let i=0;i<300;i++) Math.sqrt(i); }
  }
}, 40);
`;
    const vp = writeMockManager(dir, src);
    const victim = spawnManager(vp, { detached: !IS_WIN });
    await sleep(100);
    const wd = spawnWatchdog({
      pid: victim.pid,
      budgetMs: 400,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });
    await sleep(80);
    // Kill the watchdog itself mid-watch
    forceKillTree(wd.child.pid);
    await sleep(1500);
    const victimStill = pidAlive(victim.pid);
    const halt = readJson(haltFile);
    // After watchdog death + >budget, blocked victim should still be alive if no supervisor
    // (manager cannot notice its guard died — interface gap)
    forceKillTree(victim.pid);
    if (wd.child && pidAlive(wd.child.pid)) forceKillTree(wd.child.pid);

    if (victimStill && !halt) {
      rec(
        name,
        "FAIL",
        "watchdog death leaves blocked run unguarded; no interface for manager to detect guard death (no reverse heartbeat / exit pipe requirement)"
      );
      return;
    }
    if (halt && halt.halt) {
      rec(name, "PASS", "halt still produced (unlikely race)");
      return;
    }
    rec(name, "FAIL", `ambiguous victimStill=${victimStill} halt=${!!halt}`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testUsageExitCodes() {
  const name = "A9-usage-error-exit-2";
  try {
    const child = spawn(NODE, [WATCHDOG], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    const code = await new Promise((resolve) => child.on("close", resolve));
    if (code !== 2) {
      rec(name, "FAIL", `expected exit 2, got ${code}`);
      return;
    }
    rec(name, "PASS", "exit 2 on missing args");
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  }
}

async function testDeadPid() {
  const name = "A10-dead-pid-exit-1";
  const dir = mkTmp("a10");
  try {
    // spawn short-lived process, wait dead, attach watchdog
    const child = spawn(NODE, ["-e", "process.exit(0)"], { stdio: "ignore", windowsHide: true });
    const deadPid = child.pid;
    await new Promise((r) => child.on("close", r));
    await sleep(50);
    const wd = spawnWatchdog({
      pid: deadPid,
      budgetMs: 300,
      heartbeatFile: path.join(dir, "hb"),
      capabilityFile: path.join(dir, "cap.json"),
      haltFile: path.join(dir, "halt.json"),
    });
    fs.writeFileSync(path.join(dir, "cap.json"), "{}");
    const res = await wd.done;
    if (res.code !== 1) {
      rec(name, "FAIL", `expected exit 1 for dead pid, got ${res.code}`);
      return;
    }
    rec(name, "PASS", "exit 1 when pid already dead");
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function testPartialHeartbeatWrite() {
  const name = "A6c-partial-heartbeat-non-integer";
  const dir = mkTmp("a6c");
  try {
    const heartbeatFile = path.join(dir, "heartbeat");
    const capabilityFile = path.join(dir, "capability.json");
    const haltFile = path.join(dir, "halt.json");
    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));
    // Victim writes garbage interleaved with silence
    const src = `
"use strict";
const fs = require("fs");
const hb = ${JSON.stringify(heartbeatFile)};
fs.writeFileSync(hb, "1");
setTimeout(() => {
  fs.writeFileSync(hb, "12 partial"); // parseInt → 12 once; then nonsense
  const end = Date.now() + 30000;
  while (Date.now() < end) { for (let i=0;i<200;i++) Math.sqrt(i); }
}, 50);
`;
    const vp = writeMockManager(dir, src);
    const victim = spawnManager(vp, { detached: !IS_WIN });
    await sleep(30);
    const budgetMs = 400;
    const wd = spawnWatchdog({
      pid: victim.pid,
      budgetMs,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });
    const res = await Promise.race([
      wd.done,
      sleep(5000).then(() => ({ code: -1, timedOut: true })),
    ]);
    const halt = readJson(haltFile);
    forceKillTree(victim.pid);
    if (wd.child && pidAlive(wd.child.pid)) forceKillTree(wd.child.pid);
    if (res.timedOut || !halt || res.code !== 3) {
      rec(name, "FAIL", `did not halt on partial/garbage hb code=${res.code}`);
      return;
    }
    rec(name, "PASS", `halted despite partial hb elapsed=${halt.elapsed_ms}`);
  } catch (e) {
    rec(name, "FAIL", e.stack || e.message);
  } finally {
    rmrf(dir);
  }
}

async function main() {
  process.stdout.write(`watchdog adversarial battery (grok) platform=${process.platform} node=${process.version}\n`);
  process.stdout.write(`target=${WATCHDOG}\n\n`);

  if (!fs.existsSync(WATCHDOG)) {
    process.stdout.write("FATAL: watchdog.js missing\n");
    process.exit(1);
  }

  await testBlockedEventLoopKill();
  await testWatchdogNotStarved();
  await testProcessTreeNoOrphans();
  await testCapabilityMessages();
  await testMissingCapabilityFailSafe();
  await testCorruptCapabilityFailSafe();
  await testStaleCapabilityDuringBlock();
  await testLocalTransactionalUninspected();
  await testChaosResumeManyPoints();
  await testForgedHeartbeatCounter();
  await testStaleMtimeSingleWrite();
  await testPartialHeartbeatWrite();
  await testBudgetBoundaries();
  await testWatchdogSelfCrash();
  await testUsageExitCodes();
  await testDeadPid();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;

  process.stdout.write("\n══ SUMMARY ══\n");
  process.stdout.write(JSON.stringify({ total: results.length, passed, failed, skipped }, null, 2) + "\n");
  process.stdout.write("\n══ RESULTS ══\n");
  process.stdout.write(JSON.stringify(results, null, 2) + "\n");

  // Write machine-readable alongside FINDINGS.md (runner responsibility is stdout + files)
  try {
    fs.writeFileSync(
      path.join(__dirname, "last-run.json"),
      JSON.stringify({ when: new Date().toISOString(), passed, failed, skipped, results }, null, 2)
    );
  } catch {}

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + "\n");
  process.exit(1);
});
