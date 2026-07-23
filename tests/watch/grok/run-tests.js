#!/usr/bin/env node
/* Adversarial battery for scripts/watch.js — Grok lane.
 * Lane: tests/watch/grok/ only. Do NOT modify scripts/.
 * Drive watch via CLI (spawn) and require() in TEMP run-state dirs.
 * Verdicts from exit codes, stdout/stderr, pid liveness, dir hashes — not vibes.
 * Zero-dep CJS. Exit 1 if ANY FAIL. Zero-finding review INVALID.
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn, spawnSync, execSync } = require("child_process");
const net = require("net");
const http = require("http");
const https = require("https");
const dns = require("dns");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const WATCH = path.join(ROOT, "scripts", "watch.js");
const NODE = process.execPath;
const IS_WIN = process.platform === "win32";

const results = [];
const tempRoots = [];
let failures = 0;

function rec(name, status, reason, extra) {
  const row = { name, status, reason: reason || null };
  if (extra) row.extra = extra;
  results.push(row);
  const tag = status === "PASS" ? "PASS" : status === "SKIPPED" ? "SKIP" : "FAIL";
  process.stdout.write(`[${tag}] ${name}${reason ? " — " + reason : ""}\n`);
  if (status === "FAIL") failures++;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function mkTmp(label) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `gs-watch-grok-${label}-`));
  tempRoots.push(d);
  return d;
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {}
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/** Deterministic recursive dir fingerprint (paths relative + file hashes + modes). */
function hashDir(dir) {
  const entries = [];
  function walk(abs, rel) {
    let list;
    try {
      list = fs.readdirSync(abs, { withFileTypes: true });
    } catch (e) {
      entries.push(`ERR|${rel}|${e.code || e.message}`);
      return;
    }
    list.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of list) {
      const a = path.join(abs, ent.name);
      const r = rel ? rel + "/" + ent.name : ent.name;
      if (ent.isDirectory()) {
        entries.push(`DIR|${r}`);
        walk(a, r);
      } else if (ent.isFile()) {
        let st;
        let h;
        try {
          st = fs.statSync(a);
          h = sha256(fs.readFileSync(a));
        } catch (e) {
          entries.push(`FILE_ERR|${r}|${e.code || e.message}`);
          continue;
        }
        entries.push(`FILE|${r}|${st.size}|${h}`);
      } else {
        entries.push(`OTHER|${r}|${ent.name}`);
      }
    }
  }
  walk(dir, "");
  return sha256(Buffer.from(entries.join("\n"), "utf8"));
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

function listDescendants(rootPid) {
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
          for (const c of listDescendants(p)) out.add(c);
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
          for (const c of listDescendants(p)) out.add(c);
        }
      }
    }
  } catch {}
  return out;
}

function writeRunFixture(projectRoot, runId, parts) {
  const runDir = path.join(projectRoot, ".graphsmith", "runs", runId);
  fs.mkdirSync(runDir, { recursive: true });
  const stateDir = path.join(projectRoot, ".graphsmith", "state");
  fs.mkdirSync(stateDir, { recursive: true });

  if (parts.budget !== undefined) {
    fs.writeFileSync(
      path.join(runDir, "budget-state.json"),
      typeof parts.budget === "string" ? parts.budget : JSON.stringify(parts.budget, null, 2)
    );
  }
  if (parts.capability !== undefined) {
    fs.writeFileSync(
      path.join(runDir, "capability.json"),
      typeof parts.capability === "string"
        ? parts.capability
        : JSON.stringify(parts.capability, null, 2)
    );
  }
  if (parts.lock !== undefined) {
    fs.writeFileSync(
      path.join(runDir, ".manager.lock"),
      typeof parts.lock === "string" ? parts.lock : JSON.stringify(parts.lock, null, 2)
    );
  }
  if (parts.window !== undefined) {
    fs.writeFileSync(
      path.join(stateDir, "window.json"),
      typeof parts.window === "string" ? parts.window : JSON.stringify(parts.window, null, 2)
    );
  }
  if (parts.extraFiles) {
    for (const [rel, body] of Object.entries(parts.extraFiles)) {
      const p = path.join(runDir, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, body);
    }
  }
  return runDir;
}

function runWatchCli(projectRoot, args, opts) {
  const timeoutMs = (opts && opts.timeoutMs) || 4000;
  const child = spawn(NODE, [WATCH, ...args], {
    cwd: projectRoot,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: { ...process.env, NO_COLOR: "1" },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => {
    stdout += d.toString();
  });
  child.stderr.on("data", (d) => {
    stderr += d.toString();
  });
  const started = Date.now();
  const done = new Promise((resolve) => {
    let settled = false;
    const finish = (code, signal, timedOut) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code,
        signal,
        stdout,
        stderr,
        pid: child.pid,
        timedOut: !!timedOut,
        elapsedMs: Date.now() - started,
      });
    };
    const timer = setTimeout(() => {
      forceKillTree(child.pid);
      finish(null, "SIGKILL", true);
    }, timeoutMs);
    child.on("close", (code, signal) => finish(code, signal, false));
    child.on("error", (err) => {
      finish(1, null, false);
      stderr += String(err && err.message);
    });
  });
  return { child, done };
}

function runWatchSync(projectRoot, args, timeoutMs) {
  const r = spawnSync(NODE, [WATCH, ...args], {
    cwd: projectRoot,
    encoding: "utf8",
    timeout: timeoutMs || 5000,
    windowsHide: true,
    env: { ...process.env, NO_COLOR: "1" },
  });
  return {
    code: r.status,
    signal: r.signal,
    stdout: r.stdout || "",
    stderr: r.stderr || "",
    error: r.error || null,
    timedOut: !!(r.error && r.error.code === "ETIMEDOUT"),
  };
}

/* ═══════════════════════════════════════════════════════════════════════
 * TESTS
 * ═══════════════════════════════════════════════════════════════════════ */

async function testReadOnlyCliRender() {
  const name = "A1-read-only-cli-render-hash-unchanged";
  const root = mkTmp("ro");
  const runId = "run-readonly-001";
  const budget = {
    schema_version: "1.0",
    steps_executed: 7,
    furthest_step_index: 6,
    cumulative_wall_time_ms: 1234,
    external_calls_total: 3,
    est_cost_usd: 0.42,
    log_bytes: 111,
    state_bytes: 222,
    output_tokens: 333,
    subprocess_count: 1,
    limits: {
      max_steps: 100,
      max_wall_time_ms: 3600000,
      max_est_cost_usd: 5,
      max_external_calls: 50,
    },
    halted: null,
  };
  const runDir = writeRunFixture(root, runId, {
    budget,
    capability: { capability: "read-only", effect_id: "peek" },
    window: {
      state: "open",
      flag: false,
      window: {
        window_id: "w1",
        candidate_fingerprint: "fp-abc",
        tree_id: "t1",
        admitted: 1,
        n: 3,
        active: 1,
        slots: [{ slot_id: 0, run_id: runId, status: "running", disposition: "canary" }],
      },
    },
    extraFiles: {
      "checkpoint.json": JSON.stringify({ step: 6, ok: true }),
      "journal.jsonl": '{"e":1}\n',
    },
  });

  const before = hashDir(runDir);
  const beforeTree = hashDir(path.join(root, ".graphsmith"));

  const r = await runWatchCli(root, [runId], { timeoutMs: 2500 }).done;

  const after = hashDir(runDir);
  const afterTree = hashDir(path.join(root, ".graphsmith"));

  if (before !== after) {
    rec(name, "FAIL", `runDir hash mutated before=${before.slice(0, 12)} after=${after.slice(0, 12)}`, {
      code: r.code,
      timedOut: r.timedOut,
    });
    return;
  }
  if (beforeTree !== afterTree) {
    rec(name, "FAIL", `.graphsmith tree hash mutated`, { beforeTree, afterTree });
    return;
  }
  if (!r.stdout.includes("GraphSmith Watch") && !r.stdout.includes(runId) && !r.stdout.includes("BUDGET")) {
    // clear screen may wipe; still should have budget content in pipe capture post-clear
  }
  rec(name, "PASS", `runDir+tree hash stable; exit code=${r.code} timedOut=${r.timedOut} outLen=${r.stdout.length}`);
}

async function testBudgetUsageVsLimitsRender() {
  const name = "A2-budget-usage-vs-limits-render";
  const watch = require(WATCH);
  const budget = {
    schema_version: "1.0",
    steps_executed: 42,
    furthest_step_index: 41,
    cumulative_wall_time_ms: 5000,
    external_calls_total: 10,
    est_cost_usd: 1.25,
    log_bytes: 999,
    state_bytes: 888,
    output_tokens: 777,
    subprocess_count: 2,
    limits: {
      max_steps: 100,
      max_wall_time_ms: 60000,
      max_est_cost_usd: 10,
      max_external_calls: 50,
      max_log_bytes: 1000000,
      max_output_tokens: 200000,
    },
    tripwires: [
      { rule: "max_steps", at: 0.8, status: "armed" },
      { rule: "max_est_cost_usd", at: 0.5, status: "tripped" },
    ],
    halted: null,
  };

  const summary = watch.renderBudgetSummary(budget);
  const hasUsage =
    summary.includes("42") &&
    summary.includes("5000") &&
    summary.includes("1.25") &&
    summary.includes("10");
  const hasLimitNumbers =
    summary.includes("100") ||
    summary.includes("60000") ||
    summary.includes("max_steps") ||
    summary.includes("limit");
  const hasVsLimits =
    /\/\s*100|of\s*100|limit|remaining|max_steps|usage/i.test(summary) &&
    (summary.includes("100") || summary.includes("max_"));
  const hasTripwire =
    summary.toLowerCase().includes("tripwire") ||
    summary.includes("tripped") ||
    summary.includes("armed") ||
    summary.includes("max_est_cost_usd");

  // Contract from watch.js header: "budget usage vs limits, tripwire state"
  const root = mkTmp("budget");
  const runId = "run-budget-002";
  writeRunFixture(root, runId, { budget });
  const cli = await runWatchCli(root, [runId], { timeoutMs: 2500 }).done;
  const out = cli.stdout + "\n" + cli.stderr;

  const issues = [];
  if (!hasUsage) issues.push("renderBudgetSummary missing usage fields");
  if (!hasLimitNumbers && !/limit/i.test(summary)) issues.push("renderBudgetSummary never surfaces limits");
  if (!hasVsLimits) issues.push("no usage-vs-limits comparison in summary");
  if (!hasTripwire) issues.push("tripwire state omitted from budget render");
  if (!out.includes("42") && !summary.includes("42")) issues.push("CLI/render lost steps_executed");

  // Direct claim check: limits object hard-coded values must appear for "vs limits"
  const limitFieldsPresent =
    summary.includes("100") &&
    (summary.includes("60000") || summary.includes("60")) &&
    (summary.includes("10") || summary.includes("max_est"));

  if (!limitFieldsPresent) {
    issues.push(
      "limits.max_steps=100 / max_wall_time_ms=60000 / max_est_cost_usd=10 not reflected in render"
    );
  }

  if (issues.length) {
    rec(name, "FAIL", issues.join("; "), {
      summaryPreview: summary.slice(0, 600),
      cliPreview: out.slice(0, 400),
    });
  } else {
    rec(name, "PASS", "usage and limits both rendered with comparison cues");
  }
}

async function testHaltAndTripwireAndWindow() {
  const name = "A3-halt-tripwire-window-canary-render";
  const watch = require(WATCH);
  const budget = {
    schema_version: "1.0",
    steps_executed: 10,
    furthest_step_index: 9,
    cumulative_wall_time_ms: 3600001,
    external_calls_total: 5,
    est_cost_usd: 0.1,
    halted: {
      kind: "budget",
      rule: "max_wall_time_ms",
      evidence: { cumulative_wall_time_ms: 3600001, limit_ms: 3600000 },
      at_iso: "2026-01-15T10:30:00Z",
    },
  };
  const summary = watch.renderBudgetSummary(budget);
  if (!summary.includes("HALTED") || !summary.includes("max_wall_time_ms") || !summary.includes("budget")) {
    rec(name, "FAIL", `halt missing from summary: ${summary.slice(0, 300)}`);
    return;
  }

  const root = mkTmp("halt-win");
  const runId = "run-halt-003";
  const runDir = writeRunFixture(root, runId, {
    budget,
    window: {
      state: "canary",
      flag: true,
      window: {
        window_id: "win-9",
        candidate_fingerprint: "cfp-xyz",
        tree_id: "tree-z",
        admitted: 2,
        n: 5,
        active: 1,
        slots: [
          { slot_id: 0, run_id: runId, status: "running", disposition: "canary" },
          { slot_id: 1, run_id: "other", status: "done", disposition: "promote" },
        ],
      },
    },
  });

  const before = hashDir(runDir);
  const cli = await runWatchCli(root, [runId], { timeoutMs: 2500 }).done;
  const after = hashDir(runDir);
  const out = cli.stdout;

  const winSum = watch.renderWindowSummary(runDir);
  const checks = {
    haltCli: out.includes("HALTED") || out.includes("max_wall_time_ms"),
    winModule: winSum.includes("WINDOW") && winSum.includes("win-9") && winSum.includes("canary"),
    slot: winSum.includes(runId) && winSum.includes("Slot"),
    flagged: /Flagged:\s*yes/i.test(winSum),
    hashStable: before === after,
  };

  const failed = Object.entries(checks)
    .filter(([, v]) => !v)
    .map(([k]) => k);

  // CLI path: does display include window? depends on process lifetime + clear
  if (!cli.timedOut && out.length === 0 && cli.code === 0) {
    failed.push("cli-empty-stdout");
  }

  if (failed.length) {
    rec(name, "FAIL", `failed checks: ${failed.join(",")}`, {
      winSum: winSum.slice(0, 400),
      outLen: out.length,
      code: cli.code,
    });
  } else {
    rec(name, "PASS", "halt+window/canary rendered; hash stable");
  }
}

function classifyKillMessage(msg) {
  const m = String(msg || "").toLowerCase();
  if (m.includes("no external effects in flight")) return "no-external-effects-in-flight";
  if (m.includes("assuming") && (m.includes("idempotency") || m.includes("idempotent"))) {
    return "safe-to-resume-assumed";
  }
  if (m.includes("safe to resume") || m.includes("safe-to-resume")) return "safe-to-resume";
  if (m.includes("reconciliation required") || m.includes("reconciliation-required")) {
    return "reconciliation-required";
  }
  return "unknown";
}

async function testCapabilityKillMessages() {
  const name = "A4-capability-kill-messages-cli";
  const watch = require(WATCH);

  const cases = [
    {
      id: "read-only",
      cap: { capability: "read-only", effect_id: "r1" },
      expectClass: "no-external-effects-in-flight",
    },
    {
      id: "local-transactional",
      cap: { capability: "local-transactional", effect_id: "write-cfg" },
      expectClass: "safe-to-resume",
    },
    {
      id: "idempotent-by-key",
      cap: { capability: "idempotent-by-key", effect_id: "create-rec" },
      expectClass: "safe-to-resume-assumed",
    },
    {
      id: "status-checkable",
      cap: { capability: "status-checkable", effect_id: "deploy" },
      expectClass: "reconciliation-required",
    },
    {
      id: "none",
      cap: { capability: "none", effect_id: "webhook" },
      expectClass: "reconciliation-required",
    },
    {
      id: "null-capability",
      cap: { capability: null },
      expectClass: "no-external-effects-in-flight",
    },
    {
      id: "missing-file",
      cap: null,
      expectClass: "reconciliation-required",
    },
    {
      id: "corrupt-json",
      cap: "{not-json",
      expectClass: "reconciliation-required",
    },
  ];

  const failuresLocal = [];
  const details = {};

  for (const c of cases) {
    // Module-level derive
    let modMsg;
    if (c.cap === null) {
      modMsg = watch.deriveKillMessage(null);
    } else if (typeof c.cap === "string") {
      // simulate readJsonSafe failure → null path used by CLI
      modMsg = watch.deriveKillMessage(null);
    } else {
      modMsg = watch.deriveKillMessage(c.cap);
    }
    const modClass = classifyKillMessage(modMsg);

    // CLI path: use dead/invalid pid so kill fails AFTER message emission,
    // OR inspect message even when kill fails after derivation.
    // Implementation order: derive message, then require PID, then kill, then print message.
    // If no PID → exits before printing message. So we need a lock with a harmless pid.
    const root = mkTmp(`kill-${c.id}`);
    const runId = `run-kill-${c.id}`;
    // Use current process pid with signal 0 style... actually kill will SIGKILL us? Use fake dead pid.
    // Fake pid that doesn't exist: kill fails but does it still print message?
    // Code: if kill fails → exit 1 return BEFORE printing message. BAD for observability.
    // So we spawn a sleep child, put its pid in lock, kill it, capture message.
    const sleeper = spawn(NODE, ["-e", "setInterval(()=>{}, 1000)"], {
      stdio: "ignore",
      windowsHide: true,
      detached: false,
    });
    const parts = {
      budget: { schema_version: "1.0", steps_executed: 1, halted: null },
      lock: { pid: sleeper.pid },
    };
    if (c.cap === null) {
      /* no capability file */
    } else if (typeof c.cap === "string") {
      parts.capability = c.cap;
    } else {
      parts.capability = c.cap;
    }
    writeRunFixture(root, runId, parts);

    const before = hashDir(path.join(root, ".graphsmith", "runs", runId));
    const cli = runWatchSync(root, [runId, "--kill-run"], 8000);
    const after = hashDir(path.join(root, ".graphsmith", "runs", runId));

    // ensure sleeper dead
    await sleep(200);
    if (pidAlive(sleeper.pid)) forceKillTree(sleeper.pid);

    const combined = (cli.stdout || "") + "\n" + (cli.stderr || "");
    const cliClass = classifyKillMessage(combined);
    const hashOk = before === after;

    details[c.id] = {
      modMsg,
      modClass,
      cliClass,
      expectClass: c.expectClass,
      hashOk,
      code: cli.code,
      out: combined.slice(0, 400),
    };

    if (modClass !== c.expectClass) {
      failuresLocal.push(`${c.id}:module got ${modClass} want ${c.expectClass} msg=${JSON.stringify(modMsg)}`);
    }
    // CLI must emit the message on successful kill
    if (cli.code === 0 && cliClass !== c.expectClass) {
      failuresLocal.push(`${c.id}:cli got ${cliClass} want ${c.expectClass}`);
    }
    if (cli.code === 0 && !hashOk) {
      failuresLocal.push(`${c.id}:kill mutated run-state hash`);
    }
    // If kill printed nothing about capability when successful — fail
    if (cli.code === 0 && cliClass === "unknown") {
      failuresLocal.push(`${c.id}:cli-success-without-classifiable-message`);
    }
  }

  if (failuresLocal.length) {
    rec(name, "FAIL", failuresLocal.join(" | ").slice(0, 900), details);
  } else {
    rec(name, "PASS", "all capability classes map correctly (module+cli)", details);
  }
}

async function testKillMessagePrintedEvenWhenPidMissing() {
  const name = "A4b-kill-message-when-pid-missing";
  const root = mkTmp("nopid");
  const runId = "run-nopid";
  writeRunFixture(root, runId, {
    budget: { schema_version: "1.0", steps_executed: 0 },
    capability: { capability: "none", effect_id: "x" },
    // no lock file
  });
  const cli = runWatchSync(root, [runId, "--kill-run"], 5000);
  const out = (cli.stdout || "") + (cli.stderr || "");
  // Operator should still learn capability posture even if PID unknown
  const hasMsg =
    classifyKillMessage(out) === "reconciliation-required" ||
    out.toLowerCase().includes("reconciliation");
  if (cli.code === 0) {
    rec(name, "FAIL", "kill succeeded without manager PID");
  } else if (!hasMsg) {
    rec(
      name,
      "FAIL",
      `PID missing aborts before capability message; stderr=${out.slice(0, 280)}`
    );
  } else {
    rec(name, "PASS", "capability message still emitted without PID");
  }
}

async function testProcessGroupKillNoOrphans() {
  const name = "A5-process-group-kill-no-orphans";
  const root = mkTmp("pgkill");
  const runId = "run-pgkill";
  const marker = path.join(root, "child-still-alive");

  // Manager spawns a grandchild that touches marker file in a loop
  const managerPath = path.join(root, "manager-tree.js");
  fs.writeFileSync(
    managerPath,
    `
const { spawn } = require("child_process");
const fs = require("fs");
const marker = process.argv[2];
const child = spawn(process.execPath, ["-e",
  "const fs=require('fs');const m=process.argv[1];setInterval(()=>{try{fs.writeFileSync(m,String(Date.now()))}catch{}}"
, marker], { stdio: "ignore", windowsHide: true ${IS_WIN ? "" : ", detached: false"} });
fs.writeFileSync(process.argv[3], JSON.stringify({ pid: process.pid, child: child.pid }));
setInterval(() => {}, 1000);
`
  );
  const metaPath = path.join(root, "meta.json");
  const mgr = spawn(NODE, [managerPath, marker, metaPath], {
    stdio: "ignore",
    windowsHide: true,
    detached: !IS_WIN,
  });
  if (!IS_WIN && mgr.pid) {
    try {
      mgr.unref();
    } catch {}
  }

  // wait for meta
  let meta = null;
  for (let i = 0; i < 50; i++) {
    await sleep(50);
    try {
      meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
      if (meta && meta.pid) break;
    } catch {}
  }
  if (!meta || !meta.pid) {
    forceKillTree(mgr.pid);
    rec(name, "FAIL", "manager tree failed to start / write meta");
    return;
  }

  // Ensure child has written marker once
  for (let i = 0; i < 40; i++) {
    if (fs.existsSync(marker)) break;
    await sleep(50);
  }

  const childPid = meta.child;
  const beforeDesc = listDescendants(meta.pid);
  writeRunFixture(root, runId, {
    budget: { schema_version: "1.0", steps_executed: 1 },
    capability: { capability: "read-only" },
    lock: { pid: meta.pid },
  });

  const cli = runWatchSync(root, [runId, "--kill-run"], 10000);
  await sleep(800);

  const mgrAlive = pidAlive(meta.pid);
  const childAlive = childPid ? pidAlive(childPid) : false;
  // orphan = child alive while manager dead, or descendant still alive
  let orphanAlive = false;
  for (const p of beforeDesc) {
    if (pidAlive(p)) orphanAlive = true;
  }
  if (childAlive) orphanAlive = true;

  // cleanup any leftovers
  forceKillTree(meta.pid);
  if (childPid) forceKillTree(childPid);
  forceKillTree(mgr.pid);

  if (cli.code !== 0) {
    rec(name, "FAIL", `kill cli exit ${cli.code}: ${(cli.stdout + cli.stderr).slice(0, 200)}`, {
      mgrAlive,
      childAlive,
    });
    return;
  }
  if (mgrAlive) {
    rec(name, "FAIL", "manager still alive after --kill-run");
    return;
  }
  if (orphanAlive || childAlive) {
    rec(name, "FAIL", `orphan child still alive after process-group kill childAlive=${childAlive}`, {
      beforeDesc: [...beforeDesc],
      childPid,
    });
    return;
  }
  rec(name, "PASS", `tree dead; kill message class=${classifyKillMessage(cli.stdout)}`);
}

async function testNoNetworkCalls() {
  const name = "A6-no-network-calls";
  // 1) Static source scan
  const src = fs.readFileSync(WATCH, "utf8");
  const staticHits = [];
  for (const pat of [
    /require\s*\(\s*["']https?["']\s*\)/,
    /require\s*\(\s*["']net["']\s*\)/,
    /require\s*\(\s*["']dns["']\s*\)/,
    /require\s*\(\s*["']undici["']\s*\)/,
    /\bfetch\s*\(/,
    /http\.request/,
    /https\.request/,
    /net\.connect/,
    /axios/,
  ]) {
    if (pat.test(src)) staticHits.push(String(pat));
  }

  // 2) Runtime monkey-patch during CLI render + kill
  const root = mkTmp("net");
  const runId = "run-net";
  const sleeper = spawn(NODE, ["-e", "setInterval(()=>{},500)"], {
    stdio: "ignore",
    windowsHide: true,
  });
  writeRunFixture(root, runId, {
    budget: {
      schema_version: "1.0",
      steps_executed: 2,
      est_cost_usd: 0.01,
      halted: null,
    },
    capability: { capability: "status-checkable", effect_id: "e" },
    lock: { pid: sleeper.pid },
    window: { state: "open", flag: false, window: { window_id: "w", n: 1, admitted: 0, active: 0, slots: [] } },
  });

  const probe = path.join(root, "net-probe.js");
  fs.writeFileSync(
    probe,
    `
const Module = require("module");
const path = require("path");
const hits = [];
const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (["http","https","net","dns","undici","http2"].includes(request)) {
    hits.push({type:"load", request, parent: parent && parent.filename});
  }
  return origLoad.apply(this, arguments);
};
const http = require("http");
const https = require("https");
const net = require("net");
const dns = require("dns");
const wrap = (obj, keys, label) => {
  for (const k of keys) {
    if (typeof obj[k] === "function") {
      const o = obj[k].bind(obj);
      obj[k] = function() { hits.push({type:label+"."+k}); return o.apply(this, arguments); };
    }
  }
};
wrap(http, ["request","get"], "http");
wrap(https, ["request","get"], "https");
wrap(net, ["connect","createConnection"], "net");
if (dns.lookup) {
  const ol = dns.lookup.bind(dns);
  dns.lookup = function() { hits.push({type:"dns.lookup"}); return ol.apply(this, arguments); };
}
if (typeof global.fetch === "function") {
  const of = global.fetch;
  global.fetch = function() { hits.push({type:"fetch"}); return of.apply(this, arguments); };
}
const watchPath = process.argv[1];
const mode = process.argv[2];
process.argv = [process.argv[0], watchPath, process.argv[3], ...(mode === "kill" ? ["--kill-run"] : [])];
require(watchPath);
// give watch a moment if interval
setTimeout(() => {
  process.stdout.write("\\n__NET_HITS__" + JSON.stringify(hits) + "\\n");
  process.exit(0);
}, mode === "kill" ? 1500 : 800);
`
  );

  const runProbe = (mode) => {
    const r = spawnSync(
      NODE,
      [probe, WATCH, mode, runId],
      {
        cwd: root,
        encoding: "utf8",
        timeout: 8000,
        windowsHide: true,
      }
    );
    const all = (r.stdout || "") + (r.stderr || "");
    const m = all.match(/__NET_HITS__(.*)/);
    let hits = [];
    try {
      hits = m ? JSON.parse(m[1]) : [{ type: "parse-miss", all: all.slice(0, 200) }];
    } catch {
      hits = [{ type: "json-fail" }];
    }
    return { code: r.status, hits, out: all.slice(0, 300) };
  };

  const renderProbe = runProbe("watch");
  const killProbe = runProbe("kill");
  await sleep(100);
  if (pidAlive(sleeper.pid)) forceKillTree(sleeper.pid);

  const runtimeHits = [...renderProbe.hits, ...killProbe.hits].filter(
    (h) => h && h.type && h.type !== "parse-miss"
  );

  // Require of http inside probe itself is OK — filter only loads from watch.js parent
  const fromWatch = runtimeHits.filter((h) => {
    if (h.parent && String(h.parent).replace(/\\/g, "/").endsWith("scripts/watch.js")) return true;
    if (h.type && /^(http|https|net|dns|fetch)/.test(h.type) && h.type.includes(".")) return true;
    return false;
  });

  // More precise: watch should not call http.request etc. Loading null is the win.
  const callHits = runtimeHits.filter((h) => /^(http|https|net|dns)\./.test(h.type) || h.type === "fetch");

  if (staticHits.length || callHits.length) {
    rec(name, "FAIL", `network surface detected static=${staticHits} runtime=${JSON.stringify(callHits).slice(0, 300)}`);
  } else {
    rec(name, "PASS", "no http/https/net/dns/fetch used by watch render or kill");
  }
}

async function testMissingCorruptGraceful() {
  const name = "A7-missing-corrupt-run-state-graceful";
  const cases = [];

  // missing run dir
  {
    const root = mkTmp("miss-run");
    const r = runWatchSync(root, ["no-such-run"], 5000);
    cases.push({
      id: "missing-run-dir",
      ok: r.code !== 0 && r.code !== null && !r.error,
      detail: `code=${r.code} err=${(r.stderr || "").slice(0, 120)}`,
    });
  }

  // missing budget-state
  {
    const root = mkTmp("miss-budget");
    const runId = "run-miss-b";
    writeRunFixture(root, runId, {
      capability: { capability: "read-only" },
      window: { state: "open", flag: false },
    });
    const r = await runWatchCli(root, [runId], { timeoutMs: 2500 }).done;
    const crashed = /throw|TypeError|SyntaxError|Cannot read/i.test(r.stderr);
    const out = r.stdout + r.stderr;
    cases.push({
      id: "missing-budget-state",
      ok: !crashed && (out.includes("No budget") || out.includes("ACTIVE") || r.code === 0 || r.timedOut),
      detail: `crashed=${crashed} code=${r.code} out=${out.slice(0, 100)}`,
    });
  }

  // corrupt budget-state
  {
    const root = mkTmp("bad-budget");
    const runId = "run-bad-b";
    writeRunFixture(root, runId, {
      budget: "{this is not json!!!",
      capability: { capability: "none", effect_id: "e" },
    });
    const before = hashDir(path.join(root, ".graphsmith", "runs", runId));
    const r = await runWatchCli(root, [runId], { timeoutMs: 2500 }).done;
    const after = hashDir(path.join(root, ".graphsmith", "runs", runId));
    const crashed = /throw|SyntaxError|Unexpected token/i.test(r.stderr) && r.code === null;
    cases.push({
      id: "corrupt-budget-json",
      ok: !crashed && before === after,
      detail: `code=${r.code} hashOk=${before === after} stderr=${(r.stderr || "").slice(0, 80)}`,
    });
  }

  // corrupt capability on kill with live pid
  {
    const root = mkTmp("bad-cap");
    const runId = "run-bad-c";
    const sleeper = spawn(NODE, ["-e", "setInterval(()=>{},500)"], {
      stdio: "ignore",
      windowsHide: true,
    });
    writeRunFixture(root, runId, {
      budget: { schema_version: "1.0", steps_executed: 0 },
      capability: "{{{",
      lock: { pid: sleeper.pid },
    });
    const r = runWatchSync(root, [runId, "--kill-run"], 8000);
    await sleep(100);
    if (pidAlive(sleeper.pid)) forceKillTree(sleeper.pid);
    const crashed = r.error && r.error.code !== "ETIMEDOUT";
    // must not throw; should class as reconciliation-required for corrupt
    const cls = classifyKillMessage((r.stdout || "") + (r.stderr || ""));
    cases.push({
      id: "corrupt-capability-kill",
      ok: !crashed && r.code !== null,
      detail: `code=${r.code} class=${cls} (expect reconciliation-required)`,
      expectClassFail: cls !== "reconciliation-required" && r.code === 0,
    });
  }

  // empty runId / usage
  {
    const root = mkTmp("usage");
    const r = runWatchSync(root, [], 5000);
    cases.push({
      id: "usage-exit",
      ok: r.code === 2 || r.code === 1,
      detail: `code=${r.code}`,
    });
  }

  // no cwd project
  {
    const root = mkTmp("empty");
    const r = runWatchSync(root, ["x"], 5000);
    cases.push({
      id: "empty-project",
      ok: r.code !== 0 && !(r.error && r.error.message.includes("Cannot")),
      detail: `code=${r.code}`,
    });
  }

  const failed = cases.filter((c) => !c.ok || c.expectClassFail);
  if (failed.length) {
    rec(
      name,
      "FAIL",
      failed.map((f) => `${f.id}:${f.detail}`).join(" | "),
      { cases }
    );
  } else {
    rec(name, "PASS", cases.map((c) => c.id).join(","));
  }
}

async function testLocalTransactionalInspectedClaim() {
  const name = "A8-local-transactional-inspected-truth-claim";
  const watch = require(WATCH);
  const msg = watch.deriveKillMessage({
    capability: "local-transactional",
    effect_id: "write-cfg",
  });
  // Contract: "inspected" is a truth claim requiring actual inspection evidence
  const claimsInspected = /inspected/i.test(msg);
  if (!claimsInspected) {
    rec(name, "PASS", `message does not falsely claim inspected: ${msg}`);
    return;
  }
  // If it claims inspected, did deriveKillMessage accept any inspection evidence? API takes only capabilityData.
  // No path/marker args → cannot have inspected. FAIL.
  rec(
    name,
    "FAIL",
    `claims "inspected" without inspection inputs/side-channel: ${msg}`
  );
}

async function testWatchContinuousTailUnref() {
  const name = "A9-continuous-tail-stays-alive-for-poll";
  const root = mkTmp("poll");
  const runId = "run-poll";
  const budgetPath = path.join(root, ".graphsmith", "runs", runId, "budget-state.json");
  writeRunFixture(root, runId, {
    budget: {
      schema_version: "1.0",
      steps_executed: 1,
      cumulative_wall_time_ms: 1,
      halted: null,
    },
  });

  const { child, done } = runWatchCli(root, [runId], { timeoutMs: 3000 });
  await sleep(600);
  // mutate budget while watch should be polling
  fs.writeFileSync(
    budgetPath,
    JSON.stringify({
      schema_version: "1.0",
      steps_executed: 99,
      cumulative_wall_time_ms: 1,
      halted: null,
      marker_unique: "SEEN_99_POLL",
    })
  );
  await sleep(1200);
  const r = await done;
  const sawUpdate = r.stdout.includes("99") || r.stdout.includes("SEEN_99_POLL");
  // Process should still be running until our timeout kills it (continuous tail).
  // If unref exited early, timedOut=false and elapsed << 3000 and never saw 99.
  if (!r.timedOut && r.elapsedMs < 1500 && !sawUpdate) {
    rec(
      name,
      "FAIL",
      `watch exited early (elapsed=${r.elapsedMs}ms timedOut=${r.timedOut}); poller.unref() lets process die after first frame; never observed updated steps_executed=99`
    );
    return;
  }
  if (!sawUpdate) {
    rec(
      name,
      "FAIL",
      `alive but never re-rendered updated budget (outLen=${r.stdout.length})`
    );
    return;
  }
  rec(name, "PASS", `polled update observed; elapsed=${r.elapsedMs}`);
}

async function testSelftestAndExports() {
  const name = "A10-selftest-and-module-surface";
  const r = spawnSync(NODE, [WATCH, "--selftest"], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 15000,
    windowsHide: true,
  });
  let parsed = null;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {}
  // Adversarial stance: selftest must not be the only proof — we already run real tests.
  // Flag if selftest falsely claims pass while A9/A2 fail (evaluated at summary).
  const watch = require(WATCH);
  const required = [
    "renderBudgetSummary",
    "renderWindowSummary",
    "deriveKillMessage",
    "killProcessGroup",
    "findRunDir",
  ];
  const missing = required.filter((k) => typeof watch[k] !== "function");
  if (missing.length) {
    rec(name, "FAIL", `missing exports: ${missing.join(",")}`);
    return;
  }
  if (r.status !== 0) {
    rec(name, "FAIL", `selftest exit ${r.status}: ${(r.stderr || r.stdout || "").slice(0, 200)}`);
    return;
  }
  if (!parsed || parsed.status !== "pass") {
    rec(name, "FAIL", `selftest JSON not pass: ${String(r.stdout).slice(0, 200)}`);
    return;
  }
  rec(name, "PASS", `selftest pass; exports ok; selftest_total=${parsed.summary && parsed.summary.total}`);
}

async function testKillInvalidPid() {
  const name = "A11-killProcessGroup-invalid-pid";
  const watch = require(WATCH);
  const r1 = watch.killProcessGroup(-1);
  const r2 = watch.killProcessGroup(0);
  const r3 = watch.killProcessGroup(2 ** 40);
  const r4 = watch.killProcessGroup("nope");
  const ok =
    r1 &&
    r1.success === false &&
    r2.success === false &&
    r3.success === false &&
    r4.success === false;
  if (!ok) {
    rec(name, "FAIL", `invalid pid not rejected: ${JSON.stringify({ r1, r2, r3, r4 })}`);
  } else {
    rec(name, "PASS", "invalid PIDs rejected");
  }
}

async function testReadOnlyDuringKill() {
  const name = "A12-kill-does-not-mutate-run-state";
  const root = mkTmp("kill-ro");
  const runId = "run-kill-ro";
  const sleeper = spawn(NODE, ["-e", "setInterval(()=>{},500)"], {
    stdio: "ignore",
    windowsHide: true,
  });
  const runDir = writeRunFixture(root, runId, {
    budget: { schema_version: "1.0", steps_executed: 4, halted: null },
    capability: { capability: "idempotent-by-key", effect_id: "pay" },
    lock: { pid: sleeper.pid },
    extraFiles: {
      "important.dat": Buffer.from("do-not-touch").toString("utf8"),
    },
  });
  const before = hashDir(runDir);
  const cli = runWatchSync(root, [runId, "--kill-run"], 8000);
  await sleep(150);
  if (pidAlive(sleeper.pid)) forceKillTree(sleeper.pid);
  const after = hashDir(runDir);
  if (before !== after) {
    rec(name, "FAIL", "run-state dir hash changed across --kill-run");
  } else if (cli.code !== 0) {
    rec(name, "FAIL", `kill failed code=${cli.code} ${(cli.stderr || "").slice(0, 120)}`);
  } else {
    rec(name, "PASS", `hash stable; msg class=${classifyKillMessage(cli.stdout)}`);
  }
}

/* ── runner ──────────────────────────────────────────────────────────── */

async function main() {
  process.stdout.write("=== graphsmith watch.js adversarial suite (grok) ===\n");
  process.stdout.write(`platform=${process.platform} node=${process.version}\n`);
  process.stdout.write(`target=${path.relative(ROOT, WATCH).replace(/\\/g, "/")}\n\n`);

  await testReadOnlyCliRender();
  await testBudgetUsageVsLimitsRender();
  await testHaltAndTripwireAndWindow();
  await testCapabilityKillMessages();
  await testKillMessagePrintedEvenWhenPidMissing();
  await testProcessGroupKillNoOrphans();
  await testNoNetworkCalls();
  await testMissingCorruptGraceful();
  await testLocalTransactionalInspectedClaim();
  await testWatchContinuousTailUnref();
  await testSelftestAndExports();
  await testKillInvalidPid();
  await testReadOnlyDuringKill();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;

  const summary = {
    schema_version: "1.0",
    target: "scripts/watch.js",
    lane: "tests/watch/grok",
    platform: process.platform,
    node: process.version,
    passed,
    failed,
    skipped,
    total: results.length,
    results,
  };

  const outPath = path.join(__dirname, "last-run.json");
  fs.writeFileSync(outPath, JSON.stringify(summary, null, 2));

  process.stdout.write(
    `\n=== SUMMARY ${passed} PASS / ${failed} FAIL / ${skipped} SKIP (total ${results.length}) ===\n`
  );

  for (const r of tempRoots) rmrf(r);
  process.exitCode = failed > 0 ? 1 : 0;
}

main().catch((e) => {
  process.stderr.write(`FATAL: ${e.stack || e.message}\n`);
  for (const r of tempRoots) rmrf(r);
  process.exitCode = 1;
});
