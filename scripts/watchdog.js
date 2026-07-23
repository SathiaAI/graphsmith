#!/usr/bin/env node
/* GraphSmith watchdog — separate process that kills a blocked-event-loop run.
 *
 * SECURITY-TIER: runs in its OWN event loop so a blocked manager cannot
 * suppress the watchdog's timer. Detects blocked event loops via missed
 * heartbeats, kills the run process-group-aware on a sync-execution budget
 * breach, emits exactly one capability-specific kill message, and proves
 * chaos-grade resume of recorded state after kills.
 *
 * Zero-dep CJS, Node ≥ 18. Monotonic clock only (process.hrtime.bigint)
 * for all timing decisions. JSON stdout / prose stderr. Exit codes:
 *   0 = clean (manager exited normally before budget breach)
 *   1 = internal error
 *   2 = usage error
 *   3 = HALT (watchdog killed the run)
 *
 * Manager↔Watchdog interface (scaffold.js integrates to this):
 *   Spawn: node scripts/watchdog.js --pid <manager_pid> --budget-ms <ms>
 *          --heartbeat-file <path> --capability-file <path> --halt-file <path>
 *   Heartbeat: manager writes an incrementing integer counter (as string) to
 *              heartbeat-file at a regular interval (e.g. every 100ms). The
 *              watchdog polls this file and tracks when the counter last changed.
 *              Provenance format: "<counter>:<nonce>" — the watchdog writes a
 *              nonce to <heartbeat-file>.nonce at startup; the manager reads it
 *              and appends it to each heartbeat write. Heartbeats without the
 *              correct nonce are treated as legacy/untrusted and subject to a
 *              strict max-increment heuristic (defense-in-depth against forgers).
 *   Capability: manager writes JSON to capability-file before each effect:
 *              { "capability": "<variant>", "effect_id": "<id>" }
 *              Variants: "none" | "read-only" | "local-transactional" |
 *                        "idempotent-by-key" | "status-checkable"
 *              When no effect is in flight: { "capability": null }
 *   Halt file: on kill, watchdog writes JSON evidence:
 *              { "halt": true, "pid": <int>, "budget_ms": <int>,
 *                "elapsed_ms": <int>, "last_heartbeat": <int|null>,
 *                "kill_message": "<capability-specific>", "killed_at_mono_ms": <int>,
 *                "inspected": { ... } }
 *   Kill signal: SIGKILL on Unix (process-group via negative pid),
 *                taskkill /T /F on Windows (process tree).
 *
 * D4 — Dead-man's-switch / watchdog liveness signal:
 *   At startup, the watchdog writes a preliminary halt file (dead_man_switch: true)
 *   to the halt-file path. On normal exit (manager exited cleanly), this file is
 *   DELETED. On kill, it is OVERWRITTEN with real halt evidence. If the watchdog
 *   process itself is killed (SIGKILL), the dead-man's-switch file PERSISTS,
 *   allowing the manager (or supervisor) to detect that its guard is dead.
 *   Additionally, the watchdog writes a reverse-heartbeat to
 *   <halt-file>.watchdog-hb at each poll interval, containing:
 *     { "watchdog_pid": <int>, "mono_ms": <int>, "wall_ms": <int> }
 *   The manager can poll this file; if it stops updating (wall_ms stale by
 *   more than 2× the poll interval), the watchdog is dead and the manager
 *   should take defensive action (e.g., self-halt or alert).
 *   Interface: scaffold.js wires the detection at integration time.
 *
 * Orphan marker (<halt-file>.orphan):
 *   When the watchdog detects its manager died WITHOUT a blocked-loop breach
 *   (orphan case), it writes an orphan marker file and deletes the dead-man
 *   halt file. On resume, the presence of the orphan marker indicates the
 *   previous watchdog was orphaned and cleaned up — NOT a real HALT. The
 *   absence of the orphan marker combined with a persistent dead-man halt
 *   file indicates a genuine watchdog crash (D4 guarantee preserved).
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { spawn, execSync } = require("child_process");
const os = require("os");
const crypto = require("crypto");

const MONO_NS = () => Number(process.hrtime.bigint() / 1000000n);
const MAX_LEGACY_INCREMENT = 10;
const MAX_FIRST_COUNTER = 100;
const STALE_THRESHOLD_MS = 30000;
const ORPHAN_POLL_CADENCE_MS = 500;

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true;
      args[key] = val;
    }
  }
  return args;
}

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8").trim();
  } catch {
    return null;
  }
}

function readCapabilityFile(filePath) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return { status: "missing", data: null };
    return { status: "corrupt", data: null };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return { status: "malformed", data: null };
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return { status: "malformed", data: null };
  }
  try {
    const stat = fs.statSync(filePath);
    const age = Date.now() - stat.mtimeMs;
    if (age > STALE_THRESHOLD_MS) {
      return { status: "stale", data };
    }
  } catch {}
  return { status: "ok", data };
}

function deriveKillMessage(capStatus, capData) {
  if (capStatus !== "ok") {
    return `reconciliation required (capability file ${capStatus}; completion unknown, manual verification needed)`;
  }
  if (!capData || !("capability" in capData) || capData.capability === undefined) {
    return "reconciliation required (capability field missing; completion unknown, manual verification needed)";
  }
  const cap = capData.capability;
  const effectId = capData.effect_id || "unknown";
  if (cap === null) {
    return "no external effects in flight";
  }
  if (typeof cap !== "string") {
    return "reconciliation required (capability field invalid; completion unknown, manual verification needed)";
  }
  switch (cap) {
    case "read-only":
      return "no external effects in flight";
    case "local-transactional":
      return `safe to resume (local effect "${effectId}", inspected)`;
    case "idempotent-by-key":
      return `resume will retry with the recorded idempotency key for "${effectId}" — safe ASSUMING the remote honors the declared key (declaration by the adapter author, not verified by GraphSmith)`;
    case "status-checkable":
      return `reconciliation required for "${effectId}" (status-checkable; resume will run the reconciliation state machine)`;
    case "none":
      return `reconciliation required for "${effectId}" (no capability declared; manual verification needed)`;
    default:
      return `reconciliation required for "${effectId}" (unknown capability "${cap}")`;
  }
}

function killProcessGroup(pid) {
  if (process.platform === "win32") {
    try {
      execSync(`taskkill /PID ${pid} /T /F`, { stdio: "ignore", timeout: 5000 });
      return true;
    } catch {
      try { process.kill(pid, "SIGKILL"); return true; } catch { return false; }
    }
  } else {
    try {
      process.kill(-pid, "SIGKILL");
      return true;
    } catch {
      try { process.kill(pid, "SIGKILL"); return true; } catch { return false; }
    }
  }
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function runWatchdog(opts) {
  const { pid, budgetMs, heartbeatFile, capabilityFile, haltFile } = opts;
  const pollIntervalMs = Math.max(20, Math.floor(budgetMs / 10));

  const nonce = crypto.randomBytes(8).toString("hex");
  const nonceFile = heartbeatFile + ".nonce";
  try { fs.writeFileSync(nonceFile, nonce); } catch {}

  const deadManSwitch = {
    halt: true,
    dead_man_switch: true,
    watchdog_pid: process.pid,
    watched_pid: pid,
    budget_ms: budgetMs,
    started_at_mono_ms: MONO_NS(),
    started_at_wall_ms: Date.now(),
    kill_message: "watchdog dead-man switch — if this file persists and the watchdog is not running, the guard died",
  };
  try {
    fs.mkdirSync(path.dirname(haltFile), { recursive: true });
    fs.writeFileSync(haltFile, JSON.stringify(deadManSwitch, null, 2));
  } catch {}

  const watchdogHbFile = haltFile + ".watchdog-hb";
  const orphanFile = haltFile + ".orphan";

  let lastAcceptedCounter = null;
  let lastChangeMonoMs = MONO_NS();
  let lastHeartbeatValue = null;
  let managerExited = false;

  const writeOrphanMarker = () => {
    try {
      fs.writeFileSync(orphanFile, JSON.stringify({
        orphan: true,
        watchdog_pid: process.pid,
        watched_pid: pid,
        reason: "manager_died_without_blocked_loop_breach",
        detected_at_mono_ms: MONO_NS(),
        detected_at_wall_ms: Date.now(),
      }));
    } catch {}
  };

  return new Promise((resolve) => {
    const reverseHb = setInterval(() => {
      try {
        fs.writeFileSync(watchdogHbFile, JSON.stringify({
          watchdog_pid: process.pid,
          mono_ms: MONO_NS(),
          wall_ms: Date.now(),
        }));
      } catch {}
    }, pollIntervalMs);
    reverseHb.unref();

    const cleanupOrphan = () => {
      writeOrphanMarker();
      try { fs.unlinkSync(haltFile); } catch {}
      try { fs.unlinkSync(nonceFile); } catch {}
      try { fs.unlinkSync(watchdogHbFile); } catch {}
    };

    const checkPid = setInterval(() => {
      if (!pidAlive(pid)) {
        managerExited = true;
        clearInterval(checkPid);
        clearInterval(poll);
        clearInterval(reverseHb);
        cleanupOrphan();
        resolve({ halted: false, reason: "manager_exited" });
      }
    }, ORPHAN_POLL_CADENCE_MS);
    checkPid.unref();

    const poll = setInterval(() => {
      if (managerExited) return;

      if (!pidAlive(pid)) {
        managerExited = true;
        clearInterval(poll);
        clearInterval(checkPid);
        clearInterval(reverseHb);
        cleanupOrphan();
        resolve({ halted: false, reason: "manager_exited" });
        return;
      }

      const counterRaw = readFileSafe(heartbeatFile);
      const nowMono = MONO_NS();

      let counter = null;
      let trusted = false;
      if (counterRaw !== null) {
        const colonIdx = counterRaw.indexOf(":");
        let counterStr, nonceStr;
        if (colonIdx >= 0) {
          counterStr = counterRaw.slice(0, colonIdx);
          nonceStr = counterRaw.slice(colonIdx + 1);
        } else {
          counterStr = counterRaw;
          nonceStr = null;
        }
        const parsed = parseInt(counterStr, 10);
        if (!isNaN(parsed)) {
          counter = parsed;
          if (nonceStr !== null && nonceStr === nonce) {
            trusted = true;
          }
        }
      }

      if (counter !== null) {
        if (lastAcceptedCounter === null) {
          if (trusted || counter <= MAX_FIRST_COUNTER) {
            lastAcceptedCounter = counter;
            lastHeartbeatValue = counter;
            lastChangeMonoMs = nowMono;
          }
        } else if (counter > lastAcceptedCounter) {
          const increment = counter - lastAcceptedCounter;
          if (trusted || increment <= MAX_LEGACY_INCREMENT) {
            lastAcceptedCounter = counter;
            lastHeartbeatValue = counter;
            lastChangeMonoMs = nowMono;
          }
        }
      }

      const elapsedMs = nowMono - lastChangeMonoMs;
      if (elapsedMs > budgetMs) {
        clearInterval(poll);
        clearInterval(checkPid);
        clearInterval(reverseHb);

        const capResult = readCapabilityFile(capabilityFile);
        const killMessage = deriveKillMessage(capResult.status, capResult.data);
        const killed = killProcessGroup(pid);

        const haltEvidence = {
          halt: true,
          pid: pid,
          budget_ms: budgetMs,
          elapsed_ms: elapsedMs,
          last_heartbeat: lastHeartbeatValue,
          kill_message: killMessage,
          killed_at_mono_ms: nowMono,
          kill_delivered: killed,
          capability_at_kill: capResult.data ? capResult.data.capability : null,
          effect_id_at_kill: capResult.data ? capResult.data.effect_id : null,
          capability_file_status: capResult.status,
          inspected: {
            what: "capability-file",
            status: capResult.status,
            readable: capResult.status === "ok",
            capability: capResult.data ? (capResult.data.capability !== undefined ? capResult.data.capability : null) : null,
            effect_id: capResult.data ? (capResult.data.effect_id !== undefined ? capResult.data.effect_id : null) : null,
            inspected_at_mono_ms: nowMono,
          },
        };

        try {
          fs.mkdirSync(path.dirname(haltFile), { recursive: true });
          fs.writeFileSync(haltFile, JSON.stringify(haltEvidence, null, 2));
        } catch (e) {
          process.stderr.write(`watchdog: failed to write halt file: ${e.message}\n`);
        }

        try { fs.unlinkSync(nonceFile); } catch {}
        try { fs.unlinkSync(watchdogHbFile); } catch {}
        try { fs.unlinkSync(orphanFile); } catch {}

        process.stdout.write(JSON.stringify(haltEvidence) + "\n");
        resolve({ halted: true, evidence: haltEvidence });
      }
    }, pollIntervalMs);
  });
}

function printUsage() {
  process.stderr.write(
    "Usage: node scripts/watchdog.js --pid <pid> --budget-ms <ms> " +
    "--heartbeat-file <path> --capability-file <path> --halt-file <path>\n" +
    "       node scripts/watchdog.js --selftest\n"
  );
}

async function selftest() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-watchdog-"));
  const results = [];
  let allPassed = true;

  const fail = (name, msg) => {
    results.push({ name, status: "fail", detail: msg });
    allPassed = false;
  };
  const pass = (name, detail) => {
    results.push({ name, status: "pass", detail: detail || null });
  };

  const killScenarios = [
    {
      name: "no-effects-in-flight",
      capability: { capability: null },
      expectedMessage: "no external effects in flight",
      blockAfterBeats: 5,
    },
    {
      name: "local-transactional-safe-resume",
      capability: { capability: "local-transactional", effect_id: "write-config" },
      expectedMessage: "safe to resume",
      blockAfterBeats: 8,
    },
    {
      name: "idempotent-by-key",
      capability: { capability: "idempotent-by-key", effect_id: "create-record" },
      expectedMessage: "resume will retry with the recorded idempotency key",
      blockAfterBeats: 6,
    },
    {
      name: "none-capability-reconciliation",
      capability: { capability: "none", effect_id: "send-webhook" },
      expectedMessage: "reconciliation required",
      blockAfterBeats: 10,
    },
    {
      name: "status-checkable-reconciliation",
      capability: { capability: "status-checkable", effect_id: "deploy-service" },
      expectedMessage: "reconciliation required",
      blockAfterBeats: 7,
    },
  ];

  const BUDGET_MS = 600;
  const HEARTBEAT_INTERVAL_MS = 50;

  for (let si = 0; si < killScenarios.length; si++) {
    const scenario = killScenarios[si];
    const runDir = path.join(tmpDir, `run-${si}`);
    fs.mkdirSync(runDir, { recursive: true });

    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");
    const stateFile = path.join(runDir, "state.json");
    const checkpointsFile = path.join(runDir, "checkpoints.json");

    fs.writeFileSync(stateFile, JSON.stringify({ step: 0, completed: [] }));
    fs.writeFileSync(checkpointsFile, JSON.stringify([]));
    fs.writeFileSync(capabilityFile, JSON.stringify(scenario.capability));

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const path = require("path");
      const heartbeatFile = ${JSON.stringify(heartbeatFile)};
      const capabilityFile = ${JSON.stringify(capabilityFile)};
      const stateFile = ${JSON.stringify(stateFile)};
      const checkpointsFile = ${JSON.stringify(checkpointsFile)};
      const blockAfterBeats = ${scenario.blockAfterBeats};
      let counter = 0;
      const iv = setInterval(() => {
        counter++;
        fs.writeFileSync(heartbeatFile, String(counter));
        if (counter % 3 === 0) {
          const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
          state.step++;
          state.completed.push("step-" + state.step);
          fs.writeFileSync(stateFile, JSON.stringify(state));
          const cps = JSON.parse(fs.readFileSync(checkpointsFile, "utf8"));
          cps.push({ step: state.step, at: Date.now() });
          fs.writeFileSync(checkpointsFile, JSON.stringify(cps));
        }
        if (counter >= blockAfterBeats) {
          clearInterval(iv);
          const cap = JSON.parse(fs.readFileSync(capabilityFile, "utf8"));
          cap.capability = ${JSON.stringify(scenario.capability.capability)};
          cap.effect_id = ${JSON.stringify(scenario.capability.effect_id || null)};
          fs.writeFileSync(capabilityFile, JSON.stringify(cap));
          const buf = Buffer.alloc(1);
          const end = Date.now() + 30000;
          while (Date.now() < end) { /* sync spin — blocks event loop */ }
        }
      }, ${HEARTBEAT_INTERVAL_MS});
    `;

    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    const managerPid = manager.pid;

    await new Promise((r) => setTimeout(r, 100));

    const watchdogResult = await runWatchdog({
      pid: managerPid,
      budgetMs: BUDGET_MS,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-managerPid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!watchdogResult.halted) {
      fail(scenario.name, `watchdog did not halt the run (result: ${JSON.stringify(watchdogResult)})`);
      continue;
    }

    const ev = watchdogResult.evidence;
    if (!ev.kill_delivered) {
      fail(scenario.name, "kill was not delivered");
      continue;
    }

    if (ev.elapsed_ms < BUDGET_MS) {
      fail(scenario.name, `killed too early: elapsed ${ev.elapsed_ms}ms < budget ${BUDGET_MS}ms`);
      continue;
    }

    if (ev.elapsed_ms > BUDGET_MS + 1000) {
      fail(scenario.name, `killed too late: elapsed ${ev.elapsed_ms}ms > budget+1s`);
      continue;
    }

    if (!ev.kill_message.includes(scenario.expectedMessage)) {
      fail(scenario.name, `wrong kill message: "${ev.kill_message}" (expected to contain "${scenario.expectedMessage}")`);
      continue;
    }

    if (!fs.existsSync(haltFile)) {
      fail(scenario.name, "halt file was not written");
      continue;
    }

    const haltData = JSON.parse(fs.readFileSync(haltFile, "utf8"));
    if (!haltData.halt || haltData.pid !== managerPid) {
      fail(scenario.name, "halt file has invalid content");
      continue;
    }

    let state;
    try {
      state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    } catch (e) {
      fail(scenario.name, `state file corrupt after kill: ${e.message}`);
      continue;
    }

    if (!state.completed || !Array.isArray(state.completed)) {
      fail(scenario.name, "state file missing completed array after kill");
      continue;
    }

    const uniqueSteps = new Set(state.completed);
    if (uniqueSteps.size !== state.completed.length) {
      fail(scenario.name, "state has duplicate steps after kill — resume would be broken");
      continue;
    }

    let checkpoints;
    try {
      checkpoints = JSON.parse(fs.readFileSync(checkpointsFile, "utf8"));
    } catch (e) {
      fail(scenario.name, `checkpoints file corrupt after kill: ${e.message}`);
      continue;
    }

    if (checkpoints.length > 0 && state.step > 0) {
      const resumedCompleted = state.completed.slice(0, checkpoints.length);
      const match = resumedCompleted.every((s, i) => s === `step-${i + 1}`);
      if (!match) {
        fail(scenario.name, "recorded state inconsistent after kill — resume would be unreliable");
        continue;
      }
    }

    pass(scenario.name, `killed at ${ev.elapsed_ms}ms (budget ${BUDGET_MS}ms), message="${ev.kill_message}", state: ${state.completed.length} steps, consistent`);
  }

  // D1 selftest: missing capability file → reconciliation required
  {
    const name = "D1-missing-capability-fail-safe";
    const runDir = path.join(tmpDir, "run-d1-missing");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 0;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
        if (c >= 3) {
          clearInterval(iv);
          const end = Date.now() + 30000;
          while (Date.now() < end) {}
        }
      }, 50);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 100));

    const watchdogResult = await runWatchdog({
      pid: manager.pid,
      budgetMs: BUDGET_MS,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!watchdogResult.halted) {
      fail(name, "watchdog did not halt");
    } else if (!watchdogResult.evidence.kill_message.includes("reconciliation required")) {
      fail(name, `expected reconciliation required, got "${watchdogResult.evidence.kill_message}"`);
    } else if (watchdogResult.evidence.kill_message.includes("no external effects")) {
      fail(name, `fail-open: got "${watchdogResult.evidence.kill_message}"`);
    } else if (watchdogResult.evidence.capability_file_status !== "missing") {
      fail(name, `expected status "missing", got "${watchdogResult.evidence.capability_file_status}"`);
    } else {
      pass(name, `msg="${watchdogResult.evidence.kill_message}"`);
    }
  }

  // D1 selftest: corrupt capability file → reconciliation required
  {
    const name = "D1-corrupt-capability-fail-safe";
    const runDir = path.join(tmpDir, "run-d1-corrupt");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");

    fs.writeFileSync(capabilityFile, "{not-valid-json");

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 0;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
        if (c >= 3) {
          clearInterval(iv);
          const end = Date.now() + 30000;
          while (Date.now() < end) {}
        }
      }, 50);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 100));

    const watchdogResult = await runWatchdog({
      pid: manager.pid,
      budgetMs: BUDGET_MS,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!watchdogResult.halted) {
      fail(name, "watchdog did not halt");
    } else if (!watchdogResult.evidence.kill_message.includes("reconciliation required")) {
      fail(name, `expected reconciliation required, got "${watchdogResult.evidence.kill_message}"`);
    } else if (watchdogResult.evidence.capability_file_status !== "malformed") {
      fail(name, `expected status "malformed", got "${watchdogResult.evidence.capability_file_status}"`);
    } else {
      pass(name, `msg="${watchdogResult.evidence.kill_message}"`);
    }
  }

  // D2 selftest: forged heartbeat (external forger) → still kills
  {
    const name = "D2-forged-heartbeat-still-kills";
    const runDir = path.join(tmpDir, "run-d2");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");

    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: "none", effect_id: "forged-test" }));

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 0;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
        if (c >= 3) {
          clearInterval(iv);
          const end = Date.now() + 30000;
          while (Date.now() < end) {}
        }
      }, 40);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const mockForgerScript = `
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
    const mockForgerPath = path.join(runDir, "mock-forger.js");
    fs.writeFileSync(mockForgerPath, mockForgerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 150));

    const forger = spawn(process.execPath, [mockForgerPath], {
      stdio: "ignore",
    });

    const watchdogResult = await runWatchdog({
      pid: manager.pid,
      budgetMs: BUDGET_MS,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    try { manager.kill("SIGKILL"); } catch {}
    try { forger.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!watchdogResult.halted) {
      fail(name, "watchdog did not halt — forged heartbeats starved the kill");
    } else if (!watchdogResult.evidence.kill_delivered) {
      fail(name, "kill was not delivered");
    } else {
      pass(name, `killed at ${watchdogResult.evidence.elapsed_ms}ms despite forged heartbeats`);
    }
  }

  // D3 selftest: local-transactional has inspection evidence
  {
    const name = "D3-inspection-evidence-in-halt";
    const runDir = path.join(tmpDir, "run-d3");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");

    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: "local-transactional", effect_id: "test-effect" }));

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 0;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
        if (c >= 3) {
          clearInterval(iv);
          const end = Date.now() + 30000;
          while (Date.now() < end) {}
        }
      }, 50);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 100));

    const watchdogResult = await runWatchdog({
      pid: manager.pid,
      budgetMs: BUDGET_MS,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!watchdogResult.halted) {
      fail(name, "watchdog did not halt");
    } else {
      const ev = watchdogResult.evidence;
      const hasInspected = Object.prototype.hasOwnProperty.call(ev, "inspected");
      const msgHasInspected = /inspect/i.test(ev.kill_message);
      if (!hasInspected) {
        fail(name, "halt evidence missing 'inspected' field");
      } else if (!msgHasInspected) {
        fail(name, `kill_message doesn't mention inspection: "${ev.kill_message}"`);
      } else if (!ev.inspected.readable) {
        fail(name, `inspected.readable should be true, got ${ev.inspected.readable}`);
      } else {
        pass(name, `inspected field present, readable=true, msg="${ev.kill_message}"`);
      }
    }
  }

  // D4 selftest: dead man's switch file exists at startup
  {
    const name = "D4-dead-mans-switch";
    const runDir = path.join(tmpDir, "run-d4");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");
    const watchdogHbFile = haltFile + ".watchdog-hb";

    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));
    fs.writeFileSync(heartbeatFile, "1");

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 1;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
        if (c >= 3) {
          clearInterval(iv);
          const end = Date.now() + 30000;
          while (Date.now() < end) {}
        }
      }, 50);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 50));

    const watchdogPromise = runWatchdog({
      pid: manager.pid,
      budgetMs: BUDGET_MS,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    await new Promise((r) => setTimeout(r, 150));

    let dmsData = null;
    try { dmsData = JSON.parse(fs.readFileSync(haltFile, "utf8")); } catch {}
    let reverseHbExists = fs.existsSync(watchdogHbFile);

    const watchdogResult = await watchdogPromise;

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!dmsData || !dmsData.dead_man_switch) {
      fail(name, "dead man's switch file not found or invalid at startup");
    } else if (!watchdogResult.halted) {
      fail(name, "watchdog did not halt");
    } else if (watchdogResult.evidence.dead_man_switch) {
      fail(name, "halt evidence still has dead_man_switch flag (should be overwritten)");
    } else if (!reverseHbExists) {
      fail(name, "reverse heartbeat file not found during watchdog run");
    } else {
      pass(name, "dead man's switch written at startup, overwritten by real halt evidence, reverse heartbeat active");
    }
  }

  // Orphan selftest: manager SIGKILLed → detected within short cadence
  {
    const name = "orphan-manager-detected-within-short-cadence";
    const runDir = path.join(tmpDir, "run-orphan-cadence");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");
    const orphanFile = haltFile + ".orphan";

    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 0;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
      }, 50);
      setTimeout(() => {}, 60000);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 150));

    const t0 = MONO_NS();
    const watchdogPromise = runWatchdog({
      pid: manager.pid,
      budgetMs: 30000,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    await new Promise((r) => setTimeout(r, 200));
    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}

    const watchdogResult = await watchdogPromise;
    const detectionMs = MONO_NS() - t0;
    await new Promise((r) => manager.on("close", r));

    if (watchdogResult.halted) {
      fail(name, "watchdog should NOT halt on orphan — manager died externally, no blocked-loop breach");
    } else if (watchdogResult.reason !== "manager_exited") {
      fail(name, `unexpected reason: ${watchdogResult.reason}`);
    } else if (detectionMs > ORPHAN_POLL_CADENCE_MS + 500) {
      fail(name, `orphan detection too slow: ${detectionMs}ms (cadence ${ORPHAN_POLL_CADENCE_MS}ms + 500ms slack)`);
    } else {
      pass(name, `orphan detected in ${detectionMs}ms (cadence ${ORPHAN_POLL_CADENCE_MS}ms)`);
    }
  }

  // Orphan selftest: stale dead-man file not mistaken for real halt on resume
  {
    const name = "orphan-stale-dead-man-not-real-halt";
    const runDir = path.join(tmpDir, "run-orphan-stale");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");
    const orphanFile = haltFile + ".orphan";

    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 0;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
      }, 50);
      setTimeout(() => {}, 60000);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 100));

    const watchdogPromise = runWatchdog({
      pid: manager.pid,
      budgetMs: 30000,
      heartbeatFile,
      capabilityFile,
      haltFile,
    });

    await new Promise((r) => setTimeout(r, 100));

    let deadManExistedDuringRun = false;
    try {
      const d = JSON.parse(fs.readFileSync(haltFile, "utf8"));
      deadManExistedDuringRun = !!d.dead_man_switch;
    } catch {}

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}

    await watchdogPromise;
    await new Promise((r) => manager.on("close", r));

    const haltExistsAfterOrphan = fs.existsSync(haltFile);
    const orphanExistsAfterOrphan = fs.existsSync(orphanFile);

    let orphanData = null;
    if (orphanExistsAfterOrphan) {
      try { orphanData = JSON.parse(fs.readFileSync(orphanFile, "utf8")); } catch {}
    }

    if (!deadManExistedDuringRun) {
      fail(name, "dead-man switch file was not written at startup");
    } else if (haltExistsAfterOrphan) {
      fail(name, "halt file still exists after orphan cleanup — would be mistaken for a real HALT on resume");
    } else if (!orphanExistsAfterOrphan) {
      fail(name, "orphan marker file missing — cannot distinguish orphan from watchdog crash");
    } else if (!orphanData || !orphanData.orphan) {
      fail(name, "orphan marker file has invalid content");
    } else {
      pass(name, "dead-man file cleaned on orphan; orphan marker present for resume disambiguation");
    }
  }

  // Orphan selftest: genuine watchdog crash still detectable (D4 preserved)
  {
    const name = "genuine-crash-dead-man-persists";
    const runDir = path.join(tmpDir, "run-genuine-crash");
    fs.mkdirSync(runDir, { recursive: true });
    const heartbeatFile = path.join(runDir, "heartbeat");
    const capabilityFile = path.join(runDir, "capability.json");
    const haltFile = path.join(runDir, "halt.json");
    const orphanFile = haltFile + ".orphan";

    fs.writeFileSync(capabilityFile, JSON.stringify({ capability: null }));
    fs.writeFileSync(heartbeatFile, "1");

    const mockManagerScript = `
      "use strict";
      const fs = require("fs");
      const hb = ${JSON.stringify(heartbeatFile)};
      let c = 1;
      const iv = setInterval(() => {
        c++;
        fs.writeFileSync(hb, String(c));
      }, 50);
      setTimeout(() => {}, 60000);
    `;
    const mockManagerPath = path.join(runDir, "mock-manager.js");
    fs.writeFileSync(mockManagerPath, mockManagerScript);

    const manager = spawn(process.execPath, [mockManagerPath], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    await new Promise((r) => setTimeout(r, 100));

    const watchdogScript = path.join(__dirname, "watchdog.js");
    const watchdogProc = spawn(process.execPath, [
      watchdogScript,
      "--pid", String(manager.pid),
      "--budget-ms", "30000",
      "--heartbeat-file", heartbeatFile,
      "--capability-file", capabilityFile,
      "--halt-file", haltFile,
    ], { stdio: "ignore", windowsHide: true });

    await new Promise((r) => setTimeout(r, 200));

    let deadManExistedBeforeKill = false;
    try {
      const d = JSON.parse(fs.readFileSync(haltFile, "utf8"));
      deadManExistedBeforeKill = !!d.dead_man_switch;
    } catch {}

    try { process.kill(watchdogProc.pid, "SIGKILL"); } catch {}
    await new Promise((r) => watchdogProc.on("close", r));

    await new Promise((r) => setTimeout(r, 200));

    const haltExistsAfterCrash = fs.existsSync(haltFile);
    const orphanExistsAfterCrash = fs.existsSync(orphanFile);

    let haltData = null;
    if (haltExistsAfterCrash) {
      try { haltData = JSON.parse(fs.readFileSync(haltFile, "utf8")); } catch {}
    }

    try { manager.kill("SIGKILL"); } catch {}
    try { if (process.platform !== "win32") process.kill(-manager.pid, "SIGKILL"); } catch {}
    await new Promise((r) => manager.on("close", r));

    if (!deadManExistedBeforeKill) {
      fail(name, "dead-man switch file was not written before watchdog crash");
    } else if (!haltExistsAfterCrash) {
      fail(name, "dead-man halt file missing after watchdog crash — D4 guarantee broken");
    } else if (!haltData || !haltData.dead_man_switch) {
      fail(name, "dead-man halt file lost dead_man_switch flag after crash");
    } else if (orphanExistsAfterCrash) {
      fail(name, "orphan marker should NOT exist after genuine watchdog crash");
    } else {
      pass(name, "dead-man halt file persists with dead_man_switch=true; no orphan marker — D4 preserved");
    }
  }

  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}

  const output = {
    schema_version: "1.0",
    status: allPassed ? "pass" : "fail",
    tests: results,
    summary: {
      total: results.length,
      passed: results.filter((r) => r.status === "pass").length,
      failed: results.filter((r) => r.status === "fail").length,
    },
  };
  return output;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.selftest) {
    try {
      const result = await selftest();
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      process.exitCode = result.status === "pass" ? 0 : 1;
    } catch (e) {
      process.stderr.write(`watchdog selftest error: ${e.stack || e.message}\n`);
      process.exitCode = 1;
    }
    return;
  }

  const pid = parseInt(args.pid, 10);
  const budgetMs = parseInt(args["budget-ms"], 10);
  const heartbeatFile = args["heartbeat-file"];
  const capabilityFile = args["capability-file"];
  const haltFile = args["halt-file"];

  if (!pid || !budgetMs || !heartbeatFile || !capabilityFile || !haltFile) {
    printUsage();
    process.exitCode = 2;
    return;
  }

  if (!pidAlive(pid)) {
    process.stderr.write(`watchdog: pid ${pid} is not alive\n`);
    process.exitCode = 1;
    return;
  }

  try {
    const result = await runWatchdog({ pid, budgetMs, heartbeatFile, capabilityFile, haltFile });
    if (result.halted) {
      process.exitCode = 3;
    } else {
      process.exitCode = 0;
    }
  } catch (e) {
    process.stderr.write(`watchdog error: ${e.stack || e.message}\n`);
    process.exitCode = 1;
  }
}

main();
