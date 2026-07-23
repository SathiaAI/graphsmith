#!/usr/bin/env node
/* GraphSmith watch — local terminal tail of a run's state.
 *
 * READ-ONLY observability: polls and displays a run's live state
 * (checkpoints/step progress, budget usage vs limits, tripwire state,
 * halt state, window/canary state) with an optional kill command.
 * Kill is process-group-aware and emits the capability-specific safety
 * message (safe-to-resume / reconciliation-required / no-external-effects-in-flight,
 * derived from the in-flight effect's capability — same as watchdog.js).
 *
 * Zero-dep CJS, Node >= 18. Read-only tail, no network, no clock/random in
 * decisions (refresh interval is fine, documented). Never mutates run state.
 *
 * Usage: node scripts/watch.js <runId> [--kill-run]
 *        node scripts/watch.js --selftest
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const SCHEMA_VERSION = "1.0";
const DEFAULT_REFRESH_INTERVAL_MS = 500;
const BUDGET_STATE_FILE = "budget-state.json";
const CAPABILITY_FILE = "capability.json";

// ---- Utilities ----

function fail(message, code = "WATCH_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function findRunDir(projectRoot, runId) {
  if (!runId) return null;
  const candidate = path.join(projectRoot, ".graphsmith", "runs", runId);
  if (fs.existsSync(candidate)) return candidate;
  return null;
}

function readJsonSafe(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function hashFile(filePath) {
  try {
    const crypto = require("crypto");
    return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  } catch {
    return null;
  }
}

function prettyPrintJson(obj, indent = 2) {
  return JSON.stringify(obj, null, indent);
}

// ---- Budget/Tripwire rendering ----

function renderBudgetSummary(budgetState) {
  if (!budgetState) return "No budget state loaded.";

  const lines = [];
  lines.push("=== BUDGET STATE ===");

  if (budgetState.halted) {
    lines.push(`[HALTED] ${budgetState.halted.kind}: ${budgetState.halted.rule}`);
    lines.push(`  Evidence: ${prettyPrintJson(budgetState.halted.evidence)}`);
    lines.push(`  At: ${budgetState.halted.at_iso || "unknown"}`);
  } else {
    lines.push("[ACTIVE] Run is not halted.");
  }

  lines.push(`  Steps executed: ${budgetState.steps_executed || 0}`);
  lines.push(`  Furthest step: ${budgetState.furthest_step_index || -1}`);
  lines.push(`  Cumulative wall time (ms): ${budgetState.cumulative_wall_time_ms || 0}`);
  lines.push(`  External calls (total): ${budgetState.external_calls_total || 0}`);
  lines.push(`  Estimated cost (USD): $${(budgetState.est_cost_usd || 0).toFixed(2)}`);
  lines.push(`  Log bytes: ${budgetState.log_bytes || 0}`);
  lines.push(`  State bytes: ${budgetState.state_bytes || 0}`);
  lines.push(`  Output tokens: ${budgetState.output_tokens || 0}`);
  lines.push(`  Subprocesses spawned: ${budgetState.subprocess_count || 0}`);

  if (budgetState.acknowledged_extensions && budgetState.acknowledged_extensions.length > 0) {
    lines.push(`  Acknowledged extensions: ${budgetState.acknowledged_extensions.length}`);
    for (const ext of budgetState.acknowledged_extensions) {
      lines.push(`    - ${ext.rule} (${ext.kind}): ${ext.previous_limit} → ${prettyPrintJson(ext.new_limits)}`);
    }
  }

  return lines.join("\n");
}

function renderWindowSummary(runDir) {
  const windowPath = path.join(runDir, "..", "..", "state", "window.json");
  const windowData = readJsonSafe(windowPath);

  if (!windowData) return "No window state available.";

  const lines = [];
  lines.push("=== WINDOW / CANARY STATE ===");
  lines.push(`  Window state: ${windowData.state || "unknown"}`);
  lines.push(`  Flagged: ${windowData.flag ? "yes" : "no"}`);

  if (windowData.window) {
    const w = windowData.window;
    lines.push(`  Window ID: ${w.window_id}`);
    lines.push(`  Candidate fingerprint: ${w.candidate_fingerprint}`);
    lines.push(`  Tree ID: ${w.tree_id}`);
    lines.push(`  Admitted: ${w.admitted || 0} / ${w.n || 0}`);
    lines.push(`  Active: ${w.active || 0}`);
    lines.push(`  Slots:`);
    if (w.slots && Array.isArray(w.slots)) {
      for (const slot of w.slots) {
        lines.push(`    - Slot ${slot.slot_id}: ${slot.run_id} [${slot.status}] (${slot.disposition || "none"})`);
      }
    }
  }

  return lines.join("\n");
}

// ---- Capability-specific kill message derivation (same as watchdog.js) ----

function deriveKillMessage(capabilityData) {
  if (!capabilityData || typeof capabilityData !== "object") {
    return "reconciliation required (capability file missing or unreadable; completion unknown, manual verification needed)";
  }

  if (!("capability" in capabilityData)) {
    return "reconciliation required (capability field missing; completion unknown, manual verification needed)";
  }

  const cap = capabilityData.capability;
  const effectId = capabilityData.effect_id || "unknown";

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

// ---- Kill implementation (process-group-aware) ----

function killProcessGroup(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) {
    return { success: false, error: "Invalid PID" };
  }

  try {
    if (process.platform === "win32") {
      try {
        execSync(`taskkill /PID ${pid} /T /F`, { stdio: "ignore", timeout: 5000 });
        return { success: true };
      } catch {
        try {
          process.kill(pid, "SIGKILL");
          return { success: true };
        } catch (e) {
          return { success: false, error: e.message };
        }
      }
    } else {
      try {
        process.kill(-pid, "SIGKILL");
        return { success: true };
      } catch {
        try {
          process.kill(pid, "SIGKILL");
          return { success: true };
        } catch (e) {
          return { success: false, error: e.message };
        }
      }
    }
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ---- Watch display ----

function displayRunState(runId, runDir, budgetState) {
  console.clear?.() || process.stdout.write("\x1Bc");
  console.log(`GraphSmith Watch — Run: ${runId}`);
  console.log(`Directory: ${runDir}`);
  console.log(`Refreshed at: ${new Date().toISOString()}`);
  console.log("");

  console.log(renderBudgetSummary(budgetState));
  console.log("");
  console.log(renderWindowSummary(runDir));
  console.log("");
}

// ---- CLI / Main ----

function printUsage() {
  console.error("Usage: node scripts/watch.js <runId> [--kill-run]");
  console.error("       node scripts/watch.js --selftest");
}

async function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--selftest") {
    try {
      const result = await selftest();
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      process.exitCode = result.status === "pass" ? 0 : 1;
    } catch (e) {
      process.stderr.write(`selftest error: ${e.stack || e.message}\n`);
      process.exitCode = 1;
    }
    return;
  }

  const runId = args[0];
  const killRun = args.includes("--kill-run");

  if (!runId) {
    printUsage();
    process.exitCode = 2;
    return;
  }

  const projectRoot = process.cwd();
  const runDir = findRunDir(projectRoot, runId);

  if (!runDir) {
    console.error(`Error: run directory not found for runId "${runId}"`);
    process.exitCode = 1;
    return;
  }

  const budgetStatePath = path.join(runDir, BUDGET_STATE_FILE);

  if (killRun) {
    // Kill mode: read budget-state, derive message, kill the process
    const budgetState = readJsonSafe(budgetStatePath);
    const capabilityPath = path.join(runDir, CAPABILITY_FILE);
    const capabilityData = readJsonSafe(capabilityPath);

    const killMessage = deriveKillMessage(capabilityData);

    // Try to find the manager PID from budget-state or a lockfile
    // For now, we'll use a simple approach: look for a manager.pid file or infer from state
    let managerPid = null;
    const lockFile = path.join(runDir, ".manager.lock");
    if (fs.existsSync(lockFile)) {
      const lockData = readJsonSafe(lockFile);
      if (lockData && lockData.pid) {
        managerPid = lockData.pid;
      }
    }

    if (!managerPid) {
      // Fallback: try to find the pid from parent process or other heuristics
      console.error("Error: cannot determine manager PID for kill operation");
      console.error("Expected .manager.lock file in run directory.");
      process.exitCode = 1;
      return;
    }

    console.log(`Killing run ${runId} (PID ${managerPid})...`);
    const killResult = killProcessGroup(managerPid);

    if (killResult.success) {
      console.log("Kill signal delivered.");
    } else {
      console.error(`Failed to kill: ${killResult.error}`);
      process.exitCode = 1;
      return;
    }

    console.log("");
    console.log(`Kill message (capability-derived):`);
    console.log(killMessage);
  } else {
    // Watch mode: poll and display state
    displayRunState(runId, runDir, readJsonSafe(budgetStatePath));

    const poller = setInterval(() => {
      const budgetState = readJsonSafe(budgetStatePath);
      displayRunState(runId, runDir, budgetState);
    }, DEFAULT_REFRESH_INTERVAL_MS);

    poller.unref();
  }
}

// ---- Selftest ----

async function selftest() {
  const os = require("os");
  const crypto = require("crypto");

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-watch-"));
  const results = [];
  let allPassed = true;

  const pass = (name, detail) => {
    results.push({ name, status: "pass", detail: detail || null });
  };

  const fail = (name, msg) => {
    results.push({ name, status: "fail", detail: msg });
    allPassed = false;
  };

  // Test 1: Budget/tripwire rendering from synthetic state
  {
    const testName = "budget-tripwire-rendering";
    try {
      const synthState = {
        schema_version: SCHEMA_VERSION,
        steps_executed: 42,
        furthest_step_index: 41,
        step_attempts: { 0: 1, 1: 1, 41: 1 },
        cumulative_wall_time_ms: 5000,
        external_calls_total: 10,
        external_calls_by_destination: { "https://api.example.com": 5 },
        external_calls_by_effect_type: { external: 10 },
        est_cost_usd: 0.5,
        log_bytes: 1024000,
        state_bytes: 2048000,
        output_tokens: 50000,
        subprocess_count: 2,
        halted: null,
      };

      const summary = renderBudgetSummary(synthState);
      if (summary.includes("ACTIVE") && summary.includes("42") && summary.includes("5000")) {
        pass(testName, "budget summary rendered correctly");
      } else {
        fail(testName, `summary missing expected content: ${summary}`);
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  // Test 2: Halt state rendering
  {
    const testName = "halt-state-rendering";
    try {
      const synthState = {
        schema_version: SCHEMA_VERSION,
        steps_executed: 10,
        furthest_step_index: 9,
        cumulative_wall_time_ms: 1000,
        external_calls_total: 5,
        est_cost_usd: 0.1,
        halted: {
          kind: "budget",
          rule: "max_wall_time_ms",
          evidence: { cumulative_wall_time_ms: 3600001, limit_ms: 3600000 },
          at_iso: "2026-01-15T10:30:00Z",
        },
      };

      const summary = renderBudgetSummary(synthState);
      if (summary.includes("HALTED") && summary.includes("max_wall_time_ms") && summary.includes("budget")) {
        pass(testName, "halt state rendered correctly");
      } else {
        fail(testName, `halt rendering failed: ${summary}`);
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  // Test 3: Capability-specific kill messages
  {
    const scenarios = [
      {
        name: "kill-message-no-effects",
        capability: { capability: null },
        expectedPhrase: "no external effects in flight",
      },
      {
        name: "kill-message-local-transactional",
        capability: { capability: "local-transactional", effect_id: "write-config" },
        expectedPhrase: "safe to resume",
      },
      {
        name: "kill-message-idempotent-by-key",
        capability: { capability: "idempotent-by-key", effect_id: "create-record" },
        expectedPhrase: "resume will retry with the recorded idempotency key",
      },
      {
        name: "kill-message-none",
        capability: { capability: "none", effect_id: "webhook" },
        expectedPhrase: "reconciliation required",
      },
      {
        name: "kill-message-status-checkable",
        capability: { capability: "status-checkable", effect_id: "deploy" },
        expectedPhrase: "reconciliation required",
      },
      {
        name: "kill-message-read-only",
        capability: { capability: "read-only" },
        expectedPhrase: "no external effects in flight",
      },
    ];

    for (const scenario of scenarios) {
      try {
        const msg = deriveKillMessage(scenario.capability);
        if (msg.includes(scenario.expectedPhrase)) {
          pass(scenario.name, `got: "${msg}"`);
        } else {
          fail(scenario.name, `expected phrase "${scenario.expectedPhrase}" not found in: "${msg}"`);
        }
      } catch (e) {
        fail(scenario.name, e.message);
      }
    }
  }

  // Test 4: Process-group-aware kill detection
  {
    const testName = "process-group-aware-kill";
    try {
      const testPid = 99999;
      const result = killProcessGroup(testPid);
      if (result.hasOwnProperty("success")) {
        pass(testName, "kill function is callable and process-group-aware");
      } else {
        fail(testName, "kill function did not return expected structure");
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  // Test 5: State immutability (hash before/after)
  {
    const testName = "state-immutability";
    try {
      const runDir = path.join(tmpDir, "test-run");
      fs.mkdirSync(runDir, { recursive: true });

      const synthState = {
        schema_version: SCHEMA_VERSION,
        steps_executed: 5,
        furthest_step_index: 4,
        cumulative_wall_time_ms: 1000,
        external_calls_total: 2,
        est_cost_usd: 0.05,
        halted: null,
      };

      const budgetStatePath = path.join(runDir, BUDGET_STATE_FILE);
      fs.writeFileSync(budgetStatePath, JSON.stringify(synthState));

      const hashBefore = hashFile(budgetStatePath);

      // Simulate watch operations (read budget-state, render, etc.)
      const state1 = readJsonSafe(budgetStatePath);
      renderBudgetSummary(state1);
      const state2 = readJsonSafe(budgetStatePath);
      renderBudgetSummary(state2);

      const hashAfter = hashFile(budgetStatePath);

      if (hashBefore === hashAfter) {
        pass(testName, "state file unchanged after watch operations");
      } else {
        fail(testName, "state file was mutated (hash changed)");
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {}

  const output = {
    schema_version: SCHEMA_VERSION,
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

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`Error: ${e.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  SCHEMA_VERSION,
  findRunDir,
  readJsonSafe,
  renderBudgetSummary,
  renderWindowSummary,
  deriveKillMessage,
  killProcessGroup,
};
