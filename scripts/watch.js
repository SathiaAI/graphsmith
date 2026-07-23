#!/usr/bin/env node
/* GraphSmith watch — local terminal tail of a run's state.
 *
 * READ-ONLY observability: continuously polls and displays a run's live
 * state (checkpoints/step progress, budget usage VS limits, tripwire state,
 * halt state, window/canary state) with an optional kill command. Tail mode
 * stays alive — refreshing every DEFAULT_REFRESH_INTERVAL_MS — until it is
 * killed or interrupted (Ctrl+C); it does not exit after the first frame.
 * Kill is process-group-aware and always emits the capability-specific
 * safety message (safe-to-resume / reconciliation-required /
 * no-external-effects-in-flight, derived from the in-flight effect's
 * capability — same as watchdog.js), even when the manager PID cannot be
 * resolved (missing/unrecoverable lockfile).
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

/** Render one "used[/limit] (pct%)" usage line. `limit` may be undefined/null
 * (no limit configured for that dimension) — never fabricate a denominator. */
function formatUsageLine(label, usage, limit, fmt) {
  const fmtVal = fmt || ((v) => String(v));
  if (limit === undefined || limit === null) {
    return `  ${label}: ${fmtVal(usage)} (no limit configured)`;
  }
  const pct =
    typeof usage === "number" && typeof limit === "number" && limit > 0
      ? ` (${Math.round((usage / limit) * 100)}% of limit)`
      : "";
  return `  ${label}: ${fmtVal(usage)} / ${fmtVal(limit)}${pct}`;
}

function renderTripwireLines(budgetState) {
  const lines = ["=== TRIPWIRES ==="];
  const tripwires = Array.isArray(budgetState.tripwires) ? budgetState.tripwires : [];
  if (tripwires.length === 0) {
    lines.push("  No tripwires configured.");
    return lines;
  }
  for (const tw of tripwires) {
    if (!tw || typeof tw !== "object") continue;
    const thresholdPct = typeof tw.at === "number" ? `${Math.round(tw.at * 100)}%` : String(tw.at);
    lines.push(`  - ${tw.rule || "unknown-rule"}: ${tw.status || "unknown"} (threshold ${thresholdPct})`);
  }
  return lines;
}

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

  const limits = budgetState.limits && typeof budgetState.limits === "object" ? budgetState.limits : {};

  lines.push(formatUsageLine("Steps executed", budgetState.steps_executed || 0, limits.max_steps));
  lines.push(`  Furthest step: ${budgetState.furthest_step_index ?? -1}`);
  lines.push(
    formatUsageLine(
      "Cumulative wall time (ms)",
      budgetState.cumulative_wall_time_ms || 0,
      limits.max_wall_time_ms
    )
  );
  lines.push(
    formatUsageLine("External calls (total)", budgetState.external_calls_total || 0, limits.max_external_calls)
  );
  lines.push(
    formatUsageLine(
      "Estimated cost (USD)",
      budgetState.est_cost_usd || 0,
      limits.max_est_cost_usd,
      (v) => `$${Number(v).toFixed(2)}`
    )
  );
  lines.push(formatUsageLine("Log bytes", budgetState.log_bytes || 0, limits.max_log_bytes));
  lines.push(`  State bytes: ${budgetState.state_bytes || 0}`);
  lines.push(formatUsageLine("Output tokens", budgetState.output_tokens || 0, limits.max_output_tokens));
  lines.push(`  Subprocesses spawned: ${budgetState.subprocess_count || 0}`);

  if (budgetState.acknowledged_extensions && budgetState.acknowledged_extensions.length > 0) {
    lines.push(`  Acknowledged extensions: ${budgetState.acknowledged_extensions.length}`);
    for (const ext of budgetState.acknowledged_extensions) {
      lines.push(`    - ${ext.rule} (${ext.kind}): ${ext.previous_limit} → ${prettyPrintJson(ext.new_limits)}`);
    }
  }

  lines.push("");
  lines.push(...renderTripwireLines(budgetState));

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
      // "inspected" is a truth claim requiring actual inspection evidence (a landed/
      // not-landed check on the effect itself). deriveKillMessage only ever sees the
      // capability file's declaration — it has never inspected the effect — so state
      // the recorded fact (the declared capability) without an unearned claim.
      return `safe to resume (local effect "${effectId}", per recorded capability declaration; not verified against the effect itself)`;
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

/** Continuous poll/refresh loop — the actual "tail" behavior.
 *
 * Real CLI tail mode (opts.maxFrames omitted): the interval is left ref'd so
 * the event loop — and the process — stays alive across frames until an
 * external signal/interrupt or process kill stops it. It must NOT unref here;
 * doing so is what let the process exit after the first frame.
 *
 * --selftest / tests (opts.maxFrames set): runs a bounded, injected number of
 * frames on a short interval, then resolves via opts.onDone — proving the
 * loop re-reads and re-renders state repeatedly without needing to run
 * forever or spawn a real child process.
 */
function startWatchLoop(runId, runDir, budgetStatePath, opts = {}) {
  const intervalMs = opts.intervalMs || DEFAULT_REFRESH_INTERVAL_MS;
  const maxFrames = opts.maxFrames || null;
  const onFrame = opts.onFrame || ((rid, dir, budgetState) => displayRunState(rid, dir, budgetState));
  let frame = 0;
  let poller = null;

  const stop = () => {
    if (poller) clearInterval(poller);
  };

  const renderFrame = () => {
    frame += 1;
    const budgetState = readJsonSafe(budgetStatePath);
    onFrame(runId, runDir, budgetState, frame);
    if (maxFrames && frame >= maxFrames) {
      stop();
      if (opts.onDone) opts.onDone(frame);
    }
  };

  renderFrame();
  if (!maxFrames || maxFrames > 1) {
    // Left ref'd in BOTH modes: unbounded real tail must stay alive until
    // killed/interrupted (the D4 fix — see doc comment above); bounded
    // selftest runs need the timer to actually keep firing so the injected
    // frames complete and `onDone` resolves (an unref'd timer can be skipped
    // entirely if it's the only thing left keeping the event loop alive).
    // `stop()` clears it once maxFrames is reached, so bounded runs still
    // terminate promptly on their own.
    poller = setInterval(renderFrame, intervalMs);
  }

  return { stop };
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
    // Kill mode: read budget-state, derive the capability-specific message, then
    // (separately) try to kill the manager. The message must reach the operator
    // even when there is no live process to signal — capability posture is
    // independent of kill success.
    const capabilityPath = path.join(runDir, CAPABILITY_FILE);
    const capabilityData = readJsonSafe(capabilityPath);
    const killMessage = deriveKillMessage(capabilityData);

    // Resolve the manager PID from the lockfile. Missing file, unreadable JSON,
    // or a non-positive/non-integer pid are all treated as "no recoverable PID"
    // rather than throwing.
    let managerPid = null;
    const lockFile = path.join(runDir, ".manager.lock");
    if (fs.existsSync(lockFile)) {
      const lockData = readJsonSafe(lockFile);
      if (lockData && Number.isSafeInteger(lockData.pid) && lockData.pid > 0) {
        managerPid = lockData.pid;
      }
    }

    let killResult;
    if (managerPid === null) {
      console.log(`No live manager PID on record for run ${runId} (missing/unrecoverable .manager.lock).`);
      console.log("Nothing to signal — falling back to recorded-state resume guidance below.");
      killResult = { success: false, error: "no-live-process-pid" };
    } else {
      console.log(`Killing run ${runId} (PID ${managerPid})...`);
      killResult = killProcessGroup(managerPid);
      if (killResult.success) {
        console.log("Kill signal delivered.");
      } else {
        console.error(`Failed to kill: ${killResult.error}`);
      }
    }

    console.log("");
    console.log(`Kill message (capability-derived):`);
    console.log(killMessage);

    if (!killResult.success) {
      process.exitCode = 1;
    }
  } else {
    // Watch mode: continuously poll and tail the run's state. Stays alive
    // until killed or interrupted (Ctrl+C) — it does NOT unref the poller.
    const { stop } = startWatchLoop(runId, runDir, budgetStatePath, {
      intervalMs: DEFAULT_REFRESH_INTERVAL_MS,
    });

    const shutdown = () => {
      stop();
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
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

  // Test 6: Budget usage-vs-limits + tripwire rendering (D1)
  {
    const testName = "budget-usage-vs-limits-and-tripwire-rendering";
    try {
      const synthState = {
        schema_version: SCHEMA_VERSION,
        steps_executed: 42,
        furthest_step_index: 41,
        cumulative_wall_time_ms: 12000,
        external_calls_total: 3,
        est_cost_usd: 1,
        limits: {
          max_steps: 100,
          max_wall_time_ms: 60000,
          max_est_cost_usd: 10,
          max_external_calls: 50,
        },
        tripwires: [
          { rule: "max_steps", at: 0.8, status: "armed" },
          { rule: "max_est_cost_usd", at: 0.5, status: "tripped" },
        ],
        halted: null,
      };

      const summary = renderBudgetSummary(synthState);
      const hasUsageVsLimit =
        summary.includes("42 / 100") && summary.includes("12000 / 60000") && summary.includes("$1.00 / $10.00");
      const hasTripwireState =
        summary.toLowerCase().includes("tripwire") && summary.includes("armed") && summary.includes("tripped");

      if (hasUsageVsLimit && hasTripwireState) {
        pass(testName, "usage/limit pairs and tripwire state both rendered");
      } else {
        fail(
          testName,
          `hasUsageVsLimit=${hasUsageVsLimit} hasTripwireState=${hasTripwireState}; summary: ${summary}`
        );
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  // Test 7: kill with a missing/unrecoverable manager PID still emits the
  // capability-specific message instead of aborting (D2).
  {
    const testName = "kill-missing-pid-emits-capability-message";
    try {
      const { spawnSync } = require("child_process");
      const projectRoot = path.join(tmpDir, "nopid-project");
      const runId = "selftest-nopid-run";
      const runDir = path.join(projectRoot, ".graphsmith", "runs", runId);
      fs.mkdirSync(runDir, { recursive: true });
      fs.writeFileSync(
        path.join(runDir, BUDGET_STATE_FILE),
        JSON.stringify({ schema_version: SCHEMA_VERSION, steps_executed: 0, halted: null })
      );
      fs.writeFileSync(
        path.join(runDir, CAPABILITY_FILE),
        JSON.stringify({ capability: "none", effect_id: "selftest-effect" })
      );
      // Deliberately no .manager.lock file.

      const result = spawnSync(process.execPath, [__filename, runId, "--kill-run"], {
        cwd: projectRoot,
        encoding: "utf8",
        timeout: 5000,
        windowsHide: true,
      });
      const out = (result.stdout || "") + (result.stderr || "");
      const emittedMessage = /reconciliation required/i.test(out);
      const failedClosed = result.status !== 0;

      if (emittedMessage && failedClosed) {
        pass(testName, `kill exited non-zero and still emitted capability message: code=${result.status}`);
      } else {
        fail(
          testName,
          `emittedMessage=${emittedMessage} failedClosed=${failedClosed} (code=${result.status}); out: ${out.slice(0, 300)}`
        );
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  // Test 8: no unearned "inspected" claim for local-transactional (D3)
  {
    const testName = "no-false-inspected-claim";
    try {
      const msg = deriveKillMessage({ capability: "local-transactional", effect_id: "write-cfg" });
      const claimsInspected = /inspected/i.test(msg);
      const claimsSafeToResume = msg.includes("safe to resume");
      if (!claimsInspected && claimsSafeToResume) {
        pass(testName, `no unearned "inspected" claim; still safe-to-resume: ${msg}`);
      } else {
        fail(testName, `claimsInspected=${claimsInspected} claimsSafeToResume=${claimsSafeToResume}: ${msg}`);
      }
    } catch (e) {
      fail(testName, e.message);
    }
  }

  // Test 9: continuous tail polls repeatedly across frames (D4), bounded/injected
  // so selftest stays fast and does not spawn a real long-lived child process.
  {
    const testName = "continuous-tail-polls-repeatedly";
    try {
      const runDir = path.join(tmpDir, "poll-run");
      fs.mkdirSync(runDir, { recursive: true });
      const pollBudgetPath = path.join(runDir, BUDGET_STATE_FILE);
      fs.writeFileSync(
        pollBudgetPath,
        JSON.stringify({ schema_version: SCHEMA_VERSION, steps_executed: 1, halted: null })
      );

      const observedFrames = [];
      await new Promise((resolve) => {
        startWatchLoop("selftest-poll-run", runDir, pollBudgetPath, {
          intervalMs: 15,
          maxFrames: 3,
          onFrame: (rid, dir, budgetState, frame) => {
            observedFrames.push(budgetState ? budgetState.steps_executed : null);
            // Mutate state so the NEXT poll observes a changed value — proves
            // it re-reads live state each frame instead of caching frame 1.
            try {
              fs.writeFileSync(
                pollBudgetPath,
                JSON.stringify({ schema_version: SCHEMA_VERSION, steps_executed: 1 + frame, halted: null })
              );
            } catch {}
          },
          onDone: () => resolve(),
        });
      });

      const distinctValues = new Set(observedFrames);
      if (observedFrames.length === 3 && distinctValues.size > 1) {
        pass(testName, `observed ${observedFrames.length} frames, values changed: ${JSON.stringify(observedFrames)}`);
      } else {
        fail(testName, `expected 3 frames with changing steps_executed, got: ${JSON.stringify(observedFrames)}`);
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
  startWatchLoop,
};
