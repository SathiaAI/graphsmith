#!/usr/bin/env node
/* GraphSmith chaos harness — proves crash recovery is real.
 * Works on any project following scaffold conventions:
 *   .runs/<runId>/<step>.json checkpoints + effects.log appended per execution.
 * Usage: node chaos.js <project-dir> */
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const dir = path.resolve(process.argv[2] || ".");
const managerPath = path.join(dir, "manager.js");
if (!fs.existsSync(managerPath)) { console.error(`No manager.js in ${dir}`); process.exit(1); }

const runId = "chaos-" + Date.now();
const runDir = path.join(dir, ".runs", runId);
const fail = (msg) => { console.error("❌ FAIL: " + msg); process.exit(1); };
const pass = (msg) => console.log("✅ " + msg);

function startManager() {
  return spawn(process.execPath, ["manager.js", runId], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
}
const checkpoints = () =>
  fs.existsSync(runDir) ? fs.readdirSync(runDir).filter((f) => f.endsWith(".json")) : [];

(async () => {
  // --- Run 1: kill after the first checkpoint appears -----------------------
  const p1 = startManager();
  const killed = await new Promise((resolve) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (checkpoints().length >= 1) { clearInterval(iv); p1.kill("SIGKILL"); resolve(true); }
      else if (Date.now() - t0 > 15000) { clearInterval(iv); p1.kill("SIGKILL"); resolve(false); }
    }, 25);
  });
  if (!killed) fail("No checkpoint appeared within 15s — are save points implemented?");
  const survivedSteps = checkpoints();
  pass(`Killed run mid-flight after ${survivedSteps.length} checkpoint(s): ${survivedSteps.join(", ")}`);

  // --- Run 2: restart, must resume and complete -----------------------------
  const p2 = startManager();
  let out2 = "";
  p2.stdout.on("data", (d) => (out2 += d));
  const code = await new Promise((r) => p2.on("close", r));
  if (code !== 0) fail("Restarted run did not complete (exit " + code + ")");
  if (!out2.includes("__done__")) fail("Restarted run finished without completion marker");

  // KILL TEST: pre-crash steps must have been skipped, not re-executed
  for (const c of survivedSteps) {
    const step = c.replace(/\.json$/, "");
    if (!out2.includes(`"step":"${step}","status":"skipped`))
      fail(`Step ${step} was re-executed after restart — resume is broken`);
  }
  pass("Kill test: restart resumed from save points (no finished work redone)");

  // DOUBLE-RUN TEST: each step's side effects exactly once across both runs
  const effectsPath = path.join(runDir, "effects.log");
  if (!fs.existsSync(effectsPath)) fail("No effects.log — workers must record executions");
  const counts = {};
  for (const line of fs.readFileSync(effectsPath, "utf8").split("\n").filter(Boolean))
    counts[line] = (counts[line] || 0) + 1;
  const dupes = Object.entries(counts).filter(([, n]) => n > 1);
  if (dupes.length) fail("Side effects executed more than once: " + dupes.map(([s, n]) => `${s}×${n}`).join(", ") +
    " — a step interrupted after its side effect but before its checkpoint re-executes on resume. Guard side effects with check-before-write keyed by runId+step (see worker stubs).");
  pass("Double-run test: every step's side effects executed exactly once");

  console.log("\n🏁 Chaos harness: ALL CHECKS PASSED for " + runId);
})();
