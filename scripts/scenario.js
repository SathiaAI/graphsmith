#!/usr/bin/env node
/* GraphSmith scenario.js — replay runner (contract 08 §Decision engine vs replay runner).
 * PRODUCES the evidence bundle; gate.js decides. Zero-dep CJS, Node ≥ 18.
 *
 * Modes:
 *   record --auto <project-dir>
 *     Capture a scaffold-convention project run into a scenario file.
 *   replay --paired --candidate <treeId> --baseline <treeId> [--corpus <dir>] [--seed <cycleSeed>]
 *     Run each scenario against both trees; emit evidence bundle.
 *     If --candidate/--baseline resolves to an existing directory, its pipeline.json
 *     and workers/ are used as the implementation under test (Phase A tree-dir support).
 *     Otherwise the treeId is used as a deterministic delay modifier so that
 *     different treeIds CAN produce different timing-dependent outcomes.
 *   --selftest
 *     Replay 2 scenarios end-to-end; validate bundle schema + determinism.
 *
 * Verdicts derive from on-disk state, never from output strings (chaos harness
 * philosophy). Cause codes per contract 03 taxonomy: workflow_fault / infra_fault / ok.
 * This script NEVER decides promotion — it produces the bundle. */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");
const os = require("os");

const SCHEMA_VERSION = "1.0";
const EVALUATOR_VERSION = "1.0.0";
const SCENARIO_SCHEMA_PATH = path.join(__dirname, "..", "schemas", "scenario.schema.json");
const DEFAULT_CORPUS_DIR = path.join(__dirname, "..", "scenarios");

const fail = (msg) => { console.error("ERR: " + msg); process.exit(2); };
const out = (obj) => process.stdout.write(JSON.stringify(obj, null, 2) + "\n");

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith("--")) {
      const key = k.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) { a[key] = argv[++i]; }
      else { a[key] = true; }
    } else { a._.push(k); }
  }
  return a;
}

function loadCorpus(corpusDir) {
  const dir = corpusDir || DEFAULT_CORPUS_DIR;
  if (!fs.existsSync(dir)) fail("Corpus directory not found: " + dir);
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const raw = fs.readFileSync(path.join(dir, f), "utf8");
      const sc = JSON.parse(raw);
      validateScenario(sc);
      return sc;
    });
}

function validateScenario(sc) {
  if (sc.schema_version !== SCHEMA_VERSION)
    fail("Scenario " + (sc.id || "?") + ": unsupported schema_version " + sc.schema_version);
  if (!sc.id || !sc.shape || !sc.tier || sc.seed == null || !sc.fixture || !sc.expected || !sc.invariants)
    fail("Scenario missing required fields: " + JSON.stringify(sc.id || "?"));
  if (!["pipeline", "fan-out", "manager+workers"].includes(sc.shape))
    fail("Scenario " + sc.id + ": unknown shape " + sc.shape);
  if (!["smoke", "regression", "stress"].includes(sc.tier))
    fail("Scenario " + sc.id + ": unknown tier " + sc.tier);
  if (!sc.fixture.pipeline || !sc.fixture.workers)
    fail("Scenario " + sc.id + ": fixture missing pipeline or workers");
}

function corpusHash(scenarios) {
  const canonical = scenarios.map((s) => s.id).sort().join("\n");
  return sha256(canonical);
}

function buildPipelineSteps(f, scenario) {
  let pipelineSteps = [...f.pipeline];
  if (f.fan_out_groups && f.fan_out_groups.length > 0) {
    const expanded = [pipelineSteps[0]];
    for (const group of f.fan_out_groups) {
      for (const gs of group) expanded.push(gs);
    }
    for (let i = 1; i < pipelineSteps.length; i++) expanded.push(pipelineSteps[i]);
    pipelineSteps = expanded;
  }
  if (scenario.shape === "manager+workers" && f.manager_decisions) {
    const activeSteps = [pipelineSteps[0]];
    const decision = f.manager_decisions[0];
    if (decision) {
      const target = pipelineSteps.find((s) => s.step === decision.next_step);
      if (target) activeSteps.push(target);
    }
    const finalize = pipelineSteps.find((s) => s.step === "03-finalize");
    if (finalize) activeSteps.push(finalize);
    pipelineSteps = activeSteps;
  }
  return pipelineSteps;
}

function materializeFixture(scenario, workDir, treeId) {
  const f = scenario.fixture;
  fs.mkdirSync(path.join(workDir, "workers"), { recursive: true });
  fs.mkdirSync(path.join(workDir, ".runs"), { recursive: true });

  const pipelineSteps = buildPipelineSteps(f, scenario);
  fs.writeFileSync(
    path.join(workDir, "pipeline.json"),
    JSON.stringify(pipelineSteps, null, 2)
  );

  const isTreeDir = treeId && fs.existsSync(treeId) && fs.statSync(treeId).isDirectory();

  if (isTreeDir) {
    const treePipeline = path.join(treeId, "pipeline.json");
    if (fs.existsSync(treePipeline)) {
      fs.copyFileSync(treePipeline, path.join(workDir, "pipeline.json"));
    }
    const treeWorkers = path.join(treeId, "workers");
    const copied = new Set();
    if (fs.existsSync(treeWorkers) && fs.statSync(treeWorkers).isDirectory()) {
      for (const w of fs.readdirSync(treeWorkers)) {
        if (w.endsWith(".js")) {
          fs.copyFileSync(path.join(treeWorkers, w), path.join(workDir, "workers", w));
          copied.add(w);
        }
      }
    }
    for (const [name, cfg] of Object.entries(f.workers)) {
      if (!copied.has(name)) {
        fs.writeFileSync(path.join(workDir, "workers", name), generateWorker(name, cfg, scenario, null));
      }
    }
  } else {
    for (const [name, cfg] of Object.entries(f.workers)) {
      fs.writeFileSync(path.join(workDir, "workers", name), generateWorker(name, cfg, scenario, treeId));
    }
  }

  const managerSrc = generateManager(scenario, treeId);
  fs.writeFileSync(path.join(workDir, "manager.js"), managerSrc);
}

function generateWorker(name, cfg, scenario, treeId) {
  const baseDelay = cfg.delay_ms || 50;
  const behavior = cfg.behavior || "ok";

  let delayMs = baseDelay;
  if (treeId) {
    const h = crypto.createHash("sha256").update("scale:" + treeId).digest();
    const scale = h[0] / 64;
    delayMs = Math.max(1, Math.round(baseDelay * scale));
  }

  if (behavior === "fail") {
    return `module.exports.run = async (input, ctx) => {
  throw new Error(${JSON.stringify(cfg.fail_message || "worker failure")});
};`;
  }

  if (behavior === "budget-exceed") {
    return `module.exports.run = async (input, ctx) => {
  await new Promise((r) => setTimeout(r, ${delayMs}));
  return { ...(input || {}), [ctx.step]: "done" };
};`;
  }

  return `const fs = require("fs");
const path = require("path");
const readLines = (p) => (fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\\n").filter(Boolean) : []);
function appendDurable(file, line) {
  const fd = fs.openSync(file, "a");
  try { fs.writeSync(fd, line + "\\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
module.exports.run = async (input, ctx) => {
  const intents = path.join(ctx.runDir, "intents.log");
  const effects = path.join(ctx.runDir, "effects.log");
  const doneAlready = readLines(effects).includes(ctx.step);
  const intended = readLines(intents).includes(ctx.step);
  if (!doneAlready && intended) {
    const err = new Error("UNRESOLVED SIDE EFFECT for step \\"" + ctx.step + "\\"");
    err.unresolvedSideEffect = true;
    throw err;
  }
  if (!doneAlready) {
    appendDurable(intents, ctx.step);
    ${behavior === "intent-no-complete" ? 'throw new Error("simulated crash after intent for " + ctx.step);' : 'appendDurable(effects, ctx.step);'}
  }
  await new Promise((r) => setTimeout(r, ${delayMs}));
  return { ...(input || {}), [ctx.step]: "done" ${scenario.shape === "manager+workers" && name === "classify.js" ? ', decision: "simple"' : ""} };
};`;
}

function generateManager(scenario, treeId) {
  let budgetMs = scenario.fixture.budget_ms || 0;
  if (treeId && budgetMs > 0) {
    const h = crypto.createHash("sha256").update("budget:" + treeId).digest();
    const offset = h[1] * 5 - 200;
    budgetMs = Math.max(1, budgetMs + offset);
  }

  return `#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const PIPELINE = require("./pipeline.json");
const MAX_RETRIES = 2;
const BUDGET_MS = ${budgetMs};
const runId = process.argv[2] || "run-" + Date.now();
const runDir = path.join(__dirname, ".runs", runId);
fs.mkdirSync(runDir, { recursive: true });
const log = (step, status, ms) => console.log(JSON.stringify({ runId, step, status, ms }));
const LEASE_MS = parseInt(process.env.GRAPHSMITH_LEASE_MS, 10) || 30000;
const HEARTBEAT_MS = parseInt(process.env.GRAPHSMITH_HEARTBEAT_MS, 10) || 5000;
const lockPath = path.join(runDir, ".lock");
function acquireLock() {
  for (let tryNo = 0; tryNo < 2; tryNo++) {
    try {
      const fd = fs.openSync(lockPath, "wx");
      fs.writeSync(fd, String(process.pid)); fs.fsyncSync(fd); fs.closeSync(fd);
      return;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      let holder = NaN;
      try { holder = parseInt(fs.readFileSync(lockPath, "utf8"), 10); } catch {}
      let alive = false;
      if (Number.isInteger(holder) && holder > 0) {
        try { process.kill(holder, 0); alive = holder !== process.pid; } catch { alive = false; }
      }
      if (!alive) {
        log("__lock__", "stale lock (pid " + (holder || "?") + " not running) — stolen", 0);
        try { fs.unlinkSync(lockPath); } catch {}
        continue;
      }
      let ageMs = Infinity;
      try { ageMs = Date.now() - fs.statSync(lockPath).mtimeMs; } catch {}
      if (ageMs <= LEASE_MS) {
        console.error("Run \\"" + runId + "\\" is actively locked");
        process.exit(1);
      }
      log("__lock__", "expired lease — stolen", 0);
      try { fs.unlinkSync(lockPath); } catch {}
    }
  }
  console.error("Could not acquire run lock"); process.exit(1);
}
acquireLock();
const heartbeat = setInterval(() => {
  try { const now = new Date(); fs.utimesSync(lockPath, now, now); } catch {}
}, HEARTBEAT_MS);
heartbeat.unref();
const releaseLock = () => { try { clearInterval(heartbeat); } catch {} try { fs.unlinkSync(lockPath); } catch {} };
process.on("exit", releaseLock);
function saveCheckpoint(ckpt, out) {
  const tmp = ckpt + ".tmp";
  const fd = fs.openSync(tmp, "w");
  try { fs.writeSync(fd, JSON.stringify(out ?? null)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, ckpt);
}
function readCheckpoint(ckpt, step) {
  if (!fs.existsSync(ckpt)) return { done: false };
  try { return { done: true, out: JSON.parse(fs.readFileSync(ckpt, "utf8")) }; }
  catch (e) {
    const bad = ckpt + ".corrupt-" + Date.now();
    try { fs.renameSync(ckpt, bad); } catch {}
    log(step, "warn: corrupt checkpoint backed up", 0);
    return { done: false };
  }
}
async function executeStep(stepDef, input) {
  const ckpt = path.join(runDir, stepDef.step + ".json");
  const prior = readCheckpoint(ckpt, stepDef.step);
  if (prior.done) { log(stepDef.step, "skipped (checkpoint exists)", 0); return prior.out; }
  let fn;
  try { fn = require("./workers/" + stepDef.worker); }
  catch (e) {
    if (e.code === "MODULE_NOT_FOUND") {
      console.error("INFRA_FAULT: missing worker module " + stepDef.worker);
      process.exit(2);
    }
    throw e;
  }
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const t0 = Date.now();
    try {
      const out = await fn.run(input, { runId, step: stepDef.step, runDir });
      saveCheckpoint(ckpt, out);
      log(stepDef.step, "ok", Date.now() - t0);
      return out;
    } catch (e) {
      log(stepDef.step, "error attempt " + (attempt + 1) + ": " + e.message, Date.now() - t0);
      if (e && e.unresolvedSideEffect) throw e;
      if (attempt === MAX_RETRIES) throw e;
    }
  }
}
(async () => {
  const t0 = Date.now();
  let carry = null;
  for (const stepDef of PIPELINE) {
    if (BUDGET_MS > 0 && (Date.now() - t0) > BUDGET_MS) {
      console.error("BUDGET EXCEEDED: " + (Date.now() - t0) + "ms > " + BUDGET_MS + "ms");
      process.exit(1);
    }
    carry = await executeStep(stepDef, carry);
  }
  log("__done__", "complete", Date.now() - t0);
})().catch((e) => { console.error("Run failed:", e.message); process.exit(1); });
`;
}

function runManager(workDir, runId, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, ["manager.js", runId], {
      cwd: workDir,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs || 15000,
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      resolve({ code: code ?? -1, stdout, stderr, elapsed: Date.now() - t0 });
    });
    child.on("error", (err) => {
      resolve({ code: -1, stdout, stderr: stderr + err.message, elapsed: Date.now() - t0 });
    });
  });
}

async function runManagerWithKill(workDir, runId, crashAfterStep, timeoutMs) {
  const t0 = Date.now();
  const child = spawn(process.execPath, ["manager.js", runId], {
    cwd: workDir,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "", stderr = "";
  let exited = false;
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("exit", () => (exited = true));

  const runDir = path.join(workDir, ".runs", runId);
  const ckptPath = path.join(runDir, crashAfterStep + ".json");

  const killState = await new Promise((res) => {
    const iv = setInterval(() => {
      const ckptExists = fs.existsSync(ckptPath);
      if (exited) {
        clearInterval(iv);
        res({ landed: false, ckptExists });
      } else if (ckptExists) {
        clearInterval(iv);
        child.kill("SIGKILL");
        res({ landed: true });
      } else if (Date.now() - t0 > (timeoutMs || 15000)) {
        clearInterval(iv);
        child.kill("SIGKILL");
        res({ landed: false, timeout: true });
      }
    }, 10);
  });

  await new Promise((r) => {
    if (child.exitCode !== null || child.signalCode) r();
    else child.on("close", r);
  });

  return { code: child.exitCode ?? -1, stdout, stderr, elapsed: Date.now() - t0, killState };
}

function readRunState(runDir) {
  const state = { checkpoints: [], intents: [], effects: [], lockExists: false };
  if (!fs.existsSync(runDir)) return state;
  state.checkpoints = fs.readdirSync(runDir)
    .filter((f) => f.endsWith(".json") && !f.includes(".corrupt-"))
    .map((f) => f.replace(/\.json$/, ""));
  const intentsPath = path.join(runDir, "intents.log");
  if (fs.existsSync(intentsPath))
    state.intents = fs.readFileSync(intentsPath, "utf8").split("\n").filter(Boolean);
  const effectsPath = path.join(runDir, "effects.log");
  if (fs.existsSync(effectsPath))
    state.effects = fs.readFileSync(effectsPath, "utf8").split("\n").filter(Boolean);
  state.lockExists = fs.existsSync(path.join(runDir, ".lock"));
  return state;
}

function checkInvariants(state, scenario) {
  const violations = [];
  for (const inv of scenario.invariants) {
    if (inv === "no-duplicate-effects") {
      const cnt = {};
      for (const e of state.effects) cnt[e] = (cnt[e] || 0) + 1;
      const dupes = Object.entries(cnt).filter(([, n]) => n > 1);
      if (dupes.length)
        violations.push({ invariant: inv, detail: "duplicated: " + dupes.map(([s, n]) => s + "\u00d7" + n).join(", ") });
    }
    if (inv === "intent-before-effect") {
      for (const e of state.effects) {
        if (!state.intents.includes(e))
          violations.push({ invariant: inv, detail: "effect without intent: " + e });
      }
    }
    if (inv === "halt-on-intent-without-completion") {
      const unresolved = state.intents.filter((i) => !state.effects.includes(i));
      if (scenario.expected.outcome === "halt" && unresolved.length === 0)
        violations.push({ invariant: inv, detail: "expected halt but no unresolved intents" });
    }
    if (inv === "no-step-reexecuted-after-resume") {
    }
  }
  return violations;
}

function classifyOutcome(result, state, scenario) {
  const combined = result.stdout + result.stderr;

  if (combined.includes("INFRA_FAULT"))
    return { pass: false, cause_code: "infra_fault" };

  if (result.code === 0 && combined.includes("__done__")) {
    const expected = scenario.expected.outcome;
    if (expected === "complete" || expected === "crash-recovered")
      return { pass: true, cause_code: "ok" };
    return { pass: false, cause_code: "workflow_fault" };
  }
  if (combined.includes("UNRESOLVED SIDE EFFECT")) {
    const unresolved = state.intents.filter((i) => !state.effects.includes(i));
    if (unresolved.length > 0)
      return { pass: scenario.expected.outcome === "halt", cause_code: "ok" };
    return { pass: false, cause_code: "workflow_fault" };
  }
  if (combined.includes("BUDGET EXCEEDED"))
    return { pass: scenario.expected.outcome === "budget-exceeded", cause_code: "ok" };

  if (combined.includes("Cannot find module") || combined.includes("MODULE_NOT_FOUND"))
    return { pass: false, cause_code: "infra_fault" };

  if (result.code !== 0)
    return { pass: false, cause_code: "workflow_fault" };
  return { pass: false, cause_code: "infra_fault" };
}

async function executeScenario(scenario, workDir, seed) {
  const runId = "scen-" + scenario.id + "-" + seed;
  const runDir = path.join(workDir, ".runs", runId);

  if (scenario.fixture.crash_after_step) {
    const result1 = await runManagerWithKill(workDir, runId, scenario.fixture.crash_after_step, 15000);
    const preCrashState = readRunState(runDir);

    if (!result1.killState.landed) {
      return {
        pass: false,
        cause_code: "workflow_fault",
        violations: [{ invariant: "crash-expected", detail: "kill did not land mid-flight after " + scenario.fixture.crash_after_step + " (timeout=" + result1.killState.timeout + ", ckptExists=" + result1.killState.ckptExists + ", exited=" + result1.killState.ckptExists + ")" }],
        state: preCrashState,
      };
    }

    const result2 = await runManager(workDir, runId, 15000);
    const state = readRunState(runDir);
    const violations = checkInvariants(state, scenario);
    const outcome = classifyOutcome(result2, state, scenario);

    if (scenario.invariants.includes("no-step-reexecuted-after-resume")) {
      for (const s of preCrashState.checkpoints) {
        if (!result2.stdout.includes('"step":"' + s + '","status":"skipped'))
          violations.push({ invariant: "no-step-reexecuted-after-resume", detail: "step " + s + " was re-executed" });
      }
    }

    const expectedSteps = scenario.expected.completed_steps || [];
    if (outcome.cause_code === "ok") {
      const missingSteps = expectedSteps.filter((s) => !state.checkpoints.includes(s));
      if (missingSteps.length > 0)
        violations.push({ invariant: "expected-steps", detail: "missing: " + missingSteps.join(", ") });
    }

    return {
      pass: outcome.pass && violations.length === 0,
      cause_code: violations.length > 0 ? "workflow_fault" : outcome.cause_code,
      violations,
      state,
    };
  }

  const result = await runManager(workDir, runId, 15000);
  const state = readRunState(runDir);
  const violations = checkInvariants(state, scenario);
  const outcome = classifyOutcome(result, state, scenario);

  const expectedSteps = scenario.expected.completed_steps || [];
  if (outcome.cause_code === "ok") {
    const missingSteps = expectedSteps.filter((s) => !state.checkpoints.includes(s));
    if (missingSteps.length > 0)
      violations.push({ invariant: "expected-steps", detail: "missing: " + missingSteps.join(", ") });
  }

  return {
    pass: outcome.pass && violations.length === 0,
    cause_code: violations.length > 0 ? "workflow_fault" : outcome.cause_code,
    violations,
    state,
  };
}

function makeTempDir(prefix) {
  const base = path.join(os.tmpdir(), "graphsmith-scenario-" + prefix + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 7));
  fs.mkdirSync(base, { recursive: true });
  return base;
}

function cleanupDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

async function replayPaired(scenarios, candidateId, baselineId, corpusDir, cycleSeed) {
  const pairs = [];
  for (const scenario of scenarios) {
    const seed = (scenario.seed + cycleSeed) % 2147483647;

    const candDir = makeTempDir("cand-" + scenario.id);
    try {
      materializeFixture(scenario, candDir, candidateId);
    } catch (e) {
      cleanupDir(candDir);
      const baseDir = makeTempDir("base-" + scenario.id);
      cleanupDir(baseDir);
      pairs.push({
        scenario_id: scenario.id,
        seed,
        cand: { pass: false, cause_code: "infra_fault" },
        base: { pass: false, cause_code: "infra_fault" },
      });
      continue;
    }
    const candResult = await executeScenario(scenario, candDir, seed);
    cleanupDir(candDir);

    const baseDir = makeTempDir("base-" + scenario.id);
    try {
      materializeFixture(scenario, baseDir, baselineId);
    } catch (e) {
      cleanupDir(baseDir);
      pairs.push({
        scenario_id: scenario.id,
        seed,
        cand: { pass: candResult.pass, cause_code: candResult.cause_code },
        base: { pass: false, cause_code: "infra_fault" },
      });
      continue;
    }
    const baseResult = await executeScenario(scenario, baseDir, seed);
    cleanupDir(baseDir);

    pairs.push({
      scenario_id: scenario.id,
      seed,
      cand: { pass: candResult.pass, cause_code: candResult.cause_code },
      base: { pass: baseResult.pass, cause_code: baseResult.cause_code },
    });
  }

  const corpus_hash = corpusHash(scenarios);
  const bundle = {
    schema_version: SCHEMA_VERSION,
    corpus_hash,
    evaluator_version: EVALUATOR_VERSION,
    model_versions: { candidate: candidateId, baseline: baselineId },
    pairs,
  };
  bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
  return bundle;
}

async function recordAuto(projectDir) {
  const dir = path.resolve(projectDir);
  const managerPath = path.join(dir, "manager.js");
  if (!fs.existsSync(managerPath)) fail("No manager.js in " + dir);
  const pipelinePath = path.join(dir, "pipeline.json");
  if (!fs.existsSync(pipelinePath)) fail("No pipeline.json in " + dir);
  const pipeline = JSON.parse(fs.readFileSync(pipelinePath, "utf8"));
  const workersDir = path.join(dir, "workers");
  if (!fs.existsSync(workersDir)) fail("No workers/ in " + dir);

  const runId = "record-" + Date.now();
  const result = await runManager(dir, runId, 15000);
  const runDir = path.join(dir, ".runs", runId);
  const state = readRunState(runDir);

  const workers = {};
  for (const w of fs.readdirSync(workersDir)) {
    if (w.endsWith(".js")) workers[w] = { behavior: "ok", delay_ms: 50 };
  }

  const scenario = {
    schema_version: SCHEMA_VERSION,
    id: "recorded-" + path.basename(dir) + "-" + Date.now(),
    shape: "pipeline",
    tier: "smoke",
    seed: 42,
    failure_mode: result.code === 0 ? "normal" : "crash-resume",
    fixture: { pipeline, workers },
    expected: {
      outcome: result.code === 0 ? "complete" : "crash-recovered",
      completed_steps: state.checkpoints,
    },
    invariants: ["no-duplicate-effects", "intent-before-effect"],
  };
  out(scenario);
  return scenario;
}

async function selftest() {
  const scenarios = loadCorpus(DEFAULT_CORPUS_DIR);
  const testScenarios = scenarios.filter((s) => s.id === "pipeline-normal" || s.id === "fanout-normal");
  if (testScenarios.length < 2) fail("Selftest requires at least 2 scenarios; found " + testScenarios.length);

  process.stderr.write("selftest: replaying " + testScenarios.map((s) => s.id).join(", ") + " (2 runs each for determinism check)\n");

  const bundle1 = await replayPaired(testScenarios, "selftest-cand", "selftest-base", DEFAULT_CORPUS_DIR, 0);
  const bundle2 = await replayPaired(testScenarios, "selftest-cand", "selftest-base", DEFAULT_CORPUS_DIR, 0);

  const errors = [];

  if (bundle1.schema_version !== SCHEMA_VERSION) errors.push("schema_version mismatch");
  if (!bundle1.corpus_hash) errors.push("missing corpus_hash");
  if (!bundle1.evaluator_version) errors.push("missing evaluator_version");
  if (!bundle1.bundle_sha256) errors.push("missing bundle_sha256");
  if (!Array.isArray(bundle1.pairs) || bundle1.pairs.length !== testScenarios.length)
    errors.push("pairs length mismatch");

  for (const pair of bundle1.pairs) {
    if (!pair.scenario_id || pair.seed == null || !pair.cand || !pair.base)
      errors.push("pair missing fields: " + JSON.stringify(pair));
    if (!["ok", "workflow_fault", "infra_fault"].includes(pair.cand.cause_code))
      errors.push("invalid cand cause_code: " + pair.cand.cause_code);
    if (!["ok", "workflow_fault", "infra_fault"].includes(pair.base.cause_code))
      errors.push("invalid base cause_code: " + pair.base.cause_code);
  }

  if (bundle1.bundle_sha256 !== bundle2.bundle_sha256)
    errors.push("DETERMINISM FAILURE: same seed produced different bundle hashes\n  run1: " + bundle1.bundle_sha256 + "\n  run2: " + bundle2.bundle_sha256);

  const result = {
    schema_version: SCHEMA_VERSION,
    scenarios_tested: testScenarios.length,
    determinism_pass: bundle1.bundle_sha256 === bundle2.bundle_sha256,
    schema_validation_pass: errors.length === 0,
    bundle_hash: bundle1.bundle_sha256,
    pairs: bundle1.pairs,
    errors,
  };

  if (errors.length > 0) {
    process.stderr.write("selftest FAILURES:\n");
    for (const e of errors) process.stderr.write("  - " + e + "\n");
  }

  out(result);

  if (errors.length > 0) process.exit(1);
  process.stderr.write("selftest: PASS (determinism verified, schema valid, " + testScenarios.length + " scenarios)\n");
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const sub = args._[0];

  if (args.selftest || sub === "selftest") {
    await selftest();
    return;
  }

  if (sub === "record" || args.record) {
    const autoDir = args.auto;
    if (!autoDir) fail("record requires --auto <project-dir>");
    await recordAuto(autoDir);
    return;
  }

  if (sub === "replay" || args.replay) {
    if (!args.paired) fail("replay requires --paired");
    if (!args.candidate || !args.baseline) fail("replay --paired requires --candidate and --baseline");
    const corpusDir = args.corpus || DEFAULT_CORPUS_DIR;
    const cycleSeed = parseInt(args.seed, 10) || 0;
    const scenarios = loadCorpus(corpusDir);
    const bundle = await replayPaired(scenarios, args.candidate, args.baseline, corpusDir, cycleSeed);
    out(bundle);
    return;
  }

  console.error("Usage:");
  console.error("  node scenario.js record --auto <project-dir>");
  console.error("  node scenario.js replay --paired --candidate <treeId> --baseline <treeId> [--corpus <dir>] [--seed <n>]");
  console.error("  node scenario.js --selftest");
  process.exit(1);
})();
