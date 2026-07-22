#!/usr/bin/env node
/* Adversarial suite for scripts/scenario.js — tester: Claude Sonnet (different family than builder, Qwen).
 * Lane: tests/scenario/ only. Never modifies scripts/scenario.js, scenarios/, or anything outside this dir.
 * Temp fixtures only (os.tmpdir()). Zero-dep CJS, Node >= 18. No git. No package installs.
 * Exit 1 if ANY case FAILs.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const SCENARIO_JS = path.join(REPO_ROOT, "scripts", "scenario.js");
const REAL_CORPUS_DIR = path.join(REPO_ROOT, "scenarios");

const CLOSED_CAUSE_CODES = ["ok", "workflow_fault", "infra_fault"];
const EXPECTED_SHAPES = ["pipeline", "fan-out", "manager+workers"];
const EXPECTED_FAILURE_MODES = ["normal", "crash-resume", "halt-uncertain", "budget-fail"];

const results = [];
const tempRoots = [];

function record(name, status, detail) {
  results.push({ name, status, detail: detail === undefined ? "" : String(detail) });
  const line = `${status}\t${name}${detail ? "\t" + String(detail).replace(/\s+/g, " ").slice(0, 400) : ""}`;
  console.log(line);
}
function pass(name, detail) { record(name, "PASS", detail); }
function fail(name, detail) { record(name, "FAIL", detail); }
function skip(name, detail) { record(name, "SKIPPED", detail); }

function mkRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `gs-scenario-sonnet-${tag}-`));
  tempRoots.push(root);
  return root;
}

function writeScenario(dir, scenario) {
  fs.writeFileSync(path.join(dir, scenario.id + ".json"), JSON.stringify(scenario, null, 2));
}

function runCLI(args, opts) {
  const r = spawnSync(process.execPath, [SCENARIO_JS, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: (opts && opts.timeoutMs) || 60000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return r;
}

// scenario.js's parseArgs() only registers a flag when the token itself starts with "--"
// (`k.startsWith("--")`). Its own usage banner and header doc comment document the subcommands
// as BARE positional tokens ("replay --paired ...", "record --auto ..."), which parseArgs never
// sets as args.replay / args.record -- so the documented invocation always falls through to the
// usage/exit-1 branch. The only form that actually works is "--replay"/"--record" (undocumented).
// See CHECK 0 below, and FINDINGS.md defect D1. All other checks in this suite use the WORKING
// "--replay --paired" form so that scenario.js's actual replay/invariant/cause-code behavior can
// still be exercised and reported on.

function parseJSONStdout(r, name) {
  try {
    return JSON.parse(r.stdout);
  } catch (e) {
    fail(name, "stdout not valid JSON: " + e.message + " | stdout=" + (r.stdout || "").slice(0, 300) + " stderr=" + (r.stderr || "").slice(0, 300));
    return null;
  }
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

// ---- minimal scenario fixture builders (schema-legal only; we never alter scenarios/ or scenario.js) ----

function baseScenario(overrides) {
  return Object.assign(
    {
      schema_version: "1.0",
      id: "t-" + crypto.randomBytes(4).toString("hex"),
      shape: "pipeline",
      tier: "smoke",
      seed: 5001,
      failure_mode: "normal",
      fixture: {
        pipeline: [
          { step: "01-a", worker: "a.js" },
          { step: "02-b", worker: "b.js" },
        ],
        workers: {
          "a.js": { behavior: "ok", delay_ms: 10 },
          "b.js": { behavior: "ok", delay_ms: 10 },
        },
      },
      expected: { outcome: "complete", completed_steps: ["01-a", "02-b"] },
      invariants: ["no-duplicate-effects", "intent-before-effect"],
    },
    overrides || {}
  );
}

// =====================================================================================
// CHECK 0 — the documented CLI invocation itself (found while wiring up every other check)
// =====================================================================================

function checkDocumentedReplayCLIWorks() {
  const name = "0a. CLI: the documented invocation 'node scenario.js replay --paired ...' (as shown in scenario.js's own header comment + usage banner) actually runs";
  const r = runCLI(["replay", "--paired", "--candidate", "c1", "--baseline", "b1", "--corpus", REAL_CORPUS_DIR, "--seed", "0"], { timeoutMs: 60000 });
  if (r.status === 0) {
    pass(name, "documented bare 'replay --paired' form works");
  } else {
    fail(name, "DEFECT REPRODUCED: documented CLI form exits " + r.status + " with usage banner instead of running. " +
      "parseArgs() only sets args.replay when the token itself starts with '--' (k.startsWith(\"--\")); the doc comment " +
      "and usage banner both show bare 'replay'/'record' as the subcommand, which never sets args.replay/args.record. " +
      "Workaround that DOES work (undocumented): '--replay --paired ...' / '--record --auto ...'. stderr=" + (r.stderr || "").slice(0, 200));
  }
}

function checkDocumentedRecordCLIWorks() {
  const name = "0b. CLI: the documented invocation 'node scenario.js record --auto <dir>' actually runs";
  const dir = mkRoot("record-probe");
  fs.mkdirSync(path.join(dir, "workers"), { recursive: true });
  fs.writeFileSync(path.join(dir, "pipeline.json"), JSON.stringify([{ step: "01-a", worker: "a.js" }]));
  fs.writeFileSync(path.join(dir, "workers", "a.js"), 'module.exports.run = async (input, ctx) => ({ ...(input||{}), [ctx.step]: "done" });');
  fs.writeFileSync(path.join(dir, "manager.js"), 'console.log(JSON.stringify({runId:"x",step:"__done__",status:"complete"}));');
  const r = runCLI(["record", "--auto", dir], { timeoutMs: 30000 });
  if (r.status === 0) {
    pass(name, "documented bare 'record --auto' form works");
  } else {
    fail(name, "DEFECT REPRODUCED (same root cause as 0a): documented 'record --auto' form exits " + r.status + " with usage banner. stderr=" + (r.stderr || "").slice(0, 200));
  }
}

// =====================================================================================
// CHECK 1 — Determinism
// =====================================================================================

function checkDeterminismSameSeed() {
  const name = "1a. determinism: same seed twice -> byte-identical bundle_sha256 (real corpus)";
  const args = ["--replay", "--paired", "--candidate", "cand-fixed", "--baseline", "base-fixed", "--corpus", REAL_CORPUS_DIR, "--seed", "77"];
  const r1 = runCLI(args, { timeoutMs: 120000 });
  const r2 = runCLI(args, { timeoutMs: 120000 });
  if (r1.status !== 0 || r2.status !== 0) {
    fail(name, `nonzero exit: run1=${r1.status} run2=${r2.status} stderr1=${(r1.stderr||"").slice(0,200)} stderr2=${(r2.stderr||"").slice(0,200)}`);
    return;
  }
  const b1 = parseJSONStdout(r1, name);
  const b2 = parseJSONStdout(r2, name);
  if (!b1 || !b2) return;
  if (b1.bundle_sha256 && b1.bundle_sha256 === b2.bundle_sha256) {
    pass(name, "bundle_sha256=" + b1.bundle_sha256);
  } else {
    fail(name, `hash mismatch: run1=${b1.bundle_sha256} run2=${b2.bundle_sha256}`);
  }
}

function checkDeterminismFlippedSeed() {
  const name = "1b. determinism: flipped seed -> bundle differs but stays schema-valid";
  const argsA = ["--replay", "--paired", "--candidate", "cand-fixed", "--baseline", "base-fixed", "--corpus", REAL_CORPUS_DIR, "--seed", "77"];
  const argsB = ["--replay", "--paired", "--candidate", "cand-fixed", "--baseline", "base-fixed", "--corpus", REAL_CORPUS_DIR, "--seed", "999"];
  const rA = runCLI(argsA, { timeoutMs: 120000 });
  const rB = runCLI(argsB, { timeoutMs: 120000 });
  if (rA.status !== 0 || rB.status !== 0) {
    fail(name, `nonzero exit: A=${rA.status} B=${rB.status}`);
    return;
  }
  const bA = parseJSONStdout(rA, name);
  const bB = parseJSONStdout(rB, name);
  if (!bA || !bB) return;
  const diffHash = bA.bundle_sha256 !== bB.bundle_sha256;
  const schemaOkB = validateBundleShape(bB);
  if (diffHash && schemaOkB.ok) {
    pass(name, `hashes differ (${bA.bundle_sha256.slice(0,8)} vs ${bB.bundle_sha256.slice(0,8)}) and flipped-seed bundle is schema-valid`);
  } else if (!diffHash) {
    fail(name, "seed flip did not change bundle_sha256 (seed not incorporated into evidence)");
  } else {
    fail(name, "flipped-seed bundle failed schema validation: " + schemaOkB.errors.join("; "));
  }
}

// =====================================================================================
// CHECK 2 — Bundle schema completeness (contract 03)
// =====================================================================================

function validateBundleShape(bundle) {
  const errors = [];
  if (!bundle || typeof bundle !== "object") return { ok: false, errors: ["bundle is not an object"] };
  for (const f of ["schema_version", "corpus_hash", "evaluator_version", "model_versions", "pairs", "bundle_sha256"]) {
    if (!(f in bundle)) errors.push("missing field: " + f);
  }
  if (bundle.model_versions) {
    if (!("candidate" in bundle.model_versions)) errors.push("model_versions missing candidate");
    if (!("baseline" in bundle.model_versions)) errors.push("model_versions missing baseline");
  }
  if (!Array.isArray(bundle.pairs)) {
    errors.push("pairs is not an array");
  } else {
    bundle.pairs.forEach((p, i) => {
      if (!p.scenario_id) errors.push(`pairs[${i}] missing scenario_id`);
      if (p.seed == null) errors.push(`pairs[${i}] missing seed`);
      for (const side of ["cand", "base"]) {
        if (!p[side]) { errors.push(`pairs[${i}] missing ${side}`); continue; }
        if (typeof p[side].pass !== "boolean") errors.push(`pairs[${i}].${side}.pass not boolean`);
        if (!CLOSED_CAUSE_CODES.includes(p[side].cause_code)) errors.push(`pairs[${i}].${side}.cause_code "${p[side].cause_code}" not in closed enum`);
      }
    });
  }
  return { ok: errors.length === 0, errors };
}

function checkBundleSchemaFullCorpus() {
  const name = "2. bundle schema: full real corpus run has every contract-03 field + closed-enum cause codes";
  const r = runCLI(["--replay", "--paired", "--candidate", "c1", "--baseline", "b1", "--corpus", REAL_CORPUS_DIR, "--seed", "0"], { timeoutMs: 180000 });
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status + " stderr=" + (r.stderr||"").slice(0,300)); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const v = validateBundleShape(bundle);
  if (v.ok && bundle.pairs.length === 12) {
    pass(name, `all fields present, 12 pairs, all cause codes closed-enum`);
  } else {
    fail(name, v.errors.concat(bundle.pairs ? [`pairs.length=${bundle.pairs.length}`] : []).join("; "));
  }
}

// =====================================================================================
// CHECK 3 — Separation of concerns: no promotion/verdict decision anywhere
// =====================================================================================

function checkNoVerdictInSource() {
  const name = "3a. separation of concerns: no verdict/promote/accept/reject decision logic in scenario.js source";
  const src = fs.readFileSync(SCENARIO_JS, "utf8");
  const lines = src.split("\n");
  const offenders = [];
  lines.forEach((line, i) => {
    if (/\bpromot|verdict|\baccept\b|\breject\b/i.test(line)) {
      const trimmed = line.trim();
      const isCommentOrDisclaimer = trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("/*");
      if (!isCommentOrDisclaimer) offenders.push(`L${i + 1}: ${trimmed}`);
    }
  });
  if (offenders.length === 0) {
    pass(name, "only disclaiming comments mention promotion; no executable decision logic found");
  } else {
    fail(name, "found verdict-like code outside comments: " + offenders.join(" | "));
  }
}

function checkNoVerdictKeyInBundle() {
  const name = "3b. separation of concerns: emitted evidence bundle carries no verdict-like key (recursive scan)";
  const r = runCLI(["--replay", "--paired", "--candidate", "c1", "--baseline", "b1", "--corpus", REAL_CORPUS_DIR, "--seed", "0"], { timeoutMs: 180000 });
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const forbidden = /^(promote|promotion|accept|accepted|reject|rejected|verdict|decision)$/i;
  const hits = [];
  (function walk(obj, p) {
    if (obj && typeof obj === "object") {
      for (const k of Object.keys(obj)) {
        if (forbidden.test(k)) hits.push(p + "." + k);
        walk(obj[k], p + "." + k);
      }
    }
  })(bundle, "bundle");
  if (hits.length === 0) {
    pass(name, "no verdict-like keys in emitted bundle (pass/cause_code are per-scenario evidence, not a promotion decision)");
  } else {
    fail(name, "found verdict-like keys: " + hits.join(", "));
  }
}

// =====================================================================================
// CHECK 4 — State-based verdicts, not output strings (chaos-harness philosophy, SKILL.md:89)
// =====================================================================================

function runSingleScenarioCorpus(scenario) {
  const dir = mkRoot("case-" + scenario.id);
  writeScenario(dir, scenario);
  const r = runCLI(["--replay", "--paired", "--candidate", "c1", "--baseline", "b1", "--corpus", dir, "--seed", "0"], { timeoutMs: 30000 });
  return { r, dir };
}

function checkHaltProtectionGenuine() {
  const name = "4a. state-based verdict: declared halt scenario where worker never actually halts must FAIL (not scored as halt-pass)";
  // Worker behavior "ok" -> normal completion, no unresolved intents on disk.
  // Scenario CLAIMS outcome "halt" and declares the halt-on-intent-without-completion invariant.
  // A harness that trusted a string (or trusted the label) would wrongly pass this; a state-based
  // harness must catch that no unresolved intent ever existed.
  const scenario = baseScenario({
    id: "probe-halt-never-happens",
    failure_mode: "halt-uncertain",
    fixture: {
      pipeline: [{ step: "01-a", worker: "a.js" }, { step: "02-b", worker: "b.js" }],
      workers: { "a.js": { behavior: "ok", delay_ms: 5 }, "b.js": { behavior: "ok", delay_ms: 5 } },
    },
    expected: { outcome: "halt", completed_steps: ["01-a"], halt_reason: "UNRESOLVED SIDE EFFECT" },
    invariants: ["halt-on-intent-without-completion", "no-duplicate-effects", "intent-before-effect"],
  });
  const { r } = runSingleScenarioCorpus(scenario);
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status + " stderr=" + (r.stderr||"").slice(0,300)); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const pair = bundle.pairs[0];
  if (pair && pair.cand.pass === false) {
    pass(name, `correctly scored FAIL: cause_code=${pair.cand.cause_code} (halt-on-intent-without-completion invariant caught the mismatch)`);
  } else {
    fail(name, "declared-halt-but-never-halted scenario was scored PASS: " + JSON.stringify(pair));
  }
}

function checkBudgetExceededProtectionGap() {
  const name = "4b. state-based verdict: declared budget-exceeded scenario where budget is never actually breached must FAIL";
  // Same defect class as 4a, but for the budget-exceeded outcome, which has NO analogous
  // "expected-outcome-matches-actual" invariant in scenario.js (only halt has one).
  // budget_ms is set generously large and workers are fast, so the run completes normally
  // (exit 0, "__done__"); classifyOutcome's first branch returns pass:true whenever
  // (code===0 && stdout includes "__done__") WITHOUT checking scenario.expected.outcome at all.
  const scenario = baseScenario({
    id: "probe-budget-never-exceeded",
    failure_mode: "budget-fail",
    fixture: {
      pipeline: [{ step: "01-a", worker: "a.js" }, { step: "02-b", worker: "b.js" }],
      workers: { "a.js": { behavior: "ok", delay_ms: 5 }, "b.js": { behavior: "ok", delay_ms: 5 } },
      budget_ms: 999999,
    },
    expected: { outcome: "budget-exceeded", completed_steps: ["01-a"] },
    invariants: ["no-duplicate-effects", "intent-before-effect"],
  });
  const { r } = runSingleScenarioCorpus(scenario);
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status + " stderr=" + (r.stderr||"").slice(0,300)); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const pair = bundle.pairs[0];
  if (pair && pair.cand.pass === false) {
    pass(name, "correctly scored FAIL: expected-outcome mismatch was detected");
  } else {
    fail(name, "DEFECT REPRODUCED: budget-exceeded scenario that never breached its budget was scored PASS (cause_code=" +
      (pair && pair.cand.cause_code) + "). classifyOutcome() ignores scenario.expected.outcome on its complete-path branch.");
  }
}

// =====================================================================================
// CHECK 5 — Corpus coverage (3 shapes x 4 failure modes, self-contained, actually run a sample)
// =====================================================================================

function checkCorpusCoverageMatrix() {
  const name = "5a. corpus coverage: 12 files = 3 shapes x 4 failure_modes, each combination present exactly once";
  const files = fs.readdirSync(REAL_CORPUS_DIR).filter((f) => f.endsWith(".json"));
  if (files.length !== 12) { fail(name, "expected 12 scenario files, found " + files.length); return; }
  const seen = new Set();
  const errors = [];
  for (const f of files) {
    const sc = JSON.parse(fs.readFileSync(path.join(REAL_CORPUS_DIR, f), "utf8"));
    if (!EXPECTED_SHAPES.includes(sc.shape)) errors.push(f + ": unknown shape " + sc.shape);
    if (!EXPECTED_FAILURE_MODES.includes(sc.failure_mode)) errors.push(f + ": unknown failure_mode " + sc.failure_mode);
    const key = sc.shape + "|" + sc.failure_mode;
    if (seen.has(key)) errors.push("duplicate combination: " + key);
    seen.add(key);
  }
  const expectedCombos = EXPECTED_SHAPES.length * EXPECTED_FAILURE_MODES.length;
  if (seen.size !== expectedCombos) errors.push(`only ${seen.size}/${expectedCombos} shape x failure_mode combinations covered`);
  if (errors.length === 0) pass(name, "12/12 combinations present, no duplicates");
  else fail(name, errors.join("; "));
}

function checkCorpusSelfContained() {
  const name = "5b. corpus integrity: every scenario file is self-contained (no API keys, no network refs, no env/secret refs)";
  const files = fs.readdirSync(REAL_CORPUS_DIR).filter((f) => f.endsWith(".json"));
  const suspicious = /(api[_-]?key|process\.env|https?:\/\/|secret|token|password)/i;
  const offenders = [];
  for (const f of files) {
    const raw = fs.readFileSync(path.join(REAL_CORPUS_DIR, f), "utf8");
    if (suspicious.test(raw)) offenders.push(f);
  }
  if (offenders.length === 0) pass(name, "no secret/network/env references found in any of " + files.length + " scenario files");
  else fail(name, "suspicious references in: " + offenders.join(", "));
}

function checkRunRealSample() {
  const name = "5c. corpus coverage: actually RUN all 12 real scenarios and confirm each self-consistently passes its own design";
  const r = runCLI(["--replay", "--paired", "--candidate", "sample-cand", "--baseline", "sample-base", "--corpus", REAL_CORPUS_DIR, "--seed", "0"], { timeoutMs: 180000 });
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status + " stderr=" + (r.stderr||"").slice(0,400)); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const failing = bundle.pairs.filter((p) => !p.cand.pass || !p.base.pass);
  if (failing.length === 0) {
    pass(name, `all ${bundle.pairs.length} real corpus scenarios pass on both cand and base sides`);
  } else {
    fail(name, "scenarios failing their own design: " + failing.map((p) => p.scenario_id).join(", "));
  }
}

function checkSelftestFlag() {
  const name = "5d. built-in --selftest flag runs and exits 0";
  const r = runCLI(["--selftest"], { timeoutMs: 60000 });
  if (r.status === 0) pass(name, "selftest exited 0");
  else fail(name, "selftest exited " + r.status + " stderr=" + (r.stderr||"").slice(0,300));
}

// =====================================================================================
// CHECK 6 — Corpus integrity: pinned seeds, stable hashes, nondeterminism detection
// =====================================================================================

function checkPinnedSeeds() {
  const name = "6a. corpus integrity: every scenario has a pinned non-negative integer seed";
  const files = fs.readdirSync(REAL_CORPUS_DIR).filter((f) => f.endsWith(".json"));
  const bad = [];
  for (const f of files) {
    const sc = JSON.parse(fs.readFileSync(path.join(REAL_CORPUS_DIR, f), "utf8"));
    if (!Number.isInteger(sc.seed) || sc.seed < 0) bad.push(f + ": seed=" + sc.seed);
  }
  if (bad.length === 0) pass(name, "all " + files.length + " scenarios carry a pinned integer seed");
  else fail(name, bad.join("; "));
}

function checkStableHashAcrossTwoRuns() {
  const name = "6b. corpus integrity: two full-corpus runs with same cycleSeed give stable bundle_sha256 (already covered by 1a, re-verified with a different seed)";
  const args = ["--replay", "--paired", "--candidate", "stab-cand", "--baseline", "stab-base", "--corpus", REAL_CORPUS_DIR, "--seed", "12345"];
  const r1 = runCLI(args, { timeoutMs: 180000 });
  const r2 = runCLI(args, { timeoutMs: 180000 });
  if (r1.status !== 0 || r2.status !== 0) { fail(name, "nonzero exit"); return; }
  const b1 = parseJSONStdout(r1, name);
  const b2 = parseJSONStdout(r2, name);
  if (!b1 || !b2) return;
  if (b1.bundle_sha256 === b2.bundle_sha256) pass(name, "stable hash across two full-corpus runs");
  else fail(name, "unstable hash: " + b1.bundle_sha256 + " vs " + b2.bundle_sha256);
}

function checkNondeterminismDetectionCoverage() {
  const name = "6c. corpus integrity: attempt to construct a secretly-nondeterministic scenario (uses time/random in a decision)";
  // The schema-legal worker "behavior" vocabulary (ok, delay, fail, intent-no-complete, budget-exceed)
  // maps to generator templates in scenario.js that contain NO Math.random and no decision-affecting
  // Date.now() (only the budget check's wall-clock comparison, which is the intentional subject under
  // test for budget-fail scenarios, not a hidden source of nondeterminism). Because I may not modify
  // scripts/scenario.js or scenarios/, I cannot express a Math.random()-driven decision through the
  // schema at all -- there is no behavior enum value that reads Math.random(). This check is therefore
  // SKIPPED with an honest explanation rather than faked.
  skip(name, "cannot express nondeterministic worker logic through schema-legal fixtures without modifying scenario.js's generator (out of lane) — see FINDINGS.md coverage statement");
}

// =====================================================================================
// CHECK 7 — Cause-code correctness
// =====================================================================================

function checkWorkflowFaultOnCandidateCrash() {
  const name = "7a. cause-code correctness: unconditional worker failure -> workflow_fault on both sides";
  const scenario = baseScenario({
    id: "probe-workflow-fault",
    fixture: {
      pipeline: [{ step: "01-a", worker: "a.js" }],
      workers: { "a.js": { behavior: "fail", fail_message: "boom" } },
    },
    expected: { outcome: "complete", completed_steps: [] },
    invariants: [],
  });
  const { r } = runSingleScenarioCorpus(scenario);
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const pair = bundle.pairs[0];
  if (pair && pair.cand.cause_code === "workflow_fault" && pair.base.cause_code === "workflow_fault") {
    pass(name, "both sides correctly classified workflow_fault on unconditional worker crash");
  } else {
    fail(name, "unexpected cause codes: " + JSON.stringify(pair));
  }
}

function checkInfraFaultReachability() {
  const name = "7b. cause-code correctness: evaluation-copy setup failure (pipeline references an undefined worker) should classify as infra_fault";
  const scenario = baseScenario({
    id: "probe-infra-fault",
    fixture: {
      // pipeline references "missing.js" which is never declared under workers{}, so
      // materializeFixture() never writes workers/missing.js -> manager.js's require() throws
      // synchronously (a setup/evaluation-copy failure per contract 03's infra_fault definition,
      // not a workflow-authored crash).
      pipeline: [{ step: "01-a", worker: "missing.js" }],
      workers: { "a.js": { behavior: "ok" } },
    },
    expected: { outcome: "complete", completed_steps: [] },
    invariants: [],
  });
  const { r } = runSingleScenarioCorpus(scenario);
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const pair = bundle.pairs[0];
  if (pair && pair.cand.cause_code === "infra_fault") {
    pass(name, "setup failure correctly classified infra_fault");
  } else {
    fail(name, "DEFECT REPRODUCED: missing-worker setup failure was classified '" + (pair && pair.cand.cause_code) +
      "' instead of infra_fault (contract 03 requires evaluation-copy setup failures to be infra_fault, which carries retry-once semantics workflow_fault does not get)");
  }
}

function checkCauseCodeAlwaysClosedEnumAcrossCorpus() {
  const name = "7c. cause-code correctness: every real-corpus pair (both sides) uses only ok/workflow_fault/infra_fault";
  const r = runCLI(["--replay", "--paired", "--candidate", "c1", "--baseline", "b1", "--corpus", REAL_CORPUS_DIR, "--seed", "0"], { timeoutMs: 180000 });
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const bad = [];
  for (const p of bundle.pairs) {
    if (!CLOSED_CAUSE_CODES.includes(p.cand.cause_code)) bad.push(p.scenario_id + ".cand=" + p.cand.cause_code);
    if (!CLOSED_CAUSE_CODES.includes(p.base.cause_code)) bad.push(p.scenario_id + ".base=" + p.base.cause_code);
  }
  if (bad.length === 0) pass(name, "all cause codes closed-enum across full corpus");
  else fail(name, bad.join(", "));
}

// =====================================================================================
// CHECK 8 — root-cause isolation for the 5c corpus failure: crash injection is dead code
// =====================================================================================

function checkCrashInjectionActuallyCrashes() {
  const name = "8. crash-injection: a fresh crash_after_step scenario must actually terminate the manager after that step (root cause of 5c)";
  // generateManager()'s injected crash condition reads:
  //   if (CRASH_AFTER && stepDef.step === CRASH_AFTER && !readCheckpoint(ckpt, step).done) process.exit(1);
  // But this line only runs AFTER `carry = await executeStep(stepDef, carry)` has already returned, which
  // only happens once executeStep() has saved the checkpoint on success. So readCheckpoint(...).done is
  // always true at that point, and !true is always false -> the crash never fires. This is not specific to
  // the shipped corpus; it reproduces on any fresh scenario with crash_after_step set.
  const scenario = baseScenario({
    id: "probe-crash-injection",
    failure_mode: "crash-resume",
    fixture: {
      pipeline: [{ step: "01-a", worker: "a.js" }, { step: "02-b", worker: "b.js" }],
      workers: { "a.js": { behavior: "ok", delay_ms: 5 }, "b.js": { behavior: "ok", delay_ms: 5 } },
      crash_after_step: "01-a",
    },
    expected: { outcome: "crash-recovered", completed_steps: ["01-a", "02-b"] },
    invariants: ["no-duplicate-effects", "intent-before-effect", "no-step-reexecuted-after-resume"],
  });
  const { r } = runSingleScenarioCorpus(scenario);
  if (r.status !== 0) { fail(name, "nonzero exit " + r.status + " stderr=" + (r.stderr||"").slice(0,300)); return; }
  const bundle = parseJSONStdout(r, name);
  if (!bundle) return;
  const pair = bundle.pairs[0];
  if (pair && pair.cand.pass === false && pair.cand.cause_code === "workflow_fault") {
    fail(name, "DEFECT REPRODUCED (isolated, not corpus-specific): crash_after_step never actually crashed the manager; " +
      "scenario.js's own self-consistency guard caught it and reported workflow_fault/'crash-expected' " +
      "(loud failure, not a silent false-pass — but the crash-resume test family is entirely non-functional as shipped). " +
      "pair=" + JSON.stringify(pair));
  } else if (pair && pair.cand.pass === true) {
    pass(name, "crash injection fired and resume worked as designed");
  } else {
    fail(name, "unexpected result: " + JSON.stringify(pair));
  }
}

// =====================================================================================
// EXTRA — candidate vs baseline differentiation (found during contract review, not in the
// required checklist verbatim, but directly relevant to check 1/7 and contract 03's pairing design)
// =====================================================================================

function checkCandidateBaselineAreActuallyDifferentiable() {
  const name = "X1. paired replay: --candidate and --baseline are honored as distinct code trees, not just labels";
  // replayPaired() calls materializeFixture(scenario, candDir) and materializeFixture(scenario, baseDir)
  // using the SAME scenario.fixture for both, regardless of the --candidate/--baseline treeId values.
  // There is no code path in scenario.js that reads a candidate- or baseline-specific tree/pipeline/worker
  // set. This test proves it: two different --candidate values against the same corpus/seed produce
  // byte-identical pair results (only the label in model_versions differs), which is expected if the
  // tree ids are inert -- and is the observable symptom of the defect documented in FINDINGS.md.
  const args1 = ["--replay", "--paired", "--candidate", "tree-AAA", "--baseline", "tree-BASE", "--corpus", REAL_CORPUS_DIR, "--seed", "0"];
  const args2 = ["--replay", "--paired", "--candidate", "tree-ZZZ-totally-different", "--baseline", "tree-BASE", "--corpus", REAL_CORPUS_DIR, "--seed", "0"];
  const r1 = runCLI(args1, { timeoutMs: 180000 });
  const r2 = runCLI(args2, { timeoutMs: 180000 });
  if (r1.status !== 0 || r2.status !== 0) { fail(name, "nonzero exit"); return; }
  const b1 = parseJSONStdout(r1, name);
  const b2 = parseJSONStdout(r2, name);
  if (!b1 || !b2) return;
  const pairs1 = JSON.stringify(b1.pairs);
  const pairs2 = JSON.stringify(b2.pairs);
  if (pairs1 === pairs2) {
    fail(name, "DEFECT: changing --candidate treeId did not change a single pair result — materializeFixture() ignores candidateId/baselineId entirely and generates identical code for both sides from scenario.fixture alone. Gate 2's paired comparison can never produce a discordant pair through this path.");
  } else {
    pass(name, "candidate treeId change altered pair results as expected");
  }
}

// =====================================================================================
// Run all
// =====================================================================================

function main() {
  console.log("=== tests/scenario/run-tests.js (tester family: Claude Sonnet; builder family: Qwen) ===");
  console.log("REPO_ROOT=" + REPO_ROOT);
  console.log("SCENARIO_JS=" + SCENARIO_JS);
  console.log("REAL_CORPUS_DIR=" + REAL_CORPUS_DIR);
  console.log("");

  try {
    checkDocumentedReplayCLIWorks();
    checkDocumentedRecordCLIWorks();

    checkDeterminismSameSeed();
    checkDeterminismFlippedSeed();

    checkBundleSchemaFullCorpus();

    checkNoVerdictInSource();
    checkNoVerdictKeyInBundle();

    checkHaltProtectionGenuine();
    checkBudgetExceededProtectionGap();

    checkCorpusCoverageMatrix();
    checkCorpusSelfContained();
    checkRunRealSample();
    checkSelftestFlag();

    checkPinnedSeeds();
    checkStableHashAcrossTwoRuns();
    checkNondeterminismDetectionCoverage();

    checkWorkflowFaultOnCandidateCrash();
    checkInfraFaultReachability();
    checkCauseCodeAlwaysClosedEnumAcrossCorpus();

    checkCrashInjectionActuallyCrashes();

    checkCandidateBaselineAreActuallyDifferentiable();
  } finally {
    for (const root of tempRoots) {
      try { fs.rmSync(root, { recursive: true, force: true }); } catch (e) { /* best effort */ }
    }
  }

  console.log("");
  const summary = { PASS: 0, FAIL: 0, SKIPPED: 0 };
  for (const r of results) summary[r.status] = (summary[r.status] || 0) + 1;
  console.log(`=== SUMMARY: ${summary.PASS} PASS, ${summary.FAIL} FAIL, ${summary.SKIPPED} SKIPPED (of ${results.length}) ===`);

  if (summary.FAIL > 0) {
    console.log("");
    console.log("FAILING CASES:");
    for (const r of results) if (r.status === "FAIL") console.log("  - " + r.name);
    process.exit(1);
  }
  process.exit(0);
}

main();
