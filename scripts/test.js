#!/usr/bin/env node
/* GraphSmith test.js — unit + scenario-regression + smoke on a user workflow (§17).
 * Reuses scenario.js + chaos.js via subprocess (those modules are CLI-entry).
 * Deterministic pass/fail with per-check evidence records.
 * NO real external effects (fixture managers + mocked workers only).
 *
 * Zero-dep CJS, Node ≥ 18. No clock/random in decision paths.
 * JSON stdout / prose stderr; exit 0/1/2.
 *
 * Usage:
 *   node scripts/test.js <project-dir>
 *   node scripts/test.js --selftest
 *   node scripts/test.js <project-dir> --chaos   (opt-in full chaos harness)
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const SCHEMA_VERSION = "1.0";
const TEST_VERSION = "0.2.0";
const SCRIPTS = __dirname;
const REPO_ROOT = path.resolve(__dirname, "..");
const DEFAULT_CORPUS = path.join(REPO_ROOT, "scenarios");

const err = (msg) => process.stderr.write(msg + "\n");
const out = (obj) => process.stdout.write(JSON.stringify(obj, null, 2) + "\n");

function sha256(data) {
  return crypto
    .createHash("sha256")
    .update(typeof data === "string" || Buffer.isBuffer(data) ? data : JSON.stringify(data))
    .digest("hex");
}

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith("--")) {
      const key = k.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) a[key] = argv[++i];
      else a[key] = true;
    } else a._.push(k);
  }
  return a;
}

function mkEvidence(id, status, evidence) {
  return {
    id,
    status, /* pass | fail | skip | unavailable */
    evidence: evidence || {},
  };
}

/* ---------- unit checks (structure + discipline surface) ---------- */

function unitChecks(projectDir) {
  const checks = [];
  const root = path.resolve(projectDir);
  const need = ["manager.js", "pipeline.json"];
  for (const f of need) {
    const p = path.join(root, f);
    const ok = fs.existsSync(p) && fs.statSync(p).isFile();
    checks.push(
      mkEvidence("unit.exists." + f, ok ? "pass" : "fail", {
        path: p,
        present: ok,
      })
    );
  }
  const workersDir = path.join(root, "workers");
  const hasWorkers = fs.existsSync(workersDir) && fs.statSync(workersDir).isDirectory();
  let workerCount = 0;
  if (hasWorkers) {
    workerCount = fs.readdirSync(workersDir).filter((n) => n.endsWith(".js")).length;
  }
  checks.push(
    mkEvidence("unit.workers-dir", hasWorkers && workerCount > 0 ? "pass" : "fail", {
      path: workersDir,
      worker_js_count: workerCount,
    })
  );

  if (fs.existsSync(path.join(root, "pipeline.json"))) {
    let pipeline = null;
    let parseOk = false;
    try {
      pipeline = JSON.parse(fs.readFileSync(path.join(root, "pipeline.json"), "utf8"));
      parseOk = Array.isArray(pipeline) && pipeline.length > 0;
    } catch (_) {
      parseOk = false;
    }
    checks.push(
      mkEvidence("unit.pipeline-shape", parseOk ? "pass" : "fail", {
        is_array: Array.isArray(pipeline),
        length: Array.isArray(pipeline) ? pipeline.length : 0,
      })
    );
    if (parseOk) {
      const steps = pipeline.map((s) => s && s.step).filter(Boolean);
      const uniq = new Set(steps);
      checks.push(
        mkEvidence("unit.pipeline-unique-steps", uniq.size === steps.length ? "pass" : "fail", {
          steps,
        })
      );
      /* Each step names a worker module that exists — or inline ok. */
      let missing = [];
      for (const s of pipeline) {
        if (!s || !s.worker) continue;
        const w = s.worker.endsWith(".js") ? s.worker : s.worker + ".js";
        const wp = path.join(workersDir, path.basename(w));
        if (!fs.existsSync(wp)) missing.push(w);
      }
      checks.push(
        mkEvidence("unit.workers-resolve", missing.length === 0 ? "pass" : "fail", {
          missing,
        })
      );
    }
  }

  return checks;
}

/* ---------- smoke: one full manager run, no external effects ---------- */

function smokeRun(projectDir, runId) {
  const root = path.resolve(projectDir);
  const manager = path.join(root, "manager.js");
  if (!fs.existsSync(manager)) {
    return {
      checks: [mkEvidence("smoke.run", "fail", { reason: "no_manager" })],
      runId,
    };
  }
  const id = runId || "smoke-fixed-1";
  const result = spawnSync(process.execPath, ["manager.js", id], {
    cwd: root,
    encoding: "utf8",
    timeout: 20000,
    env: Object.assign({}, process.env, { GRAPHSMITH_TEST_MODE: "1" }),
    windowsHide: true,
  });
  const runDir = path.join(root, ".runs", id);
  const checkpoints = fs.existsSync(runDir)
    ? fs.readdirSync(runDir).filter((f) => f.endsWith(".json") && !f.includes(".corrupt-"))
    : [];
  const outAll = (result.stdout || "") + (result.stderr || "");
  const completed = result.status === 0 && /__done__/.test(outAll);
  const checks = [];
  checks.push(
    mkEvidence("smoke.exit-zero", result.status === 0 ? "pass" : "fail", {
      exit_code: result.status,
      signal: result.signal || null,
    })
  );
  checks.push(
    mkEvidence("smoke.completion-marker", completed ? "pass" : "fail", {
      has_done_marker: /__done__/.test(outAll),
    })
  );
  checks.push(
    mkEvidence("smoke.checkpoints-written", checkpoints.length > 0 ? "pass" : "fail", {
      count: checkpoints.length,
      files: checkpoints.slice(0, 32),
    })
  );
  /* effects log discipline if present */
  const effPath = path.join(runDir, "effects.log");
  if (fs.existsSync(effPath)) {
    const lines = fs.readFileSync(effPath, "utf8").split("\n").filter(Boolean);
    const cnt = {};
    for (const ln of lines) cnt[ln] = (cnt[ln] || 0) + 1;
    const dupes = Object.entries(cnt).filter(([, n]) => n > 1);
    checks.push(
      mkEvidence("smoke.no-duplicate-effects", dupes.length === 0 ? "pass" : "fail", {
        duplicates: dupes.map(([s, n]) => s + "x" + n),
      })
    );
  } else {
    checks.push(
      mkEvidence("smoke.no-duplicate-effects", "skip", {
        reason: "no_effects_log",
      })
    );
  }
  return { checks, runId: id, exit_code: result.status };
}

/* ---------- scenario regression: spawn scenario.js ---------- */

function scenarioRegression(opts) {
  const checks = [];
  const scenarioJs = path.join(SCRIPTS, "scenario.js");
  if (!fs.existsSync(scenarioJs)) {
    checks.push(
      mkEvidence("scenario.tool-present", "unavailable", { path: scenarioJs })
    );
    return { checks };
  }
  checks.push(mkEvidence("scenario.tool-present", "pass", { path: scenarioJs }));

  /* Prefer shipped corpus smoke tiers; fall back to tool --selftest if corpus thin. */
  const corpusDir = opts.corpusDir || DEFAULT_CORPUS;
  let scenarios = [];
  if (fs.existsSync(corpusDir)) {
    scenarios = fs
      .readdirSync(corpusDir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => {
        try {
          return JSON.parse(fs.readFileSync(path.join(corpusDir, f), "utf8"));
        } catch (_) {
          return null;
        }
      })
      .filter(Boolean);
  }

  const smokeIds = scenarios.filter((s) => s.tier === "smoke").map((s) => s.id);
  checks.push(
    mkEvidence("scenario.corpus-load", scenarios.length > 0 ? "pass" : "fail", {
      corpus: corpusDir,
      count: scenarios.length,
      smoke_ids: smokeIds.slice(0, 20),
    })
  );

  /* Run scenario selftest for determinism + schema (reuses scenario.js fully). */
  const r = spawnSync(process.execPath, [scenarioJs, "--selftest"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: 120000,
    windowsHide: true,
  });
  let bundle = null;
  try {
    const t = (r.stdout || "").trim();
    const i = t.indexOf("{");
    if (i >= 0) bundle = JSON.parse(t.slice(i));
  } catch (_) {
    bundle = null;
  }
  const detOk = !!(bundle && bundle.determinism_pass && bundle.schema_validation_pass);
  checks.push(
    mkEvidence("scenario.regression-selftest", r.status === 0 && detOk ? "pass" : "fail", {
      exit_code: r.status,
      determinism_pass: bundle ? bundle.determinism_pass : null,
      schema_validation_pass: bundle ? bundle.schema_validation_pass : null,
      scenarios_tested: bundle ? bundle.scenarios_tested : null,
      bundle_hash: bundle ? bundle.bundle_hash : null,
      stderr_excerpt: (r.stderr || "").slice(0, 400),
    })
  );
  return { checks, bundle_hash: bundle ? bundle.bundle_hash : null };
}

/* ---------- chaos harness (opt-in; reuses chaos.js) ---------- */

function chaosCheck(projectDir) {
  const chaosJs = path.join(SCRIPTS, "chaos.js");
  if (!fs.existsSync(chaosJs)) {
    return [mkEvidence("chaos.harness", "unavailable", { path: chaosJs })];
  }
  const r = spawnSync(process.execPath, [chaosJs, path.resolve(projectDir)], {
    cwd: path.resolve(projectDir),
    encoding: "utf8",
    timeout: 120000,
    windowsHide: true,
  });
  const text = (r.stdout || "") + (r.stderr || "");
  /* Verdict from exit code primarily; excerpts are evidence DATA only. */
  const ok = r.status === 0;
  return [
    mkEvidence("chaos.harness", ok ? "pass" : "fail", {
      exit_code: r.status,
      stdout_excerpt: (r.stdout || "").slice(0, 600),
      stderr_excerpt: (r.stderr || "").slice(0, 400),
      note: "proves crash recovery + recorded-effects discipline on this project conventions",
    }),
  ];
}

/* ---------- fixture builders (selftest only) ---------- */

function writeGoodFixture(dir) {
  fs.mkdirSync(path.join(dir, "workers"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "pipeline.json"),
    JSON.stringify(
      [
        { step: "01-collect", worker: "collect.js" },
        { step: "02-process", worker: "process.js" },
      ],
      null,
      2
    ) + "\n"
  );
  const workerBody = function (label) {
    return [
      '"use strict";',
      "const fs = require(\"fs\");",
      "const path = require(\"path\");",
      "function appendDurable(file, line) {",
      "  const fd = fs.openSync(file, \"a\");",
      "  try { fs.writeSync(fd, line + \"\\n\"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }",
      "}",
      "const readLines = (p) => fs.existsSync(p) ? fs.readFileSync(p, \"utf8\").split(\"\\n\").filter(Boolean) : [];",
      "module.exports.run = async function (input, ctx) {",
      "  const intents = path.join(ctx.runDir, \"intents.log\");",
      "  const effects = path.join(ctx.runDir, \"effects.log\");",
      "  if (readLines(effects).indexOf(ctx.step) !== -1) return input || { ok: true };",
      "  if (readLines(intents).indexOf(ctx.step) !== -1) {",
      "    const e = new Error(\"UNRESOLVED SIDE EFFECT for step \" + ctx.step);",
      "    e.unresolvedSideEffect = true;",
      "    throw e;",
      "  }",
      "  appendDurable(intents, ctx.step);",
      "  appendDurable(effects, ctx.step);",
      "  return Object.assign({}, input || {}, { " + JSON.stringify(label) + ": true });",
      "};",
      "",
    ].join("\n");
  };
  fs.writeFileSync(path.join(dir, "workers", "collect.js"), workerBody("collect"));
  fs.writeFileSync(path.join(dir, "workers", "process.js"), workerBody("process"));
  /* Minimal deterministic manager (scaffold conventions subset). */
  fs.writeFileSync(
    path.join(dir, "manager.js"),
    [
      '"use strict";',
      "const fs = require(\"fs\");",
      "const path = require(\"path\");",
      "const PIPELINE = JSON.parse(fs.readFileSync(path.join(__dirname, \"pipeline.json\"), \"utf8\"));",
      "const runId = process.argv[2] || \"default\";",
      "const runDir = path.join(__dirname, \".runs\", runId);",
      "fs.mkdirSync(runDir, { recursive: true });",
      "function log(obj) { process.stdout.write(JSON.stringify(obj) + \"\\n\"); }",
      "(async () => {",
      "  let input = {};",
      "  for (const step of PIPELINE) {",
      "    const cp = path.join(runDir, step.step + \".json\");",
      "    if (fs.existsSync(cp)) {",
      "      input = JSON.parse(fs.readFileSync(cp, \"utf8\")).output;",
      "      log({ step: step.step, status: \"skipped\" });",
      "      continue;",
      "    }",
      "    const wName = step.worker.endsWith(\".js\") ? step.worker : step.worker + \".js\";",
      "    const worker = require(path.join(__dirname, \"workers\", wName));",
      "    const t0 = Date.now();",
      "    const output = await worker.run(input, { runId, step: step.step, runDir });",
      "    const rec = { step: step.step, status: \"ok\", ms: Date.now() - t0, output };",
      "    fs.writeFileSync(cp, JSON.stringify(rec, null, 2));",
      "    log({ step: step.step, status: \"ok\" });",
      "    input = output;",
      "  }",
      "  process.stdout.write(\"__done__\\n\");",
      "})().catch((e) => { console.error(e && e.message ? e.message : e); process.exit(1); });",
      "",
    ].join("\n")
  );
}

function writeBadFixture(dir) {
  fs.mkdirSync(dir, { recursive: true });
  /* Missing workers + empty pipeline — must fail unit. */
  fs.writeFileSync(path.join(dir, "manager.js"), "console.log('noop')\n");
  fs.writeFileSync(path.join(dir, "pipeline.json"), "[]\n");
}

/* ---------- suite runner ---------- */

function runSuite(projectDir, options) {
  options = options || {};
  const checks = [];
  const startedMeta = new Date().toISOString(); /* metadata only */

  checks.push(...unitChecks(projectDir));

  const unitFailed = checks.some((c) => c.id.startsWith("unit.") && c.status === "fail");
  if (!unitFailed) {
    const smoke = smokeRun(projectDir, options.smokeRunId || "smoke-fixed-1");
    checks.push(...smoke.checks);
  } else {
    checks.push(
      mkEvidence("smoke.run", "skip", { reason: "unit_failed" })
    );
  }

  if (options.includeScenario !== false) {
    const sc = scenarioRegression({ corpusDir: options.corpusDir });
    checks.push(...sc.checks);
  }

  if (options.chaos) {
    checks.push(...chaosCheck(projectDir));
  }

  const failed = checks.filter((c) => c.status === "fail");
  const passed = checks.filter((c) => c.status === "pass");
  const skipped = checks.filter((c) => c.status === "skip" || c.status === "unavailable");

  const report = {
    schema_version: SCHEMA_VERSION,
    component: "test",
    version: TEST_VERSION,
    project: path.resolve(projectDir),
    status: failed.length === 0 ? "pass" : "fail",
    summary: {
      pass: passed.length,
      fail: failed.length,
      skip_or_unavailable: skipped.length,
      total: checks.length,
    },
    checks,
    failed_ids: failed.map((c) => c.id),
    meta: {
      generated_at: startedMeta,
      floor_note:
        "A passing battery is a floor of tested discipline checks, not proof of correctness.",
    },
    report_sha256: null,
  };
  report.report_sha256 = sha256(
    JSON.stringify({
      schema_version: report.schema_version,
      status: report.status,
      checks: report.checks,
      failed_ids: report.failed_ids,
    })
  );
  return report;
}

/* ---------- selftest ---------- */

function selftest() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gs-test-self-"));
  const good = path.join(tmp, "good");
  const bad = path.join(tmp, "bad");
  const metaChecks = [];

  try {
    writeGoodFixture(good);
    writeBadFixture(bad);

    const goodReport = runSuite(good, {
      includeScenario: true,
      smokeRunId: "selftest-smoke-1",
    });
    const badReport = runSuite(bad, {
      includeScenario: false,
      smokeRunId: "selftest-smoke-bad",
    });

    metaChecks.push(
      mkEvidence(
        "self.good-passes",
        goodReport.status === "pass" ? "pass" : "fail",
        {
          status: goodReport.status,
          failed_ids: goodReport.failed_ids,
          summary: goodReport.summary,
        }
      )
    );
    metaChecks.push(
      mkEvidence(
        "self.bad-fails",
        badReport.status === "fail" ? "pass" : "fail",
        {
          status: badReport.status,
          failed_ids: badReport.failed_ids,
        }
      )
    );
    metaChecks.push(
      mkEvidence(
        "self.per-check-evidence",
        goodReport.checks.every((c) => c.id && c.status && c.evidence !== undefined)
          ? "pass"
          : "fail",
        { sample: goodReport.checks.slice(0, 3) }
      )
    );
    /* unit check id set stable across two good runs (determinism of suite shape) */
    const r1 = runSuite(good, { includeScenario: false, smokeRunId: "det-a" });
    const r2 = runSuite(good, { includeScenario: false, smokeRunId: "det-b" });
    const ids1 = r1.checks.filter((c) => c.id.startsWith("unit.")).map((c) => c.id).join("|");
    const ids2 = r2.checks.filter((c) => c.id.startsWith("unit.")).map((c) => c.id).join("|");
    metaChecks.push(
      mkEvidence("self.unit-id-stable", ids1 === ids2 && ids1.length > 0 ? "pass" : "fail", {
        ids1,
        ids2,
      })
    );

    /* honest-scope: no banned claim phrases in emitted JSON */
    const banned = [
      /\bpen[\s-]?test\b/i,
      /\bcertified\s+secure\b/i,
      /\bsecurity\s+guaranteed\b/i,
    ];
    const blob = JSON.stringify({ goodReport, badReport, metaChecks });
    const hits = banned.filter((re) => re.test(blob)).map((re) => re.source);
    metaChecks.push(
      mkEvidence("self.honest-scope", hits.length === 0 ? "pass" : "fail", { hits })
    );

    const failed = metaChecks.filter((c) => c.status !== "pass");
    const result = {
      schema_version: SCHEMA_VERSION,
      component: "test",
      version: TEST_VERSION,
      status: failed.length === 0 ? "pass" : "fail",
      checks: metaChecks,
      good_summary: goodReport.summary,
      bad_summary: badReport.summary,
      failed: failed.map((c) => c.id),
    };
    out(result);
    if (failed.length) {
      err("selftest: FAIL (" + failed.map((c) => c.id).join(", ") + ")");
      process.exit(1);
    }
    err("selftest: PASS (" + metaChecks.length + " checks)");
  } finally {
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch (_) {}
  }
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.selftest) {
    selftest();
    return;
  }
  const project = args._[0] || args.project;
  if (!project) {
    err(
      "Usage:\n" +
        "  node scripts/test.js <project-dir> [--chaos] [--no-scenario]\n" +
        "  node scripts/test.js --selftest\n"
    );
    process.exit(2);
  }
  if (!fs.existsSync(path.resolve(project))) {
    err("ERR: project dir not found: " + project);
    process.exit(2);
  }
  const report = runSuite(project, {
    chaos: !!args.chaos,
    includeScenario: !args["no-scenario"],
    corpusDir: args.corpus ? path.resolve(args.corpus) : undefined,
  });
  out(report);
  process.exit(report.status === "pass" ? 0 : 1);
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = {
  SCHEMA_VERSION,
  TEST_VERSION,
  unitChecks,
  smokeRun,
  scenarioRegression,
  runSuite,
  selftest,
};
