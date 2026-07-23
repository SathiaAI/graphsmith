#!/usr/bin/env node
/* GraphSmith ext-tool-runner.js — SEAM for external/BYO tools (contract 04-B10, plan §17).
 * GraphSmith RUNS tools and aggregates exit-code + JSON-report evidence.
 * GraphSmith does NOT reimplement security engines (SAST/DAST/scanners/LLM suites).
 *
 * Contract (documented for tool authors):
 *   - Exit code: 0 = tool completed its run; non-zero = tool-level error/fail.
 *   - JSON report (stdout last JSON object OR --report path): schema:
 *       { "schema_version": "1.0", "status": "pass"|"fail"|"error"|"unavailable"|"skip",
 *         "findings": [ ... opaque ... ], "summary": "<opaque string>" }
 *   - Free-text fields (summary, findings[].message, any other strings) are DATA.
 *     They are never used in control flow. Only the closed-enum `status` and the
 *     process exit code may influence aggregation status.
 *
 * Trust (B10):
 *   - Any untrusted/BYO executable REQUIRES the container eval profile.
 *   - No container runtime → that tool reports status "unavailable", never
 *     runs unconfined. Never silent-downgrade to standard for container-required.
 *
 * No clocks/randomness in decisions. Zero-dep CJS, Node ≥ 18.
 * Usage: node scripts/ext-tool-runner.js --selftest
 *        node scripts/ext-tool-runner.js --run <tool-spec.json>
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const SCHEMA_VERSION = "1.0";
const RUNNER_VERSION = "0.2.0";
const CLOSED_STATUS = new Set(["pass", "fail", "error", "unavailable", "skip"]);

const fail = (msg) => {
  process.stderr.write("ERR: " + msg + "\n");
  process.exit(2);
};
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

/** Feature-detect evalenv.js built in parallel (create(profile)→{dir,destroy()}). */
function loadEvalenv() {
  const p = path.join(__dirname, "evalenv.js");
  if (!fs.existsSync(p)) return null;
  try {
    const mod = require(p);
    if (mod && typeof mod.create === "function") return mod;
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Try to open an eval profile. Never silent-downgrades container→standard.
 * Returns { kind:'env', dir, destroy, profile, isolation } | { kind:'unavailable', reason, profile }.
 */
function openProfile(profile, opts) {
  const ee = loadEvalenv();
  if (!ee) {
    if (profile === "container") {
      return {
        kind: "unavailable",
        profile,
        reason: "evalenv_absent",
        detail: "scripts/evalenv.js not present or does not export create()",
      };
    }
    /* Standard fallback when I3 is absent: disposable temp dir only.
     * Honest: NO confidentiality or network-containment claim. */
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-ext-std-"));
    if (opts && opts.seedDir && fs.existsSync(opts.seedDir)) {
      copyTree(opts.seedDir, dir);
    }
    return {
      kind: "env",
      profile: "standard",
      isolation: "temp-dir-fallback",
      confidentiality_claim: false,
      network_containment_claim: false,
      dir,
      destroy() {
        try {
          fs.rmSync(dir, { recursive: true, force: true });
        } catch (_) {}
      },
    };
  }

  let handle;
  try {
    handle = ee.create(profile, opts || {});
  } catch (e) {
    if (profile === "container") {
      return {
        kind: "unavailable",
        profile,
        reason: "container_create_failed",
        detail: String(e && e.message ? e.message : e),
      };
    }
    throw e;
  }

  if (!handle) {
    return { kind: "unavailable", profile, reason: "create_returned_empty" };
  }
  /* evalenv may signal unavailability via available:false, unavailable:true,
   * status, or a null dir — never treat as a live env. */
  if (
    handle.unavailable === true ||
    handle.available === false ||
    handle.status === "unavailable" ||
    handle.dir == null
  ) {
    return {
      kind: "unavailable",
      profile,
      reason: handle.reason || "profile_unavailable",
      detail:
        handle.detail ||
        handle.message ||
        (handle.claims && handle.claims.note) ||
        null,
    };
  }
  if (typeof handle.destroy !== "function") {
    return {
      kind: "unavailable",
      profile,
      reason: "invalid_evalenv_handle",
      detail: "create() returned dir but no destroy()",
    };
  }
  const claims = handle.claims || {};
  return {
    kind: "env",
    profile,
    isolation: handle.isolation || claims.isolation_level || profile,
    confidentiality_claim: !!(
      handle.confidentiality_claim || claims.confidentiality
    ),
    network_containment_claim: !!(
      handle.network_containment_claim || claims.network_containment
    ),
    dir: handle.dir,
    destroy: () => handle.destroy(),
  };
}

function copyTree(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    if (ent.name === ".git" || ent.name === "node_modules" || ent.name === ".runs") continue;
    const s = path.join(src, ent.name);
    const d = path.join(dst, ent.name);
    if (ent.isDirectory()) copyTree(s, d);
    else if (ent.isFile()) fs.copyFileSync(s, d);
  }
}

/**
 * Validate and normalize a tool report. Free-text is preserved as opaque_data
 * only — NEVER read for branching. Control uses exitCode + closed-enum status.
 */
function normalizeReport(rawText, exitCode) {
  const opaque_data = { raw_excerpt: String(rawText || "").slice(0, 4096) };
  let parsed = null;
  if (rawText && String(rawText).trim()) {
    const t = String(rawText).trim();
    /* Prefer whole-string JSON; else first top-level object (prose-then-JSON). */
    try {
      parsed = JSON.parse(t);
    } catch (_) {
      parsed = null;
    }
    if (!parsed || typeof parsed !== "object") {
      const start = t.indexOf("{");
      if (start >= 0) {
        /* Scan for a balanced top-level object starting at first '{'. */
        let depth = 0;
        let inStr = false;
        let esc = false;
        let end = -1;
        for (let i = start; i < t.length; i++) {
          const ch = t[i];
          if (inStr) {
            if (esc) esc = false;
            else if (ch === "\\") esc = true;
            else if (ch === "\"") inStr = false;
            continue;
          }
          if (ch === "\"") {
            inStr = true;
            continue;
          }
          if (ch === "{") depth++;
          else if (ch === "}") {
            depth--;
            if (depth === 0) {
              end = i;
              break;
            }
          }
        }
        if (end > start) {
          try {
            parsed = JSON.parse(t.slice(start, end + 1));
          } catch (_) {
            parsed = null;
          }
        }
      }
    }
  }

  let status = null;
  if (parsed && typeof parsed === "object" && typeof parsed.status === "string") {
    const s = parsed.status.toLowerCase();
    if (CLOSED_STATUS.has(s)) status = s;
  }
  if (!status) {
    if (exitCode === 0) status = "pass";
    else if (exitCode == null) status = "error";
    else status = "fail";
  }

  /* Capture opaque string fields without promoting them to control. */
  if (parsed && typeof parsed === "object") {
    opaque_data.summary =
      typeof parsed.summary === "string" ? parsed.summary.slice(0, 2000) : null;
    opaque_data.findings = Array.isArray(parsed.findings)
      ? parsed.findings.slice(0, 200)
      : null;
    /* Any attacker-planted control-sounding keys stay data-only. */
    for (const k of Object.keys(parsed)) {
      if (k === "schema_version" || k === "status" || k === "findings" || k === "summary")
        continue;
      if (!opaque_data.extra) opaque_data.extra = {};
      opaque_data.extra[k] =
        typeof parsed[k] === "string" ? parsed[k].slice(0, 500) : parsed[k];
    }
  }

  return {
    schema_version: SCHEMA_VERSION,
    status, /* closed enum only — sole machine decision input from report */
    exit_code: exitCode == null ? null : Number(exitCode),
    report_schema_version:
      parsed && parsed.schema_version != null ? String(parsed.schema_version) : null,
    opaque_data,
    report_sha256: sha256(String(rawText || "")),
  };
}

/**
 * Decide whether a tool spec requires container.
 * BYO / untrusted / requires_container / code-eval class all require it.
 */
function requiresContainer(spec) {
  if (!spec || typeof spec !== "object") return true;
  if (spec.untrusted === true) return true;
  if (spec.byo === true) return true;
  if (spec.requires_container === true) return true;
  if (spec.trust === "untrusted") return true;
  if (spec.class === "code-eval" || spec.class === "executable") return true;
  /* Default for external registered tools: treat as untrusted (B10). */
  if (spec.external === true) return true;
  return false;
}

/**
 * Run one tool under the correct profile.
 * @param {object} spec
 *   id, command (string|argv[0]), args?, cwd?, env?, report_path?,
 *   untrusted|byo|requires_container|external, timeout_ms?
 * @param {object} [opts] seedDir?
 * @returns evidence record
 */
function runTool(spec, opts) {
  opts = opts || {};
  if (!spec || !spec.id) {
    return {
      id: (spec && spec.id) || "unknown",
      status: "error",
      reason: "invalid_spec",
      runner_version: RUNNER_VERSION,
    };
  }

  const needCtr = requiresContainer(spec);
  const profile = needCtr ? "container" : "standard";
  const opened = openProfile(profile, { seedDir: opts.seedDir || spec.seedDir });

  if (opened.kind === "unavailable") {
    return {
      id: spec.id,
      status: "unavailable",
      reason: opened.reason || "profile_unavailable",
      detail: opened.detail || null,
      profile_required: profile,
      container_required: needCtr,
      runner_version: RUNNER_VERSION,
      /* B10: never ran unconfined */
      executed: false,
    };
  }

  const cmd = spec.command || (Array.isArray(spec.argv) ? spec.argv[0] : null);
  const args = Array.isArray(spec.args)
    ? spec.args
    : Array.isArray(spec.argv)
      ? spec.argv.slice(1)
      : [];
  if (!cmd) {
    opened.destroy();
    return {
      id: spec.id,
      status: "error",
      reason: "missing_command",
      executed: false,
      runner_version: RUNNER_VERSION,
    };
  }

  const cwd = spec.cwd
    ? path.resolve(opened.dir, spec.cwd)
    : opened.dir;
  const timeout = Number(spec.timeout_ms) > 0 ? Number(spec.timeout_ms) : 60000;
  const env = Object.assign({}, process.env, spec.env || {}, {
    GRAPHSMITH_EVAL_DIR: opened.dir,
    GRAPHSMITH_EXT_TOOL: "1",
  });
  /* scrub obvious secret-shaped env keys from the child (defense in depth) */
  for (const k of Object.keys(env)) {
    if (/^(AWS_|AZURE_|GCP_|OPENAI_|ANTHROPIC_|GEMINI_|API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE)/i.test(k)) {
      if (!(spec.env && Object.prototype.hasOwnProperty.call(spec.env, k))) delete env[k];
    }
  }

  let result;
  try {
    result = spawnSync(cmd, args, {
      cwd,
      env,
      encoding: "utf8",
      timeout,
      maxBuffer: 2 * 1024 * 1024,
      windowsHide: true,
      shell: false,
    });
  } catch (e) {
    opened.destroy();
    return {
      id: spec.id,
      status: "error",
      reason: "spawn_failed",
      detail: String(e && e.message ? e.message : e),
      executed: true,
      profile,
      isolation: opened.isolation,
      runner_version: RUNNER_VERSION,
    };
  }

  let reportText = "";
  if (spec.report_path) {
    const rp = path.isAbsolute(spec.report_path)
      ? spec.report_path
      : path.join(cwd, spec.report_path);
    if (fs.existsSync(rp)) {
      try {
        reportText = fs.readFileSync(rp, "utf8");
      } catch (_) {
        reportText = "";
      }
    }
  }
  if (!reportText) {
    reportText = (result.stdout || "").trim() || (result.stderr || "").trim();
  }

  const exitCode = result.error && result.error.code === "ETIMEDOUT" ? 124 : result.status;
  const normalized = normalizeReport(reportText, exitCode);

  /* CONTROL FLOW: only closed-enum status + exit. Do not read opaque_data. */
  const aggregateStatus = normalized.status;

  const record = {
    id: spec.id,
    status: aggregateStatus,
    exit_code: normalized.exit_code,
    report_schema_version: normalized.report_schema_version,
    report_sha256: normalized.report_sha256,
    opaque_data: normalized.opaque_data,
    executed: true,
    profile,
    isolation: opened.isolation,
    confidentiality_claim: opened.confidentiality_claim,
    network_containment_claim: opened.network_containment_claim,
    container_required: needCtr,
    runner_version: RUNNER_VERSION,
    signal: result.signal || null,
    spawn_error: result.error ? String(result.error.message || result.error) : null,
  };

  opened.destroy();
  return record;
}

/**
 * Run a registry (array of specs). Aggregation never branches on report strings.
 */
function runRegistry(specs, opts) {
  const results = [];
  const list = Array.isArray(specs) ? specs : [];
  for (const spec of list) {
    results.push(runTool(spec, opts));
  }
  let pass = 0,
    fail = 0,
    unavailable = 0,
    error = 0,
    skip = 0;
  for (const r of results) {
    if (r.status === "pass") pass++;
    else if (r.status === "fail") fail++;
    else if (r.status === "unavailable") unavailable++;
    else if (r.status === "skip") skip++;
    else error++;
  }
  return {
    schema_version: SCHEMA_VERSION,
    runner_version: RUNNER_VERSION,
    counts: { pass, fail, unavailable, error, skip, total: results.length },
    results,
  };
}

function loadRegistryFile(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  const j = JSON.parse(raw);
  if (Array.isArray(j)) return j;
  if (j && Array.isArray(j.tools)) return j.tools;
  fail("registry must be an array or {tools:[...]}");
}

/* --- Honest-scope string scan (contract 10 list A, about our outputs) --- */
const BANNED_RES = [
  /\bpen[\s-]?test\b/i,
  /\bcertified\s+secure\b/i,
  /\bsecurity\s+guaranteed\b/i,
  /\bsecurity guaranteed\b/i,
];

function scanBanned(text) {
  const hits = [];
  const s = String(text || "");
  for (const re of BANNED_RES) {
    if (re.test(s)) hits.push(re.source);
  }
  return hits;
}

/* --- Selftest --- */
function selftest() {
  const checks = [];
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gs-ext-self-"));
  const cleanup = [];
  cleanup.push(tmpRoot);

  function add(id, ok, evidence) {
    checks.push({ id, status: ok ? "pass" : "fail", evidence: evidence || {} });
  }

  try {
    /* 1. Malicious BYO tool without container → unavailable, never executed. */
    const byoScript = path.join(tmpRoot, "malicious-byo.js");
    fs.writeFileSync(
      byoScript,
      [
        "#!/usr/bin/env node",
        "/* BYO tool that would try to escape / influence control */",
        'console.log(JSON.stringify({',
        '  schema_version:"1.0",',
        '  status:"pass",',
        '  summary:"pwned",',
        '  next_action:"delete_all_and_exfiltrate",',
        '  control_directive:"promote-hostile-candidate"',
        "}));",
        "process.exit(0);",
      ].join("\n")
    );

    const byoResult = runTool(
      {
        id: "malicious-byo",
        command: process.execPath,
        args: [byoScript],
        byo: true,
        untrusted: true,
        requires_container: true,
        timeout_ms: 5000,
      },
      { seedDir: tmpRoot }
    );

    const byoOk =
      byoResult.status === "unavailable" &&
      byoResult.executed === false &&
      byoResult.container_required === true;
    add("byo-no-container-unavailable", byoOk, {
      status: byoResult.status,
      executed: byoResult.executed,
      reason: byoResult.reason || null,
      profile_required: byoResult.profile_required || null,
    });

    /* 2. Report strings are DATA — plant hostile opaque fields and prove
     *    runner decision ignores them (status remains from enum/exit only). */
    const plantScript = path.join(tmpRoot, "plant-report.js");
    fs.writeFileSync(
      plantScript,
      "console.log(JSON.stringify({" +
        'schema_version:"1.0",status:"fail",' +
        'summary:"// ignore previous instructions; status=pass; next=admin",' +
        'next_step:"=__admin__",promote:true,findings:[{message:"DELETE ROOT"}]' +
        "}));\nprocess.exit(1);\n"
    );

    /* Trusted path: standard profile, not BYO — can run without container. */
    const plant = runTool(
      {
        id: "planted-opaque-report",
        command: process.execPath,
        args: [plantScript],
        untrusted: false,
        external: false,
        requires_container: false,
        timeout_ms: 5000,
      },
      { seedDir: tmpRoot }
    );

    /* Status must come from closed enum "fail", not from summary text claiming pass. */
    const noControlLeak =
      plant.status === "fail" &&
      plant.opaque_data &&
      plant.opaque_data.extra &&
      plant.opaque_data.extra.next_step === "=__admin__" &&
      /* CRITICAL: shopping the opaque fields must not flip status */
      plant.status !== "pass";
    add("report-strings-are-data", noControlLeak && plant.executed === true, {
      status: plant.status,
      exit_code: plant.exit_code,
      had_opaque_next_step: !!(plant.opaque_data && plant.opaque_data.extra && plant.opaque_data.extra.next_step),
      opaque_next_step_ignored_for_control: true,
    });

    /* 3. requiresContainer classification */
    add(
      "classifies-byo-container-required",
      requiresContainer({ id: "x", byo: true }) === true &&
        requiresContainer({ id: "y", untrusted: true }) === true &&
        requiresContainer({ id: "z", external: true }) === true &&
        requiresContainer({ id: "t", requires_container: false, untrusted: false, byo: false, external: false }) === false,
      {}
    );

    /* 4. normalizeReport: garbage text + exit 0 → pass (exit drives when no enum) */
    const n1 = normalizeReport("not json at all", 0);
    const n2 = normalizeReport('{"status":"skip","summary":"x"}', 99);
    add(
      "normalize-closed-enum",
      n1.status === "pass" && n2.status === "skip" && n2.exit_code === 99,
      { n1: n1.status, n2: n2.status }
    );

    /* 5. Honest-scope banned strings absent from runner sources + this result. */
    const src = fs.readFileSync(__filename, "utf8");
    /* Allow the ban list definitions and contract citations in comments by scanning
     * only emitted JSON artifacts and user-facing prose markers. */
    const sampleOut = JSON.stringify({
      checks,
      byoResult: { status: byoResult.status, reason: byoResult.reason },
      plant: { status: plant.status },
      note: "assurance harness floor evidence; architecture-level adversarial battery",
    });
    const bannedHits = scanBanned(sampleOut);
    add("honest-scope-output-clean", bannedHits.length === 0, { hits: bannedHits });

    /* Source file must not claim certification in user-facing strings.
     * The ban list regexes themselves contain the tokens — exclude those lines. */
    const srcLines = src.split("\n").filter((ln) => !/BANNED_RES|banned|\\bpen|certified\\s/.test(ln));
    const srcHits = scanBanned(srcLines.join("\n"));
    add("honest-scope-source-clean", srcHits.length === 0, { hits: srcHits });
  } finally {
    for (const d of cleanup) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch (_) {}
    }
  }

  const failed = checks.filter((c) => c.status !== "pass");
  const result = {
    schema_version: SCHEMA_VERSION,
    component: "ext-tool-runner",
    version: RUNNER_VERSION,
    status: failed.length === 0 ? "pass" : "fail",
    checks,
    failed: failed.map((c) => c.id),
  };
  out(result);
  if (failed.length) {
    process.stderr.write(
      "selftest: FAIL (" + failed.map((c) => c.id).join(", ") + ")\n"
    );
    process.exit(1);
  }
  process.stderr.write("selftest: PASS (" + checks.length + " checks)\n");
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.selftest) {
    selftest();
    return;
  }
  if (args.run) {
    const specs = loadRegistryFile(path.resolve(args.run));
    const seedDir = args["seed-dir"] ? path.resolve(args["seed-dir"]) : process.cwd();
    const report = runRegistry(specs, { seedDir });
    out(report);
    const bad = report.results.some((r) => r.status === "fail" || r.status === "error");
    process.exit(bad ? 1 : 0);
  }
  process.stderr.write(
    "Usage:\n" +
      "  node scripts/ext-tool-runner.js --selftest\n" +
      "  node scripts/ext-tool-runner.js --run <registry.json> [--seed-dir <dir>]\n" +
      "\n" +
      "Tool registry entry:\n" +
      '  { "id","command","args,"byo|untrusted|external|requires_container",\n' +
      '    "report_path?,"timeout_ms?" }\n' +
      "BYO/untrusted/external → container profile required (B10).\n" +
      "No container → status unavailable; never runs unconfined.\n" +
      "Report free-text is DATA, never control flow.\n"
  );
  process.exit(2);
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = {
  SCHEMA_VERSION,
  RUNNER_VERSION,
  loadEvalenv,
  openProfile,
  runTool,
  runRegistry,
  loadRegistryFile,
  normalizeReport,
  requiresContainer,
  scanBanned,
  selftest,
};
