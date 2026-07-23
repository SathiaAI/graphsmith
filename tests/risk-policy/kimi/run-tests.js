#!/usr/bin/env node
"use strict";

/**
 * tests/risk-policy/kimi/run-tests.js
 *
 * Adversarial test harness for scripts/capability-policy.js + scripts/risk-policy.json.
 * Lane: ONLY tests/risk-policy/kimi/.  ZERO external deps.  Uses temp dirs only.
 * Verdicts are taken from return values, never from log strings.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../../..");
const SHELL_ROOT = ROOT.replace(/\\/g, "/");
const CP = require(ROOT + "/scripts/capability-policy.js");
const RAW_POLICY = CP.loadPolicyRaw(CP.POLICY_PATH);

function compilePatterns(group) {
  return group.patterns.map((p) => ({ id: p.id, re: new RegExp(p.pattern, p.flags || "") }));
}

const COMPILED_EXTERNAL = compilePatterns(RAW_POLICY.external_call_patterns);
const COMPILED_UNPROVABLE = compilePatterns(RAW_POLICY.unprovable_constructs);
const MAX_SCAN_BYTES = ((RAW_POLICY.bounds || []).find((b) => b.id === "max_scan_input_bytes") || {}).value ?? Infinity;

let HEAL = null;
let HEAL_SOURCE = "";
try {
  HEAL = require(ROOT + "/scripts/heal.js");
  HEAL_SOURCE = fs.readFileSync(path.join(ROOT, "scripts", "heal.js"), "utf8");
} catch (e) {
  HEAL_SOURCE = fs.readFileSync(path.join(ROOT, "scripts", "heal.js"), "utf8");
}

const results = [];

function record(name, pass, detail) {
  results.push({ name, status: pass ? "PASS" : "FAIL", detail: detail || "" });
}

function recordSkip(name, detail) {
  results.push({ name, status: "SKIPPED", detail: detail || "" });
}

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "gs-kimi-risk-"));
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function assertShape(scan) {
  return (
    scan &&
    typeof scan.no_external_calls === "boolean" &&
    Array.isArray(scan.matched_patterns) &&
    Array.isArray(scan.unprovable)
  );
}

function expectIneligible(name, payload) {
  const scan = CP.capabilityScan([payload]);
  const ok = assertShape(scan) && scan.no_external_calls === false;
  record(
    name,
    ok,
    ok ? JSON.stringify(scan) : `expected ineligible, got ${JSON.stringify(scan)}`
  );
  return scan;
}

function expectEligible(name, payload) {
  const scan = CP.capabilityScan([payload]);
  const ok = assertShape(scan) && scan.no_external_calls === true;
  record(
    name,
    ok,
    ok ? JSON.stringify(scan) : `expected eligible, got ${JSON.stringify(scan)}`
  );
  return scan;
}

function expectClassification(name, target, want) {
  const c = CP.classifyRepair(target, "");
  const ok =
    c.repairClass === want.repairClass &&
    c.isManager === want.isManager &&
    c.kind === want.kind;
  record(name, ok, JSON.stringify({ target, got: c, want }));
  return c;
}

function extractHealPatterns(source, varName) {
  const re = new RegExp(
    varName + "\\s*=\\s*Object\\.freeze\\(\\s*(\\[[\\s\\S]*?\\])\\s*\\);"
  );
  const m = source.match(re);
  if (!m) return [];
  // The captured text is a JS array literal containing RegExp literals.  It
  // comes from a trusted local file, so a Function-scoped eval is acceptable.
  const arr = new Function("return " + m[1])();
  return Array.isArray(arr) ? arr : [];
}

/* ------------------------------------------------------------------------- */
/* 1. Fail-closed eligibility bypass attacks                                 */
/* ------------------------------------------------------------------------- */

function runAttackTests() {
  expectIneligible(
    "attack-fromcharcode-require",
    "const m = String.fromCharCode(114,101,113,117,105,114,101); globalThis[m]('http');"
  );

  expectIneligible(
    "attack-hex-escape-require",
    "const s = '\\x72\\x65\\x71\\x75\\x69\\x72\\x65'; globalThis[s]('http');"
  );

  expectIneligible(
    "attack-unicode-escape-dynamic-require",
    "const s = '\\u0072\\u0065\\u0071\\u0075\\u0069\\u0072\\u0065'; const m = require(s); m.get('x');"
  );

  expectIneligible(
    "attack-string-concat-require",
    "const r = globalThis['re'+'quire']; r('http');"
  );

  expectIneligible(
    "attack-template-assembly-require",
    "const mod = 'http'; const lib = require(`${mod}`); lib.get('x');"
  );

  expectIneligible(
    "attack-computed-member-exec",
    "const cp = require('child_process'); cp['exec']('whoami');"
  );

  expectIneligible(
    "attack-dynamic-require",
    "const m = 'http'; require(m).get('x');"
  );

  expectIneligible(
    "attack-dynamic-import",
    "const m = 'fs'; import(m).then(fs => fs.readFileSync('x'));"
  );

  expectIneligible(
    "attack-globalthis-fetch",
    "globalThis.fetch('http://x');"
  );

  expectIneligible(
    "attack-function-constructor",
    "const f = new Function('return require(\"http\").get(\"x\")'); f();"
  );

  expectIneligible(
    "attack-reflect-construct",
    "const Http = require('http'); const i = Reflect.construct(Http, []);"
  );

  // The spec says this MUST be caught (unprovable -> not eligible).
  expectIneligible(
    "attack-variable-indirection-require-alias",
    "const load = require; load('http').get('x');"
  );

  // Alias of a global that is itself an external call.
  expectIneligible(
    "attack-variable-indirection-fetch-alias",
    "const f = fetch; f('http://x');"
  );

  // Comment/whitespace trick: still an external dynamic require, but the
  // regex patterns must not be evaded by block-comment insertion.
  expectIneligible(
    "attack-comment-whitespace-require",
    "require /* external */ ('http').get('x');"
  );

  expectIneligible(
    "attack-comment-whitespace-fetch",
    "fetch /* external */ ('http://x');"
  );

  // Kitchen-sink obfuscation.
  expectIneligible(
    "attack-combined-obfuscation",
    "const h='ht'+'tp'; const r=globalThis[String.fromCharCode(114,101,113,117,105,114,101)]; r(h).get('x');"
  );

  // Legitimate data should stay eligible.
  expectEligible(
    "clean-prose-prompt",
    "You are a helpful assistant. Only answer safe questions."
  );

  expectEligible(
    "clean-tunables-json",
    '{ "max_retries": 3, "timeout_ms": 5000 }'
  );
}

/* ------------------------------------------------------------------------- */
/* 2. Manager / classification                                               */
/* ------------------------------------------------------------------------- */

function runClassificationTests() {
  const wantsManager = { repairClass: "code", isManager: true, kind: "manager" };
  expectClassification("manager-MANAGER.js", "MANAGER.js", wantsManager);
  expectClassification("manager-Manager.js", "Manager.js", wantsManager);
  expectClassification("manager-nested-manager.JS", "nested/manager.JS", wantsManager);
  expectClassification("manager-manager.cjs", "manager.cjs", wantsManager);
  expectClassification("manager-manager.mjs", "manager.mjs", wantsManager);
  expectClassification("manager-Manager.BOX.js", "Manager.BOX.js", wantsManager);

  expectClassification("non-manager-executable", "workers/process.js", {
    repairClass: "code",
    isManager: false,
    kind: "executable",
  });

  expectClassification("typed-md", "docs/readme.md", {
    repairClass: "typed",
    isManager: false,
    kind: "data",
  });

  expectClassification("typed-tunables", "tunables.json", {
    repairClass: "typed",
    isManager: false,
    kind: "tunables",
  });

  expectClassification("typed-scenario", "scenario.json", {
    repairClass: "typed",
    isManager: false,
    kind: "scenario",
  });

  expectClassification("typed-config-json", "app.config.json", {
    repairClass: "typed",
    isManager: false,
    kind: "config",
  });

  expectClassification("typed-workflow-manifest", "workflow.manifest.json", {
    repairClass: "typed",
    isManager: false,
    kind: "config",
  });

  expectClassification("typed-prompt", "workers/gather.prompt.md", {
    repairClass: "typed",
    isManager: false,
    kind: "prompt",
  });

  expectClassification("typed-ts-executable", "src/adapter.ts", {
    repairClass: "code",
    isManager: false,
    kind: "executable",
  });

  expectClassification("default-unknown", "binary.exe", {
    repairClass: "code",
    isManager: false,
    kind: "unknown-executable-surface",
  });
}

/* ------------------------------------------------------------------------- */
/* 3. Policy integrity                                                       */
/* ------------------------------------------------------------------------- */

function runPolicyIntegrityTests() {
  const shape = CP.validatePolicyShape(RAW_POLICY);
  record(
    "policy-shape-valid",
    shape.valid,
    shape.valid ? "" : shape.errors.join("; ")
  );

  record(
    "external-call-patterns-non-empty",
    Array.isArray(RAW_POLICY.external_call_patterns.patterns) &&
      RAW_POLICY.external_call_patterns.patterns.length > 0
  );

  record(
    "unprovable-constructs-non-empty",
    Array.isArray(RAW_POLICY.unprovable_constructs.patterns) &&
      RAW_POLICY.unprovable_constructs.patterns.length > 0
  );

  const allCompile = (() => {
    const groups = [
      RAW_POLICY.external_call_patterns.patterns,
      RAW_POLICY.unprovable_constructs.patterns,
    ];
    for (const list of groups) {
      for (const p of list) {
        try {
          new RegExp(p.pattern, p.flags || "");
        } catch (e) {
          return false;
        }
      }
    }
    return true;
  })();
  record("all-policy-patterns-compile", allCompile);

  const boundsOk = (() => {
    if (!Array.isArray(RAW_POLICY.bounds) || RAW_POLICY.bounds.length === 0) return false;
    return RAW_POLICY.bounds.every(
      (b) =>
        typeof b.id === "string" &&
        b.id.length > 0 &&
        typeof b.value === "number" &&
        Number.isFinite(b.value) &&
        typeof b.unit === "string" &&
        b.unit.length > 0
    );
  })();
  record("bounds-present-with-units", boundsOk);
}

/* ------------------------------------------------------------------------- */
/* 4. Oversized input fail-closed                                            */
/* ------------------------------------------------------------------------- */

function runOversizedTests() {
  const maxBytes = MAX_SCAN_BYTES;

  // Boundary: exactly max bytes must be rejected.
  const atBoundary = "A".repeat(maxBytes);
  const scanAt = CP.capabilityScan([atBoundary]);
  record(
    "oversized-at-boundary-fail-closed",
    scanAt.no_external_calls === false && scanAt.unprovable.includes("input-too-large"),
    JSON.stringify({ bytes: maxBytes, scan: scanAt })
  );

  // One byte under must be allowed when clean.
  const under = "A".repeat(maxBytes - 1);
  const scanUnder = CP.capabilityScan([under]);
  record(
    "oversized-one-under-clean-eligible",
    scanUnder.no_external_calls === true,
    JSON.stringify({ bytes: maxBytes - 1, scan: scanUnder })
  );

  // One byte over must be rejected.
  const over = "A".repeat(maxBytes + 1);
  const scanOver = CP.capabilityScan([over]);
  record(
    "oversized-one-over-fail-closed",
    scanOver.no_external_calls === false && scanOver.unprovable.includes("input-too-large"),
    JSON.stringify({ bytes: maxBytes + 1, scan: scanOver })
  );
}

/* ------------------------------------------------------------------------- */
/* 5. Consistency with heal.js                                               */
/* ------------------------------------------------------------------------- */

function runConsistencyTests() {
  if (!HEAL && !HEAL_SOURCE) {
    recordSkip("heal-consistency", "could not access heal.js");
    return;
  }

  // Every heal.js pattern id must exist in the policy with an equivalent regex.
  const policyExternalIds = new Map();
  for (const p of COMPILED_EXTERNAL) {
    policyExternalIds.set(p.id, p.re);
  }
  const policyUnprovableIds = new Map();
  for (const p of COMPILED_UNPROVABLE) {
    policyUnprovableIds.set(p.id, p.re);
  }

  const healExternal = extractHealPatterns(HEAL_SOURCE, "EXTERNAL_CALL_PATTERNS");
  const healUnprovable = extractHealPatterns(HEAL_SOURCE, "STATIC_UNPROVABLE_PATTERNS");

  let consistent = true;
  let detail = [];

  for (const p of healExternal) {
    const policyRe = policyExternalIds.get(p.id);
    if (!policyRe) {
      consistent = false;
      detail.push(`missing external id ${p.id}`);
    } else if (policyRe.toString() !== p.re.toString()) {
      consistent = false;
      detail.push(`divergent regex for ${p.id}: policy=${policyRe.toString()} heal=${p.re.toString()}`);
    }
  }

  for (const p of healUnprovable) {
    const policyRe = policyUnprovableIds.get(p.id);
    if (!policyRe) {
      consistent = false;
      detail.push(`missing unprovable id ${p.id}`);
    } else if (policyRe.toString() !== p.re.toString()) {
      consistent = false;
      detail.push(`divergent regex for ${p.id}: policy=${policyRe.toString()} heal=${p.re.toString()}`);
    }
  }

  record("heal-pattern-superset-consistent", consistent, detail.join("; "));

  // For a representative sample that heal fail-closes on, the policy must also
  // fail-close (no_external_calls === false).
  const healSamples = [
    "const fs = require('fs'); fs.readFileSync('x');",
    "const http = require('http'); http.get('x');",
    "const cp = require('child_process'); cp.exec('x');",
    "fetch('http://x');",
    "process.env.X;",
    "const m = 'fs'; require(m);",
    "eval('1');",
    "new Function('return 1');",
    "require('worker_threads');",
    "String.fromCharCode(97);",
    "const s = '\\x41';",
    "'a'+'b';",
    "const x = `${y}`;",
    "obj['x'];",
    "import('x');",
    "globalThis.x;",
    "Reflect.construct(X, []);",
  ];

  const healOk = HEAL
    ? healSamples.every((s) => HEAL.capabilityPolicyScan([s]).no_external_calls === false)
    : true;
  record("heal-representative-fail-closed", healOk);

  const policyOk = healSamples.every((s) => CP.capabilityScan([s]).no_external_calls === false);
  record("policy-matches-heal-representative-fail-closed", policyOk);
}

/* ------------------------------------------------------------------------- */
/* 6. Determinism                                                            */
/* ------------------------------------------------------------------------- */

function runDeterminismTests() {
  const payload = "const m = 'http'; require(m).get('x');";
  const first = JSON.stringify(CP.capabilityScan([payload]));
  let same = true;
  for (let i = 0; i < 10; i++) {
    const next = JSON.stringify(CP.capabilityScan([payload]));
    if (next !== first) {
      same = false;
      break;
    }
  }
  record("capabilityscan-deterministic", same);

  const target = "nested/MANAGER.js";
  const classFirst = JSON.stringify(CP.classifyRepair(target, ""));
  const classSame =
    JSON.stringify(CP.classifyRepair(target, "")) === classFirst;
  record("classifyrepair-deterministic", classSame);

  // No clock/random in result shape.
  const scan = CP.capabilityScan(["clean"]);
  const noTime = !JSON.stringify(scan).match(/\d{4}-\d{2}-\d{2}|Date|now|random/i);
  record("no-clock-or-random-in-scan", noTime);
}

/* ------------------------------------------------------------------------- */
/* 7. CLI smoke                                                              */
/* ------------------------------------------------------------------------- */

function runCliTests() {
  const dir = tempDir();
  try {
    const cli = spawnSync(process.execPath, [
      `${SHELL_ROOT}/scripts/capability-policy.js`,
      "--selftest",
    ], {
      cwd: dir,
      encoding: "utf8",
    });
    let parsed = null;
    try {
      parsed = JSON.parse(cli.stdout);
    } catch (_) {}
    const ok =
      cli.status === 0 &&
      parsed &&
      parsed.all_pass === true &&
      parsed.results &&
      Array.isArray(parsed.results) &&
      parsed.results.every((r) => r.pass === true);
    record(
      "cli-selftest-from-temp-dir",
      ok,
      JSON.stringify({ status: cli.status, stdout: cli.stdout.slice(0, 500), stderr: cli.stderr.slice(0, 200) })
    );
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
  }
}

/* ------------------------------------------------------------------------- */
/* Main                                                                      */
/* ------------------------------------------------------------------------- */

function main() {
  runPolicyIntegrityTests();
  runAttackTests();
  runClassificationTests();
  runOversizedTests();
  runConsistencyTests();
  runDeterminismTests();
  runCliTests();

  const pass = results.filter((r) => r.status === "PASS").length;
  const fail = results.filter((r) => r.status === "FAIL").length;
  const skip = results.filter((r) => r.status === "SKIPPED").length;

  console.log("=== Kimi risk-policy adversarial test run ===");
  for (const r of results) {
    console.log(`${r.status.padEnd(8)} ${r.name}${r.detail ? " | " + r.detail : ""}`);
  }
  console.log(`---`);
  console.log(`PASS=${pass} FAIL=${fail} SKIPPED=${skip}`);
  console.log(`EXIT: ${fail > 0 ? "1" : "0"}`);

  if (fail > 0) process.exitCode = 1;
}

main();
