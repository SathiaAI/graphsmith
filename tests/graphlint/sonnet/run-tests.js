#!/usr/bin/env node
/* Adversarial + regression test suite for scripts/graphlint.js R5/R6 — sonnet lane.
 * Zero-dependency CJS. Drives graphlint ONLY via its CLI (node scripts/graphlint.js <path>)
 * against temp-dir fixtures created here; never imports or mutates graphlint.js.
 * One line per case: [PASS]/[FAIL]/[SKIPPED] + reason. Exit 1 if ANY FAIL.
 *
 * Two of the cases below (marked [DEFECT]) assert the CORRECT, spec-derived behavior for
 * R5's scope and are EXPECTED to FAIL against the current graphlint.js — that failure IS
 * the finding. See FINDINGS.md for the full citation and fix recommendation. */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const GRAPHLINT = path.join(REPO_ROOT, "scripts", "graphlint.js");

/* ---- infra ---- */

let passCount = 0, failCount = 0, skipCount = 0;

function report(name, status, detail) {
  const line = `[${status}] ${name}` + (detail ? ` -- ${detail}` : "");
  console.log(line);
  if (status === "PASS") passCount++;
  else if (status === "FAIL") failCount++;
  else skipCount++;
}

function test(name, fn) {
  try {
    fn();
    report(name, "PASS");
  } catch (e) {
    report(name, "FAIL", e.message);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function writeFile(root, rel, lines) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, lines.join("\n") + "\n", "utf8");
  return p;
}

/* Parse graphlint's scan-mode stdout ("[SEVERITY] file:line  rule\n        fix: ...")
 * into structured findings. graphlint's scan mode never exits non-zero on findings
 * (only --selftest does), so we always read stdout, not the exit code. */
function parseFindings(stdout) {
  const findings = [];
  const re = /^\[(HIGH|MEDIUM|REVIEW)\]\s+(.+?):(\d+)\s+(.+)$/;
  for (const ln of stdout.split("\n")) {
    const m = ln.match(re);
    if (m) findings.push({ severity: m[1], file: m[2], line: Number(m[3]), rule: m[4] });
  }
  return findings;
}

function runGraphlint(target) {
  let stdout;
  try {
    stdout = execFileSync(process.execPath, [GRAPHLINT, target], { encoding: "utf8" });
  } catch (e) {
    stdout = (e.stdout || "") + (e.stderr || "");
  }
  return { stdout, findings: parseFindings(stdout) };
}

function byRule(findings, prefix) {
  return findings.filter((f) => f.rule.startsWith(prefix));
}

/* ============================== R5 recall ============================== */

test("R5-recall-eval: eval(code) flagged HIGH at the call site", () => {
  const dir = tmpDir("gl-r5-eval");
  writeFile(dir, "candidate.js", [
    "/* evolvable candidate fixture */",
    "module.exports.run = (code) => {",
    "  return eval(code);",
    "};",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: eval()") && f.severity === "HIGH" && f.line === 3);
  assert(hits.length === 1, `expected exactly 1 R5 eval() HIGH at line 3, got ${JSON.stringify(findings)}`);
});

test("R5-recall-new-Function: new Function(...) flagged HIGH at the call site", () => {
  const dir = tmpDir("gl-r5-newfn");
  writeFile(dir, "candidate.js", [
    "module.exports.compile = (body) => {",
    '  return new Function("x", body);',
    "};",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: new Function()") && f.severity === "HIGH" && f.line === 2);
  assert(hits.length === 1, `expected exactly 1 R5 new Function() HIGH at line 2, got ${JSON.stringify(findings)}`);
});

test("R5-recall-Function-ctor: Function(\"...\") string-arg constructor flagged REVIEW", () => {
  const dir = tmpDir("gl-r5-fnctor");
  writeFile(dir, "candidate.js", [
    "module.exports.compile2 = (body) => {",
    '  return Function("return " + body);',
    "};",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: Function() used") && f.severity === "REVIEW" && f.line === 2);
  assert(hits.length === 1, `expected exactly 1 R5 Function()-ctor REVIEW at line 2, got ${JSON.stringify(findings)}`);
});

test("R5-recall-exec-spawn: child_process execSync() call flagged HIGH", () => {
  const dir = tmpDir("gl-r5-exec");
  writeFile(dir, "candidate.js", [
    'const { execSync } = require("child_process");',
    "module.exports.run = () => {",
    '  execSync("echo hi");',
    "};",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: child_process") && f.severity === "HIGH" && f.line === 3);
  assert(hits.length === 1, `expected exactly 1 R5 child_process HIGH at line 3, got ${JSON.stringify(findings)}`);
});

test("R5-recall-new-require: require() of a non-builtin module seen in only 1 file flagged REVIEW", () => {
  const dir = tmpDir("gl-r5-newreq");
  writeFile(dir, "candidate.js", [
    'const totallyFakePkg9x2 = require("totally-fake-pkg-9x2");',
    "module.exports.use = () => totallyFakePkg9x2;",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: new-require(") && f.severity === "REVIEW" && f.line === 1);
  assert(hits.length === 1, `expected exactly 1 R5 new-require REVIEW at line 1, got ${JSON.stringify(findings)}`);
});

test("R5-recall-dynamic-import: import(\"static-spec\") flagged HIGH", () => {
  const dir = tmpDir("gl-r5-dynimp");
  writeFile(dir, "candidate.js", [
    "async function load() {",
    '  return import("totally-fake-dyn-mod-9x2");',
    "}",
    "module.exports.load = load;",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: dynamic import(\"") && f.severity === "HIGH" && f.line === 2);
  assert(hits.length === 1, `expected exactly 1 R5 dynamic-import HIGH at line 2, got ${JSON.stringify(findings)}`);
});

test("R5-recall-dynamic-import-computed: import(variable) flagged HIGH", () => {
  const dir = tmpDir("gl-r5-dynimpc");
  writeFile(dir, "candidate.js", [
    "async function loadDyn(name) {",
    "  return import(name);",
    "}",
    "module.exports.loadDyn = loadDyn;",
  ]);
  const { findings } = runGraphlint(dir);
  const hits = findings.filter((f) => f.rule.startsWith("R5: dynamic import(computed)") && f.severity === "HIGH" && f.line === 2);
  assert(hits.length === 1, `expected exactly 1 R5 dynamic-import(computed) HIGH at line 2, got ${JSON.stringify(findings)}`);
});

/* ============================== R5 precision (bare-view discipline) ============================== */

test("R5-precision-comment-bait: eval/new-Function/exec/require/import tokens in comments do NOT fire", () => {
  const dir = tmpDir("gl-r5-commentbait");
  const f = writeFile(dir, "candidate.js", [
    '// eval() is dangerous, and so is new Function(body), execSync("rm -rf /"), and require("malicious-pkg").',
    '/* import("also-fake") should not fire either. */',
    'const fs = require("fs");',
    'module.exports.safe = () => fs.existsSync(".");',
  ]);
  const { findings, stdout } = runGraphlint(f);
  const r5 = byRule(findings, "R5");
  assert(r5.length === 0, `comment-only bait must not create an R5 finding, got: ${JSON.stringify(r5)}\n${stdout}`);
});

test("R5-precision-string-bait: eval/new-Function/exec/require/import tokens in string literals do NOT fire", () => {
  const dir = tmpDir("gl-r5-stringbait");
  const f = writeFile(dir, "candidate.js", [
    'const fs = require("fs");',
    'const WARNING = "Do not call eval(userInput), new Function(body), execSync(cmd), require(\'pkg\'), or import(\'mod\') here.";',
    'module.exports.safe = () => { return fs.existsSync(".") && WARNING.length > 0; };',
  ]);
  const { findings, stdout } = runGraphlint(f);
  const r5 = byRule(findings, "R5");
  assert(r5.length === 0, `string-only bait must not create an R5 finding, got: ${JSON.stringify(r5)}\n${stdout}`);
});

test("R5-precision-clean: builtin-only requires produce zero R5 findings", () => {
  const dir = tmpDir("gl-r5-clean");
  const f = writeFile(dir, "candidate.js", [
    'const fs = require("fs");',
    'const path = require("path");',
    "module.exports.join = (a, b) => path.join(a, b);",
  ]);
  const { findings } = runGraphlint(f);
  const r5 = byRule(findings, "R5");
  assert(r5.length === 0, `clean builtin-only file must have zero R5 findings, got: ${JSON.stringify(r5)}`);
});

test("R5-precision-self: graphlint.js's own R5 regex literals (eval, new Function, exec, spawn, require, import as bare source text) do not self-trip", () => {
  const { findings, stdout } = runGraphlint(GRAPHLINT);
  const r5 = byRule(findings, "R5");
  assert(r5.length === 0, `graphlint.js must not flag itself under R5 (its own corpus/regex literals contain these tokens as text), got: ${JSON.stringify(r5)}\n${stdout}`);
});

/* ============================== R6 recall / precision ============================== */

test("R6-recall: an adapter with an external effect and NO capability.json is flagged HIGH", () => {
  const dir = tmpDir("gl-r6-undeclared");
  writeFile(dir, "adapters/notify.js", [
    'const axios = require("axios");',
    'module.exports.send = (payload) => axios.post("https://example.com/hook", payload);',
  ]);
  const { findings } = runGraphlint(dir);
  const r6 = byRule(findings, "R6");
  const hit = r6.find((f) => f.file === "adapters/notify.js" && f.severity === "HIGH" && f.line === 1);
  assert(hit, `expected R6 HIGH on adapters/notify.js:1, got: ${JSON.stringify(r6)}`);
});

test("R6-precision: an adapter with a matching *.capability.json declared is clean", () => {
  const dir = tmpDir("gl-r6-declared");
  writeFile(dir, "adapters/notify.js", [
    'const axios = require("axios");',
    'module.exports.send = (payload) => axios.post("https://example.com/hook", payload);',
  ]);
  writeFile(dir, "adapters/notify.capability.json", [
    "{",
    '  "schema_version": "1.0",',
    '  "adapter_id": "notify",',
    '  "version": "1.0.0",',
    '  "effects": [',
    '    { "effect_id": "send", "effect_type": "external", "capability": { "type": "none" },',
    '      "destinations": ["https://example.com/hook"], "rate_cap_per_run": 1 }',
    "  ]",
    "}",
  ]);
  const { findings } = runGraphlint(dir);
  const r6 = byRule(findings, "R6");
  assert(r6.length === 0, `declared adapter must have zero R6 findings, got: ${JSON.stringify(r6)}`);
});

/* ============================== Regression: R1-R4 corpus (--selftest) ============================== */

test("regression-selftest: node scripts/graphlint.js --selftest is 100% green (R1-R4 corpus, no regression from R5/R6)", () => {
  let stdout, code = 0;
  try {
    stdout = execFileSync(process.execPath, [GRAPHLINT, "--selftest"], { encoding: "utf8" });
  } catch (e) {
    code = e.status;
    stdout = (e.stdout || "") + (e.stderr || "");
  }
  assert(code === 0, `--selftest exited ${code} (non-zero means a probe failed):\n${stdout}`);
  assert(!/❌/.test(stdout), `--selftest reported at least one failing probe:\n${stdout}`);
  assert(/0 failure\(s\)/.test(stdout), `--selftest summary did not report "0 failure(s)":\n${stdout}`);
});

/* ============================== THE KEY QUESTION: R5 scope ============================== */
/* Position (see FINDINGS.md for full citation): R5 is evolvable-scoped by design --
 * it must ban eval/new Function/exec/new-require in machine-evaluated candidates and
 * scaffold-generated adapters, NOT in GraphSmith's own hash-pinned constitutional
 * scripts, which legitimately use child_process to orchestrate (spawn replay runs,
 * kill/watch processes, spawn scenario, spawn workers). The following assertion
 * encodes that correct behavior and is EXPECTED TO FAIL against the current
 * unscoped implementation -- the failure is the reported defect. */

test("R5-scope [DEFECT]: R5 must not HIGH-flag legitimate child_process use in hash-pinned constitutional scripts/ files", () => {
  const { findings } = runGraphlint(path.join(REPO_ROOT, "scripts"));
  const constitutionalFiles = /^(chaos|scenario|watchdog|gate|scaffold|ci-check-pr-separation)\.js$/;
  const overFires = findings.filter(
    (f) => f.rule.startsWith("R5: child_process") && f.severity === "HIGH" && constitutionalFiles.test(f.file)
  );
  assert(
    overFires.length === 0,
    `R5 fires ${overFires.length}x HIGH on constitutional scripts' legitimate child_process orchestration ` +
      `(scenario spawns replay, watchdog kills processes, gate spawns scenario, scaffold spawns workers, ` +
      `chaos/ci-check-pr-separation spawn subprocesses for testing/CI). Per .plans/tasks/B-graphlint.md:11 ` +
      `("child_process exec/execSync/spawn* introduced in a DECISION/EVOLVABLE FILE") and ` +
      `.plans/graphsmith-v0.2.0-final-build-plan.md:104 ("bans ... raw exec in MACHINE-EVALUATED CANDIDATES ` +
      `AND IN SCAFFOLD ADAPTERS"), R5's child_process check is scoped to evolvable/candidate code -- not the ` +
      `constitutional orchestration layer itself. Offending: ${overFires.map((f) => f.file + ":" + f.line).join(", ")}`
  );
});

/* ============================== Dogfood: classify every finding on scripts/ ============================== */

function classifyDogfoodFinding(f) {
  const constitutionalFiles = /^(chaos|scenario|watchdog|gate|scaffold|ci-check-pr-separation)\.js$/;
  if (f.rule.startsWith("R5: child_process") && constitutionalFiles.test(f.file))
    return "scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)";
  if (f.rule.startsWith("R4:") && f.file === "scenario.js" && (f.line === 640 || f.line === 644))
    return "FALSE-POSITIVE (cross-function taint-variable name collision; see FINDINGS.md D2)";
  return "true-positive (unclassified default -- verify manually if this appears)";
}

test("dogfood-classify: every finding from `graphlint scripts/` is classified TP/FP/scope-question", () => {
  const { findings, stdout } = runGraphlint(path.join(REPO_ROOT, "scripts"));
  assert(findings.length > 0, `expected the known dogfood findings on scripts/, got none:\n${stdout}`);
  const rows = findings.map((f) => `  [${f.severity}] ${f.file}:${f.line} ${f.rule} => ${classifyDogfoodFinding(f)}`);
  console.log("dogfood classification (informational):\n" + rows.join("\n"));
  const unclassified = findings.filter((f) => classifyDogfoodFinding(f).startsWith("true-positive (unclassified default"));
  // A genuinely new true-positive isn't a failure by itself, but flag it loudly so it gets eyes.
  if (unclassified.length) console.log(`NOTE: ${unclassified.length} dogfood finding(s) fell through to the unclassified default -- review manually:\n` +
    unclassified.map((f) => `  [${f.severity}] ${f.file}:${f.line} ${f.rule}`).join("\n"));
});

/* ---- summary ---- */

console.log(`\n${passCount} passed, ${failCount} failed, ${skipCount} skipped.`);
process.exit(failCount ? 1 : 0);
