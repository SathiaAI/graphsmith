#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const GUARD = path.join(REPO, "scripts", "ci-check-pr-separation.js");
const CI = path.join(REPO, ".github", "workflows", "ci.yml");
const PUBLISH = path.join(REPO, ".github", "workflows", "publish.yml");
const GITLAB = path.join(REPO, "ci-templates", "gitlab-ci.yml");
const SUITE_MANIFEST = path.join(REPO, "ci-suite-manifest.json");
const tempRoots = [];
const results = [];

function compact(value) {
  return String(value).replace(/\s+/g, " ").trim().slice(0, 420);
}

function record(status, name, reason) {
  results.push({ status, name, reason });
  console.log(`${status}\t${name}\t${compact(reason)}`);
}

function check(name, condition, passReason, failReason) {
  record(condition ? "PASS" : "FAIL", name, condition ? passReason : failReason);
}

function tempDir(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `graphsmith-ci-sol-${tag}-`));
  tempRoots.push(dir);
  return dir;
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

function invokeGuard(name, files, expected, options = {}) {
  const cwd = options.cwd || tempDir("case");
  const list = path.join(cwd, `${name.replace(/[^a-z0-9]+/gi, "-")}.txt`);
  fs.writeFileSync(list, files.join("\n") + (files.length ? "\n" : ""), "utf8");
  const child = spawnSync(process.execPath, [GUARD, "--files", list], {
    cwd,
    encoding: "utf8",
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  const json = parseJson(child.stdout);
  const exit = child.status;
  let ok = false;
  if (expected === "pass") ok = exit === 0 && json && json.decision === "pass";
  if (expected === "reject") ok = exit === 1 && json && json.decision === "reject";
  if (expected === "fail-closed") ok = exit !== 0 && (!json || json.decision !== "pass");
  record(
    ok ? "PASS" : "FAIL",
    name,
    `expected=${expected} exit=${exit} decision=${json ? json.decision : "no-json"}`
  );
}

function lineOf(source, needle) {
  const index = source.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index < 0 ? "missing" : String(index + 1);
}

function section(source, startNeedle, endNeedle) {
  const start = source.indexOf(startNeedle);
  if (start < 0) return "";
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  return source.slice(start, end < 0 ? source.length : end);
}

function walkRunTests(root) {
  const found = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === "run-tests.js") found.push(path.relative(REPO, full).replace(/\\/g, "/"));
    }
  }
  walk(root);
  return found.sort();
}

function extractSuiteRunner(phaseA) {
  const match = phaseA.match(/^\s*run:\s*node -e "([^"\r\n]+)"\s*$/m);
  return match ? match[1] : "";
}

function writeExitSuite(root, relative, exitCode) {
  const file = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `process.exit(${exitCode});\n`, "utf8");
}

function runSuiteRunnerFixture(runner, suites, probeWarnings = false) {
  const root = tempDir("suite-runner");
  fs.copyFileSync(SUITE_MANIFEST, path.join(root, "ci-suite-manifest.json"));
  for (const [relative, exitCode] of suites) writeExitSuite(root, relative, exitCode);

  const env = { ...process.env };
  let warningFile = "";
  if (probeWarnings) {
    const probe = path.join(root, "warning-probe.js");
    warningFile = path.join(root, "warnings.json");
    fs.writeFileSync(
      probe,
      [
        'const fs = require("fs");',
        "let warnings = 0;",
        "const originalWarn = console.warn;",
        "console.warn = function () { warnings += 1; return originalWarn.apply(console, arguments); };",
        'process.on("exit", function () { fs.writeFileSync(process.env.GRAPHSMITH_WARNING_PROBE, JSON.stringify({ warnings })); });',
        "",
      ].join("\n"),
      "utf8"
    );
    env.GRAPHSMITH_WARNING_PROBE = warningFile;
    env.NODE_OPTIONS = `${env.NODE_OPTIONS || ""} --require=${probe}`.trim();
  }

  const child = spawnSync(process.execPath, ["-e", runner], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  const warningProbe = warningFile && fs.existsSync(warningFile)
    ? parseJson(fs.readFileSync(warningFile, "utf8"))
    : null;
  return { status: child.status, warningProbe };
}

function classifierAttacks() {
  console.log("=== PR-separation classifier attacks ===");
  invokeGuard("baseline-mixed-scenario-and-behavior", ["scripts/scenario.js", "scripts/gate.js"], "reject");
  invokeGuard("baseline-evaluator-only", ["corpus/a.json", "scenarios/b.json"], "pass");
  invokeGuard("baseline-behavior-only", ["SKILL.md", "references/a.md", "scripts/gate.js"], "pass");
  invokeGuard("known-neutral-contracts-and-tests", ["contracts/05-threat-model.md", "tests/scenario/run-tests.js"], "pass");
  invokeGuard("single-dot-prefix-normalizes", ["./scripts/scenario.js", "SKILL.md"], "reject");
  invokeGuard("backslashes-normalize", ["scripts\\scenario.js", "references\\x.md"], "reject");
  invokeGuard("repeated-dot-prefix-must-fail-closed", ["././scripts/scenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("dot-dot-reclassification-must-fail-closed", ["scenarios/../SKILL.md", "scripts/scenario.js"], "fail-closed");
  invokeGuard("dual-meaning-corpus-dot-dot-script", ["corpus/../scripts/gate.js"], "fail-closed");
  invokeGuard("trailing-slash-file-must-fail-closed", ["scripts/scenario.js/", "SKILL.md"], "fail-closed");
  invokeGuard("case-variant-must-fail-closed", ["Scripts/Scenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("unicode-fullwidth-separator-must-fail-closed", ["scripts\uff0fscenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("unicode-combining-path-must-fail-closed", ["sce\u0301narios/a.json", "SKILL.md"], "fail-closed");
  invokeGuard("nul-bearing-path-must-fail-closed", ["scripts/scenario.js\u0000.md", "SKILL.md"], "fail-closed");
  invokeGuard("neutral-unknown-file-passes", ["mystery/payload.bin"], "pass");
  invokeGuard("empty-diff-passes", [], "pass");
  invokeGuard("rename-pair-old-and-new-detected", ["scripts/scenario.js", "scripts/gate.js"], "reject");
  invokeGuard("rename-status-tuple-must-not-be-neutral", ["R100\tscripts/scenario.js\tscripts/gate.js"], "fail-closed");

  const root = tempDir("symlink");
  const corpus = path.join(root, "corpus");
  fs.mkdirSync(corpus);
  try {
    fs.symlinkSync(corpus, path.join(root, "eval-alias"), "junction");
    invokeGuard("symlink-alias-to-corpus-must-fail-closed", ["eval-alias/a.json", "SKILL.md"], "fail-closed", { cwd: root });
  } catch (error) {
    record("SKIPPED", "symlink-alias-to-corpus-must-fail-closed", `platform denied temp symlink/junction creation: ${error.code || error.message}`);
  }
}

function workflowAudit() {
  console.log("\n=== Trusted-workflow and matrix audit ===");
  const workflows = [CI, PUBLISH];
  for (const file of workflows) {
    const source = fs.readFileSync(file, "utf8");
    const relative = path.relative(REPO, file).replace(/\\/g, "/");
    const remoteUses = [...source.matchAll(/^\s*-?\s*uses:\s*([^\s#]+).*$/gm)]
      .map((match) => match[1])
      .filter((use) => !use.startsWith("./"));
    const unpinned = remoteUses.filter((use) => !/@[0-9a-fA-F]{40}$/.test(use));
    check(
      `${relative}: third-party actions full-SHA pinned`,
      unpinned.length === 0,
      `${remoteUses.length} remote action use(s), all pinned by 40 hex`,
      `unpinned action(s): ${unpinned.join(", ")}`
    );

    const preJobs = source.slice(0, source.indexOf("\njobs:"));
    check(
      `${relative}: top-level contents-read permission`,
      /\npermissions:\s*\n\s+contents:\s*read\s*(?:\n|$)/.test(preJobs),
      `top-level permissions: contents: read at line ${lineOf(source, "permissions:")}`,
      "missing exact top-level permissions: contents: read"
    );
    check(
      `${relative}: no pull_request_target`,
      !/\bpull_request_target\s*:/.test(source),
      "trigger absent",
      `pull_request_target present at line ${lineOf(source, "pull_request_target")}`
    );
    const hasPrTrigger = /^\s{2}pull_request\s*:/m.test(source);
    check(
      `${relative}: no secrets in pull_request workflow`,
      !(hasPrTrigger && /\bsecrets\s*\./.test(source)),
      hasPrTrigger ? "pull_request trigger has no secrets.* reference" : "workflow has no pull_request trigger",
      "pull_request-triggered workflow references secrets.*"
    );
    check(
      `${relative}: concurrency cancels superseded runs`,
      /\nconcurrency:\s*\n[\s\S]*?cancel-in-progress:\s*true/.test(preJobs),
      `cancel-in-progress: true at line ${lineOf(source, "cancel-in-progress:")}`,
      "missing top-level concurrency with cancel-in-progress: true"
    );
  }

  const ci = fs.readFileSync(CI, "utf8");
  const phaseA = section(ci, "  phase-a-selftests:", "\n  pr-separation-guard:");
  for (const osName of ["ubuntu-latest", "windows-latest", "macos-latest"]) {
    check(`phase-a matrix includes ${osName}`, phaseA.includes(osName), `listed at CI line ${lineOf(ci, osName)}`, "OS missing from phase-a matrix");
  }
  const nodeValues = [...phaseA.matchAll(/node:\s*\[([^\]]+)\]/g)].flatMap((match) => match[1].split(",").map((v) => Number(v.trim())));
  check("phase-a matrix Node versions are >=18", nodeValues.length > 0 && nodeValues.every((v) => v >= 18), `node=[${nodeValues.join(",")}]`, `invalid or missing node matrix: [${nodeValues.join(",")}]`);

  const componentSelftests = ["manifest.js", "state-store.js", "loaders.js", "scenario.js", "promote.js", "gate.js", "verify.js", "ci-check-pr-separation.js"];
  const missingSelftests = componentSelftests.filter((name) => !phaseA.includes(`node scripts/${name} --selftest`));
  check(
    "3-OS job invokes every Phase A component selftest",
    missingSelftests.length === 0,
    `${componentSelftests.length} component selftests invoked`,
    `missing from phase-a-selftests: ${missingSelftests.join(", ")}`
  );
  record("SKIPPED", "3-OS graphlint component selftest", "phase-b-component; graphlint remains self-tested and dogfooded in the verify job");

  const suites = walkRunTests(path.join(REPO, "tests"));
  const dynamicDiscovery = phaseA.includes("e.name === 'run-tests.js'") && phaseA.includes("walk(p)") && phaseA.includes("spawnSync(process.execPath, [s]");
  check(
    "3-OS job dynamically invokes every committed tests/**/run-tests.js",
    dynamicDiscovery,
    `recursive exact-name discovery covers ${suites.length} committed suite(s)`,
    "recursive discovery/spawn pattern not found"
  );

  const guardJob = section(ci, "  pr-separation-guard:", "\n  __no_such_job__:");
  check(
    "PR guard executes a trusted base-revision checker",
    !/node\s+scripts\/ci-check-pr-separation\.js/.test(guardJob),
    "guard is not executed from the checked-out PR workspace",
    `line ${lineOf(ci, "| node scripts/ci-check-pr-separation.js")} executes PR-controlled scripts/ci-check-pr-separation.js after checkout`
  );
  check(
    "rename source paths reach the guard",
    !/git diff\s+--name-only/.test(guardJob),
    "diff plumbing preserves old and new rename paths",
    `line ${lineOf(ci, "git diff --name-only")} uses --name-only, which supplies only the destination for renames`
  );

  const manifest = parseJson(fs.readFileSync(SUITE_MANIFEST, "utf8"));
  const reviewHarnesses = [
    "tests/attacks/deepseek/run-tests.js",
    "tests/attacks/gpt-sol-pro/run-tests.js",
    "tests/ci/deepseek/run-tests.js",
    "tests/ci/gpt-sol-pro/run-tests.js",
  ];
  const evidencePrefixes = manifest && Array.isArray(manifest.evidence_only) ? manifest.evidence_only : [];
  check(
    "manifest classifies review harnesses as evidence-only",
    reviewHarnesses.every((suite) => evidencePrefixes.some((prefix) => suite.startsWith(prefix))),
    `${reviewHarnesses.length} review harnesses explicitly covered by evidence_only prefixes`,
    "one or more review harnesses are not covered by evidence_only"
  );

  const suiteRunner = extractSuiteRunner(phaseA);
  check(
    "CI suite runner parsed from ci.yml",
    suiteRunner.length > 0,
    "embedded node runner extracted from phase-a-selftests",
    "could not parse the phase-a suite runner"
  );
  if (suiteRunner) {
    const evidenceFailure = runSuiteRunnerFixture(suiteRunner, [
      ["tests/attacks/deepseek/run-tests.js", 7],
      ["tests/gate/probe/run-tests.js", 0],
    ]);
    check(
      "evidence-only non-zero does not flip the CI gate",
      evidenceFailure.status === 0,
      `runner exit=${evidenceFailure.status}`,
      `runner exit=${evidenceFailure.status}`
    );

    const gatingFailure = runSuiteRunnerFixture(suiteRunner, [
      ["tests/attacks/deepseek/run-tests.js", 0],
      ["tests/gate/probe/run-tests.js", 7],
    ]);
    check(
      "gating suite non-zero flips the CI gate",
      gatingFailure.status !== 0,
      `runner exit=${gatingFailure.status}`,
      `runner exit=${gatingFailure.status}`
    );

    const unknownFailure = runSuiteRunnerFixture(
      suiteRunner,
      [["tests/future/probe/run-tests.js", 7]],
      true
    );
    check(
      "unlisted suite is warned and treated as gating",
      unknownFailure.status !== 0 && unknownFailure.warningProbe && unknownFailure.warningProbe.warnings > 0,
      `runner exit=${unknownFailure.status} warning-calls=${unknownFailure.warningProbe.warnings}`,
      `runner exit=${unknownFailure.status} warning-calls=${unknownFailure.warningProbe ? unknownFailure.warningProbe.warnings : "no-probe"}`
    );
  }
}

function gitlabAudit() {
  console.log("\n=== GitLab Phase A template audit ===");
  const source = fs.readFileSync(GITLAB, "utf8");
  check("GitLab template is explicitly unwired", /TEMPLATE[\s\S]*NOT\s+\n?#?\s*wired|TEMPLATE[\s\S]*NOT\s+wired/.test(source), "header marks template as not wired", "unwired/template status is absent or unclear");
  check("GitLab template covers Node 18 and 22", /image:\s*node:18/.test(source) && /image:\s*node:22/.test(source), "node:18 and node:22 jobs present", "Node 18/22 parity missing");

  const github = fs.readFileSync(CI, "utf8");
  const githubPhaseA = section(github, "  phase-a-selftests:", "\n  pr-separation-guard:");
  const expectedPhaseA = ["manifest.js", "state-store.js", "loaders.js", "scenario.js", "promote.js", "gate.js", "verify.js", "ci-check-pr-separation.js"];
  const missingPhaseA = expectedPhaseA.filter((name) => githubPhaseA.includes(`node scripts/${name} --selftest`) && !source.includes(`node scripts/${name} --selftest`));
  check("GitLab mirrors GitHub Phase A component list", missingPhaseA.length === 0, "all GitHub Phase A component selftests mirrored", `missing: ${missingPhaseA.join(", ")}`);
  check("GitLab recursively runs committed suites", source.includes("e.name === 'run-tests.js'") && source.includes("spawnSync(process.execPath, [s]"), "recursive run-tests.js discovery present", "committed suite discovery missing");

  const silentlyMissing = [
    ["syntax check", "--check"],
    ["graphlint selftest", "graphlint.js --selftest"],
    ["graphlint dogfood", "graphlint.js scripts/"],
    ["scaffold", "scaffold.js"],
    ["chaos", "chaos.js"],
  ].filter(([, needle]) => github.includes(needle) && !source.includes(needle)).map(([name]) => name);
  check(
    "GitLab declares every intentionally omitted GitHub check",
    silentlyMissing.length === 0,
    "no silent check omissions",
    `header discloses OS and PR-guard gaps but silently omits: ${silentlyMissing.join(", ")}`
  );
}

function cleanup() {
  for (const dir of tempRoots) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_) {}
  }
}

function main() {
  console.log("=== GPT-sol-pro adversarial CI review ===");
  try {
    classifierAttacks();
    workflowAudit();
    gitlabAudit();
  } catch (error) {
    record("FAIL", "harness-error", error.stack || error.message);
  } finally {
    cleanup();
  }

  const passed = results.filter((result) => result.status === "PASS").length;
  const failed = results.filter((result) => result.status === "FAIL").length;
  const skipped = results.filter((result) => result.status === "SKIPPED").length;
  console.log(`\nSUMMARY\tPASS=${passed}\tFAIL=${failed}\tSKIPPED=${skipped}`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
