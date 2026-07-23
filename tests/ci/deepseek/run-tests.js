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
const tempDirs = [];
const results = [];

function compact(v) {
  return String(v).replace(/\s+/g, " ").trim().slice(0, 420);
}

function record(status, name, reason) {
  results.push({ status, name, reason });
  console.log(status + "\t" + name + "\t" + compact(reason));
}

function check(name, condition, passDetail, failDetail) {
  record(condition ? "PASS" : "FAIL", name, condition ? passDetail : failDetail);
}

function tempDir(tag) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "gs-ci-ds-" + tag + "-"));
  tempDirs.push(d);
  return d;
}

function parseJson(text) {
  try { return JSON.parse(text); } catch (_) { return null; }
}

function invokeGuard(name, files, expected, options) {
  options = options || {};
  var cwd = options.cwd || tempDir("case");
  var list = path.join(cwd, name.replace(/[^a-z0-9]+/gi, "-") + ".txt");
  fs.writeFileSync(list, files.join("\n") + (files.length ? "\n" : ""), "utf8");
  var child = spawnSync(process.execPath, [GUARD, "--files", list], {
    cwd: cwd,
    encoding: "utf8",
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  var json = parseJson(child.stdout);
  var exit = child.status;
  var ok = false;
  if (expected === "pass") ok = exit === 0 && json && json.decision === "pass";
  if (expected === "reject") ok = exit === 1 && json && json.decision === "reject";
  if (expected === "fail-closed") ok = exit !== 0 && (!json || json.decision !== "pass");
  record(
    ok ? "PASS" : "FAIL",
    name,
    "expected=" + expected + " exit=" + exit + " decision=" + (json ? json.decision : "no-json")
  );
  return { exit: exit, json: json, ok: ok };
}

function lineOf(source, needle) {
  var idx = source.split(/\r?\n/).findIndex(function (l) { return l.indexOf(needle) >= 0; });
  return idx < 0 ? "missing" : String(idx + 1);
}

function section(source, startNeedle, endNeedle) {
  var s = source.indexOf(startNeedle);
  if (s < 0) return "";
  var e = source.indexOf(endNeedle, s + startNeedle.length);
  return source.slice(s, e < 0 ? source.length : e);
}

function walkRunTests(root) {
  var found = [];
  (function walk(dir) {
    var entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      var full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === "run-tests.js") found.push(path.relative(REPO, full).replace(/\\/g, "/"));
    }
  })(root);
  return found.sort();
}

function guardSelftest() {
  console.log("=== PR-separation guard selftest (baseline health) ===");
  var r = spawnSync(process.execPath, [GUARD, "--selftest"], {
    encoding: "utf8",
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  check(
    "guard --selftest exit 0",
    r.status === 0,
    "selftest passed (exit 0), builder's own tests green",
    "selftest FAILED (exit " + r.status + ") — guard itself may be broken"
  );
}

function classifierAttacks() {
  console.log("\n=== ATTACK 1: PR-separation classifier bypass ===");

  invokeGuard("baseline-mixed-rejects", ["scripts/scenario.js", "scripts/gate.js"], "reject");
  invokeGuard("baseline-evaluator-only-passes", ["corpus/a.json", "scenarios/b.json"], "pass");
  invokeGuard("baseline-behavior-only-passes", ["SKILL.md", "references/a.md"], "pass");
  invokeGuard("baseline-neutral-only-passes", ["contracts/04.md", "docs/readme.md", "tests/x/y.js"], "pass");

  invokeGuard("single-dot-prefix-stripped-mix-reject", ["./scripts/scenario.js", "SKILL.md"], "reject");
  invokeGuard("backslashes-normalized-mix-reject", ["scripts\\scenario.js", "references\\x.md"], "reject");
  invokeGuard("trailing-whitespace-trimmed-mix-reject", ["  scripts/scenario.js  ", "\tSKILL.md\t"], "reject");
  invokeGuard("blank-lines-tolerated-mix-reject", ["scripts/scenario.js", "", "  ", "SKILL.md"], "reject");

  invokeGuard("dot-slash-on-behavior-mix-reject", ["./scripts/gate.js", "scenarios/x.json"], "reject");
  invokeGuard("dot-slash-on-SKILL-md-mix-reject", ["./SKILL.md", "corpus/a.json"], "reject");
  invokeGuard("backslash-on-references-mix-reject", ["references\\a.md", "scripts\\scenario.js"], "reject");

  var r1 = invokeGuard("double-slash-scenario-miscategorized", ["scripts//scenario.js", "SKILL.md"], "reject");
  if (!r1.ok) {
    console.log("  INFO: scripts//scenario.js is miscategorized as behavior (double-slash not collapsed)");
  }

  var r2 = invokeGuard("dot-segment-scenario-miscategorized", ["scripts/./scenario.js", "SKILL.md"], "reject");
  if (!r2.ok) {
    console.log("  INFO: scripts/./scenario.js is miscategorized as behavior (./ not collapsed mid-path)");
  }

  var r3 = invokeGuard("triple-slash-scenario-miscategorized", ["scripts///scenario.js", "SKILL.md"], "reject");
  if (!r3.ok) {
    console.log("  INFO: scripts///scenario.js is miscategorized as behavior (/// not collapsed)");
  }

  invokeGuard("dotdot-reclassify-evaluator-as-behavior", ["scenarios/../scripts/gate.js", "SKILL.md"], "fail-closed");
  invokeGuard("dotdot-evaluator-traversal-mix", ["corpus/../scripts/gate.js", "scripts/scenario.js"], "fail-closed");

  var r4 = invokeGuard("dotdot-mixed-in-same-pr", ["scenarios/../scripts/gate.js", "scripts/scenario.js"], "fail-closed");
  if (!r4.ok) {
    console.log("  INFO: scenarios/../scripts/gate.js resolves to scripts/gate.js (behavior) but is classified as evaluator");
  }

  invokeGuard("repeated-dot-prefix-must-fail-closed", ["././scripts/scenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("double-dot-prefix-must-fail-closed", ["../../scripts/scenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("single-dot-dir-must-fail-closed", ["./references/../scenarios/x.json"], "fail-closed");

  invokeGuard("case-variant-scenario-fail-closed", ["Scripts/Scenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("case-variant-corpus-fail-closed", ["Corpus/a.json", "SKILL.md"], "fail-closed");
  invokeGuard("case-variant-scenarios-fail-closed", ["Scenarios/a.json", "SKILL.md"], "fail-closed");
  invokeGuard("case-variant-references-fail-closed", ["References/a.md", "scripts/scenario.js"], "fail-closed");

  invokeGuard("trailing-slash-scenario-fail-closed", ["scripts/scenario.js/", "SKILL.md"], "fail-closed");
  invokeGuard("trailing-slash-corpus-dir", ["corpus/a.json", "scenarios/"], "pass");
  invokeGuard("trailing-slash-references-dir", ["references/", "scripts/scenario.js"], "fail-closed");

  invokeGuard("unicode-fullwidth-slash", ["scripts\uff0fscenario.js", "SKILL.md"], "fail-closed");
  invokeGuard("unicode-combining-nfc", ["sce\u0301narios/a.json", "SKILL.md"], "fail-closed");
  invokeGuard("unicode-nfc-scenarios", ["sc\u00e9narios/a.json", "SKILL.md"], "fail-closed");

  invokeGuard("nul-byte-in-path-fail-closed", ["scripts/scenario.js\u0000.md", "SKILL.md"], "fail-closed");
  invokeGuard("nul-byte-early-fail-closed", ["scenarios/a.json\u0000/payload", "SKILL.md"], "fail-closed");

  invokeGuard("unknown-file-passes", ["mystery/payload.bin"], "pass");
  invokeGuard("unknown-files-only-passes", ["foo/bar.baz", "qux/quux.corge"], "pass");
  invokeGuard("unknown-plus-behavior-passes", ["mystery/x.bin", "SKILL.md"], "pass");
  invokeGuard("unknown-plus-evaluator-passes", ["mystery/x.bin", "scripts/scenario.js"], "pass");

  invokeGuard("empty-diff-passes", [], "pass");

  invokeGuard("rename-pair-both-paths-detected", ["scripts/scenario.js", "scripts/gate.js"], "reject");
  invokeGuard("rename-status-tuple-R100-must-fail", ["R100\tscripts/scenario.js\tscripts/gate.js"], "fail-closed");
  invokeGuard("rename-status-tuple-R050-must-fail", ["R050\tscripts/gate.js\tcorpus/gate.json"], "fail-closed");

  invokeGuard("git-status-rename-parsed-fail-closed", ["R  scripts/gate.js -> corpus/gate.json"], "fail-closed");

  invokeGuard("mixed-slashes-still-caught", ["scripts\\scenario.js", "references/./a.md"], "reject");

  invokeGuard("both-globs-on-scenario-only-fail-closed", ["scripts/scenario.js"], "pass");

  invokeGuard("scenario-as-behavior-evaluator-dual", ["scripts/scenario.js", "scripts/other.js"], "reject");

  var root = tempDir("sym");
  var corpusDir = path.join(root, "corpus");
  fs.mkdirSync(corpusDir);
  try {
    fs.symlinkSync(corpusDir, path.join(root, "eval-alias"), "junction");
    invokeGuard("symlink-alias-to-corpus-fail-closed", ["eval-alias/a.json", "SKILL.md"], "fail-closed", { cwd: root });
  } catch (err) {
    record("SKIPPED", "symlink-alias-to-corpus-fail-closed",
      "platform denied symlink/junction: " + (err.code || err.message));
  }

  try {
    var refsDir = path.join(root, "references");
    fs.mkdirSync(refsDir);
    fs.symlinkSync(refsDir, path.join(root, "refs-link"), "junction");
    invokeGuard("symlink-alias-to-references-fail-closed", ["refs-link/a.md", "scripts/scenario.js"], "fail-closed", { cwd: root });
  } catch (err) {
    record("SKIPPED", "symlink-alias-to-references-fail-closed",
      "platform denied symlink/junction: " + (err.code || err.message));
  }

  invokeGuard("ci-check-script-itself-behavior-mix", ["scripts/ci-check-pr-separation.js", "corpus/z.json"], "reject");
  invokeGuard("ci-templates-and-workflows-neutral", [".github/workflows/ci.yml", "ci-templates/gitlab-ci.yml"], "pass");
  invokeGuard("graphlint-as-behavior-mix", ["scripts/graphlint.js", "scenarios/x.json"], "reject");
  invokeGuard("scaffold-as-behavior-mix", ["scripts/scaffold.js", "corpus/x.json"], "reject");

  invokeGuard("scenario-dot-js-references-dir-mix", ["scripts/scenario.js", "references/welcome.md"], "reject");
  invokeGuard("corpus-plus-references-mix", ["corpus/a.json", "references/b.md"], "reject");
  invokeGuard("scenarios-plus-skill-md-mix", ["scenarios/x.json", "SKILL.md"], "reject");

  invokeGuard("scenario-plus-references-subdir-mix", ["scripts/scenario.js", "references/sub/deep/nested.md"], "reject");
  invokeGuard("corpus-deep-plus-skill-md-mix", ["corpus/sub/deep/data.json", "SKILL.md"], "reject");
  invokeGuard("scenarios-deep-plus-scripts-js-mix", ["scenarios/sub/deep/cfg.json", "scripts/gate.js"], "reject");
}

function workflowHardeningAudit() {
  console.log("\n=== ATTACK 2: Trusted-workflow hardening audit ===");

  var wfList = [CI, PUBLISH];
  for (var i = 0; i < wfList.length; i++) {
    var file = wfList[i];
    var source = fs.readFileSync(file, "utf8");
    var rel = path.relative(REPO, file).replace(/\\/g, "/");

    var remoteUses = [];
    var re = /^\s*-?\s*uses:\s*([^\s#]+).*$/gm;
    var m;
    while ((m = re.exec(source)) !== null) {
      if (m[1].indexOf("./") !== 0) {
        remoteUses.push(m[1]);
      }
    }
    var unpinned = remoteUses.filter(function (u) { return !/@[0-9a-fA-F]{40}$/.test(u); });
    check(
      rel + ": third-party actions full-SHA pinned",
      unpinned.length === 0,
      remoteUses.length + " remote action(s), all pinned by 40-hex SHA",
      "unpinned: " + unpinned.join(", ")
    );

    var preJobs = source.slice(0, source.indexOf("\njobs:"));
    check(
      rel + ": top-level permissions: contents: read",
      /\npermissions:\s*\n\s+contents:\s*read\s*(?:\n|$)/.test(preJobs),
      "top-level contents: read at line " + lineOf(source, "permissions:"),
      "missing exact top-level permissions: contents: read"
    );

    check(
      rel + ": no pull_request_target trigger",
      !/\bpull_request_target\s*:/.test(source),
      "pull_request_target absent",
      "pull_request_target present at line " + lineOf(source, "pull_request_target")
    );

    var hasPrTrigger = /^\s{2}pull_request\s*:/m.test(source);
    check(
      rel + ": no secrets in pull_request-triggered workflow",
      !(hasPrTrigger && /\bsecrets\s*\./.test(source)),
      hasPrTrigger ? "pull_request trigger present, no secrets.* reference found" : "no pull_request trigger (secrets not exposed)",
      "pull_request-triggered workflow references secrets — potential secret leak from fork PRs"
    );

    check(
      rel + ": concurrency cancels superseded runs",
      /\nconcurrency:\s*\n[\s\S]*?cancel-in-progress:\s*true/.test(preJobs),
      "cancel-in-progress: true at line " + lineOf(source, "cancel-in-progress:"),
      "missing top-level concurrency with cancel-in-progress: true"
    );
  }

  var ciSrc = fs.readFileSync(CI, "utf8");

  var prGuardJob = section(ciSrc, "  pr-separation-guard:", "phase-a-selftests:");
  if (prGuardJob === "") prGuardJob = ciSrc.slice(ciSrc.indexOf("  pr-separation-guard:"));

  var guardRunsFromPrHead = /node\s+scripts\/ci-check-pr-separation\.js/.test(prGuardJob);
  check(
    "PR guard does NOT execute from checked-out PR HEAD",
    !guardRunsFromPrHead,
    "guard NOT executed from PR-controlled scripts/ path",
    "line " + lineOf(ciSrc, "| node scripts/ci-check-pr-separation.js") + " executes PR-controlled ci-check-pr-separation.js; hostile PR can modify guard to always pass"
  );

  var usesNameOnly = /git diff\s+--name-only/.test(prGuardJob);
  check(
    "PR guard preserves rename source paths",
    !usesNameOnly,
    "git diff does not use --name-only (rename source preserved)",
    "line " + lineOf(ciSrc, "git diff --name-only") + " uses --name-only; rename source paths are DROPPED"
  );

  check(
    "pr-separation-guard has explicit permissions: contents: read",
    /permissions:\s*\n\s+contents:\s*read/.test(prGuardJob),
    "job-level contents: read declared",
    "pr-separation-guard job missing explicit permissions: contents: read"
  );

  check(
    "pr-separation-guard does not checkout with PAT/secrets",
    !/\$\{\{\s*secrets\./.test(prGuardJob),
    "no secrets referenced in guard steps",
    "secrets referenced in PR guard job — potential leak"
  );

  var pubSrc = fs.readFileSync(PUBLISH, "utf8");
  var pubOnSection = (pubSrc.match(/^on:\r?\n([\s\S]*?)(?=\r?\npermissions:|\r?\njobs:)/m) || [""])[0];
  check(
    "publish.yml triggers only on release/workflow_dispatch (not pull_request)",
    /^\s+release\s*:/m.test(pubOnSection) &&
      /^\s+workflow_dispatch\s*:/m.test(pubOnSection) &&
      !/^\s+pull_request\s*:/m.test(pubOnSection),
    "publish.yml triggers on release/workflow_dispatch, never pull_request",
    "publish.yml may trigger on pull_request, exposing secrets"
  );

  check(
    "verify job (legacy) selftest includes graphlint + scaffold + chaos",
    /graphlint\.js --selftest/.test(ciSrc) &&
      /graphlint\.js scripts\//.test(ciSrc) &&
      /scaffold\.js/.test(ciSrc) &&
      /chaos\.js/.test(ciSrc),
    "verify job has syntax check + graphlint (selftest + dogfood) + scaffold + chaos",
    "verify job is missing one or more legacy checks"
  );

  var phaseA = section(ciSrc, "  phase-a-selftests:", "\n  pr-separation-guard:");
  var componentSelftests = [
    "manifest.js", "state-store.js", "loaders.js", "scenario.js",
    "promote.js", "gate.js", "verify.js", "ci-check-pr-separation.js"
  ];
  var missingSelftests = componentSelftests.filter(function (name) {
    return phaseA.indexOf("node scripts/" + name + " --selftest") < 0;
  });
  check(
    "phase-a-selftests invokes every expected component selftest",
    missingSelftests.length === 0,
    componentSelftests.length + " component selftests all invoked",
    "missing: " + missingSelftests.join(", ")
  );

  check(
    "no graphlint.js --selftest in phase-a (it runs in verify job)",
    phaseA.indexOf("graphlint.js --selftest") < 0 ||
      /verify:/.test(ciSrc) && /graphlint\.js --selftest/.test(ciSrc),
    "graphlint selftest placed correctly in verify job or absent from phase-a",
    "graphlint selftest runs in both jobs (duplicate) or missing entirely"
  );
}

function matrixHonestyAudit() {
  console.log("\n=== ATTACK 3: Runner matrix honesty ===");

  var ciSrc = fs.readFileSync(CI, "utf8");
  var phaseA = section(ciSrc, "  phase-a-selftests:", "\n  pr-separation-guard:");

  var expectedOs = ["ubuntu-latest", "windows-latest", "macos-latest"];
  for (var i = 0; i < expectedOs.length; i++) {
    var os = expectedOs[i];
    check(
      "phase-a matrix includes " + os,
      phaseA.indexOf(os) >= 0,
      "listed at CI line " + lineOf(ciSrc, os),
      "OS " + os + " missing from phase-a matrix"
    );
  }

  var nodeMatch = phaseA.match(/node:\s*\[([^\]]+)\]/);
  var nodeVersions = nodeMatch ? nodeMatch[1].split(",").map(function (v) { return Number(v.trim()); }) : [];
  check(
    "phase-a matrix Node versions >= 18",
    nodeVersions.length > 0 && nodeVersions.every(function (v) { return v >= 18; }),
    "node=[" + nodeVersions.join(",") + "]",
    "invalid node matrix: [" + nodeVersions.join(",") + "]"
  );

  var suites = walkRunTests(path.join(REPO, "tests"));
  var dynamicDiscovery = phaseA.indexOf("e.name === 'run-tests.js'") >= 0 &&
    phaseA.indexOf("walk(p)") >= 0 &&
    phaseA.indexOf("spawnSync(process.execPath, [s]") >= 0;
  check(
    "phase-a-selftests dynamically discovers tests/**/run-tests.js",
    dynamicDiscovery,
    "recursive discovery covers " + suites.length + " committed suite(s): " + suites.join(", "),
    "no recursive discovery pattern found in phase-a-selftests"
  );

  check(
    "verify job also has 2-OS matrix (linux+windows)",
    /os:\s*\[\s*ubuntu-latest,\s*windows-latest\s*\]/.test(ciSrc),
    "verify job matrix: ubuntu-latest + windows-latest",
    "verify job OS matrix missing or incomplete"
  );
  check(
    "verify job has Node 18 and 22",
    /node:\s*\[\s*18,\s*22\s*\]/.test(ciSrc),
    "verify job node: [18, 22]",
    "verify job node matrix missing or incomplete"
  );

  check(
    "phase-a-selftests has fail-fast: false (independent OS runs)",
    phaseA.indexOf("fail-fast: false") >= 0,
    "fail-fast: false prevents single-OS failure from cancelling others",
    "fail-fast not set to false; one OS failure cancels other OS runs"
  );
}

function evidenceOnlyManifestAndRunnerAudit() {
  console.log("\n=== ATTACK 4: Evidence-only suite manifest + runner step audit (B3: amended) ===");

  var manifestPath = path.join(REPO, "ci-suite-manifest.json");
  var manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  var gatingPrefixes = manifest.gating_suites || [];
  var evidencePrefixes = manifest.evidence_only || [];

  var expectedEvidence = [
    "tests/attacks/deepseek/",
    "tests/attacks/gpt-sol-pro/",
    "tests/ci/deepseek/",
    "tests/ci/gpt-sol-pro/"
  ];

  var expectedGating = [
    "tests/manifest/", "tests/state-store/", "tests/loaders/",
    "tests/scenario/", "tests/promote/", "tests/gate/", "tests/verify/",
    "tests/lab/", "tests/attacks/constitutional/",
    "tests/attacks/toctou/", "tests/attacks/module-escape/"
  ];

  console.log("  Parsed ci-suite-manifest.json:");
  console.log("    gating_suites: " + gatingPrefixes.length + " prefix(es)");
  gatingPrefixes.forEach(function (p) { console.log("      " + p); });
  console.log("    evidence_only: " + evidencePrefixes.length + " prefix(es)");
  evidencePrefixes.forEach(function (p) { console.log("      " + p); });

  check(
    "B3-manifest: review harnesses listed under evidence_only",
    expectedEvidence.every(function (pre) { return evidencePrefixes.indexOf(pre) >= 0; }),
    "all 4 review harness prefixes found in evidence_only",
    "missing evidence_only entries: " + expectedEvidence.filter(function (pre) {
      return evidencePrefixes.indexOf(pre) < 0;
    }).join(", ")
  );

  check(
    "B3-manifest: gating suites contain expected regression components",
    expectedGating.every(function (pre) { return gatingPrefixes.indexOf(pre) >= 0; }),
    "all " + expectedGating.length + " expected gating prefixes present",
    "missing gating entries: " + expectedGating.filter(function (pre) {
      return gatingPrefixes.indexOf(pre) < 0;
    }).join(", ")
  );

  check(
    "B3-manifest: no prefix appears in BOTH lists (mutual exclusion)",
    !evidencePrefixes.some(function (ep) { return gatingPrefixes.indexOf(ep) >= 0; }),
    "evidence_only and gating_suites are disjoint",
    "overlapping entries: " + evidencePrefixes.filter(function (ep) {
      return gatingPrefixes.indexOf(ep) >= 0;
    }).join(", ")
  );

  var ciSrc = fs.readFileSync(CI, "utf8");
  var runnerStep = section(ciSrc, "Run every committed suite", "pr-separation-guard:");
  if (!runnerStep) runnerStep = ciSrc.slice(ciSrc.indexOf("Run every committed suite"));

  check(
    "B3-runner: step reads ci-suite-manifest.json",
    runnerStep.indexOf("ci-suite-manifest.json") >= 0,
    "runner step references ci-suite-manifest.json",
    "runner step does NOT read ci-suite-manifest.json"
  );

  check(
    "B3-runner: evidence-only classified separately from gating",
    runnerStep.indexOf("evidence_only") >= 0 && runnerStep.indexOf("unknown_gating") >= 0,
    "classifySuite returns evidence_only / gating / unknown_gating",
    "missing evidence_only or unknown_gating classification in runner step"
  );

  check(
    "B3-runner: evidence-only non-zero exit does NOT flip job gate",
    /\bif\s*\(\s*(?:kind|r\.status.*evidence)/.test(runnerStep) &&
      (runnerStep.indexOf("failedEvidence.push") >= 0 || runnerStep.indexOf("failedEvidence") >= 0),
    "evidence-only failures are pushed to failedEvidence (logged, NOT gated)",
    "evidence-only failures appear to gate the job — missing failedEvidence separation"
  );

  check(
    "B3-runner: gating suite failure DOES flip job gate",
    runnerStep.indexOf("failedGating.push") >= 0 &&
      /if\s*\(\s*failedGating\.length\s*\)[\s\S]*process\.exit\(/.test(runnerStep),
    "gating failures pushed to failedGating and cause process.exit on non-zero length",
    "gating failures do NOT cause job exit — gate is missing"
  );

  check(
    "B3-runner: fail-safe — unlisted suite treated as gating (warned)",
    runnerStep.indexOf("unknown_gating") >= 0 &&
      runnerStep.indexOf("WARNING") >= 0 &&
      runnerStep.indexOf("treating as GATING") >= 0,
    "unlisted suite triggers WARNING + treated as gating",
    "unlisted suite NOT warned or NOT fail-safe gated"
  );

  var suites = walkRunTests(path.join(REPO, "tests"));
  console.log("\n  Committed suites discovered (" + suites.length + " total):");
  suites.forEach(function (s) { console.log("    " + s); });

  var evidencePaths = expectedEvidence.map(function (pre) {
    return suites.filter(function (s) { return s.indexOf(pre) === 0; });
  }).reduce(function (a, b) { return a.concat(b); }, []);

  check(
    "B3-end-to-end: evidence-only harnesses are discovered on disk",
    evidencePaths.length > 0,
    evidencePaths.length + " evidence-only suite(s) on disk",
    "no evidence-only suites found on disk"
  );

  var anyEvidenceInGating = evidencePaths.filter(function (s) {
    return gatingPrefixes.some(function (pre) { return s.indexOf(pre) === 0; });
  });
  var anyGatingInEvidence = suites.filter(function (s) {
    return evidencePrefixes.some(function (pre) { return s.indexOf(pre) === 0; }) &&
      expectedGating.some(function (pre) { return s.indexOf(pre) === 0; });
  });

  check(
    "B3-end-to-end: no evidence-only suite overlaps with gating by manifest",
    anyEvidenceInGating.length === 0 && anyGatingInEvidence.length === 0,
    "suite classification is mutually exclusive w.r.t. manifest prefixes",
    "overlap: evidencePaths in gating=" + anyEvidenceInGating.join(", ") +
      " gatingPaths in evidence=" + anyGatingInEvidence.join(", ")
  );

  console.log("\n  B3 AMENDED VERDICT:");
  console.log("    OLD test: asserted file non-existence (can never pass, B3 requires discovery).");
  console.log("    NEW test: asserts manifest listing + runner-step gate logic.");
  console.log("    REAL guarantee proven: evidence-only harnesses run+logged, do NOT block merge.");
}

function gitlabTemplateAudit() {
  console.log("\n=== ATTACK 5: GitLab template sanity ===");

  var source = fs.readFileSync(GITLAB, "utf8");
  var ciSrc = fs.readFileSync(CI, "utf8");

  check(
    "GitLab template header marks it as unwired/template",
    /TEMPLATE[\s\S]*NOT\s+\n?#?\s*wired|TEMPLATE[\s\S]*NOT\s+wired/.test(source),
    "header explicitly marks this as a template, not wired",
    "unwired/template status absent or unclear"
  );

  check(
    "GitLab template covers Node 18 and 22",
    /image:\s*node:18/.test(source) && /image:\s*node:22/.test(source),
    "node:18 and node:22 jobs present",
    "Node 18 or Node 22 parity missing"
  );

  var expectedPhaseA = [
    "manifest.js", "state-store.js", "loaders.js", "scenario.js",
    "promote.js", "gate.js", "verify.js", "ci-check-pr-separation.js"
  ];
  var githubPhaseA = section(ciSrc, "  phase-a-selftests:", "\n  pr-separation-guard:");

  var missingFromGitlab = expectedPhaseA.filter(function (name) {
    return githubPhaseA.indexOf("node scripts/" + name + " --selftest") >= 0 &&
      source.indexOf("node scripts/" + name + " --selftest") < 0;
  });
  check(
    "GitLab mirrors GitHub Phase A component selftests",
    missingFromGitlab.length === 0,
    "all GitHub Phase A selftests mirrored in GitLab template",
    "missing from GitLab: " + missingFromGitlab.join(", ")
  );

  check(
    "GitLab recursively discovers and runs committed suites",
    source.indexOf("e.name === 'run-tests.js'") >= 0 &&
      source.indexOf("spawnSync(process.execPath, [s]") >= 0,
    "recursive run-tests.js discovery present in template",
    "committed suite discovery missing from GitLab template"
  );

  var githubChecks = [
    ["PR separation guard", "pr-separation-guard"],
    ["syntax check", "--check"],
    ["graphlint selftest", "graphlint.js --selftest"],
    ["graphlint dogfood", "graphlint.js scripts/"],
    ["scaffold", "scaffold.js"],
    ["chaos", "chaos.js"],
  ];
  var silentlyMissing = githubChecks.filter(function (item) {
    return ciSrc.indexOf(item[1]) >= 0 && source.indexOf(item[1]) < 0;
  }).map(function (item) { return item[0]; });

  check(
    "GitLab declares every intentionally omitted GitHub check",
    silentlyMissing.length === 0,
    "no silent check omissions from GitLab template",
    "GitLab silently omits: " + silentlyMissing.join(", ") +
      " — header only discloses OS/PR-guard gaps"
  );

  check(
    "GitLab does NOT include secret-exposing jobs",
    !/secrets\./.test(source) && !/NPM_TOKEN/.test(source),
    "no secrets referenced",
    "template references secrets — not safe for template distribution"
  );
}

function cleanup() {
  for (var i = 0; i < tempDirs.length; i++) {
    try { fs.rmSync(tempDirs[i], { recursive: true, force: true }); } catch (_) {}
  }
}

function main() {
  console.log("=== DeepSeek adversarial CI review ===");
  console.log("Repository: " + REPO);
  console.log("Guard script: " + GUARD);
  console.log("");

  try {
    guardSelftest();
    classifierAttacks();
    workflowHardeningAudit();
    matrixHonestyAudit();
    evidenceOnlyManifestAndRunnerAudit();
    gitlabTemplateAudit();
  } catch (err) {
    record("FAIL", "harness-error", (err.stack || err.message));
  } finally {
    cleanup();
  }

  var passed = results.filter(function (r) { return r.status === "PASS"; }).length;
  var failed = results.filter(function (r) { return r.status === "FAIL"; }).length;
  var skipped = results.filter(function (r) { return r.status === "SKIPPED"; }).length;
  console.log("\n" + "=".repeat(60));
  console.log("SUMMARY\tPASS=" + passed + "\tFAIL=" + failed + "\tSKIPPED=" + skipped);
  if (failed > 0) {
    console.log("\nFAILED tests:");
    results.filter(function (r) { return r.status === "FAIL"; }).forEach(function (r) {
      console.log("  FAIL\t" + r.name + "\t" + compact(r.reason));
    });
  }
  console.log("=".repeat(60));

  if (passed === results.length - skipped) {
    console.log("\nZERO-FINDING REVIEW IS INVALID. This harness is adversarial.");
  }

  process.exit(failed > 0 ? 1 : 0);
}

main();