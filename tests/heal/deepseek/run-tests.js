#!/usr/bin/env node
"use strict";
/* Adversarial test suite for scripts/heal.js — deepseek family lane.
 * Zero-dep CJS. Drives heal via CLI in TEMP project dirs.
 * Verdicts from before/after hashes + exit codes, never log strings.
 * Exit 1 if any FAIL. */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const cp = require("child_process");

const HEAL_PATH = path.resolve(__dirname, "..", "..", "..", "scripts", "heal.js");
const STATE_STORE_PATH = path.resolve(__dirname, "..", "..", "..", "scripts", "state-store.js");
const TMP_BASE = path.join(os.tmpdir(), "graphsmith-ds-heal-");

let failures = 0;
let skipped = 0;
let passed = 0;

function report(name, result, detail) {
  if (result === true) { console.log("PASS: " + name); passed++; }
  else if (result === false) { console.log("FAIL: " + name + (detail ? " -- " + detail : "")); failures++; }
  else if (result === "SKIP") { console.log("SKIP: " + name + (detail ? " -- " + detail : "")); skipped++; }
}

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : data).digest("hex");
}

function makeTempDir(label) {
  return fs.mkdtempSync(TMP_BASE + label + "-");
}

function cleanDir(d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {} }

function fileHash(fp) {
  try { return sha256(fs.readFileSync(fp)); } catch (_) { return null; }
}

function snapshotHashes(root, files) {
  var s = {};
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    var fp = path.join(root, f);
    s[f] = fileHash(fp);
  }
  return s;
}

function assertUnchanged(prefix, root, files, before) {
  var changed = false;
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    var fp = path.join(root, f);
    var h = fileHash(fp);
    if (h === null) continue;
    if (h !== before[f]) {
      report(prefix + ": mutated " + f, false, "hash changed: " + (before[f] || "").slice(0, 16) + " -> " + (h || "").slice(0, 16));
      changed = true;
    }
  }
  if (!changed) report(prefix + ": zero-mutation on all executables", true);
  return !changed;
}

function runHeal(args, opts) {
  opts = opts || {};
  var a = [HEAL_PATH].concat(args);
  var env = Object.assign({}, process.env);
  if (!opts.noTestMode) env.GRAPHSMITH_TEST_MODE = "1";
  try {
    var r = cp.spawnSync(process.execPath, a, {
      cwd: opts.cwd || process.cwd(),
      env: env,
      timeout: opts.timeout || 20000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return {
      exitCode: r.status,
      stdout: (r.stdout || "").toString("utf8").trim(),
      stderr: (r.stderr || "").toString("utf8").trim(),
      signal: r.signal,
      error: r.error,
    };
  } catch (e) {
    return { exitCode: null, stdout: "", stderr: "", signal: null, error: e };
  }
}

function writeFile(fp, content) {
  var dir = path.dirname(fp);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(fp, content);
}

function mkdirs(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

// Setup a window with a given state via state-store module API
function setupWindowState(root, state) {
  var stDir = path.join(root, ".graphsmith", "state");
  mkdirs(stDir);
  var State = require(STATE_STORE_PATH);
  var prior = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  try {
    var st = State.createStore(root);
    st.window.admitPending({ txid: "heal-test-" + Date.now(), fingerprint: "fp-" + Date.now(), tree_id: "v-healtest-" + Date.now(), n: 1 });
    var lk = st._testing.acquireLock();
    try {
      st._commit([{
        file: "window.json",
        make: function(raw, rv) {
          var v = JSON.parse(raw);
          v.state = state || "HALT_HUMAN";
          v.state_rev = rv;
          return JSON.stringify(v);
        },
      }]);
    } finally {
      clearInterval(lk.heartbeat);
      st._testing.releaseLock(lk.ownerToken);
    }
  } catch (e) {
    if (prior === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = prior;
    throw e;
  }
  if (prior === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
  else process.env.GRAPHSMITH_TEST_MODE = prior;
}

// Add a rollback-families entry (via state-store)
function addRollbackFamily(root, fingerprint, family, evidence) {
  var State = require(STATE_STORE_PATH);
  var prior = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  try {
    var st = State.createStore(root);
    st.rollbackFamilies.append({ fingerprint: fingerprint, family: family, evidence: evidence });
  } catch (e) {
    if (prior === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
    else process.env.GRAPHSMITH_TEST_MODE = prior;
    throw e;
  }
  if (prior === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
  else process.env.GRAPHSMITH_TEST_MODE = prior;
}

// ====== TEST SUITE ======

console.log("=== ATTACK 1: Code is STAGED-ONLY, always ===\n");

(function() {
  var root = makeTempDir("a1-code");
  var execFiles = ["step.js", "worker.js", "lib/util.mjs", "helper.cjs", "mod.ts"];
  writeFile(path.join(root, "step.js"), "exports.x = 1;\n");
  writeFile(path.join(root, "worker.js"), "exports.y = 2;\n");
  writeFile(path.join(root, "lib/util.mjs"), "export default 1;\n");
  writeFile(path.join(root, "helper.cjs"), "exports.z = 3;\n");
  writeFile(path.join(root, "mod.ts"), "const x: number = 1;\n");

  var before = snapshotHashes(root, execFiles);

  // 1a: Stage a .js code repair — must produce diff, NEVER write target
  (function() {
    var propFile = path.join(root, ".proposed-step.js");
    writeFile(propFile, "exports.x = 99;\n");
    var r = runHeal(["--stage", "step.js", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var diffOk = parsed && parsed.repair_class === "code" && typeof parsed.diff === "string" && parsed.diff.indexOf("step.js") >= 0;
    var noInlineContent = parsed && !Object.prototype.hasOwnProperty.call(parsed, "content_base64");
    var autoApplyFalse = parsed && parsed.auto_apply_eligible === false;
    var appliedFalse = parsed && parsed.applied === false;
    var notMutated = fileHash(path.join(root, "step.js")) === before["step.js"];
    var stagedExists = parsed && parsed.heal_id ? fs.existsSync(path.join(root, ".graphsmith", "heal-stages", parsed.heal_id + ".staged.json")) : false;
    report("1a: code repair produces diff-only stage",
      diffOk && noInlineContent && autoApplyFalse && appliedFalse && notMutated && stagedExists && r.exitCode === 0,
      !diffOk ? "no diff" : !noInlineContent ? "content_base64 present" : !autoApplyFalse ? "auto_apply_eligible true" : !appliedFalse ? "applied true" : !notMutated ? "file mutated" : !stagedExists ? "staged file missing" : "");
  })();

  // 1b: Stage .mjs code repair — staged-only, no mutation
  (function() {
    var propFile = path.join(root, ".proposed-util.js");
    writeFile(propFile, "export default 2;\n");
    var r = runHeal(["--stage", "lib/util.mjs", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var isCode = parsed && parsed.repair_class === "code";
    var notMutated = fileHash(path.join(root, "lib/util.mjs")) === before["lib/util.mjs"];
    report("1b: .mjs code repair staged-only",
      isCode && notMutated && r.exitCode === 0,
      !isCode ? "not code class" : !notMutated ? "file mutated" : "");
  })();

  // 1c: Stage .cjs code repair — staged-only
  (function() {
    var propFile = path.join(root, ".proposed-helper.js");
    writeFile(propFile, "exports.z = 99;\n");
    var r = runHeal(["--stage", "helper.cjs", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var isCode = parsed && parsed.repair_class === "code";
    var notMutated = fileHash(path.join(root, "helper.cjs")) === before["helper.cjs"];
    report("1c: .cjs code repair staged-only",
      isCode && notMutated && r.exitCode === 0,
      !isCode ? "not code class" : !notMutated ? "file mutated" : "");
  })();

  // 1d: Stage .ts code repair — recognized as executable (isExecutablePath), must be code, staged-only
  (function() {
    var propFile = path.join(root, ".proposed-ts.js");
    writeFile(propFile, "const x: number = 99;\n");
    var r = runHeal(["--stage", "mod.ts", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var isCode = parsed && parsed.repair_class === "code";
    var notMutated = fileHash(path.join(root, "mod.ts")) === before["mod.ts"];
    report("1d: .ts file classified as code repair, staged-only",
      isCode && notMutated && r.exitCode === 0,
      !isCode ? "not code: class=" + (parsed && parsed.repair_class) : !notMutated ? "file mutated" : "");
  })();

  // 1e: Verify no executable bytes changed across all tests
  assertUnchanged("1e", root, execFiles, before);

  cleanDir(root);
})();

console.log("\n=== ATTACK 2: Manager code is untouchable ===\n");

(function() {
  var root = makeTempDir("a2-mgr");
  var execFiles = ["manager.js", "manager.cjs", "manager.mjs", "step.js", "nested/manager.js"];
  writeFile(path.join(root, "manager.js"), "console.log('real manager');\n");
  writeFile(path.join(root, "manager.cjs"), "console.log('manager cjs');\n");
  writeFile(path.join(root, "manager.mjs"), "console.log('manager mjs');\n");
  writeFile(path.join(root, "step.js"), "exports.x = 1;\n");
  writeFile(path.join(root, "nested/manager.js"), "console.log('nested manager');\n");

  var before = snapshotHashes(root, execFiles);

  // 2a: Direct manager.js staging — MUST refuse
  (function() {
    var propFile = path.join(root, ".prop-mgr.js");
    writeFile(propFile, "console.log('hacked');\n");
    var r = runHeal(["--stage", "manager.js", "--root", root, "--proposed", propFile]);
    var refused = r.exitCode !== 0 && /MANAGER_CODE_REFUSED/i.test(r.stderr || "");
    var notMutated = fileHash(path.join(root, "manager.js")) === before["manager.js"];
    var noStage = !fs.existsSync(path.join(root, ".graphsmith", "heal-stages")) || fs.readdirSync(path.join(root, ".graphsmith", "heal-stages")).length === 0;
    report("2a: direct manager.js staging refused",
      refused && notMutated && noStage,
      !refused ? "not refused: exit=" + r.exitCode + " err=" + r.stderr : !notMutated ? "file mutated" : !noStage ? "staged file created" : "");
  })();

  // 2b: ./manager.js path trick — MUST refuse (ensureInsideRoot resolves)
  (function() {
    var propFile = path.join(root, ".prop-mgr2.js");
    writeFile(propFile, "console.log('hacked2');\n");
    var r = runHeal(["--stage", "./manager.js", "--root", root, "--proposed", propFile]);
    var refused = r.exitCode !== 0 && /MANAGER_CODE_REFUSED/i.test(r.stderr || "");
    var notMutated = fileHash(path.join(root, "manager.js")) === before["manager.js"];
    report("2b: ./manager.js path trick refused",
      refused && notMutated,
      !refused ? "not refused: exit=" + r.exitCode + " err=" + r.stderr : !notMutated ? "file mutated" : "");
  })();

  // 2c: manager.cjs also refused (isManagerPath covers manager.*.js)
  (function() {
    var propFile = path.join(root, ".prop-mgr-cjs.js");
    writeFile(propFile, "console.log('hacked cjs');\n");
    var r = runHeal(["--stage", "manager.cjs", "--root", root, "--proposed", propFile]);
    var refused = r.exitCode !== 0 && /MANAGER_CODE_REFUSED/i.test(r.stderr || "");
    var notMutated = fileHash(path.join(root, "manager.cjs")) === before["manager.cjs"];
    report("2c: manager.cjs refused",
      refused && notMutated,
      !refused ? "not refused: exit=" + r.exitCode : !notMutated ? "file mutated" : "");
  })();

  // 2d: manager.mjs also refused
  (function() {
    var propFile = path.join(root, ".prop-mgr-mjs.js");
    writeFile(propFile, "console.log('hacked mjs');\n");
    var r = runHeal(["--stage", "manager.mjs", "--root", root, "--proposed", propFile]);
    var refused = r.exitCode !== 0 && /MANAGER_CODE_REFUSED/i.test(r.stderr || "");
    report("2d: manager.mjs refused",
      refused && r.exitCode !== 0,
      !refused ? "not refused: exit=" + r.exitCode : "");
  })();

  // 2e: nested manager.js refused (regex catches /manager.js patterns)
  (function() {
    var propFile = path.join(root, ".prop-nested-mgr.js");
    writeFile(propFile, "console.log('hacked nested');\n");
    var r = runHeal(["--stage", "nested/manager.js", "--root", root, "--proposed", propFile]);
    var refused = r.exitCode !== 0 && /MANAGER_CODE_REFUSED/i.test(r.stderr || "");
    var notMutated = fileHash(path.join(root, "nested/manager.js")) === before["nested/manager.js"];
    report("2e: nested manager.js refused",
      refused && notMutated,
      !refused ? "not refused: exit=" + r.exitCode : !notMutated ? "file mutated" : "");
  })();

  // 2f: Case variant MANAGER.js — case-insensitive isManagerPath now REFUSES
  (function() {
    var caseRoot = makeTempDir("a2-mgr-case");
    var caseFile = "MANAGER.js";
    writeFile(path.join(caseRoot, caseFile), "console.log('not manager content');\n");
    var beforeCase = fileHash(path.join(caseRoot, caseFile));
    var propFile = path.join(caseRoot, ".prop-case.js");
    writeFile(propFile, "console.log('staged content');\n");
    var r = runHeal(["--stage", caseFile, "--root", caseRoot, "--proposed", propFile]);
    var refused = r.exitCode !== 0 && /MANAGER_CODE_REFUSED/i.test(r.stderr || "");
    var notMutated = fileHash(path.join(caseRoot, caseFile)) === beforeCase;
    report("2f: MANAGER.js case-variant REFUSED by case-insensitive isManagerPath",
      refused && notMutated,
      !refused ? "not refused: exit=" + r.exitCode + " err=" + r.stderr : !notMutated ? "file mutated" : "");
    cleanDir(caseRoot);
  })();

  // 2g: Symlink attack — target mal.js → real_manager.js
  //      Manifest.generate throws on symlinks, blocking the staging before manager check.
  (function() {
    var symRoot = makeTempDir("a2-mgr-sym");
    var realMgr = path.join(symRoot, "real_manager.js");
    writeFile(realMgr, "console.log('the real manager content');\n");
    var symLink = path.join(symRoot, "mal.js");
    var canSymlink = true;
    try { fs.symlinkSync(realMgr, symLink, "file"); } catch (_) { canSymlink = false; }
    if (canSymlink) {
      var propFile = path.join(symRoot, ".prop-sym.js");
      writeFile(propFile, "console.log('attack via symlink');\n");
      var r = runHeal(["--stage", "mal.js", "--root", symRoot, "--proposed", propFile]);
      // Should fail — manifest generates throws on symlinks (Refused: symlink/junction)
      var failed = r.exitCode !== 0;
      var notMutated = fileHash(realMgr) === sha256("console.log('the real manager content');\n");
      report("2g: symlink mal.js->real_manager.js blocked by manifest",
        failed && notMutated,
        !failed ? "BYPASSED: exit=" + r.exitCode + " stdout=" + r.stdout.slice(0, 100) : !notMutated ? "target mutated" : "exit=" + r.exitCode + " err=" + (r.stderr || "").slice(0, 100));
    } else {
      report("2g: symlink mal.js->real_manager.js blocked", "SKIP", "no symlink privilege");
    }
    cleanDir(symRoot);
  })();

  assertUnchanged("2h", root, execFiles, before);
  cleanDir(root);
})();

console.log("\n=== ATTACK 3: Typed repair auto-apply gating ===\n");

(function() {
  var root = makeTempDir("a3-auto");
  mkdirs(path.join(root, "workers"));
  mkdirs(path.join(root, "scenarios"));
  var execFiles = ["workers/gather.prompt.md", "tunables.json", "scenarios/test.scenario.json", "readme.md"];
  writeFile(path.join(root, "workers/gather.prompt.md"), "You are gather. Provide safe output.\n");
  writeFile(path.join(root, "tunables.json"), JSON.stringify({ limit: 2 }));
  writeFile(path.join(root, "scenarios/test.scenario.json"), JSON.stringify({ id: "test" }));
  writeFile(path.join(root, "readme.md"), "# Project\n");

  var before = snapshotHashes(root, execFiles);

  // 3a: Clean typed repair (no external calls) → auto_apply_eligible true
  (function() {
    var propFile = path.join(root, ".prop-clean.js");
    writeFile(propFile, "You are gather. Fixed version with only plain text.\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var typed = parsed && parsed.repair_class === "typed";
    var eligible = parsed && parsed.auto_apply_eligible === true;
    var noExtCalls = parsed && parsed.capability_policy && parsed.capability_policy.no_external_calls === true;
    var notMutated = fileHash(path.join(root, "workers/gather.prompt.md")) === before["workers/gather.prompt.md"];
    report("3a: clean typed repair auto_apply_eligible",
      typed && eligible && noExtCalls && notMutated && r.exitCode === 0,
      !typed ? "not typed" : !eligible ? "not eligible" : !noExtCalls ? "ext calls detected" : !notMutated ? "file mutated" : "");
  })();

  // 3b: Typed with process.env → human-gated
  (function() {
    var propFile = path.join(root, ".prop-pe.js");
    writeFile(propFile, "Use process.env.SECRET_KEY to authenticate.\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var notEligible = parsed && parsed.auto_apply_eligible === false;
    var matchedPE = parsed && parsed.capability_policy && parsed.capability_policy.matched_patterns && parsed.capability_policy.matched_patterns.indexOf("process-env-or-exit") >= 0;
    report("3b: process.env content human-gated",
      notEligible && matchedPE && r.exitCode === 0,
      !notEligible ? "eligible (bypassed)" : !matchedPE ? "wrong pattern matched" : "");
  })();

  // 3c: Typed with fetch() → human-gated
  (function() {
    var propFile = path.join(root, ".prop-fetch.js");
    writeFile(propFile, "Call fetch('https://api.example.com/data') to get results.\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var notEligible = parsed && parsed.auto_apply_eligible === false;
    report("3d: fetch() content human-gated",
      notEligible && r.exitCode === 0,
      !notEligible ? "eligible (bypassed)" : "");
  })();

  // 3d: Typed with http.request pattern → human-gated
  (function() {
    var propFile = path.join(root, ".prop-http.js");
    writeFile(propFile, "Use http.request for network calls.\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var notEligible = parsed && parsed.auto_apply_eligible === false;
    report("3e: http. content human-gated",
      notEligible && r.exitCode === 0,
      !notEligible ? "eligible (bypassed)" : "");
  })();

  // 3e: Typed with eval() in content → human-gated (eval-function pattern)
  (function() {
    var propFile = path.join(root, ".prop-eval.js");
    writeFile(propFile, "You should eval() user code.\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var notEligible = parsed && parsed.auto_apply_eligible === false;
    report("3f: eval() content human-gated",
      notEligible && r.exitCode === 0,
      !notEligible ? "eligible (bypassed)" : "");
  })();

  // 3g: CAUGHT — String.fromCharCode obfuscated exec (STATIC_UNPROVABLE_PATTERNS)
  (function() {
    var propFile = path.join(root, ".prop-charcode.js");
    writeFile(propFile, "const e = String.fromCharCode(101,120,101,99); globalThis[e]('whoami');\nconst s = String.fromCharCode(115,112,97,119,110); globalThis[s]('cmd');\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var notEligible = parsed && parsed.auto_apply_eligible === false;
    var patterns = parsed && parsed.capability_policy && parsed.capability_policy.matched_patterns;
    report("3g: fromCharCode-obfuscated exec CAUGHT by unprovable-pattern scan",
      notEligible,
      !notEligible ? "BYPASSED: auto_apply_eligible=true. patterns=" + JSON.stringify(patterns || []) :
      "human-gated: patterns=" + JSON.stringify(patterns || []));
  })();

  // 3h: CAUGHT — template-literal-constructed require (STATIC_UNPROVABLE_PATTERNS)
  (function() {
    var propFile = path.join(root, ".prop-template.js");
    writeFile(propFile, "const mod = 'fs'; const r = 're'+'quire'; globalThis[r](mod).unlinkSync('/tmp/x');\n");
    var r = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var notEligible = parsed && parsed.auto_apply_eligible === false;
    var patterns = parsed && parsed.capability_policy && parsed.capability_policy.matched_patterns;
    report("3h: template-concatenated require CAUGHT by unprovable-pattern scan",
      notEligible,
      !notEligible ? "BYPASSED: auto_apply_eligible=true. patterns=" + JSON.stringify(patterns || []) :
      "human-gated: patterns=" + JSON.stringify(patterns || []));
  })();

  // 3h: Readme.md (classified as typed:data) with clean content → auto_apply_eligible
  (function() {
    var propFile = path.join(root, ".prop-md.js");
    writeFile(propFile, "# Updated Project\n\nSafe text only.\n");
    var r = runHeal(["--stage", "readme.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var eligible = parsed && parsed.auto_apply_eligible === true;
    var kind = parsed && parsed.kind;
    var notMutated = fileHash(path.join(root, "readme.md")) === before["readme.md"];
    report("3i: clean .md typed repair auto_apply_eligible",
      eligible && notMutated && r.exitCode === 0,
      !eligible ? "not eligible, kind=" + kind : !notMutated ? "file mutated" : "");
  })();

  assertUnchanged("3j", root, execFiles, before);
  cleanDir(root);
})();

console.log("\n=== ATTACK 4: Byte-exact rollback ===\n");

(function() {
  // 4a: Typed rollback restores byte-exact via manifest tree identity
  (function() {
    var root = makeTempDir("a4-rb");
    mkdirs(path.join(root, "workers"));
    var typedFile = "workers/gather.prompt.md";
    var typedContent = "You are gather. Original content for rollback testing.\n";
    writeFile(path.join(root, typedFile), typedContent);
    var origHash = sha256(typedContent);

    var propFile = path.join(root, ".prop-rb.js");
    var newContent = "You are gather. Modified content that should be rolled back.\n";
    writeFile(propFile, newContent);

    var sr = runHeal(["--stage", typedFile, "--root", root, "--proposed", propFile]);
    var sp = null;
    try { sp = JSON.parse(sr.stdout); } catch (_) {}

    if (sp && sp.heal_id) {
      // Apply the change manually (simulate human apply)
      writeFile(path.join(root, typedFile), newContent);
      var rb = runHeal(["rollback", sp.heal_id, "--root", root]);
      var rbParsed = null;
      try { rbParsed = JSON.parse(rb.stdout); } catch (_) {}
      var rolledBack = rbParsed && (rbParsed.state === "ROLLED_BACK" || rbParsed.state === "ALREADY_ROLLED_BACK");
      var treeOk = rbParsed && rbParsed.tree_identity_verified === true;
      var restored = fileHash(path.join(root, typedFile)) === origHash;
      report("4a: typed rollback restores byte-exact via manifest tree identity",
        rolledBack && restored && treeOk && (rb.exitCode === 0 || rbParsed.state === "ALREADY_ROLLED_BACK"),
        !rolledBack ? "not rolled back: " + rb.stderr : !restored ? "hash mismatch" : !treeOk ? "tree not verified" : "");
    } else {
      report("4a: typed rollback restores byte-exact", false, "failed to stage repair: " + sr.stderr);
    }
    cleanDir(root);
  })();

  // 4b: Code repair rollback — MUST refuse
  (function() {
    var root = makeTempDir("a4-rbc");
    writeFile(path.join(root, "step.js"), "exports.x = 1;\n");
    var propFile = path.join(root, ".prop-code.js");
    writeFile(propFile, "exports.x = 99;\n");
    var sr = runHeal(["--stage", "step.js", "--root", root, "--proposed", propFile]);
    var sp = null;
    try { sp = JSON.parse(sr.stdout); } catch (_) {}
    var cHealId = sp ? sp.heal_id : null;
    if (cHealId) {
      var cr = runHeal(["rollback", cHealId, "--root", root]);
      var refused = cr.exitCode !== 0 && /FORWARD_RECOVERY_REQUIRED|forward-recovery/i.test((cr.stderr || "") + (cr.stdout || ""));
      report("4b: code repair rollback refused with forward-recovery",
        refused,
        !refused ? "not refused: exit=" + cr.exitCode : "");
    } else {
      report("4b: code repair rollback refused", false, "failed to stage");
    }
    cleanDir(root);
  })();

  // 4c: Unknown rollback id → clean refusal
  (function() {
    var root = makeTempDir("a4-unk");
    var r = runHeal(["rollback", "0".repeat(24), "--root", root]);
    var refused = r.exitCode !== 0 && /ROLLBACK_NOT_FOUND|unknown/i.test((r.stderr || ""));
    report("4c: unknown rollback id refuses cleanly",
      refused,
      !refused ? "not refused: exit=" + r.exitCode : "");
    cleanDir(root);
  })();

  // 4d: Corrupt staged JSON → clean refusal
  (function() {
    var root = makeTempDir("a4-corr");
    var stagesDir = path.join(root, ".graphsmith", "heal-stages");
    mkdirs(stagesDir);
    writeFile(path.join(stagesDir, "a".repeat(24) + ".staged.json"), "{ not json");
    var r = runHeal(["rollback", "a".repeat(24), "--root", root]);
    var refused = r.exitCode !== 0;
    report("4d: corrupt staged JSON rollback refuses",
      refused,
      !refused ? "succeeded unexpectedly: exit=" + r.exitCode : "");
    cleanDir(root);
  })();

  // 4e: Divergent edit (file changed after staging) → refuse
  (function() {
    var root = makeTempDir("a4-div");
    mkdirs(path.join(root, "workers"));
    var typedFile = "workers/gather.prompt.md";
    writeFile(path.join(root, typedFile), "original content\n");
    var propFile = path.join(root, ".prop-div.js");
    writeFile(propFile, "modified content\n");
    var sr = runHeal(["--stage", typedFile, "--root", root, "--proposed", propFile]);
    var sp = null;
    try { sp = JSON.parse(sr.stdout); } catch (_) {}
    if (sp && sp.heal_id) {
      // Tamper with the file so it matches neither before nor after
      writeFile(path.join(root, typedFile), "tampered content that matches nothing\n");
      var rb = runHeal(["rollback", sp.heal_id, "--root", root]);
      var refused = rb.exitCode !== 0;
      report("4e: divergent edit rollback refused",
        refused,
        !refused ? "not refused: exit=" + rb.exitCode : "");
    } else {
      report("4e: divergent edit rollback refused", "SKIP", "failed to stage");
    }
    cleanDir(root);
  })();

  // 4f: Corrupted before_sha256 in staged record → internal sha check fails
  (function() {
    var root = makeTempDir("a4-corrsha");
    mkdirs(path.join(root, "workers"));
    var typedFile = "workers/gather.prompt.md";
    writeFile(path.join(root, typedFile), "original for tamper\n");
    var propFile = path.join(root, ".prop-tamper.js");
    writeFile(propFile, "modified content\n");
    var sr = runHeal(["--stage", typedFile, "--root", root, "--proposed", propFile]);
    var sp = null;
    try { sp = JSON.parse(sr.stdout); } catch (_) {}
    if (sp && sp.heal_id) {
      var stagePath = path.join(root, ".graphsmith", "heal-stages", sp.heal_id + ".staged.json");
      var rec = JSON.parse(fs.readFileSync(stagePath, "utf8"));
      rec.before_sha256 = "0".repeat(64);
      fs.writeFileSync(stagePath, JSON.stringify(rec));
      // Apply the modified content so after_sha256 matches
      writeFile(path.join(root, typedFile), "modified content\n");
      var rb = runHeal(["rollback", sp.heal_id, "--root", root]);
      var refused = rb.exitCode !== 0;
      report("4f: corrupted before_sha256 rollback refused",
        refused,
        !refused ? "not refused (applied despite corrupt hash): exit=" + rb.exitCode : "");
    } else {
      report("4f: corrupted before_sha256 rollback refused", "SKIP", "failed to stage");
    }
    cleanDir(root);
  })();
})();

console.log("\n=== ATTACK 5: Typed-event boundary ===\n");

(function() {
  // 5a: diagnose reads through typed adapter, classification from window
  (function() {
    var root = makeTempDir("a5-basic");
    try { setupWindowState(root, "HALT_HUMAN"); } catch (e) {
      report("5a: diagnose uses typed adapter", false, "state-store setup failed: " + e.message);
      cleanDir(root);
      return;
    }
    var r = runHeal(["--diagnose", "--root", root]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var fromAdapter = parsed && parsed.diagnosis && parsed.diagnosis.raw_source === "state-store.typed-records+adapter";
    var proseChecked = parsed && parsed.diagnosis && parsed.diagnosis.prose_logs_consulted === false;
    var classified = parsed && parsed.diagnosis && parsed.diagnosis.classification === "HALT_HUMAN";
    var hasEvidence = parsed && parsed.diagnosis && Array.isArray(parsed.diagnosis.evidence) && parsed.diagnosis.evidence.length > 0;
    report("5a: diagnose uses typed adapter, classifies from window, prose_logs_consulted=false",
      fromAdapter && proseChecked && classified && hasEvidence && r.exitCode === 0,
      !fromAdapter ? "raw_source=" + (parsed && parsed.diagnosis && parsed.diagnosis.raw_source) : !proseChecked ? "prose_logs_consulted=true" : !classified ? "classification=" + (parsed && parsed.diagnosis && parsed.diagnosis.classification) : !hasEvidence ? "no evidence" : "");
    cleanDir(root);
  })();

  // 5b: Injection prose in rollback-families evidence → stays as DATA, not instructions
  //     The adapter only surfaces fingerprint+family from rollback records.
  //     Even if the family string contains instruction-like prose, it appears as typed data
  //     in the evidence array, not as an instruction to the diagnosis engine.
  (function() {
    var root = makeTempDir("a5-inj");
    try {
      setupWindowState(root, "HALT_HUMAN");
      addRollbackFamily(root, "a".repeat(24), "INJECTED_EXEC_cmd_rm_rf_DANGER", { payload: "exec('rm -rf /')" });
    } catch (e) {
      report("5b: injection stays as data", false, "setup failed: " + e.message);
      cleanDir(root);
      return;
    }
    var r = runHeal(["--diagnose", "--root", root]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var evidence = parsed && parsed.diagnosis && parsed.diagnosis.evidence;
    // Find the rollback evidence entry
    var rbEvidence = evidence ? evidence.filter(function(e) { return e.record_type === "ROLLBACK_RECORDED"; }) : [];
    var hasRb = rbEvidence.length > 0;
    // The diagnosis classification should be from the window (HALT_HUMAN),
    // NOT derived from the injection prose in the family/evidence.
    // The injection appears in evidence as typed DATA (faithfully reported),
    // but the diagnosis engine's classification must come from window state.
    var correctClass = parsed && parsed.diagnosis && parsed.diagnosis.classification === "HALT_HUMAN";
    // Injection appears in evidence (expected — it's typed data) but NOT as classification driver
    var injectionInEvidence = hasRb && rbEvidence.some(function(e) {
      return e.family && /INJECTED_EXEC/i.test(e.family);
    });
    var proseNotInClassification = correctClass && parsed.diagnosis &&
      !/INJECT|rm_rf|DANGER/i.test(JSON.stringify({ classification: parsed.diagnosis.classification, cause_code: parsed.diagnosis.cause_code }));
    report("5b: injection prose in rollback evidence stays as DATA, diagnosis from window",
      hasRb && injectionInEvidence && proseNotInClassification,
      !hasRb ? "no rollback evidence" : !injectionInEvidence ? "injection not in evidence (adapter dropped it)" : !proseNotInClassification ? "injection reached classification fields" : "");
    cleanDir(root);
  })();

  // 5c: diagnose with NO_WINDOW state → still works, no prose injection
  (function() {
    var root = makeTempDir("a5-nowindow");
    // No setup — empty state
    var stDir = path.join(root, ".graphsmith", "state");
    mkdirs(stDir);
    var r = runHeal(["--diagnose", "--root", root]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var cls = parsed && parsed.diagnosis && parsed.diagnosis.classification;
    var cause = parsed && parsed.diagnosis && parsed.diagnosis.cause_code;
    // Even with no window, diagnose should work cleanly through the adapter
    report("5c: diagnose handles NO_WINDOW state",
      cls === "NO_WINDOW" && r.exitCode === 0,
      "classification=" + cls + " cause_code=" + cause);
    cleanDir(root);
  })();

  // 5d: All evidence records have typed record_type (never raw prose)
  (function() {
    var root = makeTempDir("a5-typed");
    try { setupWindowState(root, "HALT_HUMAN"); } catch (e) {
      report("5d: all evidence has typed record_type", false, "setup failed: " + e.message);
      cleanDir(root);
      return;
    }
    var r = runHeal(["--diagnose", "--root", root]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var evidence = parsed && parsed.diagnosis && parsed.diagnosis.evidence;
    var allTyped = evidence && evidence.length > 0 && evidence.every(function(e) { return e && typeof e.record_type === "string"; });
    report("5d: all evidence records have typed record_type",
      allTyped,
      !evidence ? "no evidence" : !allTyped ? "some records lack record_type" : "");
    cleanDir(root);
  })();

  // 5e: diagnose raw_source NEVER raw prose logs
  (function() {
    var root = makeTempDir("a5-rawsrc");
    try { setupWindowState(root, "HALT_HUMAN"); } catch (e) {
      report("5e: raw_source is typed adapter", false, "setup failed: " + e.message);
      cleanDir(root);
      return;
    }
    var r = runHeal(["--diagnose", "--root", root]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var rawSrc = parsed && parsed.diagnosis && parsed.diagnosis.raw_source;
    report("5e: raw_source is always state-store.typed-records+adapter",
      rawSrc === "state-store.typed-records+adapter",
      "raw_source=" + JSON.stringify(rawSrc));
    cleanDir(root);
  })();
})();

console.log("\n=== ATTACK 6: No in-place mutation ever (cross-cut verification) ===\n");

(function() {
  var root = makeTempDir("a6-cross");
  mkdirs(path.join(root, "workers"));

  var allFiles = [
    "step.js", "worker.js", "manager.js",
    "workers/gather.prompt.md", "tunables.json", "config.json", "readme.md"
  ];
  writeFile(path.join(root, "step.js"), "// step executable\n");
  writeFile(path.join(root, "worker.js"), "// worker executable\n");
  writeFile(path.join(root, "manager.js"), "// manager executable\n");
  writeFile(path.join(root, "workers/gather.prompt.md"), "You are gather.\n");
  writeFile(path.join(root, "tunables.json"), "{}");
  writeFile(path.join(root, "config.json"), "{}");
  writeFile(path.join(root, "readme.md"), "# readme\n");

  var beforeOnce = snapshotHashes(root, allFiles);

  // --diagnose
  (function() {
    try { setupWindowState(root, "NO_WINDOW"); } catch (_) {}
    runHeal(["--diagnose", "--root", root]);
    assertUnchanged("6a", root, allFiles, beforeOnce);
  })();

  // --stage code (.js)
  (function() {
    var propFile = path.join(root, ".prop-6b.js");
    writeFile(propFile, "exports.x = 42;\n");
    runHeal(["--stage", "step.js", "--root", root, "--proposed", propFile]);
    assertUnchanged("6b", root, allFiles, beforeOnce);
  })();

  // --stage typed (prompt.md)
  (function() {
    var propFile = path.join(root, ".prop-6c.js");
    writeFile(propFile, "Safe text.\n");
    runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    assertUnchanged("6c", root, allFiles, beforeOnce);
  })();

  // --stage typed (.md)
  (function() {
    var propFile = path.join(root, ".prop-6d.js");
    writeFile(propFile, "# safe readme\n");
    runHeal(["--stage", "readme.md", "--root", root, "--proposed", propFile]);
    assertUnchanged("6d", root, allFiles, beforeOnce);
  })();

  // --stage manager.js (should be refused, but NEVER mutate)
  (function() {
    var propFile = path.join(root, ".prop-6e.js");
    writeFile(propFile, "console.log('hack');\n");
    runHeal(["--stage", "manager.js", "--root", root, "--proposed", propFile]);
    assertUnchanged("6e", root, allFiles, beforeOnce);
  })();

  // --stage ./manager.js (should be refused, but NEVER mutate)
  (function() {
    var propFile = path.join(root, ".prop-6f.js");
    writeFile(propFile, "console.log('hack2');\n");
    runHeal(["--stage", "./manager.js", "--root", root, "--proposed", propFile]);
    assertUnchanged("6f", root, allFiles, beforeOnce);
  })();

  // rollback unknown id (should fail, but NEVER mutate)
  (function() {
    runHeal(["rollback", "deadbeefdeadbeefdeadbeef", "--root", root]);
    assertUnchanged("6g", root, allFiles, beforeOnce);
  })();

  // typed stage + rollback (should restore)
  (function() {
    var propFile = path.join(root, ".prop-6h.js");
    writeFile(propFile, "Modified text.\n");
    var sr = runHeal(["--stage", "workers/gather.prompt.md", "--root", root, "--proposed", propFile]);
    var sp = null;
    try { sp = JSON.parse(sr.stdout); } catch (_) {}
    if (sp && sp.heal_id) {
      writeFile(path.join(root, "workers/gather.prompt.md"), "Modified text.\n");
      runHeal(["rollback", sp.heal_id, "--root", root]);
    }
    assertUnchanged("6h", root, allFiles, beforeOnce);
  })();

  cleanDir(root);
})();

console.log("\n=== EDGE CASE TESTS ===\n");

(function() {
  var root = makeTempDir("a7-edge");
  mkdirs(path.join(root, "workers"));
  writeFile(path.join(root, "step.js"), "exports.x = 1;\n");
  writeFile(path.join(root, "workers/gather.prompt.md"), "You are gather.\n");
  writeFile(path.join(root, "readme.md"), "# Project\n");
  writeFile(path.join(root, "settings.config.json"), "{}");
  writeFile(path.join(root, "notes.txt"), "plain text notes\n");

  // 7a: .md file classified as typed:data
  (function() {
    var propFile = path.join(root, ".prop-7a.js");
    writeFile(propFile, "# Modified\n");
    var r = runHeal(["--stage", "readme.md", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var typed = parsed && parsed.repair_class === "typed";
    var kind = parsed && parsed.kind;
    report("7a: .md file classified as typed:data",
      typed && kind === "data" && r.exitCode === 0,
      !typed ? "not typed" : "kind=" + kind);
  })();

  // 7b: .config.json classified as typed:config
  (function() {
    var propFile = path.join(root, ".prop-7b.js");
    writeFile(propFile, '{"key":"val"}');
    var r = runHeal(["--stage", "settings.config.json", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var typed = parsed && parsed.repair_class === "typed";
    var kindConfig = parsed && parsed.kind === "config";
    report("7b: .config.json classified as typed:config",
      typed && kindConfig && r.exitCode === 0,
      !typed ? "not typed" : "kind=" + (parsed && parsed.kind));
  })();

  // 7c: Missing target → TARGET_NOT_FOUND error
  (function() {
    var r = runHeal(["--stage", "nonexistent.js", "--root", root]);
    var failed = r.exitCode !== 0;
    report("7c: missing target errors cleanly",
      failed,
      !failed ? "succeeded unexpectedly" : "");
  })();

  // 7d: --stage without target → usage error
  (function() {
    var r = runHeal(["--stage", "--root", root]);
    var usage = r.exitCode !== 0 && r.exitCode !== null;
    report("7d: --stage without target shows usage",
      usage,
      "exit=" + r.exitCode);
  })();

  // 7e: unknown subcommand → usage
  (function() {
    var r = runHeal(["--unknown", "--root", root]);
    var usage = r.exitCode !== 0 && r.exitCode !== null;
    report("7e: unknown subcommand shows usage",
      usage,
      "exit=" + r.exitCode);
  })();

  // 7f: .txt file classified as typed:data (not executable)
  (function() {
    var propFile = path.join(root, ".prop-7f.js");
    writeFile(propFile, "plain notes updated\n");
    var r = runHeal(["--stage", "notes.txt", "--root", root, "--proposed", propFile]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var typed = parsed && parsed.repair_class === "typed";
    var kind = parsed && parsed.kind;
    report("7f: .txt file classified as typed:data",
      typed && kind === "data" && r.exitCode === 0,
      !typed ? "not typed: class=" + (parsed && parsed.repair_class) + " kind=" + (parsed && parsed.kind) : "kind=" + kind);
  })();

  // 7g: Stage with --proposed as inline text (not a file)
  (function() {
    var r = runHeal(["--stage", "readme.md", "--root", root, "--proposed", "# inline proposed content"]);
    var parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch (_) {}
    var staged = parsed && parsed.heal_id;
    report("7g: --proposed with inline text works",
      staged && r.exitCode === 0,
      !staged ? "no heal_id" : "");
  })();

  cleanDir(root);
})();

// ====== SUMMARY ======

console.log("\n=== RESULTS ===");
console.log(JSON.stringify({ passed: passed, failed: failures, skipped: skipped, total: passed + failures + skipped }));
process.exit(failures > 0 ? 1 : 0);