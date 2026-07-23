#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const REPO = path.resolve(__dirname, "../../..");
const evalenv = require(path.join(REPO, "scripts", "evalenv.js"));
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-evalenv-gpt-sol-pro-"));
const results = [];
let sequence = 0;

function record(status, name, reason) {
  results.push({ status, name, reason });
  process.stdout.write(status + " " + name + " - " + reason.replace(/\s+/g, " ") + "\n");
}

function pass(name, reason) { record("PASS", name, reason); }
function fail(name, reason) { record("FAIL", name, reason); }
function skipped(name, reason) { record("SKIPPED", name, reason); }

function test(name, body) {
  try {
    const outcome = body();
    if (outcome && outcome.skip) skipped(name, outcome.reason);
  } catch (error) {
    fail(name, "unexpected " + (error && error.stack ? error.stack : String(error)));
  }
}

function area(label) {
  const dir = path.join(ROOT, String(++sequence).padStart(3, "0") + "-" + label);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function envHas(env, name) {
  return Object.keys(env).some((key) => key.toUpperCase() === name.toUpperCase());
}

function envValue(env, name) {
  const key = Object.keys(env).find((candidate) => candidate.toUpperCase() === name.toUpperCase());
  return key === undefined ? undefined : env[key];
}

function withEnv(patch, body) {
  const old = {};
  for (const key of Object.keys(patch)) {
    old[key] = Object.prototype.hasOwnProperty.call(process.env, key) ? process.env[key] : undefined;
    process.env[key] = patch[key];
  }
  try {
    return body();
  } finally {
    for (const key of Object.keys(patch)) {
      if (old[key] === undefined) delete process.env[key];
      else process.env[key] = old[key];
    }
  }
}

function basicSource(parent, label) {
  const src = path.join(parent, label || "source");
  write(path.join(src, "app.txt"), "source-original\n");
  write(path.join(src, "lib", "value.js"), "module.exports = 7;\n");
  write(path.join(src, ".git", "HEAD"), "ref: refs/heads/main\n");
  write(path.join(src, ".graphsmith", "constitutional", "RULE"), "REAL-STATE-MUST-NOT-COPY\n");
  write(path.join(src, "node_modules", "host-only", "index.js"), "module.exports = 'host';\n");
  return src;
}

function createStandard(src, parent, extra) {
  const tmpRoot = path.join(parent, "copies");
  fs.mkdirSync(tmpRoot, { recursive: true });
  return evalenv.create("standard", Object.assign({ sourceDir: src, tmpRoot }, extra || {}));
}

function runProbe(handle, source) {
  const probe = path.join(handle.dir, ".evalenv-test-probe.js");
  fs.writeFileSync(probe, source);
  return spawnSync(process.execPath, [probe], {
    cwd: handle.dir,
    env: handle.env,
    encoding: "utf8",
    timeout: 10000,
  });
}

function testFullCopy() {
  const root = area("full-copy");
  const src = basicSource(root);
  const handle = createStandard(src, root);
  const copyFile = path.join(handle.dir, "app.txt");
  const manifest = readJson(path.join(handle.dir, ".evalenv", "manifest.json"));
  fs.writeFileSync(copyFile, "copy-mutated\n");
  const ok = handle.dir !== src &&
    fs.readFileSync(path.join(src, "app.txt"), "utf8") === "source-original\n" &&
    !fs.existsSync(path.join(handle.dir, ".git")) &&
    !fs.existsSync(path.join(handle.dir, ".graphsmith")) &&
    !fs.existsSync(path.join(handle.dir, "node_modules")) &&
    fs.existsSync(path.join(handle.dir, "lib", "value.js")) &&
    manifest.isolation.git_absent === true && manifest.isolation.graphsmith_state_absent === true;
  if (ok) pass("isolation/full-copy-no-shared-git-or-state", "copy mutation did not alter source; .git/.graphsmith/node_modules absent on disk");
  else fail("isolation/full-copy-no-shared-git-or-state", "detached-copy or exclusion invariant failed; manifest=" + JSON.stringify(manifest.isolation));
  handle.destroy();
}

function testEscapingSymlink() {
  const root = area("escaping-symlink");
  const src = basicSource(root);
  const outside = path.join(root, "outside-constitutional");
  write(path.join(outside, "SECRET"), "OUTSIDE-TREE\n");
  const link = path.join(src, "escape-via-dotdot");
  try {
    fs.symlinkSync(path.join(src, "..", "outside-constitutional"), link, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    return { skip: true, reason: "host could not create directory symlink/junction: " + error.code };
  }
  const handle = createStandard(src, root);
  const leaked = fs.existsSync(path.join(handle.dir, "escape-via-dotdot")) ||
    fs.existsSync(path.join(handle.dir, "escape-via-dotdot", "SECRET"));
  const reported = handle.copyReport.symlinks_skipped.some((item) => path.resolve(item) === path.resolve(link));
  if (!leaked && reported && handle.isolation.symlink_escapes.length === 0) {
    pass("isolation/out-of-tree-symlink-skipped", "../ symlink target absent from copy and skip recorded");
  } else {
    fail("isolation/out-of-tree-symlink-skipped", "leaked=" + leaked + "; report=" + JSON.stringify(handle.copyReport));
  }
  handle.destroy();
}

function testTraversalSourceSpelling() {
  const root = area("dotdot-source");
  const src = basicSource(root, "project");
  write(path.join(root, "sibling-secret.txt"), "SIBLING-MUST-NOT-COPY\n");
  const traversingSpelling = path.join(src, "unused", "..");
  const handle = createStandard(traversingSpelling, root);
  const manifest = readJson(path.join(handle.dir, ".evalenv", "manifest.json"));
  const ok = fs.existsSync(path.join(handle.dir, "app.txt")) &&
    !fs.existsSync(path.join(handle.dir, "sibling-secret.txt")) &&
    manifest.source_dir === path.resolve(src);
  if (ok) pass("isolation/dotdot-source-path-normalized", "source path canonicalized and sibling outside source was not copied");
  else fail("isolation/dotdot-source-path-normalized", "manifest source=" + manifest.source_dir + "; siblingPresent=" + fs.existsSync(path.join(handle.dir, "sibling-secret.txt")));
  handle.destroy();
}

function testNodePathDefault() {
  const root = area("node-path-default");
  const src = basicSource(root);
  const externalModules = path.join(root, "real-tree-modules");
  write(path.join(externalModules, "escape-probe", "index.js"), "module.exports = 'external-module-loaded';\n");
  withEnv({ NODE_PATH: externalModules }, () => {
    const handle = createStandard(src, root);
    const marker = path.join(handle.dir, "node-path-leak.txt");
    const child = runProbe(handle,
      "try { require('escape-probe'); require('fs').writeFileSync(" + JSON.stringify(marker) + ", 'LEAK'); } catch (_) {}\n" +
      "require('fs').writeFileSync('node-path-result.json', JSON.stringify({marker:require('fs').existsSync(" + JSON.stringify(marker) + ")}));\n");
    const probeResult = child.status === 0 ? readJson(path.join(handle.dir, "node-path-result.json")) : null;
    const ok = !envHas(handle.env, "NODE_PATH") && handle.isolation.node_path_stripped === true &&
      child.status === 0 && probeResult.marker === false && !fs.existsSync(marker);
    if (ok) pass("isolation/NODE_PATH-at-real-tree-stripped", "scrubbed env omitted NODE_PATH and trusted resolution probe could not load external module");
    else fail("isolation/NODE_PATH-at-real-tree-stripped", "envHas=" + envHas(handle.env, "NODE_PATH") + "; child=" + child.status + "; marker=" + fs.existsSync(marker));
    handle.destroy();
  });
}

function testNodePathExplicitAllowBypass() {
  const root = area("node-path-explicit-allow");
  const src = basicSource(root);
  const externalModules = path.join(root, "real-tree-modules");
  write(path.join(externalModules, "escape-probe", "index.js"), "module.exports = 'external';\n");
  withEnv({ NODE_PATH: externalModules }, () => {
    const handle = createStandard(src, root, { allowEnv: ["NODE_PATH"] });
    const leaked = envHas(handle.env, "NODE_PATH") || handle.isolation.node_path_stripped !== true || handle.isolation.isolated !== true;
    if (!leaked) pass("isolation/NODE_PATH-cannot-be-explicitly-reallowed", "mandatory B14 strip overrides caller allowlist");
    else fail("isolation/NODE_PATH-cannot-be-explicitly-reallowed", "allowEnv re-enabled NODE_PATH=" + JSON.stringify(envValue(handle.env, "NODE_PATH")) + "; isolation=" + JSON.stringify(handle.isolation));
    handle.destroy();
  });
}

function testCaseVariantExclusion() {
  const root = area("case-variant-state");
  const probeDir = path.join(root, "case-probe");
  fs.mkdirSync(probeDir);
  write(path.join(probeDir, "MiXeD"), "x");
  const caseInsensitive = fs.existsSync(path.join(probeDir, "mixed"));
  if (!caseInsensitive) return { skip: true, reason: "host filesystem is case-sensitive; case-variant name is not the same protected path" };

  const src = path.join(root, "source");
  write(path.join(src, "app.txt"), "ok\n");
  write(path.join(src, ".GRAPHSMITH", "constitutional", "RULE"), "CASE-BYPASS\n");
  write(path.join(src, ".GIT", "HEAD"), "shared-ish\n");
  const handle = createStandard(src, root);
  const copiedState = fs.existsSync(path.join(handle.dir, ".graphsmith", "constitutional", "RULE"));
  const copiedGit = fs.existsSync(path.join(handle.dir, ".git", "HEAD"));
  if (!copiedState && !copiedGit && handle.isolation.isolated === true) {
    pass("isolation/case-variant-protected-dirs-excluded", "case variants of .graphsmith and .git were excluded");
  } else {
    fail("isolation/case-variant-protected-dirs-excluded", "case-insensitive host copied protected dirs; state=" + copiedState + "; git=" + copiedGit + "; isolation=" + JSON.stringify(handle.isolation));
  }
  handle.destroy();
}

function testSecretScrub() {
  const root = area("secret-scrub");
  const src = basicSource(root);
  const fake = {
    FAKE_SECRET: "fake-general-secret-9f17",
    AWS_ACCESS_KEY_ID: "AKIAFAKEEVALENV1234",
    AWS_SECRET_ACCESS_KEY: "fake-aws-secret-71d2",
    OPENROUTER_API_KEY: "sk-or-v1-fake-evalenv-42",
    PATH_OPENROUTER_API_KEY: "smuggled-near-allowlist-88",
  };
  withEnv(fake, () => {
    const handle = createStandard(src, root);
    const serialized = JSON.stringify(handle.env);
    const leakedNames = Object.keys(fake).filter((key) => envHas(handle.env, key));
    const leakedValues = Object.values(fake).filter((value) => serialized.includes(value));
    if (leakedNames.length === 0 && leakedValues.length === 0) {
      pass("secrets/default-deny-and-allowlist-lookalike", "five fake secret names/values absent from returned env");
    } else {
      fail("secrets/default-deny-and-allowlist-lookalike", "leakedNames=" + JSON.stringify(leakedNames) + "; leakedValues=" + JSON.stringify(leakedValues));
    }
    handle.destroy();
  });
}

function testExplicitEnvAllow() {
  const root = area("explicit-env-allow");
  const src = basicSource(root);
  withEnv({ EVALENV_EXPLICIT_MARKER: "allowed-value-123", EVALENV_NOT_ALLOWED: "blocked-value-456" }, () => {
    const handle = createStandard(src, root, { allowEnv: ["EVALENV_EXPLICIT_MARKER"] });
    const ok = envValue(handle.env, "EVALENV_EXPLICIT_MARKER") === "allowed-value-123" && !envHas(handle.env, "EVALENV_NOT_ALLOWED");
    if (ok) pass("secrets/only-explicit-extra-allowlist-passes", "explicit marker passed and neighboring non-allowed marker did not");
    else fail("secrets/only-explicit-extra-allowlist-passes", "env keys=" + JSON.stringify(Object.keys(handle.env)));
    handle.destroy();
  });
}

function testStandardCodeRefusal() {
  const root = area("standard-refusal");
  const handle = createStandard(basicSource(root), root);
  let caught;
  try { handle.runUntrustedCode(["node", "anything.js"]); } catch (error) { caught = error; }
  if (caught && caught.code === "CONTAINER_REQUIRED") pass("container/B10-standard-code-eval-refused", "runUntrustedCode threw CONTAINER_REQUIRED");
  else fail("container/B10-standard-code-eval-refused", "observed=" + (caught && caught.code));
  handle.destroy();
}

function testContainerUnavailable() {
  const root = area("container-unavailable");
  const src = basicSource(root);
  const emptyPath = path.join(root, "no-runtime-bin");
  fs.mkdirSync(emptyPath);
  const handle = evalenv.create("container", {
    sourceDir: src,
    tmpRoot: root,
    envOverrideForDetection: { PATH: emptyPath, Path: emptyPath, PATHEXT: process.env.PATHEXT || "", SYSTEMROOT: process.env.SYSTEMROOT || "" },
  });
  let caught;
  try { handle.runUntrustedCode(["node", "anything.js"]); } catch (error) { caught = error; }
  const ok = handle.profile === "container" && handle.available === false && handle.dir === null &&
    handle.claims.isolation_level === "unavailable" && caught && caught.code === "CONTAINER_UNAVAILABLE";
  if (ok) pass("container/no-runtime-unavailable-never-downgrades", "container handle unavailable with null dir; execution refused CONTAINER_UNAVAILABLE");
  else fail("container/no-runtime-unavailable-never-downgrades", "handle=" + JSON.stringify(handle) + "; error=" + (caught && caught.code));
  handle.destroy();
}

function testRequireContainer() {
  const root = area("require-container");
  const handle = createStandard(basicSource(root), root);
  let caught;
  try { evalenv.requireContainer(handle); } catch (error) { caught = error; }
  if (caught && caught.code === "CONTAINER_REQUIRED") pass("container/requireContainer-refuses-standard", "precondition threw CONTAINER_REQUIRED");
  else fail("container/requireContainer-refuses-standard", "observed=" + (caught && caught.code));
  handle.destroy();
}

function testBudgetsAndBreachCleanup() {
  const root = area("budget-breach");
  const src = path.join(root, "source");
  write(path.join(src, "one.txt"), "1");
  write(path.join(src, "two.txt"), "2");
  const tmpRoot = path.join(root, "copies");
  fs.mkdirSync(tmpRoot);
  let caught;
  try {
    evalenv.create("standard", { sourceDir: src, tmpRoot, budgets: { max_files: 1 } });
  } catch (error) {
    caught = error;
  }
  const leftovers = fs.readdirSync(tmpRoot);
  const ok = caught && caught.code === "BUDGET_BREACH" && /HALT \(budget\): max_files/.test(caught.message) && leftovers.length === 0;
  if (ok) pass("budgets/breach-HALTS-and-cleans-partial-copy", "max_files boundary+1 threw BUDGET_BREACH and tmp root is empty on disk");
  else fail("budgets/breach-HALTS-and-cleans-partial-copy", "error=" + (caught && caught.code) + "; leftovers=" + JSON.stringify(leftovers));
}

function testBudgetStatePresent() {
  const root = area("budget-state");
  const handle = createStandard(basicSource(root), root);
  const file = path.join(handle.dir, ".evalenv", "budget-state.json");
  const state = readJson(file);
  const ok = state.files_copied === handle.budgets.snapshot.files_copied && state.files_copied >= 2 &&
    typeof state.bytes_copied === "number" && state.values.max_files === 200000 && state.values.max_disk_mb === 2048;
  if (ok) pass("budgets/supervisor-state-present-on-disk", "persisted counters and hard-ceiling values match returned snapshot");
  else fail("budgets/supervisor-state-present-on-disk", "state=" + JSON.stringify(state));
  handle.destroy();
}

function testDestroy() {
  const root = area("destroy");
  const handle = createStandard(basicSource(root), root);
  const dir = handle.dir;
  const first = handle.destroy();
  let second;
  let secondError;
  try { second = handle.destroy(); } catch (error) { secondError = error; }
  const ok = !fs.existsSync(dir) && first.destroyed === true && first.already === false &&
    !secondError && second.destroyed === true && second.already === true;
  if (ok) pass("destroy/removes-dir-and-double-destroy-noop", "directory absent after first destroy; second returned already=true");
  else fail("destroy/removes-dir-and-double-destroy-noop", "exists=" + fs.existsSync(dir) + "; first=" + JSON.stringify(first) + "; second=" + JSON.stringify(second));
}

function testHonestClaims() {
  const root = area("honest-claims");
  const handle = createStandard(basicSource(root), root);
  const manifest = readJson(path.join(handle.dir, ".evalenv", "manifest.json"));
  const ok = handle.claims.confidentiality === false && handle.claims.network_containment === false &&
    /no OS-level sandbox/i.test(handle.claims.note) && manifest.profile === "standard";
  if (ok) pass("claims/standard-does-not-overclaim-containment", "returned claims are confidentiality=false and network_containment=false");
  else fail("claims/standard-does-not-overclaim-containment", "claims=" + JSON.stringify(handle.claims) + "; profile=" + manifest.profile);
  handle.destroy();
}

function testStubbedAdapters() {
  const root = area("stubbed-adapters");
  const handle = createStandard(basicSource(root), root);
  const child = runProbe(handle,
    "const fs=require('fs'); const out={};\n" +
    "for (const pair of [['http',require('http')],['https',require('https')]]) { try { pair[1].get('http://127.0.0.1:1/'); out[pair[0]]='NO_REFUSAL'; } catch(e) { out[pair[0]]=e.code; } }\n" +
    "try { fetch('http://127.0.0.1:1/'); out.fetch='NO_REFUSAL'; } catch(e) { out.fetch=e.code; }\n" +
    "fs.writeFileSync('stub-result.json',JSON.stringify(out));\n");
  const file = path.join(handle.dir, "stub-result.json");
  const out = fs.existsSync(file) ? readJson(file) : null;
  const ok = child.status === 0 && out && out.http === "EVALENV_STUBBED_EFFECT" &&
    out.https === "EVALENV_STUBBED_EFFECT" && out.fetch === "EVALENV_STUBBED_EFFECT";
  if (ok) pass("effects/http-https-fetch-refused-by-installed-stub", "trusted probe observed synchronous EVALENV_STUBBED_EFFECT for all installed adapters");
  else fail("effects/http-https-fetch-refused-by-installed-stub", "child=" + child.status + "; result=" + JSON.stringify(out) + "; stderr=" + child.stderr);
  handle.destroy();
}

function testStubPathWithSpaces() {
  const root = area("stub-space-path");
  const src = basicSource(root);
  const spacedTmp = path.join(root, "copy root with spaces");
  fs.mkdirSync(spacedTmp);
  const handle = evalenv.create("standard", { sourceDir: src, tmpRoot: spacedTmp });
  const child = runProbe(handle,
    "const fs=require('fs'); let code; try { require('http').get('http://127.0.0.1:1/'); code='NO_REFUSAL'; } catch(e) { code=e.code; } fs.writeFileSync('space-stub-result.txt',String(code));\n");
  const file = path.join(handle.dir, "space-stub-result.txt");
  const value = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
  if (child.status === 0 && value === "EVALENV_STUBBED_EFFECT") {
    pass("effects/stub-loads-when-copy-path-has-spaces", "NODE_OPTIONS loaded on-disk stub from spaced temp path");
  } else {
    fail("effects/stub-loads-when-copy-path-has-spaces", "child=" + child.status + "; result=" + value + "; NODE_OPTIONS=" + JSON.stringify(handle.env.NODE_OPTIONS) + "; stderr=" + child.stderr);
  }
  handle.destroy();
}

function testStubClaimScope() {
  const root = area("stub-claim-scope");
  const handle = createStandard(basicSource(root), root);
  const source = fs.readFileSync(handle.stubs.file, "utf8");
  const claimsCannotReach = /cannot reach the network/.test(source);
  const coversRawNetwork = /require\(["'](?:node:)?(?:net|tls|dns|dgram)["']\)/.test(source);
  if (!claimsCannotReach || coversRawNetwork) {
    pass("claims/on-disk-stub-does-not-overclaim-network-block", "stub wording is bounded to adapters or raw network modules are controlled");
  } else {
    fail("claims/on-disk-stub-does-not-overclaim-network-block", "stub says candidate cannot reach network but only patches http/https/fetch; net/tls/dns/dgram remain outside the adapter");
  }
  handle.destroy();
}

function testDecisionDeterminism() {
  const root = area("determinism");
  const src = basicSource(root);
  const first = createStandard(src, root);
  const second = createStandard(src, root);
  const firstManifest = readJson(path.join(first.dir, ".evalenv", "manifest.json"));
  const secondManifest = readJson(path.join(second.dir, ".evalenv", "manifest.json"));
  const projection = (handle, manifest) => ({
    profile: handle.profile,
    copied: fs.readFileSync(path.join(handle.dir, "app.txt"), "utf8"),
    excluded: manifest.excluded,
    isolation: manifest.isolation,
    env: Object.fromEntries(Object.entries(handle.env).filter(([key]) => key !== "NODE_OPTIONS")),
    claims: handle.claims,
    budgetValues: handle.budgets.values,
  });
  const same = JSON.stringify(projection(first, firstManifest)) === JSON.stringify(projection(second, secondManifest));
  if (same) pass("determinism/same-inputs-same-security-decisions", "two on-disk copies had identical decision projection; only identifiers/timestamps/elapsed evidence excluded");
  else fail("determinism/same-inputs-same-security-decisions", "security decision projection differed across identical creates");
  first.destroy();
  second.destroy();
}

try {
  test("isolation/full-copy-no-shared-git-or-state", testFullCopy);
  test("isolation/out-of-tree-symlink-skipped", testEscapingSymlink);
  test("isolation/dotdot-source-path-normalized", testTraversalSourceSpelling);
  test("isolation/NODE_PATH-at-real-tree-stripped", testNodePathDefault);
  test("isolation/NODE_PATH-cannot-be-explicitly-reallowed", testNodePathExplicitAllowBypass);
  test("isolation/case-variant-protected-dirs-excluded", testCaseVariantExclusion);
  test("secrets/default-deny-and-allowlist-lookalike", testSecretScrub);
  test("secrets/only-explicit-extra-allowlist-passes", testExplicitEnvAllow);
  test("container/B10-standard-code-eval-refused", testStandardCodeRefusal);
  test("container/no-runtime-unavailable-never-downgrades", testContainerUnavailable);
  test("container/requireContainer-refuses-standard", testRequireContainer);
  test("budgets/breach-HALTS-and-cleans-partial-copy", testBudgetsAndBreachCleanup);
  test("budgets/supervisor-state-present-on-disk", testBudgetStatePresent);
  test("destroy/removes-dir-and-double-destroy-noop", testDestroy);
  test("claims/standard-does-not-overclaim-containment", testHonestClaims);
  test("effects/http-https-fetch-refused-by-installed-stub", testStubbedAdapters);
  test("effects/stub-loads-when-copy-path-has-spaces", testStubPathWithSpaces);
  test("claims/on-disk-stub-does-not-overclaim-network-block", testStubClaimScope);
  test("determinism/same-inputs-same-security-decisions", testDecisionDeterminism);
} finally {
  fs.rmSync(ROOT, { recursive: true, force: true });
}

const passCount = results.filter((item) => item.status === "PASS").length;
const failCount = results.filter((item) => item.status === "FAIL").length;
const skippedCount = results.filter((item) => item.status === "SKIPPED").length;
process.stdout.write("SUMMARY total=" + results.length + " pass=" + passCount + " fail=" + failCount + " skipped=" + skippedCount + "\n");
process.exitCode = failCount === 0 ? 0 : 1;
