#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const Module = require("module");

const REPO = path.resolve(__dirname, "..", "..", "..");
const temps = [];
const results = [];
const priorMode = process.env.GRAPHSMITH_TEST_MODE;
process.env.GRAPHSMITH_TEST_MODE = "1";

function sha256(value) {
  const input = typeof value === "string" || Buffer.isBuffer(value) ? value : JSON.stringify(value);
  return crypto.createHash("sha256").update(input).digest("hex");
}

function temp(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `gs-review-sol-${tag}-`));
  temps.push(dir);
  return dir;
}

function sandbox(tag) {
  const root = temp(tag);
  fs.cpSync(path.join(REPO, "scripts"), path.join(root, "scripts"), { recursive: true });
  fs.cpSync(path.join(REPO, "schemas"), path.join(root, "schemas"), { recursive: true });
  return root;
}

function script(root, name) {
  return path.join(root, "scripts", name);
}

function load(root, name) {
  return require(script(root, name));
}

function mutate(root, name, before, after) {
  const file = script(root, name);
  const source = fs.readFileSync(file, "utf8");
  const first = source.indexOf(before);
  if (first < 0 || source.indexOf(before, first + before.length) >= 0) {
    throw new Error(`mutation anchor must occur exactly once in ${name}: ${before.slice(0, 80)}`);
  }
  fs.writeFileSync(file, source.slice(0, first) + after + source.slice(first + before.length));
}

function append(root, name, source) {
  fs.appendFileSync(script(root, name), `\n${source}\n`);
}

function record(status, name, detail) {
  results.push({ status, name, detail });
  console.log(`${status}\t${name}\t${String(detail).replace(/\s+/g, " ").slice(0, 360)}`);
}

function bite(name, baseline, mutant, detail) {
  if (!baseline) {
    record("REAL-HOLE", name, `shipped attack failed: ${detail}`);
  } else if (mutant) {
    record("HOLLOW", name, `broken guarantee still passed: ${detail}`);
  } else {
    record("BITES", name, `shipped=PASS mutant=FAIL ${detail}`);
  }
}

function pointerBytes(pointer) {
  return Buffer.from(`${JSON.stringify(pointer, null, 2)}\n`, "utf8");
}

function locations(root) {
  const state = path.join(root, ".graphsmith", "state");
  const evolvable = path.join(root, ".graphsmith", "evolvable");
  return {
    root,
    state,
    evolvable,
    active: path.join(evolvable, "ACTIVE"),
    adoption: path.join(state, "adoption-log.jsonl"),
    projectManifest: path.join(state, "project.manifest.json"),
    journal: path.join(state, "journal.jsonl"),
  };
}

function createFixture(projectRoot, modules, label) {
  const paths = locations(projectRoot);
  fs.mkdirSync(paths.state, { recursive: true });
  fs.mkdirSync(paths.evolvable, { recursive: true });
  const seed = path.join(paths.evolvable, "seed");
  fs.mkdirSync(seed);
  fs.writeFileSync(path.join(seed, "graphsmith.learned.md"), "alpha\n");
  fs.writeFileSync(path.join(seed, "tunables.json"), "{\n  \"limit\": 1\n}\n");
  fs.mkdirSync(path.join(seed, "workers"));
  fs.writeFileSync(path.join(seed, "workers", "demo.prompt.md"), "hello worker\n");
  const manifest = modules.manifest.generate("tree", { rootDir: seed });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  fs.writeFileSync(path.join(seed, "tree.manifest.json"), manifestBytes);
  const tree = `v-${sha256(manifestBytes)}`;
  fs.renameSync(seed, path.join(paths.evolvable, tree));
  const pointer = {
    schema_version: modules.schemaVersion,
    txid: "0".repeat(16),
    tree,
    tree_manifest_sha256: sha256(manifestBytes),
  };
  fs.writeFileSync(paths.active, pointerBytes(pointer));
  fs.writeFileSync(paths.projectManifest, `${JSON.stringify({
    schema_version: modules.schemaVersion,
    kind: "project",
    generated_at: label,
    parent_release_sha256: null,
    adoption_log_head: null,
    active_tree: tree,
    active_tree_manifest_sha256: sha256(manifestBytes),
    files: [],
    workflow_manifests: [],
  }, null, 2)}\n`);
  return { paths, tree, pointer };
}

function packet(root, suffix, schemaVersion, extra = {}) {
  return {
    project_root: root,
    fingerprint: sha256(`review:${suffix}`),
    kind: "doc",
    evidence_ref: `review:${suffix}`,
    human: { name: "review", decision: "approve", ts: "2000-01-01T00:00:00.000Z" },
    edits: [{
      schema_version: schemaVersion,
      schema_ref: "review",
      file: "graphsmith.learned.md",
      anchor: "alpha",
      op: "replace",
      payload: suffix,
    }],
    reversible: true,
    auto_rollback_eligible: true,
    window_n: 1,
    ...extra,
  };
}

function catchCall(fn) {
  try {
    return { ok: true, result: fn() };
  } catch (error) {
    return { ok: false, code: error.code, message: error.message, evidence: error.evidence };
  }
}

function closeWindow(root, stateStore, schemaVersion) {
  const store = stateStore.createStore(root);
  const lock = store._testing.acquireLock();
  try {
    store._commit([{
      file: "window.json",
      make: (raw, rev) => {
        const current = raw ? JSON.parse(raw) : {
          schema_version: schemaVersion,
          state_rev: 0,
          state: "NO_WINDOW",
          flag: false,
          window: null,
        };
        current.state = "CLOSED_PASS";
        current.state_rev = rev;
        return JSON.stringify(current);
      },
    }]);
  } finally {
    clearInterval(lock.heartbeat);
    store._testing.releaseLock(lock.ownerToken);
  }
}

function makeBundle() {
  const pairs = [{
    scenario_id: "hash-0",
    seed: 1,
    cand: { pass: true, cause_code: "ok" },
    base: { pass: false, cause_code: "ok" },
  }];
  const bundle = {
    schema_version: "1.0",
    corpus_hash: sha256("hash-0"),
    evaluator_version: "1.0.0",
    model_versions: { candidate: "tampered", baseline: "b" },
    pairs,
    slices: [],
  };
  bundle.bundle_sha256 = "0".repeat(64);
  return bundle;
}

function bundleHashOracle(root) {
  const result = load(root, "gate.js").gate2Behavioral("tampered", {
    bundle: makeBundle(),
    cycleSeed: 0,
    stateStore: null,
  });
  return result.pass === false && result.tier === 0 && result.evidence && result.evidence.hashValid === false;
}

function reviewBundleHash() {
  const good = sandbox("bundle-good");
  const bad = sandbox("bundle-bad");
  mutate(bad, "gate.js", "if (claimedHash && claimedHash !== recomputed) {", "if (false) {");
  bite("tampered-bundle-hash-gate2", bundleHashOracle(good), bundleHashOracle(bad), "mutant skips bundle hash rejection");
}

function treeVerifyOracle(root) {
  const verify = load(root, "verify.js");
  const manifest = load(root, "manifest.js");
  const project = temp("tree-project");
  const fixture = createFixture(project, {
    manifest,
    schemaVersion: manifest.SCHEMA_VERSION,
  }, "tree-review");
  fs.writeFileSync(path.join(fixture.paths.evolvable, fixture.tree, "graphsmith.learned.md"), "TAMPERED\n");
  const report = verify.runIntegrity(project, {});
  const status = report.checks && report.checks.active_tree && report.checks.active_tree.status;
  return status !== "ok" && report.failure_domain !== "none" && verify.integrityExitCode(report) !== 0 && report.frozen === true;
}

function reviewTreeVerify() {
  const good = sandbox("tree-good");
  const bad = sandbox("tree-bad");
  mutate(bad, "verify.js", "status: treeResult.ok ? \"ok\" : \"fail\",", "status: \"ok\",");
  bite("tampered-tree-verify", treeVerifyOracle(good), treeVerifyOracle(bad), "mutant reports active tree ok regardless of verifyTree result");
}

function promoteModules(root) {
  const promote = load(root, "promote.js");
  return {
    promote,
    manifest: load(root, "manifest.js"),
    stateStore: load(root, "state-store.js"),
    schemaVersion: promote.SCHEMA_VERSION,
  };
}

function adoptionOracle(root) {
  const modules = promoteModules(root);
  const project = temp("chain-project");
  const fixture = createFixture(project, modules, "chain-review");
  const setup = modules.promote.promote(packet(project, "chain-setup", modules.schemaVersion));
  if (!setup || setup.state !== "DONE") return false;
  const lines = fs.readFileSync(fixture.paths.adoption, "utf8").split("\n").filter(Boolean);
  const last = JSON.parse(lines.at(-1));
  last.fingerprint = "a".repeat(64);
  lines[lines.length - 1] = JSON.stringify(last);
  fs.writeFileSync(fixture.paths.adoption, `${lines.join("\n")}\n`);
  closeWindow(project, modules.stateStore, modules.schemaVersion);
  const result = catchCall(() => modules.promote.promote(packet(project, "chain-attack", modules.schemaVersion, {
    edits: [{
      schema_version: modules.schemaVersion,
      schema_ref: "review",
      file: "graphsmith.learned.md",
      anchor: "chain-setup",
      op: "replace",
      payload: "attack",
    }],
  })));
  return !result.ok && (result.code === "HALT" || result.code === "CORRUPT_STATE");
}

function reviewAdoptionChain() {
  const good = sandbox("chain-good");
  const bad = sandbox("chain-bad");
  const before = "if (entry.schema_version !== SCHEMA_VERSION || entry.seq !== index + 1 || entry.prev_sha256 !== previous || sha256(JSON.stringify(body)) !== claimed) {";
  const after = "if (false && (entry.schema_version !== SCHEMA_VERSION || entry.seq !== index + 1 || entry.prev_sha256 !== previous || sha256(JSON.stringify(body)) !== claimed)) {";
  mutate(bad, "promote.js", before, after);
  bite("adoption-log-chain-break-HALT", adoptionOracle(good), adoptionOracle(bad), "mutant disables adoption entry chain/digest verification");
}

function parseJsonl(file) {
  const raw = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  return raw.split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

function postBeginOracle(root) {
  const modules = promoteModules(root);
  const project = temp("post-begin-project");
  const fixture = createFixture(project, modules, "post-begin-review");
  const crashed = catchCall(() => modules.promote.promote(packet(project, "begin-crash", modules.schemaVersion, {
    __test_crash_at: "before-swap",
  })));
  if (crashed.ok || crashed.code !== "SIMULATED_CRASH") return false;
  const hostile = { ...fixture.pointer, txid: "f".repeat(16) };
  fs.writeFileSync(fixture.paths.active, pointerBytes(hostile));
  const recovered = catchCall(() => modules.promote.recover(project));
  const hasHaltish = !recovered.ok && (recovered.code === "HALT" || recovered.code === "CORRUPT_STATE");
  if (hasHaltish || (!recovered.ok && recovered.code)) return true;
  const second = catchCall(() => modules.promote.promote(packet(project, "second", modules.schemaVersion)));
  return !(second.ok && second.result && second.result.state === "DONE");
}

function reviewPostBegin() {
  const good = sandbox("post-good");
  const bad = sandbox("post-bad");
  const before = "if (![oldActiveSha, toActiveSha].includes(activeSha)) recoveryHalt(paths, txid, \"ACTIVE has an unclassifiable identity\", { oldActiveSha, toActiveSha, activeSha });";
  const after = "if (![oldActiveSha, toActiveSha].includes(activeSha)) throw failure(\"ACTIVE has an unclassifiable identity\", \"CORRUPT_STATE\");";
  mutate(bad, "promote.js", before, after);
  bite("post-BEGIN-ACTIVE-mutation-HALT", postBeginOracle(good), postBeginOracle(bad), "mutant downgrades required HALT-with-evidence to CORRUPT_STATE; corpus oracle accepts it");
}

const BUILTINS = new Set([...Module.builtinModules, ...Module.builtinModules.map((name) => `node:${name}`)]);

function findRequires(source) {
  const found = [];
  const pattern = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    const lineStart = source.lastIndexOf("\n", match.index) + 1;
    if (source.slice(lineStart, match.index).includes("//")) continue;
    found.push(match[1]);
  }
  return found;
}

function nonBuiltinOracle(root) {
  return findRequires(fs.readFileSync(script(root, "gate.js"), "utf8")).every((spec) =>
    spec.startsWith(".") || spec.startsWith("/") || BUILTINS.has(spec) || BUILTINS.has(spec.replace(/^node:/, ""))
  );
}

function stripNoise(source) {
  let output = "";
  let index = 0;
  while (index < source.length) {
    if (source[index] === "/" && source[index + 1] === "/") {
      while (index < source.length && source[index] !== "\n") index++;
    } else if (source[index] === "/" && source[index + 1] === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) index++;
      index += 2;
    } else if (source[index] === "'" || source[index] === '"' || source[index] === "`") {
      const quote = source[index++];
      while (index < source.length && source[index] !== quote) {
        if (source[index] === "\\") index++;
        index++;
      }
      index++;
      output += '""';
    } else {
      output += source[index++];
    }
  }
  return output;
}

function evalOracle(root) {
  const cleaned = stripNoise(fs.readFileSync(script(root, "gate.js"), "utf8"));
  return !/(?<![\w$.])eval\s*\(|(?<![\w$.])Function\s*\(|new\s+Function\s*\(/.test(cleaned);
}

function networkOracle(root) {
  const source = fs.readFileSync(script(root, "gate.js"), "utf8");
  const patterns = [
    /\brequire\s*\(\s*["']net["']\s*\)/,
    /\brequire\s*\(\s*["']http["']\s*\)/,
    /\brequire\s*\(\s*["']https["']\s*\)/,
    /\bfetch\s*\(/,
  ];
  return !patterns.some((pattern) => pattern.test(source) || pattern.test(stripNoise(source)));
}

function reviewStaticChecks() {
  const requireGood = sandbox("require-good");
  const requireBad = sandbox("require-bad");
  append(requireBad, "gate.js", "require(\"evil-pkg\");");
  bite("module-escape/no-nonbuiltin-require-gate.js", nonBuiltinOracle(requireGood), nonBuiltinOracle(requireBad), "mutant adds non-builtin require");

  const evalGood = sandbox("eval-good");
  const evalBad = sandbox("eval-bad");
  append(evalBad, "gate.js", "eval(\"1\");");
  bite("module-escape/no-eval-Function-gate.js", evalOracle(evalGood), evalOracle(evalBad), "mutant adds direct eval");

  const networkGood = sandbox("network-good");
  const networkBad = sandbox("network-bad");
  append(networkBad, "gate.js", "require(\"net\");");
  bite("module-escape/no-network-api-gate.js", networkOracle(networkGood), networkOracle(networkBad), "mutant adds net API import");
}

function childProcessOracle(root) {
  const gate = load(root, "gate.js");
  const pairs = [{
    scenario_id: "child-0",
    seed: 1,
    cand: { pass: true, cause_code: "ok" },
    base: { pass: true, cause_code: "ok" },
  }];
  const bundle = { schema_version: "1.0", corpus_hash: sha256("child"), pairs, slices: [] };
  bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
  const result = gate.gate2Behavioral("child", { bundle, cycleSeed: 0, stateStore: null });
  return !!result && typeof result.pass === "boolean";
}

function reviewChildProcess() {
  const good = sandbox("child-good");
  const bad = sandbox("child-bad");
  mutate(
    bad,
    "gate.js",
    "function gate2Behavioral(candidateId, opts = {}) {\n  const { corpusPath, profile, cycleSeed, bundle, stateStore } = opts;",
    "function gate2Behavioral(candidateId, opts = {}) {\n  spawn(process.execPath, [\"-e\", \"\"], { stdio: \"ignore\" }).unref();\n  const { corpusPath, profile, cycleSeed, bundle, stateStore } = opts;"
  );
  bite("module-escape/child_process-posture-gate.js", childProcessOracle(good), childProcessOracle(bad), "mutant spawns on the in-memory decision path; oracle only checks for a boolean result");
}

function reportGaps() {
  record("GAP", "A2-compromised-dependency", "no attack exercises pinned tool content-hash refusal or commit-SHA-pinned CI actions");
  record("GAP", "A3-hostile-contributor", "no attack exercises trusted-workflow secret isolation, trusted attestations, or evaluator/corpus PR separation");
  record("GAP", "A4-artifact-injection", "marker strings are covered, but typed-event source authentication and safety-relevant gap invalidation are not attacked");
  record("GAP", "A5-malicious-BYO-tool", "no attack proves container-required refusal/unavailable, network denial, source read-only mounting, or environment scrubbing");
  record("DODGED", "toctou/true-parallel-rename-race", "UNAVAILABLE is not justified: a zero-dependency multi-process harness can synchronize child writers with IPC/barriers and inspect exit codes plus final disk state; platform variance warrants per-platform results, not 'inherently unprovable'");
  record("LOG-ORACLE", "none-found", "reviewed PASS branches use return fields, error codes, process exits, static scan results, marker files, or disk state; stdout JSON in gate selftest is secondary to exit=0");
}

function cleanup() {
  for (const dir of temps) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (_) {}
  }
  if (priorMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
  else process.env.GRAPHSMITH_TEST_MODE = priorMode;
}

function main() {
  console.log("=== gpt-sol-pro attack-corpus negative controls ===");
  try {
    reviewTreeVerify();
    reviewBundleHash();
    reviewAdoptionChain();
    reviewPostBegin();
    reviewStaticChecks();
    reviewChildProcess();
    reportGaps();
  } catch (error) {
    record("HARNESS-ERROR", "review-aborted", error.stack || error.message);
  } finally {
    cleanup();
  }

  const bites = results.filter((result) => result.status === "BITES").length;
  const hollow = results.filter((result) => result.status === "HOLLOW").length;
  const holes = results.filter((result) => result.status === "REAL-HOLE" || result.status === "HARNESS-ERROR").length;
  const gaps = results.filter((result) => result.status === "GAP" || result.status === "DODGED").length;
  console.log(`--- summary bites=${bites} hollow=${hollow} real_holes=${holes} gaps=${gaps} ---`);
  process.exit(hollow || holes ? 1 : 0);
}

main();
