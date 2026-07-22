#!/usr/bin/env node
/* GraphSmith manifest generator & tree verifier — zero-dep CJS, Node ≥ 18.
 * v0.2.0: implements contract 09 (manifest formats) + contract 01 §Topology
 * (tree.manifest.json closed inventory).
 *
 * Exports:  generate(kind, opts) · verifyTree(manifestPath, rootDir)
 * CLI:      node manifest.js generate <release|project|tree> [opts]
 *           node manifest.js verify <manifest.json> --root <dir>
 *           node manifest.js --selftest
 *
 * Hashing:  raw-byte SHA-256, no content normalization (contract 09 v2).
 * Paths:    repo-relative, forward slashes, NFC, case-fold collision REFUSAL.
 * No clocks/randomness in decision paths (timestamps in metadata OK). */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const SCHEMA_VERSION = "1.0";

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function toForwardSlash(p) {
  return p.split(path.sep).join("/");
}

function canonicalPath(p) {
  return toForwardSlash(p).normalize("NFC");
}

function walkDir(dir, base) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkDir(full, base));
    } else if (entry.isFile()) {
      results.push(path.relative(base, full));
    }
  }
  return results;
}

function checkCaseFoldCollisions(paths) {
  const seen = new Map();
  for (const p of paths) {
    const folded = p.toLowerCase();
    if (seen.has(folded)) {
      throw new Error(
        `Case-fold collision: "${p}" and "${seen.get(folded)}" are identical after case-fold — refused (contract 09)`
      );
    }
    seen.set(folded, p);
  }
}

function hashFiles(filePaths, rootDir) {
  const files = [];
  for (const rel of filePaths) {
    const full = path.join(rootDir, rel);
    const buf = fs.readFileSync(full);
    files.push({
      path: canonicalPath(rel),
      sha256: sha256(buf),
      bytes: buf.length,
    });
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return files;
}

function generate(kind, opts) {
  opts = opts || {};
  if (!["release", "project", "tree"].includes(kind)) {
    throw new Error(`Unknown manifest kind: ${kind} (expected release|project|tree)`);
  }

  const rootDir = opts.rootDir || opts.root || process.cwd();
  const excludeManifest = opts.excludeManifest || null;

  let rawPaths = walkDir(rootDir, rootDir);

  if (excludeManifest) {
    const exclCanon = canonicalPath(excludeManifest);
    rawPaths = rawPaths.filter((p) => canonicalPath(p) !== exclCanon);
  }

  if (opts.includeOnly) {
    const includeSet = new Set(opts.includeOnly.map(canonicalPath));
    rawPaths = rawPaths.filter((p) => includeSet.has(canonicalPath(p)));
  }

  if (opts.exclude) {
    const excludeSet = new Set(opts.exclude.map(canonicalPath));
    rawPaths = rawPaths.filter((p) => !excludeSet.has(canonicalPath(p)));
  }

  const canonPaths = rawPaths.map(canonicalPath);
  checkCaseFoldCollisions(canonPaths);

  const files = hashFiles(rawPaths, rootDir);

  if (kind === "tree") {
    return { schema_version: SCHEMA_VERSION, files };
  }

  if (kind === "release") {
    return {
      schema_version: SCHEMA_VERSION,
      kind: "release",
      release: opts.release || "0.0.0",
      algo: "sha256",
      files: files.map((f) => ({ path: f.path, sha256: f.sha256 })),
      constitutional_set: opts.constitutionalSet || [],
      tunables_bounds: opts.tunablesBounds || {},
      created_by: opts.createdBy || {},
    };
  }

  if (kind === "project") {
    return {
      schema_version: SCHEMA_VERSION,
      kind: "project",
      generated_at: new Date().toISOString(),
      parent_release_sha256: opts.parentReleaseSha256 || null,
      adoption_log_head: opts.adoptionLogHead || null,
      files: files.map((f) => ({ path: f.path, sha256: f.sha256 })),
      workflow_manifests: opts.workflowManifests || [],
    };
  }
}

function verifyTree(manifestPath, rootDir) {
  const raw = fs.readFileSync(manifestPath, "utf8");
  const manifest = JSON.parse(raw);

  if (!manifest.files || !Array.isArray(manifest.files)) {
    throw new Error("Manifest missing .files array");
  }

  const manifestAbs = path.resolve(manifestPath);
  const manifestRel = canonicalPath(path.relative(rootDir, manifestAbs));

  const expected = new Map();
  for (const entry of manifest.files) {
    expected.set(canonicalPath(entry.path), entry);
  }

  const diskPaths = walkDir(rootDir, rootDir);
  const diskCanon = diskPaths.map(canonicalPath).filter((p) => p !== manifestRel);
  checkCaseFoldCollisions(diskCanon);

  const diskSet = new Set(diskCanon);
  const results = [];
  let allOk = true;

  for (const [canonPath, entry] of expected) {
    if (!diskSet.has(canonPath)) {
      results.push({ path: canonPath, status: "missing" });
      allOk = false;
      continue;
    }
    const full = path.join(rootDir, canonPath.split("/").join(path.sep));
    const buf = fs.readFileSync(full);
    const actual = sha256(buf);
    if (actual === entry.sha256 && buf.length === entry.bytes) {
      results.push({ path: canonPath, status: "ok" });
    } else {
      results.push({
        path: canonPath,
        status: "mismatch",
        expected_sha256: entry.sha256,
        actual_sha256: actual,
        expected_bytes: entry.bytes,
        actual_bytes: buf.length,
      });
      allOk = false;
    }
  }

  for (const dp of diskSet) {
    if (!expected.has(dp)) {
      results.push({ path: dp, status: "extra" });
      allOk = false;
    }
  }

  results.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return { ok: allOk, files: results };
}

function selftest() {
  const os = require("os");
  const tmpBase = path.join(os.tmpdir(), "graphsmith-manifest-selftest-");
  const tmpDir = fs.mkdtempSync(tmpBase);
  const failures = [];
  let passed = 0;

  function assert(label, cond, detail) {
    if (cond) {
      passed++;
      process.stderr.write(`  PASS  ${label}\n`);
    } else {
      failures.push(label);
      process.stderr.write(`  FAIL  ${label}${detail ? " — " + detail : ""}\n`);
    }
  }

  try {
    const treeDir = path.join(tmpDir, "tree");
    fs.mkdirSync(path.join(treeDir, "sub"), { recursive: true });
    fs.writeFileSync(path.join(treeDir, "alpha.js"), "const a = 1;\n");
    fs.writeFileSync(path.join(treeDir, "beta.json"), '{"key":"value"}\n');
    fs.writeFileSync(path.join(treeDir, "sub", "gamma.md"), "# hello\n");

    const manifest = generate("tree", { rootDir: treeDir });
    const manifestPath = path.join(treeDir, "tree.manifest.json");
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    assert("generate tree produces schema_version", manifest.schema_version === SCHEMA_VERSION);
    assert("generate tree produces 3 files", manifest.files.length === 3);
    assert("paths are forward-slash", manifest.files.every((f) => !f.path.includes("\\")));

    const v1 = verifyTree(manifestPath, treeDir);
    assert("clean verify: all ok", v1.ok === true);
    assert("clean verify: 3 files ok", v1.files.filter((f) => f.status === "ok").length === 3);

    fs.writeFileSync(path.join(treeDir, "alpha.js"), "const a = 2;\n");
    const v2 = verifyTree(manifestPath, treeDir);
    assert("tamper detected: not ok", v2.ok === false);
    const tampered = v2.files.find((f) => f.path === "alpha.js");
    assert("tamper detected: mismatch status", tampered && tampered.status === "mismatch");

    fs.writeFileSync(path.join(treeDir, "alpha.js"), "const a = 1;\n");
    fs.writeFileSync(path.join(treeDir, "extra.txt"), "sneaky\n");
    const v3 = verifyTree(manifestPath, treeDir);
    assert("extra file rejected: not ok", v3.ok === false);
    const extra = v3.files.find((f) => f.path === "extra.txt");
    assert("extra file rejected: extra status", extra && extra.status === "extra");
    fs.unlinkSync(path.join(treeDir, "extra.txt"));

    let collisionCaught = false;
    try {
      checkCaseFoldCollisions(["Readme.md", "readme.md"]);
    } catch (e) {
      collisionCaught = /case-fold collision/i.test(e.message);
    }
    assert("case-fold collision refused", collisionCaught);

    fs.unlinkSync(path.join(treeDir, "beta.json"));
    const v4 = verifyTree(manifestPath, treeDir);
    assert("missing file detected", v4.ok === false);
    const missing = v4.files.find((f) => f.path === "beta.json");
    assert("missing file: missing status", missing && missing.status === "missing");

    const releaseManifest = generate("release", {
      rootDir: treeDir,
      release: "0.2.0",
      constitutionalSet: ["scripts/gate.js"],
      createdBy: { ci_workflow: "test" },
    });
    assert("release kind field", releaseManifest.kind === "release");
    assert("release algo field", releaseManifest.algo === "sha256");
    assert("release schema_version", releaseManifest.schema_version === SCHEMA_VERSION);

    const projectManifest = generate("project", {
      rootDir: treeDir,
      parentReleaseSha256: "abc123",
      adoptionLogHead: "def456",
    });
    assert("project kind field", projectManifest.kind === "project");
    assert("project has generated_at", typeof projectManifest.generated_at === "string");
    assert("project parent_release_sha256", projectManifest.parent_release_sha256 === "abc123");

    process.stderr.write(`\nselftest: ${passed} passed, ${failures.length} failed\n`);
    if (failures.length > 0) {
      process.stderr.write(`failures: ${failures.join(", ")}\n`);
    }
    return failures.length === 0;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function cli() {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    const ok = selftest();
    process.exit(ok ? 0 : 1);
  }

  const cmd = args[0];
  if (!cmd) {
    process.stderr.write("Usage: node manifest.js <generate|verify> [options]\n");
    process.stderr.write("       node manifest.js --selftest\n");
    process.exit(2);
  }

  if (cmd === "generate") {
    const kind = args[1];
    if (!kind) {
      process.stderr.write("Usage: node manifest.js generate <release|project|tree> [--root <dir>] [--out <file>]\n");
      process.exit(2);
    }
    const opts = {};
    for (let i = 2; i < args.length; i++) {
      if (args[i] === "--root" && args[i + 1]) opts.rootDir = args[++i];
      else if (args[i] === "--release" && args[i + 1]) opts.release = args[++i];
      else if (args[i] === "--exclude-manifest" && args[i + 1]) opts.excludeManifest = args[++i];
      else if (args[i] === "--out" && args[i + 1]) opts._out = args[++i];
    }
    try {
      const manifest = generate(kind, opts);
      const json = JSON.stringify(manifest, null, 2);
      if (opts._out) {
        fs.mkdirSync(path.dirname(path.resolve(opts._out)), { recursive: true });
        fs.writeFileSync(opts._out, json + "\n");
        process.stderr.write(`Wrote ${kind} manifest to ${opts._out}\n`);
      } else {
        process.stdout.write(json + "\n");
      }
      process.exit(0);
    } catch (e) {
      process.stderr.write(`Error: ${e.message}\n`);
      process.exit(1);
    }
  } else if (cmd === "verify") {
    const manifestPath = args[1];
    if (!manifestPath) {
      process.stderr.write("Usage: node manifest.js verify <manifest.json> --root <dir>\n");
      process.exit(2);
    }
    let rootDir = process.cwd();
    for (let i = 2; i < args.length; i++) {
      if (args[i] === "--root" && args[i + 1]) rootDir = args[++i];
    }
    try {
      const result = verifyTree(manifestPath, rootDir);
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      if (result.ok) {
        process.stderr.write("Verification: OK\n");
        process.exit(0);
      } else {
        const counts = { ok: 0, mismatch: 0, missing: 0, extra: 0 };
        for (const f of result.files) counts[f.status]++;
        process.stderr.write(
          `Verification: FAILED (${counts.ok} ok, ${counts.mismatch} mismatch, ${counts.missing} missing, ${counts.extra} extra)\n`
        );
        process.exit(1);
      }
    } catch (e) {
      process.stderr.write(`Error: ${e.message}\n`);
      process.exit(1);
    }
  } else {
    process.stderr.write(`Unknown command: ${cmd}\n`);
    process.stderr.write("Usage: node manifest.js <generate|verify> [options]\n");
    process.exit(2);
  }
}

if (require.main === module) {
  cli();
}

module.exports = { generate, verifyTree, SCHEMA_VERSION };
