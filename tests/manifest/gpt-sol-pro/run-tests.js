#!/usr/bin/env node
"use strict";

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "../../..");
const manifestScript = path.join(repoRoot, "scripts", "manifest.js");
const { generate, verifyTree } = require(manifestScript);
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-manifest-gpt-sol-pro-"));
const results = [];

function digest(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function makeTree(name, files) {
  const root = path.join(scratch, name);
  fs.mkdirSync(root, { recursive: true });
  for (const [relative, contents] of Object.entries(files)) {
    const destination = path.join(root, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, contents);
  }
  return root;
}

function writeTreeManifest(root, manifest) {
  const manifestPath = path.join(root, "tree.manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  return manifestPath;
}

function runCli(args) {
  return spawnSync(process.execPath, [manifestScript, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

function concise(value) {
  return String(value).replace(/\s+/g, " ").trim();
}

function test(name, fn) {
  try {
    const reason = fn();
    results.push({ status: "PASS", name, reason: reason || "contract behavior observed" });
  } catch (error) {
    results.push({ status: "FAIL", name, reason: concise(error.message || error) });
  }
}

function skipped(name, reason) {
  results.push({ status: "SKIPPED", name, reason });
}

function expectRefusalForVirtualNames(names) {
  const virtualRoot = path.join(scratch, `virtual-${results.length}`);
  const originalReaddirSync = fs.readdirSync;
  const originalReadFileSync = fs.readFileSync;
  fs.readdirSync = function patchedReaddirSync(dir, options) {
    if (path.resolve(dir) === path.resolve(virtualRoot) && options && options.withFileTypes) {
      return names.map((name) => ({
        name,
        isDirectory: () => false,
        isFile: () => true,
      }));
    }
    return originalReaddirSync.apply(this, arguments);
  };
  fs.readFileSync = function patchedReadFileSync(file) {
    if (path.dirname(path.resolve(file)) === path.resolve(virtualRoot)) {
      return Buffer.from(path.basename(file), "utf8");
    }
    return originalReadFileSync.apply(this, arguments);
  };
  try {
    assert.throws(
      () => generate("tree", { rootDir: virtualRoot }),
      /collision|refus/i,
      "generate accepted colliding paths"
    );
  } finally {
    fs.readdirSync = originalReaddirSync;
    fs.readFileSync = originalReadFileSync;
  }
}

try {
  test("tamper detection reports mismatch", () => {
    const root = makeTree("tamper", { "payload.bin": Buffer.from([0, 1, 2, 3]) });
    const manifestPath = writeTreeManifest(root, generate("tree", { rootDir: root }));
    fs.writeFileSync(path.join(root, "payload.bin"), Buffer.from([0, 1, 2, 4]));
    const result = verifyTree(manifestPath, root);
    assert.strictEqual(result.ok, false, "tampered tree falsely passed");
    assert.strictEqual(result.files.find((entry) => entry.path === "payload.bin").status, "mismatch");
    return "one-byte change returned mismatch";
  });

  test("closed inventory rejects extra payload", () => {
    const root = makeTree("extra", { "known.txt": "known\n" });
    const manifestPath = writeTreeManifest(root, generate("tree", { rootDir: root }));
    fs.writeFileSync(path.join(root, "extra.txt"), "extra\n");
    const result = verifyTree(manifestPath, root);
    assert.strictEqual(result.ok, false, "extra payload falsely passed");
    assert.strictEqual(result.files.find((entry) => entry.path === "extra.txt").status, "extra");
    return "unlisted file returned extra";
  });

  test("closed inventory rejects missing payload", () => {
    const root = makeTree("missing", { "known.txt": "known\n", "gone.txt": "gone\n" });
    const manifestPath = writeTreeManifest(root, generate("tree", { rootDir: root }));
    fs.unlinkSync(path.join(root, "gone.txt"));
    const result = verifyTree(manifestPath, root);
    assert.strictEqual(result.ok, false, "missing payload falsely passed");
    assert.strictEqual(result.files.find((entry) => entry.path === "gone.txt").status, "missing");
    return "absent listed file returned missing";
  });

  test("tree.manifest.json is not an extra payload", () => {
    const root = makeTree("manifest-exception", { "known.txt": "known\n" });
    const manifestPath = writeTreeManifest(root, generate("tree", { rootDir: root }));
    const result = verifyTree(manifestPath, root);
    assert.strictEqual(result.ok, true, JSON.stringify(result.files));
    assert.ok(!result.files.some((entry) => entry.path === "tree.manifest.json"));
    return "clean tree passed with manifest metadata present";
  });

  test("generate excludes exactly tree.manifest.json automatically", () => {
    const root = makeTree("generate-exclusion", {
      "known.txt": "known\n",
      "tree.manifest.json": "{}\n",
    });
    const generated = generate("tree", { rootDir: root });
    assert.ok(
      !generated.files.some((entry) => entry.path === "tree.manifest.json"),
      "generate inventoried tree.manifest.json as payload"
    );
    return "existing manifest omitted without caller-specific option";
  });

  test("case-fold collision is refused", () => {
    expectRefusalForVirtualNames(["Readme.md", "README.md"]);
    return "public generate refused virtual case-distinct entries";
  });

  test("Unicode NFC/NFD paths canonicalize to NFC", () => {
    const nfd = "cafe\u0301.txt";
    const root = makeTree("unicode-single", { [nfd]: "coffee\n" });
    const generated = generate("tree", { rootDir: root });
    assert.strictEqual(generated.files[0].path, nfd.normalize("NFC"));
    return "NFD filename emitted in NFC form";
  });

  test("Unicode NFC/NFD collision is refused", () => {
    expectRefusalForVirtualNames(["caf\u00e9.txt", "cafe\u0301.txt"]);
    return "public generate refused post-NFC duplicate entries";
  });

  test("raw CRLF and LF bytes hash differently", () => {
    const root = makeTree("raw-bytes", { "lf.txt": "a\nb\n", "crlf.txt": "a\r\nb\r\n" });
    const generated = generate("tree", { rootDir: root });
    const lf = generated.files.find((entry) => entry.path === "lf.txt");
    const crlf = generated.files.find((entry) => entry.path === "crlf.txt");
    assert.notStrictEqual(lf.sha256, crlf.sha256, "line endings were normalized before hashing");
    assert.strictEqual(lf.sha256, digest(Buffer.from("a\nb\n")));
    assert.strictEqual(crlf.sha256, digest(Buffer.from("a\r\nb\r\n")));
    return "hashes match distinct raw-byte SHA-256 values";
  });

  {
    const root = makeTree("link-refusal", { "payload.txt": "payload\n" });
    const outside = makeTree("link-target", { "target.txt": "outside\n" });
    const linkPath = path.join(root, "linked-dir");
    try {
      fs.symlinkSync(outside, linkPath, process.platform === "win32" ? "junction" : "dir");
      test("symlink or junction is refused", () => {
        assert.throws(
          () => generate("tree", { rootDir: root }),
          /symlink|junction|refus/i,
          "generate silently accepted a directory link"
        );
        return "generate refused linked tree entry";
      });
    } catch (error) {
      skipped("symlink or junction is refused", `link creation unavailable: ${concise(error.code || error.message)}`);
    }
  }

  test("tree generation is byte-deterministic", () => {
    const root = makeTree("determinism", { "z.txt": "z\n", "a.txt": "a\n", "sub/b.txt": "b\n" });
    const first = JSON.stringify(generate("tree", { rootDir: root }), null, 2) + "\n";
    const second = JSON.stringify(generate("tree", { rootDir: root }), null, 2) + "\n";
    assert.strictEqual(first, second, "same tree produced different bytes");
    return "two generated serializations were byte-identical";
  });

  test("truncated JSON exits cleanly nonzero", () => {
    const root = makeTree("truncated", { "payload.txt": "payload\n" });
    const manifestPath = path.join(root, "tree.manifest.json");
    fs.writeFileSync(manifestPath, '{"schema_version":"1.0","files":[');
    const child = runCli(["verify", manifestPath, "--root", root]);
    assert.ok(child.status === 1 || child.status === 2, `unexpected exit ${child.status}`);
    assert.match(child.stderr, /^Error:/);
    assert.doesNotMatch(child.stderr, /\n\s+at /, "CLI leaked a stack trace");
    return `exit ${child.status} with concise Error output`;
  });

  test("wrong schema_version exits cleanly nonzero", () => {
    const root = makeTree("wrong-version", { "payload.txt": "payload\n" });
    const generated = generate("tree", { rootDir: root });
    generated.schema_version = "999.0";
    const manifestPath = writeTreeManifest(root, generated);
    const child = runCli(["verify", manifestPath, "--root", root]);
    assert.ok(child.status === 1 || child.status === 2, `false PASS with exit ${child.status}`);
    return `exit ${child.status}`;
  });

  test("negative byte size exits cleanly nonzero", () => {
    const root = makeTree("negative-size", { "payload.txt": "payload\n" });
    const generated = generate("tree", { rootDir: root });
    generated.files[0].bytes = -1;
    const manifestPath = writeTreeManifest(root, generated);
    const child = runCli(["verify", manifestPath, "--root", root]);
    assert.ok(child.status === 1 || child.status === 2, `false PASS with exit ${child.status}`);
    assert.doesNotMatch(child.stderr, /\n\s+at /, "CLI leaked a stack trace");
    return `exit ${child.status} without crash`;
  });

  test("closed schema rejects additional properties", () => {
    const root = makeTree("additional-property", { "payload.txt": "payload\n" });
    const generated = generate("tree", { rootDir: root });
    generated.unexpected = true;
    const manifestPath = writeTreeManifest(root, generated);
    const child = runCli(["verify", manifestPath, "--root", root]);
    assert.ok(child.status === 1 || child.status === 2, `false PASS with exit ${child.status}`);
    return `exit ${child.status}`;
  });

  test("duplicate manifest paths are rejected", () => {
    const root = makeTree("duplicate-entry", { "payload.txt": "payload\n" });
    const generated = generate("tree", { rootDir: root });
    generated.files.push({ ...generated.files[0] });
    const manifestPath = writeTreeManifest(root, generated);
    const child = runCli(["verify", manifestPath, "--root", root]);
    assert.ok(child.status === 1 || child.status === 2, `duplicate entry falsely passed with exit ${child.status}`);
    return `exit ${child.status}`;
  });
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}

for (const result of results) {
  process.stdout.write(`${result.status} ${result.name}: ${result.reason}\n`);
}

const failures = results.filter((result) => result.status === "FAIL").length;
const skippedCount = results.filter((result) => result.status === "SKIPPED").length;
process.stdout.write(`SUMMARY ${results.length - failures - skippedCount} PASS, ${failures} FAIL, ${skippedCount} SKIPPED\n`);
process.exitCode = failures === 0 ? 0 : 1;
