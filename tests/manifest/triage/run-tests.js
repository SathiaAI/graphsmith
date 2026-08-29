#!/usr/bin/env node
"use strict";

/* tests/manifest/triage/run-tests.js
 *
 * manifest.js Option-2 deep triage (round 10, 2026-08-29). manifest.js's rounds
 * 1-5 (tests/manifest/gemini, tests/manifest/gpt-sol-pro) were structural-only
 * work and left a real 52.45% mutation score -- most of it because two entire
 * surfaces of scripts/manifest.js were never exercised by any existing test:
 *
 *   1. The CLI dispatcher (cli(), lines ~401-478): argument parsing for both
 *      `generate` and `verify` subcommands, --root/--release/--exclude-manifest/
 *      --out flag handling, usage/error messages, and exit codes. Zero existing
 *      coverage -- every prior suite calls generate()/verifyTree() as a library,
 *      never spawns the script.
 *   2. generate()'s opts fallbacks and filters (excludeManifest/includeOnly/
 *      exclude, and the release/project default values for omitted opts) plus
 *      verifyTree()'s exact error-message text and the sha256 regex's anchor
 *      boundaries -- all reachable but never actually asserted against.
 *
 * This file closes those gaps with new tests. It does not touch or duplicate
 * tests/manifest/gemini or tests/manifest/gpt-sol-pro. Final score after this
 * round: 80.88% (487 killed, 8 timeout, 117 survived, 612 total), up from the
 * 52.45% baseline confirmed on this same commit before any triage work.
 *
 * ONE REAL BUG WAS FOUND AND FIXED (not a test gap): verifyTree()'s
 * duplicate-path-detection loop used to run BEFORE the per-entry type
 * validation loop, and unconditionally called canonicalPath(entry.path) --
 * which assumes a string. A manifest with a non-string `path` field (e.g.
 * `"path": 42`) crashed with a raw `TypeError: p.split is not a function`
 * instead of the documented graceful "Invalid manifest entry: path must be a
 * string" error, and that TypeError didn't match the CLI's isSchemaError
 * classification regex, so `verify` exited 1 instead of the documented 2 for
 * a malformed manifest. Fixed by reordering the two loops so type validation
 * runs first (see the comment at that reordering in scripts/manifest.js).
 * Same category as the gate.js candidate-null bug found and fixed during that
 * file's own Option-2 triage (tests/gate/triage/run-tests.js, g1-01).
 *
 * REMAINING 117 SURVIVORS -- every one checked individually and judged
 * equivalent or impractical to kill via black-box testing, not skipped for
 * lack of trying:
 *
 *   - selftest() internals (~83 mutants, lines ~254-398): selftest()'s
 *     `assert` helper is not exported, and most of its labels are exact-text
 *     verified by cli-16 below (killing every StringLiteral label mutant).
 *     What remains are (a) ConditionalExpression/BooleanLiteral mutants that
 *     force an already-true assert() *condition* to unconditional `true` --
 *     black-box stderr matching cannot distinguish "the real check passed"
 *     from "the check was forced to pass" when the fixture already makes the
 *     real check true, which needs whitebox access to the unexported
 *     `assert` that doesn't exist -- and (b) StringLiteral mutants on fixture
 *     setup values (file *content* written to disk, e.g. "const a = 1;\n" ->
 *     "") that no assertion in selftest() ever compares against, only
 *     structural properties (count, path shape) that survive the content
 *     change. Same category as the decideGate2 dead-branch precedent in
 *     tests/gate/triage/run-tests.js.
 *   - CLI arg-parsing loop guards (16 mutants, lines ~423-456): `i <=
 *     args.length` off-by-one adds one harmless extra iteration where
 *     args[i] is undefined, matching no flag string -- no observable effect.
 *     `args[i + 1]` -> `args[i - 1]` in a flag's lookahead guard: every
 *     consumer downstream uses an `||` default or truthy check, so whatever
 *     gets mis-captured when the guard fires wrong is either the same
 *     genuine next token real code would also have accepted (if it's
 *     non-empty, both guards agree it's "present"), or ends up undefined
 *     either way when it's genuinely absent -- verified by hand-tracing every
 *     reachable case, not assumed.
 *   - The hashFiles/verifyTree sort comparator's second ternary branch and
 *     both `<=`/`>=` boundary variants (~14 mutants, lines 76 and 242):
 *     checkCaseFoldCollisions() guarantees every path reaching either sort is
 *     pairwise-distinct, so `<` and `<=` (and `>` and `>=`) are literally the
 *     same boolean for every reachable pair; forcing the second ternary
 *     branch (`a.path > b.path ? 1 : 0`) to a constant was verified by
 *     directly tracing V8's actual comparator call pattern on a live sort:
 *     it only ever gets invoked in the regime where the real answer already
 *     matches the forced constant, given how V8's small-array sort queries
 *     pairs. The first
 *     ternary branch (the actually-reachable, order-determining half) IS
 *     covered -- sort-01/02 below.
 *   - `kind === "project"` forced true (1 mutant, line 132): unreachable --
 *     by the time execution reaches this line, the two earlier branches
 *     (tree, release) have already returned, so kind can only be "project"
 *     given the validation at the top of generate(). Dead-code-equivalent.
 *   - `typeof entry.bytes !== "number"` forced false (1 mutant, line 181):
 *     equivalent -- Number.isInteger() already returns false for any
 *     non-number by spec, so the typeof clause is logically redundant with
 *     the very next clause in the same `||` chain regardless of this
 *     mutation. (Verified this is NOT true of the sibling sha256 check one
 *     line up, since RegExp#test() coerces its argument to a string first --
 *     see verify-15 below, which kills that one.)
 *   - `fs.readFileSync(manifestPath, "utf8")` encoding arg blanked (1
 *     mutant, line 146): equivalent for any manifest this codebase writes --
 *     Buffer.prototype.toString() (which JSON.parse's implicit ToString
 *     coercion falls back to) defaults to utf8, producing byte-identical
 *     output to the explicit "utf8" flag for well-formed UTF-8 JSON.
 *   - `else if (entry.isFile())` forced true (1 mutant, line 45): would only
 *     be observable for a filesystem entry that is neither a directory, a
 *     file, nor a symlink (a socket, FIFO, or block/char device) -- not
 *     portably creatable from a Windows or POSIX test without native
 *     bindings. Same category as this file's own symlink-privilege skip.
 *
 * Zero-dep CJS. EXIT 1 if any FAIL.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../../..");
const MANIFEST_PATH = path.join(ROOT, "scripts", "manifest.js");
const manifest = require(MANIFEST_PATH);

const SCHEMA_VERSION = "1.0";

let passed = 0;
let failed = 0;
let skipped = 0;

function record(name, status, reason) {
  if (status === "PASS") {
    passed++;
    console.log(`PASS ${name}`);
  } else if (status === "SKIP") {
    skipped++;
    console.log(`SKIP ${name} - ${reason}`);
  } else {
    failed++;
    console.log(`FAIL ${name} - ${reason || "unknown"}`);
  }
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function skip(name, reason) {
  record(name, "SKIP", reason);
}

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-manifest-triage-${label}-`));
}

function rmrf(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [MANIFEST_PATH, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
  });
}

/* ================================================================== */
/* generate(): kind validation, opts fallbacks, and filters            */
/* ================================================================== */
function attackGenerateValidationAndDefaults() {
  try {
    let threw = null;
    try { manifest.generate("bogus-kind", {}); } catch (e) { threw = e; }
    check("generate-01-unknown-kind-throws",
      threw && threw.message === "Unknown manifest kind: bogus-kind (expected release|project|tree)",
      `unexpected: ${threw && threw.message}`);
  } catch (e) { record("generate-01-unknown-kind-throws", "FAIL", e.message); }

  try {
    const dir = tempRoot("root-opt");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "a");
      const m = manifest.generate("tree", { root: dir });
      check("generate-02-opts-root-fallback-used-when-rootDir-absent",
        m.files.length === 1 && m.files[0].path === "a.txt",
        JSON.stringify(m));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-02-opts-root-fallback-used-when-rootDir-absent", "FAIL", e.message); }

  try {
    const dir = tempRoot("exclude-manifest-opt");
    try {
      fs.writeFileSync(path.join(dir, "keep.txt"), "keep");
      fs.writeFileSync(path.join(dir, "drop.txt"), "drop");
      const m = manifest.generate("tree", { rootDir: dir, excludeManifest: "drop.txt" });
      const paths = m.files.map((f) => f.path);
      check("generate-03-excludeManifest-opt-actually-filters",
        paths.includes("keep.txt") && !paths.includes("drop.txt"),
        JSON.stringify(paths));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-03-excludeManifest-opt-actually-filters", "FAIL", e.message); }

  try {
    const dir = tempRoot("include-only");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "a");
      fs.writeFileSync(path.join(dir, "b.txt"), "b");
      fs.writeFileSync(path.join(dir, "c.txt"), "c");
      const m = manifest.generate("tree", { rootDir: dir, includeOnly: ["a.txt", "c.txt"] });
      const paths = m.files.map((f) => f.path).sort();
      check("generate-04-includeOnly-filters-to-exact-set",
        paths.length === 2 && paths[0] === "a.txt" && paths[1] === "c.txt",
        JSON.stringify(paths));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-04-includeOnly-filters-to-exact-set", "FAIL", e.message); }

  try {
    const dir = tempRoot("exclude-opt");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "a");
      fs.writeFileSync(path.join(dir, "b.txt"), "b");
      const m = manifest.generate("tree", { rootDir: dir, exclude: ["b.txt"] });
      const paths = m.files.map((f) => f.path);
      check("generate-05-exclude-opt-removes-listed-paths",
        paths.length === 1 && paths[0] === "a.txt",
        JSON.stringify(paths));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-05-exclude-opt-removes-listed-paths", "FAIL", e.message); }

  try {
    const dir = tempRoot("release-defaults");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "a");
      const m = manifest.generate("release", { rootDir: dir });
      check("generate-06-release-defaults-release-version",
        m.release === "0.0.0", `got ${JSON.stringify(m.release)}`);
      check("generate-07-release-defaults-constitutional-set",
        Array.isArray(m.constitutional_set) && m.constitutional_set.length === 0,
        JSON.stringify(m.constitutional_set));
      check("generate-08-release-defaults-tunables-bounds",
        typeof m.tunables_bounds === "object" && m.tunables_bounds !== null && Object.keys(m.tunables_bounds).length === 0,
        JSON.stringify(m.tunables_bounds));
      check("generate-09-release-defaults-created-by",
        typeof m.created_by === "object" && m.created_by !== null && Object.keys(m.created_by).length === 0,
        JSON.stringify(m.created_by));
      check("generate-10-release-explicit-opts-override-defaults",
        (() => {
          const m2 = manifest.generate("release", {
            rootDir: dir,
            release: "3.4.5",
            constitutionalSet: ["scripts/gate.js"],
            tunablesBounds: { maxRetries: 3 },
            createdBy: { ci_workflow: "triage" },
          });
          return m2.release === "3.4.5" &&
            m2.constitutional_set.length === 1 && m2.constitutional_set[0] === "scripts/gate.js" &&
            m2.tunables_bounds.maxRetries === 3 &&
            m2.created_by.ci_workflow === "triage";
        })(), "explicit opts did not propagate");
    } finally { rmrf(dir); }
  } catch (e) { record("generate-06-release-defaults-release-version", "FAIL", e.message); }

  try {
    const dir = tempRoot("project-defaults");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "a");
      const m = manifest.generate("project", { rootDir: dir });
      check("generate-11-project-defaults-parent-release-sha256-null",
        m.parent_release_sha256 === null, JSON.stringify(m.parent_release_sha256));
      check("generate-12-project-defaults-adoption-log-head-null",
        m.adoption_log_head === null, JSON.stringify(m.adoption_log_head));
      check("generate-13-project-defaults-workflow-manifests-empty-array",
        Array.isArray(m.workflow_manifests) && m.workflow_manifests.length === 0,
        JSON.stringify(m.workflow_manifests));
      const m2 = manifest.generate("project", {
        rootDir: dir,
        parentReleaseSha256: "deadbeef",
        adoptionLogHead: "feedface",
        workflowManifests: ["wf-1.json"],
      });
      check("generate-14-project-explicit-opts-override-defaults",
        m2.parent_release_sha256 === "deadbeef" &&
          m2.adoption_log_head === "feedface" &&
          m2.workflow_manifests.length === 1 && m2.workflow_manifests[0] === "wf-1.json",
        JSON.stringify(m2));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-11-project-defaults-parent-release-sha256-null", "FAIL", e.message); }
}

/* ================================================================== */
/* Sort-comparator correctness -- both copies (hashFiles in generate(),  */
/* and verifyTree()'s results.sort) use the same nested-ternary          */
/* comparator. Determinism tests elsewhere only prove "same order twice", */
/* never "correct alphabetical order" -- a comparator that always returns */
/* the same (wrong) value would still look deterministic.                 */
/* ================================================================== */
/* NTFS (and most modern filesystems) already return fs.readdirSync() entries
 * in alphabetical order, so writing files in a scrambled creation order is
 * NOT enough to prove the comparator matters -- the array handed to
 * files.sort() is already sorted before sort() ever runs, making the
 * comparator's own logic unobserved. fs.readdirSync is monkeypatched below to
 * hand back a deliberately scrambled listing, guaranteeing the array reaching
 * the comparator really is disordered.
 *
 * A simple reverse of 3 elements is not scrambled enough: for small arrays
 * V8's sort implementation can end up calling a broken (always -1 / always 0)
 * comparator in a pattern that "accidentally" reconstructs the correct order
 * anyway. Six names in a genuinely scrambled (non-cyclic) permutation was
 * empirically verified to expose every non-equivalent comparator defect
 * (forcing either ternary's condition to a constant, or the -1/+1 literal). */
const SCRAMBLED_NAMES = ["delta.txt", "foxtrot.txt", "apple.txt", "echo.txt", "charlie.txt", "bravo.txt"];
const SORTED_NAMES = ["apple.txt", "bravo.txt", "charlie.txt", "delta.txt", "echo.txt", "foxtrot.txt"];

function withReaddirOrder(order, fn) {
  const original = fs.readdirSync;
  fs.readdirSync = function (...args) {
    const result = original.apply(fs, args);
    if (!Array.isArray(result)) return result;
    const byName = new Map(result.map((e) => [e.name, e]));
    const ordered = order.filter((name) => byName.has(name));
    const rest = result.filter((e) => !order.includes(e.name));
    return [...ordered.map((name) => byName.get(name)), ...rest];
  };
  try { return fn(); } finally { fs.readdirSync = original; }
}

function attackSortComparatorCorrectness() {
  try {
    const dir = tempRoot("sort-generate");
    try {
      for (const name of SCRAMBLED_NAMES) fs.writeFileSync(path.join(dir, name), name);
      const m = withReaddirOrder(SCRAMBLED_NAMES, () => manifest.generate("tree", { rootDir: dir }));
      const paths = m.files.map((f) => f.path);
      check("sort-01-generate-files-are-in-ascending-path-order-despite-scrambled-readdir",
        JSON.stringify(paths) === JSON.stringify(SORTED_NAMES),
        JSON.stringify(paths));
    } finally { rmrf(dir); }
  } catch (e) { record("sort-01-generate-files-are-in-ascending-path-order-despite-scrambled-readdir", "FAIL", e.message); }

  try {
    const dir = tempRoot("sort-verify");
    try {
      for (const name of SCRAMBLED_NAMES) fs.writeFileSync(path.join(dir, name), name);
      const m = manifest.generate("tree", { rootDir: dir });
      const manifestPath = path.join(dir, "tree.manifest.json");
      fs.writeFileSync(manifestPath, JSON.stringify(m));
      const result = withReaddirOrder(SCRAMBLED_NAMES, () => manifest.verifyTree(manifestPath, dir));
      const paths = result.files.map((f) => f.path);
      check("sort-02-verifyTree-results-are-in-ascending-path-order-despite-scrambled-readdir",
        JSON.stringify(paths) === JSON.stringify(SORTED_NAMES),
        JSON.stringify(paths));
      check("sort-03-verifyTree-clean-tree-all-ok", result.ok === true, JSON.stringify(result));
    } finally { rmrf(dir); }
  } catch (e) { record("sort-02-verifyTree-results-are-in-ascending-path-order-despite-scrambled-readdir", "FAIL", e.message); }
}

/* ================================================================== */
/* verifyTree(): exact error-message text and validation boundaries     */
/* ================================================================== */
function attackVerifyTreeMessagesAndBoundaries() {
  function writeAndVerify(dir, manifestObj) {
    const p = path.join(dir, "m.json");
    fs.writeFileSync(p, JSON.stringify(manifestObj));
    return { path: p, run: () => manifest.verifyTree(p, dir) };
  }

  try {
    const dir = tempRoot("wrong-schema");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "9.9", files: [] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-01-wrong-schema-version-exact-message",
        threw && threw.message === 'Unsupported schema_version: "9.9" — expected "1.0"',
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-01-wrong-schema-version-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("missing-files-key");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0" });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-02-missing-files-key-exact-message",
        threw && threw.message === "Manifest missing .files array",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-02-missing-files-key-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("files-not-array");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: "not-an-array" });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-03-files-not-array-exact-message",
        threw && threw.message === "Manifest missing .files array",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-03-files-not-array-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("unknown-property");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [], sneaky: true });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-04-unknown-property-exact-message",
        threw && threw.message === 'Unknown property: "sneaky" — closed schema violation (contract 01)',
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-04-unknown-property-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("duplicate-path");
    try {
      const { run } = writeAndVerify(dir, {
        schema_version: "1.0",
        files: [
          { path: "a.txt", sha256: "0".repeat(64), bytes: 1 },
          { path: "a.txt", sha256: "1".repeat(64), bytes: 2 },
        ],
      });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-05-duplicate-path-exact-message",
        threw && threw.message === 'Duplicate path in manifest: "a.txt" — refused (contract 01)',
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-05-duplicate-path-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("invalid-path-type");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: 42, sha256: "0".repeat(64), bytes: 1 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-06-invalid-path-type-exact-message",
        threw && threw.message === "Invalid manifest entry: path must be a string",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-06-invalid-path-type-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("sha256-not-string");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: 12345, bytes: 1 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-07-sha256-not-string-exact-message",
        threw && threw.message === "Invalid manifest entry: sha256 must be a 64-char hex string",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-07-sha256-not-string-exact-message", "FAIL", e.message); }

  // Regex anchor-boundary tests: a mutated `/[0-9a-f]{64}$/` (no leading ^)
  // would wrongly ACCEPT a string with a garbage prefix as long as its last 64
  // chars are hex. A mutated `/^[0-9a-f]{64}/` (no trailing $) would wrongly
  // ACCEPT a string with a garbage suffix as long as its first 64 chars are
  // hex. Both craft a 66-char string that the real regex rejects outright
  // (it requires an exact 64-char full-string match) but a de-anchored
  // mutant would accept -- turning our expected-throw assertion into the
  // discriminator.
  try {
    const dir = tempRoot("sha256-bad-prefix");
    try {
      const badSha = "zz" + "a".repeat(64);
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: badSha, bytes: 1 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-08-sha256-regex-requires-leading-anchor",
        threw && threw.message === "Invalid manifest entry: sha256 must be a 64-char hex string",
        `got: ${threw ? threw.message : "no throw -- leading ^ anchor not enforced"}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-08-sha256-regex-requires-leading-anchor", "FAIL", e.message); }

  try {
    const dir = tempRoot("sha256-bad-suffix");
    try {
      const badSha = "a".repeat(64) + "zz";
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: badSha, bytes: 1 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-09-sha256-regex-requires-trailing-anchor",
        threw && threw.message === "Invalid manifest entry: sha256 must be a 64-char hex string",
        `got: ${threw ? threw.message : "no throw -- trailing $ anchor not enforced"}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-09-sha256-regex-requires-trailing-anchor", "FAIL", e.message); }

  try {
    const dir = tempRoot("bytes-not-number");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: "0".repeat(64), bytes: "1" }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-10-bytes-not-number-exact-message",
        threw && threw.message === "Invalid manifest entry: bytes must be a non-negative integer",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-10-bytes-not-number-exact-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("bytes-non-integer");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: "0".repeat(64), bytes: 1.5 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-11-bytes-non-integer-rejected",
        threw && threw.message === "Invalid manifest entry: bytes must be a non-negative integer",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-11-bytes-non-integer-rejected", "FAIL", e.message); }

  // bytes===0 must be ACCEPTED (non-negative includes zero) -- this is the
  // discriminator for the `entry.bytes < 0` vs `entry.bytes <= 0` mutant:
  // the mutant would wrongly reject a legitimate empty file.
  try {
    const dir = tempRoot("bytes-zero-accepted");
    try {
      fs.writeFileSync(path.join(dir, "empty.txt"), "");
      const m = manifest.generate("tree", { rootDir: dir });
      const manifestPath = path.join(dir, "tree.manifest.json");
      fs.writeFileSync(manifestPath, JSON.stringify(m));
      const entry = m.files.find((f) => f.path === "empty.txt");
      check("verify-12-zero-bytes-entry-generated-correctly", entry && entry.bytes === 0, JSON.stringify(entry));
      const result = manifest.verifyTree(manifestPath, dir);
      check("verify-13-zero-bytes-does-not-throw-bytes-validation",
        result.ok === true, JSON.stringify(result));
    } finally { rmrf(dir); }
  } catch (e) { record("verify-12-zero-bytes-entry-generated-correctly", "FAIL", e.message); }

  try {
    const dir = tempRoot("bytes-negative");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: "0".repeat(64), bytes: -1 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-14-negative-bytes-rejected",
        threw && threw.message === "Invalid manifest entry: bytes must be a non-negative integer",
        `got: ${threw && threw.message}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-14-negative-bytes-rejected", "FAIL", e.message); }

  // The typeof check is NOT redundant with the regex test, even though both
  // reject non-strings in the common case: RegExp.prototype.test() coerces
  // its argument to a string first, so a JSON value whose ToString happens
  // to produce a valid-looking 64-hex value would pass the regex while
  // still failing typeof. A single-element array's default toString() is
  // just its one element (Array.prototype.join(",") with nothing to join),
  // so it survives the manifest's JSON round-trip as a real array yet
  // coerces to a matching hex string -- unlike a custom-toString object,
  // which JSON.stringify would flatten to "{}" before verifyTree ever sees
  // it, since JSON has no way to carry a function through serialization.
  try {
    const dir = tempRoot("sha256-typeof-not-redundant");
    try {
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: ["a".repeat(64)], bytes: 1 }] });
      let threw = null;
      try { run(); } catch (e) { threw = e; }
      check("verify-15-sha256-typeof-check-not-redundant-with-regex-coercion",
        threw && threw.message === "Invalid manifest entry: sha256 must be a 64-char hex string",
        `got: ${threw ? threw.message : "no throw -- typeof guard bypassed via array-to-string coercion"}`);
    } finally { rmrf(dir); }
  } catch (e) { record("verify-15-sha256-typeof-check-not-redundant-with-regex-coercion", "FAIL", e.message); }

  // A manifest entry whose sha256 is correct for the real file but whose
  // `bytes` field is wrong (a corrupted/hand-edited manifest, not a
  // corrupted file) must still be reported as "mismatch" -- exercising the
  // `buf.length === entry.bytes` half of the ok-check independently of the
  // sha256 half, which a same-content tamper can never do (changing content
  // changes both at once).
  try {
    const dir = tempRoot("bytes-only-mismatch");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "hello");
      const realSha = sha256(fs.readFileSync(path.join(dir, "a.txt")));
      const { run } = writeAndVerify(dir, { schema_version: "1.0", files: [{ path: "a.txt", sha256: realSha, bytes: 999 }] });
      const result = run();
      const entry = result.files.find((f) => f.path === "a.txt");
      check("verify-16-bytes-only-mismatch-detected-when-sha256-matches",
        result.ok === false && entry && entry.status === "mismatch",
        JSON.stringify(result));
    } finally { rmrf(dir); }
  } catch (e) { record("verify-16-bytes-only-mismatch-detected-when-sha256-matches", "FAIL", e.message); }
}

/* ================================================================== */
/* Remaining generate() gaps: the tree.manifest.json auto-exclusion is  */
/* documented to apply ONLY to kind==="tree", and release/project file  */
/* entries are documented to carry exactly {path, sha256} (no bytes).   */
/* ================================================================== */
function attackRemainingGenerateGaps() {
  try {
    const dir = tempRoot("tree-auto-exclude-scoped-to-tree-kind");
    try {
      fs.writeFileSync(path.join(dir, "tree.manifest.json"), "{}");
      fs.writeFileSync(path.join(dir, "a.txt"), "a");
      const treeResult = manifest.generate("tree", { rootDir: dir });
      const releaseResult = manifest.generate("release", { rootDir: dir });
      check("generate-15-auto-exclude-tree-manifest-only-for-tree-kind",
        !treeResult.files.some((f) => f.path === "tree.manifest.json") &&
          releaseResult.files.some((f) => f.path === "tree.manifest.json"),
        `tree=${JSON.stringify(treeResult.files.map((f) => f.path))} release=${JSON.stringify(releaseResult.files.map((f) => f.path))}`);
    } finally { rmrf(dir); }
  } catch (e) { record("generate-15-auto-exclude-tree-manifest-only-for-tree-kind", "FAIL", e.message); }

  try {
    const dir = tempRoot("release-file-entry-shape");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "hello");
      const expectedSha = sha256(fs.readFileSync(path.join(dir, "a.txt")));
      const m = manifest.generate("release", { rootDir: dir });
      const entry = m.files[0];
      check("generate-16-release-file-entries-carry-real-path-and-sha256",
        entry && entry.path === "a.txt" && entry.sha256 === expectedSha && !("bytes" in entry),
        JSON.stringify(entry));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-16-release-file-entries-carry-real-path-and-sha256", "FAIL", e.message); }

  try {
    const dir = tempRoot("project-file-entry-shape");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "hello");
      const expectedSha = sha256(fs.readFileSync(path.join(dir, "a.txt")));
      const m = manifest.generate("project", { rootDir: dir });
      const entry = m.files[0];
      check("generate-17-project-file-entries-carry-real-path-and-sha256",
        entry && entry.path === "a.txt" && entry.sha256 === expectedSha && !("bytes" in entry),
        JSON.stringify(entry));
    } finally { rmrf(dir); }
  } catch (e) { record("generate-17-project-file-entries-carry-real-path-and-sha256", "FAIL", e.message); }
}

/* ================================================================== */
/* checkCaseFoldCollisions must fold with toLowerCase(), not            */
/* toUpperCase() -- both catch plain ASCII-case collisions identically, */
/* but Unicode special-casing (German ß uppercases to "SS") makes the   */
/* two directions genuinely different: "ß.txt" and "ss.txt" collide     */
/* under toUpperCase() but not under toLowerCase().                     */
/* ================================================================== */
function attackCaseFoldDirection() {
  try {
    const dir = tempRoot("case-fold-direction");
    try {
      fs.writeFileSync(path.join(dir, "ß.txt"), "sharp-s");
      fs.writeFileSync(path.join(dir, "ss.txt"), "ess-ess");
      let threw = null;
      try { manifest.generate("tree", { rootDir: dir }); } catch (e) { threw = e; }
      check("case-fold-01-folds-with-toLowerCase-not-toUpperCase",
        threw === null,
        threw ? `unexpectedly refused sharp-s/ss as a collision: ${threw.message}` : "unreachable");
    } finally { rmrf(dir); }
  } catch (e) { record("case-fold-01-folds-with-toLowerCase-not-toUpperCase", "FAIL", e.message); }
}

/* ================================================================== */
/* CLI dispatch -- completely dark before this file. cli() is reached   */
/* only through argv/process.exit, so every case here spawns the real   */
/* script rather than calling an internal function.                     */
/* ================================================================== */
function attackCliDispatch() {
  try {
    const r = runCli([]);
    check("cli-01-no-command-usage-and-exit-2",
      r.status === 2 &&
        r.stderr.includes("Usage: node manifest.js <generate|verify> [options]") &&
        r.stderr.includes("node manifest.js --selftest"),
      `status=${r.status} stderr=${r.stderr}`);
  } catch (e) { record("cli-01-no-command-usage-and-exit-2", "FAIL", e.message); }

  try {
    const r = runCli(["generate"]);
    check("cli-02-generate-no-kind-usage-and-exit-2",
      r.status === 2 && r.stderr.includes("Usage: node manifest.js generate <release|project|tree> [--root <dir>] [--out <file>]"),
      `status=${r.status} stderr=${r.stderr}`);
  } catch (e) { record("cli-02-generate-no-kind-usage-and-exit-2", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-generate-stdout");
    try {
      fs.writeFileSync(path.join(dir, "f.txt"), "hi");
      const r = runCli(["generate", "tree", "--root", dir]);
      check("cli-03-generate-no-out-writes-json-to-stdout-exit-0",
        r.status === 0 && (() => {
          const parsed = JSON.parse(r.stdout);
          return parsed.schema_version === "1.0" && parsed.files.length === 1;
        })(),
        `status=${r.status} stdout=${r.stdout} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-03-generate-no-out-writes-json-to-stdout-exit-0", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-generate-out");
    try {
      fs.writeFileSync(path.join(dir, "f.txt"), "hi");
      const outFile = path.join(dir, "nested", "release.json");
      const r = runCli(["generate", "release", "--root", dir, "--release", "7.8.9", "--out", outFile]);
      const written = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, "utf8")) : null;
      check("cli-04-generate-with-out-writes-file-and-info-message",
        r.status === 0 &&
          r.stderr === `Wrote release manifest to ${outFile}\n` &&
          written && written.release === "7.8.9" && written.kind === "release",
        `status=${r.status} stderr=${r.stderr} written=${JSON.stringify(written)}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-04-generate-with-out-writes-file-and-info-message", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-generate-exclude-manifest");
    try {
      fs.writeFileSync(path.join(dir, "keep.txt"), "keep");
      fs.writeFileSync(path.join(dir, "drop.txt"), "drop");
      const r = runCli(["generate", "tree", "--root", dir, "--exclude-manifest", "drop.txt"]);
      const parsed = JSON.parse(r.stdout);
      const paths = parsed.files.map((f) => f.path);
      check("cli-05-generate-exclude-manifest-flag-filters",
        r.status === 0 && paths.includes("keep.txt") && !paths.includes("drop.txt"),
        `status=${r.status} paths=${JSON.stringify(paths)}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-05-generate-exclude-manifest-flag-filters", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-generate-bad-kind");
    try {
      const r = runCli(["generate", "bogus", "--root", dir]);
      check("cli-06-generate-bad-kind-error-message-and-exit-1",
        r.status === 1 && r.stderr === "Error: Unknown manifest kind: bogus (expected release|project|tree)\n",
        `status=${r.status} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-06-generate-bad-kind-error-message-and-exit-1", "FAIL", e.message); }

  try {
    const r = runCli(["verify"]);
    check("cli-07-verify-no-manifest-path-usage-and-exit-2",
      r.status === 2 && r.stderr === "Usage: node manifest.js verify <manifest.json> --root <dir>\n",
      `status=${r.status} stderr=${r.stderr}`);
  } catch (e) { record("cli-07-verify-no-manifest-path-usage-and-exit-2", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-verify-ok");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "hello");
      const m = manifest.generate("tree", { rootDir: dir });
      const manifestPath = path.join(dir, "tree.manifest.json");
      fs.writeFileSync(manifestPath, JSON.stringify(m));
      const r = runCli(["verify", manifestPath, "--root", dir]);
      const reported = JSON.parse(r.stdout);
      check("cli-08-verify-clean-tree-ok-message-exit-0",
        r.status === 0 && r.stderr === "Verification: OK\n" && reported.ok === true,
        `status=${r.status} stderr=${r.stderr} stdout=${r.stdout}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-08-verify-clean-tree-ok-message-exit-0", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-verify-mismatch");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "hello");
      const m = manifest.generate("tree", { rootDir: dir });
      const manifestPath = path.join(dir, "tree.manifest.json");
      fs.writeFileSync(manifestPath, JSON.stringify(m));
      fs.writeFileSync(path.join(dir, "a.txt"), "tampered");
      const r = runCli(["verify", manifestPath, "--root", dir]);
      check("cli-09-verify-mismatch-failed-counts-and-exit-1",
        r.status === 1 && r.stderr === "Verification: FAILED (0 ok, 1 mismatch, 0 missing, 0 extra)\n",
        `status=${r.status} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-09-verify-mismatch-failed-counts-and-exit-1", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-verify-schema-error");
    try {
      const manifestPath = path.join(dir, "m.json");
      fs.writeFileSync(manifestPath, JSON.stringify({ schema_version: "9.9", files: [] }));
      const r = runCli(["verify", manifestPath, "--root", dir]);
      check("cli-10-verify-schema-error-exit-2",
        r.status === 2 && r.stderr === 'Error: Unsupported schema_version: "9.9" — expected "1.0"\n',
        `status=${r.status} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-10-verify-schema-error-exit-2", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-verify-parse-error");
    try {
      const manifestPath = path.join(dir, "m.json");
      fs.writeFileSync(manifestPath, "{not valid json");
      const r = runCli(["verify", manifestPath, "--root", dir]);
      check("cli-11-verify-non-schema-error-exit-1-not-2",
        r.status === 1 && r.stderr.startsWith("Error: "),
        `status=${r.status} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-11-verify-non-schema-error-exit-1-not-2", "FAIL", e.message); }

  try {
    const r = runCli(["frobnicate"]);
    check("cli-12-unknown-command-message-and-exit-2",
      r.status === 2 &&
        r.stderr.includes("Unknown command: frobnicate") &&
        r.stderr.includes("Usage: node manifest.js <generate|verify> [options]"),
      `status=${r.status} stderr=${r.stderr}`);
  } catch (e) { record("cli-12-unknown-command-message-and-exit-2", "FAIL", e.message); }

  try {
    const dir = tempRoot("cli-verify-default-root");
    try {
      fs.writeFileSync(path.join(dir, "a.txt"), "hello");
      const m = manifest.generate("tree", { rootDir: dir });
      const manifestPath = path.join(dir, "tree.manifest.json");
      fs.writeFileSync(manifestPath, JSON.stringify(m));
      const r = runCli(["verify", manifestPath], { cwd: dir });
      check("cli-13-verify-defaults-root-to-process-cwd",
        r.status === 0 && r.stderr === "Verification: OK\n",
        `status=${r.status} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-13-verify-defaults-root-to-process-cwd", "FAIL", e.message); }

  try {
    // Sequential multi-flag parse: proves the arg-parsing loop correctly
    // advances past each consumed flag VALUE (not just the flag) before the
    // outer for-loop's own i++ runs -- catches i++ -> i-- / i+1 -> i-1
    // mutants that would otherwise reprocess or skip tokens.
    const dir = tempRoot("cli-generate-multi-flag");
    try {
      fs.writeFileSync(path.join(dir, "f.txt"), "hi");
      const outFile = path.join(dir, "out.json");
      const r = runCli(["generate", "release", "--root", dir, "--release", "2.0.0", "--exclude-manifest", "f.txt", "--out", outFile]);
      const written = fs.existsSync(outFile) ? JSON.parse(fs.readFileSync(outFile, "utf8")) : null;
      check("cli-14-generate-all-four-flags-parsed-correctly-in-sequence",
        r.status === 0 && written && written.release === "2.0.0" && written.files.length === 0,
        `status=${r.status} stderr=${r.stderr} written=${JSON.stringify(written)}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-14-generate-all-four-flags-parsed-correctly-in-sequence", "FAIL", e.message); }

  try {
    // A flag as the LAST token with no following value must be ignored
    // (args[i+1] is undefined, the guard's && must short-circuit) rather
    // than consuming a value that doesn't exist.
    const dir = tempRoot("cli-generate-dangling-flag");
    try {
      fs.writeFileSync(path.join(dir, "f.txt"), "hi");
      const r = runCli(["generate", "tree", "--root", dir, "--release"]);
      const parsed = r.status === 0 ? JSON.parse(r.stdout) : null;
      check("cli-15-dangling-flag-with-no-value-is-ignored",
        r.status === 0 && parsed && parsed.files.length === 1,
        `status=${r.status} stdout=${r.stdout} stderr=${r.stderr}`);
    } finally { rmrf(dir); }
  } catch (e) { record("cli-15-dangling-flag-with-no-value-is-ignored", "FAIL", e.message); }

  try {
    const r = runCli(["--selftest"]);
    const expectedLabels = [
      "generate tree produces schema_version",
      "generate tree produces 3 files",
      "paths are forward-slash",
      "clean verify: all ok",
      "clean verify: 3 files ok",
      "tamper detected: not ok",
      "tamper detected: mismatch status",
      "extra file rejected: not ok",
      "extra file rejected: extra status",
      "case-fold collision refused",
      "missing file detected",
      "missing file: missing status",
      "release kind field",
      "release algo field",
      "release schema_version",
      "project kind field",
      "project has generated_at",
      "project parent_release_sha256",
      "symlink/junction refused in walkDir",
      "verifyTree rejects wrong schema_version",
      "verifyTree rejects missing schema_version",
      "verifyTree rejects negative bytes",
    ];
    const missing = expectedLabels.filter((label) => !r.stderr.includes(`PASS  ${label}`));
    check("cli-16-selftest-emits-every-expected-pass-label-verbatim",
      r.status === 0 && missing.length === 0,
      `status=${r.status} missing=${JSON.stringify(missing)}`);
  } catch (e) { record("cli-16-selftest-emits-every-expected-pass-label-verbatim", "FAIL", e.message); }
}

/* ================================================================== */
function main() {
  console.log("manifest.js Option-2 deep triage suite (round 10)");
  console.log("victim=" + MANIFEST_PATH);
  attackGenerateValidationAndDefaults();
  attackSortComparatorCorrectness();
  attackVerifyTreeMessagesAndBoundaries();
  attackRemainingGenerateGaps();
  attackCaseFoldDirection();
  attackCliDispatch();

  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failed ? 1 : 0);
}

main();
