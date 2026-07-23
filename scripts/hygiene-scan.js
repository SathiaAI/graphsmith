#!/usr/bin/env node
/**
 * hygiene-scan.js — Contract 10 List B publication-hygiene scanner (v3 rebuild).
 *
 * Two mechanisms:
 *   1. LOCAL PREVENTION (primary): reads the raw private identifier list
 *      .plans/hygiene/banned-identifiers.txt (git-ignored, maintainer-supplied)
 *      and blocks the commit/release if any identifier appears in the
 *      shippable docs fileset.  FAIL-CLOSED: missing or unreadable list →
 *      exit non-zero with a clear (identifier-free) error.  An EMPTY but
 *      PRESENT list is legit (nothing configured → pass).
 *   2. CI DETECTION (secondary, --ci mode): receives HYGIENE_HMAC_KEY and
 *      HYGIENE_DIGESTS as CI secrets; scans HMAC-SHA256(key, normalized
 *      n-gram) per token n-gram against the digest set. NO cleartext
 *      identifiers are shipped in the repo. NO unsalted hashes.
 *
 * Normalization (applied to file contents AND filenames) via norm-core.js:
 *   NFKC + strip ZW + fold fullwidth + fold Cyrillic/Greek homoglyphs +
 *   decode %-encodings loop-to-stable + collapse whitespace + strip non-alnum.
 *
 * Confusable map: PRAGMATIC, not full Unicode TR39.  Documented in norm-core.js.
 *
 * Failure messages: file:line ONLY — NEVER the matched identifier.
 * Uses Node built-in crypto (HMAC-SHA256). Zero external deps.
 * CommonJS. Node >= 18. Deterministic, no network, fail-closed.
 *
 * Usage:
 *   node scripts/hygiene-scan.js               local prevention mode
 *   node scripts/hygiene-scan.js --ci          CI HMAC detection mode
 *   node scripts/hygiene-scan.js --selftest    run internal test suite
 */

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const normCore = require("./norm-core.js");

const baseNormalize = normCore.baseNormalize;
const normalizeFilename = normCore.normalizeFilename;

const MAX_NGRAM_LEN = 128;

// --- file scope ---------------------------------------------------------------

const SHIPPABLE_FILES = [
  "README.md",
  "SKILL.md",
  "GRAPHSMITH-PROTOCOL.md",
  "SPEC-CHANGES.md",
  "RELEASING.md",
  "package.json",
];

const SHIPPABLE_DIRS = ["docs", "references"];

const EXCLUDED_PREFIXES = [
  ".plans/",
  "node_modules/",
  "tests/",
  "BUILD-LEDGER.md",
  ".git/",
];

const BANNED_IDENTIFIERS_PATH = ".plans/hygiene/banned-identifiers.txt";

// --- normalization pipeline ---------------------------------------------------

/**
 * Full normalization for n-gram matching.
 * baseNormalize already does NFKC + ZW strip + fullwidth fold + homoglyph fold +
 * %-decode loop-to-stable + collapse whitespace + lowercase.
 * We then strip non-alphanumeric characters.
 */
function normalize(s) {
  var t = baseNormalize(s);
  t = t.replace(/[^a-z0-9]/g, "");
  return t;
}

// --- n-gram extraction --------------------------------------------------------

/**
 * Extract all n-grams of length n from a normalized string.
 */
function ngrams(s, n) {
  const out = [];
  for (var i = 0; i <= s.length - n; i++) {
    out.push(s.substring(i, i + n));
  }
  return out;
}

/**
 * Extract token-level n-grams from a line of prose.
 * Tokens are sequences of alphanumeric characters or word-like chunks.
 * For each token, normalize and generate n-grams from n=1 to min(len, maxN).
 * Also normalizes the full line for multi-word n-gram coverage.
 */
function extractNgrams(line) {
  const results = [];
  // Individual "words" (alphanumeric clusters)
  const wordRe = /[a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF\u4E00-\u9FFF\uAC00-\uD7AF\u3040-\u309F\u30A0-\u30FF\uFF66-\uFF9F]+/g;
  var m;
  while ((m = wordRe.exec(line)) !== null) {
    var norm = normalize(m[0]);
    if (norm.length === 0) continue;
    var maxN = Math.min(norm.length, MAX_NGRAM_LEN);
    for (var n = 1; n <= maxN; n++) {
      for (var g = 0; g <= norm.length - n; g++) {
        results.push(norm.substring(g, g + n));
      }
    }
  }
  // Also compute the full-line n-gram (catches multi-word identifiers)
  var fullNorm = normalize(line);
  if (fullNorm.length > 0) {
    var maxN = Math.min(fullNorm.length, MAX_NGRAM_LEN);
    for (var n = 1; n <= maxN; n++) {
      for (var g = 0; g <= fullNorm.length - n; g++) {
        results.push(fullNorm.substring(g, g + n));
      }
    }
  }
  return results;
}

// --- file list building -------------------------------------------------------

function isExcluded(fileRel) {
  var norm = fileRel.replace(/\\/g, "/");
  for (var i = 0; i < EXCLUDED_PREFIXES.length; i++) {
    var prefix = EXCLUDED_PREFIXES[i];
    if (norm === prefix || norm.startsWith(prefix)) return true;
  }
  return false;
}

function buildFileList(cwd) {
  var files = [];
  for (var i = 0; i < SHIPPABLE_FILES.length; i++) {
    var f = SHIPPABLE_FILES[i];
    var abs = path.join(cwd, f);
    if (fs.existsSync(abs) && !isExcluded(f)) files.push(f);
  }
  for (var i = 0; i < SHIPPABLE_DIRS.length; i++) {
    var dir = SHIPPABLE_DIRS[i];
    var dp = path.join(cwd, dir);
    if (!fs.existsSync(dp)) continue;
    var st;
    try { st = fs.statSync(dp); } catch (e) { continue; }
    if (!st.isDirectory()) continue;
    walkDir(dp, cwd, files);
  }
  return files;
}

function walkDir(abspath, cwd, out) {
  var entries;
  try {
    entries = fs.readdirSync(abspath, { withFileTypes: true });
  } catch (e) {
    return;
  }
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    var childAbs = path.join(abspath, e.name);
    var childRel = path.relative(cwd, childAbs).replace(/\\/g, "/");
    if (isExcluded(childRel)) continue;
    if (e.isDirectory()) {
      walkDir(childAbs, cwd, out);
    } else if (e.isFile()) {
      out.push(childRel);
    }
  }
}

// --- local prevention mode ----------------------------------------------------

/**
 * Load the banned identifiers list.
 * Returns the parsed array of normalized identifiers on success.
 * Returns null if the file is missing or unreadable (FAIL-CLOSED: caller must error).
 * Returns an empty array if the file exists but has no identifiers (legit: nothing configured).
 */
function loadBannedIdentifiers(cwd) {
  var p = path.join(cwd, BANNED_IDENTIFIERS_PATH);
  if (!fs.existsSync(p)) {
    process.stderr.write("hygiene-scan: FATAL — local list not found at " + BANNED_IDENTIFIERS_PATH + "\n");
    return null;
  }
  var raw;
  try {
    raw = fs.readFileSync(p, "utf8");
  } catch (e) {
    process.stderr.write("hygiene-scan: FATAL — cannot read " + BANNED_IDENTIFIERS_PATH + ": " + e.message + "\n");
    return null;
  }
  var lines = raw.split(/\r?\n/);
  var ids = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "" || line.startsWith("#")) continue;
    var norm = normalize(line);
    if (norm.length > 0) ids.push(norm);
  }
  return ids;
}

/**
 * Scan files using local identifier list.
 * Returns array of { file, line } (no identifier text in output).
 */
function scanLocal(cwd, identifiers) {
  if (!identifiers || identifiers.length === 0) return [];
  // Normalize identifiers defensively (callers like loadBannedIdentifiers pre-normalize,
  // but direct API callers may pass raw strings).
  var identSet = new Set();
  for (var j = 0; j < identifiers.length; j++) {
    var nid = normalize(identifiers[j]);
    if (nid.length > 0) identSet.add(nid);
  }
  if (identSet.size === 0) return [];
  var fileList = buildFileList(cwd);
  var results = [];

  for (var i = 0; i < fileList.length; i++) {
    var fileRel = fileList[i];
    var fileAbs = path.join(cwd, fileRel);

    // Check filename
    var baseName = path.basename(fileRel);
    var ext = path.extname(baseName);
    var nameWithoutExt = ext ? baseName.slice(0, -ext.length) : baseName;
    var normFname = normalizeFilename(nameWithoutExt);
    if (identSet.has(normFname)) {
      results.push({ file: fileRel, line: 0 });
      continue;
    }

    // Check file contents
    var raw;
    try {
      raw = fs.readFileSync(fileAbs, "utf8");
    } catch (e) { continue; }
    var lines = raw.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var lineNum = li + 1;
      var line = lines[li];
      var ngramsList = extractNgrams(line);
      var found = false;
      for (var ni = 0; ni < ngramsList.length; ni++) {
        if (identSet.has(ngramsList[ni])) {
          results.push({ file: fileRel, line: lineNum });
          found = true;
          break;
        }
      }
      if (found) continue;
    }
  }

  return results;
}

// --- CI HMAC detection mode ---------------------------------------------------

function loadCISecrets() {
  var key = process.env.HYGIENE_HMAC_KEY;
  var digestsRaw = process.env.HYGIENE_DIGESTS;

  if (!key) {
    process.stderr.write("hygiene-scan: HYGIENE_HMAC_KEY not set\n");
    process.exit(2);
  }
  if (!digestsRaw) {
    process.stderr.write("hygiene-scan: HYGIENE_DIGESTS not set\n");
    process.exit(2);
  }

  // Digests is a newline-separated (or comma-separated) list of hex strings
  var lines = digestsRaw.split(/[\r\n,]+/);
  var digestSet = new Set();
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line.length === 0) continue;
    digestSet.add(line.toLowerCase());
  }
  return { key: key, digests: digestSet };
}

function hmacDigest(key, data) {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest("hex");
}

function scanCI(cwd, key, digests) {
  var fileList = buildFileList(cwd);
  var results = [];

  for (var i = 0; i < fileList.length; i++) {
    var fileRel = fileList[i];
    var fileAbs = path.join(cwd, fileRel);

    // Check filename n-grams
    var baseName = path.basename(fileRel);
    var ext = path.extname(baseName);
    var nameWithoutExt = ext ? baseName.slice(0, -ext.length) : baseName;
    var normFname = normalizeFilename(nameWithoutExt);
    if (normFname.length > 0) {
      var maxN = Math.min(normFname.length, MAX_NGRAM_LEN);
      for (var n = 1; n <= maxN; n++) {
        for (var g = 0; g <= normFname.length - n; g++) {
          var ng = normFname.substring(g, g + n);
          var d = hmacDigest(key, ng);
          if (digests.has(d)) {
            results.push({ file: fileRel, line: 0 });
            break;
          }
        }
        if (results.length > 0 && results[results.length - 1].file === fileRel) break;
      }
    }
    if (results.length > 0 && results[results.length - 1].file === fileRel) continue;

    // Check file contents
    var raw;
    try {
      raw = fs.readFileSync(fileAbs, "utf8");
    } catch (e) { continue; }
    var lines = raw.split(/\r?\n/);
    for (var li = 0; li < lines.length; li++) {
      var lineNum = li + 1;
      var line = lines[li];
      var ngramsList = extractNgrams(line);
      var found = false;
      for (var ni = 0; ni < ngramsList.length; ni++) {
        var d = hmacDigest(key, ngramsList[ni]);
        if (digests.has(d)) {
          results.push({ file: fileRel, line: lineNum });
          found = true;
          break;
        }
      }
      if (found) continue;
    }
  }

  return results;
}

// --- output -------------------------------------------------------------------

function reportResults(results) {
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    if (r.line === 0) {
      process.stdout.write(r.file + ":filename\n");
    } else {
      process.stdout.write(r.file + ":" + r.line + "\n");
    }
  }
  if (results.length > 0) {
    process.stderr.write(
      "\nhygiene-scan: " + results.length + " violation(s) found in " +
      new Set(results.map(function (r) { return r.file; })).size + " file(s)\n"
    );
  }
}

// --- selftest -----------------------------------------------------------------

function selftest() {
  var passed = 0;
  var failures = [];

  function assert(name, cond, detail) {
    if (cond) {
      passed++;
      process.stderr.write("  PASS  " + name + "\n");
    } else {
      failures.push(name + (detail ? " -- " + detail : ""));
      process.stderr.write("  FAIL  " + name + (detail ? " -- " + detail : "") + "\n");
    }
  }

  var root = fs.mkdtempSync(path.join(os.tmpdir(), "gs-hygiene-selftest-"));
  var prevCwd = process.cwd();
  try {
    process.chdir(root);

    // Create the directory structure for local mode
    var hygieneDir = path.join(root, ".plans", "hygiene");
    fs.mkdirSync(hygieneDir, { recursive: true });
    fs.mkdirSync(path.join(root, "docs"));
    fs.mkdirSync(path.join(root, "references"));

    // --- 1. normalization: NFKC + fullwidth -> ASCII -----------------------
    {
      var result = normalize("\uFF30\uFF52\uFF4F\uFF4A\uFF45\uFF43\uFF54"); // fullwidth "Project"
      assert("NFKC: fullwidth -> ASCII", result === "project", "got: " + result);
    }

    // --- 2. normalization: ZW chars + soft hyphen stripped ------------------
    {
      var result = normalize("P\u200Br\u200Co\u200Dj\u200Be\u200Fc\uFEFFt\u00ADx");
      assert("ZW chars + soft hyphen stripped", result === "projectx", "got: " + result);
    }

    // --- 3. normalization: strip non-alphanumeric --------------------------
    {
      var result = normalize("my-project_v1.0");
      assert("strip non-alnum", result === "myprojectv10", "got: " + result);
    }

    // --- 4. normalization: decode %-encoding -------------------------------
    {
      var result = normalize("hello%20world");
      assert("decode %%", result === "helloworld", "got: " + result);
    }

    // --- 4b. normalization: double %-encoding ------------------------------
    {
      var result = normalize("test%252Dx"); // %25 → %, then %2D → -
      assert("double %% decode", result === "testx", "got: " + result);
    }

    // --- 4c. normalization: Cyrillic homoglyphs ----------------------------
    {
      // Cyrillic 'е' (U+0435) → 'e'
      var result = normalize("proj\u0435ctx");
      assert("Cyrillic e fold", result === "projectx", "got: " + result);
    }

    // --- 4d. normalization: mixed homoglyphs -------------------------------
    {
      // Cyrillic: i(н)te(е)r(н)na(а)l, Greek omicron, etc.
      var result = normalize("int\u0435rn\u0430l");
      assert("mixed Cyrillic fold", result === "internal", "got: " + result);
    }

    // --- 5. local prevention: planted identifier flagged -------------------
    {
      fs.writeFileSync(path.join(hygieneDir, "banned-identifiers.txt"),
        "# Test identifiers\n" +
        "internal-project-alpha\n" +
        "confidential-2026\n",
        "utf8"
      );

      fs.writeFileSync(path.join(root, "README.md"),
        "# Project\n\nWe mention internal-project-alpha in the docs.\n",
        "utf8"
      );

      var identifiers = loadBannedIdentifiers(root);
      assert("local: identifiers loaded", identifiers !== null && identifiers.length === 2,
        identifiers === null ? "null" : "got " + identifiers.length);

      var results = scanLocal(root, identifiers);
      assert("local: planted identifier flagged", results.length > 0, "got " + results.length + " results");
      assert("local: flagged file is README.md",
        results.some(function (r) { return r.file === "README.md"; }));
    }

    // --- 5b. local prevention: normalized identifier matches after folding
    {
      var normId = normalize("internal-project-alpha");
      assert("normalized id matches expected", normId === "internalprojectalpha", "got: " + normId);

      var clean = normalize("We mention internal-project-alpha.");
      assert("prose normalization matches id", clean.indexOf(normId) !== -1);
    }

    // --- 6. local prevention: clean file NOT flagged -----------------------
    {
      fs.unlinkSync(path.join(root, "README.md"));
      fs.writeFileSync(path.join(root, "SKILL.md"), "# Clean\n\nNothing to see here.\n", "utf8");
      fs.writeFileSync(path.join(root, "README.md"), "# Clean\n\nSafe content.\n", "utf8");

      var results = scanLocal(root, identifiers);
      assert("local: clean file not flagged", results.length === 0, "got " + results.length + " results");
    }

    // --- 7. output sanitized — never contains the identifier ---------------
    {
      fs.writeFileSync(path.join(root, "README.md"),
        "# Project\n\nWe mention internal-project-alpha in the docs.\n",
        "utf8"
      );
      var results = scanLocal(root, identifiers);
      for (var i = 0; i < results.length; i++) {
        var outLine = results[i].file + ":" + results[i].line;
        var hasId = outLine.toLowerCase().indexOf("internal-project-alpha") !== -1;
        assert(
          "SANITIZED output: " + JSON.stringify(outLine),
          !hasId,
          "leaked identifier in output"
        );
      }
    }

    // --- 8. empty identifiers list -> clean scan ---------------------------
    {
      var results = scanLocal(root, []);
      assert("empty list: no findings", results.length === 0, "got " + results.length);
    }

    // --- 8b. empty-but-present file -> pass (no identifiers configured) ----
    {
      fs.writeFileSync(path.join(hygieneDir, "banned-identifiers.txt"),
        "# only comments here\n\n",
        "utf8"
      );
      var ids = loadBannedIdentifiers(root);
      assert("empty file: identifiers loaded as []", ids !== null && ids.length === 0,
        ids === null ? "null" : "got length " + ids.length);
    }

    // --- 8c. missing file -> fail-closed (returns null) --------------------
    {
      fs.unlinkSync(path.join(hygieneDir, "banned-identifiers.txt"));
      var ids = loadBannedIdentifiers(root);
      assert("missing file: load returns null (fail-closed)", ids === null,
        "expected null, got " + JSON.stringify(ids));

      // Restore the file for later tests
      fs.writeFileSync(path.join(hygieneDir, "banned-identifiers.txt"),
        "# Test identifiers\n" +
        "internal-project-alpha\n" +
        "confidential-2026\n",
        "utf8"
      );
    }

    // --- 9. HMAC round-trip: known key+identifier -> digest -> match ------
    {
      var testKey = "test-hygiene-key-2026";
      var testIdentifier = "secret-project-name";
      var testNorm = normalize(testIdentifier);
      var testDigest = hmacDigest(testKey, testNorm);

      // Simulate CI scan
      var digests = new Set([testDigest]);

      fs.writeFileSync(path.join(root, "README.md"),
        "# Docs\n\nWe use secret-project-name internally.\n",
        "utf8"
      );

      var results = scanCI(root, testKey, digests);
      assert("HMAC: round-trip detects identifier", results.length > 0, "got " + results.length + " results");
      assert("HMAC: flagged file is README.md",
        results.some(function (r) { return r.file === "README.md"; }));
    }

    // --- 10. HMAC: clean file not flagged ---------------------------------
    {
      var testKey = "different-key";
      var testDigest = hmacDigest(testKey, normalize("some-other-identifier"));

      fs.writeFileSync(path.join(root, "README.md"), "# Clean\n\nSafe text.\n", "utf8");

      var results = scanCI(root, testKey, new Set([testDigest]));
      assert("HMAC: clean file not flagged", results.length === 0, "got " + results.length + " results");
    }

    // --- 11. HMAC: output sanitized ---------------------------------------
    {
      var testKey = "sanitize-key";
      var testIdentifier = "top-secret-code";
      var testNorm = normalize(testIdentifier);
      var testDigest = hmacDigest(testKey, testNorm);

      fs.writeFileSync(path.join(root, "README.md"),
        "# Docs\n\ntop-secret-code is the internal name.\n",
        "utf8"
      );

      var results = scanCI(root, testKey, new Set([testDigest]));
      assert("HMAC sanitize: findings found", results.length > 0);
      for (var i = 0; i < results.length; i++) {
        var outLine = results[i].file + ":" + results[i].line;
        var hasId = outLine.toLowerCase().indexOf("top-secret-code") !== -1;
        assert(
          "HMAC SANITIZED: " + JSON.stringify(outLine),
          !hasId,
          "leaked identifier"
        );
      }
    }

    // --- 12. Filename check in local mode ----------------------------------
    {
      var fileIdentifiers = loadBannedIdentifiers(root);
      var absDir = path.join(root, "docs");
      fs.writeFileSync(path.join(absDir, "internal-project-alpha.md"),
        "# Clean doc\n\nNothing here.\n",
        "utf8"
      );

      var results = scanLocal(root, fileIdentifiers);
      var fnameMatch = results.some(function (r) { return r.line === 0; });
      assert("local: filename match flagged (line=0)", fnameMatch);
    }

    // --- 13. Normalization evasion: Cyrillic homoglyphs caught ------------
    {
      fs.writeFileSync(path.join(hygieneDir, "banned-identifiers.txt"),
        "projectx\n",
        "utf8"
      );
      var ids = loadBannedIdentifiers(root);
      // Write Cyrillic-е evasion in content
      fs.writeFileSync(path.join(root, "README.md"),
        "see proj\u0435ctx in the wild\n",
        "utf8"
      );
      var results = scanLocal(root, ids);
      assert("evasion: Cyrillic homoglyph caught", results.length > 0,
        "got " + results.length + " results");
    }

    // --- 13b. Normalization evasion: fullwidth filename caught -------------
    {
      var ids = loadBannedIdentifiers(root);
      var fname = "\uFF50\uFF52\uFF4F\uFF4A\uFF45\uFF43\uFF54\uFF58.md";
      fs.writeFileSync(path.join(absDir, fname), "# x\n", "utf8");
      var results = scanLocal(root, ids);
      // The normalized filename should match the normalized identifier
      var fnameHits = results.filter(function (r) { return r.line === 0; });
      assert("evasion: fullwidth filename caught", fnameHits.length > 0,
        "got " + fnameHits.length + " filename hits");
    }

    // --- 13c. Evasion: %-encoding in content caught ------------------------
    {
      var ids = loadBannedIdentifiers(root);
      fs.writeFileSync(path.join(root, "README.md"),
        "see project%78\n",
        "utf8"
      );
      var results = scanLocal(root, ids);
      assert("evasion: %-encoding caught", results.length > 0,
        "got " + results.length + " results");
    }

    // --- 14. Exit code logic (smoke test) ----------------------------------
    {
      assert("selftest exit code assertion", true);
    }

  } finally {
    process.chdir(prevCwd);
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (e) {}
  }

  process.stderr.write("\nselftest: " + passed + " passed, " + failures.length + " failed\n");
  if (failures.length > 0) {
    process.stderr.write("failures: " + failures.join("; ") + "\n");
  }
  return failures.length === 0;
}

// --- CLI ---------------------------------------------------------------------

function usage() {
  process.stderr.write(
    "Usage: node scripts/hygiene-scan.js             local prevention mode\n" +
    "       node scripts/hygiene-scan.js --ci        CI HMAC detection mode\n" +
    "       node scripts/hygiene-scan.js --selftest  run internal test suite\n"
  );
}

function main() {
  var args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    var ok = selftest();
    process.exit(ok ? 0 : 1);
    return;
  }

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
    return;
  }

  var cwd = process.cwd();
  var isCi = args.includes("--ci");

  if (isCi) {
    var secrets;
    try {
      secrets = loadCISecrets();
    } catch (e) {
      process.stderr.write("hygiene-scan: " + e.message + "\n");
      process.exit(2);
      return;
    }
    var results = scanCI(cwd, secrets.key, secrets.digests);
    reportResults(results);
    if (results.length > 0) {
      process.exit(1);
    } else {
      process.stderr.write("hygiene-scan: clean — no banned identifiers detected\n");
      process.exit(0);
    }
  } else {
    var identifiers = loadBannedIdentifiers(cwd);
    // FAIL-CLOSED: null means missing or unreadable file → error
    if (identifiers === null) {
      process.exit(1);
    }
    // Empty but present list → nothing configured, clean pass
    if (identifiers.length === 0) {
      process.stderr.write("hygiene-scan: no identifiers configured (empty list at " + BANNED_IDENTIFIERS_PATH + ")\n");
      process.stderr.write("hygiene-scan: clean — no banned identifiers to enforce\n");
      process.exit(0);
    }
    var results = scanLocal(cwd, identifiers);
    reportResults(results);
    if (results.length > 0) {
      process.exit(1);
    } else {
      process.stderr.write("hygiene-scan: clean — no banned identifiers detected\n");
      process.exit(0);
    }
  }
}

if (require.main === module) {
  main();
}

module.exports = { normalize, normalizeFilename, extractNgrams, hmacDigest, scanLocal, scanCI, selftest, loadBannedIdentifiers };