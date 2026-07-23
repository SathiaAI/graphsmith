const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const docsLint = require("../../../scripts/docs-lint.js");
const hygieneScan = require("../../../scripts/hygiene-scan.js");

let passed = 0;
let failed = 0;
let findings = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log("[PASS] " + name);
  } catch (err) {
    failed++;
    console.error("[FAIL] " + name + "\n       " + err.message);
    findings.push(name + ": " + err.message);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function runAdversarialTests() {
  const tmpDir = "tests/banned-lint/gemini/tmp-gs-adversarial";
  if (fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  fs.mkdirSync(tmpDir, { recursive: true });
  const docsDir = tmpDir + "/docs";
  fs.mkdirSync(docsDir, { recursive: true });

  // 1. HMAC/DIGEST CORRECTNESS (hygiene-scan)
  test("HMAC round-trip correctness", () => {
    const key = "adversarial-key-123";
    const identifier = "super-secret-codename";
    const norm = hygieneScan.normalize(identifier);
    const digest = hygieneScan.hmacDigest(key, norm);
    
    // Verify it matches with known key
    const digests = new Set([digest]);
    
    fs.writeFileSync(docsDir + "/test.md", `This mentions the super-secret-codename in text.`);
    const results = hygieneScan.scanCI(tmpDir, key, digests);
    assert(results.length > 0, "Failed to detect identifier with correct key");
    assert(results[0].file === "docs/test.md", "Wrong file reported");
    
    // Verify wrong key does not match
    const wrongKeyResults = hygieneScan.scanCI(tmpDir, "wrong-key", digests);
    assert(wrongKeyResults.length === 0, "Wrong key produced a match (collision/bypass)");
  });

  test("No cleartext leak in output", () => {
    const key = "k1";
    const identifier = "leaktest-id-99";
    const digest = hygieneScan.hmacDigest(key, hygieneScan.normalize(identifier));
    
    fs.writeFileSync(docsDir + "/leak.md", `Here is leaktest-id-99 inside.`);
    const results = hygieneScan.scanCI(tmpDir, key, new Set([digest]));
    
    // Results should only have file and line
    assert(results.length > 0, "Did not find identifier");
    const r = results[0];
    assert(r.file === "docs/leak.md", "File mismatch");
    assert(r.line === 1, "Line mismatch");
    assert(r.identifier === undefined, "Identifier leaked in result object");
  });

  // 2. NORMALIZATION EVASION
  test("Normalization evasion: Cyrillic homoglyphs", () => {
    const identifier = "internal-project";
    const norm = hygieneScan.normalize(identifier);
    // Use Cyrillic 'a', 'e', 'o', 'p', 'c'
    // 'a' = \u0430, 'e' = \u0435, 'o' = \u043E, 'p' = \u0440, 'c' = \u0441
    const evasion = "int\u0435rn\u0430l-pr\u043Ej\u0435\u0441t";
    const evasionNorm = hygieneScan.normalize(evasion);
    assert(norm === evasionNorm, `Homoglyph evasion successful: "${evasionNorm}" != "${norm}"`);
  });

  test("Normalization evasion: Zero-width insertions", () => {
    const identifier = "bannedid";
    const norm = hygieneScan.normalize(identifier);
    const evasion = "b\u200Ca\u200Bn\u200Dn\u200Ee\u200Fd\uFEFFi\u00ADd";
    const evasionNorm = hygieneScan.normalize(evasion);
    assert(norm === evasionNorm, `Zero-width evasion successful: "${evasionNorm}" != "${norm}"`);
  });

  test("Normalization evasion: Double URL encoding", () => {
    const identifier = "secret-project";
    const evasion = "secret%252Dproject"; // %252D = %2D = -
    fs.writeFileSync(docsDir + "/url.md", `Link: http://test.com/${evasion}`);
    const results = hygieneScan.scanLocal(tmpDir, [identifier]);
    assert(results.length > 0, "Double URL encoding evasion successful");
  });

  // 3 & 4. CORPUS INTEGRITY AND LINT SEMANTICS
  test("Docs-lint: TP evasion via multiline split", () => {
    fs.writeFileSync(docsDir + "/multiline.md", `This system is certified\nsecure by us.`);
    const results = docsLint.scanFile("docs/multiline.md", docsDir + "/multiline.md");
    const flagged = results.some(r => r.ruleId === "R9a-certified-secure");
    assert(flagged, "Multiline split evasion successful for 'certified secure'");
  });

  test("Docs-lint: TP evasion via double spacing", () => {
    fs.writeFileSync(docsDir + "/spacing.md", `This provides exactly  once delivery.`);
    const results = docsLint.scanFile("docs/spacing.md", docsDir + "/spacing.md");
    const flagged = results.some(r => r.ruleId === "R5-exactly-once");
    assert(flagged, "Double space evasion successful for 'exactly once'");
  });

  test("Docs-lint: FP triggered by multiline HTML comment", () => {
    fs.writeFileSync(docsDir + "/comment.md", `<!--\nThis is proven to work.\n-->`);
    const results = docsLint.scanFile("docs/comment.md", docsDir + "/comment.md");
    const flagged = results.some(r => r.ruleId === "R1-proven");
    assert(!flagged, "Multiline HTML comment flagged falsely");
  });

  test("Docs-lint: Unqualified-only semantics (bare vs qualified)", () => {
    fs.writeFileSync(docsDir + "/semantics.md", 
      `Bare claim: The system is proven.\n` +
      `Qualified claim: The system was tested: test shows it works.\n` +
      `Negated claim: It is not proven.`
    );
    const results = docsLint.scanFile("docs/semantics.md", docsDir + "/semantics.md");
    
    const bareFlagged = results.some(r => r.line === 1 && r.ruleId === "R1-proven");
    const qualFlagged = results.some(r => r.line === 2 && r.ruleId === "R1-proven");
    const negFlagged = results.some(r => r.line === 3 && r.ruleId === "R1-proven");
    
    assert(bareFlagged, "Bare claim missed");
    assert(!qualFlagged, "Qualified claim falsely flagged");
    assert(!negFlagged, "Negated claim falsely flagged");
  });
  
  test("Docs-lint: Multiple negations handling", () => {
     fs.writeFileSync(docsDir + "/multiple-neg.md", 
      `The claim that it is proven is wrong.`
    );
    const results = docsLint.scanFile("docs/multiple-neg.md", docsDir + "/multiple-neg.md");
    const negFlagged = results.some(r => r.ruleId === "R1-proven");
    assert(!negFlagged, "Negated claim 'proven is wrong' falsely flagged");
  });

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log("FINDINGS:");
    findings.forEach(f => console.log(`- ${f}`));
  }
}

runAdversarialTests();
