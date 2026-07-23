#!/usr/bin/env node
"use strict";

// Adversarial test battery for scripts/matrix.js (F22 platform property matrix).
// Tester: Claude family (cross-family vs GLM-4.7 builder). Zero-dep CJS, deterministic.
// Lane: tests/matrix/claude/ ONLY. Does not modify scripts/matrix.js.
//
// Run: node tests/matrix/claude/tests.js

const fs = require("fs");
const path = require("path");

const M = require("../../../scripts/matrix.js");
const {
  aggregateReports,
  generateMarkdown,
  generateJson,
  validateCiUrl,
  escapeHtml,
  escapeMarkdown,
  SCHEMA_VERSION,
} = M;

// ---- tiny harness ------------------------------------------------------
let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log("PASS  " + name);
  } else {
    failed++;
    failures.push(name + (detail ? "  -- " + detail : ""));
    console.log("FAIL  " + name + (detail ? "  -- " + detail : ""));
  }
}

// ---- temp fixture helpers ---------------------------------------------
const TMP = "tests/matrix/claude/.tmp";
function freshTmp() {
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  fs.mkdirSync(TMP, { recursive: true });
}
let seq = 0;
function writeReport(obj) {
  const p = path.join(TMP, "report-" + (seq++) + ".json").split(path.sep).join("/");
  fs.writeFileSync(p, typeof obj === "string" ? obj : JSON.stringify(obj));
  return p;
}
function baseReport(platform, profiles, extra) {
  return Object.assign({
    schema_version: "1.0",
    command: "profiles",
    verifier_version: "1.0",
    platform: platform,
    node_version: "v18.0.0",
    evaluated_at: "2024-01-15T10:30:00Z",
    profiles: profiles,
  }, extra || {});
}
function allVerified() {
  const p = {};
  for (const k of ["R", "E", "B", "T", "G", "Q", "X"]) p[k] = { status: "verified", evidence: [], assumptions: [] };
  return p;
}

freshTmp();

console.log("=== matrix.js adversarial battery (Claude tester) ===\n");

// =======================================================================
// ATTACK 1 — RENDER-INJECTION
// =======================================================================
console.log("-- ATTACK 1: RENDER-INJECTION --");

// 1a. escapeHtml unit — the primitive must neutralize all HTML metachars.
check("1a escapeHtml <script>", escapeHtml('<script>alert(1)</script>') === "&lt;script&gt;alert(1)&lt;/script&gt;");
check("1a escapeHtml img onerror", !escapeHtml('<img src=x onerror="alert(1)">').includes("<"));
check("1a escapeHtml ampersand", escapeHtml("a & b") === "a &amp; b");
check("1a escapeHtml double-quote", escapeHtml('"x"') === "&quot;x&quot;");
check("1a escapeHtml single-quote", escapeHtml("'x'") === "&#39;x&#39;");
check("1a escapeHtml null/undefined", escapeHtml(null) === "" && escapeHtml(undefined) === "");

// 1b. escapeMarkdown unit — must neutralize table-breaking pipe + emphasis + code.
check("1b escapeMarkdown pipe", escapeMarkdown("a|b") === "a\\|b");
check("1b escapeMarkdown asterisk", escapeMarkdown("*b*") === "\\*b\\*");
check("1b escapeMarkdown underscore", escapeMarkdown("_b_") === "\\_b\\_");
check("1b escapeMarkdown backtick", escapeMarkdown("`c`") === "\\`c\\`");
check("1b escapeMarkdown angle", !escapeMarkdown("<x>").includes("<"));

// 1c. evidence[]/assumptions[] carrying markup must NOT reach either output.
//     (Builder chose to never render evidence — verify that holds.)
{
  const evilEvidence = '<script>alert("pwn")</script>';
  const evilAssume = '<img src=x onerror=alert(2)>';
  const rp = writeReport(baseReport("linux", (function () {
    const p = allVerified();
    p.R = { status: "verified", evidence: [evilEvidence, "SENTINEL_EVID_7f3"], assumptions: [evilAssume, "SENTINEL_ASSUME_7f3"] };
    return p;
  })()));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const md = generateMarkdown(matrix, metadata);
  const js = JSON.stringify(generateJson(matrix, metadata));
  check("1c evidence markup absent from Markdown", !md.includes("<script>") && !md.includes("onerror"));
  check("1c evidence sentinel absent from Markdown", !md.includes("SENTINEL_EVID_7f3") && !md.includes("SENTINEL_ASSUME_7f3"), "evidence/assumptions leaked into MD");
  check("1c evidence markup absent from JSON", !js.includes("<script>") && !js.includes("onerror"));
  check("1c evidence sentinel absent from JSON", !js.includes("SENTINEL_EVID_7f3") && !js.includes("SENTINEL_ASSUME_7f3"), "evidence/assumptions leaked into JSON");
}

// 1d. status carrying an HTML payload — must be enum-validated, not rendered.
{
  const rp = writeReport(baseReport("linux", (function () {
    const p = allVerified();
    p.R = { status: '<script>alert(1)</script>', evidence: [], assumptions: [] };
    return p;
  })()));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const md = generateMarkdown(matrix, metadata);
  const js = JSON.stringify(generateJson(matrix, metadata));
  check("1d status <script> not raw in Markdown", !md.includes("<script>"), "enum validation prevents raw tags");
  check("1d status <script> not raw in JSON", !js.includes("<script>"), "enum validation prevents raw tags in JSON");
  check("1d hostile status rendered as unavailable", /unavailable/.test(md) && js.includes('"status":"unavailable"'), "malicious status normalized to unavailable");
}

// 1e. **PIPE-INJECTION in status** — a hostile status with a Markdown pipe.
//     The cell is escaped with escapeHtml (which does NOT escape '|'),
//     so the pipe survives and forges extra table columns.
{
  const rp = writeReport(baseReport("linux", (function () {
    const p = allVerified();
    p.R = { status: "verified | INJECTED_COL | INJECTED_COL2", evidence: [], assumptions: [] };
    return p;
  })()));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const md = generateMarkdown(matrix, metadata);
  // Find the R data row. A single-platform matrix R row must have exactly
  // one platform cell => 3 pipes: "| R | <cell> |". Injected pipes add cells.
  const rRow = md.split("\n").find((l) => /^\|\s*R\s*\|/.test(l));
  const pipeCount = rRow ? (rRow.match(/\|/g) || []).length : 0;
  check("1e status pipe does not forge table columns", pipeCount === 3,
    "R row = " + JSON.stringify(rRow) + " (pipeCount=" + pipeCount + ", expected 3)");
}

// 1f. **NEWLINE-INJECTION in status** — a status containing a newline
//     escapes the table row entirely and can inject arbitrary Markdown
//     (e.g. a fake heading) into PROPERTY-MATRIX.md.
{
  const rp = writeReport(baseReport("linux", (function () {
    const p = allVerified();
    p.R = { status: "verified\n\n# INJECTED HEADING\n\nfake body", evidence: [], assumptions: [] };
    return p;
  })()));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const md = generateMarkdown(matrix, metadata);
  check("1f status newline does not inject Markdown lines", !md.includes("\n# INJECTED HEADING"),
    "newline in status broke out of the table cell");
}

// =======================================================================
// ATTACK 2 — HOSTILE CI-URL
// =======================================================================
console.log("\n-- ATTACK 2: HOSTILE CI-URL --");

check("2a rejects javascript:", validateCiUrl("javascript:alert(1)") === false);
check("2a rejects data:", validateCiUrl("data:text/html,<script>alert(1)</script>") === false);
check("2a rejects vbscript:", validateCiUrl("vbscript:msgbox(1)") === false);
check("2a rejects file:", validateCiUrl("file:///etc/passwd") === false);
check("2a rejects ftp:", validateCiUrl("ftp://x/y") === false);
check("2a rejects empty/null/non-string", validateCiUrl("") === false && validateCiUrl(null) === false && validateCiUrl(42) === false);
check("2a rejects garbage", validateCiUrl("not a url") === false);
check("2a accepts https", validateCiUrl("https://ci.example.com/run/1") === true);
check("2a accepts http", validateCiUrl("http://ci.example.com/run/1") === true);

// 2b. hostile URL fed through the render path — must not emit an executable link.
{
  const rp = writeReport(baseReport("linux", allVerified()));
  const { matrix, metadata } = aggregateReports([rp], ["javascript:alert(1)"]);
  const md = generateMarkdown(matrix, metadata);
  const json = generateJson(matrix, metadata);
  check("2b javascript: URL not present in Markdown", !md.includes("javascript:"));
  check("2b javascript: URL not emitted as href", !/href="javascript:/.test(md));
  check("2b hostile ci_url nulled in JSON", json.matrix.Linux.R.ci_url === null,
    "ci_url=" + JSON.stringify(json.matrix.Linux.R.ci_url));
}

// 2c. valid http URL carrying quote/markdown-breaking chars — attribute must not break out.
{
  const rp = writeReport(baseReport("linux", allVerified()));
  const evil = 'https://ci.example.com/run"><script>alert(1)</script>';
  const { matrix, metadata } = aggregateReports([rp], [evil]);
  const md = generateMarkdown(matrix, metadata);
  // validateCiUrl(evil): new URL parses it as http host+path; check the emitted href is escaped.
  check("2c quote-bearing URL does not break out of href attribute", !md.includes('"><script>'),
    "possible attribute breakout in href");
}

// =======================================================================
// ATTACK 3 — UNAVAILABLE-NEVER-GREEN (contract 10 / F22)
// =======================================================================
console.log("\n-- ATTACK 3: UNAVAILABLE-NEVER-GREEN --");

// 3a. profiles missing several properties => those cells must be 'unavailable'.
{
  const partial = { R: { status: "verified", evidence: [], assumptions: [] } }; // only R
  const rp = writeReport(baseReport("linux", partial));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const json = generateJson(matrix, metadata);
  check("3a missing property cell => unavailable in JSON", json.matrix.Linux.E.status === "unavailable" && json.matrix.Linux.X.status === "unavailable");
  check("3a missing property cell not green", json.matrix.Linux.E.status !== "verified");
  const md = generateMarkdown(matrix, metadata);
  const eRow = md.split("\n").find((l) => /^\|\s*E\s*\|/.test(l));
  check("3a missing property cell => unavailable in Markdown", /unavailable/.test(eRow) && !/verified/.test(eRow));
}

// 3b. explicit unavailable / not-applicable / failed must render as-is, never green.
{
  const p = allVerified();
  p.E = { status: "unavailable", evidence: [], assumptions: [] };
  p.T = { status: "failed", evidence: [], assumptions: [] };
  p.X = { status: "not-applicable", evidence: [], assumptions: [] };
  const rp = writeReport(baseReport("linux", p));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const json = generateJson(matrix, metadata);
  check("3b unavailable stays unavailable", json.matrix.Linux.E.status === "unavailable");
  check("3b failed stays failed", json.matrix.Linux.T.status === "failed");
  check("3b not-applicable stays not-applicable", json.matrix.Linux.X.status === "not-applicable");
  check("3b none of the non-verified cells became verified",
    json.matrix.Linux.E.status !== "verified" && json.matrix.Linux.T.status !== "verified" && json.matrix.Linux.X.status !== "verified");
}

// 3c. falsy / absent status inside a profile => unavailable, never assumed green.
{
  const p = allVerified();
  p.E = { status: "", evidence: [], assumptions: [] };       // empty string
  p.T = { evidence: [], assumptions: [] };                   // no status key
  p.G = null;                                                // null profile
  const rp = writeReport(baseReport("linux", p));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const json = generateJson(matrix, metadata);
  check("3c empty-string status => unavailable", json.matrix.Linux.E.status === "unavailable");
  check("3c missing status key => unavailable", json.matrix.Linux.T.status === "unavailable");
  check("3c null profile => unavailable", json.matrix.Linux.G.status === "unavailable");
}

// 3d. a platform whose only report is corrupt must not appear green anywhere.
{
  const bad = writeReport("{ this is not json ");
  const { matrix, metadata } = aggregateReports([bad], [null]);
  const json = generateJson(matrix, metadata);
  const platformKeys = Object.keys(json.matrix);
  const anyGreen = platformKeys.some((pk) => Object.values(json.matrix[pk]).some((c) => c.status === "verified"));
  check("3d corrupt-only report yields no verified cell", !anyGreen, "platforms=" + JSON.stringify(platformKeys));
}

// =======================================================================
// ATTACK 4 — STATUS VOCAB honesty mapping
// =======================================================================
console.log("\n-- ATTACK 4: STATUS VOCAB --");
{
  const p = {
    R: { status: "verified", evidence: [], assumptions: [] },
    E: { status: "unavailable", evidence: [], assumptions: [] },
    B: { status: "failed", evidence: [], assumptions: [] },
    T: { status: "not-applicable", evidence: [], assumptions: [] },
    G: { status: "verified", evidence: [], assumptions: [] },
    Q: { status: "unavailable", evidence: [], assumptions: [] },
    X: { status: "failed", evidence: [], assumptions: [] },
  };
  const rp = writeReport(baseReport("darwin", p));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const json = generateJson(matrix, metadata);
  const md = generateMarkdown(matrix, metadata);
  check("4 verified maps verified", json.matrix.macOS.R.status === "verified");
  check("4 unavailable maps unavailable", json.matrix.macOS.E.status === "unavailable");
  check("4 failed maps failed", json.matrix.macOS.B.status === "failed");
  check("4 not-applicable maps not-applicable", json.matrix.macOS.T.status === "not-applicable");
  check("4 all four vocab words appear in Markdown", /verified/.test(md) && /unavailable/.test(md) && /failed/.test(md) && /not-applicable/.test(md));
}

// =======================================================================
// ATTACK 5 — MALFORMED INPUT
// =======================================================================
console.log("\n-- ATTACK 5: MALFORMED INPUT --");

// 5a. empty report set — no throw, valid structure, no fabricated green.
{
  let threw = false, json, md;
  try {
    const { matrix, metadata } = aggregateReports([], []);
    json = generateJson(matrix, metadata);
    md = generateMarkdown(matrix, metadata);
  } catch (e) { threw = true; }
  check("5a empty set does not throw", !threw);
  check("5a empty set yields empty matrix", json && Object.keys(json.matrix).length === 0);
  check("5a empty set has schema_version", json && json.schema_version === SCHEMA_VERSION);
  // NB: the Legend section always contains the word "verified"; only inspect DATA rows.
  const dataRowGreen = md && md.split("\n").some((l) => /^\|\s*[REBTGQX]\s*\|/.test(l) && /verified/.test(l));
  check("5a empty set Markdown has no verified data cell", md && !dataRowGreen);
}

// 5b. report missing 'profiles' entirely — no throw; that platform is all-unavailable.
{
  let threw = false, json;
  try {
    const rp = writeReport(baseReport("win32", undefined)); // profiles undefined
    const { matrix, metadata } = aggregateReports([rp], [null]);
    json = generateJson(matrix, metadata);
  } catch (e) { threw = true; }
  check("5b missing profiles does not throw", !threw);
  if (json && json.matrix.Windows) {
    const allUnavail = Object.values(json.matrix.Windows).every((c) => c.status === "unavailable");
    check("5b missing-profiles platform is all unavailable", allUnavail);
  } else {
    check("5b missing-profiles platform is all unavailable", true, "platform absent (also not green)");
  }
}

// 5c. report file not found — must skip, not throw.
{
  let threw = false, json;
  try {
    const { matrix, metadata } = aggregateReports([TMP + "/does-not-exist.json"], [null]);
    json = generateJson(matrix, metadata);
  } catch (e) { threw = true; }
  check("5c missing file does not throw", !threw);
  check("5c missing file yields empty matrix", json && Object.keys(json.matrix).length === 0);
}

// 5d. mixed batch: one good + one corrupt + one missing — good survives, no throw.
{
  let threw = false, json;
  try {
    const good = writeReport(baseReport("linux", allVerified()));
    const bad = writeReport("<<<not json>>>");
    const { matrix, metadata } = aggregateReports([good, bad, TMP + "/nope.json"], [null, null, null]);
    json = generateJson(matrix, metadata);
  } catch (e) { threw = true; }
  check("5d mixed batch does not throw", !threw);
  check("5d good report still aggregated", json && json.matrix.Linux && json.matrix.Linux.R.status === "verified");
}

// 5e. aggregateReports called without a ciUrls arg — must not throw.
{
  let threw = false;
  try {
    const rp = writeReport(baseReport("linux", allVerified()));
    aggregateReports([rp]); // no second arg
  } catch (e) { threw = true; }
  check("5e aggregateReports without ciUrls arg does not throw", !threw);
}

// 5f. Markdown <-> JSON status agreement (round-trip honesty) on a mixed report.
{
  const p = allVerified();
  p.E = { status: "unavailable", evidence: [], assumptions: [] };
  p.T = { status: "failed", evidence: [], assumptions: [] };
  const rp = writeReport(baseReport("linux", p));
  const { matrix, metadata } = aggregateReports([rp], [null]);
  const json = generateJson(matrix, metadata);
  const md = generateMarkdown(matrix, metadata);
  const eRow = md.split("\n").find((l) => /^\|\s*E\s*\|/.test(l));
  const tRow = md.split("\n").find((l) => /^\|\s*T\s*\|/.test(l));
  check("5f MD/JSON agree: E unavailable", json.matrix.Linux.E.status === "unavailable" && /unavailable/.test(eRow));
  check("5f MD/JSON agree: T failed", json.matrix.Linux.T.status === "failed" && /failed/.test(tRow));
}

// ---- summary -----------------------------------------------------------
console.log("\n=== SUMMARY ===");
console.log("PASSED: " + passed);
console.log("FAILED: " + failed);
if (failures.length) {
  console.log("\nFailing checks:");
  for (const f of failures) console.log("  - " + f);
}

// cleanup temp fixtures
try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}

process.exit(failed === 0 ? 0 : 1);
