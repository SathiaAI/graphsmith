#!/usr/bin/env node
/* Adversarial test suite for scripts/diagnostics.js — deepseek family lane.
 * Attacks all 5 I4 guarantees: ZERO EGRESS, F16 REDACTION, RAW-PROMPT/EV-MAP
 * EXCLUSION, CONSENT GATE, no-write-without-consent. Drives via CLI and
 * require() API in temp project dirs. Zero-dependency CJS, Node >= 18.
 * One line per case: PASS/FAIL/SKIPPED. Exit code 0 iff zero FAIL. */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");

const DIAGNOSTICS_PATH = path.resolve(__dirname, "..", "..", "..", "scripts", "diagnostics.js");

/* ---- results accumulator ---- */
const results = [];
let failCount = 0;

function record(name, status, detail) {
  const d = detail ? " -- " + detail : "";
  const line = status === "PASS" ? "PASS: " + name : status === "FAIL" ? "FAIL: " + name + d : "SKIPPED: " + name + " (" + (detail || "") + ")";
  results.push({ name, status, detail: detail || "" });
  if (status === "FAIL") failCount++;
  process.stdout.write(line + "\n");
}

/* ---- temp dir helpers ---- */
function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "gs-diag-ds-"));
}
function cleanTempDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* best-effort */ }
}

/* ---- fixture builder ---- */
function buildMinimalProject(dir) {
  const stateDir = path.join(dir, ".graphsmith", "state");
  const harvestDir = path.join(dir, ".graphsmith", "harvest");
  fs.mkdirSync(stateDir, { recursive: true });
  fs.mkdirSync(harvestDir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "test-proj", version: "1.0.0" }));
  fs.writeFileSync(path.join(stateDir, "schema.version"), "1.1\n");
  return { stateDir, harvestDir };
}

/* ---- source scan (independent from selftest) ---- */

function test_source_scan_network_apis() {
  const name = "1. Zero-egress: source scan finds NO network requires or fetch() calls";
  try {
    const source = fs.readFileSync(DIAGNOSTICS_PATH, "utf8");

    const disallowedModules = [
      "http", "https", "http2", "net", "dns", "tls", "dgram",
      "child_process", "node:http", "node:https", "node:http2",
      "node:net", "node:dns", "node:tls", "node:dgram", "node:child_process",
    ];

    const requireRe = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    let m;
    const found = [];
    while ((m = requireRe.exec(source)) !== null) {
      if (disallowedModules.includes(m[1])) found.push(m[1]);
    }
    if (found.length > 0) throw new Error("Network requires found: " + found.join(", "));

    const fetchRe = /\bfetch\s*\(/g;
    if (fetchRe.test(source)) throw new Error("fetch() call found in source");

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- Secret categories planted simultaneously across all available string fields ---- */

function test_multi_secret_redaction() {
  const name = "2. F16 redaction: 15 secret categories planted across all fields, NONE survive in written file";
  try {
    const root = makeTempDir();
    const { stateDir, harvestDir } = buildMinimalProject(root);

    /* window.json with secret-like values */
    fs.writeFileSync(path.join(stateDir, "window.json"), JSON.stringify({
      schema_version: "1.0", state_rev: 1, state: "OBSERVING", flag: false,
      window: { slots: [], active: 0, admitted: 0 },
    }));

    fs.writeFileSync(path.join(stateDir, "run-registry.jsonl"),
      [{ record_type: "REGISTERED", run_id: "r1", tree_id: "t1" }].map(JSON.stringify).join("\n") + "\n");

    fs.writeFileSync(path.join(stateDir, "alpha-ledger.jsonl"),
      [{ record_type: "RESERVED", alpha_slot: 1 }].map(JSON.stringify).join("\n") + "\n");

    fs.writeFileSync(path.join(stateDir, "rejected-buffer.jsonl"),
      [{ record_type: "REJECTED", fingerprint: "fp-1" }].map(JSON.stringify).join("\n") + "\n");

    fs.writeFileSync(path.join(stateDir, "rollback-families.jsonl"),
      [{ record_type: "ROLLBACK_RECORDED", fingerprint: "fp-rb-1" }].map(JSON.stringify).join("\n") + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 1, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    /* Plant secrets in every available string field of events-proposer */
    const secrets = {
      sk:    "sk-A1b2C3d4E5f6G7h8I9j0K1l2",                           /* opaque-secret-prefix */
      pk:    "pk_myprefixkeyVALUE9876543210",                          /* opaque-secret-prefix */
      gh:    "ghp_abcdefghijklmnopqrstuvwx12345678",                   /* github-token */
      aws:   "AKIA1234567890ABCDXY",                                   /* aws-key */
      jwt:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature12345", /* jwt */
      conn:  "mongodb://admin:hunter2@192.168.1.100:27017/secrets",    /* connection-string + private-ip */
      email: "adversary@evil-corp-test.example.com",                   /* email */
      cc:    "4111-2222-3333-4444",                                    /* credit-card */
      pass:  "password: SuperS3cret!2024Pass",                         /* password */
      apik:  "api_key=sk-PLANTEDapikeyABCDEF1234",                     /* api-key */
      bearer:"Bearer: eyJtokenRidingBearerHeader12345",                /* bearer-token */
      oauth: "client_secret=C1i3ntOAuthS3cr3t98765",                  /* oauth-secret */
      token: "token=ABCDEFGHIJKLMNOPQRST12345",                        /* generic-token */
      pem:   "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----", /* private-key */
      ip:    "10.0.0.99",                                              /* private-ip standalone */
    };

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"), [
      { seq: 0, type: "run_halt",    code: "unknown_halt", run_ref: secrets.sk,     step_ref: secrets.gh,     evidence_ref: secrets.aws,    fingerprint: secrets.jwt,   counters: { name: secrets.cc } },
      { seq: 1, type: "tripwire",    code: "trip",         run_ref: secrets.conn,   step_ref: secrets.email,  evidence_ref: secrets.pass,   fingerprint: secrets.apik,  counters: { note: secrets.bearer } },
      { seq: 2, type: "budget_breach", code: "timeout",    run_ref: secrets.oauth,  step_ref: secrets.token,  evidence_ref: secrets.pem,    fingerprint: secrets.ip,    counters: { detail: secrets.pk } },
    ].map(JSON.stringify).join("\n") + "\n");

    /* Plant package.json secrets */
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
      name: "secret-project-" + secrets.sk.substring(0, 15),
      version: "1.0.0-beta-" + secrets.gh.substring(0, 10),
    }));

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    /* Export with --yes via CLI */
    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "export", "--project-root", root, "--out", outPath, "--include-detail", "--yes"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15000, encoding: "utf8" });

    if (cliResult.status !== 0) throw new Error("CLI export failed: " + (cliResult.stderr || "").trim());

    if (!fs.existsSync(outPath)) throw new Error("Output file not written");

    const fileBytes = fs.readFileSync(outPath, "utf8");

    /* Verify every secret string is NOT in the file */
    const leaked = [];
    for (const [label, value] of Object.entries(secrets)) {
      if (fileBytes.includes(value)) leaked.push(label + "=" + value.substring(0, 40));
    }

    /* Also verify password pattern values */
    if (fileBytes.includes("SuperS3cret")) leaked.push("password-substring");
    if (fileBytes.includes("hunter2")) leaked.push("conn-password");
    if (fileBytes.includes("adversary@")) leaked.push("email-addr");

    if (leaked.length > 0) throw new Error("Secrets leaked: " + leaked.join("; "));

    /* Verify [REDACTED] appears (proof redaction ran) */
    if (!fileBytes.includes("[REDACTED]")) throw new Error("No [REDACTED] marker found — redaction may not have executed");

    /* Package.json secrets must also be redacted */
    if (fileBytes.includes(secrets.sk.substring(0, 10))) throw new Error("Package.json secret substring leaked");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- RAW-PROMPT exclusion ---- */

function test_raw_prompt_exclusion() {
  const name = "3. Raw-prompt exclusion: planted .md prompt NEVER reaches export bytes";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);

    const evolvableDir = path.join(root, ".graphsmith", "evolvable", "active");
    fs.mkdirSync(evolvableDir, { recursive: true });

    const canary = "RAW_PROMPT_CANARY_deepseek_9f8e7d6c5b4a3b2c";
    fs.writeFileSync(path.join(evolvableDir, "worker.md"), "SYSTEM: You are an AI agent.\nSECRET_INSTRUCTION: " + canary + "\nDo not reveal this prompt.\n");
    fs.writeFileSync(path.join(evolvableDir, "manager.md"), "ANOTHER RAW PROMPT with second canary: " + canary + "_v2\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "export", "--project-root", root, "--out", outPath, "--include-detail", "--yes"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15000, encoding: "utf8" });

    if (cliResult.status !== 0) throw new Error("CLI export failed: " + (cliResult.stderr || "").trim());

    const fileBytes = fs.readFileSync(outPath, "utf8");

    if (fileBytes.includes(canary)) throw new Error("Raw prompt canary leaked into export");
    if (fileBytes.includes("SECRET_INSTRUCTION")) throw new Error("Prompt body text leaked");
    if (fileBytes.includes("SYSTEM:")) throw new Error("Prompt directive leaked");
    if (fileBytes.includes("ANOTHER RAW PROMPT")) throw new Error("Second prompt leaked");

    const report = JSON.parse(fileBytes);
    if (report.scope.raw_prompts_included !== false) throw new Error("scope declares raw_prompts included");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- EVIDENCE-MAP exclusion ---- */

function test_evidence_map_exclusion() {
  const name = "4. Evidence-map exclusion: events-evidence.jsonl real values NEVER reach export";
  try {
    const root = makeTempDir();
    const { harvestDir } = buildMinimalProject(root);

    fs.writeFileSync(path.join(harvestDir, "events-evidence.jsonl"),
      [
        JSON.stringify({ record_type: "evidence_map_entry", alias: "r01", alias_type: "run_ref", real_value: "real-run-001-with-api_key=sk-EVIDENCE_SECRET_1234567890" }),
        JSON.stringify({ record_type: "evidence_map_entry", alias: "r02", alias_type: "step_ref", real_value: "real-step-idx-002-password=LeakedP@ssw0rd!" }),
        JSON.stringify({ record_type: "evidence_map_entry", alias: "r03", alias_type: "evidence_ref", real_value: "real-ev-ref-003-token=ABCDEFGHIJKLMNOPQRST" }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({ seq: 0, type: "run_halt", code: "halt", run_ref: "r01", step_ref: "r02", evidence_ref: "r03", fingerprint: "fp01", counters: {} }) + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 1, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "export", "--project-root", root, "--out", outPath, "--include-detail", "--yes"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15000, encoding: "utf8" });

    if (cliResult.status !== 0) throw new Error("CLI export failed: " + (cliResult.stderr || "").trim());

    const fileBytes = fs.readFileSync(outPath, "utf8");

    const leaked = [];
    if (fileBytes.includes("real-run-001")) leaked.push("real-run-id-001");
    if (fileBytes.includes("real-step-idx-002")) leaked.push("real-step-idx-002");
    if (fileBytes.includes("real-ev-ref-003")) leaked.push("real-ev-ref-003");
    if (fileBytes.includes("sk-EVIDENCE_SECRET")) leaked.push("evidence-secret");
    if (fileBytes.includes("LeakedP@ssw0rd")) leaked.push("evidence-password");
    if (fileBytes.includes("ABCDEFGHIJKLMNOPQRST")) leaked.push("evidence-token");
    if (fileBytes.includes("evidence_map_entry")) leaked.push("evidence_map_entry record_type");

    if (leaked.length > 0) throw new Error("Evidence-map real values leaked: " + leaked.join("; "));

    const report = JSON.parse(fileBytes);
    if (report.scope.evidence_map_real_values_included !== false) throw new Error("scope declares ev map real values included");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- NO WRITE WITHOUT --yes (CLI path) ---- */

function test_no_write_without_yes_cli() {
  const name = "5. Consent gate: CLI without --yes writes NOTHING to disk";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);
    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "export", "--project-root", root, "--out", outPath, "--include-detail"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15000, encoding: "utf8" });

    const stdout = cliResult.stdout || "";
    const stderr = cliResult.stderr || "";

    /* CLI should exit 0 (not error) but NOT write */
    if (cliResult.status !== 0) throw new Error("CLI exited with code " + cliResult.status + " stderr=" + stderr.trim());

    if (fs.existsSync(outPath)) throw new Error("File was written despite NO --yes flag");

    /* Must contain preview and consent-prompt text */
    if (!stdout.includes("PREVIEW")) throw new Error("No PREVIEW section in output");
    if (!stdout.includes("Not written")) throw new Error("Missing 'Not written' message");
    if (!stdout.includes("--yes")) throw new Error("Missing --yes instructions");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- NO WRITE without consent via require() API ---- */

function test_no_write_without_consent_api() {
  const name = "6. Consent gate: require() API without confirmWrite returns written=false";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);
    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const logs = [];
    const result = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: false,
      outPath,
      log: (line) => logs.push(line),
    });

    if (result.written !== false) throw new Error("written should be false, got " + result.written);
    if (result.path !== null) throw new Error("path should be null when not written, got " + result.path);
    if (fs.existsSync(outPath)) throw new Error("File written despite confirmWrite=false");
    if (typeof result.report !== "object" || result.report === null) throw new Error("report not returned");
    if (typeof result.previewText !== "string" || result.previewText.length === 0) throw new Error("previewText not returned");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- FULL CONSENT GATE flow (CLI with --yes) ---- */

function test_full_consent_gate_flow() {
  const name = "7. Consent gate: CLI with --yes writes file, preview shown before write, warning present";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);
    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "export", "--project-root", root, "--out", outPath, "--include-detail", "--yes"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15000, encoding: "utf8" });

    if (cliResult.status !== 0) throw new Error("CLI exited with code " + cliResult.status + " stderr=" + (cliResult.stderr || "").trim());

    if (!fs.existsSync(outPath)) throw new Error("File not written despite --yes");

    const stdout = cliResult.stdout || "";

    /* Check preview appears BEFORE written message */
    const previewIdx = stdout.indexOf("PREVIEW");
    const writtenIdx = stdout.indexOf("Written:");
    if (previewIdx === -1) throw new Error("No PREVIEW in output");
    if (writtenIdx === -1) throw new Error("No Written: in output");
    if (previewIdx >= writtenIdx) throw new Error("PREVIEW appears after Written: — consent gate ordering broken");

    /* Public tracker warning */
    if (!stdout.includes("PUBLIC")) throw new Error("No PUBLIC warning");
    if (!/issue trackers are PUBLIC/i.test(stdout)) throw new Error("Missing 'issue trackers are PUBLIC' warning");
    if (!/review this before posting/i.test(stdout)) throw new Error("Missing 'review this before posting'");

    /* Reminder after write */
    if (!/issue trackers are PUBLIC/i.test(stdout.substring(writtenIdx))) throw new Error("No post-write reminder about public trackers");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- PREVIEW === WRITTEN BYTES ---- */

function test_preview_matches_written_bytes() {
  const name = "8. Preview == written: previewText byte-identical to written file (via API)";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);
    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const logs = [];
    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: true,
      outPath,
      log: (line) => logs.push(line),
    });

    if (!result.written) throw new Error("File not written");

    const fileBytes = fs.readFileSync(outPath, "utf8");
    if (fileBytes !== result.previewText) throw new Error("previewText does not match written file byte-for-byte");

    /* Also verify that preview appears in log output before Written line */
    const joined = logs.join("\n");
    const previewLogIdx = joined.indexOf('"schema_version"');
    const writtenLogIdx = joined.indexOf("Written:");
    if (previewLogIdx === -1) throw new Error("Preview not logged");
    if (writtenLogIdx === -1) throw new Error("Written not logged");
    if (previewLogIdx >= writtenLogIdx) throw new Error("Preview logged after write notification");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- MALFORMED STATE: corrupt JSON window.json ---- */

function test_malformed_state_corrupt_json() {
  const name = "9. Malformed state: corrupt window.json tolerated, no write without --yes";
  try {
    const root = makeTempDir();
    const { stateDir } = buildMinimalProject(root);

    /* Write corrupt non-JSON window.json */
    fs.writeFileSync(path.join(stateDir, "window.json"), "NOT_VALID_JSON{{{{broken");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    /* Should NOT crash, should produce preview, should NOT write without --yes */
    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const logs = [];
    const result = exportDiagnostics(root, {
      confirmWrite: false,
      outPath,
      log: (line) => logs.push(line),
    });

    if (result.written !== false) throw new Error("Written despite corrupt state and no --yes");
    if (fs.existsSync(outPath)) throw new Error("File written despite corrupt state");
    if (typeof result.previewText !== "string" || result.previewText.length === 0) throw new Error("No preview text for corrupt state");

    /* Report should still have structure but window should be NO_WINDOW */
    if (!result.report.state_summary) throw new Error("No state_summary in corrupt-state report");
    if (result.report.state_summary.window.state !== "NO_WINDOW") throw new Error("Expected NO_WINDOW for corrupt json, got " + result.report.state_summary.window.state);

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- MALFORMED STATE: empty state directory ---- */

function test_malformed_state_empty_dir() {
  const name = "10. Malformed state: empty .graphsmith/state/ tolerated, no crash, no write without --yes";
  try {
    const root = makeTempDir();
    /* Create .graphsmith/state but leave it empty (no files) */
    fs.mkdirSync(path.join(root, ".graphsmith", "state"), { recursive: true });
    fs.mkdirSync(path.join(root, ".graphsmith", "harvest"), { recursive: true });
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "empty-proj", version: "0.0.0" }));

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const logs = [];
    const result = exportDiagnostics(root, {
      confirmWrite: false,
      outPath,
      log: (line) => logs.push(line),
    });

    if (result.written !== false) throw new Error("Written despite empty state and no --yes");
    if (fs.existsSync(outPath)) throw new Error("File written despite empty state");

    /* Report should have reasonable defaults */
    const report = result.report;
    if (!report) throw new Error("No report produced for empty state");
    if (typeof report.previewText !== "string") { /* check result.previewText, not report.previewText */ }
    if (typeof result.previewText !== "string" || result.previewText.length === 0) throw new Error("No preview text for empty state");

    /* state_summary should have empty/zero counts */
    if (!report.state_summary) throw new Error("No state_summary");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- MALFORMED STATE: missing .graphsmith dir entirely ---- */

function test_malformed_state_no_graphsmith_dir() {
  const name = "11. Malformed state: no .graphsmith/ dir at all — tolerated, no crash, no write without --yes";
  try {
    const root = makeTempDir();
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "bare-proj", version: "0.1.0" }));

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      confirmWrite: false,
      outPath,
      log: () => {},
    });

    if (result.written !== false) throw new Error("Written despite missing .graphsmith/");
    if (fs.existsSync(outPath)) throw new Error("File written despite missing .graphsmith/");

    if (!result.report.state_summary) throw new Error("No state_summary for missing .graphsmith/");
    if (result.report.state_summary.window.state !== "NO_WINDOW") throw new Error("Expected NO_WINDOW");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- AGGREGATE-ONLY mode has no detail events, no raw content ---- */

function test_aggregate_only_mode() {
  const name = "12. Aggregate-only mode: no detail field, no raw event fields, only aggregate counters";
  try {
    const root = makeTempDir();
    const { harvestDir } = buildMinimalProject(root);

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      [
        JSON.stringify({ seq: 0, type: "run_halt", code: "halt", run_ref: "r01", step_ref: "s01", evidence_ref: "e01", fingerprint: "fp01", counters: { x: 1 } }),
        JSON.stringify({ seq: 1, type: "tripwire", code: "trip", run_ref: "r02", step_ref: "s02", evidence_ref: "e02", fingerprint: "fp02", counters: { y: 2 } }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 2, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      includeDetail: false,
      confirmWrite: true,
      outPath,
      log: () => {},
    });

    if (result.report.detail !== undefined) throw new Error("detail field present in aggregate-only mode");
    if (result.report.scope.mode !== "aggregate") throw new Error("scope.mode should be 'aggregate', got " + result.report.scope.mode);

    /* Verify aggregate counters are present */
    if (result.report.event_counters.total_proposer_records !== 2) throw new Error("Wrong proposer record count");
    if (result.report.event_counters.by_type.run_halt.count !== 1) throw new Error("Wrong run_halt count");

    /* verify no raw event fields in output bytes */
    const fileBytes = fs.readFileSync(outPath, "utf8");
    if (fileBytes.includes('"seq"')) throw new Error("Raw event 'seq' field leaked in aggregate mode");
    if (fileBytes.includes('"step_ref"')) throw new Error("Raw event 'step_ref' leaked in aggregate mode");
    if (fileBytes.includes('"run_ref"')) throw new Error("Raw event 'run_ref' leaked in aggregate mode");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- CLI usage message on bad args ---- */

function test_cli_usage_on_bad_args() {
  const name = "13. CLI: bad subcommand prints usage to stderr, exits non-zero";
  try {
    const root = makeTempDir();
    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "bogus-cmd"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 10000, encoding: "utf8" });

    if (cliResult.status !== 2) throw new Error("Expected exit code 2, got " + cliResult.status);
    if (!(cliResult.stderr || "").includes("Usage")) throw new Error("No usage message on bad command");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Require() API: default outPath ---- */

function test_require_api_default_outpath() {
  const name = "14. require() API: default outPath resolves to .graphsmith/diagnostics/";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      confirmWrite: true,
      log: () => {},
    });

    if (!result.written) throw new Error("File not written");
    const expectedPath = path.join(root, ".graphsmith", "diagnostics", "diagnostics-report.json");
    if (result.path !== expectedPath) throw new Error("Wrong default path: " + result.path + " vs " + expectedPath);
    if (!fs.existsSync(expectedPath)) throw new Error("Default outPath file not on disk");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Require() API: --selftest via require ---- */

function test_selftest_via_require() {
  const name = "15. Built-in selftest: selftest() returns passing report with zero errors";
  try {
    const { selftest } = require(DIAGNOSTICS_PATH);
    const report = selftest();

    if (report.status !== "pass") throw new Error("selftest status is '" + report.status + "' — " + (report.errors || []).join("; "));
    if (report.exitCode !== 0) throw new Error("selftest exitCode is " + report.exitCode);
    if (!Array.isArray(report.tests) || report.tests.length === 0) throw new Error("No tests in selftest report");

    const failTests = report.tests.filter(t => t.status === "fail");
    if (failTests.length > 0) throw new Error(failTests.length + " selftest failures: " + JSON.stringify(failTests));

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- Nested secret in package.json name survives redaction check ---- */

function test_package_json_secrets_redacted() {
  const name = "16. Package.json: secrets in name/version fields redacted in export";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);

    /* Plant a github token in package name */
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
      name: "myapp-ghp_1234567890abcdefghij1234567890",
      version: "2.0.0-api_key=sk-PKGsecretABCDEFGHIJ1234",
    }));

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      confirmWrite: true,
      outPath,
      log: () => {},
    });

    const fileBytes = fs.readFileSync(outPath, "utf8");

    if (fileBytes.includes("ghp_1234567890abcdefghij")) throw new Error("Github token in package name leaked");
    if (fileBytes.includes("sk-PKGsecret")) throw new Error("API-key pattern in package version leaked");

    if (!fileBytes.includes("[REDACTED]")) throw new Error("No [REDACTED] markers — package.json secrets not redacted");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Nested secret in counter string value ---- */

function test_nested_counter_secret_redacted() {
  const name = "17. Nested secrets: secrets inside counter object string values redacted";
  try {
    const root = makeTempDir();
    const { harvestDir } = buildMinimalProject(root);

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({
        seq: 0, type: "run_halt", code: "halt", run_ref: "r01", step_ref: "s01",
        evidence_ref: "e01", fingerprint: "fp01",
        counters: {
          metrics: "normal",
          deep_nested: {
            inner_key: "this contains sk-DEEPnestedSECRET12345 buried in counter object",
            arr: [{ tag: "Bearer: DEEPbearerTokenNestedSecretXYZ" }],
          },
        },
      }) + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 1, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: true,
      outPath,
      log: () => {},
    });

    const fileBytes = fs.readFileSync(outPath, "utf8");

    if (fileBytes.includes("sk-DEEPnested")) throw new Error("Deeply nested opaque-secret-prefix leaked");
    if (fileBytes.includes("DEEPbearerToken")) throw new Error("Deeply nested bearer token leaked");

    /* Verify [REDACTED] in counter sections */
    if (!fileBytes.includes("[REDACTED]")) throw new Error("No [REDACTED] in nested counter secrets output");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Detail mode: event fields contain only aliases, no secrets ---- */

function test_detail_mode_events_are_safe() {
  const name = "18. Detail mode safety: event detail fields are aliases/closures only, no raw secrets";
  try {
    const root = makeTempDir();
    const { harvestDir } = buildMinimalProject(root);

    const cleanAlias = "run-ref-abcdef";
    const cleanStep = "step-ref-12345";
    const cleanEvidence = "ev-ref-98765";

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      [
        JSON.stringify({ seq: 0, type: "run_halt", code: "unknown_halt", run_ref: cleanAlias, step_ref: cleanStep, evidence_ref: cleanEvidence, fingerprint: "fp-clean-01", counters: { steps: 5 } }),
        JSON.stringify({ seq: 1, type: "tripwire", code: "network_access", run_ref: "r02", step_ref: "s02", evidence_ref: "e02", fingerprint: "fp-clean-02", counters: { trips: 1 } }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 2, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: true,
      outPath,
      log: () => {},
    });

    const detail = result.report.detail;
    if (!detail || !Array.isArray(detail.events)) throw new Error("No detail events in report");
    if (detail.events.length !== 2) throw new Error("Expected 2 detail events, got " + detail.events.length);

    const ev0 = detail.events[0];
    if (ev0.run_ref !== cleanAlias) throw new Error("run_ref mismatch in detail");
    if (ev0.step_ref !== cleanStep) throw new Error("step_ref mismatch");
    if (ev0.type !== "run_halt") throw new Error("type mismatch");
    if (ev0.seq !== 0) throw new Error("seq mismatch");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Aggregate counters correctness ---- */

function test_aggregate_counters_correct() {
  const name = "19. Aggregate counters: run_registry, alpha, event tallies computed correctly";
  try {
    const root = makeTempDir();
    const { stateDir, harvestDir } = buildMinimalProject(root);

    fs.writeFileSync(path.join(stateDir, "run-registry.jsonl"),
      [
        JSON.stringify({ record_type: "REGISTERED", run_id: "r1", tree_id: "t1" }),
        JSON.stringify({ record_type: "REGISTERED", run_id: "r2", tree_id: "t1" }),
        JSON.stringify({ record_type: "REGISTERED", run_id: "r3", tree_id: "t2" }),
        JSON.stringify({ record_type: "HEARTBEAT", run_id: "r1" }),
        JSON.stringify({ record_type: "HEARTBEAT", run_id: "r2" }),
        JSON.stringify({ record_type: "DEREGISTERED", run_id: "r3" }),
        JSON.stringify({ record_type: "EXPIRED", run_id: "r1" }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(stateDir, "alpha-ledger.jsonl"),
      [
        JSON.stringify({ record_type: "RESERVED", alpha_slot: 1 }),
        JSON.stringify({ record_type: "RESERVED", alpha_slot: 2 }),
        JSON.stringify({ record_type: "COMPLETED", reservation_id: "res1" }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(stateDir, "rejected-buffer.jsonl"),
      [
        JSON.stringify({ record_type: "REJECTED", fingerprint: "fp-a" }),
        JSON.stringify({ record_type: "REJECTED", fingerprint: "fp-b" }),
        JSON.stringify({ record_type: "REJECTED", fingerprint: "fp-c" }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(stateDir, "rollback-families.jsonl"),
      [
        JSON.stringify({ record_type: "ROLLBACK_RECORDED", fingerprint: "rb-1" }),
        JSON.stringify({ record_type: "ROLLBACK_RECORDED", fingerprint: "rb-2" }),
        JSON.stringify({ record_type: "HUMAN_ACK", fingerprint: "rb-1" }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      [
        JSON.stringify({ seq: 0, type: "run_halt", code: "halt", counters: {} }),
        JSON.stringify({ seq: 1, type: "tripwire", code: "net", counters: {} }),
        JSON.stringify({ seq: 2, type: "tripwire", code: "io", counters: {} }),
        JSON.stringify({ seq: 3, type: "budget_breach", code: "timeout", counters: {} }),
        JSON.stringify({ seq: 4, type: "adoption", code: "adopt1", counters: {} }),
      ].join("\n") + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 5, skipped: 1, quarantined: 2, dropped_refs: 0, rejected: 3, harvest_valid: true, run_count: 4, broken_runs: 1 }) + "\n");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      confirmWrite: true,
      log: () => {},
    });

    const s = result.report.state_summary;
    const e = result.report.event_counters;

    if (s.run_registry.registered !== 3) throw new Error("Expected 3 REGISTERED, got " + s.run_registry.registered);
    if (s.run_registry.heartbeat !== 2) throw new Error("Expected 2 HEARTBEAT, got " + s.run_registry.heartbeat);
    if (s.run_registry.deregistered !== 1) throw new Error("Expected 1 DEREGISTERED, got " + s.run_registry.deregistered);
    if (s.run_registry.expired !== 1) throw new Error("Expected 1 EXPIRED, got " + s.run_registry.expired);

    if (s.alpha_ledger.reserved !== 2) throw new Error("Expected 2 RESERVED, got " + s.alpha_ledger.reserved);
    if (s.alpha_ledger.completed !== 1) throw new Error("Expected 1 COMPLETED, got " + s.alpha_ledger.completed);

    if (s.rejected_buffer_count !== 3) throw new Error("Expected 3 rejected, got " + s.rejected_buffer_count);

    if (s.rollback_families.recorded !== 2) throw new Error("Expected 2 ROLLBACK_RECORDED, got " + s.rollback_families.recorded);
    if (s.rollback_families.unacknowledged !== 1) throw new Error("Expected 1 unacknowledged, got " + s.rollback_families.unacknowledged);

    if (e.total_proposer_records !== 5) throw new Error("Expected 5 proposer records, got " + e.total_proposer_records);
    if (e.by_type.run_halt.count !== 1) throw new Error("Expected 1 run_halt");
    if (e.by_type.tripwire.count !== 2) throw new Error("Expected 2 tripwire, got " + e.by_type.tripwire.count);

    const cs = e.compiler_stats;
    if (cs.total_events !== 5) throw new Error("Expected compiler total_events=5, got " + cs.total_events);
    if (cs.skipped !== 1) throw new Error("Expected skipped=1");
    if (cs.quarantined !== 2) throw new Error("Expected quarantined=2");
    if (cs.rejected !== 3) throw new Error("Expected rejected=3");
    if (cs.run_count !== 4) throw new Error("Expected run_count=4");
    if (cs.broken_runs !== 1) throw new Error("Expected broken_runs=1");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Scope declarations verified ---- */

function test_scope_declarations() {
  const name = "20. Scope declarations: all 4 exclusion booleans + redaction applied flag are correct";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, { confirmWrite: true, log: () => {} });

    const scope = result.report.scope;
    if (scope.raw_prompts_included !== false) throw new Error("raw_prompts_included is not false");
    if (scope.learned_rule_bodies_included !== false) throw new Error("learned_rule_bodies_included is not false");
    if (scope.evidence_map_real_values_included !== false) throw new Error("evidence_map_real_values_included is not false");
    if (scope.secrets_included !== false) throw new Error("secrets_included is not false");
    if (scope.redaction_applied !== true) throw new Error("redaction_applied is not true");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Platform + metadata fields present ---- */

function test_report_metadata() {
  const name = "21. Report metadata: schema_version, platform, component_versions all present";
  try {
    const root = makeTempDir();
    buildMinimalProject(root);

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, { confirmWrite: true, log: () => {} });

    const r = result.report;
    if (r.schema_version !== "1.0") throw new Error("schema_version mismatch");
    if (r.report_type !== "graphsmith-diagnostics-export") throw new Error("report_type mismatch");
    if (!r.generated_at || !r.generated_at.includes("T")) throw new Error("generated_at missing or malformed");
    if (!r.platform.node_version) throw new Error("node_version missing");
    if (!r.platform.os_platform) throw new Error("os_platform missing");
    if (!r.component_versions.package_name) throw new Error("package_name missing");
    if (!r.component_versions.package_version) throw new Error("package_version missing");
    if (!r.component_versions.state_schema_version) throw new Error("state_schema_version missing");
    if (!r.verifier_profile) throw new Error("verifier_profile missing");
    if (r.verifier_profile.checked !== false) throw new Error("verifier_profile.checked should be false");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Multiple iterations: no stale secrets in second export ---- */

function test_two_exports_consistent() {
  const name = "22. Session consistency: two exports produce identical redacted output for same state";
  try {
    const root = makeTempDir();
    const { harvestDir } = buildMinimalProject(root);

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({ seq: 0, type: "run_halt", code: "test", run_ref: "r01", step_ref: "api_key=sk-sameSECRETvalue99999", evidence_ref: "e01", fingerprint: "fp01", counters: {} }) + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 1, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);

    const out1 = path.join(root, ".graphsmith", "diagnostics", "diag1.json");
    const r1 = exportDiagnostics(root, { includeDetail: true, confirmWrite: true, outPath: out1, log: () => {} });

    const out2 = path.join(root, ".graphsmith", "diagnostics", "diag2.json");
    const r2 = exportDiagnostics(root, { includeDetail: true, confirmWrite: true, outPath: out2, log: () => {} });

    const bytes1 = fs.readFileSync(out1, "utf8");
    const bytes2 = fs.readFileSync(out2, "utf8");

    /* The generated_at timestamp will differ; strip it for comparison */
    const stripped1 = bytes1.replace(/"generated_at": "[^"]+"/, '"generated_at": "STRIPPED"');
    const stripped2 = bytes2.replace(/"generated_at": "[^"]+"/, '"generated_at": "STRIPPED"');

    if (stripped1 !== stripped2) throw new Error("Two exports of same state differ (besides timestamp)");

    /* Both must be redacted */
    if (bytes1.includes("api_key=sk-sameSECRET")) throw new Error("Export 1 leaked secret");
    if (bytes2.includes("api_key=sk-sameSECRET")) throw new Error("Export 2 leaked secret");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Adversarial: secrets as standalone strings in event fields ---- */

function test_secret_in_value_fields_redacted() {
  const name = "23. Adversarial value fields: secrets in evidence_ref/fingerprint/step_ref all redacted";
  try {
    const root = makeTempDir();
    const { stateDir, harvestDir } = buildMinimalProject(root);

    /* Plant a JWT as a fingerprint in rollback-families */
    fs.writeFileSync(path.join(stateDir, "rollback-families.jsonl"),
      JSON.stringify({ record_type: "ROLLBACK_RECORDED", fingerprint: "eyJhbGciOiJIUzI1NiJ9.eyJmaW5nZXJwcmludCI6Imp3dC1zZWNyZXQifQ.sigXYZ9876543210abcdef" }) + "\n");

    /* Plant secrets in evidence_ref and step_ref — use patterns that match redaction regexes */
    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({ seq: 0, type: "run_halt", code: "normal_code", run_ref: "r01", step_ref: "sk-stepREFleakTEST12345", evidence_ref: "AKIAZZZZZZZZZZZZZZZZ", fingerprint: "fp01", counters: {} }) + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 1, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");

    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);
    const result = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: true,
      outPath,
      log: () => {},
    });

    const fileBytes = fs.readFileSync(outPath, "utf8");

    /* VALUE-field secrets must be redacted */
    if (fileBytes.includes("AKIAZZZZZZZZZZZZZZZZ")) throw new Error("AWS key in evidence_ref (value field) leaked");
    if (fileBytes.includes("sk-stepREFleakTEST12345")) throw new Error("sk-opaque-secret in step_ref (value field) leaked");

    /* The rollback fingerprint is aggregate-only; verify it's NOT in the file as raw text */
    if (fileBytes.includes("eyJhbGciOiJIUzI1NiJ9")) throw new Error("JWT from rollback fingerprint leaked");

    if (!fileBytes.includes("[REDACTED]")) throw new Error("No [REDACTED] for planted adversarial secrets");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
}

/* ---- Known limitation: aggregate by_code uses code values as object keys ---- */

function test_by_code_key_not_redacted() {
  const name = "24. Untrusted code as aggregate by_code KEY must be enum-validated (poisoned code bucketed, never emitted verbatim)";
  try {
    const root = makeTempDir();
    const { harvestDir } = buildMinimalProject(root);

    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({ seq: 0, type: "run_halt", code: "AKIA1234567890ABCDEF", run_ref: "r01", step_ref: "s01", evidence_ref: "e01", fingerprint: "fp01", counters: {} }) + "\n");

    fs.writeFileSync(path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({ record_type: "compiler_stats", total_events: 1, skipped: 0, quarantined: 0, dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 1, broken_runs: 0 }) + "\n");

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diag.json");
    const { exportDiagnostics } = require(DIAGNOSTICS_PATH);

    /* DEFAULT (aggregate) mode — the export a human is MOST likely to post to a public
     * tracker. A poisoned code from the untrusted B4 proposer file (events-proposer.jsonl,
     * unsigned per contracts/04) must NOT survive as a by_code object KEY. The closed-enum
     * guarantee is a PRODUCER property; the consumer (diagnostics) must RE-VALIDATE code
     * against the closed per-type enum and bucket non-conforming values under a safe key
     * (e.g. invalid_code/unknown), never emit the raw value. Same root class as watcher D1
     * and diagnostics test 23. */
    exportDiagnostics(root, { includeDetail: false, confirmWrite: true, outPath, log: () => {} });
    const aggBytes = fs.readFileSync(outPath, "utf8");
    if (aggBytes.includes("AKIA1234567890ABCDEF")) throw new Error("poisoned code leaked as by_code KEY in DEFAULT aggregate mode");

    /* Detail mode: code (value or key) must also not survive (test 23 covers the value path). */
    exportDiagnostics(root, { includeDetail: true, confirmWrite: true, outPath, log: () => {} });
    const detailBytes = fs.readFileSync(outPath, "utf8");
    if (detailBytes.includes("AKIA1234567890ABCDEF")) throw new Error("poisoned code leaked in detail mode (value or key)");

    cleanTempDir(root);
    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
    try { cleanTempDir(root); } catch (ex) {}
  }
} /* end test_by_code_key_not_redacted */

/* ---- CLI selftest path ---- */

function test_cli_selftest() {
  const name = "25. CLI --selftest: produces JSON report with status=pass, exits 0";
  try {
    const cliResult = cp.spawnSync(process.execPath,
      [DIAGNOSTICS_PATH, "--selftest"],
      { stdio: ["ignore", "pipe", "pipe"], timeout: 15000, encoding: "utf8" });

    const stdout = cliResult.stdout || "";
    if (cliResult.status !== 0) throw new Error("selftest exited with code " + cliResult.status + " stderr=" + (cliResult.stderr || "").trim());

    let report;
    try {
      report = JSON.parse(stdout.trim());
    } catch (e) {
      throw new Error("selftest stdout not valid JSON: " + stdout.substring(0, 200));
    }

    if (report.status !== "pass") throw new Error("selftest status=" + report.status);
    if (report.exitCode !== 0) throw new Error("selftest exitCode=" + report.exitCode);

    record(name, "PASS");
  } catch (e) {
    record(name, "FAIL", e.message);
  }
}

/* ---- Main ---- */

function main() {
  process.stdout.write("=== GraphSmith diagnostics.js adversarial test suite (deepseek family) ===\n\n");

  /* Execute all tests */
  const tests = [
    test_source_scan_network_apis,
    test_multi_secret_redaction,
    test_raw_prompt_exclusion,
    test_evidence_map_exclusion,
    test_no_write_without_yes_cli,
    test_no_write_without_consent_api,
    test_full_consent_gate_flow,
    test_preview_matches_written_bytes,
    test_malformed_state_corrupt_json,
    test_malformed_state_empty_dir,
    test_malformed_state_no_graphsmith_dir,
    test_aggregate_only_mode,
    test_cli_usage_on_bad_args,
    test_require_api_default_outpath,
    test_selftest_via_require,
    test_package_json_secrets_redacted,
    test_nested_counter_secret_redacted,
    test_detail_mode_events_are_safe,
    test_aggregate_counters_correct,
    test_scope_declarations,
    test_report_metadata,
    test_two_exports_consistent,
    test_secret_in_value_fields_redacted,
    test_by_code_key_not_redacted,
    test_cli_selftest,
  ];

  for (const t of tests) {
    try {
      t();
    } catch (e) {
      process.stderr.write("FATAL UNHANDLED in test: " + e.message + "\n" + (e.stack || "") + "\n");
      failCount++;
    }
  }

  const passCount = results.filter(r => r.status === "PASS").length;
  const skipCount = results.filter(r => r.status === "SKIPPED").length;

  process.stdout.write("\n=== Results: " + results.length + " tests ===\n");
  process.stdout.write("PASS: " + passCount + "  FAIL: " + failCount + "  SKIPPED: " + skipCount + "\n");

  process.exitCode = failCount > 0 ? 1 : 0;
}

main();