#!/usr/bin/env node
/* GraphSmith diagnostics.js — Phase D (I4, the no-telemetry-ever boundary).
 * Zero-dep CJS, Node >= 18.
 *
 * `graphsmith diagnostics export`: a LOCAL-ONLY report generator, built to
 * help a human file an issue without hand-collecting logs. Plan Section 6,
 * verbatim: "GraphSmith sends NO telemetry, learned state, artifacts, or
 * diagnostics to maintainers or any upstream service, automatically, EVER."
 * and "diagnostics export: local-only report generation with preview +
 * redaction, aggregate counters by default, raw prompts EXCLUDED, ZERO
 * upload code, and a warning that issue trackers are PUBLIC."
 *
 * This file reads ONLY typed aggregate counters — the run registry, alpha
 * ledger, rejected buffer, rollback families, window state, and the
 * compiler's own stats/proposer-view files. events-proposer.jsonl is
 * already alias + closed-enum + number ONLY, per contract 07 (no raw
 * producer strings ever reach it). This file never reads:
 *   - .graphsmith/harvest/events-evidence.jsonl (the alias -> real value
 *     map — REAL values, never for export)
 *   - anything under .graphsmith/evolvable/ (prompts, learned-rule bodies)
 *   - gate3 packets, run.jsonl producer logs, or any other raw artifact
 * Every value that reaches the report is still passed through F16
 * redaction (scripts/migrate.js's redactEvidenceRecord, reused here — not
 * re-implemented) before preview or write, as defense in depth.
 *
 * Egress: this file performs no outbound data transfer of any kind. It
 * does not open sockets, resolve names, or speak any wire protocol; the
 * only I/O is local filesystem reads/writes under the project root.
 * --selftest proves this two ways: (1) every module this file loads is
 * checked against a short allowlist of local, filesystem-only built-ins —
 * so anything else this file might ever come to require is caught by
 * construction, not by guessing a blacklist; (2) the file is scanned for
 * the one relevant call-shape that needs no module load at all (the
 * runtime's built-in outbound-request global), using a pattern built at
 * runtime from split string fragments so this very check cannot pass by
 * accident (its own source text never spells the target contiguously).
 *
 * `--selftest` proves: a planted secret is [REDACTED] in the written
 * file; this file's own source contains zero disallowed requires and zero
 * disallowed call-shapes; a planted raw prompt and a planted evidence-map
 * real value never reach the export (by construction — those files are
 * never opened); the preview text is produced, and is byte-identical to
 * what gets written, strictly before any write happens; a write only
 * happens with explicit --yes; and the public-tracker warning text is
 * present in the preview. No clock/random value is used in any decision
 * path — only as a `generated_at` metadata timestamp. */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const migrateLib = require("./migrate.js");

const SCHEMA_VERSION = "1.0";

/* ---------------------------------------------------------------------------
 * I4 egress proof: allowlisted requires + a runtime-built pattern for the
 * one no-require outbound-request global. See header comment for why the
 * patterns below are built the way they are (self-scan safety).
 * ------------------------------------------------------------------------- */

const NETWORK_MODULE_NAMES = new Set([
  "http", "https", "http2", "net", "dns", "dns/promises", "tls", "dgram", "child_process",
  "node:http", "node:https", "node:http2", "node:net", "node:dns", "node:dns/promises",
  "node:tls", "node:dgram", "node:child_process",
]);

const ALLOWED_REQUIRE_MODULES = new Set(["fs", "path", "os", "./migrate.js"]);

const REQUIRE_CALL_RE = /require\(\s*['"]([^'"]+)['"]\s*\)/g;

/* Built from split fragments on purpose: the contiguous identifier never
 * appears as literal text in this file, so scanning this file's own source
 * cannot trivially "pass" just because the detector mentions its target. */
const OUTBOUND_REQUEST_GLOBAL = "fe" + "tch";
const OUTBOUND_REQUEST_CALL_RE = new RegExp("\\b" + OUTBOUND_REQUEST_GLOBAL + "\\s*\\(");

function extractRequiredModules(sourceText) {
  const mods = [];
  REQUIRE_CALL_RE.lastIndex = 0;
  let match;
  while ((match = REQUIRE_CALL_RE.exec(sourceText)) !== null) mods.push(match[1]);
  return mods;
}

function scanSourceForNetworkAPIs(sourceText) {
  const findings = [];
  for (const mod of extractRequiredModules(sourceText)) {
    if (NETWORK_MODULE_NAMES.has(mod)) findings.push({ kind: "banned-require", module: mod });
    else if (!ALLOWED_REQUIRE_MODULES.has(mod)) findings.push({ kind: "unlisted-require", module: mod });
  }
  if (OUTBOUND_REQUEST_CALL_RE.test(sourceText)) findings.push({ kind: "banned-api-usage", api: "global-outbound-request" });
  return findings;
}

/* ---------------------------------------------------------------------------
 * Safe readers — data ONLY, never evaluated, ENOENT tolerant
 * ------------------------------------------------------------------------- */

function readTextSafe(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}

function readJsonSafe(filePath) {
  const raw = readTextSafe(filePath);
  if (raw === null || !raw.trim()) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function readJsonlSafe(filePath) {
  const raw = readTextSafe(filePath);
  if (raw === null) return [];
  return raw
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter((record) => record !== null);
}

function safeInt(value) {
  return Number.isSafeInteger(value) ? value : 0;
}

/* ---------------------------------------------------------------------------
 * Aggregate summarizers — counts and closed enums ONLY
 * ------------------------------------------------------------------------- */

function readPackageMeta(projectRoot) {
  const pkg = readJsonSafe(path.join(projectRoot, "package.json"));
  return {
    name: pkg && typeof pkg.name === "string" ? pkg.name : "unknown",
    version: pkg && typeof pkg.version === "string" ? pkg.version : "unknown",
  };
}

function summarizeWindow(win) {
  if (!win || typeof win !== "object") {
    return { state: "NO_WINDOW", flag: false, has_window: false, slot_count: 0, active: 0 };
  }
  return {
    state: typeof win.state === "string" ? win.state : "unknown",
    flag: win.flag === true,
    has_window: !!win.window,
    slot_count: win.window && Array.isArray(win.window.slots) ? win.window.slots.length : 0,
    active: win.window && Number.isSafeInteger(win.window.active) ? win.window.active : 0,
  };
}

function summarizeRegistry(records) {
  const counts = { registered: 0, heartbeat: 0, deregistered: 0, expired: 0, unknown: 0 };
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const t = record.record_type;
    if (t === "REGISTERED") counts.registered++;
    else if (t === "HEARTBEAT") counts.heartbeat++;
    else if (t === "DEREGISTERED") counts.deregistered++;
    else if (t === "EXPIRED") counts.expired++;
    else counts.unknown++;
  }
  return counts;
}

function summarizeAlpha(records) {
  let reserved = 0;
  let completed = 0;
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    if (record.record_type === "RESERVED") reserved++;
    else if (record.record_type === "COMPLETED") completed++;
  }
  return { reserved, completed };
}

function summarizeRollback(records) {
  const acknowledged = new Set();
  for (const record of records) {
    if (record && record.record_type === "HUMAN_ACK" && typeof record.fingerprint === "string") {
      acknowledged.add(record.fingerprint);
    }
  }
  let recorded = 0;
  let unacknowledged = 0;
  for (const record of records) {
    if (record && record.record_type === "ROLLBACK_RECORDED" && typeof record.fingerprint === "string") {
      recorded++;
      if (!acknowledged.has(record.fingerprint)) unacknowledged++;
    }
  }
  return { recorded, unacknowledged };
}

function summarizeCompilerStats(records) {
  if (records.length === 0) return null;
  const last = records[records.length - 1];
  if (!last || typeof last !== "object") return null;
  return {
    total_events: safeInt(last.total_events),
    skipped: safeInt(last.skipped),
    quarantined: safeInt(last.quarantined),
    dropped_refs: safeInt(last.dropped_refs),
    rejected: safeInt(last.rejected),
    harvest_valid: last.harvest_valid === true,
    run_count: safeInt(last.run_count),
    broken_runs: safeInt(last.broken_runs),
  };
}

/* Closed per-type code enum, mirrored from event-compiler.js's TYPE_CODES
 * (the same lists watcher.js validates against). Duplicated as a local
 * frozen constant rather than require()d, because event-compiler.js is not
 * on this file's require allowlist and importing it would (correctly) trip
 * the I4 egress self-scan. KNOWN_EVENT_TYPES is derived from its keys so the
 * two can never drift apart. */
const TYPE_CODES = Object.freeze({
  run_halt:           ["unresolved_side_effect", "out_of_memory", "signal_termination", "watchdog_timeout", "orphaned_lock", "budget_exhausted", "unknown_halt"],
  budget_breach:      ["max_wall_time", "max_token_count", "max_api_calls", "max_step_execution", "max_memory", "max_cost"],
  tripwire:           ["unexpected_output_schema", "production_api_call", "file_access_outside_boundary", "network_access", "privilege_escalation", "env_access"],
  retry_exhausted:    ["max_retries_step", "max_retries_run"],
  step_failure:       ["worker_error", "module_not_found", "worker_timeout", "invalid_output", "side_effect_mismatch", "unhandled_exception"],
  corrupt_checkpoint: ["unreadable_file", "schema_mismatch", "hash_mismatch", "truncated_file", "missing_file"],
  lock_contention:    ["deadlock_detected", "lease_expired", "lock_file_corrupt", "owner_mismatch", "stale_lock"],
  scenario_fail:      ["invariant_violation", "expected_outcome_mismatch", "scenario_crash", "infra_fault", "workflow_fault"],
  human_correction:   ["gate3_prompt_adjustment", "data_correction", "config_update", "manual_override", "knob_tune"],
  adoption:           ["doc_change", "knob_change", "prompt_change", "code_change", "config_only", "migration"],
  rollback:           ["hard_failure", "human_decision", "pre_authorized", "flagged", "abandoned_window"],
});

const KNOWN_EVENT_TYPES = Object.keys(TYPE_CODES);

/* Any code not in its type's closed enum is bucketed under this single safe
 * key — the untrusted raw string is NEVER emitted as an object key (object
 * keys are not reached by value redaction). */
const INVALID_CODE_KEY = "invalid_code";

function summarizeEventsByType(records) {
  const byType = {};
  for (const type of KNOWN_EVENT_TYPES) byType[type] = { count: 0, by_code: {} };
  let otherCount = 0;
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const type = typeof record.type === "string" ? record.type : null;
    if (!type || !byType[type]) {
      otherCount++;
      continue;
    }
    byType[type].count++;
    /* Validate code against its type's closed enum BEFORE using it as a key.
     * A poisoned/malformed code from the untrusted events-proposer.jsonl (B4)
     * must never survive verbatim as an aggregate key. */
    const rawCode = typeof record.code === "string" ? record.code : "";
    const code = TYPE_CODES[type].includes(rawCode) ? rawCode : INVALID_CODE_KEY;
    byType[type].by_code[code] = (byType[type].by_code[code] || 0) + 1;
  }
  return { byType, otherCount };
}

/* Detail mode: aliases + closed enums + numbers ONLY — never raw text.
 *
 * SOURCE IS UNTRUSTED. Every field here originates from
 * .graphsmith/harvest/events-proposer.jsonl, a B4 boundary
 * (contracts/04-trust-boundary-matrix.md): nothing signs it or proves it
 * came from event-compiler.js's compile(). A poisoned or malformed record
 * can smuggle a secret into ANY string field — including the structural
 * identifier fields (code/type/fingerprint/run_ref/step_ref) that would
 * otherwise look like trusted closed enums. So we treat NO key as
 * structurally trusted: every string value of the assembled detail record,
 * regardless of key name, is passed through the same F16 redaction the
 * value fields use (migrate.js redactEvidenceRecord, which walks and
 * redacts every nested string). This is defense in depth local to the
 * detail path — it does not rely on the outer report-wide redaction pass
 * remembering to cover detail. Redaction is idempotent, so the later
 * report-wide pass over the same values is harmless.
 *
 * evidence_ref stays an ALIAS only (the events-evidence.jsonl real-value
 * map is never opened by this file); like every other field its alias is
 * still redaction-eligible here. */
function buildDetailEvents(records) {
  return records
    .map((record) => {
      if (!record || typeof record !== "object") return null;
      const detail = {
        seq: Number.isSafeInteger(record.seq) ? record.seq : null,
        type: typeof record.type === "string" ? record.type : null,
        code: typeof record.code === "string" ? record.code : null,
        run_ref: typeof record.run_ref === "string" ? record.run_ref : null,
        step_ref: typeof record.step_ref === "string" ? record.step_ref : null,
        evidence_ref: typeof record.evidence_ref === "string" ? record.evidence_ref : null,
        fingerprint: typeof record.fingerprint === "string" ? record.fingerprint : null,
        counters: record.counters && typeof record.counters === "object" ? record.counters : {},
      };
      /* Redact EVERY string value regardless of key — no structural-field
       * allowlist, because the source is untrusted. */
      return migrateLib.redactEvidenceRecord(detail);
    })
    .filter(Boolean);
}

/* ---------------------------------------------------------------------------
 * Report assembly
 * ------------------------------------------------------------------------- */

function buildReport(projectRoot, opts = {}) {
  const root = path.resolve(projectRoot || ".");
  const stateDir = path.join(root, ".graphsmith", "state");
  const harvestDir = path.join(root, ".graphsmith", "harvest");

  const windowRecord = readJsonSafe(path.join(stateDir, "window.json"));
  const registryRecords = readJsonlSafe(path.join(stateDir, "run-registry.jsonl"));
  const alphaRecords = readJsonlSafe(path.join(stateDir, "alpha-ledger.jsonl"));
  const rejectedRecords = readJsonlSafe(path.join(stateDir, "rejected-buffer.jsonl"));
  const rollbackRecords = readJsonlSafe(path.join(stateDir, "rollback-families.jsonl"));
  const stateSchemaVersion = (readTextSafe(path.join(stateDir, "schema.version")) || "").trim() || "unknown";

  const compilerStatsRecords = readJsonlSafe(path.join(harvestDir, "compiler-stats.jsonl"));
  const proposerRecords = readJsonlSafe(path.join(harvestDir, "events-proposer.jsonl"));

  const eventSummary = summarizeEventsByType(proposerRecords);
  const pkg = readPackageMeta(root);

  const report = {
    schema_version: SCHEMA_VERSION,
    report_type: "graphsmith-diagnostics-export",
    generated_at: new Date().toISOString(),
    scope: {
      raw_prompts_included: false,
      learned_rule_bodies_included: false,
      evidence_map_real_values_included: false,
      secrets_included: false,
      redaction_applied: true,
      mode: opts.includeDetail ? "aggregate+detail" : "aggregate",
    },
    platform: {
      node_version: process.version,
      os_platform: os.platform(),
      os_arch: os.arch(),
      os_type: os.type(),
      os_release: os.release(),
    },
    component_versions: {
      package_name: pkg.name,
      package_version: pkg.version,
      state_schema_version: stateSchemaVersion,
      diagnostics_schema_version: SCHEMA_VERSION,
    },
    verifier_profile: {
      checked: false,
      note: "diagnostics.js does not itself invoke the verifier (contract 10: never claim a check that was not run). For a live capability profile run scripts/verify.js separately with its --profiles flag.",
    },
    state_summary: {
      window: summarizeWindow(windowRecord),
      run_registry: summarizeRegistry(registryRecords),
      alpha_ledger: summarizeAlpha(alphaRecords),
      rejected_buffer_count: rejectedRecords.length,
      rollback_families: summarizeRollback(rollbackRecords),
    },
    event_counters: {
      compiler_stats: summarizeCompilerStats(compilerStatsRecords),
      total_proposer_records: proposerRecords.length,
      other_type_count: eventSummary.otherCount,
      by_type: eventSummary.byType,
    },
  };

  if (opts.includeDetail) {
    report.detail = {
      note: "Aggregate-safe detail: aliases, closed enums, and counters only (contract 07 events-proposer.jsonl shape). Never raw prompts or evidence-map real values.",
      events: buildDetailEvents(proposerRecords),
    };
  }

  return report;
}

/* F16 redaction — reused, not re-implemented (scripts/migrate.js is the
 * sole owner of the pattern list; this file only calls its export). */
function redactReport(report) {
  return migrateLib.redactEvidenceRecord(report);
}

function serializeReport(report) {
  return JSON.stringify(report, null, 2) + "\n";
}

/* ---------------------------------------------------------------------------
 * Preview + explicit consent + local-only write
 * ------------------------------------------------------------------------- */

const PUBLIC_TRACKER_WARNING = [
  "=".repeat(72),
  "WARNING: issue trackers are PUBLIC -- review this before posting.",
  "This report is written to LOCAL disk only. GraphSmith never uploads,",
  "posts, or transmits it anywhere, automatically or otherwise. You decide",
  "if, where, and with whom to share it.",
  "=".repeat(72),
].join("\n");

function defaultOutPath(root) {
  return path.join(root, ".graphsmith", "diagnostics", "diagnostics-report.json");
}

function exportDiagnostics(projectRoot, opts = {}) {
  const root = path.resolve(projectRoot || ".");
  const rawReport = buildReport(root, opts);
  const redacted = redactReport(rawReport);
  const previewText = serializeReport(redacted);
  const outPath = path.resolve(opts.outPath || defaultOutPath(root));
  const log = typeof opts.log === "function" ? opts.log : (line) => process.stdout.write(`${line}\n`);

  /* Preview is built and shown BEFORE any write happens, and BEFORE the
   * consent check is even evaluated — the human sees exactly what would be
   * written whether or not they consent. */
  log(PUBLIC_TRACKER_WARNING);
  log("");
  log(`PREVIEW of ${outPath} (nothing written yet):`);
  log(previewText);

  if (!opts.confirmWrite) {
    log("Not written. Re-run with --yes to write this file to local disk.");
    return { report: redacted, previewText, written: false, path: null };
  }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const tmp = `${outPath}.tmp-${process.pid}`;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, previewText);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, outPath);

  log(`Written: ${outPath}`);
  log("Reminder: issue trackers are PUBLIC. Review the file above before attaching or posting it anywhere.");

  return { report: redacted, previewText, written: true, path: outPath };
}

/* ---------------------------------------------------------------------------
 * Selftest
 * ------------------------------------------------------------------------- */

function selftest() {
  const tests = [];
  const errors = [];

  function check(name, condition, detail) {
    if (condition) {
      tests.push({ name, status: "pass" });
    } else {
      tests.push({ name, status: "fail", detail: detail === undefined ? null : String(detail) });
      errors.push(`FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
    }
  }

  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-diagnostics-"));

  try {
    /* --- PROOF: this file's own source contains zero disallowed requires
     * and zero disallowed call-shapes (the I4 egress guarantee). --- */
    const selfSource = fs.readFileSync(__filename, "utf8");
    const findings = scanSourceForNetworkAPIs(selfSource);
    check(
      "source-self-scan-zero-network-apis",
      findings.length === 0,
      findings.length ? JSON.stringify(findings) : undefined
    );

    /* --- Fixture project --- */
    const root = path.join(base, "project");
    const stateDir = path.join(root, ".graphsmith", "state");
    const harvestDir = path.join(root, ".graphsmith", "harvest");
    const evolvableDir = path.join(root, ".graphsmith", "evolvable", "active");
    fs.mkdirSync(stateDir, { recursive: true });
    fs.mkdirSync(harvestDir, { recursive: true });
    fs.mkdirSync(evolvableDir, { recursive: true });

    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "fixture-project", version: "0.2.0" }));
    fs.writeFileSync(path.join(stateDir, "schema.version"), "1.1\n");
    fs.writeFileSync(
      path.join(stateDir, "window.json"),
      JSON.stringify({ schema_version: "1.0", state_rev: 3, state: "CLOSED_PASS", flag: false, window: null })
    );
    fs.writeFileSync(
      path.join(stateDir, "run-registry.jsonl"),
      [
        { record_type: "REGISTERED", run_id: "run-1", tree_id: "tree-1" },
        { record_type: "HEARTBEAT", run_id: "run-1" },
        { record_type: "DEREGISTERED", run_id: "run-1" },
        { record_type: "REGISTERED", run_id: "run-2", tree_id: "tree-1" },
        { record_type: "EXPIRED", run_id: "run-2" },
      ]
        .map((r) => JSON.stringify(r))
        .join("\n") + "\n"
    );
    fs.writeFileSync(
      path.join(stateDir, "alpha-ledger.jsonl"),
      [{ record_type: "RESERVED", alpha_slot: 1 }, { record_type: "COMPLETED", reservation_id: "r1" }]
        .map((r) => JSON.stringify(r))
        .join("\n") + "\n"
    );
    fs.writeFileSync(
      path.join(stateDir, "rejected-buffer.jsonl"),
      [{ record_type: "REJECTED", fingerprint: "fp-1" }].map((r) => JSON.stringify(r)).join("\n") + "\n"
    );
    fs.writeFileSync(
      path.join(stateDir, "rollback-families.jsonl"),
      [{ record_type: "ROLLBACK_RECORDED", fingerprint: "fp-rb-1" }].map((r) => JSON.stringify(r)).join("\n") + "\n"
    );
    fs.writeFileSync(
      path.join(harvestDir, "compiler-stats.jsonl"),
      JSON.stringify({
        record_type: "compiler_stats", total_events: 4, skipped: 0, quarantined: 1,
        dropped_refs: 0, rejected: 0, harvest_valid: true, run_count: 2, broken_runs: 0,
      }) + "\n"
    );

    /* PLANTED SECRET inside a normally-safe alias field (step_ref), to
     * prove the F16 redaction layer catches it even if it ever slipped in
     * upstream — the real end-to-end pipeline, not a unit-tested helper. */
    const plantedSecret = "sk-plantedSECRETvalue1234567890abcdef";

    /* PLANTED STRUCTURAL-FIELD SECRETS: a poisoned harvest record whose
     * "structural" identifier fields (code / fingerprint / run_ref /
     * step_ref) each carry a real, pattern-matching secret. These fields
     * used to look like trusted closed enums; because events-proposer.jsonl
     * is an untrusted B4 source, they must be redacted like any value field.
     * The probe uses an UNKNOWN event type so the code secret is isolated to
     * the detail path (a known type would surface code as an aggregate
     * by_code object KEY — a separate documented aggregate limitation, out
     * of scope for this detail-redaction proof). */
    const detailCodeSecret = "AKIA1234567890ABCDEF"; /* aws-key */
    const detailFpSecret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.sigABCDEF1234567890"; /* jwt */
    const detailRunSecret = "ghp_selftestRUNref1234567890abcdef"; /* github-token */
    const detailStepSecret = "sk-selftestSTEPref1234567890"; /* opaque-secret-prefix */

    /* PLANTED AGGREGATE-KEY SECRET: a poisoned `code` on a KNOWN event type.
     * `code` is used as an object KEY in by_code; object keys are not reached
     * by value redaction, so an out-of-enum code must be bucketed under a
     * single safe key ("invalid_code") and never emitted verbatim. Uses type
     * step_failure (its count is not asserted elsewhere in this selftest). */
    const aggCodeSecret = "AKIA9999888877776666"; /* aws-key, not in any code enum */

    fs.writeFileSync(
      path.join(harvestDir, "events-proposer.jsonl"),
      [
        { seq: 0, type: "run_halt", code: "unknown_halt", run_ref: "r01", step_ref: "s00", evidence_ref: "p01", fingerprint: "fp01", counters: { retries_attempted: 0, steps_completed: 1, steps_remaining: 0 } },
        { seq: 1, type: "tripwire", code: "network_access", run_ref: "r01", step_ref: "s01", evidence_ref: "p02", fingerprint: "fp02", counters: { tripwire_index: 0, total_tripwires: 1 } },
        { seq: 2, type: "budget_breach", code: "max_wall_time", run_ref: "r02", step_ref: plantedSecret, evidence_ref: "p03", fingerprint: "fp03", counters: { elapsed_ms: 10, budget_ms: 5, overshoot_ms: 5 } },
        { seq: 3, type: "corrupt_detail_probe", code: detailCodeSecret, run_ref: detailRunSecret, step_ref: detailStepSecret, evidence_ref: "p04", fingerprint: detailFpSecret, counters: {} },
        { seq: 4, type: "step_failure", code: aggCodeSecret, run_ref: "r05", step_ref: "s05", evidence_ref: "p05", fingerprint: "fp05", counters: {} },
      ]
        .map((r) => JSON.stringify(r))
        .join("\n") + "\n"
    );

    /* PLANTED RAW PROMPT and PLANTED EVIDENCE-MAP REAL VALUE, in files
     * diagnostics.js must NEVER open. */
    const rawPromptCanary = "RAW_PROMPT_CANARY__manager_worker_instructions__9f8e7d6c5b4a";
    fs.writeFileSync(path.join(evolvableDir, "manager.md"), `SYSTEM PROMPT for manager worker.\n${rawPromptCanary}\n`);
    fs.writeFileSync(
      path.join(harvestDir, "events-evidence.jsonl"),
      JSON.stringify({
        record_type: "evidence_map_entry", alias: "r01", alias_type: "run_ref",
        real_value: "real-run-id-with-api_key=sk-evmapSECRET0987654321zzzzzzz",
      }) + "\n"
    );

    const outPath = path.join(root, ".graphsmith", "diagnostics", "diagnostics-report.json");

    /* --- Export WITHOUT --yes: preview only, nothing written --- */
    const logsNoWrite = [];
    const resultNoWrite = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: false,
      outPath,
      log: (line) => logsNoWrite.push(line),
    });
    check(
      "no-write-without-consent",
      resultNoWrite.written === false && !fs.existsSync(outPath),
      `written=${resultNoWrite.written} exists=${fs.existsSync(outPath)}`
    );
    check(
      "preview-available-without-write",
      typeof resultNoWrite.previewText === "string" && resultNoWrite.previewText.length > 0
    );

    const noWriteJoined = logsNoWrite.join("\n");
    check(
      "public-tracker-warning-present",
      /issue trackers are PUBLIC/i.test(noWriteJoined) && /review this before posting/i.test(noWriteJoined),
      "warning text missing from preview output"
    );

    /* --- Export WITH --yes: preview must be logged before the write --- */
    const logsWrite = [];
    const resultWrite = exportDiagnostics(root, {
      includeDetail: true,
      confirmWrite: true,
      outPath,
      log: (line) => logsWrite.push(line),
    });

    const previewLineIdx = logsWrite.findIndex((l) => l.includes('"schema_version"'));
    const writtenLineIdx = logsWrite.findIndex((l) => l.startsWith("Written:"));
    check(
      "preview-shown-before-write",
      previewLineIdx !== -1 && writtenLineIdx !== -1 && previewLineIdx < writtenLineIdx,
      `previewIdx=${previewLineIdx} writtenIdx=${writtenLineIdx}`
    );
    check("file-written-with-consent", resultWrite.written === true && fs.existsSync(outPath));

    const fileContent = fs.readFileSync(outPath, "utf8");
    check(
      "preview-matches-written-file-exactly",
      fileContent === resultWrite.previewText,
      "preview text did not match written file byte-for-byte"
    );

    /* --- PROOF: planted secret redacted, does not survive --- */
    check(
      "planted-secret-redacted-in-file",
      !fileContent.includes(plantedSecret) && fileContent.includes("[REDACTED]"),
      `contains_secret=${fileContent.includes(plantedSecret)}`
    );
    check("planted-secret-redacted-in-preview", !resultWrite.previewText.includes(plantedSecret));
    check(
      "planted-secret-redacted-in-report-object",
      JSON.stringify(resultWrite.report).indexOf(plantedSecret) === -1
    );

    /* --- PROOF: structural identifier fields of an untrusted detail record
     * (code / fingerprint / run_ref / step_ref) are redacted, not trusted
     * verbatim. None of the planted secrets survive into the written file. --- */
    check(
      "detail-structural-fields-secrets-do-not-survive",
      !fileContent.includes(detailCodeSecret) &&
        !fileContent.includes(detailFpSecret) &&
        !fileContent.includes(detailRunSecret) &&
        !fileContent.includes(detailStepSecret),
      `code=${fileContent.includes(detailCodeSecret)} fp=${fileContent.includes(detailFpSecret)} run=${fileContent.includes(detailRunSecret)} step=${fileContent.includes(detailStepSecret)}`
    );

    const probeEvent =
      resultWrite.report.detail &&
      Array.isArray(resultWrite.report.detail.events)
        ? resultWrite.report.detail.events.find((e) => e && e.seq === 3)
        : null;
    check(
      "detail-structural-fields-replaced-with-redacted-token",
      !!probeEvent &&
        probeEvent.code === "[REDACTED]" &&
        probeEvent.fingerprint === "[REDACTED]" &&
        probeEvent.run_ref === "[REDACTED]" &&
        probeEvent.step_ref === "[REDACTED]",
      probeEvent ? JSON.stringify(probeEvent) : "probe detail record (seq=3) missing"
    );

    /* --- PROOF: raw prompt / evidence-map real values never exported --- */
    check(
      "raw-prompt-canary-excluded",
      !fileContent.includes(rawPromptCanary) && !fileContent.includes("SYSTEM PROMPT"),
      "raw prompt content leaked into diagnostics export"
    );
    check(
      "evidence-map-real-value-excluded",
      !fileContent.includes("real-run-id-with-api_key"),
      "events-evidence.jsonl real_value leaked into diagnostics export"
    );
    check(
      "scope-declares-no-raw-prompts",
      resultWrite.report.scope && resultWrite.report.scope.raw_prompts_included === false
    );

    /* --- PROOF: aggregate counters are computed correctly --- */
    check(
      "aggregate-counters-run-registry",
      resultWrite.report.state_summary.run_registry.registered === 2 &&
        resultWrite.report.state_summary.run_registry.expired === 1
    );
    check(
      "aggregate-counters-event-tallies",
      resultWrite.report.event_counters.by_type.tripwire.count === 1 &&
        resultWrite.report.event_counters.by_type.run_halt.count === 1 &&
        resultWrite.report.event_counters.by_type.budget_breach.count === 1
    );

    /* --- PROOF: default (no --include-detail) mode has no detail field --- */
    const resultDefault = exportDiagnostics(root, { confirmWrite: false, outPath, log: () => {} });
    check("default-mode-no-detail-field", resultDefault.report.detail === undefined);

    /* --- PROOF: a poisoned `code` on a known event type is NOT emitted as a
     * verbatim aggregate object key in DEFAULT (aggregate) mode — it is
     * bucketed under "invalid_code". Object keys are not reached by value
     * redaction, so this must be enforced by enum validation, not redaction. --- */
    const aggByCode =
      resultDefault.report.event_counters &&
      resultDefault.report.event_counters.by_type &&
      resultDefault.report.event_counters.by_type.step_failure
        ? resultDefault.report.event_counters.by_type.step_failure.by_code
        : {};
    check(
      "aggregate-poisoned-code-not-emitted-as-key",
      Object.prototype.hasOwnProperty.call(aggByCode, "invalid_code") &&
        !Object.prototype.hasOwnProperty.call(aggByCode, aggCodeSecret) &&
        JSON.stringify(resultDefault.report).indexOf(aggCodeSecret) === -1,
      `by_code_keys=${JSON.stringify(Object.keys(aggByCode))}`
    );

    return {
      schema_version: SCHEMA_VERSION,
      status: errors.length === 0 ? "pass" : "fail",
      tests,
      errors,
      exitCode: errors.length === 0 ? 0 : 1,
    };
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

function printUsage() {
  process.stderr.write(
    "Usage: node scripts/diagnostics.js export [--project-root <dir>] [--out <path>] [--include-detail] [--yes]\n" +
      "       node scripts/diagnostics.js --selftest\n"
  );
}

if (require.main === module) {
  const argv = process.argv.slice(2);

  if (argv.includes("--selftest")) {
    const report = selftest();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exit(report.exitCode);
  } else if (argv[0] === "export") {
    const rest = argv.slice(1);
    const projectRootIdx = rest.indexOf("--project-root");
    const outIdx = rest.indexOf("--out");
    const opts = {
      includeDetail: rest.includes("--include-detail"),
      confirmWrite: rest.includes("--yes"),
      outPath: outIdx >= 0 ? rest[outIdx + 1] : null,
    };
    const projectRoot = projectRootIdx >= 0 ? rest[projectRootIdx + 1] : ".";
    try {
      exportDiagnostics(projectRoot, opts);
      process.exit(0);
    } catch (err) {
      process.stderr.write(`Error: ${err && err.message ? err.message : String(err)}\n`);
      process.exit(1);
    }
  } else {
    printUsage();
    process.exit(2);
  }
}

/* ---------------------------------------------------------------------------
 * Exports
 * ------------------------------------------------------------------------- */

module.exports = {
  SCHEMA_VERSION,
  buildReport,
  redactReport,
  serializeReport,
  exportDiagnostics,
  scanSourceForNetworkAPIs,
  PUBLIC_TRACKER_WARNING,
  selftest,
};
