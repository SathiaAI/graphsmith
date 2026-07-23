#!/usr/bin/env node
/* GraphSmith migrate.js — Phase C (migration API). Zero-dep CJS, Node >= 18.
 *
 * .graphsmith/ state migration API with schema_version tracking, forward
 * migration path, and F16 redaction (no secret survives into evidence.jsonl).
 *
 * --selftest: schema migrate round-trip, redaction no-secret proof.
 * No LLM/clock/random in decision paths. */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

const CURRENT_SCHEMA_VERSION = "1.0";
const TARGET_SCHEMA_VERSION = "1.1";

const STATE_FILES = [
  "window.json",
  "run-registry.jsonl",
  "run-anchors.jsonl",
  "alpha-ledger.jsonl",
  "rejected-buffer.jsonl",
  "rollback-families.jsonl",
  "project.manifest.json",
  "adoption-log.jsonl",
  "journal.jsonl",
];

const EVIDENCE_FILES = [
  "events-evidence.jsonl",
  "compiler-stats.jsonl",
];

const HARVEST_FILES = [
  "events-proposer.jsonl",
];

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

/* ---------------------------------------------------------------------------
 * F16 redaction patterns
 * ------------------------------------------------------------------------- */

const SECRET_PATTERNS = [
  { name: "api-key", pattern: /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{20,}['"]?/gi },
  { name: "password", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?/gi },
  { name: "email", pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { name: "credit-card", pattern: /\b(?:\d[ -]*?){13,16}\b/g },
  { name: "private-key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: "aws-key", pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g },
  { name: "github-token", pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}/g },
  { name: "bearer-token", pattern: /bearer\s*:?\s+[A-Za-z0-9_\-\.]{15,}/gi },
  { name: "jwt", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: "connection-string", pattern: /(?:mongodb|postgres|mysql|redis|sqlite):\/\/[^\s'"]{10,}/gi },
  { name: "oauth-secret", pattern: /(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{16,}['"]?/gi },
  { name: "private-ip", pattern: /\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g },
  { name: "generic-token", pattern: /(?:token|key|secret)\s*[:=]\s*['"]?[A-Za-z0-9+/_=-]{20,}['"]?/gi },
  { name: "opaque-secret-prefix", pattern: /\b(?:sk|pk|rk|ak)[_-][A-Za-z0-9][A-Za-z0-9_-]{10,}\b/g },
];

function redactText(content) {
  let result = content;
  for (const rule of SECRET_PATTERNS) {
    result = result.replace(rule.pattern, "[REDACTED]");
  }
  return result;
}

function redactEvidenceRecord(record) {
  if (typeof record === "string") return redactText(record);
  if (record === null || record === undefined) return record;
  if (typeof record !== "object") return record;

  if (Array.isArray(record)) {
    return record.map(redactEvidenceRecord);
  }

  const redacted = {};
  for (const key of Object.keys(record)) {
    const value = record[key];
    if (typeof value === "string") {
      redacted[key] = redactText(value);
    } else if (typeof value === "object" && value !== null) {
      redacted[key] = redactEvidenceRecord(value);
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}

/* ---------------------------------------------------------------------------
 * Migration engine
 * ------------------------------------------------------------------------- */

function locations(projectRoot) {
  const state = path.join(projectRoot, ".graphsmith", "state");
  const harvest = path.join(projectRoot, ".graphsmith", "harvest");
  return { state, harvest };
}

function readStateVersion(stateDir) {
  const versionFile = path.join(stateDir, "schema.version");
  try {
    return fs.readFileSync(versionFile, "utf8").trim();
  } catch (err) {
    if (err.code === "ENOENT") return CURRENT_SCHEMA_VERSION;
    throw err;
  }
}

function writeStateVersion(stateDir, version) {
  const versionFile = path.join(stateDir, "schema.version");
  fs.mkdirSync(stateDir, { recursive: true });
  const content = version + "\n";
  const tmp = versionFile + ".tmp-" + process.pid;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, versionFile);
  try {
    const dirFd = fs.openSync(stateDir, "r");
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
  } catch (e) {
    if (process.platform !== "win32" && !["EINVAL", "EISDIR", "EPERM"].includes(e.code)) throw e;
  }
}

function readJsonlSafe(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    if (!raw.trim()) return [];
    return raw.split("\n").filter(Boolean).map(function(line) {
      try { return JSON.parse(line); }
      catch (e) { return null; }
    }).filter(Boolean);
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
}

function readJsonSafe(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    if (!raw.trim()) return null;
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}

function writeJsonlSafe(filePath, records) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const content = records.map(function(r) { return JSON.stringify(r); }).join("\n");
  const writeContent = content ? content + "\n" : "";
  const tmp = filePath + ".tmp-" + process.pid;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, writeContent);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
}

function writeJsonSafe(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const content = JSON.stringify(data, null, 2) + "\n";
  const tmp = filePath + ".tmp-" + process.pid;
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
}

/* ---------------------------------------------------------------------------
 * Migration: 1.0 → 1.1
 *   - Add schema_version bump
 *   - Apply F16 redaction to all evidence/harvest files
 * ------------------------------------------------------------------------- */

function migrate1_0_to_1_1(stateDir, harvestDir) {
  const changes = [];

  /* --- F16 redaction: evidence files --- */
  const evidenceFiles = [];
  if (fs.existsSync(harvestDir)) {
    for (const entry of fs.readdirSync(harvestDir)) {
      if (entry.endsWith(".jsonl") || entry.endsWith(".json")) {
        evidenceFiles.push(path.join(harvestDir, entry));
      }
    }
  }

  /* Also check for evidence files in state dir */
  if (fs.existsSync(stateDir)) {
    for (const entry of fs.readdirSync(stateDir)) {
      const fp = path.join(stateDir, entry);
      if (fs.statSync(fp).isFile() && (entry.startsWith("evidence") || entry === "events-evidence.jsonl")) {
        evidenceFiles.push(fp);
      }
    }
  }

  for (const filePath of evidenceFiles) {
    if (!fs.existsSync(filePath)) continue;
    const records = readJsonlSafe(filePath);
    if (records.length === 0) {
      const single = readJsonSafe(filePath);
      if (single === null) continue;
      const redacted = redactEvidenceRecord(single);
      writeJsonSafe(filePath, redacted);
      changes.push({ file: path.basename(filePath), action: "redacted-json", entries: 1 });
    } else {
      const redactedRecords = records.map(redactEvidenceRecord);
      writeJsonlSafe(filePath, redactedRecords);
      changes.push({ file: path.basename(filePath), action: "redacted-jsonl", entries: redactedRecords.length });
    }
  }

  /* --- Bump schema_version --- */
  writeStateVersion(stateDir, TARGET_SCHEMA_VERSION);
  changes.push({ file: "schema.version", action: "bumped", from: CURRENT_SCHEMA_VERSION, to: TARGET_SCHEMA_VERSION });

  return {
    from: CURRENT_SCHEMA_VERSION,
    to: TARGET_SCHEMA_VERSION,
    changes,
  };
}

/* ---------------------------------------------------------------------------
 * Main migrate function
 * ------------------------------------------------------------------------- */

function migrate(projectRoot) {
  const root = path.resolve(projectRoot || ".");
  const locs = locations(root);
  const stateDir = locs.state;
  const harvestDir = locs.harvest;

  fs.mkdirSync(stateDir, { recursive: true });

  const currentVersion = readStateVersion(stateDir);

  if (currentVersion === TARGET_SCHEMA_VERSION) {
    return {
      schema_version: currentVersion,
      migrated: false,
      reason: "already-at-target",
      changes: [],
    };
  }

  /* Future: chain multiple migrations. v0.2.0 has only 1.0 → 1.1 */
  const migrationPath = {
    "1.0": migrate1_0_to_1_1,
  };

  const migrateFn = migrationPath[currentVersion];
  if (!migrateFn) {
    return {
      schema_version: currentVersion,
      migrated: false,
      reason: "no-migration-path",
      supported: Object.keys(migrationPath),
    };
  }

  const result = migrateFn(stateDir, harvestDir);

  return {
    schema_version: TARGET_SCHEMA_VERSION,
    migrated: true,
    from: result.from,
    to: result.to,
    changes: result.changes,
  };
}

/* ---------------------------------------------------------------------------
 * Redaction verification: scan for secrets
 * ------------------------------------------------------------------------- */

function scanForSecrets(content) {
  const findings = [];
  for (const rule of SECRET_PATTERNS) {
    const matches = content.match(rule.pattern);
    if (matches && matches.length > 0) {
      findings.push({ rule: rule.name, count: matches.length, samples: matches.slice(0, 3) });
    }
  }
  return findings;
}

function scanFileForSecrets(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    return { file: path.basename(filePath), findings: scanForSecrets(content) };
  } catch (err) {
    if (err.code === "ENOENT") return { file: path.basename(filePath), findings: [], missing: true };
    return { file: path.basename(filePath), findings: [], error: err.message };
  }
}

/* ---------------------------------------------------------------------------
 * Selftest
 * ------------------------------------------------------------------------- */

function selftest() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-migrate-"));
  const tests = [];
  const errors = [];

  function check(name, condition, detail) {
    if (!condition) {
      errors.push("FAIL: " + name + (detail ? " — " + detail : ""));
      return false;
    }
    tests.push({ name: name, status: "pass" });
    return true;
  }

  try {
    /* --- PROOF 1: Schema migrate round-trip --- */
    {
      const projectRoot = path.join(base, "p1-roundtrip");
      const stateDir = path.join(projectRoot, ".graphsmith", "state");
      const harvestDir = path.join(projectRoot, ".graphsmith", "harvest");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.mkdirSync(harvestDir, { recursive: true });

      writeStateVersion(stateDir, CURRENT_SCHEMA_VERSION);

      const initialVersion = readStateVersion(stateDir);
      check("roundtrip-initial-version-is-1-0", initialVersion === CURRENT_SCHEMA_VERSION,
        "initial version: " + initialVersion);

      const result1 = migrate(projectRoot);

      check("roundtrip-migration-succeeded", result1.migrated === true,
        "migrated: " + result1.migrated);

      check("roundtrip-target-version-is-1-1", result1.schema_version === TARGET_SCHEMA_VERSION,
        "schema_version: " + result1.schema_version);

      const finalVersion = readStateVersion(stateDir);
      check("roundtrip-final-version-matches", finalVersion === TARGET_SCHEMA_VERSION,
        "final version: " + finalVersion);

      const result2 = migrate(projectRoot);
      check("roundtrip-idempotent-no-re-migrate", result2.migrated === false,
        "second migrate should be no-op, migrated=" + result2.migrated);

      check("roundtrip-both-directions-consistent", result1.schema_version === result2.schema_version,
        "version1=" + result1.schema_version + " version2=" + result2.schema_version);
    }

    /* --- PROOF 2: F16 redaction — no secret survives into evidence.jsonl --- */
    {
      const projectRoot = path.join(base, "p2-redact");
      const harvestDir = path.join(projectRoot, ".graphsmith", "harvest");
      fs.mkdirSync(harvestDir, { recursive: true });

      const evidencePath = path.join(harvestDir, "events-evidence.jsonl");
      const secretsInEvidence = [
        { record_type: "evidence", run_id: "test-1", secret: "api_key=sk-abcdefghijklmnopqrstuvwxyz123456" },
        { record_type: "evidence", run_id: "test-2", config: "password=SuperSecret123!@#" },
        { record_type: "evidence", run_id: "test-3", email: "alice@example.com" },
        { record_type: "evidence", run_id: "test-4", token: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab" },
        { record_type: "evidence", run_id: "test-5", key: "AKIAIOSFODNN7EXAMPLE" },
        { record_type: "evidence", run_id: "test-6", conn: "mongodb://admin:password123@db.example.com:27017/mydb" },
        { record_type: "evidence", run_id: "test-7", bearer: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" },
        { record_type: "evidence", run_id: "test-8", secret_field: "Bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" },
        { record_type: "evidence", run_id: "test-9", header: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" },
      ];

      fs.writeFileSync(evidencePath,
        secretsInEvidence.map(function(r) { return JSON.stringify(r); }).join("\n") + "\n");

      const beforeScan = scanFileForSecrets(evidencePath);
      const totalBeforeFindings = beforeScan.findings.reduce(function(sum, f) { return sum + f.count; }, 0);
      check("redaction-secrets-present-before-migration", totalBeforeFindings > 0,
        "found " + totalBeforeFindings + " secret matches before migration");

      const stateDir = path.join(projectRoot, ".graphsmith", "state");
      fs.mkdirSync(stateDir, { recursive: true });
      writeStateVersion(stateDir, CURRENT_SCHEMA_VERSION);

      const migrationResult = migrate(projectRoot);
      check("redaction-migration-completed", migrationResult.migrated === true,
        "migration completed successfully");

      const afterScan = scanFileForSecrets(evidencePath);
      const totalAfterFindings = afterScan.findings.reduce(function(sum, f) { return sum + f.count; }, 0);
      check("redaction-no-secrets-survive-in-evidence-jsonl", totalAfterFindings === 0,
        "found " + totalAfterFindings + " unredacted secrets after migration (must be 0)");

      const afterContent = fs.readFileSync(evidencePath, "utf8");
      const redactionCount = (afterContent.match(/\[REDACTED\]/g) || []).length;
      check("redaction-tokens-present", redactionCount > 0,
        "found " + redactionCount + " [REDACTED] tokens in evidence file");

      /* Verify specific secrets don't survive */
      const specificChecks = [
        "sk-abcdefghijklmnopqrstuvwxyz123456",
        "SuperSecret123!@#",
        "alice@example.com",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab",
        "AKIAIOSFODNN7EXAMPLE",
        "admin:password123",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      ];
      for (const secret of specificChecks) {
        check("redaction-specific-secret-gone-" + secret.substring(0, 20) + "...",
          !afterContent.includes(secret),
          "secret substring must not survive redaction");
      }
    }

    /* --- PROOF 3: Redaction handles nested objects and arrays --- */
    {
      const projectRoot = path.join(base, "p3-nested");
      const harvestDir = path.join(projectRoot, ".graphsmith", "harvest");
      fs.mkdirSync(harvestDir, { recursive: true });

      const evidencePath = path.join(harvestDir, "events-evidence.jsonl");
      const nestedEvidence = [
        {
          record_type: "evidence_map_entry",
          alias: "r01",
          alias_type: "run_ref",
          real_value: "api_key=sk-nested-secret-key-1234567890abcdef",
        },
        {
          record_type: "compiler_stats",
          total_events: 5,
          meta: { description: "secret token: ghp_nestedSecretToken1234567890abcdefgh" },
        },
      ];
      fs.writeFileSync(evidencePath,
        nestedEvidence.map(function(r) { return JSON.stringify(r); }).join("\n") + "\n");

      const stateDir = path.join(projectRoot, ".graphsmith", "state");
      fs.mkdirSync(stateDir, { recursive: true });
      writeStateVersion(stateDir, CURRENT_SCHEMA_VERSION);
      migrate(projectRoot);

      const afterContent = fs.readFileSync(evidencePath, "utf8");
      check("redaction-nested-real-value-redacted", !afterContent.includes("sk-nested-secret-key"),
        "nested real_value must be redacted");
      check("redaction-nested-description-redacted", !afterContent.includes("ghp_nestedSecretToken"),
        "nested description must be redacted");
      check("redaction-nested-redaction-tokens", (afterContent.match(/\[REDACTED\]/g) || []).length >= 2,
        "at least 2 [REDACTED] tokens in nested evidence");
    }

    /* --- PROOF 4: Non-evidence state files are NOT redacted (only evidence is) --- */
    {
      const projectRoot = path.join(base, "p4-scope");
      const stateDir = path.join(projectRoot, ".graphsmith", "state");
      const harvestDir = path.join(projectRoot, ".graphsmith", "harvest");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.mkdirSync(harvestDir, { recursive: true });

      const stateFilePath = path.join(stateDir, "window.json");
      const legitStateValue = JSON.stringify({
        schema_version: "1.0", state_rev: 1, state: "NO_WINDOW", flag: false, window: null,
        comment: "This contains a word like token but is not a real token so should not be redacted",
      }, null, 2);
      fs.writeFileSync(stateFilePath, legitStateValue + "\n");

      const evidenceFilePath = path.join(harvestDir, "events-evidence.jsonl");
      fs.writeFileSync(evidenceFilePath,
        JSON.stringify({ record_type: "evidence", secret_token: "sk-should-be-redacted-12345abcdef" }) + "\n");

      writeStateVersion(stateDir, CURRENT_SCHEMA_VERSION);
      migrate(projectRoot);

      const stateContent = fs.readFileSync(stateFilePath, "utf8");
      const evidenceContent = fs.readFileSync(evidenceFilePath, "utf8");

      check("redaction-scope-state-file-untouched",
        !stateContent.includes("[REDACTED]"),
        "state file (window.json) must not contain redaction tokens");
      check("redaction-scope-evidence-redacted",
        !evidenceContent.includes("sk-should-be-redacted-12345abcdef"),
        "evidence file must have secret redacted");
    }

    /* --- PROOF 5: Forward-only migration (no downgrade path) --- */
    {
      const projectRoot = path.join(base, "p5-forward");
      const stateDir = path.join(projectRoot, ".graphsmith", "state");
      fs.mkdirSync(stateDir, { recursive: true });

      writeStateVersion(stateDir, "1.1");
      const result = migrate(projectRoot);
      check("forward-only-already-at-target-no-migrate", result.migrated === false,
        "migrated=" + result.migrated + ", reason=" + result.reason);

      writeStateVersion(stateDir, "0.9");
      const result2 = migrate(projectRoot);
      check("forward-only-unsupported-version-no-migrate", result2.migrated === false,
        "migrated=" + result2.migrated + ", reason=" + result2.reason);
    }

    /* --- PROOF 6: Changes list is complete --- */
    {
      const projectRoot = path.join(base, "p6-changes");
      const stateDir = path.join(projectRoot, ".graphsmith", "state");
      const harvestDir = path.join(projectRoot, ".graphsmith", "harvest");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.mkdirSync(harvestDir, { recursive: true });

      fs.writeFileSync(path.join(harvestDir, "events-evidence.jsonl"),
        JSON.stringify({ record_type: "test", password: "should-be-redacted" }) + "\n");

      writeStateVersion(stateDir, CURRENT_SCHEMA_VERSION);
      const result = migrate(projectRoot);

      check("changes-list-has-schema-bump",
        result.changes.some(function(c) { return c.action === "bumped"; }),
        "changes list must include schema version bump");
      check("changes-list-has-redaction-entries",
        result.changes.some(function(c) { return c.action === "redacted-jsonl"; }),
        "changes list must include redaction actions");
    }

    return {
      schema_version: CURRENT_SCHEMA_VERSION,
      target_schema_version: TARGET_SCHEMA_VERSION,
      status: errors.length === 0 ? "pass" : "fail",
      tests: tests,
      errors: errors,
      exitCode: errors.length === 0 ? 0 : 1,
    };
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    const report = selftest();
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    if (report.exitCode !== 0) process.exit(report.exitCode);
    process.exit(0);
  }

  const projectRoot = args.length > 0 && !args[0].startsWith("--") ? args[0] : ".";
  const result = migrate(projectRoot);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exitCode = result.migrated ? 0 : 1;
}

/* ---------------------------------------------------------------------------
 * Exports
 * ------------------------------------------------------------------------- */

module.exports = {
  migrate,
  redactText,
  redactEvidenceRecord,
  scanForSecrets,
  scanFileForSecrets,
  readStateVersion,
  writeStateVersion,
  CURRENT_SCHEMA_VERSION,
  TARGET_SCHEMA_VERSION,
  selftest,
};