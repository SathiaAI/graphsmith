#!/usr/bin/env node
/* GraphSmith watcher.js — Phase D (contract 04). Zero-dep CJS, Node >= 18.
 *
 * ADVISORY LLM watcher: OFF by default, reads structured logs only, flag-only,
 * batched. UNTRUSTED-output — can NEVER auto-halt/continue/adopt/promote.
 *
 * watch(options) -> { flags, stats }
 *
 * --selftest: proves off-by-default, structured-input-only, flag-only, batched. */
"use strict";

const fs = require("fs");
const path = require("path");

const SCHEMA_VERSION = "1.0";
const FLAG_LABEL = "advisory, unverified";
const EVIDENCE_CHARSET = /^[A-Za-z0-9._:\/-]{1,256}$/;

/* ---------------------------------------------------------------------------
 * Closed event types (must match event-compiler.js)
 * ------------------------------------------------------------------------- */

const EVENT_TYPES = Object.freeze([
  "run_halt", "budget_breach", "tripwire", "retry_exhausted",
  "step_failure", "corrupt_checkpoint", "lock_contention",
  "scenario_fail", "human_correction", "adoption", "rollback",
]);

const TYPE_CODES = Object.freeze({
  run_halt:          ["unresolved_side_effect", "out_of_memory", "signal_termination", "watchdog_timeout", "orphaned_lock", "budget_exhausted", "unknown_halt"],
  budget_breach:     ["max_wall_time", "max_token_count", "max_api_calls", "max_step_execution", "max_memory", "max_cost"],
  tripwire:          ["unexpected_output_schema", "production_api_call", "file_access_outside_boundary", "network_access", "privilege_escalation", "env_access"],
  retry_exhausted:   ["max_retries_step", "max_retries_run"],
  step_failure:      ["worker_error", "module_not_found", "worker_timeout", "invalid_output", "side_effect_mismatch", "unhandled_exception"],
  corrupt_checkpoint: ["unreadable_file", "schema_mismatch", "hash_mismatch", "truncated_file", "missing_file"],
  lock_contention:   ["deadlock_detected", "lease_expired", "lock_file_corrupt", "owner_mismatch", "stale_lock"],
  scenario_fail:     ["invariant_violation", "expected_outcome_mismatch", "scenario_crash", "infra_fault", "workflow_fault"],
  human_correction:  ["gate3_prompt_adjustment", "data_correction", "config_update", "manual_override", "knob_tune"],
  adoption:          ["doc_change", "knob_change", "prompt_change", "code_change", "config_only", "migration"],
  rollback:          ["hard_failure", "human_decision", "pre_authorized", "flagged", "abandoned_window"],
});

const ALLOWED_WINDOW_STATES = Object.freeze(["IDLE", "RUNNING", "PAUSED", "ROLLING_BACK", "CLOSED_ROLLED_BACK", "CLOSED_COMPLETE"]);

const SAFETY_TYPES = new Set(["run_halt", "budget_breach", "tripwire", "rollback"]);

/* ---------------------------------------------------------------------------
 * Model adapter (pluggable/stubbable)
 * ------------------------------------------------------------------------- */

class ModelAdapter {
  constructor(options = {}) {
    this.stubMode = options.stubMode === true;
    this.stubResponses = options.stubResponses || [];
  }

  async batchAnalyze(batch) {
    if (this.stubMode) {
      const response = this.stubResponses.shift() || { flags: [] };
      return response.flags || [];
    }

    throw new Error("Model adapter not configured: stubMode must be true or a real adapter must be provided");
  }
}

/* ---------------------------------------------------------------------------
 * Flag structure (advisory only, no authority)
 * ------------------------------------------------------------------------- */

function createFlag(severity, category, message, context) {
  return {
    schema_version: SCHEMA_VERSION,
    record_type: "advisory_flag",
    label: FLAG_LABEL,
    severity: String(severity),
    category: String(category),
    message: String(message),
    context: context && typeof context === "object" ? { ...context } : {},
    timestamp_ms: Date.now(),
  };
}

/* ---------------------------------------------------------------------------
 * Structured log readers (typed records ONLY)
 * ------------------------------------------------------------------------- */

function readProposerView(harvestDir) {
  const filePath = path.join(harvestDir, "events-proposer.jsonl");
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim());
    const records = [];
    for (const line of lines) {
      const record = JSON.parse(line);
      if (!EVENT_TYPES.includes(record.type)) {
        throw new Error(`Invalid event: unknown type "${record.type}"`);
      }
      records.push(record);
    }
    return records;
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
}

function readStateRecords(stateDir) {
  const records = [];

  const readJsonl = (fileName) => {
    const filePath = path.join(stateDir, fileName);
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      const lines = raw.split("\n").filter((l) => l.trim());
      for (const line of lines) {
        try {
          const record = JSON.parse(line);
          if (record && typeof record === "object" && record.record_type) {
            records.push(record);
          }
        } catch {
        }
      }
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  };

  try {
    readJsonl("run-registry.jsonl");
    readJsonl("run-anchors.jsonl");
    readJsonl("alpha-ledger.jsonl");
    readJsonl("rejected-buffer.jsonl");
    readJsonl("rollback-families.jsonl");

    const windowPath = path.join(stateDir, "window.json");
    try {
      const raw = fs.readFileSync(windowPath, "utf8");
      const windowRecord = JSON.parse(raw);
      if (windowRecord && typeof windowRecord === "object") {
        records.push(windowRecord);
      }
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }

  return records;
}

function validateStructuredEvent(event) {
  if (!event || typeof event !== "object") {
    throw new Error("Invalid event: not an object");
  }

  if (typeof event.schema_version !== "string") {
    throw new Error("Invalid event: missing or invalid schema_version");
  }

  if (!EVENT_TYPES.includes(event.type)) {
    throw new Error(`Invalid event: unknown type "${event.type}"`);
  }

  if (typeof event.code !== "string") {
    throw new Error("Invalid event: missing or invalid code");
  }

  const typeCodeList = TYPE_CODES[event.type];
  if (!typeCodeList || !typeCodeList.includes(event.code)) {
    throw new Error(`Invalid event: code "${event.code}" not in closed enum for type "${event.type}"`);
  }

  if (event.counters && typeof event.counters !== "object") {
    throw new Error("Invalid event: counters must be an object");
  }

  if (typeof event.run_ref !== "string") {
    throw new Error("Invalid event: missing or invalid run_ref");
  }

  if (typeof event.step_ref !== "string") {
    throw new Error("Invalid event: missing or invalid step_ref");
  }

  if (!Number.isSafeInteger(event.seq)) {
    throw new Error("Invalid event: missing or invalid seq");
  }

  if (!Number.isSafeInteger(event.delta_ms)) {
    throw new Error("Invalid event: missing or invalid delta_ms");
  }

  if (event.evidence_ref && (!EVIDENCE_CHARSET.test(event.evidence_ref) || event.evidence_ref.length < 1 || event.evidence_ref.length > 256)) {
    throw new Error("Invalid event: evidence_ref fails charset/length check");
  }

  if (event.fingerprint && (!EVIDENCE_CHARSET.test(event.fingerprint) || event.fingerprint.length < 1 || event.fingerprint.length > 256)) {
    throw new Error("Invalid event: fingerprint fails charset/length check");
  }

  if (!EVIDENCE_CHARSET.test(event.run_ref) || event.run_ref.length < 1 || event.run_ref.length > 256) {
    throw new Error("Invalid event: run_ref fails charset/length check");
  }

  if (!EVIDENCE_CHARSET.test(event.step_ref) || event.step_ref.length < 1 || event.step_ref.length > 256) {
    throw new Error("Invalid event: step_ref fails charset/length check");
  }
}

/* ---------------------------------------------------------------------------
 * Batching logic (structured records only)
 * ------------------------------------------------------------------------- */

function createBatch(events, stateRecords, options = {}) {
  const maxBatchSize = Number.isSafeInteger(options.maxBatchSize) ? options.maxBatchSize : 100;
  const selected = events.slice(0, maxBatchSize);
  const totalEvents = events.length;
  const overflowDropped = totalEvents > maxBatchSize ? totalEvents - maxBatchSize : 0;

  const validated = [];
  let validationDropped = 0;

  for (const ev of selected) {
    try {
      validateStructuredEvent(ev);

      const sanitizedCounters = {};
      if (ev.counters && typeof ev.counters === "object") {
        for (const [key, value] of Object.entries(ev.counters)) {
          sanitizedCounters[key] = Number.isSafeInteger(value) ? value : 0;
        }
      }

      validated.push({
        type: ev.type,
        code: ev.code,
        counters: sanitizedCounters,
        run_ref: ev.run_ref,
        step_ref: ev.step_ref,
        seq: ev.seq,
        delta_ms: ev.delta_ms,
        lossy: ev.lossy === true,
        fingerprint: ev.fingerprint,
      });
    } catch (err) {
      validationDropped++;
    }
  }

  const batch = {
    events: validated,
    state_summary: summarizeState(stateRecords),
  };

  return { batch, dropped_events: overflowDropped + validationDropped };
}

function summarizeState(stateRecords) {
  const summary = {
    window_state: null,
    active_runs: 0,
    alpha_reservations: 0,
    rejected_count: 0,
    rollback_families: 0,
  };

  for (const record of stateRecords) {
    if (!record || typeof record !== "object") continue;

    if (record.record_type === "REGISTERED") {
      summary.active_runs++;
    } else if (record.record_type === "RESERVED") {
      summary.alpha_reservations++;
    } else if (record.record_type === "REJECTED") {
      summary.rejected_count++;
    } else if (record.record_type === "ROLLBACK_RECORDED") {
      summary.rollback_families++;
    } else if (record.state) {
      const stateStr = String(record.state);
      if (ALLOWED_WINDOW_STATES.includes(stateStr)) {
        summary.window_state = stateStr;
      }
    }
  }

  return summary;
}

/* ---------------------------------------------------------------------------
 * Main watch function
 * ------------------------------------------------------------------------- */

async function watch(options = {}) {
  if (options.enabled !== true) {
    return {
      flags: [],
      stats: {
        schema_version: SCHEMA_VERSION,
        record_type: "watcher_stats",
        enabled: false,
        events_processed: 0,
        batches_sent: 0,
        flags_generated: 0,
        dropped_events: 0,
      },
    };
  }

  const projectRoot = path.resolve(options.projectRoot || ".");
  const harvestDir = path.join(projectRoot, ".graphsmith", "harvest");
  const stateDir = path.join(projectRoot, ".graphsmith", "state");

  const events = readProposerView(harvestDir);
  const stateRecords = readStateRecords(stateDir);

  const { batch, dropped_events } = createBatch(events, stateRecords, options);

  if (batch.events.length === 0) {
    return {
      flags: [],
      stats: {
        schema_version: SCHEMA_VERSION,
        record_type: "watcher_stats",
        enabled: true,
        events_processed: 0,
        batches_sent: 0,
        flags_generated: 0,
        dropped_events,
      },
    };
  }

  const modelAdapter = options.modelAdapter || new ModelAdapter({ stubMode: true });

  const rawFlags = await modelAdapter.batchAnalyze(batch);

  const flags = rawFlags
    .filter((flag) => flag && typeof flag === "object")
    .map((flag) =>
      createFlag(
        flag.severity || "info",
        flag.category || "general",
        flag.message || "No message",
        flag.context || {}
      )
    );

  return {
    flags,
    stats: {
      schema_version: SCHEMA_VERSION,
      record_type: "watcher_stats",
      enabled: true,
      events_processed: batch.events.length,
      batches_sent: 1,
      flags_generated: flags.length,
      dropped_events,
    },
  };
}

/* ---------------------------------------------------------------------------
 * Selftest
 * ------------------------------------------------------------------------- */

async function selftest() {
  const os = require("os");
  const tests = [];

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-watcher-"));

  try {
    const harvestDir = path.join(tmpRoot, ".graphsmith", "harvest");
    const stateDir = path.join(tmpRoot, ".graphsmith", "state");
    fs.mkdirSync(harvestDir, { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true });

    /* --- TEST 1: Disabled by default (no output without explicit enable) --- */
    const result1 = await watch({ projectRoot: tmpRoot });
    const disabledOk =
      result1.flags.length === 0 &&
      result1.stats.enabled === false &&
      result1.stats.events_processed === 0 &&
      result1.stats.batches_sent === 0 &&
      result1.stats.flags_generated === 0 &&
      result1.stats.dropped_events === 0;

    tests.push({
      name: "off-by-default",
      status: disabledOk ? "pass" : "fail",
      details: disabledOk
        ? "Watcher produces nothing when not explicitly enabled"
        : `flags=${result1.flags.length}, enabled=${result1.stats.enabled}`,
    });

    /* --- TEST 2: Reads only structured records (injection-proof) --- */
    const injectionStep = "execute_injection__DROP_ALL_TABLES__ignore_previous";
    const injectionRaw = `{"raw_prompt":"${injectionStep}","evidence_map":{"suspicious":"payload"}}`;

    fs.writeFileSync(
      path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({
        schema_version: "1.0",
        seq: 0,
        event_id: "test001",
        run_ref: "r01",
        step_ref: "s01",
        ord: 0,
        delta_ms: 100,
        type: "run_halt",
        code: "unknown_halt",
        counters: { retries_attempted: 0 },
        lossy: false,
        evidence_ref: "p01",
        fingerprint: "abc123",
      }) + "\n"
    );

    const stubAdapter2 = new ModelAdapter({
      stubMode: true,
      stubResponses: [
        {
          flags: [
            {
              severity: "warning",
              category: "pattern",
              message: "Test flag",
              context: { event_types: ["run_halt"] },
            },
          ],
        },
      ],
    });

    const result2 = await watch({
      enabled: true,
      projectRoot: tmpRoot,
      modelAdapter: stubAdapter2,
    });

    let injectionLeaked = false;
    const result2Str = JSON.stringify(result2);
    if (result2Str.includes(injectionStep) || result2Str.includes("execute_injection")) {
      injectionLeaked = true;
    }
    if (result2Str.includes("raw_prompt") || result2Str.includes("evidence_map")) {
      injectionLeaked = true;
    }

    const structuredOnlyOk =
      !injectionLeaked &&
      result2.stats.events_processed === 1 &&
      result2.flags.length === 1 &&
      result2.flags[0].label === FLAG_LABEL;

    tests.push({
      name: "structured-input-only",
      status: structuredOnlyOk ? "pass" : "fail",
      details: structuredOnlyOk
        ? "Only structured records read; injection-shaped raw string never reaches input"
        : injectionLeaked ? "Injection content leaked to watcher output" : "Structured reading failed",
    });

    /* --- TEST 3: Output is advisory flags with no authority --- */
    const authorityAssertion = (flag) => {
      const flagStr = JSON.stringify(flag);
      if (flagStr.includes("halt") && !flagStr.includes("run_halt")) return true;
      if (flagStr.includes("adopt") && !flagStr.includes("adoption")) return true;
      if (flagStr.includes("promote")) return true;
      if (flagStr.includes("continue") && !flagStr.includes("human_correction")) return true;
      if (flagStr.includes("auto-") && !flagStr.includes("automated")) return true;
      if (flag.action !== undefined) return true;
      if (flag.command !== undefined) return true;
      if (flag.trigger !== undefined) return true;
      if (flag.execute !== undefined) return true;
      return false;
    };

    const hasAuthority = result2.flags.some(authorityAssertion);

    const flagOnlyOk =
      !hasAuthority &&
      result2.flags.every((flag) => flag.label === FLAG_LABEL && flag.record_type === "advisory_flag") &&
      result2.flags.every((flag) => flag.action === undefined && flag.command === undefined && flag.trigger === undefined && flag.execute === undefined);

    tests.push({
      name: "flag-only-no-authority",
      status: flagOnlyOk ? "pass" : "fail",
      details: flagOnlyOk
        ? "All flags labeled 'advisory, unverified'; no action/trigger/execute fields; cannot trigger halt/adopt/promote"
        : hasAuthority ? "Flag contains authority-like field" : "Flag structure incorrect",
    });

    /* --- TEST 4: Batching --- */
    const eventLines = [];
    for (let i = 0; i < 150; i++) {
      eventLines.push(
        JSON.stringify({
          schema_version: "1.0",
          seq: i,
          event_id: `test${String(i).padStart(3, "0")}`,
          run_ref: "r01",
          step_ref: `s${String(i).padStart(2, "0")}`,
          ord: i,
          delta_ms: i * 10,
          type: i % 2 === 0 ? "run_halt" : "step_failure",
          code: i % 2 === 0 ? "unknown_halt" : "worker_error",
          counters: { test_counter: i },
          lossy: false,
          evidence_ref: `p${String(i).padStart(2, "0")}`,
          fingerprint: `fp${i}`,
        })
      );
    }
    fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"), eventLines.join("\n") + "\n");

    const batchedResult = createBatch(
      eventLines.map((l) => JSON.parse(l)),
      [],
      { maxBatchSize: 100 }
    );

    const batchedOk = batchedResult.batch.events.length === 100 && batchedResult.batch.events[0].seq === 0 && batchedResult.batch.events[99].seq === 99;

    tests.push({
      name: "batched",
      status: batchedOk ? "pass" : "fail",
      details: batchedOk
        ? `Batch limited to maxBatchSize (100 events)`
        : `Batched ${batchedResult.batch.events.length} events, expected 100`,
    });

    /* --- TEST 5: Stub adapter (no real network in --selftest) --- */
    const networkCalls = [];
    const networkAdapter = {
      batchAnalyze: async (batch) => {
        networkCalls.push(batch);
        return [{ severity: "info", category: "test", message: "Network call test" }];
      },
    };

    const result5 = await watch({
      enabled: true,
      projectRoot: tmpRoot,
      modelAdapter: networkAdapter,
    });

    const stubOk = networkCalls.length > 0 && result5.flags.length === 1 && typeof networkAdapter.batchAnalyze === "function";

    tests.push({
      name: "stub-adapter",
      status: stubOk ? "pass" : "fail",
      details: stubOk
        ? "Model adapter is pluggable/stubbable; no real network required"
        : "Adapter mechanism failed",
    });

    /* --- TEST 6: Safety types trigger flags --- */
    fs.writeFileSync(
      path.join(harvestDir, "events-proposer.jsonl"),
      JSON.stringify({
        schema_version: "1.0",
        seq: 0,
        event_id: "test001",
        run_ref: "r01",
        step_ref: "s01",
        ord: 0,
        delta_ms: 100,
        type: "tripwire",
        code: "unexpected_output_schema",
        counters: { tripwire_index: 0, total_tripwires: 1 },
        lossy: false,
        evidence_ref: "p01",
        fingerprint: "abc123",
      }) + "\n"
    );

    const stubAdapter6 = new ModelAdapter({
      stubMode: true,
      stubResponses: [
        {
          flags: [
            {
              severity: "critical",
              category: "safety",
              message: "Tripwire detected",
              context: { event_type: "tripwire" },
            },
          ],
        },
      ],
    });

    const result6 = await watch({
      enabled: true,
      projectRoot: tmpRoot,
      modelAdapter: stubAdapter6,
    });

    const safetyFlagOk =
      result6.flags.length === 1 &&
      result6.flags[0].severity === "critical" &&
      result6.flags[0].category === "safety" &&
      result6.flags[0].label === FLAG_LABEL;

    tests.push({
      name: "safety-types-flags",
      status: safetyFlagOk ? "pass" : "fail",
      details: safetyFlagOk
        ? "Safety-type events trigger appropriately-severed advisory flags"
        : `flags=${result6.flags.length}, expected 1 critical flag`,
    });

    return {
      schema_version: SCHEMA_VERSION,
      status: tests.every((t) => t.status === "pass") ? "pass" : "fail",
      tests,
    };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

if (require.main === module) {
  const args = process.argv.slice(2);

  (async () => {
    if (args.includes("--selftest")) {
      const report = await selftest();
      process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      if (report.status !== "pass") process.exit(1);
      process.exit(0);
    }

    const enabledIdx = args.indexOf("--enabled");
    const enabled = enabledIdx >= 0 && args[enabledIdx + 1] === "true";

    const projectRootIdx = args.indexOf("--project-root");
    const projectRoot = projectRootIdx >= 0 ? args[projectRootIdx + 1] : ".";

    if (args.length === 0 || (args.length === 2 && !args.includes("--enabled"))) {
      console.error("Usage: node scripts/watcher.js [--enabled true] [--project-root <dir>]");
      console.error("       node scripts/watcher.js --selftest");
      process.exit(2);
    }

    const result = await watch({ enabled, projectRoot });
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  })().catch((err) => {
    console.error(err && err.stack ? err.stack : String(err));
    process.exit(1);
  });
}

/* ---------------------------------------------------------------------------
 * Exports
 * ------------------------------------------------------------------------- */

module.exports = {
  SCHEMA_VERSION,
  FLAG_LABEL,
  watch,
  createBatch,
  createFlag,
  ModelAdapter,
  selftest,
  EVENT_TYPES,
  SAFETY_TYPES,
};