#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const repoRoot = path.resolve(__dirname, "../../..");
const compilerPath = path.join(repoRoot, "scripts", "event-compiler.js");
const schemaPath = path.join(repoRoot, "schemas", "lesson-event.schema.json");
const compiler = require(compilerPath);
const schema = require(schemaPath);
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-event-compiler-gpt-sol-pro-"));
const results = [];
let fixtureCounter = 0;
let emissionCounter = 0;

const EVENT_KEYS = [
  "schema_version", "seq", "event_id", "run_ref", "step_ref", "ord",
  "delta_ms", "type", "code", "counters", "lossy", "evidence_ref", "fingerprint",
].sort();

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

function makeRoot(label) {
  const root = path.join(scratch, `${String(++fixtureCounter).padStart(2, "0")}-${label}`);
  fs.mkdirSync(path.join(root, ".graphsmith", "state"), { recursive: true });
  return root;
}

function writeJsonl(file, records) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, records.length ? `${records.map((record) => JSON.stringify(record)).join("\n")}\n` : "");
}

function chainBodies(bodies) {
  let previous = "genesis";
  return bodies.map((body) => {
    const lineHash = compiler.computeRecordHash(previous, body);
    const line = { prev_hash: previous, line_hash: lineHash, ...body };
    previous = lineHash;
    return line;
  });
}

function addRun(root, runId, bodies, options = {}) {
  const runDir = path.join(root, "runs", runId);
  fs.mkdirSync(runDir, { recursive: true });
  const lines = options.lines || chainBodies(bodies);
  writeJsonl(path.join(runDir, "run.jsonl"), lines);
  return { runDir, lines, chainHead: lines.length ? lines[lines.length - 1].line_hash : null };
}

function writeAnchors(root, anchors) {
  writeJsonl(path.join(root, ".graphsmith", "state", "run-anchors.jsonl"), anchors.map((anchor, index) => ({
    schema_version: "1.0",
    state_rev: index + 1,
    record_type: "ANCHOR_SET",
    ...anchor,
  })));
}

function anchorFor(runId, run, expectedTerminalStatus) {
  return { run_id: runId, chain_head: run.chainHead, expected_terminal_status: expectedTerminalStatus };
}

function emit(root, runDirs) {
  const outputDir = path.join(root, `emitted-${String(++emissionCounter).padStart(3, "0")}`);
  const result = compiler.compileToFiles(runDirs, outputDir, { projectRoot: root });
  return {
    result,
    proposerBytes: fs.readFileSync(path.join(outputDir, "events-proposer.jsonl")),
    evidenceBytes: fs.readFileSync(path.join(outputDir, "events-evidence.jsonl")),
    statsBytes: fs.readFileSync(path.join(outputDir, "compiler-stats.jsonl")),
  };
}

function baseBody(overrides = {}) {
  return {
    seq: 0,
    step: "normal-step",
    type: "step_failure",
    code: "worker_error",
    counters: { attempt: 1, total_retries: 0, step_duration_ms: 5 },
    delta_ms: 5,
    lossy: false,
    run_id: "normal-run",
    ...overrides,
  };
}

function makeGoodRun(root, runId = "good-run") {
  const run = addRun(root, runId, [
    baseBody({ seq: 0, run_id: runId, step: "good-step" }),
    baseBody({ seq: 1, run_id: runId, step: "terminal", type: "run_halt", code: "unknown_halt", counters: {} }),
  ]);
  return run;
}

function visit(value, at, callback) {
  callback(value, at);
  if (Array.isArray(value)) value.forEach((child, index) => visit(child, `${at}[${index}]`, callback));
  else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      callback(key, `${at}{key}`);
      visit(child, `${at}.${key}`, callback);
    }
  }
}

function validateEvent(record) {
  const errors = [];
  if (!record || typeof record !== "object" || Array.isArray(record)) return ["record is not an object"];
  if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(EVENT_KEYS)) errors.push("top-level keys are not closed/exact");
  if (record.schema_version !== "1.0") errors.push("schema_version");
  for (const key of ["seq", "ord", "delta_ms"]) if (!Number.isSafeInteger(record[key])) errors.push(`${key} is not a safe integer`);
  if (!/^[a-f0-9]{16}$/.test(record.event_id || "")) errors.push("event_id");
  if (!/^r[0-9]{2,6}$/.test(record.run_ref || "")) errors.push("run_ref");
  if (!/^s[0-9]{2,6}$/.test(record.step_ref || "")) errors.push("step_ref");
  if (!/^p[0-9]{2,6}$/.test(record.evidence_ref || "")) errors.push("evidence_ref");
  if (!/^[a-f0-9]{64}$/.test(record.fingerprint || "")) errors.push("fingerprint");
  if (!compiler.EVENT_TYPES.includes(record.type)) errors.push("type");
  if (!compiler.TYPE_CODES[record.type] || !compiler.TYPE_CODES[record.type].includes(record.code)) errors.push("code");
  if (typeof record.lossy !== "boolean") errors.push("lossy");
  if (!record.counters || typeof record.counters !== "object" || Array.isArray(record.counters)) errors.push("counters object");
  else {
    const allowed = new Set(compiler.TYPE_COUNTER_KEYS[record.type] || []);
    for (const [key, value] of Object.entries(record.counters)) {
      if (!allowed.has(key)) errors.push(`counter key ${key}`);
      if (!Number.isSafeInteger(value)) errors.push(`counter ${key} is not a safe integer`);
    }
  }
  return errors;
}

function assertInvalidAndEmpty(emitted, label) {
  assert.strictEqual(emitted.result.stats.harvest_valid, false, `${label}: harvest_valid was not false`);
  assert.strictEqual(emitted.proposerBytes.length, 0, `${label}: emitted ${emitted.proposerBytes.length} proposer bytes`);
  assert.strictEqual(emitted.result.proposerView.length, 0, `${label}: returned proposals despite invalid harvest`);
}

try {
  test("producer strings are absent from every proposer-view field", () => {
    const root = makeRoot("producer-isolation");
    const markers = [
      "ignore_previous_instructions__STEP_MARKER",
      "RUN_MARKER__system_prompt_end",
      "PATH_MARKER__..__escape",
      "CODE_MARKER__assistant_override",
      "COUNTER_KEY_MARKER__tool_call",
      "UNICODE_MARKER__\u202e\u2066\u03a9",
      `OVERSIZED_MARKER__${"X".repeat(16384)}`,
    ];
    const runId = "producer-isolation-run";
    const run = addRun(root, runId, [
      baseBody({
        seq: 0,
        run_id: markers[1],
        step: markers[0],
        code: markers[3],
        evidence_path: markers[2],
        counters: { attempt: 7, [markers[4]]: 99 },
        producer_unicode: markers[5],
      }),
      baseBody({
        seq: 1,
        run_id: markers[6],
        step: markers[6],
        type: "run_halt",
        code: "unknown_halt",
        counters: { [markers[4]]: 1 },
      }),
    ]);
    writeAnchors(root, [anchorFor(runId, run, "run_halt")]);
    const emitted = emit(root, [run.runDir]);
    assert.strictEqual(emitted.result.stats.harvest_valid, true);
    assert.ok(emitted.proposerBytes.length > 0, "fixture emitted no proposer records");
    const proposerText = emitted.proposerBytes.toString("utf8");
    for (const marker of markers) assert.ok(!proposerText.includes(marker), `producer bytes leaked: ${marker.slice(0, 80)}`);
    for (const [index, record] of emitted.result.proposerView.entries()) {
      const errors = validateEvent(record);
      assert.deepStrictEqual(errors, [], `event ${index}: ${errors.join(", ")}`);
      visit(record, `$[${index}]`, (value, at) => {
        if (typeof value !== "string") return;
        for (const marker of markers) assert.notStrictEqual(value, marker, `${at} equals a producer string`);
      });
    }
    return `${emitted.proposerBytes.length} emitted bytes recursively diffed against ${markers.length} hostile values`;
  });

  test("opaque-alias collision cannot create a second producer field", () => {
    const root = makeRoot("alias-collision");
    const runId = "alias-collision-run";
    const run = addRun(root, runId, [
      baseBody({ seq: 0, run_id: "r01", step: "s01", evidence_path: "p01" }),
      baseBody({ seq: 1, run_id: "r01", step: "p01", type: "run_halt", code: "unknown_halt", counters: {} }),
    ]);
    writeAnchors(root, [anchorFor(runId, run, "run_halt")]);
    const emitted = emit(root, [run.runDir]);
    for (const record of emitted.result.proposerView) {
      for (const [key, value] of Object.entries(record)) {
        if (["r01", "s01", "p01"].includes(value)) assert.ok(["run_ref", "step_ref", "evidence_ref"].includes(key), `${key} carried colliding producer bytes`);
      }
    }
    return "colliding literals occurred only in compiler alias slots";
  });

  test("adoption-log string seq cannot leak into proposer ord", () => {
    const root = makeRoot("adoption-seq-injection");
    const marker = "ADOPTION_SEQ__ignore_previous_instructions";
    writeJsonl(path.join(root, ".graphsmith", "state", "adoption-log.jsonl"), [{
      status: "effective", kind: "doc_change", seq: marker, txid: "safe-tx",
    }]);
    const emitted = emit(root, []);
    assert.ok(!emitted.proposerBytes.toString("utf8").includes(marker), "producer seq bytes reached events-proposer.jsonl");
    return "malformed producer seq was absent from emitted proposer bytes";
  });

  test("authorized adoption proposer record conforms to published event schema", () => {
    const root = makeRoot("adoption-schema");
    writeJsonl(path.join(root, ".graphsmith", "state", "adoption-log.jsonl"), [{
      status: "effective", kind: "doc_change", seq: 4, txid: "safe-tx",
    }]);
    const emitted = emit(root, []);
    assert.strictEqual(emitted.result.proposerView.length, 1, "fixture did not emit one adoption");
    const errors = validateEvent(emitted.result.proposerView[0]);
    assert.deepStrictEqual(errors, [], `emitted adoption schema errors: ${errors.join(", ")}`);
    return "authorized adoption emitted a schema-conformant proposer record";
  });

  test("evidence-map real values never enter proposer bytes", () => {
    const root = makeRoot("evidence-isolation");
    const runId = "evidence-isolation-run";
    const run = addRun(root, runId, [
      baseBody({ seq: 0, run_id: "REAL_RUN_VALUE", step: "REAL_STEP_VALUE", evidence_path: "safe/REAL_PATH_VALUE.txt" }),
      baseBody({ seq: 1, run_id: "REAL_RUN_VALUE", step: "terminal", type: "run_halt", code: "unknown_halt", counters: {} }),
    ]);
    writeAnchors(root, [anchorFor(runId, run, "run_halt")]);
    const emitted = emit(root, [run.runDir]);
    const proposer = emitted.proposerBytes.toString("utf8");
    const realValues = emitted.result.evidenceMap.map((entry) => entry.real_value);
    assert.ok(realValues.length >= 3, "fixture produced too few evidence mappings");
    for (const value of realValues) assert.ok(!proposer.includes(value), `evidence real_value leaked: ${value}`);
    return `${realValues.length} emitted evidence values absent from proposer bytes`;
  });

  test("proposer prompt path statically and dynamically excludes evidence map", () => {
    const consumerPath = path.join(repoRoot, "scripts", "evolve.js");
    const source = fs.readFileSync(consumerPath, "utf8");
    assert.match(source, /const events = compiled\.proposerView;/, "evolve.js does not select the proposer-only compiler view");
    assert.doesNotMatch(source, /events-evidence|evidenceMap/, "evolve.js imports evidence-map data");

    const evolvePath = require.resolve(path.join(repoRoot, "scripts", "evolve.js"));
    const originalCompile = compiler.compile;
    let evidenceMapRead = false;
    compiler.compile = () => {
      const compiled = { proposerView: [], stats: { harvest_valid: true } };
      Object.defineProperty(compiled, "evidenceMap", {
        get() {
          evidenceMapRead = true;
          throw new Error("proposer consumer read evidenceMap");
        },
      });
      return compiled;
    };
    delete require.cache[evolvePath];
    try {
      const evolve = require(evolvePath);
      const result = evolve.cycle(["synthetic-run"], { projectRoot: makeRoot("proposer-context") });
      assert.strictEqual(result.reason, "no-events", "dynamic proposer-only fixture did not reach the expected consumer path");
      assert.strictEqual(evidenceMapRead, false, "evolve.js dynamically read evidenceMap");
    } finally {
      compiler.compile = originalCompile;
      delete require.cache[evolvePath];
    }
    return "statically and dynamically verified evolve.js consumes proposerView only";
  });

  test("wrong-source adoption, rollback, and human_correction are rejected and counted", () => {
    const root = makeRoot("source-auth");
    const runId = "source-auth-run";
    const run = addRun(root, runId, [
      baseBody({ seq: 0, run_id: runId, type: "adoption", code: "doc_change", counters: {} }),
      baseBody({ seq: 1, run_id: runId, type: "rollback", code: "human_decision", counters: {} }),
      baseBody({ seq: 2, run_id: runId, type: "human_correction", code: "manual_override", counters: {} }),
    ]);
    writeAnchors(root, [anchorFor(runId, run, "completed")]);
    const emitted = emit(root, [run.runDir]);
    assert.strictEqual(emitted.result.stats.rejected, 3, "wrong-source count");
    assert.strictEqual(emitted.proposerBytes.length, 0, "rejected records reached proposer output");
    return "all three wrong-source records rejected; emitted proposer file empty";
  });

  test("unanchored run_halt is rejected with invalid empty harvest", () => {
    const root = makeRoot("unanchored-halt");
    const run = addRun(root, "unanchored-run", [baseBody({ type: "run_halt", code: "unknown_halt", counters: {} })]);
    const emitted = emit(root, [run.runDir]);
    assertInvalidAndEmpty(emitted, "unanchored run_halt");
    assert.strictEqual(emitted.result.stats.rejected, 1, "unanchored run_halt was not counted as rejected");
    return "missing trusted anchor yielded invalid harvest, rejection count, and zero bytes";
  });

  test("broken hash chain invalidates the whole cycle and suppresses good proposals", () => {
    const root = makeRoot("broken-chain");
    const good = makeGoodRun(root);
    const badBodies = [baseBody({ seq: 0 }), baseBody({ seq: 1, type: "run_halt", code: "unknown_halt", counters: {} })];
    const badLines = chainBodies(badBodies);
    badLines[1].prev_hash = "0".repeat(64);
    const bad = addRun(root, "bad-run", badBodies, { lines: badLines });
    writeAnchors(root, [anchorFor("good-run", good, "run_halt"), anchorFor("bad-run", bad, "run_halt")]);
    const emitted = emit(root, [good.runDir, bad.runDir]);
    assertInvalidAndEmpty(emitted, "broken chain plus good run");
    return "cycle invalid and all proposals suppressed";
  });

  test("missing anchor invalidates the whole cycle and suppresses good proposals", () => {
    const root = makeRoot("missing-anchor-cycle");
    const good = makeGoodRun(root);
    const bad = addRun(root, "no-anchor-run", [baseBody({ type: "run_halt", code: "unknown_halt", counters: {} })]);
    writeAnchors(root, [anchorFor("good-run", good, "run_halt")]);
    const emitted = emit(root, [good.runDir, bad.runDir]);
    assertInvalidAndEmpty(emitted, "missing anchor plus good run");
    return "cycle invalid and all proposals suppressed";
  });

  test("truncated anchored chain invalidates the whole cycle and suppresses good proposals", () => {
    const root = makeRoot("truncated-chain");
    const good = makeGoodRun(root);
    const original = addRun(root, "truncated-run", [
      baseBody({ seq: 0 }),
      baseBody({ seq: 1, type: "run_halt", code: "unknown_halt", counters: {} }),
    ]);
    writeJsonl(path.join(original.runDir, "run.jsonl"), original.lines.slice(0, 1));
    writeAnchors(root, [anchorFor("good-run", good, "run_halt"), anchorFor("truncated-run", original, "run_halt")]);
    const emitted = emit(root, [good.runDir, original.runDir]);
    assertInvalidAndEmpty(emitted, "truncated chain plus good run");
    return "cycle invalid and all proposals suppressed";
  });

  for (const safetyType of ["run_halt", "budget_breach", "tripwire"]) {
    test(`selective deletion of ${safetyType} invalidates cycle with zero proposals`, () => {
      const root = makeRoot(`delete-${safetyType}`);
      const good = makeGoodRun(root);
      const code = compiler.TYPE_CODES[safetyType][0];
      const victim = addRun(root, `victim-${safetyType}`, [
        baseBody({ seq: 0, step: "before" }),
        baseBody({ seq: 1, step: "safety", type: safetyType, code, counters: {} }),
        baseBody({ seq: 2, step: "after" }),
      ]);
      writeJsonl(path.join(victim.runDir, "run.jsonl"), [victim.lines[0], victim.lines[2]]);
      writeAnchors(root, [anchorFor("good-run", good, "run_halt"), anchorFor(`victim-${safetyType}`, victim, safetyType)]);
      const emitted = emit(root, [good.runDir, victim.runDir]);
      assertInvalidAndEmpty(emitted, `deleted ${safetyType}`);
      return "cycle invalid and all proposals suppressed";
    });
  }

  test("selective deletion of rollback state invalidates harvest", () => {
    const root = makeRoot("delete-rollback");
    const stateFile = path.join(root, ".graphsmith", "state", "window.json");
    const rollbackWindow = {
      schema_version: "1.0", state_rev: 1, state: "CLOSED_ROLLED_BACK", flag: false,
      window: { window_id: "w1", slots: [{ disposition: "completed_hard_fail" }] },
    };
    fs.writeFileSync(stateFile, JSON.stringify(rollbackWindow));
    const before = emit(root, []);
    assert.ok(before.result.proposerView.some((event) => event.type === "rollback"), "fixture did not contain rollback");
    fs.unlinkSync(stateFile);
    const after = emit(root, []);
    assert.strictEqual(after.result.stats.harvest_valid, false, "deleted rollback was treated as a valid empty harvest");
    assert.strictEqual(after.proposerBytes.length, 0);
    return "rollback deletion detected as invalid";
  });

  test("same input emits byte-identical proposer and evidence files", () => {
    const root = makeRoot("determinism");
    const run = makeGoodRun(root);
    writeAnchors(root, [anchorFor("good-run", run, "run_halt")]);
    const first = emit(root, [run.runDir]);
    const second = emit(root, [run.runDir]);
    assert.ok(first.proposerBytes.equals(second.proposerBytes), "proposer bytes differ");
    assert.ok(first.evidenceBytes.equals(second.evidenceBytes), "evidence bytes differ");
    return `${first.proposerBytes.length + first.evidenceBytes.length} bytes identical across two emissions`;
  });

  test("source timestamps do not affect proposer ordering or bytes", () => {
    function timestampFixture(label, firstTs, secondTs) {
      const root = makeRoot(label);
      const run = addRun(root, "timestamp-run", [
        baseBody({ seq: 0, run_id: "timestamp-run", step: "first", timestamp: firstTs }),
        baseBody({ seq: 1, run_id: "timestamp-run", step: "second", type: "run_halt", code: "unknown_halt", counters: {}, timestamp: secondTs }),
      ]);
      writeAnchors(root, [anchorFor("timestamp-run", run, "run_halt")]);
      return emit(root, [run.runDir]);
    }
    const forward = timestampFixture("timestamps-forward", "2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
    const reversed = timestampFixture("timestamps-reversed", "2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z");
    assert.ok(forward.proposerBytes.equals(reversed.proposerBytes), "timestamp mutation changed proposer bytes/order");
    assert.ok(forward.evidenceBytes.equals(reversed.evidenceBytes), "timestamp mutation changed evidence aliases/order");
    return "reversed timestamps produced identical proposer and evidence bytes";
  });

  test("published event schema is closed and emitted records conform", () => {
    const eventSchema = schema.$defs.eventRecord;
    assert.strictEqual(eventSchema.additionalProperties, false, "event schema is open");
    assert.strictEqual(schema.$defs.compilerStats.additionalProperties, false, "stats schema is open");
    assert.strictEqual(schema.$defs.evidenceMapEntry.additionalProperties, false, "evidence schema is open");
    for (const counterName of Object.keys(compiler.TYPE_COUNTER_KEYS)) {
      const defName = `${counterName.replace(/_([a-z])/g, (_m, char) => char.toUpperCase())}Counters`;
      assert.ok(schema.$defs[defName], `missing ${defName}`);
      assert.strictEqual(schema.$defs[defName].additionalProperties, false, `${defName} is open`);
    }
    const root = makeRoot("schema-conformance");
    const run = makeGoodRun(root);
    writeAnchors(root, [anchorFor("good-run", run, "run_halt")]);
    const emitted = emit(root, [run.runDir]);
    emitted.result.proposerView.forEach((record, index) => assert.deepStrictEqual(validateEvent(record), [], `event ${index}`));
    return `${emitted.result.proposerView.length} emitted records satisfy explicit zero-dependency schema checks`;
  });

  test("malformed non-safety record is quarantined rather than best-effort parsed", () => {
    const root = makeRoot("malformed-quarantine");
    const runId = "malformed-run";
    const run = addRun(root, runId, [
      baseBody({ seq: 0, run_id: runId, code: "NOT_A_CLOSED_CODE", delta_ms: "not-an-integer", counters: { attempt: "seven" } }),
      baseBody({ seq: 1, run_id: runId, type: "run_halt", code: "unknown_halt", counters: {} }),
    ]);
    writeAnchors(root, [anchorFor(runId, run, "run_halt")]);
    const emitted = emit(root, [run.runDir]);
    assert.strictEqual(emitted.result.stats.quarantined, 1, "malformed record was not counted as quarantined");
    assert.strictEqual(emitted.result.proposerView.filter((event) => event.type === "step_failure").length, 0, "malformed record was best-effort normalized into a proposal");
    return "malformed record quarantined by reference";
  });

  test("evidence_ref path escape is dropped and counted", () => {
    const root = makeRoot("path-escape");
    const runId = "path-escape-run";
    const escape = "../outside/secret.txt";
    const run = addRun(root, runId, [
      baseBody({ seq: 0, run_id: runId, evidence_path: escape }),
      baseBody({ seq: 1, run_id: runId, type: "run_halt", code: "unknown_halt", counters: {} }),
    ]);
    writeAnchors(root, [anchorFor(runId, run, "run_halt")]);
    const emitted = emit(root, [run.runDir]);
    assert.ok(!emitted.evidenceBytes.toString("utf8").includes(escape), "escaping path reached evidence map bytes");
    assert.ok(emitted.result.stats.dropped_refs >= 1, "dropped_refs was not incremented");
    return "escape absent from evidence bytes and counted";
  });
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}

for (const result of results) process.stdout.write(`${result.status} ${result.name}: ${result.reason}\n`);
const failures = results.filter((result) => result.status === "FAIL").length;
const skippedCount = results.filter((result) => result.status === "SKIPPED").length;
process.stdout.write(`SUMMARY ${results.length - failures - skippedCount} PASS, ${failures} FAIL, ${skippedCount} SKIPPED\n`);
process.exitCode = failures === 0 ? 0 : 1;
