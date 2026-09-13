#!/usr/bin/env node
"use strict";
/*
 * gate.js coverage-gap triage suite.
 *
 * Origin: round-6 systematic triage of gate.js's 811 non-selftest survived
 * mutants (see claude/graphsmith-mutation-gate-remediation-verify-2026-08-10.md
 * for the full method). Each test below closes ONE confirmed real coverage
 * gap -- a distinct error code, branch, or function that existing tests
 * (tests/gate/grok, tests/gate/gpt-sol-pro) never exercised at all. This file
 * does not duplicate anything those suites already cover.
 *
 * Two equivalent-mutant clusters found during the triage (decideGate2 lines
 * ~536-539's dead else-if/else and line ~541's redundant typeof guard) are
 * NOT tested here -- they are behaviorally unobservable by design, matching
 * the verify.js mutant-371 precedent from round 1. See the project doc.
 *
 * Zero-dep CJS. EXIT 1 if any FAIL.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../../..");
const GATE_PATH = path.join(ROOT, "scripts", "gate.js");

const gate = require(GATE_PATH);

const SCHEMA_VERSION = "1.0";

let failures = 0;
const results = [];

function report(name, status, reason) {
  const line =
    status === "PASS" ? `PASS\t${name}\t${reason || ""}` : `FAIL\t${name}\t${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gate-triage-${label}-`));
}

function rmrf(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

/* ================================================================== */
/* Gate 1 -- static-screen error codes/branches never triggered by any
   existing test. Every candidate uses ctx.aliasesResolved=true to bypass
   the (already-tested) G1_LITERAL_PATH alias check, isolating the branch
   under test. */
/* ================================================================== */
function attackGate1Gaps() {
  const CTX = { aliasesResolved: true };

  try {
    /* candidate=null/undefined must return the documented G1_MISSING_CANDIDATE
       finding, not throw. Guards against a real defect found during this
       triage: `evidence` used to be built with `candidate.id` BEFORE the
       null-check below it, so gate1Static(null) / gate1Static(undefined)
       threw an uncaught TypeError instead of the graceful rejection the
       surrounding code is clearly designed to produce -- e.g. a gate-1 CLI
       run against a candidate file containing literal `null` JSON would
       crash with a raw stack trace instead of a structured FAIL. Fixed
       alongside this test (scripts/gate.js line ~127: candidateId now reads
       `candidate && (candidate.id || candidate.fingerprint)`). */
    const resultNull = gate.gate1Static(null, {});
    assert(resultNull.pass === false, "must reject null candidate");
    assert(resultNull.findings.some((f) => f.code === "G1_MISSING_CANDIDATE"), "want G1_MISSING_CANDIDATE for null");
    const resultUndef = gate.gate1Static(undefined, {});
    assert(resultUndef.pass === false, "must reject undefined candidate");
    assert(resultUndef.findings.some((f) => f.code === "G1_MISSING_CANDIDATE"), "want G1_MISSING_CANDIDATE for undefined");
    report("g1-01-missing-candidate", "PASS", JSON.stringify(resultNull.findings.map((f) => f.code)));
  } catch (e) { report("g1-01-missing-candidate", "FAIL", e.message); }

  try {
    const candidate = { kind: "bogus", fingerprint: "fp1", edits: [{ file: "docs/a.md", op: "replace", payload: "x" }] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject unknown kind");
    assert(result.findings.some((f) => f.code === "G1_UNKNOWN_KIND"), "want G1_UNKNOWN_KIND");
    report("g1-02-unknown-kind", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-02-unknown-kind", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", edits: [{ file: "docs/a.md", op: "replace", payload: "x" }] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject missing fingerprint");
    assert(result.findings.some((f) => f.code === "G1_MISSING_FINGERPRINT"), "want G1_MISSING_FINGERPRINT");
    report("g1-03-missing-fingerprint", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-03-missing-fingerprint", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject empty edits");
    assert(result.findings.some((f) => f.code === "G1_NO_EDITS"), "want G1_NO_EDITS");
    report("g1-04-no-edits", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-04-no-edits", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [null] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject non-object edit");
    assert(result.findings.some((f) => f.code === "G1_INVALID_EDIT"), "want G1_INVALID_EDIT");
    report("g1-05-invalid-edit-object", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-05-invalid-edit-object", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [{ op: "replace", payload: "x" }] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject missing file");
    assert(result.findings.some((f) => f.code === "G1_MISSING_FILE"), "want G1_MISSING_FILE");
    report("g1-06-missing-file", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-06-missing-file", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [{ file: "docs/a.md", op: "bogus-op", payload: "x" }] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject invalid op");
    assert(result.findings.some((f) => f.code === "G1_INVALID_OP"), "want G1_INVALID_OP");
    report("g1-07-invalid-op", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-07-invalid-op", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [{ file: "docs/a.md", anchor: null, op: "replace", payload: "safe text" }] };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === true, "missing schema_ref is a warn, not fatal");
    const f = result.findings.find((f) => f.code === "G1_MISSING_SCHEMA_REF");
    assert(f && f.severity === "warn", "want warn G1_MISSING_SCHEMA_REF");
    report("g1-08-missing-schema-ref-warn", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-08-missing-schema-ref-warn", "FAIL", e.message); }

  try {
    const candidate = {
      kind: "doc", fingerprint: "fp1",
      edits: [{ file: "docs/a.md", anchor: null, op: "replace", payload: "safe text", schema_ref: "doc/v1", schema_version: "0.9" }],
    };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === true, "schema_version mismatch is a warn, not fatal");
    const f = result.findings.find((f) => f.code === "G1_SCHEMA_VERSION_MISMATCH");
    assert(f && f.severity === "warn", "want warn G1_SCHEMA_VERSION_MISMATCH");
    report("g1-09-schema-version-mismatch-warn", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-09-schema-version-mismatch-warn", "FAIL", e.message); }

  try {
    /* two replace ops, same file+anchor, different payload -- distinct from
       the already-tested "same anchor, different op" contradiction branch */
    const candidate = {
      kind: "doc", fingerprint: "fp1",
      edits: [
        { file: "docs/a.md", anchor: "sec1", op: "replace", payload: "version A", schema_ref: "doc/v1", schema_version: SCHEMA_VERSION },
        { file: "docs/a.md", anchor: "sec1", op: "replace", payload: "version B", schema_ref: "doc/v1", schema_version: SCHEMA_VERSION },
      ],
    };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject replace/replace payload contradiction");
    const f = result.findings.find((f) => f.code === "G1_CONTRADICTION");
    assert(f && /different payload/.test(f.detail), "want contradiction detail to cite different payload, got: " + JSON.stringify(f));
    report("g1-10-replace-payload-contradiction", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-10-replace-payload-contradiction", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [{ file: "docs/a.md", anchor: null, op: "replace", payload: "x", schema_ref: "doc/v1" }] };
    const result = gate.gate1Static(candidate, { ...CTX, sentinelHook: () => ({ pass: false, reason: "sentinel says no" }) });
    assert(result.pass === false, "sentinel reject must fail gate1");
    const f = result.findings.find((f) => f.code === "G1_SENTINEL_REJECT");
    assert(f && f.detail === "sentinel says no", "want sentinel reason surfaced");
    report("g1-11-sentinel-reject", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-11-sentinel-reject", "FAIL", e.message); }

  try {
    const candidate = { kind: "doc", fingerprint: "fp1", edits: [{ file: "docs/a.md", anchor: null, op: "replace", payload: "x", schema_ref: "doc/v1" }] };
    const result = gate.gate1Static(candidate, { ...CTX, sentinelHook: () => { throw new Error("sentinel exploded"); } });
    assert(result.pass === false, "sentinel throw must fail gate1, not crash it");
    const f = result.findings.find((f) => f.code === "G1_SENTINEL_ERROR");
    assert(f && /sentinel exploded/.test(f.detail), "want thrown message surfaced");
    report("g1-12-sentinel-throws", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-12-sentinel-throws", "FAIL", e.message); }

  try {
    /* INJECTION_MARKERS' /Function\s*\(/i pattern -- the only one of the 6
       injection markers with zero prior test coverage (the loop test 06d
       only exercises the other 5). */
    const candidate = {
      kind: "doc", fingerprint: "fp1",
      edits: [{ file: "docs/a.md", anchor: null, op: "replace", payload: "run new Function('return 1')() to escalate", schema_ref: "doc/v1" }],
    };
    const result = gate.gate1Static(candidate, CTX);
    assert(result.pass === false, "must reject Function( injection marker");
    assert(result.findings.some((f) => f.code === "G1_INJECTION"), "want G1_INJECTION");
    report("g1-13-injection-function-marker", "PASS", JSON.stringify(result.findings.map((f) => f.code)));
  } catch (e) { report("g1-13-injection-function-marker", "FAIL", e.message); }
}

/* ================================================================== */
/* resolvePair / classifyDiscordance -- retry recursion and fallback
   branches never exercised. Driven through the public gate2Behavioral
   entry point since resolvePair/classifyDiscordance aren't exported. */
/* ================================================================== */
function makeOkPair(id) {
  return { scenario_id: id, seed: 1, cand: { pass: true, cause_code: "ok" }, base: { pass: true, cause_code: "ok" } };
}
function makeCandWin(id) {
  return { scenario_id: id, seed: 1, cand: { pass: true, cause_code: "ok" }, base: { pass: false, cause_code: "ok" } };
}
function makeSyntheticBundle(pairs, overrides = {}) {
  const corpusHash = overrides.corpus_hash || sha256(pairs.map((p) => p.scenario_id).sort().join("\n"));
  const bundle = {
    schema_version: SCHEMA_VERSION,
    corpus_hash: corpusHash,
    evaluator_version: "1.0.0",
    model_versions: { candidate: overrides.candidateId || "cand", baseline: "base" },
    pairs,
    slices: overrides.slices || [],
  };
  bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
  return bundle;
}

/* 6 guaranteed candidate-wins provide power; specialPairs are assigned to
   the confirmation-split ids immediately after those 6. */
function buildResolvePairBundle(candidateId, specialPairs) {
  const POOL = 300;
  const allIds = Array.from({ length: POOL }, (_, i) => "rp-" + candidateId + "-" + i);
  const corpusHash = sha256(allIds.sort().join("\n"));
  const conf = allIds.filter((id) => gate.assignSplit(id, 0, corpusHash) === "confirmation");
  assert(conf.length >= 6 + specialPairs.length, "need enough confirmation ids: got " + conf.length);
  const winIds = conf.slice(0, 6);
  const winSet = new Set(winIds);
  const specialMap = new Map();
  specialPairs.forEach((p, i) => specialMap.set(conf[6 + i], p));
  const pairs = allIds.map((id) => {
    if (specialMap.has(id)) return { scenario_id: id, seed: 1, ...specialMap.get(id) };
    if (winSet.has(id)) return makeCandWin(id);
    return makeOkPair(id);
  });
  return makeSyntheticBundle(pairs, { candidateId, corpus_hash: corpusHash });
}

function attackResolvePairGaps() {
  try {
    const bundle = buildResolvePairBundle("rp-a", [
      { cand: { pass: false, cause_code: "infra_fault" }, cand_retry: { pass: true, cause_code: "ok" }, base: { pass: false, cause_code: "ok" } },
    ]);
    const result = gate.gate2Behavioral("rp-a", { bundle, cycleSeed: 0, stateStore: null, profile: "standard" });
    assert(result.primary, "need primary");
    assert(result.primary.verdict !== "inconclusive_underpowered", "must clear power precheck");
    assert(result.primary.wins === 7, `candidate_infra+cand_retry must resolve to a win: want wins=7 got ${result.primary.wins}`);
    assert(result.primary.excluded === 0, `must not still be excluded after retry: got excluded=${result.primary.excluded}`);
    report("rp-01-candidate-infra-retry-resolves-to-win", "PASS", `wins=${result.primary.wins} excluded=${result.primary.excluded}`);
  } catch (e) { report("rp-01-candidate-infra-retry-resolves-to-win", "FAIL", e.message); }

  try {
    const bundle = buildResolvePairBundle("rp-b", [
      {
        cand: { pass: false, cause_code: "infra_fault" }, cand_retry: { pass: true, cause_code: "ok" },
        base: { pass: false, cause_code: "infra_fault" }, base_retry: { pass: true, cause_code: "ok" },
      },
    ]);
    const result = gate.gate2Behavioral("rp-b", { bundle, cycleSeed: 0, stateStore: null, profile: "standard" });
    assert(result.primary, "need primary");
    assert(result.primary.verdict !== "inconclusive_underpowered", "must clear power precheck");
    assert(result.primary.wins === 6, `both_infra+both-retries resolving concordant must not add a win: want wins=6 got ${result.primary.wins}`);
    assert(result.primary.losses === 0, `must not be a loss: got losses=${result.primary.losses}`);
    assert(result.primary.excluded === 0, `must not still be excluded after double retry: got excluded=${result.primary.excluded}`);
    report("rp-02-both-infra-double-retry-resolves-concordant", "PASS", `wins=${result.primary.wins} losses=${result.primary.losses} excluded=${result.primary.excluded}`);
  } catch (e) { report("rp-02-both-infra-double-retry-resolves-concordant", "FAIL", e.message); }

  try {
    const bundle = buildResolvePairBundle("rp-c", [
      { cand: { pass: false, cause_code: "infra_fault" }, base: { pass: false, cause_code: "workflow_fault" } },
    ]);
    const result = gate.gate2Behavioral("rp-c", { bundle, cycleSeed: 0, stateStore: null, profile: "standard" });
    assert(result.primary, "need primary");
    assert(result.primary.wins === 6, `unrelated wins must be unaffected: want wins=6 got ${result.primary.wins}`);
    assert(result.primary.excluded === 1, `both_non_ok (cand infra + base workflow_fault) must be excluded: got excluded=${result.primary.excluded}`);
    report("rp-03-both-non-ok-excluded", "PASS", `wins=${result.primary.wins} excluded=${result.primary.excluded}`);
  } catch (e) { report("rp-03-both-non-ok-excluded", "FAIL", e.message); }

  try {
    const bundle = buildResolvePairBundle("rp-d", [
      { cand: { pass: true, cause_code: "some_unrecognized_code" }, base: { pass: true, cause_code: "ok" } },
    ]);
    const result = gate.gate2Behavioral("rp-d", { bundle, cycleSeed: 0, stateStore: null, profile: "standard" });
    assert(result.primary, "need primary");
    assert(result.primary.wins === 6, `unrelated wins must be unaffected: want wins=6 got ${result.primary.wins}`);
    assert(result.primary.excluded === 1, `unrecognized cause_code combo must fall through to "unknown"/excluded, not silently win or crash: got excluded=${result.primary.excluded}`);
    report("rp-04-unknown-cause-code-falls-through-excluded", "PASS", `wins=${result.primary.wins} excluded=${result.primary.excluded}`);
  } catch (e) { report("rp-04-unknown-cause-code-falls-through-excluded", "FAIL", e.message); }
}

/* ================================================================== */
/* decideGate2 -- maxAttainableN_d power-precheck condition
   `!(base.pass === true && base.cause_code === "ok")`. Every existing test
   pairs base.pass with a MATCHING cause_code ("ok"+true, non-"ok"+false).
   base.pass=true with a non-"ok" cause_code is the one combination that
   distinguishes a mutant checking only `pass` from one checking the
   full AND. */
/* ================================================================== */
function attackDecideGate2Gap() {
  try {
    const POOL = 300;
    const allIds = Array.from({ length: POOL }, (_, i) => "wf-pass-true-" + i);
    const corpusHash = sha256(allIds.sort().join("\n"));
    const conf = allIds.filter((id) => gate.assignSplit(id, 0, corpusHash) === "confirmation");
    assert(conf.length >= 6, "need >=6 confirmation ids");
    const specialIds = new Set(conf.slice(0, 6));
    const pairs = allIds.map((id) => {
      if (specialIds.has(id)) {
        return { scenario_id: id, seed: 1, cand: { pass: true, cause_code: "ok" }, base: { pass: true, cause_code: "workflow_fault" } };
      }
      return makeOkPair(id);
    });
    const bundle = makeSyntheticBundle(pairs, { candidateId: "wf-pass-true", corpus_hash: corpusHash });
    const result = gate.gate2Behavioral("wf-pass-true", { bundle, cycleSeed: 0, stateStore: null, profile: "standard" });
    assert(result.primary, "need primary");
    assert(
      result.primary.verdict !== "inconclusive_underpowered",
      `base.pass=true + non-"ok" cause_code must still count toward maxAttainableN_d (power precheck): verdict=${result.primary.verdict}`
    );
    assert(result.primary.excluded === 6, `all 6 must resolve to excluded (baseline_workflow_fault): got excluded=${result.primary.excluded}`);
    report("dg2-01-maxAttainableNd-basepass-true-nonok-causecode", "PASS", `verdict=${result.primary.verdict} excluded=${result.primary.excluded}`);
  } catch (e) { report("dg2-01-maxAttainableNd-basepass-true-nonok-causecode", "FAIL", e.message); }
}

/* ================================================================== */
/* gate3Prepare -- the two op-type switches (plainEnglish, invertEdit) are
   exercised end-to-end by exactly one existing test, and it only produces
   "replace" edits. This covers insert/delete/set-knob/unknown-op (default)
   in both switches in one candidate. */
/* ================================================================== */
function attackGate3Switches() {
  try {
    const candidate = {
      id: "c-g3", kind: "code", fingerprint: "fp-g3",
      edits: [
        { file: "scripts/a.js", anchor: "x1", op: "insert", payload: "new code" },
        { file: "scripts/a.js", anchor: "x2", op: "delete" },
        { file: "tunables/x.json", anchor: null, op: "set-knob", payload: 42, _originalValue: 7 },
        { file: "scripts/a.js", anchor: "x4", op: "weird-op-not-in-switch" },
      ],
    };
    const result = gate.gate3Prepare("c-g3", { candidate });

    assert(/Insert new content at scripts\/a\.js#x1/.test(result.plainEnglish), "want insert plainEnglish, got: " + result.plainEnglish);
    assert(/Delete content at scripts\/a\.js#x2/.test(result.plainEnglish), "want delete plainEnglish, got: " + result.plainEnglish);
    assert(/Set configuration knob at tunables\/x\.json to 42/.test(result.plainEnglish), "want set-knob plainEnglish, got: " + result.plainEnglish);
    assert(/Unknown operation on scripts\/a\.js#x4/.test(result.plainEnglish), "want default-branch plainEnglish, got: " + result.plainEnglish);

    assert(result.inverse.length === 3, `unknown op must invert to null and be filtered: want inverse.length=3 got ${result.inverse.length}`);
    assert(result.inverse[0].op === "delete", "insert must invert to delete");
    assert(result.inverse[1].op === "insert", "delete must invert to insert");
    assert(result.inverse[2].op === "set-knob" && result.inverse[2].payload === 7, "set-knob must invert to _originalValue");

    assert(result.reversible === false, `4 edits but only 3 invertible: reversible must be false, got ${result.reversible}`);
    assert(result.autoRollbackEligible === false, "code-kind candidate must never be autoRollbackEligible");

    report("g3-01-non-replace-op-switches", "PASS", `plainEnglish="${result.plainEnglish}" inverse.length=${result.inverse.length}`);
  } catch (e) { report("g3-01-non-replace-op-switches", "FAIL", e.message); }
}

/* ================================================================== */
/* gate4Admit / gate4Observe / gate4Close -- NEVER called by any existing
   test anywhere in the repo (confirmed via repo-wide grep). Tested here
   against a purpose-built mock stateStore, not state-store.js's own
   singleton or createStore() instance: state-store.js already has its own
   separate adversarial suite that verifies admitPending/registerRun/
   closeWindow correctness. gate.js's own job here is only to (a) guard
   against a missing/malformed stateStore and (b) map its own parameters
   onto whatever stateStore it's given -- a mock is the right tool for
   that, and it avoids coupling to global singleton state (which would
   also write real .graphsmith/state files into the repo as a side effect
   of running tests). */
/* ================================================================== */
function makeMockStateStore() {
  const calls = { admitPending: [], register: [], windowClose: [] };
  return {
    calls,
    admitPending: (tx) => { calls.admitPending.push(tx); return { ok: true, echo: tx }; },
    register: (runId, treeId) => { calls.register.push([runId, treeId]); return { ok: true, runId, treeId }; },
    window: { close: (windowId, outcome) => { calls.windowClose.push([windowId, outcome]); return { ok: true, windowId, outcome }; } },
  };
}

function attackGate4Functions() {
  /* gate4Admit guards */
  try {
    let threw = false;
    try { gate.gate4Admit("tx1", {}, null); } catch (e) { threw = /stateStore required for gate4Admit/.test(e.message); }
    assert(threw, "gate4Admit must throw on missing stateStore");
    report("g4-01-admit-guard-missing-store", "PASS", "");
  } catch (e) { report("g4-01-admit-guard-missing-store", "FAIL", e.message); }

  try {
    let threw = false;
    try { gate.gate4Admit("tx1", {}, {}); } catch (e) { threw = /stateStore required for gate4Admit/.test(e.message); }
    assert(threw, "gate4Admit must throw when admitPending is not a function");
    report("g4-02-admit-guard-malformed-store", "PASS", "");
  } catch (e) { report("g4-02-admit-guard-malformed-store", "FAIL", e.message); }

  /* gate4Admit parameter mapping -- explicit opts */
  try {
    const store = makeMockStateStore();
    gate.gate4Admit("tx1", { fingerprint: "fp1", treeId: "t1", n: 3, baselineMetric: 0.5, maxWindowMs: 9000 }, store);
    assert(store.calls.admitPending.length === 1, "must call admitPending exactly once");
    const tx = store.calls.admitPending[0];
    assert(tx.window_id === "tx1", `window_id: got ${tx.window_id}`);
    assert(tx.txid === "tx1", `txid: got ${tx.txid}`);
    assert(tx.candidate_fingerprint === "fp1", `candidate_fingerprint: got ${tx.candidate_fingerprint}`);
    assert(tx.tree_id === "t1", `tree_id: got ${tx.tree_id}`);
    assert(tx.n === 3, `n: got ${tx.n}`);
    assert(tx.baseline_metric === 0.5, `baseline_metric: got ${tx.baseline_metric}`);
    assert(tx.max_window_wall_time_ms === 9000, `max_window_wall_time_ms: got ${tx.max_window_wall_time_ms}`);
    report("g4-03-admit-param-mapping-explicit", "PASS", JSON.stringify(tx));
  } catch (e) { report("g4-03-admit-param-mapping-explicit", "FAIL", e.message); }

  /* gate4Admit parameter mapping -- defaults/fallbacks */
  try {
    const store = makeMockStateStore();
    gate.gate4Admit("tx2", {}, store);
    const tx = store.calls.admitPending[0];
    assert(tx.window_id === "tx2" && tx.txid === "tx2", "window_id/txid must both echo txid");
    assert(tx.candidate_fingerprint === "tx2", `candidate_fingerprint must default to txid: got ${tx.candidate_fingerprint}`);
    assert(tx.tree_id === "tx2", `tree_id must default to txid: got ${tx.tree_id}`);
    assert(tx.n === 5, `n must default to 5: got ${tx.n}`);
    assert(tx.baseline_metric === null, `baseline_metric must default to null: got ${tx.baseline_metric}`);
    report("g4-04-admit-param-mapping-defaults", "PASS", JSON.stringify(tx));
  } catch (e) { report("g4-04-admit-param-mapping-defaults", "FAIL", e.message); }

  /* gate4Observe guards */
  try {
    let threw = false;
    try { gate.gate4Observe({ runId: "r1", treeId: "t1" }, null); } catch (e) { threw = /stateStore required for gate4Observe/.test(e.message); }
    assert(threw, "gate4Observe must throw on missing stateStore");
    report("g4-05-observe-guard-missing-store", "PASS", "");
  } catch (e) { report("g4-05-observe-guard-missing-store", "FAIL", e.message); }

  try {
    const store = makeMockStateStore();
    let threw = false;
    try { gate.gate4Observe({}, store); } catch (e) { threw = /runResult must have runId and treeId/.test(e.message); }
    assert(threw, "gate4Observe must throw when runId/treeId missing");
    assert(store.calls.register.length === 0, "must not call register when validation fails");
    report("g4-06-observe-guard-missing-ids", "PASS", "");
  } catch (e) { report("g4-06-observe-guard-missing-ids", "FAIL", e.message); }

  /* gate4Observe field-name fallback: snake_case */
  try {
    const store = makeMockStateStore();
    const out = gate.gate4Observe({ run_id: "r1", tree_id: "t1" }, store);
    assert(store.calls.register.length === 1 && store.calls.register[0][0] === "r1" && store.calls.register[0][1] === "t1",
      `want register("r1","t1"), got ${JSON.stringify(store.calls.register)}`);
    assert(out && out.ok === true, "must return register()'s result");
    report("g4-07-observe-snake-case-fallback", "PASS", JSON.stringify(store.calls.register));
  } catch (e) { report("g4-07-observe-snake-case-fallback", "FAIL", e.message); }

  /* gate4Observe field-name fallback: camelCase (preferred over snake_case) */
  try {
    const store = makeMockStateStore();
    gate.gate4Observe({ runId: "r2", treeId: "t2", run_id: "wrong", tree_id: "wrong" }, store);
    assert(store.calls.register[0][0] === "r2" && store.calls.register[0][1] === "t2",
      `camelCase must win over snake_case: got ${JSON.stringify(store.calls.register)}`);
    report("g4-08-observe-camelcase-precedence", "PASS", JSON.stringify(store.calls.register));
  } catch (e) { report("g4-08-observe-camelcase-precedence", "FAIL", e.message); }

  /* gate4Close guards */
  try {
    let threw = false;
    try { gate.gate4Close("w1", "flagged", null); } catch (e) { threw = /stateStore required for gate4Close/.test(e.message); }
    assert(threw, "gate4Close must throw on missing stateStore");
    report("g4-09-close-guard-missing-store", "PASS", "");
  } catch (e) { report("g4-09-close-guard-missing-store", "FAIL", e.message); }

  try {
    let threw = false;
    try { gate.gate4Close("w1", "flagged", { window: {} }); } catch (e) { threw = /stateStore required for gate4Close/.test(e.message); }
    assert(threw, "gate4Close must throw when window.close is not a function");
    report("g4-10-close-guard-malformed-window", "PASS", "");
  } catch (e) { report("g4-10-close-guard-malformed-window", "FAIL", e.message); }

  try {
    const store = makeMockStateStore();
    const out = gate.gate4Close("w1", "rolled_back", store);
    assert(store.calls.windowClose.length === 1 && store.calls.windowClose[0][0] === "w1" && store.calls.windowClose[0][1] === "rolled_back",
      `want window.close("w1","rolled_back"), got ${JSON.stringify(store.calls.windowClose)}`);
    assert(out && out.ok === true, "must return window.close()'s result");
    report("g4-11-close-happy-path", "PASS", JSON.stringify(store.calls.windowClose));
  } catch (e) { report("g4-11-close-happy-path", "FAIL", e.message); }
}

/* ================================================================== */
/* CLI dispatch (cli()/parseArgs) -- gate modes 2/3/4 and the top-level
   selftest OR-chain are never invoked as a real subprocess by any existing
   test (only mode 1's reject path and --selftest are). This exercises the
   argument-extraction/guard/exit-code logic in each branch. Deep
   functional success paths for gate 2 (spawns scenario.js against a real
   corpus) and gate 4 (full admit/observe/close lifecycle) are deliberately
   OUT of scope here -- gate 2's decision engine is already covered via
   decideGate2/gate2Behavioral direct calls, and gate 4's own logic is unit
   tested above via the mock stateStore. This suite only needs to prove the
   CLI wiring reaches each branch with the right args/exit code. */
/* ================================================================== */
function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [GATE_PATH, ...args], { encoding: "utf8", cwd: opts.cwd || ROOT });
}

function attackCliDispatch() {
  try {
    const r = runCli([]);
    assert(r.status === 0, `bare invocation must run selftest, exit 0: got ${r.status}`);
    const out = JSON.parse(r.stdout);
    assert(out.status === "pass", `bare-invocation selftest must pass: ${JSON.stringify(out).slice(0, 200)}`);
    report("cli-01-bare-invocation-runs-selftest", "PASS", `exit=${r.status}`);
  } catch (e) { report("cli-01-bare-invocation-runs-selftest", "FAIL", e.message); }

  try {
    /* args.selftest flag must trigger selftest even when a gate number is
       also present -- distinct OR-branch from the literal "--selftest"
       positional already covered by the existing 09f test. */
    const r = runCli(["1", "--selftest"]);
    assert(r.status === 0, `--selftest flag must win over gate="1": got exit ${r.status}`);
    const out = JSON.parse(r.stdout);
    assert(out.status === "pass", "selftest must pass");
    report("cli-02-selftest-flag-overrides-gate-number", "PASS", `exit=${r.status}`);
  } catch (e) { report("cli-02-selftest-flag-overrides-gate-number", "FAIL", e.message); }

  try {
    const r = runCli(["2"]);
    assert(r.status === 2, `gate=2 without --candidate must exit 2: got ${r.status}`);
    assert(/--candidate <id> required/.test(r.stderr), `want candidate-required message, got: ${r.stderr}`);
    report("cli-03-gate2-missing-candidate", "PASS", `exit=${r.status} stderr=${r.stderr.trim()}`);
  } catch (e) { report("cli-03-gate2-missing-candidate", "FAIL", e.message); }

  try {
    const r = runCli(["3", "--candidate", "cid-no-file"]);
    assert(r.status === 0, `gate=3 without --file must still succeed with an empty candidate: got exit ${r.status}, stderr=${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert(out.candidateId === "cid-no-file", `want candidateId echoed, got ${out.candidateId}`);
    assert(Array.isArray(out.diff) && out.diff.length === 0, "empty candidate must produce empty diff");
    assert(out.reversible === true, "zero edits: inverse.length(0) === edits.length(0) must be reversible=true");
    report("cli-04-gate3-no-file-defaults-empty-candidate", "PASS", `exit=${r.status}`);
  } catch (e) { report("cli-04-gate3-no-file-defaults-empty-candidate", "FAIL", e.message); }

  try {
    const root = tempRoot("g3-badfile");
    try {
      const badPath = path.join(root, "not-json.txt");
      fs.writeFileSync(badPath, "{ not valid json", "utf8");
      const r = runCli(["3", "--candidate", "cid", "--file", badPath]);
      assert(r.status === 2, `gate=3 with unreadable --file must exit 2: got ${r.status}`);
      assert(/ERR: cannot read candidate/.test(r.stderr), `want cannot-read message, got: ${r.stderr}`);
      report("cli-05-gate3-bad-file-exits-2", "PASS", `exit=${r.status} stderr=${r.stderr.trim()}`);
    } finally { rmrf(root); }
  } catch (e) { report("cli-05-gate3-bad-file-exits-2", "FAIL", e.message); }

  try {
    const r = runCli(["4"]);
    assert(r.status === 2, `gate=4 with no flags must exit 2: got ${r.status}`);
    assert(/Usage: node scripts\/gate\.js 4/.test(r.stderr), `want gate-4 usage message, got: ${r.stderr}`);
    report("cli-06-gate4-no-flags-usage", "PASS", `exit=${r.status}`);
  } catch (e) { report("cli-06-gate4-no-flags-usage", "FAIL", e.message); }

  try {
    const root = tempRoot("g4-status");
    try {
      const r = runCli(["4", "--status"], { cwd: root });
      assert(r.status === 0, `gate=4 --status must exit 0 in a fresh project root: got ${r.status}, stderr=${r.stderr}`);
      const out = JSON.parse(r.stdout);
      assert(out.schema_version === SCHEMA_VERSION, "status must report schema_version");
      assert(Array.isArray(out.runs), "status must report runs array");
      report("cli-07-gate4-status", "PASS", `exit=${r.status}`);
    } finally { rmrf(root); }
  } catch (e) { report("cli-07-gate4-status", "FAIL", e.message); }

  try {
    const root = tempRoot("g4-observe");
    try {
      const r = runCli(["4", "--observe", "run-abc", "--tree", "tree-xyz"], { cwd: root });
      assert(r.status === 0, `gate=4 --observe must exit 0 in a fresh project root: got ${r.status}, stderr=${r.stderr}`);
      const out = JSON.parse(r.stdout);
      assert(out.registration && out.registration.run_id === "run-abc" && out.registration.tree_id === "tree-xyz",
        `want registration for run-abc/tree-xyz, got: ${JSON.stringify(out)}`);
      report("cli-08-gate4-observe", "PASS", `exit=${r.status}`);
    } finally { rmrf(root); }
  } catch (e) { report("cli-08-gate4-observe", "FAIL", e.message); }

  try {
    const root = tempRoot("g4-close");
    try {
      /* No window was ever admitted in this fresh root, so closeWindow()
         throws synchronously (WINDOW_NOT_FOUND) and cli() has no try/catch
         around gate 4's --close branch -- this still exercises the
         dispatch/parameter-extraction lines up to that throw. */
      const r = runCli(["4", "--close", "w-does-not-exist"], { cwd: root });
      assert(r.status !== 0, `gate=4 --close on an unknown window must not exit 0: got ${r.status}`);
      assert(/WINDOW_NOT_FOUND|Unknown window/.test(r.stderr), `want WINDOW_NOT_FOUND surfaced, got: ${r.stderr}`);
      report("cli-09-gate4-close-unknown-window", "PASS", `exit=${r.status}`);
    } finally { rmrf(root); }
  } catch (e) { report("cli-09-gate4-close-unknown-window", "FAIL", e.message); }

  try {
    const r = runCli(["9"]);
    assert(r.status === 2, `unknown gate number must exit 2: got ${r.status}`);
    assert(/Usage: node scripts\/gate\.js 1\|2\|3\|4/.test(r.stderr), `want top-level usage message, got: ${r.stderr}`);
    report("cli-10-unknown-gate-number-usage", "PASS", `exit=${r.status}`);
  } catch (e) { report("cli-10-unknown-gate-number-usage", "FAIL", e.message); }
}

/* ================================================================== */
function main() {
  console.log("gate.js coverage-gap triage suite");
  console.log("victim=" + GATE_PATH);
  attackGate1Gaps();
  attackResolvePairGaps();
  attackDecideGate2Gap();
  attackGate3Switches();
  attackGate4Functions();
  attackCliDispatch();

  const pass = results.filter((r) => r.status === "PASS").length;
  const fail = results.filter((r) => r.status === "FAIL").length;
  console.log("---");
  console.log(`TOTAL\tPASS=${pass}\tFAIL=${fail}`);
  process.exit(fail > 0 ? 1 : 0);
}

main();
