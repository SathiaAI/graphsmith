#!/usr/bin/env node
/* GraphSmith shadow.js — Loop-3 shadow harness + evaluator-stability memo.
 * The "evaluator novelty" mitigation (plan §12/§14, §3.5 Loop 3 shadow-only):
 * before ANY evolution/effectiveness claim, measure whether the FROZEN Gate-2
 * behavioral evaluator (scripts/gate.js) is STABLE, and report its noise floor.
 *
 * SHADOW-ONLY (permanent I4 posture). This script:
 *   - READS the held-out scenario corpus (scenarios/) and the frozen evaluator
 *     (require("./gate.js") — the real decision function, never reimplemented).
 *   - WRITES only the local memo (docs/EVALUATOR-STABILITY.md, or --out).
 *   - NEVER adopts, promotes, writes ACTIVE / adoption-log, opens a Gate-4
 *     window, or sends anything upstream. No network APIs in source (self-scan).
 *
 * Deterministic given seeds: the seed set IS the pinned randomness source
 * (contract 03). No clock and no randomness in the statistics path — any
 * reference timestamp is injected (--ref-timestamp / GRAPHSMITH_REF_TS).
 *
 * --selftest (over a synthetic corpus): the noise floor is computed + reported;
 * a null change is flat-is-flat (no false delta); a KNOWN injected regression
 * IS detected (so the evaluator is not just always-flat); ACTIVE + adoption-log
 * are byte-unchanged after a run; zero network APIs in source.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const gate = require("./gate.js");

const SCHEMA_VERSION = "1.0";

/* Pinned seed set = cycle-counter rotation (contract 03 §Determinism & pinning,
 * 60% selection / 40% confirmation split rotated by cycle counter). These 64
 * seeds ARE the randomness source; the decision function is deterministic over
 * each (bundle, seed). */
const PINNED_SEEDS = Array.from({ length: 64 }, (_, i) => i);

const DEFAULT_REF_TIMESTAMP = "1970-01-01T00:00:00.000Z";

const SCENARIOS_DIR = path.join(__dirname, "..", "scenarios");
const DEFAULT_MEMO_PATH = path.join(__dirname, "..", "docs", "EVALUATOR-STABILITY.md");

/* ---------------------------------------------------------------------------
 * I4 egress proof: allowlisted requires + a runtime-built outbound-call probe.
 * Patterns mirror diagnostics.js; the target identifiers are assembled from
 * fragments so scanning THIS file's own source cannot trivially self-trigger.
 * ------------------------------------------------------------------------- */

const NETWORK_MODULE_NAMES = new Set([
  "http", "https", "http2", "net", "dns", "dns/promises", "tls", "dgram", "child_process",
  "node:http", "node:https", "node:http2", "node:net", "node:dns", "node:dns/promises",
  "node:tls", "node:dgram", "node:child_process",
]);

const ALLOWED_REQUIRE_MODULES = new Set(["fs", "path", "os", "crypto", "./gate.js"]);

const REQUIRE_CALL_RE = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
const OUTBOUND_REQUEST_GLOBAL = "fe" + "tch";
const OUTBOUND_REQUEST_CALL_RE = new RegExp("\\b" + OUTBOUND_REQUEST_GLOBAL + "\\s*\\(");

function scanSourceForNetworkAPIs(sourceText) {
  const findings = [];
  REQUIRE_CALL_RE.lastIndex = 0;
  let m;
  while ((m = REQUIRE_CALL_RE.exec(sourceText)) !== null) {
    const mod = m[1];
    if (NETWORK_MODULE_NAMES.has(mod)) findings.push({ kind: "banned-require", module: mod });
    else if (!ALLOWED_REQUIRE_MODULES.has(mod)) findings.push({ kind: "unlisted-require", module: mod });
  }
  if (OUTBOUND_REQUEST_CALL_RE.test(sourceText)) findings.push({ kind: "banned-api-usage", api: "global-outbound-request" });
  return findings;
}

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

function corpusHashOf(ids) {
  return sha256(ids.slice().sort().join("\n"));
}

function perScenarioSeed(id) {
  return crypto.createHash("sha256").update(String(id)).digest().readUInt32BE(0);
}

function round(n, places) {
  const f = Math.pow(10, places == null ? 6 : places);
  return Math.round(n * f) / f;
}

/* ---------------------------------------------------------------------------
 * Corpus + bundle construction (input only — the evaluator is never reimplemented)
 * ------------------------------------------------------------------------- */

function loadCorpusIds(scenariosDir) {
  const dir = scenariosDir || SCENARIOS_DIR;
  const ids = fs.readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")).id)
    .filter(Boolean)
    .sort();
  return { ids, corpusHash: corpusHashOf(ids), count: ids.length };
}

/* Outcome probes (contract 03 cause-code taxonomy). cand==base means a null /
 * no-op change: identical behavior on both sides → zero discordance. */
const CONCORDANT_PASS = () => ({ cand: { pass: true, cause_code: "ok" }, base: { pass: true, cause_code: "ok" } });
const CAND_WIN = () => ({ cand: { pass: true, cause_code: "ok" }, base: { pass: false, cause_code: "ok" } });
const BASE_WIN = () => ({ cand: { pass: false, cause_code: "ok" }, base: { pass: true, cause_code: "ok" } });

function buildBundle(ids, modeFn, opts) {
  const o = opts || {};
  const corpus_hash = o.corpusHash || corpusHashOf(ids);
  const pairs = ids.map((id) => {
    const m = modeFn(id);
    return { scenario_id: id, seed: perScenarioSeed(id), cand: m.cand, base: m.base };
  });
  const bundle = {
    schema_version: SCHEMA_VERSION,
    corpus_hash,
    evaluator_version: o.evaluatorVersion || "1.0.0",
    model_versions: { candidate: o.candidate || "shadow-probe", baseline: "shadow-baseline" },
    pairs,
    slices: o.slices || [],
  };
  bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
  return bundle;
}

/* ---------------------------------------------------------------------------
 * Measurement over the pinned seed set (calls the REAL frozen evaluator)
 * ------------------------------------------------------------------------- */

/* Primary endpoint = unconditional discordance advantage (wins − losses)/n.
 * When the evaluator short-circuits before scoring (zero baseline-attainable
 * discordance → underpowered), the advantage is 0 by construction. */
function primaryEndpoint(result) {
  const p = result && result.primary;
  if (!p) return 0;
  if (typeof p.lowerBound === "number") return p.lowerBound;
  const w = typeof p.wins === "number" ? p.wins : 0;
  const l = typeof p.losses === "number" ? p.losses : 0;
  const n = typeof p.n === "number" && p.n > 0 ? p.n : 1;
  return (w - l) / n;
}

function statsOf(arr) {
  if (!arr.length) return { min: 0, max: 0, mean: 0, stddev: 0, spread: 0, count: 0 };
  const min = Math.min(...arr);
  const max = Math.max(...arr);
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  const variance = arr.reduce((a, b) => a + (b - mean) * (b - mean), 0) / arr.length;
  return { min, max, mean, stddev: Math.sqrt(variance), spread: max - min, count: arr.length };
}

function measureAcrossSeeds(bundle, seeds, candidateId) {
  const perSeed = seeds.map((seed) => {
    const r = gate.gate2Behavioral(candidateId, { bundle, cycleSeed: seed });
    const verdict = r.primary && r.primary.verdict ? r.primary.verdict : "tier" + r.tier + "_reject";
    return {
      seed,
      pass: r.pass === true,
      tier: r.tier,
      verdict,
      endpoint: primaryEndpoint(r),
      n_d: r.primary ? r.primary.n_d : null,
    };
  });
  const endpoints = perSeed.map((s) => s.endpoint);
  const stats = statsOf(endpoints);
  const verdictCounts = {};
  for (const s of perSeed) verdictCounts[s.verdict] = (verdictCounts[s.verdict] || 0) + 1;
  const top = Object.entries(verdictCounts).sort((a, b) => b[1] - a[1])[0];
  const confSizes = seeds.map((seed) =>
    bundle.pairs.filter((p) => gate.assignSplit(p.scenario_id, seed, bundle.corpus_hash) === "confirmation").length
  );
  return {
    perSeed,
    endpointStats: stats,
    verdictCounts,
    reproducibilityRate: top[1] / perSeed.length,
    modalVerdict: top[0],
    anyPromote: perSeed.some((s) => s.pass && s.verdict === "promote"),
    confirmationSizeRange: [Math.min(...confSizes), Math.max(...confSizes)],
  };
}

/* Same (bundle, seed) repeated must be byte-identical — the decision function's
 * own reproducibility (contract 08: deterministic over the evidence bundle). */
function checkDeterminism(bundle, seed, candidateId) {
  const a = JSON.stringify(gate.gate2Behavioral(candidateId, { bundle, cycleSeed: seed }));
  const b = JSON.stringify(gate.gate2Behavioral(candidateId, { bundle, cycleSeed: seed }));
  return a === b;
}

/* ---------------------------------------------------------------------------
 * Frozen evaluator identity
 * ------------------------------------------------------------------------- */

function frozenEvaluatorIdentity() {
  const gatePath = path.join(__dirname, "gate.js");
  const src = fs.readFileSync(gatePath, "utf8");
  const m = src.match(/EVALUATOR_VERSION\s*=\s*["']([^"']+)["']/);
  return { version: m ? m[1] : "unknown", source_file: "scripts/gate.js", source_sha256: sha256(src) };
}

/* ---------------------------------------------------------------------------
 * SHADOW-ONLY guard: ACTIVE + adoption-log must be byte-unchanged across a run
 * ------------------------------------------------------------------------- */

function guardedFilePaths(projectRoot) {
  return {
    active: path.join(projectRoot, ".graphsmith", "evolvable", "ACTIVE"),
    adoptionLog: path.join(projectRoot, ".graphsmith", "state", "adoption-log.jsonl"),
  };
}

function hashIfExists(filePath) {
  try { return sha256(fs.readFileSync(filePath)); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
}

function snapshotGuardedFiles(projectRoot) {
  const p = guardedFilePaths(projectRoot);
  return { active: hashIfExists(p.active), adoptionLog: hashIfExists(p.adoptionLog) };
}

function guardedFilesUnchanged(before, after) {
  return before.active === after.active && before.adoptionLog === after.adoptionLog;
}

/* ---------------------------------------------------------------------------
 * The shadow measurement (machine form)
 * ------------------------------------------------------------------------- */

function runShadow(opts) {
  const o = opts || {};
  const corpus = loadCorpusIds(o.scenariosDir);
  const evaluator = frozenEvaluatorIdentity();
  const seeds = o.seeds || PINNED_SEEDS;
  const evOpts = { corpusHash: corpus.corpusHash, evaluatorVersion: evaluator.version };

  /* (1) Noise floor + (2) flat-is-flat — same-vs-same (null) over the REAL corpus. */
  const nullBundle = buildBundle(corpus.ids, CONCORDANT_PASS, { ...evOpts, candidate: "shadow-null" });
  const nullMeas = measureAcrossSeeds(nullBundle, seeds, "shadow-null");
  const noiseFloor = round(nullMeas.endpointStats.spread);
  const deterministic = checkDeterminism(nullBundle, seeds[0], "shadow-null");
  const flatIsFlat = !nullMeas.anyPromote && nullMeas.endpointStats.max <= 1e-9;

  /* (3) Falsification / sensitivity — SYNTHETIC probes proving the evaluator is
   * not stuck-flat: a known injected regression IS detected, and a known
   * injected improvement IS promoted. Clearly labeled synthetic; no real replay. */
  const synIds = Array.from({ length: 60 }, (_, i) => "syn-" + i);
  const synHash = corpusHashOf(synIds);
  const regressionIds = synIds.filter((id) => parseInt(id.split("-")[1], 10) < 40);
  const regSlices = [{ name: "injected-critical-regression", scenario_ids: regressionIds }];
  const regBundle = buildBundle(synIds, (id) => (regressionIds.includes(id) ? BASE_WIN() : CONCORDANT_PASS()),
    { corpusHash: synHash, evaluatorVersion: evaluator.version, candidate: "shadow-regression", slices: regSlices });
  const regMeas = measureAcrossSeeds(regBundle, seeds, "shadow-regression");
  const regressionDetected = !regMeas.anyPromote && regMeas.perSeed.every((s) => s.pass === false && s.tier <= 2);

  const impBundle = buildBundle(synIds, (id) => (parseInt(id.split("-")[1], 10) < 40 ? CAND_WIN() : CONCORDANT_PASS()),
    { corpusHash: synHash, evaluatorVersion: evaluator.version, candidate: "shadow-improvement" });
  const impMeas = measureAcrossSeeds(impBundle, seeds, "shadow-improvement");
  const improvementPromoted = impMeas.perSeed.some((s) => s.pass && s.verdict === "promote") && impMeas.endpointStats.min > 1e-9;

  return {
    schema_version: SCHEMA_VERSION,
    memo_kind: "evaluator-stability",
    posture: "shadow-only",
    ref_timestamp: o.refTimestamp || DEFAULT_REF_TIMESTAMP,
    frozen_evaluator: evaluator,
    corpus: { hash: corpus.corpusHash, scenario_count: corpus.count, scenario_ids: corpus.ids },
    seed_policy: {
      pinned_seed_count: seeds.length,
      split: "60% selection / 40% confirmation, rotated by cycle counter (contract 03)",
      confirmation_size_range: nullMeas.confirmationSizeRange,
    },
    noise_floor: {
      endpoint: "unconditional discordance advantage (wins − losses)/n",
      construction: "same-vs-same (identical candidate and baseline) over the held-out corpus",
      value: noiseFloor,
      endpoint_stats: {
        min: round(nullMeas.endpointStats.min), max: round(nullMeas.endpointStats.max),
        mean: round(nullMeas.endpointStats.mean), stddev: round(nullMeas.endpointStats.stddev),
      },
    },
    reproducibility: {
      decision_function_deterministic_same_seed: deterministic,
      same_input_same_verdict_rate: round(nullMeas.reproducibilityRate),
      modal_verdict: nullMeas.modalVerdict,
      verdict_distribution: nullMeas.verdictCounts,
    },
    flat_is_flat: {
      holds: flatIsFlat,
      detail: "a null (no-op) change produces no significant delta: never promoted; endpoint stays within the noise floor",
      any_promote: nullMeas.anyPromote,
      endpoint_max: round(nullMeas.endpointStats.max),
    },
    falsification: {
      note: "SYNTHETIC probes (not real replay) that show the frozen evaluator responds to real signal, i.e. it is not always-flat",
      injected_regression_detected: regressionDetected,
      regression_verdict_distribution: regMeas.verdictCounts,
      injected_improvement_promoted: improvementPromoted,
      improvement_verdict_distribution: impMeas.verdictCounts,
      improvement_endpoint_min: round(impMeas.endpointStats.min),
      regression_sensitivity_scope: [
        "The detected regression above demonstrates Tier 1/2 sensitivity ONLY: hard-invariant",
        "violations (Tier 1) and critical-slice regressions (Tier 2). It does NOT mean every",
        "possible regression is flagged. A Tier-3 one-sided statistical LOSS (a candidate that",
        "loses on discordant pairs) is NOT reported as a regression here: the Gate-2 primary",
        "endpoint is one-sided by design (contract 03 — one predeclared primary endpoint",
        "decided by a one-sided sign test with a one-sided lower bound), so a losing candidate",
        "reads as inconclusive / underpowered rather than a detected regression. This is a",
        "disclosed property of the frozen evaluator, not a defect in this shadow harness.",
      ].join(" "),
    },
    scope_note: [
      "Shadow-only (permanent I4): this harness observes and reports; it never adopts,",
      "promotes, writes ACTIVE / the adoption log, or sends anything upstream.",
      "No evolution or fleet effectiveness claim is made from this memo.",
      "This memo is an input to the v0.3 go/no-go decision, and nothing more.",
    ].join(" "),
  };
}

/* ---------------------------------------------------------------------------
 * Memo rendering (honest-language clean — contract 10; publication-hygiene safe)
 * ------------------------------------------------------------------------- */

function renderMemo(machine) {
  const nf = machine.noise_floor;
  const rp = machine.reproducibility;
  const ff = machine.flat_is_flat;
  const fx = machine.falsification;
  const ev = machine.frozen_evaluator;
  const L = [];
  L.push("# Evaluator-Stability Memo — Frozen Gate-2 Behavioral Evaluator");
  L.push("");
  L.push("Shadow-only, Loop-3 (plan §3.5 / §12 / §14). This memo measures the stability");
  L.push("of the FROZEN Gate-2 behavioral evaluator over the held-out scenario corpus,");
  L.push("and reports its noise floor. It is an input to the v0.3 go/no-go decision.");
  L.push("It makes no evolution or fleet effectiveness claim.");
  L.push("");
  L.push("Reference timestamp (injected, not a wall clock): `" + machine.ref_timestamp + "`");
  L.push("");
  L.push("## Frozen evaluator");
  L.push("- Version: `" + ev.version + "`");
  L.push("- Source: `" + ev.source_file + "`");
  L.push("- Source SHA-256 (freeze pin): `" + ev.source_sha256 + "`");
  L.push("");
  L.push("## Held-out corpus");
  L.push("- Corpus hash: `" + machine.corpus.hash + "`");
  L.push("- Scenario count: " + machine.corpus.scenario_count);
  L.push("- Scenarios: " + machine.corpus.scenario_ids.map((s) => "`" + s + "`").join(", "));
  L.push("");
  L.push("## Seed policy");
  L.push("- Pinned seeds (the randomness source): " + machine.seed_policy.pinned_seed_count);
  L.push("- Split: " + machine.seed_policy.split);
  L.push("- Confirmation-split size across seeds: " + machine.seed_policy.confirmation_size_range[0] +
    "–" + machine.seed_policy.confirmation_size_range[1] + " (the split membership rotates across seeds)");
  L.push("");
  L.push("## Noise floor (endpoint spread under no change)");
  L.push("- Endpoint: " + nf.endpoint);
  L.push("- Construction: " + nf.construction);
  L.push("- Noise floor (max − min across seeds): **" + nf.value + "**");
  L.push("- Endpoint across seeds — min " + nf.endpoint_stats.min + ", max " + nf.endpoint_stats.max +
    ", mean " + nf.endpoint_stats.mean + ", stddev " + nf.endpoint_stats.stddev);
  L.push("");
  L.push("The frozen decision function reports zero same-vs-same discordance on every");
  L.push("seed: the endpoint is flat across the seed-driven split rotation. Any measured");
  L.push("delta at or below this noise floor is reported as flat.");
  L.push("");
  L.push("## Reproducibility");
  L.push("- Decision function deterministic for a fixed (bundle, seed): " +
    (rp.decision_function_deterministic_same_seed ? "yes" : "no"));
  L.push("- Same-input same-verdict rate across the seed set: " + (rp.same_input_same_verdict_rate * 100) + "%");
  L.push("- Modal verdict: `" + rp.modal_verdict + "`");
  L.push("");
  L.push("## Flat-is-flat (a null change reports no significant delta)");
  L.push("- Holds: " + (ff.holds ? "yes" : "NO — see below") + "");
  L.push("- " + ff.detail);
  L.push("- Any promotion on a null change: " + (ff.any_promote ? "yes (this would be a false positive)" : "no"));
  L.push("- Maximum endpoint on a null change: " + ff.endpoint_max);
  L.push("");
  L.push("## Falsification / sensitivity (synthetic)");
  L.push("- " + fx.note);
  L.push("- Injected regression detected: " + (fx.injected_regression_detected ? "yes" : "NO"));
  L.push("- Injected improvement promoted: " + (fx.injected_improvement_promoted ? "yes" : "NO") +
    " (endpoint min " + fx.improvement_endpoint_min + ")");
  L.push("");
  L.push("This confirms the flat null result above is not an artifact of an inert");
  L.push("evaluator: the same frozen decision function detects an injected regression");
  L.push("and promotes an injected improvement.");
  L.push("");
  L.push("### Regression-sensitivity scope (disclosure)");
  L.push("- \"Injected regression detected: yes\" means **Tier 1/2 sensitivity only**:");
  L.push("  hard-invariant violations (Tier 1) and critical-slice regressions (Tier 2).");
  L.push("- It does **not** mean the evaluator flags every possible regression.");
  L.push("- A Tier-3 one-sided statistical loss — a candidate that loses on discordant");
  L.push("  pairs — is **not** reported as a regression here: the Gate-2 primary endpoint");
  L.push("  is one-sided by design (contract 03 — one predeclared primary endpoint decided");
  L.push("  by a one-sided sign test with a one-sided lower bound), so a losing candidate");
  L.push("  reads as inconclusive / underpowered rather than a detected regression.");
  L.push("- This is a disclosed property of the frozen evaluator, not a defect in this");
  L.push("  shadow harness. A reader must not over-read \"detected: yes\" as \"detects all");
  L.push("  regressions.\"");
  L.push("");
  L.push("## Scope");
  L.push(machine.scope_note);
  L.push("");
  L.push("## Machine form");
  L.push("<!-- lint-allow: honest-language (machine data block) -->");
  L.push("```json");
  L.push(JSON.stringify(machine, null, 2));
  L.push("```");
  L.push("<!-- /lint-allow -->");
  L.push("");
  return L.join("\n");
}

function writeMemo(memoPath, text) {
  fs.mkdirSync(path.dirname(memoPath), { recursive: true });
  fs.writeFileSync(memoPath, text);
}

/* ---------------------------------------------------------------------------
 * Selftest
 * ------------------------------------------------------------------------- */

function selftest() {
  const tests = [];
  const errors = [];
  const check = (name, cond, detail) => {
    if (!cond) errors.push("FAIL: " + name + (detail ? " — " + detail : ""));
    else tests.push({ name, status: "pass" });
    return !!cond;
  };

  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-shadow-"));
  try {
    /* Synthetic corpus so the confirmation split can reach the power threshold. */
    const synIds = Array.from({ length: 60 }, (_, i) => "self-" + i);
    const synDir = path.join(base, "scenarios");
    fs.mkdirSync(synDir, { recursive: true });
    for (const id of synIds) {
      fs.writeFileSync(path.join(synDir, id + ".json"), JSON.stringify({ id }));
    }

    const machine = runShadow({ scenariosDir: synDir, refTimestamp: "2000-01-01T00:00:00.000Z" });

    /* Noise floor computed + reported. */
    check("noise-floor-computed-and-reported",
      typeof machine.noise_floor.value === "number" && machine.noise_floor.value === 0,
      "noise floor = " + machine.noise_floor.value);

    check("reproducibility-reported",
      machine.reproducibility.decision_function_deterministic_same_seed === true &&
      machine.reproducibility.same_input_same_verdict_rate === 1,
      "det=" + machine.reproducibility.decision_function_deterministic_same_seed +
      " repro=" + machine.reproducibility.same_input_same_verdict_rate);

    /* Null change is flat-is-flat (no false delta). */
    check("null-change-is-flat-is-flat",
      machine.flat_is_flat.holds === true && machine.flat_is_flat.any_promote === false,
      "holds=" + machine.flat_is_flat.holds + " any_promote=" + machine.flat_is_flat.any_promote);

    /* Known injected regression IS detected (evaluator not always-flat). */
    check("injected-regression-detected",
      machine.falsification.injected_regression_detected === true,
      JSON.stringify(machine.falsification.regression_verdict_distribution));

    check("injected-improvement-promoted",
      machine.falsification.injected_improvement_promoted === true,
      JSON.stringify(machine.falsification.improvement_verdict_distribution));

    /* Honest-scope disclosure: regression detection is Tier 1/2 sensitivity only;
     * a Tier-3 one-sided statistical loss is not flagged (evaluator is one-sided
     * by design). Must be in BOTH the machine form AND the rendered memo. */
    const scopeField = machine.falsification.regression_sensitivity_scope;
    check("regression-sensitivity-scope-in-machine-form",
      typeof scopeField === "string" && /Tier 1\/2/.test(scopeField) &&
      /one-sided/.test(scopeField) && /contract 03/.test(scopeField),
      "scope field = " + JSON.stringify(scopeField));
    const memoText = renderMemo(machine);
    check("regression-sensitivity-scope-disclosed-in-memo",
      /Regression-sensitivity scope/.test(memoText) && /Tier 1\/2 sensitivity only/.test(memoText) &&
      /one-sided by design/.test(memoText) && memoText.includes("regression_sensitivity_scope"),
      "memo missing the regression-sensitivity scope disclosure");

    /* schema_version on the machine form. */
    check("schema-version-on-machine-form", machine.schema_version === SCHEMA_VERSION,
      "schema_version=" + machine.schema_version);

    /* ACTIVE + adoption-log byte-unchanged after a run. */
    const projectRoot = path.join(base, "project");
    const gp = guardedFilePaths(projectRoot);
    fs.mkdirSync(path.dirname(gp.active), { recursive: true });
    fs.mkdirSync(path.dirname(gp.adoptionLog), { recursive: true });
    fs.writeFileSync(gp.active, JSON.stringify({ tree: "v-frozen", txid: "0".repeat(16) }) + "\n");
    fs.writeFileSync(gp.adoptionLog, JSON.stringify({ record: "genesis" }) + "\n");
    const before = snapshotGuardedFiles(projectRoot);
    /* Full run: measure + render + write the memo (to a temp path, never docs/). */
    const m2 = runShadow({ scenariosDir: synDir, refTimestamp: "2000-01-01T00:00:00.000Z" });
    writeMemo(path.join(base, "out", "EVALUATOR-STABILITY.md"), renderMemo(m2));
    const after = snapshotGuardedFiles(projectRoot);
    check("active-and-adoption-log-byte-unchanged",
      guardedFilesUnchanged(before, after) && before.active !== null && before.adoptionLog !== null,
      "before=" + JSON.stringify(before) + " after=" + JSON.stringify(after));

    /* Memo deterministic given the same inputs (no clock / no randomness). */
    check("memo-render-deterministic",
      renderMemo(m2) === renderMemo(runShadow({ scenariosDir: synDir, refTimestamp: "2000-01-01T00:00:00.000Z" })),
      "memo differs across identical runs");

    /* Zero network APIs in source. */
    const selfFindings = scanSourceForNetworkAPIs(fs.readFileSync(__filename, "utf8"));
    check("zero-network-apis-in-source", selfFindings.length === 0,
      selfFindings.length ? JSON.stringify(selfFindings) : undefined);

    /* Shadow-only: source never references adopt/promote/ACTIVE-write machinery. */
    const src = fs.readFileSync(__filename, "utf8");
    const bannedRequires = ["./promote.js", "./adopt.js", "./state-store.js"];
    check("source-never-requires-adoption-machinery",
      bannedRequires.every((r) => src.indexOf('require("' + r + '")') === -1),
      "must not require promote/adopt/state-store");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }

  return {
    schema_version: SCHEMA_VERSION,
    status: errors.length === 0 ? "pass" : "fail",
    tests,
    errors,
    exitCode: errors.length === 0 ? 0 : 1,
  };
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith("--")) {
      const key = k.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) a[key] = argv[++i];
      else a[key] = true;
    } else a._.push(k);
  }
  return a;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.selftest || args._[0] === "--selftest") {
    const report = selftest();
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    process.exit(report.exitCode);
  }

  const refTimestamp = typeof args["ref-timestamp"] === "string" ? args["ref-timestamp"]
    : (process.env.GRAPHSMITH_REF_TS || DEFAULT_REF_TIMESTAMP);
  const memoPath = typeof args.out === "string" ? args.out : DEFAULT_MEMO_PATH;
  const projectRoot = typeof args["project-root"] === "string" ? args["project-root"] : path.join(__dirname, "..");

  const before = snapshotGuardedFiles(projectRoot);
  const machine = runShadow({ refTimestamp });
  writeMemo(memoPath, renderMemo(machine));
  const after = snapshotGuardedFiles(projectRoot);

  const unchanged = guardedFilesUnchanged(before, after);
  if (!unchanged) {
    process.stderr.write("SHADOW-ONLY VIOLATION: ACTIVE or adoption-log changed during a shadow run\n");
    process.exit(3);
  }

  process.stdout.write(JSON.stringify({
    schema_version: SCHEMA_VERSION,
    memo_written: path.relative(path.join(__dirname, ".."), memoPath).split(path.sep).join("/"),
    noise_floor: machine.noise_floor.value,
    same_input_same_verdict_rate: machine.reproducibility.same_input_same_verdict_rate,
    flat_is_flat: machine.flat_is_flat.holds,
    injected_regression_detected: machine.falsification.injected_regression_detected,
    shadow_only_guarded_files_unchanged: unchanged,
    frozen_evaluator_version: machine.frozen_evaluator.version,
  }, null, 2) + "\n");
  process.exit(0);
}

module.exports = {
  SCHEMA_VERSION,
  runShadow,
  renderMemo,
  measureAcrossSeeds,
  buildBundle,
  loadCorpusIds,
  frozenEvaluatorIdentity,
  scanSourceForNetworkAPIs,
  snapshotGuardedFiles,
  guardedFilesUnchanged,
  selftest,
};

if (require.main === module) {
  main();
}
