/* GraphSmith Attestation (GSA) plan + replay — scripts/gsa-plan.js.
 *   planDrift(prev, curr) — diff two bundles; flag DESTRUCTIVE changes (removed artifacts,
 *     changed outputs, mode downgrade, dropped profiles) so a human sees what a re-run would undo.
 *   replayBundle(bundle) — recompute the deterministic hashes from the bundle's own contents and
 *     confirm they match the manifest (deterministic reproduction). Model-dependent steps marked
 *     in the trace are reported non-replayable rather than failing (§9.11).
 * Pure (no network/clock/random). Reuses gsa-verify's canonicalize/sha256. Zero-dep CJS, Node >= 18.
 */
"use strict";
const { canonicalize, sha256Hex } = require("./gsa-verify.js");

// Artifacts whose content change is DESTRUCTIVE (a re-run would overwrite produced results).
const OUTPUT_ARTIFACTS = new Set(["output_manifest", "decision_record"]);
const MODE_RANK = { standard: 0, deterministic: 1, regulator: 2 };

function refMap(manifest) {
  const m = {};
  const arts = manifest && manifest.artifacts ? manifest.artifacts : {};
  for (const k of Object.keys(arts)) if (arts[k] && typeof arts[k].sha256 === "string") m[k] = arts[k].sha256;
  return m;
}

/* Diff two bundle manifests. Returns added/removed/changed artifact keys + a destructive[] list. */
function planDrift(prev, curr) {
  try {
    const pm = (prev && prev.manifest) || prev || {};
    const cm = (curr && curr.manifest) || curr || {};
    const a = refMap(pm), b = refMap(cm);
    const added = [], removed = [], changed = [], destructive = [];
    for (const k of Object.keys(b)) if (!(k in a)) added.push(k);
    for (const k of Object.keys(a)) if (!(k in b)) { removed.push(k); destructive.push({ kind: "artifact-removed", key: k }); }
    for (const k of Object.keys(a)) if (k in b && a[k] !== b[k]) {
      changed.push(k);
      if (OUTPUT_ARTIFACTS.has(k)) destructive.push({ kind: "output-changed", key: k });
    }
    // Mode downgrade (regulator -> standard) and dropped profiles are destructive assurance losses.
    if (MODE_RANK[cm.mode] < MODE_RANK[pm.mode]) destructive.push({ kind: "mode-downgrade", from: pm.mode, to: cm.mode });
    const pProf = new Set(Array.isArray(pm.profiles) ? pm.profiles : []);
    const cProf = new Set(Array.isArray(cm.profiles) ? cm.profiles : []);
    for (const p of pProf) if (!cProf.has(p)) destructive.push({ kind: "profile-dropped", profile: p });
    return { added, removed, changed, destructive, safe: destructive.length === 0 };
  } catch (e) {
    return { added: [], removed: [], changed: [], destructive: [{ kind: "error", detail: String(e && e.message || e) }], safe: false };
  }
}

const MODEL_DEP_MARKERS = ["model_call", "sampled", "nondeterministic", "llm_"];

/* Recompute deterministic hashes from the bundle's own contents; confirm they match the manifest. */
function replayBundle(bundle) {
  try {
    const m = bundle && bundle.manifest, c = (bundle && bundle.contents) || {};
    if (!m || !m.artifacts) return { reproducible: false, deterministic_confirmed: false, mismatches: ["no manifest/artifacts"], non_replayable: [] };
    const get = (key) => String(c[m.artifacts[key] && m.artifacts[key].path] || "");
    const mismatches = [];
    // Artifact-content hashes.
    for (const key of Object.keys(m.artifacts)) {
      const ref = m.artifacts[key];
      const body = c[ref.path];
      if (body === undefined) { mismatches.push("missing content: " + key); continue; }
      const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
      if (sha256Hex(buf) !== ref.sha256) mismatches.push("artifact hash drift: " + key);
    }
    // Plan hashes (graph/policy/skill-set) — the deterministic seal.
    const gs = m.graph_signature || {};
    if (sha256Hex(Buffer.from(get("compiled_graph"), "utf8")) !== gs.graph_hash) mismatches.push("graph_hash not reproducible");
    if (sha256Hex(Buffer.from(get("policy"), "utf8")) !== gs.policy_hash) mismatches.push("policy_hash not reproducible");
    const skills = Array.isArray(m.skills) ? m.skills : [];
    const ssh = sha256Hex(Buffer.from(canonicalize(skills.map((s) => ({ skill_id: s.skill_id, version: s.version, implementation_hash: s.implementation_hash })).sort((a, b) => (a.skill_id + a.version).localeCompare(b.skill_id + b.version))), "utf8"));
    if (ssh !== gs.skill_set_hash) mismatches.push("skill_set_hash not reproducible");
    // Model-dependent steps are honestly reported non-replayable, not failed.
    const trace = get("execution_trace");
    const non_replayable = MODEL_DEP_MARKERS.filter((mk) => trace.indexOf(mk) !== -1);
    return { reproducible: mismatches.length === 0, deterministic_confirmed: mismatches.length === 0, mismatches, non_replayable };
  } catch (e) {
    return { reproducible: false, deterministic_confirmed: false, mismatches: ["exception: " + String(e && e.message || e)], non_replayable: [] };
  }
}

module.exports = { planDrift, replayBundle };

if (require.main === module && process.argv.includes("--selftest")) {
  const crypto = require("crypto");
  const { produceBundle } = require("./gsa-produce.js");
  const kp = crypto.generateKeyPairSync("ed25519");
  const A = (path, body) => ({ path, body });
  const base = () => ({
    bundle_id: "gsa-" + "2".repeat(16), mode: "regulator", profiles: ["A", "X"], producer: { name: "graphsmith", version: "0.3.0" },
    artifacts: {
      goal: A("goal.txt", "g"), policy: A("policy.yaml", "mode: regulator"), model_manifest: A("model_manifest.json", "{}"),
      generated_ir: A("generated_ir.json", "{}"), compiled_graph: A("compiled_graph.json", '{"n":1}'), validation_report: A("validation_report.json", "{}"),
      execution_trace: A("execution_trace.jsonl", '{"step":1,"model_call":true}'), output_manifest: A("output_manifest.json", '{"out":"v1"}'), decision_record: A("decision_record.md", "# ok"),
      regulator_summary: A("regulator_summary.md", "# reg"),
    },
    skills: [{ skill_id: "s1", version: "1.0", implementation_hash: "a".repeat(64), source: "authored", approval_status: "approved", signature: "sig" }],
    adversarial: { suites: [{ name: "c", blocked: 5, total: 5 }] }, capabilities: { result: "satisfied", resources: {} },
  });
  const keys = { privateKey: kp.privateKey, signer: "k", algo: "ed25519" };
  const prev = produceBundle(base(), keys);
  // curr: change an output + drop to standard mode + drop a profile → all destructive.
  const r2 = base(); r2.artifacts.output_manifest = A("output_manifest.json", '{"out":"v2-CHANGED"}'); r2.mode = "standard"; delete r2.artifacts.regulator_summary; r2.profiles = ["A"];
  const curr = produceBundle(r2, keys);
  const drift = planDrift(prev, curr);
  const replay = replayBundle(prev);
  const destKinds = drift.destructive.map((d) => d.kind).sort();
  const pass = !drift.safe && destKinds.includes("output-changed") && destKinds.includes("mode-downgrade") && destKinds.includes("profile-dropped") &&
    replay.reproducible === true && replay.non_replayable.includes("model_call");
  console.log("gsa-plan selftest:", pass ? "OK" : "FAIL", "| destructive=" + JSON.stringify(destKinds), "replay-reproducible=" + replay.reproducible, "non-replayable=" + JSON.stringify(replay.non_replayable));
  process.exit(pass ? 0 : 1);
}
