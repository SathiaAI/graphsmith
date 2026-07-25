/* GSA conformance kit — scripts/gsa-conformance.js.
 * A portable, self-contained battery any GSA verifier implementation runs to check §9 conformance:
 * one valid bundle per mode + one negative per attack class, each expected to PASS or to FAIL at a
 * defined step. Emits an EVIDENCE-CARRYING badge (profile string + verifier version + platform +
 * date + result); unavailable profiles/steps never render green. Reuses gsa-produce/gsa-verify.
 * Zero-dep CJS, Node >= 18.   Run:  node scripts/gsa-conformance.js
 */
"use strict";
const crypto = require("crypto");
const { produceBundle } = require("./gsa-produce.js");
const { verifyBundle, canonicalize, sha256Hex } = require("./gsa-verify.js");

const VERIFIER_VERSION = "1.0";

function baseRun(mode) {
  const A = (path, body) => ({ path, body });
  const run = {
    bundle_id: "gsa-" + "c".repeat(16), mode, profiles: ["A", "X"], producer: { name: "graphsmith", version: "0.3.0" },
    artifacts: {
      goal: A("goal.txt", "g"), policy: A("policy.yaml", "mode: " + mode), model_manifest: A("model_manifest.json", "{}"),
      generated_ir: A("generated_ir.json", "{}"), compiled_graph: A("compiled_graph.json", '{"n":1}'), validation_report: A("validation_report.json", "{}"),
      execution_trace: A("execution_trace.jsonl", '{"step":1}'), output_manifest: A("output_manifest.json", "{}"), decision_record: A("decision_record.md", "# ok"),
    },
    skills: [{ skill_id: "s1", version: "1.0", implementation_hash: "a".repeat(64), source: "authored", approval_status: "approved", signature: "sig" }],
    adversarial: { suites: [{ name: "c", blocked: 5, total: 5 }] }, capabilities: { result: "satisfied", resources: {} },
  };
  if (mode === "regulator") run.artifacts.regulator_summary = A("regulator_summary.md", "# reg");
  if (mode === "regulator") run.control_mode_deterministic = true;
  return run;
}

/* Build the vector set. Each: { name, bundle, trustedKeys, expect } */
function buildVectors(kp) {
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  const keys = { privateKey: kp.privateKey, signer: "k", algo: "ed25519" };
  const tk = { k: pem };
  const reseal = (m) => { const p = { ...m }; delete p.bundle_signature; const h = sha256Hex(Buffer.from(canonicalize(p), "utf8")); m.bundle_signature.manifest_sha256 = h; m.bundle_signature.value = crypto.sign(null, Buffer.from(h, "utf8"), kp.privateKey).toString("base64"); return m; };
  const clone = (b) => ({ manifest: JSON.parse(JSON.stringify(b.manifest)), contents: { ...b.contents } });
  const V = [];
  const std = produceBundle(baseRun("standard"), keys);
  const reg = produceBundle(baseRun("regulator"), keys);
  V.push({ name: "valid-standard", bundle: std, trustedKeys: tk, expect: "PASS" });
  V.push({ name: "valid-regulator", bundle: reg, trustedKeys: tk, expect: "PASS" });
  // negatives
  let b;
  b = clone(std); b.contents["goal.txt"] = "TAMPERED"; V.push({ name: "neg-artifact-tamper", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); b.manifest.mode = "regulator"; V.push({ name: "neg-manifest-tamper-no-resign", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); b.manifest.bundle_signature.value = ""; V.push({ name: "neg-empty-signature", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); V.push({ name: "neg-untrusted-signer", bundle: b, trustedKeys: {}, expect: "FAIL" });
  b = clone(std); b.manifest.artifacts.goal.path = "../evil"; V.push({ name: "neg-path-traversal", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); b.manifest.control_attestations.adversarial_batteries_passed = false; reseal(b.manifest); V.push({ name: "neg-control-lie", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(reg); delete b.manifest.artifacts.regulator_summary; delete b.contents["regulator_summary.md"]; reseal(b.manifest); V.push({ name: "neg-regulator-missing-summary", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); b.manifest.artifacts.regulator_summary = { path: "regulator_summary.md", sha256: sha256Hex(Buffer.from("x", "utf8")), bytes: 1 }; b.contents["regulator_summary.md"] = "x"; reseal(b.manifest); V.push({ name: "neg-regulator-summary-wrong-mode", bundle: b, trustedKeys: tk, expect: "FAIL" });

  // v0.4.0 §9.11 extended-control vectors — the verifier recomputes a claimed control from the bundle's
  // own §9.3-verified execution_trace and fails closed on a lie. trace_redaction is the portable case.
  const setTrace = (bb, body) => { bb.contents["execution_trace.jsonl"] = body; bb.manifest.artifacts.execution_trace.sha256 = sha256Hex(Buffer.from(body, "utf8")); bb.manifest.artifacts.execution_trace.bytes = Buffer.byteLength(body, "utf8"); };
  b = clone(std); b.manifest.trace_mode = "full"; b.manifest.control_attestations_v040 = { trace_redaction: true }; reseal(b.manifest); V.push({ name: "valid-v040-trace-redaction", bundle: b, trustedKeys: tk, expect: "PASS" });
  b = clone(std); setTrace(b, '{"step":1,"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}'); b.manifest.trace_mode = "full"; b.manifest.control_attestations_v040 = { trace_redaction: true }; reseal(b.manifest); V.push({ name: "neg-v040-redaction-lie", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); b.manifest.control_attestations_v040 = { made_up_control: true }; reseal(b.manifest); V.push({ name: "neg-v040-unknown-control", bundle: b, trustedKeys: tk, expect: "FAIL" });
  b = clone(std); b.manifest.control_attestations_v040 = ["not", "an", "object"]; reseal(b.manifest); V.push({ name: "neg-v040-malformed-ext", bundle: b, trustedKeys: tk, expect: "FAIL" });
  return V;
}

function runConformance(vectors) {
  const results = vectors.map((v) => {
    let actual; try { actual = verifyBundle(v.bundle, { trustedKeys: v.trustedKeys }).status; } catch { actual = "THREW"; }
    return { name: v.name, expected: v.expect, actual, ok: actual === v.expect };
  });
  const passed = results.filter((r) => r.ok).length;
  const total = results.length;
  // Evidence-carrying badge: unavailable is explicit; conformance is N/N, never a bare "pass".
  const badge = "GSA-conformance verifier=" + VERIFIER_VERSION + " platform=" + process.platform + " node=" + process.version +
    " date=unavailable(no-clock-in-decision-path) result=" + passed + "/" + total + (passed === total ? " (all vectors matched)" : " (MISMATCH — not conformant)");
  return { results, passed, total, conformant: passed === total, badge };
}

module.exports = { buildVectors, runConformance };

if (require.main === module) {
  const kp = crypto.generateKeyPairSync("ed25519");
  const report = runConformance(buildVectors(kp));
  if (process.argv.includes("--selftest")) {
    const pass = report.conformant;
    console.log("gsa-conformance selftest:", pass ? "OK" : "FAIL", "| " + report.passed + "/" + report.total + " vectors matched expected");
    if (!pass) for (const r of report.results) if (!r.ok) console.log("  MISMATCH", r.name, "expected", r.expected, "got", r.actual);
    process.exit(pass ? 0 : 1);
  }
  for (const r of report.results) console.log("  " + (r.ok ? "ok  " : "XX  ") + r.name.padEnd(34) + " expected=" + r.expected + " actual=" + r.actual);
  console.log("");
  console.log("badge: " + report.badge);
  process.exit(report.conformant ? 0 : 1);
}
