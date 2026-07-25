/* Shared harness for the §9.11 extended-control council suites (tests/gsa-ext/harness.js).
 * Exports a signed-bundle builder so adversarial testers focus on ATTACKS, not crypto plumbing.
 * buildBundle({ traceBody?, claim?, evidence?, mutate? }) -> verifyBundle result {status, steps, ...}.
 *   - claim: the control_attestations_v040 object (omit for a v0.3.0-style bundle; §9.11 is then skipped).
 *   - evidence: overrides merged over EVIDENCE (capability_grant / effects / signer_registry / build_provenance).
 *   - mutate(manifest, contents): optional hook to tamper the manifest BEFORE it is signed.
 * Zero-dep, Node >= 18.
 */
"use strict";
const crypto = require("crypto");
const { verifyBundle, canonicalize, sha256Hex } = require("../../scripts/gsa-verify.js");
const provenance = require("../../checks/v040-provenance.js");

const kp = crypto.generateKeyPairSync("ed25519");
const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
const sign = (hex) => crypto.sign(null, Buffer.from(hex, "utf8"), kp.privateKey).toString("base64");
const tk = { k: pem };

const provComps = [{ path: "scripts/install.js", sha256: sha256Hex(Buffer.from("x", "utf8")) }];
const provActual = { "scripts/install.js": sha256Hex(Buffer.from("x", "utf8")) };
const provDigest = provenance.sbomDigest(provComps);

const EVIDENCE = {
  capability_grant: {
    grant: { schema_version: "1.0", grants: { network: { destinations: ["api.example.com"] } }, enforced: ["network"] },
    requested: { network: { destinations: ["api.example.com"] } }, attested: { network: true },
  },
  effects: [{ action: "send", receipt: { schema_version: "1.0", adapter_id: "a", action: "send", status: "success", external_id: "ext-1" } }],
  signer_registry: { signer: "k-sig", registry: { schema_version: "1.0", signers: [{ signer_id: "k-sig", public_key_pem: pem, status: "active" }] } },
  build_provenance: {
    sbom: { schema_version: "1.0", subject: { name: "graphsmith-skill", version: "0.4.0" }, components: provComps },
    provenance: { schema_version: "1.0", build_type: "https://graphsmith.dev/build/v1", builder: { id: "gh-actions" }, materials: provComps.map((c) => ({ path: c.path, sha256: c.sha256 })), subject: [{ name: "sbom", sha256: provDigest }] },
    actual: provActual,
  },
};
const ALL_TRUE = { capability_conformance: true, effects_reconciled: true, signer_trust: true, trace_redaction: true, build_provenance: true };

function buildBundle({ traceBody = '{"step":1,"status":"ok"}', claim, evidence = {}, mutate } = {}) {
  const c = {}, art = {};
  const add = (key, path, body) => { c[path] = body; art[key] = { path, sha256: sha256Hex(Buffer.from(body, "utf8")), bytes: Buffer.byteLength(body, "utf8") }; };
  add("goal", "goal.txt", "ship it"); add("policy", "policy.yaml", "mode: standard"); add("model_manifest", "model_manifest.json", "{}");
  add("generated_ir", "generated_ir.json", "{}"); add("compiled_graph", "compiled_graph.json", '{"nodes":1}'); add("validation_report", "validation_report.json", "{}");
  add("execution_trace", "execution_trace.jsonl", traceBody); add("output_manifest", "output_manifest.json", "{}"); add("decision_record", "decision_record.md", "# ok");
  const skills = [{ skill_id: "s1", version: "1.0", implementation_hash: "a".repeat(64), source: "authored", approval_status: "approved", signature: "sig" }];
  const graphHash = sha256Hex(Buffer.from(c["compiled_graph.json"], "utf8"));
  const policyHash = sha256Hex(Buffer.from(c["policy.yaml"], "utf8"));
  const skillSetHash = sha256Hex(Buffer.from(canonicalize(skills.map((s) => ({ skill_id: s.skill_id, version: s.version, implementation_hash: s.implementation_hash }))), "utf8"));
  const ev = { ...EVIDENCE, ...evidence };
  const m = {
    schema_version: "0.1", bundle_id: "gsa-" + "0".repeat(16), created: "unavailable", producer: { name: "graphsmith", version: "0.4.0" },
    mode: "standard", profiles: ["A", "X"], artifacts: art, skills,
    graph_signature: { graph_hash: graphHash, policy_hash: policyHash, skill_set_hash: skillSetHash, signer: "k", signed_at: "unavailable", algo: "ed25519", value: sign(graphHash + policyHash + skillSetHash) },
    capabilities: { result: "satisfied", resources: {} },
    control_attestations: { auto_skill_creation_disabled: true, all_skills_signed_and_approved: true, deterministic_mode: false, regulator_mode: false, adversarial_batteries_passed: true },
    adversarial: { suites: [{ name: "constitutional", blocked: 10, total: 10 }] },
    trace_mode: "full", capability_grant: ev.capability_grant, effects: ev.effects, signer_registry: ev.signer_registry, build_provenance: ev.build_provenance,
    bundle_signature: { algo: "ed25519", signer: "k", manifest_sha256: "", value: "" },
  };
  if (claim !== undefined) m.control_attestations_v040 = claim;
  if (typeof mutate === "function") mutate(m, c);
  const pre = { ...m }; delete pre.bundle_signature;
  const ph = sha256Hex(Buffer.from(canonicalize(pre), "utf8"));
  m.bundle_signature.manifest_sha256 = ph; m.bundle_signature.value = sign(ph);
  return verifyBundle({ manifest: m, contents: c }, { trustedKeys: tk });
}

module.exports = { buildBundle, EVIDENCE, ALL_TRUE, tk, pem, sha256Hex, provenance };
