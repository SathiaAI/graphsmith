/* GraphSmith v0.4.0 Wave 2 — §9.11 extended-control integration regression test (tests/gsa-ext/validate.js).
 * Builds a fully valid, signed GSA bundle that declares ALL FIVE v0.4.0 extended controls with real
 * evidence (must PASS), then lies about each control one at a time (each must FAIL closed), plus
 * malformed / unknown-key / backward-compat cases. Proves gsa-verify.js §9.11 recomputes every control
 * through its checks/v040-*.js module and never trusts a claimed control (D5). Zero-dep, Node >= 18.
 */
"use strict";
const crypto = require("crypto");
const { verifyBundle, canonicalize, sha256Hex } = require("../../scripts/gsa-verify.js");
const provenance = require("../../checks/v040-provenance.js");

let pass = 0, fail = 0;
const test = (name, fn) => { try { if (fn() === true) { console.log("PASS " + name); pass++; } else { console.log("FAIL " + name); fail++; } } catch (e) { console.log("FAIL " + name + " threw " + e.message); fail++; } };

// ---- signing infra (test harness; not a decision path) ----
const kp = crypto.generateKeyPairSync("ed25519");
const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
const sign = (hex) => crypto.sign(null, Buffer.from(hex, "utf8"), kp.privateKey).toString("base64");
const tk = { k: pem };

// ---- valid evidence for each of the five controls ----
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

// ---- build a signed bundle with a given trace body, extended-control claim, and evidence overrides ----
function buildBundle({ traceBody = '{"step":1,"status":"ok"}', claim, evidence = {} } = {}) {
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
    // v0.4.0 extended surface:
    trace_mode: "full", capability_grant: ev.capability_grant, effects: ev.effects, signer_registry: ev.signer_registry, build_provenance: ev.build_provenance,
    bundle_signature: { algo: "ed25519", signer: "k", manifest_sha256: "", value: "" },
  };
  if (claim !== undefined) m.control_attestations_v040 = claim;
  const pre = { ...m }; delete pre.bundle_signature;
  const ph = sha256Hex(Buffer.from(canonicalize(pre), "utf8"));
  m.bundle_signature.manifest_sha256 = ph; m.bundle_signature.value = sign(ph);
  return verifyBundle({ manifest: m, contents: c }, { trustedKeys: tk });
}

const ALL_TRUE = { capability_conformance: true, effects_reconciled: true, signer_trust: true, trace_redaction: true, build_provenance: true };

// 1. Fully valid extended bundle — every control claimed true with real evidence → PASS.
test("all-five-controls-valid", () => buildBundle({ claim: ALL_TRUE }).status === "PASS");

// 2. Per-control LIES: break the evidence for one control while still claiming true → each FAILs closed.
test("lie-capability (requested exceeds grant)", () => buildBundle({ claim: ALL_TRUE, evidence: { capability_grant: { grant: { schema_version: "1.0", grants: { network: { destinations: ["a.com"] } }, enforced: ["network"] }, requested: { network: { destinations: ["evil.com"] } }, attested: { network: true } } } }).status === "FAIL");
test("lie-effects (unreconciled: success w/o external_id)", () => buildBundle({ claim: ALL_TRUE, evidence: { effects: [{ action: "send", receipt: { schema_version: "1.0", adapter_id: "a", action: "send", status: "success" } }] } }).status === "FAIL");
test("lie-signer (revoked signer)", () => buildBundle({ claim: ALL_TRUE, evidence: { signer_registry: { signer: "k-sig", registry: { schema_version: "1.0", signers: [{ signer_id: "k-sig", public_key_pem: pem, status: "revoked" }] } } } }).status === "FAIL");
test("lie-trace (leaky trace claims redaction)", () => buildBundle({ claim: ALL_TRUE, traceBody: '{"step":1,"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}' }).status === "FAIL");
test("lie-provenance (tampered actual hash)", () => buildBundle({ claim: ALL_TRUE, evidence: { build_provenance: { ...EVIDENCE.build_provenance, actual: { "scripts/install.js": sha256Hex(Buffer.from("TAMPERED", "utf8")) } } } }).status === "FAIL");

// 3. A subset claim with honest evidence verifies (declared-only; controls you don't claim aren't required).
test("subset-claim-valid", () => buildBundle({ claim: { trace_redaction: true, signer_trust: true } }).status === "PASS");

// 4. Honest "false" about a broken control passes (§9.11 catches lies, not the underlying condition).
test("honest-false-not-a-lie", () => buildBundle({ claim: { ...ALL_TRUE, trace_redaction: false }, traceBody: '{"step":1,"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}' }).status === "PASS");

// 5. Malformed / unknown extended keys fail closed.
test("malformed-ext-not-object", () => buildBundle({ claim: [1, 2, 3] }).status === "FAIL");
test("unknown-ext-control-key", () => buildBundle({ claim: { capability_conformance: true, made_up_control: true } }).status === "FAIL");

// 6. Backward-compat: a bundle with NO extended-control key verifies unchanged (§9.11 skipped).
test("backward-compat-no-ext-key", () => buildBundle({ claim: undefined }).status === "PASS");

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
