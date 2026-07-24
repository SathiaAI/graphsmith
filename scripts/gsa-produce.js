/* GraphSmith Attestation (GSA) producer — scripts/gsa-produce.js.
 * Seals one workflow run into a signed, verifiable GSA bundle (manifest + artifacts) that
 * scripts/gsa-verify.js accepts. HONEST BY CONSTRUCTION: control attestations are RECOMPUTED
 * from the run's own skills/mode/trace/adversarial results — the producer never asserts a control
 * the evidence doesn't support (a bundle that lied would fail its own §9 verification anyway).
 *
 * Discipline: pure (no network/clock/random in the sealing path — timestamps that a run carries
 * are recorded as 'unavailable' unless supplied as data, never read from the clock here). Reuses
 * gsa-verify's canonicalize/sha256 so the produce/verify hashing is single-source.
 * Zero-dep CJS, Node >= 18.
 */
"use strict";
const crypto = require("crypto");
const { canonicalize, sha256Hex, verifyBundle } = require("./gsa-verify.js");

const NONDET = ["skill_generated", "auto_promote", "remote_registry_fetch", "runtime_graph_modification", "unbounded_repair", "undeclared_network"];

/* Recompute the five control attestations from the run — identical logic to the verifier, so a
 * produced bundle always matches its own recomputation (honest by construction). */
function computeControls(skills, mode, traceStr, adversarial, hasRegulatorSummary, revoked) {
  revoked = revoked instanceof Set ? revoked : new Set();
  const suites = adversarial && Array.isArray(adversarial.suites) ? adversarial.suites : [];
  return {
    auto_skill_creation_disabled: !skills.some((s) => s.source === "generated" && s.approval_status !== "approved"),
    all_skills_signed_and_approved: skills.length > 0 && skills.every((s) => typeof s.signature === "string" && s.signature.length > 0 && s.approval_status === "approved" && !revoked.has(s.implementation_hash)),
    deterministic_mode: (mode === "deterministic" || mode === "regulator") && !NONDET.some((mk) => traceStr.indexOf(mk) !== -1),
    regulator_mode: mode === "regulator" && hasRegulatorSummary,
    adversarial_batteries_passed: suites.length > 0 && suites.every((s) => s && s.blocked === s.total && s.total > 0),
  };
}

/* run = {
 *   bundle_id, mode, profiles:[], producer:{name,version},
 *   artifacts: { goal, policy, model_manifest, generated_ir, compiled_graph, validation_report,
 *                execution_trace, output_manifest, decision_record, [repair_log], [adversarial_report],
 *                [regulator_summary] }  // each value is { path, body:string }
 *   skills:[], adversarial:{suites}, capabilities:{result,resources}
 * }
 * keys = { privateKey (KeyObject), signer, algo }  */
function produceBundle(run, keys) {
  if (!run || typeof run !== "object") throw new Error("produceBundle: run required");
  if (!keys || !keys.privateKey || typeof keys.signer !== "string") throw new Error("produceBundle: signing key + signer required");
  const algo = keys.algo || "ed25519";
  const sign = (hex) => {
    if (algo === "ed25519") return crypto.sign(null, Buffer.from(hex, "utf8"), keys.privateKey).toString("base64");
    if (algo === "ecdsa-p256-sha256") return crypto.sign("sha256", Buffer.from(hex, "utf8"), keys.privateKey).toString("base64");
    if (algo === "rsa-pss-sha256") return crypto.sign("sha256", { key: keys.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, Buffer.from(hex, "utf8")).toString("base64");
    throw new Error("unsupported algo " + algo);
  };

  const contents = {};
  const artifacts = {};
  for (const key of Object.keys(run.artifacts || {})) {
    const a = run.artifacts[key];
    const body = String(a.body);
    contents[a.path] = body;
    artifacts[key] = { path: a.path, sha256: sha256Hex(Buffer.from(body, "utf8")), bytes: Buffer.byteLength(body, "utf8") };
  }

  const skills = Array.isArray(run.skills) ? run.skills : [];
  const traceStr = String((run.artifacts.execution_trace && run.artifacts.execution_trace.body) || "");
  const hasRegSummary = Object.prototype.hasOwnProperty.call(artifacts, "regulator_summary");

  const graphHash = sha256Hex(Buffer.from(String(run.artifacts.compiled_graph.body), "utf8"));
  const policyHash = sha256Hex(Buffer.from(String(run.artifacts.policy.body), "utf8"));
  const skillSetHash = sha256Hex(Buffer.from(canonicalize(skills.map((s) => ({ skill_id: s.skill_id, version: s.version, implementation_hash: s.implementation_hash })).sort((a, b) => (a.skill_id + a.version).localeCompare(b.skill_id + b.version))), "utf8"));

  const manifest = {
    schema_version: "0.1",
    bundle_id: run.bundle_id,
    created: run.created || "unavailable",           // no clock read here; a run supplies it as data or it's unavailable
    producer: run.producer,
    mode: run.mode,
    profiles: run.profiles || [],
    artifacts,
    skills,
    graph_signature: { graph_hash: graphHash, policy_hash: policyHash, skill_set_hash: skillSetHash, signer: keys.signer, signed_at: run.signed_at || "unavailable", algo, value: sign(graphHash + policyHash + skillSetHash) },
    capabilities: run.capabilities || { result: "satisfied", resources: {} },
    control_attestations: computeControls(skills, run.mode, traceStr, run.adversarial, hasRegSummary, keys.revoked),
    adversarial: run.adversarial || { suites: [] },
    bundle_signature: { algo, signer: keys.signer, manifest_sha256: "", value: "" },
  };
  const preimage = { ...manifest }; delete preimage.bundle_signature;
  const manifestSha = sha256Hex(Buffer.from(canonicalize(preimage), "utf8"));
  manifest.bundle_signature.manifest_sha256 = manifestSha;
  manifest.bundle_signature.value = sign(manifestSha);

  return { manifest, contents };
}

module.exports = { produceBundle, computeControls };

if (require.main === module && process.argv.includes("--selftest")) {
  const kp = crypto.generateKeyPairSync("ed25519");
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  const A = (path, body) => ({ path, body });
  const run = {
    bundle_id: "gsa-" + "1".repeat(16), mode: "standard", profiles: ["A", "X"], producer: { name: "graphsmith", version: "0.3.0" },
    artifacts: {
      goal: A("goal.txt", "ship it"), policy: A("policy.yaml", "mode: standard"), model_manifest: A("model_manifest.json", "{}"),
      generated_ir: A("generated_ir.json", "{}"), compiled_graph: A("compiled_graph.json", '{"nodes":2}'), validation_report: A("validation_report.json", "{}"),
      execution_trace: A("execution_trace.jsonl", '{"step":1}'), output_manifest: A("output_manifest.json", "{}"), decision_record: A("decision_record.md", "# ok"),
    },
    skills: [{ skill_id: "s1", version: "1.0", implementation_hash: "a".repeat(64), source: "authored", approval_status: "approved", signature: "sig" }],
    adversarial: { suites: [{ name: "constitutional", blocked: 10, total: 10 }] },
    capabilities: { result: "satisfied", resources: {} },
  };
  const bundle = produceBundle(run, { privateKey: kp.privateKey, signer: "k", algo: "ed25519" });
  const v = verifyBundle(bundle, { trustedKeys: { k: pem } });
  // A produced bundle whose adversarial suite did NOT fully pass must NOT be able to claim X and verify:
  const run2 = JSON.parse(JSON.stringify(run)); run2.adversarial.suites[0].blocked = 3; // 3/10
  const bundle2 = produceBundle(run2, { privateKey: kp.privateKey, signer: "k", algo: "ed25519" });
  const v2 = verifyBundle(bundle2, { trustedKeys: { k: pem } });
  // honest producer recomputes adversarial_batteries_passed=false → the control matches, but X downgrades.
  const pass = v.status === "PASS" && v.confirmed_profiles.indexOf("X") !== -1 &&
    v2.status === "PASS" && v2.confirmed_profiles.indexOf("X") === -1 && v2.downgraded_profiles.indexOf("X") !== -1;
  console.log("gsa-produce selftest:", pass ? "OK" : "FAIL",
    "| round-trip=" + (v.status === "PASS"), "X-confirmed=" + (v.confirmed_profiles.indexOf("X") !== -1),
    "partial-battery-downgrades-X=" + (v2.confirmed_profiles.indexOf("X") === -1));
  process.exit(pass ? 0 : 1);
}
