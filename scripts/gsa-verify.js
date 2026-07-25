/* GraphSmith Attestation (GSA) verifier — scripts/gsa-verify.js.
 * Implements the normative §9 verification algorithm against schemas/attestation-bundle.schema.json.
 * A verifier proves a bundle is a complete, hash-valid, signature-valid record and is UNALTERED —
 * it does NOT assert the workflow is safe, correct, or compliant (evidence, not certification).
 *
 * Discipline: fail closed at the FIRST violation; pure decision path (no network/clock/random);
 * "unavailable" is never rendered green; report contract mirrors verify.js {status,evidence,...}.
 * mode/control-attestations are RECOMPUTED, never trusted-as-declared (D5). Signing: ed25519 /
 * ecdsa-p256-sha256 / rsa-pss-sha256, with declared-algo === key-type enforced (no algo confusion).
 * Zero-dep CJS, Node >= 18.
 */
"use strict";
const crypto = require("crypto");
// v0.4.0 extended-control checks (§9.11). Each exports run(ctx) -> {status}. The bundle's claimed
// extended controls are RECOMPUTED through these, never trusted-as-declared (D5), exactly like §9.9.
const v040Caps = require("../checks/v040-caps.js");
const v040Receipts = require("../checks/v040-receipts.js");
const v040Signer = require("../checks/v040-signer.js");
const v040Trace = require("../checks/v040-trace.js");
const v040Provenance = require("../checks/v040-provenance.js");

const HEX64 = /^[0-9a-f]{64}$/;
const SIG_ALGOS = new Set(["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"]);
const ALGO_KEYTYPE = { "ed25519": ["ed25519"], "ecdsa-p256-sha256": ["ec"], "rsa-pss-sha256": ["rsa", "rsa-pss"] };
const MODES = new Set(["standard", "deterministic", "regulator"]);
const REQUIRED_ARTIFACTS = ["goal", "policy", "model_manifest", "generated_ir", "compiled_graph", "validation_report", "execution_trace", "output_manifest", "decision_record"];
const CONTROL_KEYS = ["auto_skill_creation_disabled", "all_skills_signed_and_approved", "deterministic_mode", "regulator_mode", "adversarial_batteries_passed"];
// Behaviours forbidden in deterministic/regulator mode (scanned in the execution trace).
const NONDETERMINISTIC_MARKERS = ["skill_generated", "auto_promote", "remote_registry_fetch", "runtime_graph_modification", "unbounded_repair", "undeclared_network"];

function sha256Hex(buf) { return crypto.createHash("sha256").update(buf).digest("hex"); }

/* RFC 8785-ish canonical JSON: recursively sorted keys, compact. */
function canonicalize(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
}

function verifySignatureValue(algo, publicKeyPem, msgHex, valueB64) {
  let sigBuf; try { sigBuf = Buffer.from(valueB64, "base64"); } catch { return false; }
  const msg = Buffer.from(msgHex, "utf8");
  try {
    let key; try { key = crypto.createPublicKey(publicKeyPem); } catch { return false; }
    const allowed = ALGO_KEYTYPE[algo];
    if (!allowed || allowed.indexOf(key.asymmetricKeyType) === -1) return false;
    if (algo === "ed25519") return crypto.verify(null, msg, key, sigBuf);
    if (algo === "ecdsa-p256-sha256") return crypto.verify("sha256", msg, key, sigBuf);
    if (algo === "rsa-pss-sha256") return crypto.verify("sha256", msg, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, sigBuf);
    return false;
  } catch { return false; }
}

function pathSafe(p) {
  if (typeof p !== "string" || p.length === 0) return false;
  if (p.indexOf("\\") !== -1) return false;                 // no backslash
  if (p.normalize("NFC") !== p) return false;               // must be NFC
  const segs = p.split("/");
  for (const s of segs) if (s === ".." || s === "") return false; // no traversal / empty seg
  return true;
}

/* bundle = { manifest, contents: { <path>: string|Buffer } }  — contents holds each artifact's raw bytes.
 * opts   = { trustedKeys: {signer:pem}, revoked?: Set<hash> } */
function verifyBundle(bundle, opts) {
  opts = opts || {};
  const steps = [];
  const rec = (step, status, detail) => { steps.push({ step, status, detail }); return status === "FAIL"; };
  const done = (overall, confirmed, downgraded) => ({
    status: overall, steps,
    confirmed_profiles: confirmed || [], downgraded_profiles: downgraded || [],
    note: "A PASS asserts only §1 scope: what the run requested/produced and that the record is unaltered — NOT that the workflow is safe/correct/compliant.",
  });
  try {
    if (!bundle || typeof bundle !== "object") return done("FAIL", [], []);
    const m = bundle.manifest, contents = bundle.contents || {};
    const own = (o, k) => o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);

    // §9.1 Manifest validity (structural).
    if (!m || typeof m !== "object") { rec("1-manifest-validity", "FAIL", "no manifest"); return done("FAIL"); }
    if (m.schema_version !== "0.1") { rec("1-manifest-validity", "FAIL", "schema_version must be '0.1'"); return done("FAIL"); }
    if (!MODES.has(m.mode)) { rec("1-manifest-validity", "FAIL", "mode not in enum"); return done("FAIL"); }
    if (!m.artifacts || typeof m.artifacts !== "object") { rec("1-manifest-validity", "FAIL", "artifacts missing"); return done("FAIL"); }
    for (const a of REQUIRED_ARTIFACTS) if (!own(m.artifacts, a)) { rec("1-manifest-validity", "FAIL", "required artifact '" + a + "' missing"); return done("FAIL"); }
    for (const k of ["graph_signature", "bundle_signature", "control_attestations", "capabilities", "adversarial", "profiles", "skills"]) {
      if (!own(m, k)) { rec("1-manifest-validity", "FAIL", "manifest field '" + k + "' missing"); return done("FAIL"); }
    }
    rec("1-manifest-validity", "PASS", "required structure present");

    // §9.2 Path safety.
    for (const key of Object.keys(m.artifacts)) {
      const ref = m.artifacts[key];
      if (!ref || typeof ref.path !== "string" || typeof ref.sha256 !== "string" || typeof ref.bytes !== "number") { rec("2-path-safety", "FAIL", "artifact '" + key + "' malformed ref"); return done("FAIL"); }
      if (!pathSafe(ref.path)) { rec("2-path-safety", "FAIL", "unsafe/traversing/non-NFC path: " + ref.path); return done("FAIL"); }
      if (!HEX64.test(ref.sha256)) { rec("2-path-safety", "FAIL", "artifact '" + key + "' sha256 not 64-hex"); return done("FAIL"); }
    }
    rec("2-path-safety", "PASS", "all artifact paths canonical");

    // §9.3 Artifact integrity (recompute raw-byte sha256 + bytes).
    for (const key of Object.keys(m.artifacts)) {
      const ref = m.artifacts[key];
      if (!own(contents, ref.path)) { rec("3-artifact-integrity", "FAIL", "artifact content absent: " + ref.path); return done("FAIL"); }
      const buf = Buffer.isBuffer(contents[ref.path]) ? contents[ref.path] : Buffer.from(String(contents[ref.path]), "utf8");
      if (buf.length !== ref.bytes) { rec("3-artifact-integrity", "FAIL", "bytes mismatch for " + ref.path); return done("FAIL"); }
      if (sha256Hex(buf) !== ref.sha256) { rec("3-artifact-integrity", "FAIL", "sha256 mismatch for " + ref.path); return done("FAIL"); }
    }
    rec("3-artifact-integrity", "PASS", "every artifact hash + length matches");

    // §9.4 Conditional presence.
    const traceBuf = Buffer.isBuffer(contents[m.artifacts.execution_trace.path]) ? contents[m.artifacts.execution_trace.path] : Buffer.from(String(contents[m.artifacts.execution_trace.path] || ""), "utf8");
    const traceStr = traceBuf.toString("utf8");
    const repairOccurred = /"MUTATION_INTENT"|"repair"|"heal"/.test(traceStr);
    if (repairOccurred && !own(m.artifacts, "repair_log")) { rec("4-conditional-presence", "FAIL", "trace shows repair but repair_log absent"); return done("FAIL"); }
    if (m.mode === "regulator" && !own(m.artifacts, "regulator_summary")) { rec("4-conditional-presence", "FAIL", "mode=regulator but regulator_summary absent"); return done("FAIL"); }
    if (m.mode !== "regulator" && own(m.artifacts, "regulator_summary")) { rec("4-conditional-presence", "FAIL", "regulator_summary present but mode!=regulator"); return done("FAIL"); }
    rec("4-conditional-presence", "PASS", "conditional artifacts consistent with mode/trace");

    // §9.5 Manifest signature — preimage = JCS(manifest with the WHOLE bundle_signature removed).
    const bsig = m.bundle_signature;
    if (!SIG_ALGOS.has(bsig.algo) || typeof bsig.signer !== "string" || typeof bsig.value !== "string" || !HEX64.test(bsig.manifest_sha256 || "")) { rec("5-manifest-signature", "FAIL", "bundle_signature malformed"); return done("FAIL"); }
    const mPreimage = { ...m }; delete mPreimage.bundle_signature;
    const manifestSha = sha256Hex(Buffer.from(canonicalize(mPreimage), "utf8"));
    if (manifestSha !== bsig.manifest_sha256) { rec("5-manifest-signature", "FAIL", "recomputed manifest_sha256 != claimed (manifest altered)"); return done("FAIL"); }
    if (!own(opts.trustedKeys || {}, bsig.signer)) { return rec("5-manifest-signature", "UNAVAILABLE", "signer '" + bsig.signer + "' not in trusted set — authenticity not establishable"), done("FAIL"); }
    if (!verifySignatureValue(bsig.algo, opts.trustedKeys[bsig.signer], bsig.manifest_sha256, bsig.value)) { rec("5-manifest-signature", "FAIL", "bundle signature does not verify"); return done("FAIL"); }
    rec("5-manifest-signature", "PASS", "manifest unaltered + bundle signature valid");

    // §9.6 Graph signature — over graph_hash||policy_hash||skill_set_hash (recomputed).
    const gs = m.graph_signature;
    if (!SIG_ALGOS.has(gs.algo)) { rec("6-graph-signature", "FAIL", "graph_signature.algo invalid"); return done("FAIL"); }
    const graphHash = sha256Hex(Buffer.from(String(contents[m.artifacts.compiled_graph.path] || ""), "utf8"));
    const policyHash = sha256Hex(Buffer.from(String(contents[m.artifacts.policy.path] || ""), "utf8"));
    const skillSetHash = sha256Hex(Buffer.from(canonicalize([...(m.skills || [])].map((s) => ({ skill_id: s.skill_id, version: s.version, implementation_hash: s.implementation_hash })).sort((a, b) => (a.skill_id + a.version).localeCompare(b.skill_id + b.version))), "utf8"));
    if (gs.graph_hash !== graphHash || gs.policy_hash !== policyHash || gs.skill_set_hash !== skillSetHash) { rec("6-graph-signature", "FAIL", "graph/policy/skill-set hash mismatch (plan altered)"); return done("FAIL"); }
    if (own(opts.trustedKeys || {}, gs.signer)) {
      if (!verifySignatureValue(gs.algo, opts.trustedKeys[gs.signer], gs.graph_hash + gs.policy_hash + gs.skill_set_hash, gs.value)) { rec("6-graph-signature", "FAIL", "graph signature does not verify"); return done("FAIL"); }
      rec("6-graph-signature", "PASS", "plan hashes match + graph signature valid");
    } else {
      rec("6-graph-signature", "PASS", "plan hashes match (graph signer not in trusted set — signature not checked)");
    }

    // §9.9 Control attestations — RECOMPUTE all five; each stated value MUST match.
    const skills = Array.isArray(m.skills) ? m.skills : [];
    const revoked = opts.revoked instanceof Set ? opts.revoked : new Set();
    const recomputed = {
      auto_skill_creation_disabled: !skills.some((s) => s.source === "generated" && s.approval_status !== "approved"),
      all_skills_signed_and_approved: skills.length > 0 && skills.every((s) => typeof s.signature === "string" && s.signature.length > 0 && s.approval_status === "approved" && !revoked.has(s.implementation_hash)),
      deterministic_mode: (m.mode === "deterministic" || m.mode === "regulator") && !NONDETERMINISTIC_MARKERS.some((mk) => traceStr.indexOf(mk) !== -1),
      regulator_mode: m.mode === "regulator" && own(m.artifacts, "regulator_summary"),
      adversarial_batteries_passed: Array.isArray(m.adversarial.suites) && m.adversarial.suites.length > 0 && m.adversarial.suites.every((s) => s && s.blocked === s.total && s.total > 0),
    };
    for (const k of CONTROL_KEYS) {
      if (m.control_attestations[k] !== recomputed[k]) { rec("9-control-attestations", "FAIL", "control '" + k + "' claimed " + m.control_attestations[k] + " but recomputes to " + recomputed[k]); return done("FAIL"); }
    }
    rec("9-control-attestations", "PASS", "all five control attestations match the recomputed evidence");

    // §9.11 Extended controls (v0.4.0) — ADDITIVE + backward-compatible: engages ONLY when the bundle
    // declares `control_attestations_v040`. Each claimed control is RECOMPUTED through its checks/v040-*.js
    // module from the bundle's own evidence (the execution_trace bytes are the §9.3-verified artifact),
    // and the claim MUST match the recomputed verdict — a control claimed true that recomputes non-verified
    // is a lie and fails closed (D5, same discipline as §9.9). A v0.3.0 bundle without this key is untouched.
    if (own(m, "control_attestations_v040")) {
      const ext = m.control_attestations_v040;
      if (!ext || typeof ext !== "object" || Array.isArray(ext)) { rec("11-extended-controls", "FAIL", "control_attestations_v040 malformed"); return done("FAIL"); }
      const verified = (mod, ctx) => { try { return mod.run(ctx).status === "verified"; } catch { return false; } };
      const cg = (m.capability_grant && typeof m.capability_grant === "object") ? m.capability_grant : {};
      const recomputedExt = {
        capability_conformance: verified(v040Caps, { grant: cg.grant, requested: cg.requested, attested: cg.attested }),
        effects_reconciled: verified(v040Receipts, { effects: m.effects }),
        signer_trust: verified(v040Signer, m.signer_registry && typeof m.signer_registry === "object"
          ? { ...m.signer_registry, bundle_id: m.bundle_id, manifest_sha256: bsig.manifest_sha256 } : {}),
        trace_redaction: verified(v040Trace, { trace_mode: m.trace_mode, trace: traceStr }),
        build_provenance: verified(v040Provenance, (m.build_provenance && typeof m.build_provenance === "object") ? m.build_provenance : {}),
      };
      for (const k of Object.keys(ext)) {
        if (!Object.prototype.hasOwnProperty.call(recomputedExt, k)) { rec("11-extended-controls", "FAIL", "unknown extended control '" + k + "'"); return done("FAIL"); }
        if (ext[k] !== recomputedExt[k]) { rec("11-extended-controls", "FAIL", "extended control '" + k + "' claimed " + ext[k] + " but recomputes to " + recomputedExt[k]); return done("FAIL"); }
      }
      rec("11-extended-controls", "PASS", "all declared v0.4.0 controls match recomputed evidence: " + Object.keys(ext).join(", "));
    }

    // §9.10 Profiles — confirm the ones we can; A is the floor (a passing §9 to here).
    const asserted = Array.isArray(m.profiles) ? m.profiles : [];
    const confirmed = [], downgraded = [];
    for (const p of asserted) {
      if (p === "A") { confirmed.push("A"); continue; }               // A: a complete, valid bundle exists (we got here)
      if (p === "X") { (recomputed.adversarial_batteries_passed ? confirmed : downgraded).push("X"); continue; }
      if (p === "T") { (own(opts.trustedKeys || {}, bsig.signer) ? confirmed : downgraded).push("T"); continue; }
      downgraded.push(p); // R/E/B/G/Q evidence lives in artifacts a fuller verifier walks — honestly downgraded here
    }
    rec("10-profiles", "PASS", "confirmed=[" + confirmed.join(",") + "] downgraded-to-unavailable=[" + downgraded.join(",") + "]");

    return done("PASS", confirmed, downgraded);
  } catch (e) {
    steps.push({ step: "exception", status: "FAIL", detail: "failing closed: " + (e && e.message ? e.message : String(e)) });
    return done("FAIL");
  }
}

module.exports = { verifyBundle, canonicalize, sha256Hex, verifySignatureValue, pathSafe };

if (require.main === module && process.argv.includes("--selftest")) {
  // Build a minimal VALID standard-mode bundle, sign it, verify PASS, then tamper cases.
  const kp = crypto.generateKeyPairSync("ed25519");
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  const sign = (hex) => crypto.sign(null, Buffer.from(hex, "utf8"), kp.privateKey).toString("base64");
  const c = {}; const art = {};
  const add = (key, path, body) => { c[path] = body; art[key] = { path, sha256: sha256Hex(Buffer.from(body, "utf8")), bytes: Buffer.byteLength(body, "utf8") }; };
  add("goal", "goal.txt", "ship it"); add("policy", "policy.yaml", "mode: standard"); add("model_manifest", "model_manifest.json", "{}");
  add("generated_ir", "generated_ir.json", "{}"); add("compiled_graph", "compiled_graph.json", '{"nodes":1}'); add("validation_report", "validation_report.json", "{}");
  add("execution_trace", "execution_trace.jsonl", '{"step":1}'); add("output_manifest", "output_manifest.json", "{}"); add("decision_record", "decision_record.md", "# ok");
  const skills = [{ skill_id: "s1", version: "1.0", implementation_hash: "a".repeat(64), source: "authored", approval_status: "approved", signature: "sig" }];
  const graphHash = sha256Hex(Buffer.from(c["compiled_graph.json"], "utf8"));
  const policyHash = sha256Hex(Buffer.from(c["policy.yaml"], "utf8"));
  const skillSetHash = sha256Hex(Buffer.from(canonicalize(skills.map((s) => ({ skill_id: s.skill_id, version: s.version, implementation_hash: s.implementation_hash }))), "utf8"));
  const manifest = {
    schema_version: "0.1", bundle_id: "gsa-" + "0".repeat(16), created: "unavailable", producer: { name: "graphsmith", version: "0.3.0" },
    mode: "standard", profiles: ["A", "X"], artifacts: art, skills,
    graph_signature: { graph_hash: graphHash, policy_hash: policyHash, skill_set_hash: skillSetHash, signer: "k", signed_at: "unavailable", algo: "ed25519", value: sign(graphHash + policyHash + skillSetHash) },
    capabilities: { result: "satisfied", resources: {} },
    control_attestations: { auto_skill_creation_disabled: true, all_skills_signed_and_approved: true, deterministic_mode: false, regulator_mode: false, adversarial_batteries_passed: true },
    adversarial: { suites: [{ name: "constitutional", blocked: 10, total: 10 }] },
    bundle_signature: { algo: "ed25519", signer: "k", manifest_sha256: "", value: "" },
  };
  const preHash = sha256Hex(Buffer.from(canonicalize((() => { const x = { ...manifest }; delete x.bundle_signature; return x; })()), "utf8"));
  manifest.bundle_signature.manifest_sha256 = preHash; manifest.bundle_signature.value = sign(preHash);
  const tk = { k: pem };
  const good = verifyBundle({ manifest, contents: c }, { trustedKeys: tk });
  const tampArt = JSON.parse(JSON.stringify(manifest)); const c2 = { ...c, "goal.txt": "TAMPERED" };
  const badArtifact = verifyBundle({ manifest: tampArt, contents: c2 }, { trustedKeys: tk });
  const tampCtrl = JSON.parse(JSON.stringify(manifest)); tampCtrl.control_attestations.adversarial_batteries_passed = false; // now lies vs recomputed true... re-sign so it's a control-lie not a sig-fail
  tampCtrl.bundle_signature.manifest_sha256 = sha256Hex(Buffer.from(canonicalize((() => { const x = { ...tampCtrl }; delete x.bundle_signature; return x; })()), "utf8")); tampCtrl.bundle_signature.value = sign(tampCtrl.bundle_signature.manifest_sha256);
  const badControl = verifyBundle({ manifest: tampCtrl, contents: c }, { trustedKeys: tk });
  const badTrust = verifyBundle({ manifest, contents: c }, { trustedKeys: {} });
  const traversal = JSON.parse(JSON.stringify(manifest)); traversal.artifacts.goal.path = "../evil";
  const badPath = verifyBundle({ manifest: traversal, contents: c }, { trustedKeys: tk });

  // §9.11 extended-control (v0.4.0) cases — recompute trace_redaction from the REAL execution_trace bytes.
  const signedExtBundle = (traceBody, claim) => {
    const cx = { ...c, "execution_trace.jsonl": traceBody };
    const ax = JSON.parse(JSON.stringify(art));
    ax.execution_trace = { path: "execution_trace.jsonl", sha256: sha256Hex(Buffer.from(traceBody, "utf8")), bytes: Buffer.byteLength(traceBody, "utf8") };
    const mx = { ...manifest, artifacts: ax, control_attestations_v040: claim, trace_mode: "full" };
    delete mx.bundle_signature;
    const ph = sha256Hex(Buffer.from(canonicalize(mx), "utf8"));
    mx.bundle_signature = { algo: "ed25519", signer: "k", manifest_sha256: ph, value: sign(ph) };
    return verifyBundle({ manifest: mx, contents: cx }, { trustedKeys: tk });
  };
  const extValid = signedExtBundle('{"step":1,"status":"ok"}', { trace_redaction: true });                 // clean trace, claim honest → PASS
  const extLie = signedExtBundle('{"step":1,"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}', { trace_redaction: true }); // leaky trace, claim is a lie → FAIL
  const extFalseHonest = signedExtBundle('{"step":1,"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}', { trace_redaction: false }); // leaky trace, honestly claims false → PASS (§9.11 catches lies, not leaks per se)

  const pass = good.status === "PASS" && badArtifact.status === "FAIL" && badControl.status === "FAIL" && badTrust.status === "FAIL" && badPath.status === "FAIL" &&
    extValid.status === "PASS" && extLie.status === "FAIL" && extFalseHonest.status === "PASS";
  console.log("gsa-verify selftest:", pass ? "OK" : "FAIL",
    "| valid=" + (good.status === "PASS"), "confirmed=" + JSON.stringify(good.confirmed_profiles),
    "tamper-artifact=" + (badArtifact.status === "FAIL"), "control-lie=" + (badControl.status === "FAIL"),
    "untrusted=" + (badTrust.status === "FAIL"), "path-traversal=" + (badPath.status === "FAIL"),
    "| ext-valid=" + (extValid.status === "PASS"), "ext-redaction-lie=" + (extLie.status === "FAIL"), "ext-honest-false=" + (extFalseHonest.status === "PASS"));
  process.exit(pass ? 0 : 1);
}
