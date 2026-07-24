/* GSA regulated-register integration + activation guard — scripts/gsa-register.js.
 * Composes the four register lanes (approver / obligations / retention / air-gapped) into one
 * regulated-mode decision and, when it holds, seals their evidence into a GSA regulator bundle.
 *
 * THE PB-8 FAIL-CLOSED HEART: regulated mode activates ONLY when EVERY activation precondition in
 * register-policy holds against a complete, valid register. Any unmet / missing / ambiguous
 * precondition => NOT activated, loudly. The register produces evidence + an honest coverage map;
 * it never emits a "compliant" verdict. C1: identity/timestamps are evidence, never decision inputs.
 * Reuses the four TEST-PASSED lane checks + gsa-produce. Zero-dep CJS, Node >= 18.
 */
"use strict";
const approver = require("../checks/register-approver.js");
const obligations = require("../checks/register-obligations.js");
const retention = require("../checks/register-retention.js");
const airgap = require("../checks/register-airgap.js");
const { produceBundle } = require("./gsa-produce.js");

const PRECONDITIONS = ["obligations_register_complete", "no_manual_only_marked_covered", "approver_attestation_valid", "retention_chain_intact", "release_signature_verified"];

/* Run the four lanes and derive the activation preconditions from their real results (recomputed,
 * never trusted-as-declared). inputs = { obligations, approver, retention, airgap } — each the ctx
 * that lane's check expects. */
function evaluateRegister(inputs) {
  try {
  inputs = inputs || {};
  const obl = obligations.run(inputs.obligations || {});
  const app = approver.run(inputs.approver || {});
  const ret = retention.run(inputs.retention || {});
  const air = airgap.run(inputs.airgap || {});

  // A manual-only-marked-covered attempt surfaces as a CRITICAL/HIGH violation in the coverage report;
  // the obligations lane already fails closed on it. We require BOTH the clean status AND the explicit
  // may-activate flag, and independently confirm no coverage row is manual-only-yet-covered.
  const covMap = Array.isArray(obl.coverage_map) ? obl.coverage_map : [];
  const manualMarkedCovered = covMap.some((c) => c.actual_coverage === "manual-only" && c.declared_coverage === "covered");

  const preconditions = {
    obligations_register_complete: obl.status === "verified" && obl.regulated_mode_may_activate === true,
    no_manual_only_marked_covered: !manualMarkedCovered && obl.status !== "failed",
    approver_attestation_valid: app.status === "verified",
    retention_chain_intact: ret.status === "verified",
    release_signature_verified: air.status === "verified",
  };
  return { preconditions, checks: { obligations: obl, approver: app, retention: ret, airgap: air } };
  } catch (e) {
    // Any hostile input (throwing getter, proxy trap, etc.) fails closed: every precondition false.
    const preconditions = {}; for (const p of PRECONDITIONS) preconditions[p] = false;
    return { preconditions, checks: {}, error: "evaluation failed closed: " + (e && e.message ? e.message : String(e)) };
  }
}

/* The activation guard. policy = register-policy object (must have fail_closed:true + activation_preconditions).
 * Returns { activated, reason, unmet[], evaluation }. Fail-closed on every error path. */
function activateRegulatedMode(inputs, policy) {
  const ev = evaluateRegister(inputs);
  const deny = (reason, unmet) => ({ activated: false, reason, unmet: unmet || [], evaluation: ev });

  if (!policy || typeof policy !== "object" || policy.schema_version !== "1.0") return deny("register-policy missing or invalid");
  if (policy.fail_closed !== true) return deny("register-policy.fail_closed must be true — refusing to activate under a relaxed policy");
  const required = Array.isArray(policy.activation_preconditions) ? policy.activation_preconditions : [];
  if (required.length === 0) return deny("no activation preconditions declared — refusing to activate on an empty guard");

  const unmet = [];
  for (const p of required) {
    if (PRECONDITIONS.indexOf(p) === -1) return deny("unknown activation precondition '" + p + "' — failing closed", [p]);
    if (ev.preconditions[p] !== true) unmet.push(p);
  }
  if (unmet.length > 0) return deny("regulated mode NOT activated — " + unmet.length + " precondition(s) not met (fail-closed)", unmet);
  return { activated: true, reason: "all " + required.length + " activation preconditions met against a complete, valid register", unmet: [], evaluation: ev };
}

/* When (and only when) regulated mode activates, seal the register evidence into a GSA regulator
 * bundle. The regulator_summary is Article-12-shaped and honestly labels evidence vs human judgment. */
function sealRegulatedBundle(inputs, policy, run, keys) {
  const gate = activateRegulatedMode(inputs, policy);
  if (!gate.activated) return { sealed: false, gate };
  const covMap = gate.evaluation.checks.obligations.coverage_map || [];
  const A = (path, body) => ({ path, body });
  const summary = "# Article-12 regulator summary (evidence, not a compliance verdict)\n\n" +
    "Regulated mode activated: all preconditions met. This bundle is evidence; the compliance conclusion belongs to the accountable humans.\n\n" +
    "Obligation coverage (recomputed from evidence):\n" +
    covMap.map((c) => "- " + c.obligation_id + ": " + c.actual_coverage + (c.evidence_vs_judgment ? " — human judgment: " + c.evidence_vs_judgment.human_judgment : "")).join("\n") +
    "\n\nApprover: valid · Retention chain: intact · Release signature: verified offline.";
  const regRun = { ...run, mode: "regulator", profiles: Array.from(new Set([...(run.profiles || []), "A"])) };
  regRun.artifacts = { ...run.artifacts, regulator_summary: A("regulator_summary.md", summary) };
  const bundle = produceBundle(regRun, keys);
  return { sealed: true, gate, bundle };
}

module.exports = { evaluateRegister, activateRegulatedMode, sealRegulatedBundle, PRECONDITIONS };

if (require.main === module && process.argv.includes("--selftest")) {
  const crypto = require("crypto");
  const H = (n) => String(n).padStart(2, "0").repeat(32);
  const head = "e".repeat(64);
  // Build valid inputs for all four lanes.
  const kApp1 = crypto.generateKeyPairSync("ed25519"), kApp2 = crypto.generateKeyPairSync("ed25519");
  const kRel = crypto.generateKeyPairSync("ed25519");
  const pem = (k) => k.publicKey.export({ type: "spki", format: "pem" }).toString();
  const split = { graphsmith_evidence: "T verified offline", human_judgment: "auditor confirms scope" };
  const appAtt = (kp, signer, who) => ({ schema_version: "1.0", approver_id: who, role: "release-owner", method: "signed-commit", artifact_sha256: head, obligation_set_id: "set-1",
    signature: { algo: "ed25519", signer, packet_sha256: head, value: crypto.sign(null, Buffer.from(head, "utf8"), kp.privateKey).toString("base64") } });
  const manifest = { schema_version: "1.0", kind: "release", release: "v0.3.0", files: [{ path: "a.js", sha256: "a".repeat(64) }] };
  const airCore = require("./gsa-verify.js"); // reuse canonicalize/sha256 for the airgap manifest hash
  const mhash = airgap.sha256Hex(Buffer.from(airgap.canonicalize(manifest), "utf8"));
  const goodInputs = {
    obligations: { register: { schema_version: "1.0", obligation_set_id: "set-1", obligations: [
      { obligation_id: "o1", source: { framework: "EU-AI-Act", clause: "Article-12" }, controls: [{ type: "profile", ref: "T" }], evidence_artifact: { type: "profile-result", ref: "T" }, coverage: "covered", evidence_vs_judgment: split },
      { obligation_id: "o2", source: { framework: "EU-AI-Act", clause: "Article-14" }, controls: [], coverage: "manual-only", evidence_vs_judgment: split },
    ] }, evidence: { profiles: { T: "verified" } } },
    approver: { packet_sha256: head, approvals: [appAtt(kApp1, "k1", "alice"), appAtt(kApp2, "k2", "bob")], policy: { schema_version: "1.0", separation_of_duties: { proposer_ne_approver: true, n_of_m: { n: 2, m: 3 } }, fail_closed: true, activation_preconditions: ["approver_attestation_valid"] }, trustedKeys: { k1: pem(kApp1), k2: pem(kApp2) }, proposer_id: "carol" },
    retention: { chain: [{ schema_version: "1.0", seq: 1, prev_packet_sha256: null, packet_sha256: H(1), anchored_head: head }, { schema_version: "1.0", seq: 2, prev_packet_sha256: H(1), packet_sha256: H(2), anchored_head: head }], expected_anchored_head: head },
    airgap: { manifest, signature: { schema_version: "1.0", algo: "ed25519", signer: "rel", manifest_sha256: mhash, value: crypto.sign(null, Buffer.from(mhash, "utf8"), kRel.privateKey).toString("base64"), delivery: "out-of-band" }, trustedKeys: { rel: pem(kRel) } },
  };
  const policy = { schema_version: "1.0", separation_of_duties: { proposer_ne_approver: true }, fail_closed: true, activation_preconditions: PRECONDITIONS };

  const good = activateRegulatedMode(goodInputs, policy);
  // fail-closed cases: break each lane, must NOT activate.
  const brokenObl = JSON.parse(JSON.stringify(goodInputs)); brokenObl.obligations.register.obligations[0].coverage = "covered"; brokenObl.obligations.evidence.profiles.T = "unavailable"; // over-claim
  const dObl = activateRegulatedMode(brokenObl, policy);
  const brokenRet = JSON.parse(JSON.stringify(goodInputs)); brokenRet.retention.chain[1].prev_packet_sha256 = H(9); // broken chain
  const dRet = activateRegulatedMode(brokenRet, policy);
  const relaxed = activateRegulatedMode(goodInputs, { ...policy, fail_closed: false }); // relaxed policy refused
  const manualCovered = JSON.parse(JSON.stringify(goodInputs)); manualCovered.obligations.register.obligations[1].coverage = "covered"; // manual-only marked covered
  const dManual = activateRegulatedMode(manualCovered, policy);

  const pass = good.activated === true && dObl.activated === false && dRet.activated === false && relaxed.activated === false && dManual.activated === false;
  console.log("gsa-register selftest:", pass ? "OK" : "FAIL",
    "| complete-activates=" + good.activated, "obl-overclaim-denied=" + (!dObl.activated), "broken-retention-denied=" + (!dRet.activated),
    "relaxed-policy-refused=" + (!relaxed.activated), "manual-marked-covered-denied=" + (!dManual.activated));
  if (!pass) console.log("  good.reason=", good.reason, "| dManual.unmet=", dManual.unmet);
  process.exit(pass ? 0 : 1);
}
