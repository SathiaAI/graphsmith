/* GraphSmith register Lane A — approver identity (checks/register-approver.js).
 * Verifies detached approver signatures over the assure-packet hash (the anchored head),
 * enforcing separation-of-duties and N-of-M from register-policy.json.
 *
 * Discipline (frozen Contract 13):
 *   - C1: approver identity and timestamps are EVIDENCE, recorded and verified — NEVER a
 *     decision input. The pass/fail decision is purely "are there >= N distinct valid
 *     non-proposer signatures over THIS packet hash by trusted keys". Identity strings are
 *     counted/verified, never used to branch the verdict.
 *   - C2 fail-closed: any invalid signature, SoD violation, or under-threshold => refused.
 *   - Report contract (D3): { status, evidence[], assumptions[], failure_domain? }; pure
 *     (no network/clock/random). Schemas: approver-attestation, register-policy.
 * Zero-dep CJS, Node >= 18.
 */
"use strict";
const crypto = require("crypto");

const SIG_ALGOS = new Set(["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"]);
const HEX64 = /^[0-9a-f]{64}$/;
const ATT_KEYS = ["schema_version", "approver_id", "role", "method", "artifact_sha256", "obligation_set_id", "attested_at", "signature"];
const SIG_KEYS = ["algo", "signer", "packet_sha256", "value"];
const ALGO_KEYTYPE = { "ed25519": ["ed25519"], "ecdsa-p256-sha256": ["ec"], "rsa-pss-sha256": ["rsa", "rsa-pss"] };
const METHODS = new Set(["signed-commit", "os-user", "external-idp"]);

/* Own-key allowlist: required subset present, no extra own keys (rejects extra + inherited). */
function shapeOk(obj, required, allowed) {
  if (!obj || typeof obj !== "object") return false;
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) return false;
  for (const k of Object.keys(obj)) if (allowed.indexOf(k) === -1) return false;
  return true;
}

function verifySig(algo, publicKeyPem, packetSha256Hex, valueB64) {
  let sigBuf;
  try { sigBuf = Buffer.from(valueB64, "base64"); } catch { return false; }
  const msg = Buffer.from(packetSha256Hex, "utf8");
  try {
    let keyObj;
    try { keyObj = crypto.createPublicKey(publicKeyPem); } catch { return false; }
    const allowed = ALGO_KEYTYPE[algo];
    if (!allowed || allowed.indexOf(keyObj.asymmetricKeyType) === -1) return false;
    if (algo === "ed25519") return crypto.verify(null, msg, keyObj, sigBuf);
    if (algo === "ecdsa-p256-sha256") return crypto.verify("sha256", msg, keyObj, sigBuf);
    if (algo === "rsa-pss-sha256") return crypto.verify("sha256", msg, { key: keyObj, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, sigBuf);
    return false;
  } catch { return false; }
}

/* ctx = {
 *   packet_sha256: hex,                 // the anchored head the approvals must cover
 *   approvals:    [approver-attestation],
 *   policy:       register-policy object (separation_of_duties, fail_closed, ...),
 *   trustedKeys:  { [signer]: publicKeyPem },
 *   proposer_id:  string                // who proposed the change (SoD: must not approve)
 * } */
function verifyApprovers(ctx) {
  const evidence = [];
  const assumptions = [
    "Approver identity and timestamps are evidence, recorded and verified — never a decision input (C1).",
    "Trust of a signer's key is verifier policy; a privileged local attacker who rewrites keys is out of scope (A6).",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const { packet_sha256, approvals, policy, trustedKeys, proposer_id } = ctx;
    if (typeof packet_sha256 !== "string" || !HEX64.test(packet_sha256)) return fail("packet_sha256 not a 64-hex string");
    if (!policy || typeof policy !== "object" || policy.schema_version !== "1.0") return fail("register-policy missing/invalid");
    if (policy.fail_closed !== true) return fail("register-policy.fail_closed must be true");
    if (!Array.isArray(approvals) || approvals.length === 0) {
      return { status: "unavailable", evidence, assumptions, reason: "no approver attestations present" };
    }
    const sod = policy.separation_of_duties || {};
    const needProposerNeApprover = sod.proposer_ne_approver === true;
    const nOfM = sod.n_of_m && typeof sod.n_of_m.n === "number" ? sod.n_of_m.n : 1;

    // If SoD is required, it cannot be enforced without a valid proposer identity — fail closed
    // rather than silently skip the check (Mistral Lane-A finding: malformed proposer_id).
    if (needProposerNeApprover && (typeof proposer_id !== "string" || proposer_id.length < 1)) {
      return fail("separation-of-duties required but proposer_id is missing/invalid — cannot enforce, failing closed", "untrusted-input");
    }

    // Anti-Sybil: distinct authority = distinct SIGNER KEY, not claimed approver_id. One trusted
    // key must never mint multiple "approvers" to beat N-of-M (DeepSeek Lane-A finding).
    const validSigners = new Set();
    for (let i = 0; i < approvals.length; i++) {
      const a = approvals[i];
      if (!shapeOk(a, ["schema_version", "approver_id", "role", "method", "artifact_sha256", "obligation_set_id", "signature"], ATT_KEYS)) { evidence.push("attestation[" + i + "]: bad shape — ignored"); continue; }
      if (a.schema_version !== "1.0") { evidence.push("attestation[" + i + "]: schema_version != '1.0' — ignored"); continue; }
      if (typeof a.approver_id !== "string" || a.approver_id.length < 1) { evidence.push("attestation[" + i + "]: missing approver_id — ignored"); continue; }
      if (!METHODS.has(a.method)) { evidence.push("attestation[" + i + "]: bad method — ignored"); continue; }
      if (typeof a.artifact_sha256 !== "string" || a.artifact_sha256 !== packet_sha256) { evidence.push("attestation[" + i + "]: artifact_sha256 does not cover the anchored head — ignored"); continue; }
      const s = a.signature;
      if (!shapeOk(s, SIG_KEYS, SIG_KEYS) || !SIG_ALGOS.has(s.algo)) { evidence.push("attestation[" + i + "]: bad signature shape — ignored"); continue; }
      if (typeof s.packet_sha256 !== "string" || s.packet_sha256 !== packet_sha256) { evidence.push("attestation[" + i + "]: signature.packet_sha256 mismatch — ignored"); continue; }
      if (!trustedKeys || !Object.prototype.hasOwnProperty.call(trustedKeys, s.signer)) { evidence.push("attestation[" + i + "]: signer '" + s.signer + "' not trusted — ignored"); continue; }
      if (!verifySig(s.algo, trustedKeys[s.signer], packet_sha256, s.value)) { evidence.push("attestation[" + i + "]: signature does not verify — ignored"); continue; }
      // C2: separation-of-duties — the proposer's approval never counts.
      if (needProposerNeApprover && typeof proposer_id === "string" && a.approver_id === proposer_id) {
        return fail("separation-of-duties violated: proposer '" + proposer_id + "' also approved", "untrusted-input");
      }
      validSigners.add(s.signer); // distinct KEY = distinct authority (identity is evidence, not the count)
    }

    const distinct = validSigners.size;
    evidence.push("distinct valid non-proposer signer keys over the anchored head: " + distinct + " (threshold N=" + nOfM + ").");
    if (distinct < nOfM) {
      return { status: "unavailable", evidence, assumptions, reason: "under threshold — " + distinct + " valid approver(s), need " + nOfM };
    }
    evidence.push("approver requirement satisfied (fail-closed): " + distinct + " >= " + nOfM + ".");
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception during verification — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "register-approver",
  run(ctx) {
    const r = verifyApprovers(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) out.evidence.push("reason: " + r.reason);
    return out;
  },
};

module.exports = { ...check, verifyApprovers, verifySig };

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    const mk = () => crypto.generateKeyPairSync("ed25519");
    const pem = (k) => k.publicKey.export({ type: "spki", format: "pem" }).toString();
    const head = "c".repeat(64);
    const k1 = mk(), k2 = mk();
    const sign = (kp, signer, approver) => ({ schema_version: "1.0", approver_id: approver, role: "release-owner", method: "signed-commit", artifact_sha256: head, obligation_set_id: "set-1",
      signature: { algo: "ed25519", signer, packet_sha256: head, value: crypto.sign(null, Buffer.from(head, "utf8"), kp.privateKey).toString("base64") } });
    const policy = { schema_version: "1.0", separation_of_duties: { proposer_ne_approver: true, n_of_m: { n: 2, m: 3 } }, fail_closed: true, activation_preconditions: ["approver_attestation_valid"] };
    const trusted = { "key-1": pem(k1), "key-2": pem(k2) };
    // 1. two distinct valid non-proposer approvers meets N=2 -> verified.
    const good = check.run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice"), sign(k2, "key-2", "bob")], policy, trustedKeys: trusted, proposer_id: "carol" });
    // 2. proposer also approves -> SoD failed.
    const sod = check.run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice"), sign(k2, "key-2", "bob")], policy, trustedKeys: trusted, proposer_id: "bob" });
    // 3. only one valid approver -> under threshold (unavailable).
    const under = check.run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice")], policy, trustedKeys: trusted, proposer_id: "carol" });
    // 4. tampered value -> that attestation ignored -> under threshold.
    const tamperA = sign(k1, "key-1", "alice"); const tamperB = sign(k2, "key-2", "bob"); tamperB.signature.value = "AAAA";
    const tampered = check.run({ packet_sha256: head, approvals: [tamperA, tamperB], policy, trustedKeys: trusted, proposer_id: "carol" });
    const pass = good.status === "verified" && sod.status === "failed" && under.status === "unavailable" && tampered.status === "unavailable";
    console.log("register-approver selftest:", pass ? "OK" : "FAIL", "| n-of-m=" + (good.status === "verified"), "sod=" + (sod.status === "failed"), "under=" + (under.status === "unavailable"), "tamper=" + (tampered.status === "unavailable"));
    process.exit(pass ? 0 : 1);
  } else {
    console.error("Usage: node checks/register-approver.js --selftest");
    process.exit(1);
  }
}
