/* GraphSmith register Lane D — air-gapped release verification (checks/register-airgap.js).
 * Extends the T (trust-root) profile from "manifest matches disk" to "manifest is
 * AUTHENTIC without a network": an out-of-band maintainer signature over the release
 * manifest lets an air-gapped site verify signature -> manifest -> files with no network
 * and no trust in the distributing registry.
 *
 * Discipline (frozen Contract 13):
 *   - PURE decision path: no network, no clock, no randomness. Identity (the signer) and
 *     any timestamp are EVIDENCE, never decision inputs (C1). Trust of the signer's key is
 *     the VERIFIER's policy, not a GraphSmith guarantee.
 *   - Fail-closed (C2): any shape violation, hash mismatch, or bad signature -> failed;
 *     an untrusted/unknown signer -> unavailable (honest: cannot establish authenticity),
 *     never green.
 *   - Report contract (D3): { status, evidence[], assumptions[], failure_domain? };
 *     status in { verified | unavailable | failed | not-applicable }.
 * Zero-dep CJS, Node >= 18. Schema: schemas/release-signature.schema.json.
 */
"use strict";
const crypto = require("crypto");

const SIG_ALGOS = new Set(["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"]);
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_KEYS = ["schema_version", "algo", "signer", "manifest_sha256", "value", "delivery"];
// A declared algo MUST match the actual key type — otherwise crypto.verify auto-detects
// from the key and an algo mislabel slips through (algorithm-confusion, Codex D1/D2).
const ALGO_KEYTYPE = { "ed25519": ["ed25519"], "ecdsa-p256-sha256": ["ec"], "rsa-pss-sha256": ["rsa", "rsa-pss"] };

/* Strict shape: exactly the allowed OWN keys — rejects extra fields (additionalProperties:false)
 * and inherited/prototype-supplied fields (own-property required). */
function strictSigShape(sig) {
  if (!sig || typeof sig !== "object") return false;
  for (const k of SIG_KEYS) if (!Object.prototype.hasOwnProperty.call(sig, k)) return false;
  for (const k of Object.keys(sig)) if (SIG_KEYS.indexOf(k) === -1) return false;
  return true;
}

/* Deterministic canonical JSON (RFC 8785-ish): recursively sorted keys, compact.
 * No clock/random. Used to hash the manifest object stably across producers. */
function canonicalize(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/* Verify an ed25519 (or declared) signature over the manifest_sha256 hex string.
 * Returns boolean; never throws on a bad signature (returns false). */
function verifySignatureValue(algo, publicKeyPem, manifestSha256Hex, valueB64) {
  let sigBuf;
  try {
    sigBuf = Buffer.from(valueB64, "base64");
  } catch {
    return false;
  }
  const msg = Buffer.from(manifestSha256Hex, "utf8");
  try {
    let keyObj;
    try {
      keyObj = crypto.createPublicKey(publicKeyPem);
    } catch {
      return false;
    }
    // Enforce declared-algo === key-type (defeats algorithm confusion).
    const allowedTypes = ALGO_KEYTYPE[algo];
    if (!allowedTypes || allowedTypes.indexOf(keyObj.asymmetricKeyType) === -1) return false;
    if (algo === "ed25519") return crypto.verify(null, msg, keyObj, sigBuf);
    if (algo === "ecdsa-p256-sha256") return crypto.verify("sha256", msg, keyObj, sigBuf);
    if (algo === "rsa-pss-sha256") {
      return crypto.verify("sha256", msg, { key: keyObj, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, sigBuf);
    }
    return false;
  } catch {
    return false;
  }
}

/* Core Lane-D check.
 * ctx = {
 *   manifest:      object (the release manifest),
 *   signature:     object conforming to release-signature.schema.json,
 *   trustedKeys:   { [signerId]: publicKeyPem }  // verifier policy — which keys to trust
 *   files?:        { [path]: sha256hex }          // optional on-disk hashes for matches-disk
 * }
 * Fails closed at the first violation. */
function verifyAirgap(ctx) {
  const evidence = [];
  const assumptions = [
    "Trust of the signer's key is the verifier's policy (out-of-band key distribution), not a GraphSmith guarantee.",
    "Decision path performs no network I/O and reads no clock/randomness (C1); a privileged local attacker who rewrites the verifier and keys is out of scope (A6).",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "trusted-core", reason: msg });

  // Any exception from hostile input (throwing getters, BigInt/circular/proxy in canonicalize)
  // fails closed rather than crashing the verifier (C2).
  try {
  if (!ctx || typeof ctx !== "object") return fail("no verification context provided");
  const { manifest, signature, trustedKeys, files } = ctx;

  if (!manifest || typeof manifest !== "object") return fail("release manifest missing or not an object");
  if (signature === undefined || signature === null) {
    return { status: "not-applicable", evidence, assumptions, reason: "no release signature present (a dev checkout legitimately has none)" };
  }
  if (typeof signature !== "object") return fail("release-signature must be an object");

  // 1. Signature shape — strict own-property allowlist (rejects extra + inherited fields).
  if (!strictSigShape(signature)) return fail("release-signature has extra, inherited, or missing fields — strict shape required");
  if (signature.schema_version !== "1.0") return fail("release-signature.schema_version must be '1.0'");
  if (!SIG_ALGOS.has(signature.algo)) return fail("release-signature.algo not in the allowed set");
  if (signature.delivery !== "out-of-band") return fail("release-signature.delivery must be 'out-of-band' — the whole point of air-gapped trust");
  if (typeof signature.signer !== "string" || signature.signer.length < 1) return fail("release-signature.signer missing");
  if (typeof signature.manifest_sha256 !== "string" || !HEX64.test(signature.manifest_sha256)) return fail("release-signature.manifest_sha256 not a 64-hex string");
  if (typeof signature.value !== "string" || signature.value.length < 1) return fail("release-signature.value missing");

  // 2. Recompute manifest hash; must match what was signed (detects a tampered manifest).
  const recomputed = sha256Hex(Buffer.from(canonicalize(manifest), "utf8"));
  if (recomputed !== signature.manifest_sha256) {
    return fail("manifest hash does not match the signed manifest_sha256 — manifest tampered or re-serialized", "trusted-core");
  }
  evidence.push("manifest_sha256 recomputed offline and matches the signed value (" + recomputed.slice(0, 12) + "…).");

  // 3. Signer trust is verifier policy. Unknown signer => honest 'unavailable', never green.
  if (!trustedKeys || typeof trustedKeys !== "object" || !Object.prototype.hasOwnProperty.call(trustedKeys, signature.signer)) {
    return {
      status: "unavailable",
      evidence,
      assumptions,
      reason: "signer '" + signature.signer + "' is not in the verifier's trusted-key set; authenticity cannot be established (not a pass)",
    };
  }

  // 4. Cryptographically verify the out-of-band signature over the manifest hash.
  const ok = verifySignatureValue(signature.algo, trustedKeys[signature.signer], signature.manifest_sha256, signature.value);
  if (!ok) return fail("signature does not verify against the trusted key for signer '" + signature.signer + "'", "trusted-core");
  evidence.push("out-of-band " + signature.algo + " signature verified against trusted key for signer '" + signature.signer + "' — AUTHENTIC-OFFLINE.");

  // 5. Optional matches-disk: each on-disk file hash must match the manifest.
  let matchesDisk = null;
  if (files && typeof files === "object" && Array.isArray(manifest.files)) {
    matchesDisk = true;
    for (const entry of manifest.files) {
      if (!entry || typeof entry.path !== "string") continue;
      // Own-property only — a polluted Object.prototype must not fake a match (Codex D3).
      if (!Object.prototype.hasOwnProperty.call(files, entry.path)) { matchesDisk = false; evidence.push("matches-disk: '" + entry.path + "' absent on disk."); break; }
      if (files[entry.path] !== entry.sha256) { matchesDisk = false; evidence.push("matches-disk: '" + entry.path + "' hash differs from manifest."); break; }
    }
    if (matchesDisk) evidence.push("matches-disk: all " + manifest.files.length + " manifest files match on-disk hashes.");
  }

  // T-profile distinction: authentic-offline (signature) vs matches-disk (hashes only).
  const tProfile = matchesDisk === false ? "authentic-offline (signature ok; on-disk hashes DIVERGE — investigate)" : "authentic-offline" + (matchesDisk === true ? " + matches-disk" : " (matches-disk not evaluated — no on-disk hashes supplied)");
  evidence.push("T-profile: " + tProfile + ".");

  // A signature that verifies but whose files diverge from disk is not a clean pass.
  if (matchesDisk === false) {
    return { status: "failed", evidence, assumptions, failure_domain: "evolvable-surface", reason: "manifest is authentic but on-disk files diverge from it" };
  }
  return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception during verification — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "register-airgap",
  run(ctx) {
    const r = verifyAirgap(ctx || {});
    // Normalize to the frozen report contract (drop the internal `reason` into evidence).
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason && (r.status === "failed" || r.status === "unavailable" || r.status === "not-applicable")) out.evidence.push("reason: " + r.reason);
    return out;
  },
};

module.exports = { ...check, verifyAirgap, canonicalize, sha256Hex, verifySignatureValue };

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    // Minimal smoke selftest (the full adversarial suite lives in tests/register/airgap/).
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const manifest = { schema_version: "1.0", kind: "release", release: "v0.3.0", files: [{ path: "a.js", sha256: "a".repeat(64) }] };
    const mhash = sha256Hex(Buffer.from(canonicalize(manifest), "utf8"));
    const value = crypto.sign(null, Buffer.from(mhash, "utf8"), privateKey).toString("base64");
    const signature = { schema_version: "1.0", algo: "ed25519", signer: "maintainer-1", manifest_sha256: mhash, value, delivery: "out-of-band" };
    const good = check.run({ manifest, signature, trustedKeys: { "maintainer-1": pem } });
    const tampered = check.run({ manifest: { ...manifest, release: "v9.9.9" }, signature, trustedKeys: { "maintainer-1": pem } });
    const untrusted = check.run({ manifest, signature, trustedKeys: {} });
    const pass = good.status === "verified" && tampered.status === "failed" && untrusted.status === "unavailable";
    console.log("register-airgap selftest:", pass ? "OK" : "FAIL", "| verified/failed/unavailable =", good.status, tampered.status, untrusted.status);
    process.exit(pass ? 0 : 1);
  } else {
    console.error("Usage: node checks/register-airgap.js --selftest");
    process.exit(1);
  }
}
