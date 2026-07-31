"use strict";
const crypto = require("crypto");
/* canonicalize, not JSON.stringify: gsa-verify.js hashes the manifest preimage with
 * RFC-8785-ish canonical JSON (sorted keys, compact). Every re-sign in this file used
 * JSON.stringify, producing a different digest, so each tampered bundle died at the
 * SIGNATURE step and never reached the check it was written to exercise. One case
 * (profile_confusion) failed outright; three others -- false_control,
 * conditional_presence and revoked_skill -- reported PASS for the same wrong reason,
 * and were verified to still report PASS with their target checks neutered. Zero
 * coverage, printed green. */
const { verifyBundle, canonicalize } = require("../../../scripts/gsa-verify.js");
const { produceBundle } = require("../../../scripts/gsa-produce.js");

let pass = 0, fail = 0;

// Helper to generate key pairs
function generateKeyPair(algo = "ed25519") {
  return crypto.generateKeyPairSync(algo);
}

// Helper to create a valid bundle
async function createValidBundle() {
  const kp = generateKeyPair();
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  const run = {
    bundle_id: "gsa-" + Date.now(),
    mode: "standard",
    profiles: ["A", "X"],
    producer: { name: "test", version: "1.0" },
    artifacts: {
      goal: { path: "goal.txt", body: "test" },
      policy: { path: "policy.yaml", body: "mode: standard" },
      model_manifest: { path: "model.json", body: "{}" },
      generated_ir: { path: "ir.json", body: "{}" },
      compiled_graph: { path: "graph.json", body: "{}" },
      validation_report: { path: "report.json", body: "{}" },
      execution_trace: { path: "trace.json", body: "{}" },
      output_manifest: { path: "out.json", body: "{}" },
      decision_record: { path: "dec.md", body: "# ok" }
    },
    skills: [],
    adversarial: { suites: [{ name: "test", blocked: 1, total: 1 }] },
    capabilities: { result: "satisfied", resources: {} }
  };
  const bundle = produceBundle(run, { 
    privateKey: kp.privateKey, 
    signer: "test", 
    algo: "ed25519" 
  });
  return { bundle, pem, kp };
}

// Test 1: Empty signature value
(async () => {
  const { bundle, pem } = await createValidBundle();
  bundle.manifest.bundle_signature.value = "";
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS empty_signature" : "FAIL empty_signature");
})();

// Test 2: Untrusted signer
(async () => {
  const { bundle } = await createValidBundle();
  const kp2 = generateKeyPair();
  const pem2 = kp2.publicKey.export({ type: "spki", format: "pem" }).toString();
  const result = verifyBundle(bundle, { trustedKeys: { other: pem2 } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS untrusted_signer" : "FAIL untrusted_signer");
})();

// Test 3: Tampered manifest field
(async () => {
  const { bundle, pem, kp } = await createValidBundle();
  bundle.manifest.mode = "deterministic"; // Change without re-signing
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS tampered_manifest" : "FAIL tampered_manifest");
})();

// Test 4: Tampered artifact content
(async () => {
  const { bundle, pem } = await createValidBundle();
  bundle.contents["goal.txt"] = "tampered";
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS tampered_artifact" : "FAIL tampered_artifact");
})();

// Test 5: False control attestation
(async () => {
  const { bundle, pem, kp } = await createValidBundle();
  // Change control and re-sign to make it a pure control lie
  bundle.manifest.control_attestations.adversarial_batteries_passed = false;
  const preimage = { ...bundle.manifest }; delete preimage.bundle_signature;
  const manifestSha = crypto.createHash("sha256").update(canonicalize(preimage)).digest("hex");
  bundle.manifest.bundle_signature.manifest_sha256 = manifestSha;
  bundle.manifest.bundle_signature.value = crypto.sign(null, Buffer.from(manifestSha, "utf8"), kp.privateKey).toString("base64");
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS false_control" : "FAIL false_control");
})();

// Test 6: Profile confusion (claim X without evidence)
(async () => {
  const { bundle, pem, kp } = await createValidBundle();
  bundle.manifest.adversarial.suites[0].blocked = 0; // Make adversarial fail
  // ...and tell the truth about it in control_attestations. Leaving this true made the
  // bundle contain an actual LIE, which step 9 correctly rejected before the §9.10
  // profile-downgrade logic this case is named for ever ran. The scenario under test
  // is an honest bundle that claims a profile its evidence does not support -- not a
  // bundle that misreports a control.
  bundle.manifest.control_attestations.adversarial_batteries_passed = false;
  // Re-sign to make it a pure profile lie
  const preimage = { ...bundle.manifest }; delete preimage.bundle_signature;
  const manifestSha = crypto.createHash("sha256").update(canonicalize(preimage)).digest("hex");
  bundle.manifest.bundle_signature.manifest_sha256 = manifestSha;
  bundle.manifest.bundle_signature.value = crypto.sign(null, Buffer.from(manifestSha, "utf8"), kp.privateKey).toString("base64");
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "PASS" && result.downgraded_profiles.includes("X")) pass++;
  else fail++;
  console.log(result.status === "PASS" && result.downgraded_profiles.includes("X") 
    ? "PASS profile_confusion" 
    : "FAIL profile_confusion");
})();

// Test 7: Path traversal
(async () => {
  const { bundle, pem } = await createValidBundle();
  bundle.manifest.artifacts.goal.path = "../evil";
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS path_traversal" : "FAIL path_traversal");
})();

// Test 8: Conditional presence violation
(async () => {
  const { bundle, pem, kp } = await createValidBundle();
  bundle.manifest.mode = "regulator"; // Change to regulator without summary
  // Re-sign
  const preimage = { ...bundle.manifest }; delete preimage.bundle_signature;
  const manifestSha = crypto.createHash("sha256").update(canonicalize(preimage)).digest("hex");
  bundle.manifest.bundle_signature.manifest_sha256 = manifestSha;
  bundle.manifest.bundle_signature.value = crypto.sign(null, Buffer.from(manifestSha, "utf8"), kp.privateKey).toString("base64");
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS conditional_presence" : "FAIL conditional_presence");
})();

// Test 9: Malformed bundle (circular reference)
(async () => {
  const { bundle, pem } = await createValidBundle();
  const circular = { manifest: bundle.manifest };
  circular.self = circular;
  const result = verifyBundle(circular, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS malformed_circular" : "FAIL malformed_circular");
})();

// Test 10: Malformed bundle (wrong types)
(async () => {
  const result = verifyBundle({ manifest: "not an object", contents: {} }, {});
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS malformed_types" : "FAIL malformed_types");
})();

// Test 11: Signature algorithm confusion
(async () => {
  const { bundle, pem } = await createValidBundle();
  bundle.manifest.bundle_signature.algo = "ecdsa-p256-sha256"; // Claim wrong algorithm
  const result = verifyBundle(bundle, { trustedKeys: { test: pem } });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS algo_confusion" : "FAIL algo_confusion");
})();

// Test 12: Revoked skill
(async () => {
  const { bundle, pem, kp } = await createValidBundle();
  bundle.manifest.skills = [{
    skill_id: "bad", 
    version: "1.0", 
    implementation_hash: "revoked", 
    source: "authored", 
    approval_status: "approved", 
    signature: "sig"
  }];
  // Re-sign
  const preimage = { ...bundle.manifest }; delete preimage.bundle_signature;
  const manifestSha = crypto.createHash("sha256").update(canonicalize(preimage)).digest("hex");
  bundle.manifest.bundle_signature.manifest_sha256 = manifestSha;
  bundle.manifest.bundle_signature.value = crypto.sign(null, Buffer.from(manifestSha, "utf8"), kp.privateKey).toString("base64");
  const result = verifyBundle(bundle, { 
    trustedKeys: { test: pem },
    revoked: new Set(["revoked"])
  });
  if (result.status === "FAIL") pass++; else fail++;
  console.log(result.status === "FAIL" ? "PASS revoked_skill" : "FAIL revoked_skill");
})();

// Wait for async tests to complete
setTimeout(() => {
  console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
  process.exitCode = fail === 0 ? 0 : 1;
}, 1000);
