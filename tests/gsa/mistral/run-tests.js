"use strict";
const crypto = require("crypto");
const verify = require("../../../scripts/gsa-verify.js");
const produce = require("../../../scripts/gsa-produce.js");

let pass = 0, fail = 0;

function test(name, fn) {
  try {
    fn();
    console.log("PASS " + name);
    pass++;
  } catch (e) {
    console.log("FAIL " + name + " " + (e.message || String(e)));
    fail++;
  }
}

function generateKeyPair(algo) {
  if (algo === "ed25519") return crypto.generateKeyPairSync("ed25519");
  if (algo === "ecdsa-p256-sha256") return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  if (algo === "rsa-pss-sha256") return crypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048, hashAlgorithm: "sha256" });
  throw new Error("Unsupported algorithm: " + algo);
}

function createValidBundle(algo = "ed25519") {
  const kp = generateKeyPair(algo);
  const privateKey = kp.privateKey;
  const publicKeyPem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();

  const run = {
    bundle_id: "gsa-valid-test",
    mode: "standard",
    profiles: ["A", "X", "T"],
    producer: { name: "test", version: "1.0" },
    artifacts: {
      goal: { path: "goal.txt", body: "test goal" },
      policy: { path: "policy.yaml", body: "mode: standard" },
      model_manifest: { path: "model_manifest.json", body: "{}" },
      generated_ir: { path: "generated_ir.json", body: "{}" },
      compiled_graph: { path: "compiled_graph.json", body: '{"nodes":1}' },
      validation_report: { path: "validation_report.json", body: "{}" },
      execution_trace: { path: "execution_trace.jsonl", body: '{"step":1}' },
      output_manifest: { path: "output_manifest.json", body: "{}" },
      decision_record: { path: "decision_record.md", body: "# test" }
    },
    skills: [{
      skill_id: "s1",
      version: "1.0",
      implementation_hash: "a".repeat(64),
      source: "authored",
      approval_status: "approved",
      signature: "sig"
    }],
    adversarial: {
      suites: [{
        name: "test-suite",
        blocked: 10,
        total: 10
      }]
    },
    capabilities: { result: "satisfied", resources: {} }
  };

  const keys = { privateKey, signer: "test-signer", algo };
  const bundle = produce.produceBundle(run, keys);
  return { bundle, publicKeyPem, keys };
}

test("valid-bundle-passes", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const result = verify.verifyBundle(bundle, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status !== "PASS") throw new Error("Valid bundle should PASS");
  if (!result.confirmed_profiles.includes("A") || !result.confirmed_profiles.includes("X") || !result.confirmed_profiles.includes("T")) {
    throw new Error("Valid bundle should confirm A, X, T profiles");
  }
});

test("signature-strip-value", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.bundle_signature.value = "";
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with empty signature should FAIL");
});

test("signature-replace-with-another-key", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const kp2 = generateKeyPair("ed25519");
  const privateKey2 = kp2.privateKey;
  const publicKeyPem2 = kp2.publicKey.export({ type: "spki", format: "pem" }).toString();

  const tampered = JSON.parse(JSON.stringify(bundle));
  const preimage = { ...tampered.manifest };
  delete preimage.bundle_signature;
  const manifestSha = verify.sha256Hex(Buffer.from(verify.canonicalize(preimage), "utf8"));
  const newSig = crypto.sign(null, Buffer.from(manifestSha, "utf8"), privateKey2).toString("base64");
  tampered.manifest.bundle_signature.value = newSig;

  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with signature from untrusted key should FAIL");
});

test("signature-untrusted-signer", () => {
  const { bundle } = createValidBundle();
  const result = verify.verifyBundle(bundle, { trustedKeys: {} });
  if (result.status === "PASS") throw new Error("Bundle with untrusted signer should FAIL");
});

test("manifest-tamper-mode", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.mode = "regulator";
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with tampered mode should FAIL");
});

test("manifest-tamper-profile", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.profiles.push("R");
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with tampered profiles should FAIL");
});

test("manifest-tamper-artifact-sha256", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.artifacts.goal.sha256 = "0".repeat(64);
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with tampered artifact sha256 should FAIL");
});

test("manifest-tamper-control-attestations", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.control_attestations.adversarial_batteries_passed = false;
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with tampered control attestations should FAIL");
});

test("artifact-tamper-bytes", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tamperedContents = { ...bundle.contents };
  tamperedContents["goal.txt"] = "tampered content";
  const result = verify.verifyBundle({ manifest: bundle.manifest, contents: tamperedContents }, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with tampered artifact bytes should FAIL");
});

test("control-attestation-lie", () => {
  const { bundle, publicKeyPem, keys } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));

  // Create a bundle where adversarial batteries didn't pass but claim they did
  tampered.manifest.adversarial.suites[0].blocked = 5;
  tampered.manifest.control_attestations.adversarial_batteries_passed = true;

  // Re-sign the bundle to make it look valid
  const preimage = { ...tampered.manifest };
  delete preimage.bundle_signature;
  const manifestSha = verify.sha256Hex(Buffer.from(verify.canonicalize(preimage), "utf8"));
  const newSig = crypto.sign(null, Buffer.from(manifestSha, "utf8"), keys.privateKey).toString("base64");
  tampered.manifest.bundle_signature.manifest_sha256 = manifestSha;
  tampered.manifest.bundle_signature.value = newSig;

  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with lying control attestation should FAIL");
});

test("profile-confusion-A-without-evidence", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.profiles = ["A"];

  // Remove all artifacts to make A claim false
  const emptyContents = {};
  const result = verify.verifyBundle({ manifest: tampered.manifest, contents: emptyContents }, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS" && result.confirmed_profiles.includes("A")) {
    throw new Error("Profile A should not be confirmed without evidence");
  }
});

test("profile-confusion-X-without-evidence", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.profiles = ["X"];
  tampered.manifest.adversarial.suites[0].blocked = 5; // Not all blocked

  // Re-sign
  const preimage = { ...tampered.manifest };
  delete preimage.bundle_signature;
  const manifestSha = verify.sha256Hex(Buffer.from(verify.canonicalize(preimage), "utf8"));
  const newSig = crypto.sign(null, Buffer.from(manifestSha, "utf8"), bundle.manifest.bundle_signature.algo === "ed25519" ?
    keys.privateKey : (() => { throw new Error("Unsupported algo") })()).toString("base64");
  tampered.manifest.bundle_signature.manifest_sha256 = manifestSha;
  tampered.manifest.bundle_signature.value = newSig;

  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.confirmed_profiles.includes("X")) {
    throw new Error("Profile X should not be confirmed without evidence");
  }
});

test("path-traversal-dotdot", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.artifacts.goal.path = "../evil.txt";
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with path traversal should FAIL");
});

test("path-backslash", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.artifacts.goal.path = "evil\\file.txt";
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with backslash path should FAIL");
});

test("path-non-nfc-unicode", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.artifacts.goal.path = "file\u0308.txt"; // Combining diaeresis
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with non-NFC unicode path should FAIL");
});

test("conditional-presence-mode-regulator-missing-summary", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.mode = "regulator";
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Regulator mode without summary should FAIL");
});

test("conditional-presence-regulator-summary-with-wrong-mode", () => {
  const { bundle, publicKeyPem, keys } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.mode = "standard";
  tampered.manifest.artifacts.regulator_summary = {
    path: "regulator_summary.json",
    sha256: verify.sha256Hex(Buffer.from("{}", "utf8")),
    bytes: 2
  };
  tampered.contents = { ...tampered.contents, "regulator_summary.json": "{}" };

  // Re-sign
  const preimage = { ...tampered.manifest };
  delete preimage.bundle_signature;
  const manifestSha = verify.sha256Hex(Buffer.from(verify.canonicalize(preimage), "utf8"));
  const newSig = crypto.sign(null, Buffer.from(manifestSha, "utf8"), keys.privateKey).toString("base64");
  tampered.manifest.bundle_signature.manifest_sha256 = manifestSha;
  tampered.manifest.bundle_signature.value = newSig;

  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Regulator summary with non-regulator mode should FAIL");
});

test("canonicalization-key-reordering", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));

  // Create a manifest with reordered keys that should canonicalize to the same value
  const original = { ...tampered.manifest };
  delete original.bundle_signature;
  const originalCanonical = verify.canonicalize(original);

  const reordered = {};
  const keys = Object.keys(original).sort((a, b) => b.localeCompare(a));
  for (const key of keys) {
    reordered[key] = original[key];
  }

  const reorderedCanonical = verify.canonicalize(reordered);
  if (originalCanonical !== reorderedCanonical) {
    throw new Error("Canonicalization should be order-independent");
  }

  // Now test that the verifier catches a real tamper
  tampered.manifest.profiles = ["A", "X", "T", "R"];
  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with tampered profiles should FAIL");
});

test("canonicalization-different-manifest-same-hash", () => {
  // This would be a serious vulnerability if found
  const obj1 = { a: 1, b: 2 };
  const obj2 = { b: 2, a: 1 };
  const canonical1 = verify.canonicalize(obj1);
  const canonical2 = verify.canonicalize(obj2);
  if (canonical1 !== canonical2) {
    throw new Error("Canonicalization should make equivalent objects identical");
  }

  // Test with nested objects
  const nested1 = { a: { b: 1, c: 2 }, d: 3 };
  const nested2 = { d: 3, a: { c: 2, b: 1 } };
  const nestedCanonical1 = verify.canonicalize(nested1);
  const nestedCanonical2 = verify.canonicalize(nested2);
  if (nestedCanonical1 !== nestedCanonical2) {
    throw new Error("Canonicalization should handle nested objects correctly");
  }
});

test("malformed-bundle-null", () => {
  const result = verify.verifyBundle(null, { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("Null bundle should FAIL");
});

test("malformed-bundle-undefined", () => {
  const result = verify.verifyBundle(undefined, { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("Undefined bundle should FAIL");
});

test("malformed-bundle-wrong-type", () => {
  const result = verify.verifyBundle("not an object", { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("String bundle should FAIL");
});

test("malformed-bundle-circular-reference", () => {
  const circular = { manifest: {}, contents: {} };
  circular.manifest.self = circular;
  const result = verify.verifyBundle(circular, { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("Circular bundle should FAIL");
});

test("malformed-bundle-proxy", () => {
  const target = { manifest: {}, contents: {} };
  const proxy = new Proxy(target, {
    get: (obj, prop) => {
      if (prop === "toString") return () => "[object Object]";
      throw new Error("Access denied");
    }
  });
  const result = verify.verifyBundle(proxy, { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("Proxy bundle should FAIL");
});

test("malformed-bundle-bigint", () => {
  const bundle = {
    manifest: {
      schema_version: "0.1",
      mode: "standard",
      artifacts: {
        goal: { path: "goal.txt", sha256: "a".repeat(64), bytes: 999n }
      },
      bundle_signature: { algo: "ed25519", signer: "test", manifest_sha256: "a".repeat(64), value: "sig" }
    },
    contents: { "goal.txt": "test" }
  };
  const result = verify.verifyBundle(bundle, { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("Bundle with BigInt should FAIL");
});

test("malformed-bundle-getter-throws", () => {
  const bundle = {
    get manifest() { throw new Error("Hostile getter"); },
    contents: {}
  };
  const result = verify.verifyBundle(bundle, { trustedKeys: {} });
  if (result.status !== "FAIL") throw new Error("Bundle with throwing getter should FAIL");
});

test("different-algorithms", () => {
  for (const algo of ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"]) {
    const { bundle, publicKeyPem } = createValidBundle(algo);
    const result = verify.verifyBundle(bundle, { trustedKeys: { "test-signer": publicKeyPem } });
    if (result.status !== "PASS") throw new Error(`Valid bundle with ${algo} should PASS`);
  }
});

test("revoked-skill", () => {
  const { bundle, publicKeyPem } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.manifest.skills[0].approval_status = "approved";
  tampered.manifest.skills[0].implementation_hash = "revoked-hash";

  const result = verify.verifyBundle(tampered, {
    trustedKeys: { "test-signer": publicKeyPem },
    revoked: new Set(["revoked-hash"])
  });
  if (result.status === "PASS") throw new Error("Bundle with revoked skill should FAIL");
});

test("repair-log-conditional-presence", () => {
  const { bundle, publicKeyPem, keys } = createValidBundle();
  const tampered = JSON.parse(JSON.stringify(bundle));

  // Add repair markers to trace
  tampered.contents["execution_trace.jsonl"] = '{"step":1,"MUTATION_INTENT":true}';
  tampered.manifest.artifacts.execution_trace.sha256 = verify.sha256Hex(Buffer.from(tampered.contents["execution_trace.jsonl"], "utf8"));
  tampered.manifest.artifacts.execution_trace.bytes = Buffer.byteLength(tampered.contents["execution_trace.jsonl"], "utf8");

  // Re-sign
  const preimage = { ...tampered.manifest };
  delete preimage.bundle_signature;
  const manifestSha = verify.sha256Hex(Buffer.from(verify.canonicalize(preimage), "utf8"));
  const newSig = crypto.sign(null, Buffer.from(manifestSha, "utf8"), keys.privateKey).toString("base64");
  tampered.manifest.bundle_signature.manifest_sha256 = manifestSha;
  tampered.manifest.bundle_signature.value = newSig;

  const result = verify.verifyBundle(tampered, { trustedKeys: { "test-signer": publicKeyPem } });
  if (result.status === "PASS") throw new Error("Bundle with repair markers but no repair log should FAIL");
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
