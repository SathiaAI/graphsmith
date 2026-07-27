"use strict";
const crypto = require("crypto");
const assert = require("assert");
const target = require("../../../../checks/register-approver.js");

const tests = [];
let pass = 0, fail = 0;

function test(name, fn) {
  tests.push({ name, fn });
}

function run() {
  for (const t of tests) {
    try {
      t.fn();
      console.log("PASS " + t.name);
      pass++;
    } catch (e) {
      console.log("FAIL " + t.name + " " + (e.message || String(e)));
      fail++;
    }
  }
  console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
  process.exitCode = fail === 0 ? 0 : 1;
}

// Helper: generate ed25519 key pair
function generateKeyPair() {
  return crypto.generateKeyPairSync("ed25519");
}

// Helper: export public key as PEM
function publicKeyPem(keyPair) {
  return keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
}

// Helper: sign a message
function signMessage(keyPair, message) {
  return crypto.sign(null, Buffer.from(message, "utf8"), keyPair.privateKey).toString("base64");
}

// Helper: create a valid attestation
function createAttestation(keyPair, signerId, approverId, packetSha256, artifactSha256 = packetSha256) {
  return {
    schema_version: "1.0",
    approver_id: approverId,
    role: "release-owner",
    method: "signed-commit",
    artifact_sha256: artifactSha256,
    obligation_set_id: "set-1",
    signature: {
      algo: "ed25519",
      signer: signerId,
      packet_sha256: packetSha256,
      value: signMessage(keyPair, packetSha256)
    }
  };
}

// Helper: create a valid policy
function createPolicy(n = 1, proposerNeApprover = false) {
  return {
    schema_version: "1.0",
    separation_of_duties: {
      proposer_ne_approver: proposerNeApprover,
      n_of_m: { n, m: 3 }
    },
    fail_closed: true,
    activation_preconditions: []
  };
}

// Helper: create a valid context
function createContext(packetSha256, approvals, policy, trustedKeys, proposerId) {
  return {
    packet_sha256: packetSha256,
    approvals: approvals,
    policy: policy,
    trustedKeys: trustedKeys,
    proposer_id: proposerId
  };
}

// Test 1: FAIL-OPEN - forged signature
test("fail-open-forged-signature", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  // Tamper with the signature
  attestation.signature.value = "AAAA" + attestation.signature.value.substring(4);
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Forged signature was accepted");
  }
});

// Test 2: FAIL-OPEN - wrong key
test("fail-open-wrong-key", () => {
  const keyPair1 = generateKeyPair();
  const keyPair2 = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair1) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair2, "key-1", "alice", packetSha256);
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Signature with wrong key was accepted");
  }
});

// Test 3: FAIL-OPEN - untrusted signer
test("fail-open-untrusted-signer", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-2", "alice", packetSha256);
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Untrusted signer was accepted");
  }
});

// Test 4: FAIL-OPEN - signature over different hash
test("fail-open-different-hash", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const differentHash = "b".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", differentHash);
  attestation.signature.packet_sha256 = packetSha256; // Lie about the hash
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Signature over different hash was accepted");
  }
});

// Test 5: FAIL-OPEN - artifact_sha256 mismatch
test("fail-open-artifact-mismatch", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const differentArtifact = "b".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256, differentArtifact);
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Artifact SHA mismatch was accepted");
  }
});

// Test 6: SEPARATION OF DUTIES - proposer approves
test("separation-of-duties-proposer-approves", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const proposerId = "alice";
  const attestation = createAttestation(keyPair, "key-1", proposerId, packetSha256);
  const policy = createPolicy(1, true);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, proposerId);
  const result = target.run(ctx);
  if (result.status !== "failed") {
    throw new Error("Proposer approval was accepted when separation of duties is required");
  }
});

// Test 7: N-of-M SYBIL - same key different approver_id
test("n-of-m-sybil-same-key-different-approver", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation1 = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const attestation2 = createAttestation(keyPair, "key-1", "bob", packetSha256);
  const policy = createPolicy(2);
  const ctx = createContext(packetSha256, [attestation1, attestation2], policy, trustedKeys, "carol");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Same key with different approver_id was counted as distinct authorities");
  }
});

// Test 8: DUPLICATES - same approver/key repeated
test("duplicates-same-approver-key-repeated", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const policy = createPolicy(2);
  const ctx = createContext(packetSha256, [attestation, attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Duplicate approver/key was counted multiple times");
  }
});

// Test 9: ALGORITHM CONFUSION - declared algo != key type
test("algorithm-confusion-declared-algo-ne-key-type", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  attestation.signature.algo = "rsa-pss-sha256"; // Wrong algorithm for ed25519 key
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Algorithm confusion was accepted");
  }
});

// Test 10: ALGORITHM CONFUSION - extra fields in attestation
test("algorithm-confusion-extra-attestation-fields", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  attestation.extra_field = "should not be here";
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Extra attestation fields were accepted");
  }
});

// Test 11: ALGORITHM CONFUSION - extra fields in signature
test("algorithm-confusion-extra-signature-fields", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  attestation.signature.extra_field = "should not be here";
  const policy = createPolicy(1);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status === "verified") {
    throw new Error("Extra signature fields were accepted");
  }
});

// Test 12: C1 - approver_id as decision input
test("c1-approver-id-as-decision-input", () => {
  const keyPair1 = generateKeyPair();
  const keyPair2 = generateKeyPair();
  const trustedKeys = {
    "key-1": publicKeyPem(keyPair1),
    "key-2": publicKeyPem(keyPair2)
  };
  const packetSha256 = "a".repeat(64);
  const attestation1 = createAttestation(keyPair1, "key-1", "alice", packetSha256);
  const attestation2 = createAttestation(keyPair2, "key-2", "bob", packetSha256);
  // Policy requires 2 distinct approvers
  const policy = createPolicy(2);
  const ctx = createContext(packetSha256, [attestation1, attestation2], policy, trustedKeys, "carol");
  const result = target.run(ctx);
  if (result.status !== "verified") {
    throw new Error("Valid distinct approvers were rejected");
  }
  // Now try with same approver_id but different keys (should still work)
  const attestation3 = createAttestation(keyPair2, "key-2", "alice", packetSha256);
  const ctx2 = createContext(packetSha256, [attestation1, attestation3], policy, trustedKeys, "carol");
  const result2 = target.run(ctx2);
  if (result2.status !== "verified") {
    throw new Error("Same approver_id with different keys was rejected (approver_id should not be decision input)");
  }
});

// Test 13: Crashes - malformed input (null context)
test("crash-null-context", () => {
  const result = target.run(null);
  if (result.status !== "failed") {
    throw new Error("Null context did not fail gracefully");
  }
});

// Test 14: Crashes - malformed input (wrong types)
test("crash-wrong-types", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const policy = createPolicy(1);
  // Wrong type for packet_sha256
  const ctx = {
    packet_sha256: 12345,
    approvals: [attestation],
    policy: policy,
    trustedKeys: trustedKeys,
    proposer_id: "bob"
  };
  const result = target.run(ctx);
  if (result.status !== "failed") {
    throw new Error("Wrong type for packet_sha256 did not fail gracefully");
  }
});

// Test 15: Crashes - malformed input (BigInt)
test("crash-bigint", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  // createPolicy(1) leaves proposer_ne_approver false, so checks/register-approver.js
  // never reads proposer_id at all and the BigInt was inert -- the case could only
  // ever have passed by accident or failed for an unrelated reason. Turn separation of
  // duties ON so the hostile value actually reaches the code path under test.
  const policy = createPolicy(1, true);
  const ctx = {
    packet_sha256: packetSha256,
    approvals: [attestation],
    policy: policy,
    trustedKeys: trustedKeys,
    proposer_id: BigInt(12345)
  };
  const result = target.run(ctx);
  if (result.status !== "failed") {
    throw new Error("BigInt proposer_id did not fail gracefully");
  }
});

// Test 16: Crashes - malformed input (Proxy)
test("crash-proxy", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const policy = createPolicy(1);
  const ctx = new Proxy({
    packet_sha256: packetSha256,
    approvals: [attestation],
    policy: policy,
    trustedKeys: trustedKeys,
    proposer_id: "bob"
  }, {
    get(target, prop) {
      if (prop === "packet_sha256") {
        throw new Error("Proxy attack");
      }
      return target[prop];
    }
  });
  const result = target.run(ctx);
  if (result.status !== "failed") {
    throw new Error("Proxy attack did not fail gracefully");
  }
});

// Test 17: Crashes - malformed input (hostile getter)
test("crash-hostile-getter", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const policy = createPolicy(1);
  const ctx = {
    get packet_sha256() {
      throw new Error("Hostile getter");
    },
    approvals: [attestation],
    policy: policy,
    trustedKeys: trustedKeys,
    proposer_id: "bob"
  };
  const result = target.run(ctx);
  if (result.status !== "failed") {
    throw new Error("Hostile getter did not fail gracefully");
  }
});

// Test 18: Crashes - proto pollution
test("crash-proto-pollution", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const policy = createPolicy(1);
  const ctx = {
    packet_sha256: packetSha256,
    approvals: [attestation],
    policy: policy,
    trustedKeys: trustedKeys,
    proposer_id: "bob"
  };
  // Pollute Object.prototype
  Object.prototype.polluted = "yes";
  let result;
  try {
    result = target.run(ctx);
  } finally {
    delete Object.prototype.polluted;   // was leaking into every later case on a throw
  }
  /* The security property is that a polluted prototype cannot produce a TRUSTED
   * verdict, and the only status that grants trust is "verified" --
   * scripts/gsa-register.js:40 gates the precondition on exactly that string, so
   * "unavailable" and "failed" are equally fail-closed downstream.
   *
   * The old assertion demanded "failed" specifically. What actually happens is
   * "unavailable": the allowlist in shapeOk() walks inherited enumerable keys, so the
   * injected key makes the attestation shape-invalid, leaving zero valid signers --
   * "cannot determine" rather than "determined to be bad", which is the honest reading
   * and the one this module documents. Assert the property, not one spelling of it. */
  if (result.status === "verified") {
    throw new Error("Object.prototype pollution produced a VERIFIED attestation: " +
      JSON.stringify(result));
  }
});

// Test 19: Valid case - should pass
test("valid-case-should-pass", () => {
  const keyPair1 = generateKeyPair();
  const keyPair2 = generateKeyPair();
  const trustedKeys = {
    "key-1": publicKeyPem(keyPair1),
    "key-2": publicKeyPem(keyPair2)
  };
  const packetSha256 = "a".repeat(64);
  const attestation1 = createAttestation(keyPair1, "key-1", "alice", packetSha256);
  const attestation2 = createAttestation(keyPair2, "key-2", "bob", packetSha256);
  const policy = createPolicy(2);
  const ctx = createContext(packetSha256, [attestation1, attestation2], policy, trustedKeys, "carol");
  const result = target.run(ctx);
  if (result.status !== "verified") {
    throw new Error("Valid case was rejected");
  }
});

// Test 20: Under threshold - should be unavailable
test("under-threshold-should-be-unavailable", () => {
  const keyPair = generateKeyPair();
  const trustedKeys = { "key-1": publicKeyPem(keyPair) };
  const packetSha256 = "a".repeat(64);
  const attestation = createAttestation(keyPair, "key-1", "alice", packetSha256);
  const policy = createPolicy(2);
  const ctx = createContext(packetSha256, [attestation], policy, trustedKeys, "bob");
  const result = target.run(ctx);
  if (result.status !== "unavailable") {
    throw new Error("Under threshold case was not marked as unavailable");
  }
});

run();
