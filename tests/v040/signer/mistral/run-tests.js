"use strict";

const check = require("../../../../checks/v040-signer.js");
let pass = 0, fail = 0;

function test(name, fn) {
  try {
    const result = fn();
    if (result) {
      console.log("PASS " + name);
      pass++;
    } else {
      console.log("FAIL " + name + " " + (result === false ? "unexpected status" : String(result)));
      fail++;
    }
  } catch (e) {
    console.log("FAIL " + name + " exception: " + String(e));
    fail++;
  }
}

// 1. REVOKED bypass
test("revoked_signer_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "revoked" }
  ]};
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "failed" && result.reason.includes("REVOKED");
});

test("revoked_signer_with_rotation_chain_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" },
    { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k1" },
    { signer_id: "k3", public_key_pem: "PEM3", status: "revoked" }
  ]};
  const result = check.run({ signer: "k3", registry: reg });
  return result.status === "failed" && result.reason.includes("REVOKED");
});

// 2. RECALL bypass
test("full_recall_match_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" }
  ]};
  const recalls = { schema_version: "1.0", recalls: [
    { bundle_id: "bundle1", manifest_sha256: "sha1", reason: "test" }
  ]};
  const result = check.run({
    signer: "k1",
    registry: reg,
    recalls,
    bundle_id: "bundle1",
    manifest_sha256: "sha1"
  });
  return result.status === "failed" && result.reason.includes("RECALLED");
});

test("partial_recall_bundle_id_only_must_not_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" }
  ]};
  const recalls = { schema_version: "1.0", recalls: [
    { bundle_id: "bundle1", manifest_sha256: "sha1", reason: "test" }
  ]};
  const result = check.run({
    signer: "k1",
    registry: reg,
    recalls,
    bundle_id: "bundle1",
    manifest_sha256: "sha2"
  });
  return result.status === "verified";
});

test("partial_recall_manifest_only_must_not_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" }
  ]};
  const recalls = { schema_version: "1.0", recalls: [
    { bundle_id: "bundle1", manifest_sha256: "sha1", reason: "test" }
  ]};
  const result = check.run({
    signer: "k1",
    registry: reg,
    recalls,
    bundle_id: "bundle2",
    manifest_sha256: "sha1"
  });
  return result.status === "verified";
});

// 3. ROTATION chain
test("rotation_chain_to_active_must_verify", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" },
    { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k1" }
  ]};
  const result = check.run({ signer: "k2", registry: reg });
  return result.status === "verified";
});

test("rotation_chain_cycle_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" },
    { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k1" }
  ]};
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "failed" && result.reason.includes("rotation chain is broken");
});

test("rotation_chain_dangling_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" }
  ]};
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "failed" && result.reason.includes("rotation chain is broken");
});

test("rotation_chain_into_revoked_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "revoked" },
    { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k1" }
  ]};
  const result = check.run({ signer: "k2", registry: reg });
  return result.status === "failed" && result.reason.includes("rotation chain is broken");
});

test("long_rotation_cycle_must_fail", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" },
    { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k3" },
    { signer_id: "k3", public_key_pem: "PEM3", status: "rotated", rotated_to: "k1" }
  ]};
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "failed" && result.reason.includes("rotation chain is broken");
});

// 4. UNKNOWN signer
test("unknown_signer_must_be_unavailable", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" }
  ]};
  const result = check.run({ signer: "k2", registry: reg });
  return result.status === "unavailable";
});

// 5. C1: added_at/recalled_at must not affect decision
test("added_at_recalled_at_ignored", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active", added_at: "2020-01-01" }
  ]};
  const recalls = { schema_version: "1.0", recalls: [
    { bundle_id: "bundle1", manifest_sha256: "sha1", reason: "test", recalled_at: "2020-01-02" }
  ]};
  const result1 = check.run({
    signer: "k1",
    registry: reg,
    recalls,
    bundle_id: "bundle1",
    manifest_sha256: "sha1"
  });
  const result2 = check.run({
    signer: "k1",
    registry: { ...reg, signers: [{ ...reg.signers[0], added_at: "2021-01-01" }] },
    recalls: { ...recalls, recalls: [{ ...recalls.recalls[0], recalled_at: "2021-01-02" }] },
    bundle_id: "bundle1",
    manifest_sha256: "sha1"
  });
  return result1.status === "failed" && result2.status === "failed";
});

// 6. Crashes: malformed inputs
test("null_context_must_not_crash", () => {
  const result = check.run(null);
  return result.status === "failed";
});

test("malformed_registry_must_not_crash", () => {
  const result = check.run({ signer: "k1", registry: null });
  return result.status === "failed";
});

test("malformed_recalls_must_not_crash", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" }
  ]};
  const result = check.run({ signer: "k1", registry: reg, recalls: null });
  return result.status === "verified";
});

test("hostile_getters_must_not_crash", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" }
  ]};
  const hostile = new Proxy(reg, {
    get(target, prop) {
      if (prop === "signers") throw new Error("evil");
      return target[prop];
    }
  });
  const result = check.run({ signer: "k1", registry: hostile });
  return result.status === "failed";
});

test("bigint_must_not_crash", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: BigInt(123), public_key_pem: "PEM1", status: "active" }
  ]};
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "failed";
});

test("proto_pollution_must_not_crash", () => {
  const reg = { schema_version: "1.0", signers: [] };
  reg.__proto__.evil = "polluted";
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "unavailable";
});

test("duplicate_signer_ids_must_not_crash", () => {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" },
    { signer_id: "k1", public_key_pem: "PEM2", status: "revoked" }
  ]};
  const result = check.run({ signer: "k1", registry: reg });
  return result.status === "failed" || result.status === "verified";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
