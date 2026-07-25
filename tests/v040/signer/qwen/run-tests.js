const checks = require("../../../../checks/v040-signer.js");

let pass = 0;
let fail = 0;

function test(name, ctx, expected) {
  const result = checks.run(ctx);
  if (result.status === expected) {
    console.log("PASS " + name);
    pass++;
  } else {
    console.log("FAIL " + name + " " + JSON.stringify(result));
    fail++;
  }
}

// REVOKED bypass
test("revoked-bypass", { signer: "k2", registry: { schema_version: "1.0", signers: [{ signer_id: "k2", public_key_pem: "PEM2", status: "revoked" }] } }, "failed");

// RECALL bypass
test("recall-bypass-full-match", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }] }, recalls: { schema_version: "1.0", recalls: [{ bundle_id: "gsa-aaaaaaaaaaaaaaaa", manifest_sha256: "b".repeat(64), reason: "defect-found" }] }, bundle_id: "gsa-aaaaaaaaaaaaaaaa", manifest_sha256: "b".repeat(64) }, "failed");
test("recall-bypass-partial-match-bundle-id", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }] }, recalls: { schema_version: "1.0", recalls: [{ bundle_id: "gsa-aaaaaaaaaaaaaaaa", manifest_sha256: "b".repeat(64), reason: "defect-found" }] }, bundle_id: "gsa-aaaaaaaaaaaaaaaa", manifest_sha256: "c".repeat(64) }, "verified");
test("recall-bypass-partial-match-manifest-sha256", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }] }, recalls: { schema_version: "1.0", recalls: [{ bundle_id: "gsa-aaaaaaaaaaaaaaaa", manifest_sha256: "b".repeat(64), reason: "defect-found" }] }, bundle_id: "gsa-bbbbbbbbbbbbbbbb", manifest_sha256: "b".repeat(64) }, "verified");

// ROTATION chain
test("rotation-chain-cycle", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" }, { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k3" }, { signer_id: "k3", public_key_pem: "PEM3", status: "rotated", rotated_to: "k1" }] } }, "failed");
test("rotation-chain-dangling", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" }, { signer_id: "k2", public_key_pem: "PEM2", status: "rotated", rotated_to: "k3" }] } }, "failed");
test("rotation-chain-into-revoked", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" }, { signer_id: "k2", public_key_pem: "PEM2", status: "revoked" }] } }, "failed");
test("rotation-chain-live", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "rotated", rotated_to: "k2" }, { signer_id: "k2", public_key_pem: "PEM2", status: "active" }] } }, "verified");

// UNKNOWN signer
test("unknown-signer", { signer: "kX", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }] } }, "unavailable");

// added_at / recalled_at must NOT change a pass/fail decision
test("added-at-recalled-at-no-effect", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", added_at: "2023-01-01T00:00:00Z" }] }, recalls: { schema_version: "1.0", recalls: [{ bundle_id: "gsa-aaaaaaaaaaaaaaaa", manifest_sha256: "b".repeat(64), reason: "defect-found", recalled_at: "2023-01-01T00:00:00Z" }] }, bundle_id: "gsa-bbbbbbbbbbbbbbbb", manifest_sha256: "b".repeat(64) }, "verified");

// Crashes: malformed registry/recalls
test("malformed-registry-null", { signer: "k1", registry: null }, "failed");
test("malformed-registry-wrong-type", { signer: "k1", registry: 123 }, "failed");
test("malformed-registry-hostile-getter", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", get added_at() { throw new Error("hostile getter"); } }] } }, "failed");
test("malformed-registry-bigint", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", added_at: 123n }] } }, "failed");
test("malformed-registry-proto-pollution", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", __proto__: { pollute: "polluted" } }] } }, "failed");
test("malformed-registry-proxy", { signer: "k1", registry: { schema_version: "1.0", signers: new Proxy([{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }], {}) } }, "failed");
test("malformed-registry-duplicate-signer-ids", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }, { signer_id: "k1", public_key_pem: "PEM2", status: "active" }] } }, "failed");

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
