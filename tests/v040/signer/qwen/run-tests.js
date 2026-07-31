const checks = require("../../../../checks/v040-signer.js");

let pass = 0;
let fail = 0;

/* ADJUDICATED cases.
 *
 * This is an adversarial-review artifact: it records what a tester expected, which is
 * not always what the product should do. Where a case was formally adjudicated in the
 * lane's ADJUDICATION.md as NOT a defect, two wrong things could be done with it --
 * flip the expectation silently, which erases the record that the disagreement ever
 * happened, or leave it FAILing forever, which is why nobody reads the evidence-only
 * list any more.
 *
 * Third option: run the case, assert the ADJUDICATED behaviour so a regression away
 * from it still fails, and print it under its own status citing the ruling. The
 * history survives, and a permanently-red line stops training people to ignore red.
 */
let adjudicated = 0;

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

/* @param ruling one-line citation of the ADJUDICATION.md paragraph that settled it. */
function adjudicatedTest(name, ctx, adjudicatedStatus, ruling) {
  /* Contract 10 List C: an ADJUDICATED verdict is only admissible with a citation to
   * the ruling that produced it. Without one it is an unexplained non-failure, which is
   * the shape this status exists to prevent. Fail closed on a missing citation. */
  if (typeof ruling !== "string" || ruling.trim().length === 0) {
    console.log("FAIL " + name + " - ADJUDICATED recorded with no citation to the ruling " +
      "that settled it (contract 10 List C)");
    fail++;
    return;
  }
  const result = checks.run(ctx);
  if (result.status === adjudicatedStatus) {
    console.log("ADJUDICATED " + name + " -> " + adjudicatedStatus + " (not a defect: " + ruling + ")");
    adjudicated++;
  } else {
    console.log("FAIL " + name + " REGRESSED away from the adjudicated behaviour: expected " +
      adjudicatedStatus + ", got " + result.status + " " + JSON.stringify(result));
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
adjudicatedTest("malformed-registry-hostile-getter", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", get added_at() { throw new Error("hostile getter"); } }] } }, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — added_at/recalled_at are C1 evidence fields the check deliberately never reads');
adjudicatedTest("malformed-registry-bigint", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", added_at: 123n }] } }, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — added_at/recalled_at are C1 evidence fields the check deliberately never reads');
adjudicatedTest("malformed-registry-proto-pollution", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active", __proto__: { pollute: "polluted" } }] } }, "verified",
  'ADJUDICATION.md — inert __proto__ on an otherwise-valid entry; every read field is own and valid');
adjudicatedTest("malformed-registry-proxy", { signer: "k1", registry: { schema_version: "1.0", signers: new Proxy([{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }], {}) } }, "verified",
  'ADJUDICATION.md — a transparent Proxy that Array.isArray sees through and that returns the valid entry');
test("malformed-registry-duplicate-signer-ids", { signer: "k1", registry: { schema_version: "1.0", signers: [{ signer_id: "k1", public_key_pem: "PEM1", status: "active" }, { signer_id: "k1", public_key_pem: "PEM2", status: "active" }] } }, "failed");

console.log("# summary PASS=" + pass + " FAIL=" + fail + " ADJUDICATED=" + adjudicated +
  " total=" + (pass + fail + adjudicated));
process.exitCode = fail === 0 ? 0 : 1;
