"use strict";
const crypto = require("crypto");
const { run, verifyApprovers, verifySig } = require("../../../../checks/register-approver.js");

let pass = 0, fail = 0;
const tests = [];

function test(name, fn) {
  try {
    fn();
    console.log("PASS " + name);
    pass++;
  } catch (e) {
    console.log("FAIL " + name + " " + e.message);
    fail++;
  }
}

// Helper functions
const mkKeyPair = () => crypto.generateKeyPairSync("ed25519");
const pem = (k) => k.publicKey.export({ type: "spki", format: "pem" }).toString();
const head = "c".repeat(64);
const sign = (kp, signer, approver) => ({
  schema_version: "1.0",
  approver_id: approver,
  role: "release-owner",
  method: "signed-commit",
  artifact_sha256: head,
  obligation_set_id: "set-1",
  signature: {
    algo: "ed25519",
    signer,
    packet_sha256: head,
    value: crypto.sign(null, Buffer.from(head, "utf8"), kp.privateKey).toString("base64")
  }
});
const policy = {
  schema_version: "1.0",
  separation_of_duties: { proposer_ne_approver: true, n_of_m: { n: 2, m: 3 } },
  fail_closed: true,
  activation_preconditions: ["approver_attestation_valid"]
};

// Test cases
tests.push(() => test("FAIL-OPEN: forged signature", () => {
  const k1 = mkKeyPair(), k2 = mkKeyPair();
  const trusted = { "key-1": pem(k1) };
  const forgedSig = sign(k2, "key-1", "alice"); // Using k2 but claiming to be key-1
  const result = run({ packet_sha256: head, approvals: [forgedSig], policy, trustedKeys: trusted, proposer_id: "carol" });
  if (result.status === "verified") throw new Error("Forged signature accepted");
}));

tests.push(() => test("SEPARATION OF DUTIES: proposer approves", () => {
  const k1 = mkKeyPair(), k2 = mkKeyPair();
  const trusted = { "key-1": pem(k1), "key-2": pem(k2) };
  const result = run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice"), sign(k2, "key-2", "carol")], policy, trustedKeys: trusted, proposer_id: "carol" });
  if (result.status !== "failed") throw new Error("Separation of duties violated");
}));

tests.push(() => test("N-of-M SYBIL: one key minting multiple approvers", () => {
  const k1 = mkKeyPair();
  const trusted = { "key-1": pem(k1) };
  const result = run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice"), sign(k1, "key-1", "bob")], policy, trustedKeys: trusted, proposer_id: "carol" });
  if (result.status === "verified") throw new Error("One key minting multiple approvers accepted");
}));

tests.push(() => test("DUPLICATES: same approver/key repeated", () => {
  const k1 = mkKeyPair(), k2 = mkKeyPair();
  const trusted = { "key-1": pem(k1), "key-2": pem(k2) };
  const result = run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice"), sign(k1, "key-1", "alice")], policy, trustedKeys: trusted, proposer_id: "carol" });
  if (result.status === "verified") throw new Error("Duplicate approver/key accepted");
}));

tests.push(() => test("ALGORITHM CONFUSION: declared algo != key type", () => {
  const k1 = mkKeyPair();
  const trusted = { "key-1": pem(k1) };
  const attestation = sign(k1, "key-1", "alice");
  attestation.signature.algo = "ecdsa-p256-sha256"; // Wrong algo for ed25519 key
  const result = run({ packet_sha256: head, approvals: [attestation], policy, trustedKeys: trusted, proposer_id: "carol" });
  if (result.status === "verified") throw new Error("Algorithm confusion accepted");
}));

tests.push(() => test("C1: approver_id not a pass/fail decision input", () => {
  const k1 = mkKeyPair(), k2 = mkKeyPair();
  const trusted = { "key-1": pem(k1), "key-2": pem(k2) };
  const result = run({ packet_sha256: head, approvals: [sign(k1, "key-1", "alice"), sign(k2, "key-2", "bob")], policy, trustedKeys: trusted, proposer_id: "carol" });
  if (result.status !== "verified") throw new Error("Approver_id influenced decision");
}));

tests.push(() => test("Crashes on malformed input: hostile getter", () => {
  const ctx = {
    packet_sha256: head,
    approvals: [new Proxy({}, { get: () => { throw new Error("hostile getter"); } })],
    policy,
    trustedKeys: {},
    proposer_id: "carol"
  };
  const result = run(ctx);
  if (result.status === undefined) throw new Error("Crashed on hostile getter");
}));

tests.push(() => test("Crashes on malformed input: proto pollution", () => {
  const ctx = {
    packet_sha256: head,
    approvals: [{ __proto__: null }],
    policy,
    trustedKeys: {},
    proposer_id: "carol"
  };
  const result = run(ctx);
  if (result.status === undefined) throw new Error("Crashed on proto pollution");
}));

tests.push(() => test("Crashes on malformed input: BigInt", () => {
  const ctx = {
    packet_sha256: head,
    approvals: [BigInt(123)],
    policy,
    trustedKeys: {},
    proposer_id: "carol"
  };
  const result = run(ctx);
  if (result.status === undefined) throw new Error("Crashed on BigInt");
}));

tests.push(() => test("Crashes on malformed input: wrong types", () => {
  const ctx = {
    packet_sha256: head,
    approvals: [123],
    policy,
    trustedKeys: {},
    proposer_id: "carol"
  };
  const result = run(ctx);
  if (result.status === undefined) throw new Error("Crashed on wrong types");
}));

// Run all tests
tests.forEach(t => t());
console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
process.exitCode = fail === 0 ? 0 : 1;
