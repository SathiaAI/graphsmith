const crypto = require("crypto");
const reg = require("../../../scripts/gsa-register.js");
const airgap = require("../../../checks/register-airgap.js");
const H = (n) => String(n).padStart(2, "0").repeat(32);
const head = "e".repeat(64);
const kApp1 = crypto.generateKeyPairSync("ed25519"), kApp2 = crypto.generateKeyPairSync("ed25519"), kRel = crypto.generateKeyPairSync("ed25519");
const pem = (k) => k.publicKey.export({ type: "spki", format: "pem" }).toString();
const split = { graphsmith_evidence: "T verified offline", human_judgment: "auditor confirms scope" };
const appAtt = (kp, signer, who) => ({ schema_version:"1.0", approver_id:who, role:"release-owner", method:"signed-commit", artifact_sha256:head, obligation_set_id:"set-1", signature:{ algo:"ed25519", signer, packet_sha256:head, value: crypto.sign(null, Buffer.from(head,"utf8"), kp.privateKey).toString("base64") } });
const manifest = { schema_version:"1.0", kind:"release", release:"v0.3.0", files:[{ path:"a.js", sha256:"a".repeat(64) }] };
const mhash = airgap.sha256Hex(Buffer.from(airgap.canonicalize(manifest), "utf8"));
const goodInputs = {
  obligations: { register:{ schema_version:"1.0", obligation_set_id:"set-1", obligations:[
    { obligation_id:"o1", source:{framework:"EU-AI-Act",clause:"Article-12"}, controls:[{type:"profile",ref:"T"}], evidence_artifact:{type:"profile-result",ref:"T"}, coverage:"covered", evidence_vs_judgment:split },
    { obligation_id:"o2", source:{framework:"EU-AI-Act",clause:"Article-14"}, controls:[], coverage:"manual-only", evidence_vs_judgment:split } ] }, evidence:{ profiles:{ T:"verified" } } },
  approver: { packet_sha256:head, approvals:[appAtt(kApp1,"k1","alice"), appAtt(kApp2,"k2","bob")], policy:{ schema_version:"1.0", separation_of_duties:{proposer_ne_approver:true,n_of_m:{n:2,m:3}}, fail_closed:true, activation_preconditions:["approver_attestation_valid"] }, trustedKeys:{ k1:pem(kApp1), k2:pem(kApp2) }, proposer_id:"carol" },
  retention: { chain:[{ schema_version:"1.0", seq:1, prev_packet_sha256:null, packet_sha256:H(1), anchored_head:head }, { schema_version:"1.0", seq:2, prev_packet_sha256:H(1), packet_sha256:H(2), anchored_head:head }], expected_anchored_head:head },
  airgap: { manifest, signature:{ schema_version:"1.0", algo:"ed25519", signer:"rel", manifest_sha256:mhash, value: crypto.sign(null, Buffer.from(mhash,"utf8"), kRel.privateKey).toString("base64"), delivery:"out-of-band" }, trustedKeys:{ rel:pem(kRel) } },
};
const policy = { schema_version:"1.0", separation_of_duties:{proposer_ne_approver:true}, fail_closed:true, activation_preconditions: reg.PRECONDITIONS };
const clone = (o) => JSON.parse(JSON.stringify(o));

let pass = 0, fail = 0;

function test(name, fn) {
  try {
    const result = fn();
    if (result) { pass++; console.log("PASS", name); }
    else { fail++; console.log("FAIL", name, "unexpected activation"); }
  } catch (e) {
    fail++; console.log("FAIL", name, "threw: " + e.message);
  }
}

// 1. Baseline
test("baseline", () => reg.activateRegulatedMode(goodInputs, policy).activated === true);

// 2. FAIL-OPEN: Break each lane
test("obligations-overclaim", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.evidence.profiles.T = "unavailable";
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("manual-only-marked-covered", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.register.obligations[1].coverage = "covered";
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("approver-single-approver", () => {
  const inputs = clone(goodInputs);
  inputs.approver.approvals.pop();
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("approver-proposer-conflict", () => {
  const inputs = clone(goodInputs);
  inputs.approver.proposer_id = "alice";
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("retention-broken-chain", () => {
  const inputs = clone(goodInputs);
  inputs.retention.chain[1].prev_packet_sha256 = H(9);
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("airgap-corrupt-signature", () => {
  const inputs = clone(goodInputs);
  inputs.airgap.signature.value = "invalid";
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("airgap-no-trusted-keys", () => {
  const inputs = clone(goodInputs);
  inputs.airgap.trustedKeys = {};
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

// 3. RELAXED POLICY
test("relaxed-policy-refused", () => {
  const relaxedPolicy = clone(policy);
  relaxedPolicy.fail_closed = false;
  return !reg.activateRegulatedMode(goodInputs, relaxedPolicy).activated;
});

test("empty-preconditions-refused", () => {
  const emptyPolicy = clone(policy);
  emptyPolicy.activation_preconditions = [];
  return !reg.activateRegulatedMode(goodInputs, emptyPolicy).activated;
});

test("unknown-precondition-refused", () => {
  const badPolicy = clone(policy);
  badPolicy.activation_preconditions = ["invalid_precondition"];
  return !reg.activateRegulatedMode(goodInputs, badPolicy).activated;
});

// 4. PARTIAL: Drop one lane
test("missing-obligations", () => {
  const inputs = clone(goodInputs);
  inputs.obligations = undefined;
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("missing-approver", () => {
  const inputs = clone(goodInputs);
  inputs.approver = undefined;
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("missing-retention", () => {
  const inputs = clone(goodInputs);
  inputs.retention = undefined;
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

test("missing-airgap", () => {
  const inputs = clone(goodInputs);
  inputs.airgap = undefined;
  return !reg.activateRegulatedMode(inputs, policy).activated;
});

// 5. Crashes: malformed inputs
test("null-inputs", () => {
  const result = reg.activateRegulatedMode(null, policy);
  return result.activated === false && !result.reason.includes("throw");
});

test("missing-lanes", () => {
  const result = reg.activateRegulatedMode({}, policy);
  return result.activated === false && !result.reason.includes("throw");
});

test("wrong-types", () => {
  const inputs = { obligations: "string", approver: 123, retention: true, airgap: [] };
  const result = reg.activateRegulatedMode(inputs, policy);
  return result.activated === false && !result.reason.includes("throw");
});

test("hostile-getters", () => {
  const inputs = {
    get obligations() { throw new Error("hostile getter"); },
    get approver() { return {}; },
    get retention() { return {}; },
    get airgap() { return {}; }
  };
  const result = reg.activateRegulatedMode(inputs, policy);
  return result.activated === false && !result.reason.includes("throw");
});

test("bigint-values", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.register.obligations[0].obligation_id = BigInt(123);
  const result = reg.activateRegulatedMode(inputs, policy);
  return result.activated === false && !result.reason.includes("throw");
});

test("proto-pollution", () => {
  const inputs = clone(goodInputs);
  inputs.__proto__ = { activated: true };
  const result = reg.activateRegulatedMode(inputs, policy);
  return result.activated === false && !result.reason.includes("throw");
});

console.log("# summary PASS="+pass+" FAIL="+fail+" total="+(pass+fail));
process.exitCode = fail===0?0:1;
