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
    if (result) {
      console.log("PASS", name);
      pass++;
    } else {
      console.log("FAIL", name, "unexpected activation");
      fail++;
    }
  } catch (e) {
    console.log("FAIL", name, "threw:", e.message);
    fail++;
  }
}

test("baseline - valid inputs activate", () => {
  const r = reg.activateRegulatedMode(goodInputs, policy);
  return r.activated === true;
});

test("obligations - over-claim (evidence unavailable but coverage covered)", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.evidence.profiles.T = "unavailable";
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("obligations - manual-only obligation marked covered", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.register.obligations[1].coverage = "covered";
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("approver - single approver (below n=2)", () => {
  const inputs = clone(goodInputs);
  inputs.approver.approvals = [inputs.approver.approvals[0]];
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("approver - proposer equals approver", () => {
  const inputs = clone(goodInputs);
  inputs.approver.proposer_id = "alice";
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("approver - invalid signature", () => {
  const inputs = clone(goodInputs);
  inputs.approver.approvals[0].signature.value = "invalid";
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("retention - broken chain (prev_packet_sha256 mismatch)", () => {
  const inputs = clone(goodInputs);
  inputs.retention.chain[1].prev_packet_sha256 = H(9);
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("retention - missing chain", () => {
  const inputs = clone(goodInputs);
  inputs.retention = {};
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("airgap - corrupted signature", () => {
  const inputs = clone(goodInputs);
  inputs.airgap.signature.value = "corrupted";
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("airgap - empty trustedKeys", () => {
  const inputs = clone(goodInputs);
  inputs.airgap.trustedKeys = {};
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("airgap - missing airgap lane", () => {
  const inputs = clone(goodInputs);
  inputs.airgap = {};
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("policy - fail_closed=false refused", () => {
  const badPolicy = clone(policy);
  badPolicy.fail_closed = false;
  const r = reg.activateRegulatedMode(goodInputs, badPolicy);
  return r.activated === false;
});

test("policy - empty activation_preconditions refused", () => {
  const badPolicy = clone(policy);
  badPolicy.activation_preconditions = [];
  const r = reg.activateRegulatedMode(goodInputs, badPolicy);
  return r.activated === false;
});

test("policy - unknown precondition refused", () => {
  const badPolicy = clone(policy);
  badPolicy.activation_preconditions = ["unknown_precondition"];
  const r = reg.activateRegulatedMode(goodInputs, badPolicy);
  return r.activated === false;
});

test("partial - missing obligations lane", () => {
  const inputs = clone(goodInputs);
  inputs.obligations = {};
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("partial - missing approver lane", () => {
  const inputs = clone(goodInputs);
  inputs.approver = {};
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("crash - null inputs", () => {
  const r = reg.activateRegulatedMode(null, policy);
  return r.activated === false;
});

test("crash - missing inputs", () => {
  const r = reg.activateRegulatedMode({}, policy);
  return r.activated === false;
});

test("crash - wrong types (number instead of object)", () => {
  const r = reg.activateRegulatedMode(42, policy);
  return r.activated === false;
});

test("crash - hostile getters", () => {
  const inputs = clone(goodInputs);
  Object.defineProperty(inputs, 'obligations', {
    get: () => { throw new Error("hostile getter"); }
  });
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("crash - BigInt values", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.register.obligations[0].obligation_id = BigInt(123);
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("crash - proto pollution", () => {
  const inputs = clone(goodInputs);
  inputs.__proto__.polluted = true;
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

test("crash - circular reference", () => {
  const inputs = clone(goodInputs);
  inputs.obligations.register.obligations.push(inputs.obligations.register);
  const r = reg.activateRegulatedMode(inputs, policy);
  return r.activated === false;
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
