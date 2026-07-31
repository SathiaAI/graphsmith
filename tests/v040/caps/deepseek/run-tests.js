"use strict";

const { run, verifyCapabilities, subsetOk } = require("../../../../checks/v040-caps.js");

let pass = 0, fail = 0;

// 1. D1 FAIL-OPEN: Attest unenforced classes
const unenforcedClasses = ["filesystem", "model", "subprocess", "network"];
for (const cls of unenforcedClasses) {
  const ctx = {
    grant: { schema_version: "1.0", skill_id: "s1", grants: {}, enforced: [] },
    requested: {},
    attested: { [cls]: true }
  };
  const result = run(ctx);
  if (result.status === "failed" && result.reason.includes("NOT in the enforced set")) {
    pass++;
    console.log("PASS D1 fail-open " + cls);
  } else {
    fail++;
    console.log("FAIL D1 fail-open " + cls, result.status);
  }
}

// 2. ESCALATION: Request outside granted envelope
const escalationTests = [
  { cls: "filesystem", req: { read: ["/secret"], write: [] }, grant: { read: ["/inputs"] } },
  { cls: "filesystem", req: { read: [], write: ["/etc/passwd"] }, grant: { write: ["/outputs"] } },
  { cls: "model", req: { allowed: ["gpt-5"] }, grant: { allowed: ["gpt-3.5"] } },
  { cls: "subprocess", req: { allowed: ["sh"] }, grant: { allowed: ["ls"] } },
  { cls: "network", req: { destinations: ["evil.com"] }, grant: { destinations: ["api.example.com"] } }
];
for (const { cls, req, grant } of escalationTests) {
  const ctx = {
    grant: { schema_version: "1.0", skill_id: "s1", grants: { [cls]: grant }, enforced: [cls] },
    requested: { [cls]: req },
    attested: { [cls]: true }
  };
  const result = run(ctx);
  if (result.status === "failed" && result.reason.includes("requested ⊄ granted")) {
    pass++;
    console.log("PASS escalation " + cls);
  } else {
    fail++;
    console.log("FAIL escalation " + cls, result.status);
  }
}

// 3. PATH-PREFIX CONFUSION
const pathTests = [
  { req: "/inputs-evil/secret", grant: "/inputs" },
  { req: "/inputs/../etc/passwd", grant: "/inputs" },
  { req: "/input", grant: "/inputs" },
  { req: "/inputs/.", grant: "/inputs" }
];
for (const { req, grant } of pathTests) {
  const ctx = {
    grant: { schema_version: "1.0", skill_id: "s1", grants: { filesystem: { read: [grant] } }, enforced: ["filesystem"] },
    requested: { filesystem: { read: [req] } },
    attested: { filesystem: true }
  };
  const result = run(ctx);
  if (result.status === "failed" && result.reason.includes("requested ⊄ granted")) {
    pass++;
    console.log("PASS path-prefix " + req);
  } else {
    fail++;
    console.log("FAIL path-prefix " + req, result.status);
  }
}

// 4. ALLOWLIST BYPASS
const allowlistTests = [
  { cls: "model", req: "GPT-3.5", grant: "gpt-3.5" },
  { cls: "model", req: "gpt-3.5 ", grant: "gpt-3.5" },
  { cls: "subprocess", req: " LS", grant: "ls" },
  { cls: "network", req: "API.example.com", grant: "api.example.com" }
];
for (const { cls, req, grant } of allowlistTests) {
  // subsetOk() keys the network class on `destinations`, every other class on
  // `allowed` (checks/v040-caps.js). Building the network case with `allowed` meant
  // req.destinations was undefined, within() saw nothing requested, and the case
  // vacuously "verified" -- it never exercised the case-sensitivity check it names.
  const key = cls === "network" ? "destinations" : "allowed";
  const ctx = {
    grant: { schema_version: "1.0", skill_id: "s1", grants: { [cls]: { [key]: [grant] } }, enforced: [cls] },
    requested: { [cls]: { [key]: [req] } },
    attested: { [cls]: true }
  };
  const result = run(ctx);
  if (result.status === "failed" && result.reason.includes("requested ⊄ granted")) {
    pass++;
    console.log("PASS allowlist " + cls);
  } else {
    fail++;
    console.log("FAIL allowlist " + cls, result.status);
  }
}

// 5. C1: No identity/clock influence
const c1Tests = [
  { skill_id: "evil", shouldFail: false },
  { skill_id: null, shouldFail: false },
  { skill_id: 123, shouldFail: false }
];
for (const { skill_id, shouldFail } of c1Tests) {
  const ctx = {
    grant: { schema_version: "1.0", skill_id, grants: { filesystem: { read: ["/inputs"] } }, enforced: ["filesystem"] },
    requested: { filesystem: { read: ["/inputs/file"] } },
    attested: { filesystem: true }
  };
  const result = run(ctx);
  if ((result.status === "verified") !== shouldFail) {
    pass++;
    console.log("PASS C1 skill_id " + skill_id);
  } else {
    fail++;
    console.log("FAIL C1 skill_id " + skill_id, result.status);
  }
}

// 6. CRASH TESTS
const crashTests = [
  { name: "null ctx", input: null },
  { name: "undefined ctx", input: undefined },
  { name: "non-object ctx", input: "string" },
  { name: "missing grant", input: {} },
  { name: "null grant", input: { grant: null } },
  { name: "invalid schema", input: { grant: { schema_version: "2.0" } } },
  { name: "malicious getter", input: { get grant() { throw new Error("boom"); } } },
  { name: "proto pollution", input: Object.assign(Object.create({ grant: { schema_version: "1.0" } }), { requested: {} }) },
  { name: "proxy grant", input: { grant: new Proxy({}, { get() { return "1.0"; } }) } },
  { name: "bigint", input: { grant: { schema_version: 1n }, requested: { filesystem: { read: [1n] } } } }
];
for (const { name, input } of crashTests) {
  try {
    const result = run(input);
    if (result && typeof result.status === "string") {
      pass++;
      console.log("PASS crash " + name);
    } else {
      fail++;
      console.log("FAIL crash " + name, "invalid result");
    }
  } catch (e) {
    fail++;
    console.log("FAIL crash " + name, "threw exception");
  }
}

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
