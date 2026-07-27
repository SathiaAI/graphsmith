const mod = require("../../../../checks/register-obligations.js");
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

// Test 1: Empty register should be not-applicable
tests.push(() => test("empty register", () => {
  const res = mod.run({ register: { schema_version: "1.0", obligation_set_id: "empty", obligations: [] } });
  if (res.status !== "not-applicable") throw new Error("Expected not-applicable for empty register");
}));

// Test 2: Manual-only obligation declared covered should fail
tests.push(() => test("manual-only declared covered", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "manual-covered",
    obligations: [{
      obligation_id: "o1",
      controls: [],
      coverage: "covered",
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "test" }
    }]
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed" || res.regulated_mode_may_activate) {
    throw new Error("Should fail and block activation for manual-only declared covered");
  }
}));

// Test 3: Missing human_judgment for manual-only should fail
tests.push(() => test("manual-only missing judgment", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "no-judgment",
    obligations: [{
      obligation_id: "o1",
      controls: [],
      coverage: "manual-only",
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "" }
    }]
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed" || res.regulated_mode_may_activate) {
    throw new Error("Should fail for missing human_judgment on manual-only");
  }
}));

// Test 4: Over-claimed coverage should be caught
tests.push(() => test("over-claimed coverage", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "over-claim",
    obligations: [{
      obligation_id: "o1",
      controls: [{type: "profile", ref: "T"}],
      evidence_artifact: {type: "profile-result", ref: "T"},
      coverage: "covered",
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "" }
    }]
  };
  const res = mod.run({ register: reg, evidence: { profiles: { T: "unavailable" } } });
  if (res.status !== "failed" || res.coverage_map[0].actual_coverage !== "not-covered") {
    throw new Error("Should detect over-claimed coverage");
  }
}));

// Test 5: Duplicate obligation_id should fail
tests.push(() => test("duplicate obligation_id", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "dupes",
    obligations: [
      { obligation_id: "o1", controls: [], coverage: "manual-only", evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "test" } },
      { obligation_id: "o1", controls: [], coverage: "manual-only", evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "test" } }
    ]
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed") throw new Error("Should fail for duplicate obligation_id");
}));

// Test 6: Malformed register should not throw
tests.push(() => test("malformed register", () => {
  const res = mod.run({ register: { schema_version: "1.0", obligation_set_id: 123 } });
  if (res.status !== "failed") throw new Error("Should handle malformed register without throwing");
}));

// Test 7: Proto pollution attempt
tests.push(() => test("proto pollution", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "proto-pollute",
    obligations: [{
      obligation_id: "o1",
      __proto__: { polluted: true },
      controls: [],
      coverage: "manual-only",
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "test" }
    }]
  };
  /* Object-literal `__proto__: {...}` syntax rewires only THIS literal's prototype at
   * parse time -- Object.prototype is untouched, every field the check reads is an own
   * property, and checks/register-obligations.js never walks the prototype chain. The
   * register is therefore a legitimately valid manual-only obligation and "verified"
   * is the correct answer; demanding otherwise made the case require a false alarm.
   *
   * Assert the invariance that the inert decoration is SUPPOSED to have: it must not
   * move the verdict in either direction. A check that started reading inherited
   * fields would fail this. */
  const clean = mod.run({ register: JSON.parse(JSON.stringify(reg)) }).status;
  const res = mod.run({ register: reg });
  if (res.status !== clean) {
    throw new Error("an inert __proto__ decoration changed the verdict: " + clean + " -> " + res.status);
  }
  if (res.status === "verified") return;   // expected: valid input verifies
  throw new Error("expected the valid manual-only register to verify, got " + res.status);
}));

// Test 8: Circular reference should not throw
tests.push(() => test("circular reference", () => {
  const ob = { obligation_id: "o1", controls: [], coverage: "manual-only" };
  ob.self = ob;
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "circular",
    obligations: [ob]
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed") throw new Error("Should handle circular references without throwing");
}));

// Test 9: Proxy object should not throw
tests.push(() => test("proxy object", () => {
  const handler = {
    get(target, prop) {
      if (prop === "controls") return [];
      return prop in target ? target[prop] : "default";
    }
  };
  const proxyOb = new Proxy({ obligation_id: "o1" }, handler);
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "proxy",
    obligations: [proxyOb]
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed") throw new Error("Should handle proxy objects without throwing");
}));

// Test 10: BigInt in register should not throw
tests.push(() => test("BigInt in register", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "bigint",
    obligations: [{
      obligation_id: "o1",
      controls: [],
      coverage: BigInt(123),
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "test" }
    }]
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed") throw new Error("Should handle BigInt without throwing");
}));

// Test 11: Valid complete register should verify
tests.push(() => test("valid complete register", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "valid",
    obligations: [
      {
        obligation_id: "o1",
        controls: [{type: "profile", ref: "T"}],
        evidence_artifact: {type: "profile-result", ref: "T"},
        coverage: "covered",
        evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "" }
      },
      {
        obligation_id: "o2",
        controls: [],
        coverage: "manual-only",
        evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "test" }
      }
    ]
  };
  const res = mod.run({ register: reg, evidence: { profiles: { T: "verified" } } });
  if (res.status !== "verified" || !res.regulated_mode_may_activate) {
    throw new Error("Valid complete register should verify and allow activation");
  }
}));

// Test 12: Partial coverage should not activate
tests.push(() => test("partial coverage", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "partial",
    obligations: [{
      obligation_id: "o1",
      controls: [{type: "harness", ref: "redteam"}],
      evidence_artifact: {type: "redteam-packet", ref: "redteam"},
      coverage: "partial",
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "" }
    }]
  };
  const res = mod.run({ register: reg, evidence: { redteamSuites: { redteam: { blocked: 3, total: 10 } } } });
  if (res.status !== "unavailable" || res.regulated_mode_may_activate) {
    throw new Error("Partial coverage should not allow activation");
  }
}));

// Test 13: Missing schema_version should fail
tests.push(() => test("missing schema_version", () => {
  const reg = {
    obligation_set_id: "no-schema",
    obligations: []
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed") throw new Error("Missing schema_version should fail");
}));

// Test 14: Missing obligation_set_id should fail
tests.push(() => test("missing obligation_set_id", () => {
  const reg = {
    schema_version: "1.0",
    obligations: []
  };
  const res = mod.run({ register: reg });
  if (res.status !== "failed") throw new Error("Missing obligation_set_id should fail");
}));

// Test 15: Malformed evidence_artifact should not throw
tests.push(() => test("malformed evidence_artifact", () => {
  const reg = {
    schema_version: "1.0",
    obligation_set_id: "bad-evidence",
    obligations: [{
      obligation_id: "o1",
      controls: [{type: "profile", ref: "T"}],
      evidence_artifact: "not-an-object",
      coverage: "covered",
      evidence_vs_judgment: { graphsmith_evidence: "", human_judgment: "" }
    }]
  };
  const res = mod.run({ register: reg, evidence: { profiles: { T: "verified" } } });
  if (res.status !== "failed") throw new Error("Malformed evidence_artifact should fail");
}));

// Run all tests
tests.forEach(t => t());
console.log("# summary PASS="+pass+" FAIL="+fail+" total="+tests.length);
process.exitCode = fail===0?0:1;
