const check = require("../../../../checks/register-obligations.js");

let pass = 0;
let fail = 0;
const tests = [];

function test(name, fn) {
  try {
    if (fn()) {
      console.log("PASS " + name);
      pass++;
    } else {
      console.log("FAIL " + name);
      fail++;
    }
  } catch (e) {
    console.log("FAIL " + name + " " + e.message);
    fail++;
  }
  tests.push(name);
}

// Test 1: FAIL-OPEN
test("FAIL-OPEN: Partial register", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("FAIL-OPEN: Missing evidence", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o2", source: { framework: "X", clause: "2" }, controls: [{ type: "profile", ref: "T" }], evidence_artifact: { type: "profile-result", ref: "T" }, coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: { profiles: { T: "unavailable" } }
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("FAIL-OPEN: Duplicate obligation_ids", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } },
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

// Test 2: MANUAL-MARKED-COVERED
test("MANUAL-MARKED-COVERED: Force covered", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

// Test 3: DECLARED-COVERAGE TRUST
test("DECLARED-COVERAGE TRUST: Declared coverage leak", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [{ type: "profile", ref: "T" }], evidence_artifact: { type: "profile-result", ref: "T" }, coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: { profiles: { T: "unavailable" } }
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

// Test 4: Crashes on malformed register
test("Crashes on malformed register: Hostile getters", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], get coverage() { throw new Error("Hostile getter"); }, evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("Crashes on malformed register: Proto pollution", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  ctx.register.__proto__.polluted = true;
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("Crashes on malformed register: BigInt", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: 1234567890123456789012345678901234567890n, evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("Crashes on malformed register: Circular reference", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  ctx.register.obligations[0].circular = ctx.register;
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("Crashes on malformed register: Proxy", () => {
  const ctx = {
    register: new Proxy({
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    }, {
      get: (target, prop) => {
        if (prop === "obligations") throw new Error("Proxy error");
        return target[prop];
      }
    }),
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

test("Crashes on malformed register: Wrong types", () => {
  const ctx = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: 123, evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result = check.run(ctx);
  return result.status === "failed" && !result.regulated_mode_may_activate;
});

// Test 5: C1: obligation_id / any identity must not change a pass/fail decision
test("C1: Identity change", () => {
  const ctx1 = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-1",
      obligations: [
        { obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "manual-only", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result1 = check.run(ctx1);

  const ctx2 = {
    register: {
      schema_version: "1.0",
      obligation_set_id: "set-2",
      obligations: [
        { obligation_id: "o2", source: { framework: "X", clause: "1" }, controls: [], coverage: "manual-only", evidence_vs_judgment: { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" } }
      ]
    },
    evidence: {}
  };
  const result2 = check.run(ctx2);

  return result1.status === result2.status && result1.regulated_mode_may_activate === result2.regulated_mode_may_activate;
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + tests.length);
process.exitCode = fail === 0 ? 0 : 1;
