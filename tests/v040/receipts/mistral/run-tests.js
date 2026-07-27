"use strict";

const check = require("../../../../checks/v040-receipts.js");
let pass = 0, fail = 0;

/* ADJUDICATED cases: this is an adversarial-review artifact, and a tester's
 * expectation is not automatically the right answer. Where tests/v040/receipts/
 * ADJUDICATION.md formally settled a case as NOT a defect, flipping the expectation
 * silently erases the record of the disagreement, and leaving it FAILing forever is
 * why nobody reads the evidence-only list. Run it, assert the adjudicated behaviour
 * so a regression away from it still fails, and print it under its own status. */
let adjudicated = 0;
function adjudicatedTest(name, fn, ruling) {
  /* Contract 10 List C: an ADJUDICATED verdict is only admissible with a citation to
   * the ruling that produced it. Without one it is an unexplained non-failure, which is
   * the shape this status exists to prevent. Fail closed on a missing citation. */
  if (typeof ruling !== "string" || ruling.trim().length === 0) {
    console.log("FAIL " + name + " - ADJUDICATED recorded with no citation to the ruling " +
      "that settled it (contract 10 List C)");
    fail++;
    return;
  }
  const ok = fn();
  if (ok === true) {
    console.log("ADJUDICATED " + name + " (not a defect: " + ruling + ")");
    adjudicated++;
  } else {
    console.log("FAIL " + name + " REGRESSED away from the adjudicated behaviour");
    fail++;
  }
}

function test(name, fn) {
  try {
    const result = fn();
    if (result) {
      console.log("PASS " + name);
      pass++;
    } else {
      console.log("FAIL " + name + " " + JSON.stringify(result));
      fail++;
    }
  } catch (e) {
    console.log("FAIL " + name + " exception: " + e.message);
    fail++;
  }
}

// 1. FORGED SUCCESS
test("forged-success-null-external_id", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: null
  }}]};
  const res = check.run(ctx);
  return res.status === "unavailable";
});

test("forged-success-undefined-external_id", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success"
  }}]};
  const res = check.run(ctx);
  return res.status === "unavailable";
});

test("forged-success-empty-string-external_id", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: ""
  }}]};
  const res = check.run(ctx);
  return res.status === "unavailable";
});

adjudicatedTest("forged-success-non-string-external_id", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: 123
  }}]};
  const res = check.run(ctx);
  return res.status === "unavailable";
}, 'ADJUDICATION.md "The invalid-external_id design decision" — an invalid external_id VALUE routes to UNKNOWN -> unavailable, never failed; the forged success still never reaches verified, which is the security-critical property');

// 2. UNKNOWN_EFFECT
test("unknown-effect-no-receipt", () => {
  const ctx = { effects: [{ action: "test" }] };
  const res = check.run(ctx);
  return res.status === "unavailable";
});

test("unknown-effect-receipt-status-unknown", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "unknown"
  }}]};
  const res = check.run(ctx);
  return res.status === "unavailable";
});

test("unknown-effect-mixed-with-reconciled", () => {
  const ctx = { effects: [
    { action: "test1", receipt: {
      schema_version: "1.0", adapter_id: "test", action: "test1", status: "success", external_id: "123"
    }},
    { action: "test2" }
  ]};
  const res = check.run(ctx);
  return res.status === "unavailable";
});

// 3. FAILED
test("failed-effect", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "failed"
  }}]};
  const res = check.run(ctx);
  return res.status === "failed";
});

// 4. MALFORMED receipt
test("malformed-schema_version", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "2.0", adapter_id: "test", action: "test", status: "success", external_id: "123"
  }}]};
  const res = check.run(ctx);
  return res.status === "failed";
});

test("malformed-missing-action", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", status: "success", external_id: "123"
  }}]};
  const res = check.run(ctx);
  return res.status === "failed";
});

test("malformed-missing-adapter_id", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", action: "test", status: "success", external_id: "123"
  }}]};
  const res = check.run(ctx);
  return res.status === "failed";
});

test("malformed-bad-status", () => {
  const ctx = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "invalid", external_id: "123"
  }}]};
  const res = check.run(ctx);
  return res.status === "failed";
});

// 5. C1: ts should not affect decision
test("ts-present-vs-absent", () => {
  const ctx1 = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: "123", ts: "2023-01-01"
  }}]};
  const ctx2 = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: "123"
  }}]};
  const res1 = check.run(ctx1);
  const res2 = check.run(ctx2);
  return res1.status === res2.status;
});

test("ts-different-values", () => {
  const ctx1 = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: "123", ts: "2023-01-01"
  }}]};
  const ctx2 = { effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: "123", ts: "2023-01-02"
  }}]};
  const res1 = check.run(ctx1);
  const res2 = check.run(ctx2);
  return res1.status === res2.status;
});

// 6. Crashes
test("null-ctx", () => {
  const res = check.run(null);
  return res.status === "failed";
});

test("non-object-ctx", () => {
  const res = check.run("not an object");
  return res.status === "failed";
});

test("effects-not-array", () => {
  const ctx = { effects: "not an array" };
  const res = check.run(ctx);
  return res.status === "failed";
});

test("effect-with-hostile-getter", () => {
  const effect = {};
  Object.defineProperty(effect, 'receipt', {
    get: () => { throw new Error("hostile getter"); }
  });
  const ctx = { effects: [effect] };
  const res = check.run(ctx);
  return res.status === "failed";
});

test("effect-with-bigint", () => {
  const ctx = { effects: [BigInt(123)] };
  const res = check.run(ctx);
  return res.status === "failed";
});

/* Was unfalsifiable twice over: the merge result was discarded (Object.assign into a
 * fresh {} never touched ctx), and the assertion accepted either verified OR failed,
 * so no product change short of a crash could have failed it. Mutate ctx for real and
 * pin the one correct answer -- the pollution is inert, every read field is own and
 * valid, so this reconciles. */
test("proto-pollution", () => {
  const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
  const ctx = Object.assign({ effects: [{ action: "test", receipt: {
    schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: "123"
  }}] }, malicious);
  const res = check.run(ctx);
  return res.status === "verified";
});

test("proxy-effect", () => {
  const effect = new Proxy({}, {
    get: (target, prop) => {
      if (prop === 'receipt') return {
        schema_version: "1.0", adapter_id: "test", action: "test", status: "success", external_id: "123"
      };
      return undefined;
    }
  });
  const ctx = { effects: [effect] };
  const res = check.run(ctx);
  return res.status === "verified";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " ADJUDICATED=" + adjudicated +
  " total=" + (pass + fail + adjudicated));
process.exitCode = fail === 0 ? 0 : 1;
