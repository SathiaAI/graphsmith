"use strict";
const { reconcileEffects } = require("../../../../checks/v040-receipts.js");

let pass = 0, fail = 0;

/* ADJUDICATED cases: this is an adversarial-review artifact, and a tester's
 * expectation is not automatically the right answer. Where tests/v040/receipts/
 * ADJUDICATION.md formally settled a case as NOT a defect, flipping the expectation
 * silently erases the record of the disagreement, and leaving it FAILing forever is
 * why nobody reads the evidence-only list. Run it, assert the adjudicated behaviour
 * so a regression away from it still fails, and print it under its own status. */
let adjudicated = 0;
function adjudicatedTest(name, ctx, adjudicatedStatus, ruling) {
  const result = reconcileEffects(ctx);
  if (result.status === adjudicatedStatus) {
    console.log("ADJUDICATED " + name + " -> " + adjudicatedStatus + " (not a defect: " + ruling + ")");
    adjudicated++;
  } else {
    console.log("FAIL " + name + " REGRESSED away from the adjudicated behaviour: expected " +
      adjudicatedStatus + ", got " + result.status);
    fail++;
  }
}

function test(name, ctx, expectedStatus) {
  const result = reconcileEffects(ctx);
  if (result.status === expectedStatus) {
    pass++;
    console.log("PASS", name);
  } else {
    fail++;
    console.log("FAIL", name, `expected=${expectedStatus} got=${result.status}`);
  }
}

// 1. FORGED SUCCESS - evidence-less success must not verify
test("1.1 success no external_id", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success" } }] }, "unavailable");
test("1.2 success empty external_id", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: "" } }] }, "unavailable");
test("1.3 success null external_id", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: null } }] }, "unavailable");
test("1.4 success non-string external_id", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: 123 } }] }, "unavailable");
test("1.5 mixed forged+real", { effects: [
  { action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: "real" } },
  { action: "y", receipt: { schema_version: "1.0", adapter_id: "a", action: "y", status: "success" } }
] }, "unavailable");

// 2. UNKNOWN_EFFECT - missing receipt or unknown status
test("2.1 no receipt", { effects: [{ action: "x" }] }, "unavailable");
test("2.2 null receipt", { effects: [{ action: "x", receipt: null }] }, "unavailable");
test("2.3 unknown status", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "unknown" } }] }, "unavailable");
test("2.4 mixed unknown+verified", { effects: [
  { action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: "real" } },
  { action: "y", receipt: { schema_version: "1.0", adapter_id: "a", action: "y", status: "unknown" } }
] }, "unavailable");

// 3. FAILED - must fail
test("3.1 failed status", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "failed" } }] }, "failed");
test("3.2 failed among verified", { effects: [
  { action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: "real" } },
  { action: "y", receipt: { schema_version: "1.0", adapter_id: "a", action: "y", status: "failed" } }
] }, "failed");

// 4. MALFORMED receipt - must fail
test("4.1 bad schema_version", { effects: [{ action: "x", receipt: { schema_version: "2.0", adapter_id: "a", action: "x", status: "success" } }] }, "failed");
test("4.2 missing action", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", status: "success" } }] }, "failed");
test("4.3 missing adapter_id", { effects: [{ action: "x", receipt: { schema_version: "1.0", action: "x", status: "success" } }] }, "failed");
test("4.4 invalid status", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "pending" } }] }, "failed");

// 5. C1 - ts must not affect decision
const baseCtx = { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: "real" } }] };
const result1 = reconcileEffects(baseCtx);
const result2 = reconcileEffects({ effects: [{ ...baseCtx.effects[0], receipt: { ...baseCtx.effects[0].receipt, ts: 123 } }] });
const result3 = reconcileEffects({ effects: [{ ...baseCtx.effects[0], receipt: { ...baseCtx.effects[0].receipt, ts: "2024" } }] });
if (result1.status === "verified" && result1.status === result2.status && result1.status === result3.status) {
  pass++;
  console.log("PASS 5.1 ts does not affect decision");
} else {
  fail++;
  console.log("FAIL 5.1 ts affects decision", `base=${result1.status} with_ts=${result2.status} with_string_ts=${result3.status}`);
}

// 6. Crashes - must return status, not throw
test("6.1 null ctx", null, "failed");
test("6.2 non-object ctx", "not an object", "failed");
test("6.3 effects not array", { effects: "not array" }, "failed");
test("6.4 hostile getter", { get effects() { throw new Error("boom"); } }, "failed");
adjudicatedTest("6.5 BigInt in receipt", { effects: [{ action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: 123n } }] }, "unavailable",
  'ADJUDICATION.md "The invalid-external_id design decision" — an invalid external_id VALUE is not valid external evidence, so the effect is UNKNOWN -> unavailable (reconciliation-required). "failed" would be a false claim that the effect failed; it may well have succeeded. The security property holds either way: a forged evidence-less success never reaches verified');
test("6.6 proto pollution", { effects: [{ __proto__: { polluted: true }, action: "x", receipt: { schema_version: "1.0", adapter_id: "a", action: "x", status: "success", external_id: "real" } }] }, "verified");
const proxy = new Proxy({ effects: [] }, {});
test("6.7 proxy ctx", proxy, "not-applicable");

console.log("# summary PASS=" + pass + " FAIL=" + fail + " ADJUDICATED=" + adjudicated +
  " total=" + (pass + fail + adjudicated));
process.exitCode = fail === 0 ? 0 : 1;
