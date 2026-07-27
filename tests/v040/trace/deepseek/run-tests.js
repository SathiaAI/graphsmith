"use strict";

const { run, scanLeaks, PATTERNS } = require("../../../../checks/v040-trace.js");

let pass = 0;
let fail = 0;

function test(name, ctx, expectedStatus) {
    try {
        const result = run(ctx);
        const actualStatus = result.status;
        if (actualStatus === expectedStatus) {
            console.log("PASS " + name);
            pass++;
        } else {
            console.log("FAIL " + name + " expected=" + expectedStatus + " actual=" + actualStatus + " reason=" + (result.reason || "none"));
            fail++;
        }
    } catch (e) {
        console.log("FAIL " + name + " crashed: " + e.message);
        fail++;
    }
}

/* This is an adversarial-review artifact: it records what a tester expected, which is
 * not always what the product should do. Where a case was formally adjudicated in
 * tests/v040/trace/ADJUDICATION.md as NOT a defect, flipping the expectation silently
 * would erase the record that the disagreement happened, and leaving it FAILing
 * forever is why nobody reads the evidence-only list any more.
 *
 * adjudicatedTest() runs the case, asserts the ADJUDICATED behaviour so a regression
 * away from it still fails loudly, and prints it under its own status citing the
 * ruling. The history survives and a permanently-red line stops training people to
 * ignore red. */

/* ADJUDICATED cases — see the note above adjudicatedTest(). */
let adjudicated = 0;
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
    let result;
    try {
        result = run(ctx);
    } catch (e) {
        console.log("FAIL " + name + " REGRESSED: threw instead of returning " +
            adjudicatedStatus + " -- " + e.message);
        fail++;
        return;
    }
    if (result.status === adjudicatedStatus) {
        console.log("ADJUDICATED " + name + " -> " + adjudicatedStatus + " (not a defect: " + ruling + ")");
        adjudicated++;
    } else {
        console.log("FAIL " + name + " REGRESSED away from the adjudicated behaviour: expected " +
            adjudicatedStatus + ", got " + result.status + " reason=" + (result.reason || "none"));
        fail++;
    }
}

// Test 1: Clean trace should verify
test("clean-trace", { trace_mode: "full", trace: '{"step":1,"status":"ok"}' }, "verified");

// Test 2: AWS secret access key bypass (40-char base64)
const awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // 40 chars
test("aws-secret-bypass", { trace_mode: "redacted", trace: '{"secret":"' + awsSecret + '"}' }, "failed");

// Test 3: JWT token bypass
const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
test("jwt-bypass", { trace_mode: "full", trace: '{"token":"' + jwtToken + '"}' }, "failed");

// Test 4: Google API key bypass
const googleKey = "AIzaSyD-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678";
test("google-key-bypass", { trace_mode: "redacted", trace: '{"key":"' + googleKey + '"}' }, "failed");

// Test 5: Stripe key bypass
const stripeKey = "sk_live_1234567890abcdef";
test("stripe-key-bypass", { trace_mode: "full", trace: '{"stripe":"' + stripeKey + '"}' }, "failed");

// Test 6: Generic base64 token with no keyword
const genericB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"; // 40 chars
test("generic-b64-bypass", { trace_mode: "redacted", trace: '{"data":"' + genericB64 + '"}' }, "failed");

// Test 7: Generic hex token
const genericHex = "1234567890abcdef1234567890abcdef12345678"; // 40 chars
test("generic-hex-bypass", { trace_mode: "full", trace: '{"token":"' + genericHex + '"}' }, "failed");

// Test 8: UK national insurance number
const niNumber = "AB123456C";
test("uk-ni-bypass", { trace_mode: "redacted", trace: '{"ni":"' + niNumber + '"}' }, "failed");

// Test 9: IPv4 address as PII
const ipAddress = "192.168.1.1";
adjudicatedTest("ipv4-bypass", { trace_mode: "full", trace: '{"ip":"' + ipAddress + '"}' }, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — a bare/RFC1918 IP is not a credential and appears throughout legitimate traces');

// Test 10: Phone number as PII
const phone = "+44 20 7946 0958";
test("phone-bypass", { trace_mode: "redacted", trace: '{"phone":"' + phone + '"}' }, "failed");

// Test 11: PKCS8 private key
const pkcs8Key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7";
test("pkcs8-bypass", { trace_mode: "full", trace: '{"key":"' + pkcs8Key + '"}' }, "failed");

// Test 12: Secret spread across JSON fields
const partialSecret1 = "wJalrXUtnFEMI/K7MDENG";
const partialSecret2 = "/bPxRfiCYEXAMPLEKEY";
adjudicatedTest("split-secret-bypass", { trace_mode: "redacted", trace: '{"part1":"' + partialSecret1 + '","part2":"' + partialSecret2 + '"}' }, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — cross-field reassembly is out of scope for a stateless pattern battery; declared limitation');

// Test 13: Base64-encoded secret
const originalSecret = "my-super-secret-password-123";
const base64Secret = Buffer.from(originalSecret).toString('base64');
adjudicatedTest("base64-encoded-bypass", { trace_mode: "full", trace: '{"encoded":"' + base64Secret + '"}' }, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — a sub-40-char base64 blob is indistinguishable from legitimate encoded data');

// Test 14: Metadata-only with payload fields
test("metadata-payload-fields", { trace_mode: "metadata-only", trace: '{"step":1,"content":"secret data"}' }, "failed");

// Test 15: Invalid trace_mode
test("invalid-mode", { trace_mode: "invalid", trace: "{}" }, "failed");

// Test 16: Null context
test("null-context", null, "failed");

// Test 17: Non-string trace that stringifies to a secret
const secretObject = { toString: () => "sk-ABCDEFGHIJKLMNOPQRSTUV" };
test("object-toString-secret", { trace_mode: "full", trace: secretObject }, "failed");

// Test 18: BigInt in trace
adjudicatedTest("bigint-trace", { trace_mode: "redacted", trace: 12345678901234567890n }, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — String() coercion is scan-covered and fail-closed-safe; a toString-secret IS caught (see object-toString-secret above)');

// Test 19: Hostile getter
/* The trap used to be defined as a `trace` property ON hostileObject, while
 * ctx.trace was set to hostileObject itself -- so nothing ever read
 * hostileObject.trace and the getter never fired. The check saw an ordinary object.
 *
 * ADJUDICATION.md attributes this case to "the harness mis-recorded the verdict";
 * that rationale is itself wrong. The harness recorded correctly, the trap was in the
 * wrong place. Put the getter where the check actually reads -- ctx.trace -- and the
 * documented fail-closed behaviour is exercised for real. */
const hostileCtx = { trace_mode: "full" };
Object.defineProperty(hostileCtx, 'trace', {
    get: () => { throw new Error("Hostile getter"); },
    enumerable: true,
});
test("hostile-getter", hostileCtx, "failed");

// Test 20: Proto pollution
const polluted = JSON.parse('{"__proto__":{"polluted":true},"trace_mode":"full","trace":"{}"}');
adjudicatedTest("proto-pollution", polluted, "verified",
  'ADJUDICATION.md "Adjudicated NOT defects" — JSON.parse makes "__proto__" an own data property, so the pollution is inert and the trace is genuinely clean');

// Test 21: Proxy object
const handler = {
    get: (target, prop) => {
        if (prop === 'trace') return '{"secret":"sk-ABCDEFGHIJKLMNOPQRSTUV"}';
        return target[prop];
    }
};
const proxyCtx = new Proxy({ trace_mode: "redacted" }, handler);
test("proxy-object", proxyCtx, "failed");

// Test 22: Empty trace
test("empty-trace", { trace_mode: "full", trace: "" }, "verified");

// Test 23: Trace with only metadata
test("metadata-only-clean", { trace_mode: "metadata-only", trace: '{"step":1,"timestamp":"2023-01-01"}' }, "verified");

// Test 24: Redacted mode with redactions array
test("redacted-with-redactions", { trace_mode: "redacted", trace: '{"step":1}', redactions: [] }, "verified");

console.log("# summary PASS=" + pass + " FAIL=" + fail + " ADJUDICATED=" + adjudicated +
    " total=" + (pass + fail + adjudicated));
process.exitCode = fail === 0 ? 0 : 1;
