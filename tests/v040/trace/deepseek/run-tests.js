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
test("ipv4-bypass", { trace_mode: "full", trace: '{"ip":"' + ipAddress + '"}' }, "failed");

// Test 10: Phone number as PII
const phone = "+44 20 7946 0958";
test("phone-bypass", { trace_mode: "redacted", trace: '{"phone":"' + phone + '"}' }, "failed");

// Test 11: PKCS8 private key
const pkcs8Key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7";
test("pkcs8-bypass", { trace_mode: "full", trace: '{"key":"' + pkcs8Key + '"}' }, "failed");

// Test 12: Secret spread across JSON fields
const partialSecret1 = "wJalrXUtnFEMI/K7MDENG";
const partialSecret2 = "/bPxRfiCYEXAMPLEKEY";
test("split-secret-bypass", { trace_mode: "redacted", trace: '{"part1":"' + partialSecret1 + '","part2":"' + partialSecret2 + '"}' }, "failed");

// Test 13: Base64-encoded secret
const originalSecret = "my-super-secret-password-123";
const base64Secret = Buffer.from(originalSecret).toString('base64');
test("base64-encoded-bypass", { trace_mode: "full", trace: '{"encoded":"' + base64Secret + '"}' }, "failed");

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
test("bigint-trace", { trace_mode: "redacted", trace: 12345678901234567890n }, "failed");

// Test 19: Hostile getter
const hostileObject = {};
Object.defineProperty(hostileObject, 'trace', {
    get: () => { throw new Error("Hostile getter"); }
});
test("hostile-getter", { trace_mode: "full", trace: hostileObject }, "failed");

// Test 20: Proto pollution
const polluted = JSON.parse('{"__proto__":{"polluted":true},"trace_mode":"full","trace":"{}"}');
test("proto-pollution", polluted, "failed");

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

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
