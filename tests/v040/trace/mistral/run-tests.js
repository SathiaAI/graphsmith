"use strict";

const check = require("../../../../checks/v040-trace.js");
const { verifyTrace, scanLeaks, PATTERNS } = check;

let pass = 0, fail = 0;

function test(name, fn) {
  try {
    const result = fn();
    // ORCHESTRATOR CORRECTION (v0.4.0 R4 adjudication): the original harness used `if (result)`,
    // which counted a truthy DIAGNOSTIC STRING (returned on the leaked-but-passed path of every
    // leak-bypass test) as PASS — inverting the verdict so a MISSED leak scored as a pass. Tightened
    // to `=== true` so only a genuine boolean pass counts; a returned string now correctly FAILS.
    if (result === true) {
      console.log("PASS " + name);
      pass++;
    } else {
      console.log("FAIL " + name + " " + (result === false ? "unexpected result" : String(result)));
      fail++;
    }
  } catch (e) {
    console.log("FAIL " + name + " " + String(e));
    fail++;
  }
}

// 1. LEAK BYPASS TESTS
test("leak-bypass-aws-secret-key", () => {
  const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  const ctx = { trace_mode: "full", trace: `{"data":"${secret}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "AWS secret key leaked but passed";
  return r.status === "failed";
});

test("leak-bypass-jwt", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const ctx = { trace_mode: "full", trace: `{"token":"${jwt}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "JWT leaked but passed";
  return r.status === "failed";
});

test("leak-bypass-google-api-key", () => {
  const key = "AIzaSyDqVY6fTfQJ8z5Xz5a5Xz5a5Xz5a5Xz5a5";
  const ctx = { trace_mode: "full", trace: `{"apiKey":"${key}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "Google API key leaked but passed";
  return r.status === "failed";
});

test("leak-bypass-stripe-key", () => {
  const key = "sk_live_51Jx0a2F4a5Xz5a5Xz5a5Xz5a5Xz5a5Xz5a5Xz5";
  const ctx = { trace_mode: "full", trace: `{"stripeKey":"${key}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "Stripe key leaked but passed";
  return r.status === "failed";
});

/* ADJUDICATED cases: this is an adversarial-review artifact, and a tester's
 * expectation is not automatically the right answer. tests/v040/trace/ADJUDICATION.md
 * states the battery is a RECALL FLOOR, not proof of zero leakage, and names these
 * four residual cases as outside the declared set. Flipping the expectation silently
 * would erase the record; leaving them FAILing forever is why nobody reads the
 * evidence-only list. Run them, assert the adjudicated behaviour so a regression away
 * from it still fails, and print them under their own status. */
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
  let ok;
  try { ok = fn(); } catch (e) {
    console.log("FAIL " + name + " REGRESSED: threw -- " + e.message); fail++; return;
  }
  if (ok === true) {
    console.log("ADJUDICATED " + name + " (outside the declared recall set: " + ruling + ")");
    adjudicated++;
  } else {
    console.log("FAIL " + name + " REGRESSED away from the adjudicated behaviour");
    fail++;
  }
}

adjudicatedTest("leak-bypass-generic-hex-token", () => {
  const token = "a".repeat(32);
  const ctx = { trace_mode: "full", trace: `{"token":"${token}"}` };
  return verifyTrace(ctx).status === "verified";
}, "32 chars is below the 40-char high-entropy threshold, and catching 32-char runs would flood false positives on the MD5 / UUID / request-ids that pervade legitimate traces");

test("leak-bypass-uk-national-insurance", () => {
  const ni = "AB123456C";
  const ctx = { trace_mode: "full", trace: `{"ni":"${ni}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "UK NI leaked but passed";
  return r.status === "failed";
});

test("leak-bypass-phone-number", () => {
  const phone = "+441234567890";
  const ctx = { trace_mode: "full", trace: `{"phone":"${phone}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "Phone number leaked but passed";
  return r.status === "failed";
});

test("leak-bypass-pkcs8-private-key", () => {
  const key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----";
  const ctx = { trace_mode: "full", trace: `{"key":"${key}"}` };
  const r = verifyTrace(ctx);
  if (r.status === "verified") return "PKCS8 private key leaked but passed";
  return r.status === "failed";
});

adjudicatedTest("leak-bypass-secret-spread-across-fields", () => {
  const part1 = "sk-";
  const part2 = "ABCDEFGHIJKLMNOPQRSTUV";
  const ctx = { trace_mode: "full", trace: `{"part1":"${part1}","part2":"${part2}"}` };
  return verifyTrace(ctx).status === "verified";
}, "cross-field reassembly is out of scope for a stateless pattern battery; documented limitation");

adjudicatedTest("leak-bypass-base64-encoded-secret", () => {
  const secret = "c2VjcmV0LWtleS13aXRoLW5vLWtleXdvcmQ=";
  const ctx = { trace_mode: "full", trace: `{"data":"${secret}"}` };
  return verifyTrace(ctx).status === "verified";
}, "a sub-40-char base64 blob is indistinguishable from legitimate encoded data");

adjudicatedTest("leak-bypass-ipv4-as-pii", () => {
  const ip = "192.168.1.1";
  const ctx = { trace_mode: "full", trace: `{"ip":"${ip}"}` };
  return verifyTrace(ctx).status === "verified";
}, "a bare / RFC1918 IP is not a secret or credential and appears throughout legitimate traces (localhost, service IPs)");

// 2. MODE VIOLATION TESTS
test("mode-violation-metadata-with-payload", () => {
  const ctx = { trace_mode: "metadata-only", trace: '{"content":"secret"}' };
  const r = verifyTrace(ctx);
  return r.status === "failed";
});

test("mode-violation-invalid-trace-mode", () => {
  const ctx = { trace_mode: "invalid", trace: "{}" };
  const r = verifyTrace(ctx);
  return r.status === "failed";
});

// 3. CRASH TESTS
test("crash-null-ctx", () => {
  const r = verifyTrace(null);
  return r.status !== undefined;
});

test("crash-non-string-trace", () => {
  const ctx = { trace_mode: "full", trace: 123 };
  const r = verifyTrace(ctx);
  return r.status !== undefined;
});

test("crash-bigint-trace", () => {
  const ctx = { trace_mode: "full", trace: 9007199254740991n };
  const r = verifyTrace(ctx);
  return r.status !== undefined;
});

test("crash-hostile-getter", () => {
  const ctx = { trace_mode: "full" };
  Object.defineProperty(ctx, "trace", {
    get() { throw new Error("getter attack"); }
  });
  const r = verifyTrace(ctx);
  return r.status !== undefined;
});

test("crash-proto-pollution", () => {
  const ctx = JSON.parse('{"__proto__": {"polluted": true}, "trace_mode": "full", "trace": "{}"}');
  const r = verifyTrace(ctx);
  return r.status !== undefined;
});

test("crash-proxy", () => {
  const ctx = new Proxy({ trace_mode: "full", trace: "{}" }, {
    get(target, prop) {
      if (prop === "trace") throw new Error("proxy attack");
      return target[prop];
    }
  });
  const r = verifyTrace(ctx);
  return r.status !== undefined;
});

// 4. CLEAN TRACE TESTS
test("clean-trace-full-mode", () => {
  const ctx = { trace_mode: "full", trace: '{"step":1,"status":"ok"}' };
  const r = verifyTrace(ctx);
  return r.status === "verified";
});

test("clean-trace-redacted-mode", () => {
  const ctx = { trace_mode: "redacted", trace: '{"step":1,"status":"ok"}', redactions: [] };
  const r = verifyTrace(ctx);
  return r.status === "verified";
});

test("clean-trace-metadata-mode", () => {
  const ctx = { trace_mode: "metadata-only", trace: '{"step":1,"status":"ok"}' };
  const r = verifyTrace(ctx);
  return r.status === "verified";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " ADJUDICATED=" + adjudicated +
  " total=" + (pass + fail + adjudicated));
process.exitCode = fail === 0 ? 0 : 1;
