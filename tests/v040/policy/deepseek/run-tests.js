"use strict";

const { verifyPolicy, serializePolicy, parsePolicy } = require("../../../../checks/v040-policy.js");

let pass = 0;
let fail = 0;

function test(name, fn) {
    try {
        const result = fn();
        if (result === true) {
            console.log("PASS " + name);
            pass++;
        } else {
            console.log("FAIL " + name + " returned " + result);
            fail++;
        }
    } catch (e) {
        console.log("FAIL " + name + " threw " + e);
        fail++;
    }
}

const basePolicy = {
    schema_version: "1.0",
    policy_version: "1.0.0",
    profiles: {
        "secure": { requires: ["control1", "control2"], forbids: ["bad1"] },
        "open": { requires: [] }
    }
};

const baseControls = {
    "control1": { enforced: true },
    "control2": { enforced: true }
};

test("UNENFORCED_BYPASS_1", () => {
    const ctx = {
        policy: basePolicy,
        profile: "secure",
        controls: { ...baseControls, "control1": { enforced: false } }
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNENFORCED_BYPASS_2", () => {
    const ctx = {
        policy: basePolicy,
        profile: "secure",
        controls: { ...baseControls, "control1": { enforced: "true" } }
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNENFORCED_BYPASS_3", () => {
    const ctx = {
        policy: basePolicy,
        profile: "secure",
        controls: { ...baseControls, "control1": { enforced: 1 } }
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNENFORCED_BYPASS_4", () => {
    const ctx = {
        policy: basePolicy,
        profile: "secure",
        controls: { ...baseControls, "control1": { enforced: "false" } }
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNKNOWN_PROFILE_1", () => {
    const ctx = {
        policy: basePolicy,
        profile: "",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNKNOWN_PROFILE_2", () => {
    const ctx = {
        policy: basePolicy,
        profile: "__proto__",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNKNOWN_PROFILE_3", () => {
    const ctx = {
        policy: basePolicy,
        profile: "constructor",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("UNKNOWN_PROFILE_4", () => {
    const ctx = {
        policy: basePolicy,
        profile: "toString",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("FORBIDDEN_ENFORCED", () => {
    const ctx = {
        policy: basePolicy,
        profile: "secure",
        controls: { ...baseControls, "bad1": { enforced: true } }
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("ROUND_TRIP_1", () => {
    const serialized = serializePolicy(basePolicy);
    const parsed = parsePolicy(serialized);
    const originalResult = verifyPolicy({ policy: basePolicy, profile: "secure", controls: baseControls });
    const roundTripResult = verifyPolicy({ policy: parsed, profile: "secure", controls: baseControls });
    return originalResult.status === roundTripResult.status;
});

test("ROUND_TRIP_2", () => {
    const serialized = serializePolicy(basePolicy);
    const parsed = parsePolicy(serialized);
    const originalResult = verifyPolicy({ policy: basePolicy, profile: "open", controls: {} });
    const roundTripResult = verifyPolicy({ policy: parsed, profile: "open", controls: {} });
    return originalResult.status === roundTripResult.status;
});

test("MALFORMED_SCHEMA_VERSION", () => {
    const ctx = {
        policy: { ...basePolicy, schema_version: "2.0" },
        profile: "secure",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("MALFORMED_POLICY_VERSION", () => {
    const ctx = {
        policy: { ...basePolicy, policy_version: "v1.0.0" },
        profile: "secure",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("MALFORMED_PROFILES_ARRAY", () => {
    const ctx = {
        policy: { ...basePolicy, profiles: [] },
        profile: "secure",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("MALFORMED_REQUIRES_NOT_ARRAY", () => {
    const policy = {
        ...basePolicy,
        profiles: { "secure": { requires: "not-an-array", forbids: [] } }
    };
    const ctx = { policy, profile: "secure", controls: baseControls };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("MALFORMED_CONTROL_ID_NUMBER", () => {
    const policy = {
        ...basePolicy,
        profiles: { "secure": { requires: [123], forbids: [] } }
    };
    const ctx = { policy, profile: "secure", controls: baseControls };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("MALFORMED_CONTROL_ID_OBJECT", () => {
    const policy = {
        ...basePolicy,
        profiles: { "secure": { requires: [{}], forbids: [] } }
    };
    const ctx = { policy, profile: "secure", controls: baseControls };
    const result = verifyPolicy(ctx);
    return result.status === "failed";
});

test("C1_METADATA_IMMUNITY", () => {
    const policyWithExtra = {
        ...basePolicy,
        timestamp: "2023-01-01",
        author: "test"
    };
    const originalResult = verifyPolicy({ policy: basePolicy, profile: "secure", controls: baseControls });
    const extraResult = verifyPolicy({ policy: policyWithExtra, profile: "secure", controls: baseControls });
    return originalResult.status === extraResult.status;
});

test("CRASH_NULL_CTX", () => {
    const result = verifyPolicy(null);
    return typeof result.status === "string";
});

test("CRASH_UNDEFINED_CTX", () => {
    const result = verifyPolicy(undefined);
    return typeof result.status === "string";
});

test("CRASH_CONTROLS_NULL", () => {
    const ctx = { policy: basePolicy, profile: "secure", controls: null };
    const result = verifyPolicy(ctx);
    return typeof result.status === "string";
});

test("CRASH_CONTROLS_ARRAY", () => {
    const ctx = { policy: basePolicy, profile: "secure", controls: [] };
    const result = verifyPolicy(ctx);
    return typeof result.status === "string";
});

test("CRASH_BIGINT", () => {
    const ctx = {
        policy: { ...basePolicy, policy_version: 123n },
        profile: "secure",
        controls: baseControls
    };
    const result = verifyPolicy(ctx);
    return typeof result.status === "string";
});

test("CRASH_HOSTILE_GETTER", () => {
    const hostileControls = {};
    Object.defineProperty(hostileControls, "control1", {
        get: () => { throw new Error("Hostile getter"); },
        enumerable: true
    });
    const ctx = { policy: basePolicy, profile: "secure", controls: hostileControls };
    const result = verifyPolicy(ctx);
    return typeof result.status === "string";
});

test("CRASH_PROTO_POLLUTION_POLICY", () => {
    const pollutedPolicy = JSON.parse('{"__proto__": {"polluted": true}, "schema_version": "1.0", "policy_version": "1.0.0", "profiles": {"secure": {"requires": ["control1"]}}}');
    const ctx = { policy: pollutedPolicy, profile: "secure", controls: baseControls };
    const result = verifyPolicy(ctx);
    return typeof result.status === "string";
});

test("CRASH_PROTO_POLLUTION_CONTROLS", () => {
    const pollutedControls = JSON.parse('{"__proto__": {"polluted": true}, "control1": {"enforced": true}}');
    const ctx = { policy: basePolicy, profile: "secure", controls: pollutedControls };
    const result = verifyPolicy(ctx);
    return typeof result.status === "string";
});

test("SATISFIED_PROFILE", () => {
    const ctx = { policy: basePolicy, profile: "secure", controls: baseControls };
    const result = verifyPolicy(ctx);
    return result.status === "verified";
});

test("SATISFIED_OPEN_PROFILE", () => {
    const ctx = { policy: basePolicy, profile: "open", controls: {} };
    const result = verifyPolicy(ctx);
    return result.status === "verified";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
