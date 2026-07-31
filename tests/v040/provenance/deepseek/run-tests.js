"use strict";
const { verifyProvenance, sbomDigest, sha256Hex, canonicalize } = require("../../../../checks/v040-provenance.js");

let pass = 0;
let fail = 0;

function test(name, fn) {
    try {
        const result = fn();
        if (result === true) {
            pass++;
            console.log("PASS " + name);
        } else {
            fail++;
            console.log("FAIL " + name + " returned non-true: " + JSON.stringify(result));
        }
    } catch (e) {
        fail++;
        console.log("FAIL " + name + " threw: " + e.message);
    }
}

// Helper to create valid base case
function createValidContext() {
    const files = {
        "main.js": "console.log('hello');",
        "util.js": "module.exports = {};"
    };
    const actual = {};
    for (const [p, body] of Object.entries(files)) {
        actual[p] = sha256Hex(Buffer.from(body, "utf8"));
    }
    const components = Object.keys(files).map(p => ({
        path: p,
        sha256: actual[p],
        bytes: Buffer.byteLength(files[p], "utf8")
    }));
    const sbom = {
        schema_version: "1.0",
        subject: { name: "test", version: "1.0" },
        components,
        complete: true
    };
    const digest = sbomDigest(components);
    const provenance = {
        schema_version: "1.0",
        build_type: "test",
        builder: { id: "test-builder" },
        materials: components.map(c => ({ path: c.path, sha256: c.sha256 })),
        subject: [{ name: "sbom", sha256: digest }],
        build_started_at: "2024-01-01T00:00:00Z",
        build_finished_at: "2024-01-01T00:05:00Z"
    };
    return { sbom, provenance, actual };
}

// Test 1: Genuine consistent case must verify
test("genuine-consistent", () => {
    const ctx = createValidContext();
    const result = verifyProvenance(ctx);
    return result.status === "verified";
});

// Test 2: Tampered component hash
test("tampered-component", () => {
    const ctx = createValidContext();
    ctx.actual["main.js"] = "a".repeat(64); // Wrong hash
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("SBOM tamper");
});

// Test 3: Forged provenance - wrong subject digest
test("forged-provenance-wrong-digest", () => {
    const ctx = createValidContext();
    ctx.provenance.subject[0].sha256 = "a".repeat(64);
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("provenance does not attest this SBOM");
});

// Test 4: Stray material not in SBOM
test("stray-material", () => {
    const ctx = createValidContext();
    ctx.provenance.materials.push({ path: "evil.js", sha256: "b".repeat(64) });
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("provenance material not in SBOM");
});

// Test 5: Completeness violation
test("completeness-violation", () => {
    const ctx = createValidContext();
    ctx.sbom.complete = true;
    ctx.actual["sneaky.js"] = "c".repeat(64);
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("complete SBOM omits");
});

// Test 6: C1 invariant - builder identity change
test("c1-builder-identity", () => {
    const ctx = createValidContext();
    ctx.provenance.builder.id = "attacker";
    const result = verifyProvenance(ctx);
    return result.status === "verified"; // Must still verify
});

// Test 7: C1 invariant - timestamp change
test("c1-timestamps", () => {
    const ctx = createValidContext();
    ctx.provenance.build_started_at = "1999-01-01T00:00:00Z";
    ctx.provenance.build_finished_at = "1999-01-01T00:00:01Z";
    const result = verifyProvenance(ctx);
    return result.status === "verified"; // Must still verify
});

// Test 8: Absent SBOM
test("absent-sbom", () => {
    const ctx = createValidContext();
    ctx.sbom = null;
    const result = verifyProvenance(ctx);
    return result.status === "unavailable";
});

// Test 9: Absent provenance
test("absent-provenance", () => {
    const ctx = createValidContext();
    ctx.provenance = null;
    const result = verifyProvenance(ctx);
    return result.status === "unavailable";
});

// Test 10: Absent both
test("absent-both", () => {
    const result = verifyProvenance({ sbom: null, provenance: null, actual: {} });
    return result.status === "unavailable";
});

// Test 11: Malformed SBOM schema_version
test("malformed-sbom-schema", () => {
    const ctx = createValidContext();
    ctx.sbom.schema_version = "2.0";
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("SBOM schema_version");
});

// Test 12: Malformed provenance schema_version
test("malformed-provenance-schema", () => {
    const ctx = createValidContext();
    ctx.provenance.schema_version = "2.0";
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("provenance schema_version");
});

// Test 13: Non-hex sha256 in component
test("non-hex-component-sha256", () => {
    const ctx = createValidContext();
    ctx.sbom.components[0].sha256 = "g".repeat(64);
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("malformed SBOM component");
});

// Test 14: Non-hex sha256 in material
test("non-hex-material-sha256", () => {
    const ctx = createValidContext();
    ctx.provenance.materials[0].sha256 = "x".repeat(64);
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("malformed provenance material");
});

// Test 15: Components not array
test("components-not-array", () => {
    const ctx = createValidContext();
    ctx.sbom.components = { "main.js": ctx.sbom.components[0] };
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("components must be a non-empty array");
});

// Test 16: Empty components array
test("empty-components", () => {
    const ctx = createValidContext();
    ctx.sbom.components = [];
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("non-empty array");
});

// Test 17: Duplicate component path
test("duplicate-component-path", () => {
    const ctx = createValidContext();
    ctx.sbom.components.push({ ...ctx.sbom.components[0] });
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("duplicate SBOM component path");
});

// Test 18: Missing actual hash map
test("missing-actual-map", () => {
    const ctx = createValidContext();
    ctx.actual = null;
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("actual artifact-hash map required");
});

// Test 19: Actual map is array instead of object
test("actual-map-array", () => {
    const ctx = createValidContext();
    ctx.actual = [];
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("actual artifact-hash map required");
});

// Test 20: Proto pollution attempt
/* Inert by construction: assigning __proto__ only changes what ctx.sbom INHERITS, and
 * sbom.components is already an OWN property, so nothing the check reads changes. The
 * context stays valid and "verified" is the correct answer -- expecting "failed" made
 * this case demand a false alarm. Assert the real property: an inert prototype
 * decoration must not move the verdict in EITHER direction, which is the C1/C2
 * invariance the sibling lanes adjudicated the same way. */
test("proto-pollution", () => {
    const clean = verifyProvenance(createValidContext()).status;
    const ctx = createValidContext();
    ctx.sbom.__proto__ = { components: [] };
    const polluted = verifyProvenance(ctx).status;
    return polluted === clean && polluted === "verified";
});

// Test 21: BigInt in bytes field
test("bigint-bytes", () => {
    const ctx = createValidContext();
    ctx.sbom.components[0].bytes = BigInt(100);
    const result = verifyProvenance(ctx);
    return typeof result.status === "string"; // Should return a status, not throw
});

// Test 22: Hostile getter in component
test("hostile-getter", () => {
    const ctx = createValidContext();
    let callCount = 0;
    const hostileComponent = {
        get path() { callCount++; return "main.js"; },
        get sha256() { callCount++; return ctx.sbom.components[0].sha256; },
        get bytes() { callCount++; return 100; }
    };
    ctx.sbom.components[0] = hostileComponent;
    const result = verifyProvenance(ctx);
    return typeof result.status === "string" && callCount > 0; // Should handle getters
});

// Test 23: Proxy object attack
test("proxy-attack", () => {
    const ctx = createValidContext();
    const handler = {
        get(target, prop) {
            if (prop === "components") return []; // Try to break verification
            return target[prop];
        }
    };
    ctx.sbom = new Proxy(ctx.sbom, handler);
    const result = verifyProvenance(ctx);
    return typeof result.status === "string"; // Should return a status, not throw
});

// Test 24: Undefined values in objects
test("undefined-values", () => {
    const ctx = createValidContext();
    ctx.sbom.subject.version = undefined;
    const result = verifyProvenance(ctx);
    return typeof result.status === "string"; // Should handle undefined
});

// Test 25: Empty subject in provenance
test("empty-provenance-subject", () => {
    const ctx = createValidContext();
    ctx.provenance.subject = [];
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("provenance subject must be a non-empty array");
});

// Test 26: Material hash disagrees with SBOM
test("material-hash-disagreement", () => {
    const ctx = createValidContext();
    ctx.provenance.materials[0].sha256 = "d".repeat(64);
    const result = verifyProvenance(ctx);
    return result.status === "failed" && result.reason.includes("provenance material hash disagrees with SBOM");
});

// Test 27: No context object
test("no-context", () => {
    const result = verifyProvenance();
    return result.status === "failed" && result.reason.includes("no context");
});

// Test 28: Context is primitive
test("context-primitive", () => {
    const result = verifyProvenance("not an object");
    return result.status === "failed" && result.reason.includes("no context");
});

// Test 29: Incomplete SBOM allows extra files
test("incomplete-sbom-extra-files", () => {
    const ctx = createValidContext();
    ctx.sbom.complete = false;
    ctx.actual["extra.js"] = "e".repeat(64);
    const result = verifyProvenance(ctx);
    return result.status === "verified"; // Should allow extra files when not complete
});

// Test 30: Verify sbomDigest consistency
test("sbomdigest-consistency", () => {
    const components = [
        { path: "a", sha256: "a".repeat(64), bytes: 1 },
        { path: "b", sha256: "b".repeat(64), bytes: 2 }
    ];
    const digest1 = sbomDigest(components);
    const digest2 = sbomDigest([...components].reverse()); // Different order
    return digest1 === digest2; // Should be order-invariant due to sorting
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
