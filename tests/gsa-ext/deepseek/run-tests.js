const { buildBundle, EVIDENCE, ALL_TRUE, tk, pem, sha256Hex } = require("../harness.js");

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
            console.log("FAIL " + name + " " + JSON.stringify(result));
        }
    } catch (e) {
        fail++;
        console.log("FAIL " + name + " " + e.message);
    }
}

// 1. LIE PER CONTROL - Key attack: claim true with broken evidence
test("LIE_capability_conformance_exceeds_grant", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            capability_grant: {
                grant: ["read:file1"],
                requested: ["read:file1", "write:file1"],
                attested: ["read:file1", "write:file1"]
            }
        }
    });
    return result.status === "FAIL";
});

test("LIE_capability_conformance_unenforced_class", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            capability_grant: {
                grant: ["read:file1"],
                requested: ["execute:file1"],
                attested: ["execute:file1"]
            }
        }
    });
    return result.status === "FAIL";
});

test("LIE_effects_reconciled_no_external_id", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            effects: [{
                action: "create",
                receipt: { status: "success" }
            }]
        }
    });
    return result.status === "FAIL";
});

test("LIE_effects_reconciled_failed_status", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            effects: [{
                action: "create",
                external_id: "obj123",
                receipt: { status: "failed" }
            }]
        }
    });
    return result.status === "FAIL";
});

test("LIE_effects_reconciled_unknown_status", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            effects: [{
                action: "create",
                external_id: "obj123",
                receipt: { status: "unknown" }
            }]
        }
    });
    return result.status === "FAIL";
});

test("LIE_signer_trust_revoked", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            signer_registry: {
                signer: "revoked_signer",
                registry: { revoked_signer: { status: "revoked" } }
            }
        }
    });
    return result.status === "FAIL";
});

test("LIE_signer_trust_unknown", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            signer_registry: {
                signer: "unknown_signer",
                registry: { valid_signer: { status: "active" } }
            }
        }
    });
    return result.status === "FAIL";
});

test("LIE_trace_redaction_leaky", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        traceBody: '{"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV","password":"secret123"}'
    });
    return result.status === "FAIL";
});

test("LIE_build_provenance_tampered_hash", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            build_provenance: {
                sbom: "valid-sbom",
                provenance: "valid-provenance",
                actual: "tampered-hash-different-from-real"
            }
        }
    });
    return result.status === "FAIL";
});

// 2. FAIL-OPEN probes: claim true but delete evidence
test("FAILOPEN_capability_conformance_missing_evidence", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            capability_grant: undefined,
            effects: EVIDENCE.effects,
            signer_registry: EVIDENCE.signer_registry,
            build_provenance: EVIDENCE.build_provenance
        }
    });
    return result.status === "FAIL";
});

test("FAILOPEN_effects_reconciled_missing_evidence", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            capability_grant: EVIDENCE.capability_grant,
            effects: undefined,
            signer_registry: EVIDENCE.signer_registry,
            build_provenance: EVIDENCE.build_provenance
        }
    });
    return result.status === "FAIL";
});

test("FAILOPEN_signer_trust_missing_evidence", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            capability_grant: EVIDENCE.capability_grant,
            effects: EVIDENCE.effects,
            signer_registry: undefined,
            build_provenance: EVIDENCE.build_provenance
        }
    });
    return result.status === "FAIL";
});

test("FAILOPEN_build_provenance_missing_evidence", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE },
        evidence: {
            capability_grant: EVIDENCE.capability_grant,
            effects: EVIDENCE.effects,
            signer_registry: EVIDENCE.signer_registry,
            build_provenance: undefined
        }
    });
    return result.status === "FAIL";
});

// 3. MALFORMED extended block
test("MALFORMED_control_attestations_v040_array", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = [];
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_null", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = null;
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_string", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = "invalid";
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_number", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = 42;
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_unknown_key", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = { ...ALL_TRUE, unknown_control: true };
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_non_boolean", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = { capability_conformance: 1 };
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_string_true", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = { capability_conformance: "true" };
        }
    });
    return result.status === "FAIL";
});

test("MALFORMED_control_attestations_v040_object", () => {
    const result = buildBundle({
        mutate: (manifest) => {
            manifest.control_attestations_v040 = { capability_conformance: {} };
        }
    });
    return result.status === "FAIL";
});

// 4. HONEST claims - should PASS
test("HONEST_trace_redaction_false_with_leak", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE, trace_redaction: false },
        traceBody: '{"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}'
    });
    return result.status === "PASS";
});

test("HONEST_subset_claims_valid", () => {
    const result = buildBundle({
        claim: { capability_conformance: true, effects_reconciled: true },
        evidence: EVIDENCE
    });
    return result.status === "PASS";
});

test("HONEST_all_true_valid_evidence", () => {
    const result = buildBundle({
        claim: ALL_TRUE,
        evidence: EVIDENCE
    });
    return result.status === "PASS";
});

test("HONEST_backward_compat_no_claim", () => {
    const result = buildBundle({
        claim: undefined
    });
    return result.status === "PASS";
});

test("HONEST_capability_conformance_false_with_broken", () => {
    const result = buildBundle({
        claim: { ...ALL_TRUE, capability_conformance: false },
        evidence: {
            capability_grant: {
                grant: ["read:file1"],
                requested: ["write:file1"],
                attested: ["write:file1"]
            }
        }
    });
    return result.status === "PASS";
});

// 5. C1: flipping identity/timestamp-ish fields
test("C1_bundle_id_change", () => {
    const result1 = buildBundle({ claim: ALL_TRUE, evidence: EVIDENCE });
    const result2 = buildBundle({
        claim: ALL_TRUE,
        evidence: EVIDENCE,
        mutate: (manifest) => {
            manifest.bundle_id = "different-bundle-id";
        }
    });
    return result1.status === "PASS" && result2.status === "PASS";
});

test("C1_timestamp_change", () => {
    const result1 = buildBundle({ claim: ALL_TRUE, evidence: EVIDENCE });
    const result2 = buildBundle({
        claim: ALL_TRUE,
        evidence: EVIDENCE,
        mutate: (manifest) => {
            if (manifest.timestamp) manifest.timestamp = "2024-01-02T00:00:00Z";
        }
    });
    return result1.status === "PASS" && result2.status === "PASS";
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
