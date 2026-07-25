"use strict";
const { buildBundle, EVIDENCE, ALL_TRUE, tk, pem, sha256Hex } = require("../harness.js");

let pass = 0, fail = 0;

function test(name, fn) {
  try {
    const result = fn();
    if (result) {
      console.log("PASS " + name);
      pass++;
    } else {
      console.log("FAIL " + name + " (unexpected result)");
      fail++;
    }
  } catch (e) {
    console.log("FAIL " + name + " (exception: " + e.message + ")");
    fail++;
  }
}

// 1. LIE PER CONTROL
test("capability_conformance-lie-requested-exceeds-grant", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    capability_grant: {
      grant: { classes: ["A"], tokens: 10 },
      requested: { classes: ["A", "B"], tokens: 20 },
      attested: { classes: ["A"], tokens: 10 }
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("capability_conformance-lie-attested-unenforced-class", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    capability_grant: {
      grant: { classes: ["A"], tokens: 10 },
      requested: { classes: ["A"], tokens: 5 },
      attested: { classes: ["A", "B"], tokens: 5 }
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("effects_reconciled-lie-success-no-external_id", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    effects: [{ action: "create", receipt: { status: "success" } }]
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("effects_reconciled-lie-receipt-unknown-status", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    effects: [{ action: "create", receipt: { status: "unknown", external_id: "123" } }]
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("effects_reconciled-lie-receipt-failed-status", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    effects: [{ action: "create", receipt: { status: "failed", external_id: "123" } }]
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("signer_trust-lie-signer-revoked", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    signer_registry: { signer: tk.revoked, registry: "test" }
  };
  const res = buildBundle({ claim, evidence, opts: { revoked: new Set([tk.revoked]) } });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("signer_trust-lie-signer-unknown", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    signer_registry: { signer: "unknown-signer", registry: "test" }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("signer_trust-lie-rotation-cycle", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    signer_registry: {
      signer: tk.valid,
      registry: "test",
      rotation: {
        current: tk.valid,
        previous: [tk.valid] // cycle
      }
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("trace_redaction-lie-leaky-trace", () => {
  const claim = { ...ALL_TRUE };
  const traceBody = '{"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}';
  const res = buildBundle({ claim, traceBody });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("build_provenance-lie-tampered-actual-hash", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    build_provenance: {
      sbom: { hash: sha256Hex("sbom") },
      provenance: { subject: { digest: sha256Hex("provenance") } },
      actual: sha256Hex("tampered")
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("build_provenance-lie-forged-subject-digest", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    build_provenance: {
      sbom: { hash: sha256Hex("sbom") },
      provenance: { subject: { digest: "forged" } },
      actual: sha256Hex("actual")
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("build_provenance-lie-stray-material", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    build_provenance: {
      sbom: { hash: sha256Hex("sbom") },
      provenance: { subject: { digest: sha256Hex("provenance") }, materials: [{ uri: "stray" }] },
      actual: sha256Hex("actual")
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

// 2. FAIL-OPEN probes
test("fail-open-capability_grant-missing", () => {
  const claim = { ...ALL_TRUE };
  const evidence = { ...EVIDENCE };
  delete evidence.capability_grant;
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("fail-open-effects-missing", () => {
  const claim = { ...ALL_TRUE };
  const evidence = { ...EVIDENCE };
  delete evidence.effects;
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("fail-open-signer_registry-missing", () => {
  const claim = { ...ALL_TRUE };
  const evidence = { ...EVIDENCE };
  delete evidence.signer_registry;
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("fail-open-build_provenance-missing", () => {
  const claim = { ...ALL_TRUE };
  const evidence = { ...EVIDENCE };
  delete evidence.build_provenance;
  const res = buildBundle({ claim, evidence });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

// 3. MALFORMED extended block
test("malformed-extended-block-array", () => {
  const claim = [];
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-extended-block-null", () => {
  const claim = null;
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-extended-block-string", () => {
  const claim = "invalid";
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-extended-block-number", () => {
  const claim = 123;
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-unknown-control-key", () => {
  const claim = { ...ALL_TRUE, unknown_control: true };
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-control-value-number", () => {
  const claim = { capability_conformance: 1 };
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-control-value-string", () => {
  const claim = { capability_conformance: "true" };
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

test("malformed-control-value-object", () => {
  const claim = { capability_conformance: {} };
  const res = buildBundle({ claim });
  return res.status === "FAIL" && res.steps.some(s => s.step === "11-extended-controls" && s.status === "FAIL");
});

// 4. HONEST claims
test("honest-trace-leaks-but-false", () => {
  const claim = { ...ALL_TRUE, trace_redaction: false };
  const traceBody = '{"tok":"sk-ABCDEFGHIJKLMNOPQRSTUV"}';
  const res = buildBundle({ claim, traceBody });
  return res.status === "PASS";
});

test("honest-subset-claim", () => {
  const claim = { capability_conformance: true, effects_reconciled: true };
  const evidence = {
    ...EVIDENCE,
    capability_grant: {
      grant: { classes: ["A"], tokens: 10 },
      requested: { classes: ["A"], tokens: 5 },
      attested: { classes: ["A"], tokens: 5 }
    },
    effects: [{ action: "create", receipt: { status: "success", external_id: "123" } }]
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "PASS";
});

test("honest-all-true-valid", () => {
  const claim = { ...ALL_TRUE };
  const evidence = {
    ...EVIDENCE,
    capability_grant: {
      grant: { classes: ["A"], tokens: 10 },
      requested: { classes: ["A"], tokens: 5 },
      attested: { classes: ["A"], tokens: 5 }
    },
    effects: [{ action: "create", receipt: { status: "success", external_id: "123" } }],
    signer_registry: { signer: tk.valid, registry: "test" },
    build_provenance: {
      sbom: { hash: sha256Hex("sbom") },
      provenance: { subject: { digest: sha256Hex("provenance") } },
      actual: sha256Hex("provenance")
    }
  };
  const res = buildBundle({ claim, evidence });
  return res.status === "PASS";
});

test("backward-compat-no-claim", () => {
  const res = buildBundle({});
  return res.status === "PASS";
});

// 5. C1: identity/timestamp-ish fields
test("c1-bundle_id-change", () => {
  const claim = { ...ALL_TRUE };
  const evidence = { ...EVIDENCE };
  const res1 = buildBundle({ claim, evidence });
  const mutate = (manifest) => {
    manifest.bundle_id = "changed";
    return manifest;
  };
  const res2 = buildBundle({ claim, evidence, mutate });
  return res1.status === "PASS" && res2.status === "PASS" &&
         res1.steps.find(s => s.step === "11-extended-controls").status ===
         res2.steps.find(s => s.step === "11-extended-controls").status;
});

test("c1-timestamp-change", () => {
  const claim = { ...ALL_TRUE };
  const evidence = { ...EVIDENCE };
  const res1 = buildBundle({ claim, evidence });
  const mutate = (manifest) => {
    manifest.timestamp = "2023-01-02T00:00:00Z";
    return manifest;
  };
  const res2 = buildBundle({ claim, evidence, mutate });
  return res1.status === "PASS" && res2.status === "PASS" &&
         res1.steps.find(s => s.step === "11-extended-controls").status ===
         res2.steps.find(s => s.step === "11-extended-controls").status;
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
