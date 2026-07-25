"use strict";
const assert = require("assert");
const { run, verifyProvenance, sbomDigest, sha256Hex } = require("../../../../checks/v040-provenance.js");

let pass = 0, fail = 0;

function test(name, fn) {
  try {
    const result = fn();
    if (result === true) {
      console.log("PASS " + name);
      pass++;
    } else {
      console.log("FAIL " + name + " (test returned non-true)");
      fail++;
    }
  } catch (e) {
    console.log("FAIL " + name + " (threw: " + (e.message || String(e)) + ")");
    fail++;
  }
}

// Helper to create consistent test data
function createTestData() {
  const files = {
    "src/index.js": "console.log('hello');\n",
    "package.json": JSON.stringify({ name: "test", version: "1.0.0" })
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
    subject: { name: "test", version: "1.0.0" },
    components,
    complete: true
  };
  const digest = sbomDigest(components);
  const provenance = {
    schema_version: "1.0",
    build_type: "https://example.com/build",
    builder: { id: "test-builder" },
    materials: components.map(c => ({ path: c.path, sha256: c.sha256 })),
    subject: [{ name: "sbom", sha256: digest }],
    build_started_at: "2023-01-01T00:00:00Z",
    build_finished_at: "2023-01-01T00:01:00Z"
  };
  return { sbom, provenance, actual, components, digest };
}

test("tamper-actual-hash", () => {
  const { sbom, provenance, actual } = createTestData();
  const tamperedActual = { ...actual, "src/index.js": sha256Hex(Buffer.from("malicious\n")) };
  const result = run({ sbom, provenance, actual: tamperedActual });
  return result.status === "failed" && result.reason.includes("SBOM tamper");
});

test("tamper-sbom-hash", () => {
  const { sbom, provenance, actual } = createTestData();
  const tamperedSbom = {
    ...sbom,
    components: sbom.components.map(c =>
      c.path === "src/index.js" ? { ...c, sha256: sha256Hex(Buffer.from("wrong")) } : c
    )
  };
  const result = run({ sbom: tamperedSbom, provenance, actual });
  return result.status === "failed" && result.reason.includes("SBOM tamper");
});

test("forged-provenance-subject", () => {
  const { sbom, provenance, actual } = createTestData();
  const forgedProvenance = {
    ...provenance,
    subject: [{ name: "sbom", sha256: sha256Hex(Buffer.from("forged-digest")) }]
  };
  const result = run({ sbom, provenance: forgedProvenance, actual });
  return result.status === "failed" && result.reason.includes("provenance does not attest this SBOM");
});

test("stray-material-path", () => {
  const { sbom, provenance, actual } = createTestData();
  const strayProvenance = {
    ...provenance,
    materials: [...provenance.materials, { path: "evil.js", sha256: sha256Hex(Buffer.from("x")) }]
  };
  const result = run({ sbom, provenance: strayProvenance, actual });
  return result.status === "failed" && result.reason.includes("provenance material not in SBOM");
});

test("stray-material-hash", () => {
  const { sbom, provenance, actual } = createTestData();
  const strayProvenance = {
    ...provenance,
    materials: provenance.materials.map(m =>
      m.path === "src/index.js" ? { ...m, sha256: sha256Hex(Buffer.from("wrong")) } : m
    )
  };
  const result = run({ sbom, provenance: strayProvenance, actual });
  return result.status === "failed" && result.reason.includes("provenance material hash disagrees");
});

test("completeness-extra-file", () => {
  const { sbom, provenance, actual } = createTestData();
  const extraActual = {
    ...actual,
    "extra.js": sha256Hex(Buffer.from("extra content"))
  };
  const result = run({ sbom, provenance, actual: extraActual });
  return result.status === "failed" && result.reason.includes("complete SBOM omits actual artifact");
});

test("completeness-allowed-extra-file", () => {
  const { sbom, provenance, actual } = createTestData();
  const nonCompleteSbom = { ...sbom, complete: false };
  const extraActual = {
    ...actual,
    "extra.js": sha256Hex(Buffer.from("extra content"))
  };
  const result = run({ sbom: nonCompleteSbom, provenance, actual: extraActual });
  return result.status === "verified";
});

test("c1-builder-id-invariant", () => {
  const { sbom, provenance, actual } = createTestData();
  const modifiedProvenance = {
    ...provenance,
    builder: { id: "different-builder" }
  };
  const result1 = run({ sbom, provenance, actual });
  const result2 = run({ sbom, provenance: modifiedProvenance, actual });
  return result1.status === "verified" && result2.status === "verified";
});

test("c1-timestamps-invariant", () => {
  const { sbom, provenance, actual } = createTestData();
  const modifiedProvenance = {
    ...provenance,
    build_started_at: "1970-01-01T00:00:00Z",
    build_finished_at: "1970-01-01T00:01:00Z"
  };
  const result1 = run({ sbom, provenance, actual });
  const result2 = run({ sbom, provenance: modifiedProvenance, actual });
  return result1.status === "verified" && result2.status === "verified";
});

test("absent-sbom", () => {
  const { provenance, actual } = createTestData();
  const result = run({ sbom: null, provenance, actual });
  return result.status === "unavailable";
});

test("absent-provenance", () => {
  const { sbom, actual } = createTestData();
  const result = run({ sbom, provenance: null, actual });
  return result.status === "unavailable";
});

test("absent-both", () => {
  const result = run({ sbom: null, provenance: null, actual: {} });
  return result.status === "unavailable";
});

test("malformed-sbom-schema-version", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = { ...sbom, schema_version: "2.0" };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "failed" && result.reason.includes("SBOM schema_version must be '1.0'");
});

test("malformed-provenance-schema-version", () => {
  const { sbom, provenance, actual } = createTestData();
  const badProvenance = { ...provenance, schema_version: "2.0" };
  const result = run({ sbom, provenance: badProvenance, actual });
  return result.status === "failed" && result.reason.includes("provenance schema_version must be '1.0'");
});

test("malformed-sbom-components-not-array", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = { ...sbom, components: "not-an-array" };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "failed";
});

test("malformed-sbom-components-empty", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = { ...sbom, components: [] };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "failed" && result.reason.includes("SBOM components must be a non-empty array");
});

test("malformed-sbom-component-path", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = {
    ...sbom,
    components: sbom.components.map(c => ({ ...c, path: 123 }))
  };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "failed";
});

test("malformed-sbom-component-sha256", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = {
    ...sbom,
    components: sbom.components.map(c => ({ ...c, sha256: "not-hex" }))
  };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "failed";
});

test("malformed-provenance-subject-not-array", () => {
  const { sbom, provenance, actual } = createTestData();
  const badProvenance = { ...provenance, subject: "not-an-array" };
  const result = run({ sbom, provenance: badProvenance, actual });
  return result.status === "failed";
});

test("malformed-provenance-subject-empty", () => {
  const { sbom, provenance, actual } = createTestData();
  const badProvenance = { ...provenance, subject: [] };
  const result = run({ sbom, provenance: badProvenance, actual });
  return result.status === "failed" && result.reason.includes("provenance subject must be a non-empty array");
});

test("malformed-provenance-materials-not-array", () => {
  const { sbom, provenance, actual } = createTestData();
  const badProvenance = { ...provenance, materials: "not-an-array" };
  const result = run({ sbom, provenance: badProvenance, actual });
  return result.status === "failed";
});

test("malformed-actual-not-object", () => {
  const { sbom, provenance } = createTestData();
  const result = run({ sbom, provenance, actual: "not-an-object" });
  return result.status === "failed";
});

test("malformed-sha256-non-hex", () => {
  const { sbom, provenance, actual } = createTestData();
  const badActual = { ...actual, "src/index.js": "not-hex" };
  const result = run({ sbom, provenance, actual: badActual });
  return result.status === "failed";
});

test("duplicate-component-path", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = {
    ...sbom,
    components: [...sbom.components, sbom.components[0]]
  };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "failed" && result.reason.includes("duplicate SBOM component path");
});

test("valid-consistent-data", () => {
  const { sbom, provenance, actual } = createTestData();
  const result = run({ sbom, provenance, actual });
  return result.status === "verified";
});

test("hostile-getter", () => {
  const { sbom, provenance, actual } = createTestData();
  const hostileSbom = new Proxy(sbom, {
    get(target, prop) {
      if (prop === "components") {
        throw new Error("getter attack");
      }
      return target[prop];
    }
  });
  const result = run({ sbom: hostileSbom, provenance, actual });
  return result.status === "failed";
});

test("proto-pollution", () => {
  const { sbom, provenance, actual } = createTestData();
  const polluted = JSON.parse('{"__proto__": {"evil": true}, "schema_version": "1.0", "subject": {"name": "test"}, "components": []}');
  const result = run({ sbom: polluted, provenance, actual });
  return result.status === "failed";
});

test("bigint-component-bytes", () => {
  const { sbom, provenance, actual } = createTestData();
  const badSbom = {
    ...sbom,
    components: sbom.components.map(c => ({ ...c, bytes: 1n }))
  };
  const result = run({ sbom: badSbom, provenance, actual });
  return result.status === "verified"; // bytes is optional and not decision-relevant
});

test("null-actual", () => {
  const { sbom, provenance } = createTestData();
  const result = run({ sbom, provenance, actual: null });
  return result.status === "failed";
});

test("undefined-actual", () => {
  const { sbom, provenance } = createTestData();
  const result = run({ sbom, provenance, actual: undefined });
  return result.status === "failed";
});

test("empty-actual", () => {
  const { sbom, provenance } = createTestData();
  const result = run({ sbom, provenance, actual: {} });
  return result.status === "failed" && result.reason.includes("no actual hash for declared component");
});

test("missing-actual-for-component", () => {
  const { sbom, provenance, actual } = createTestData();
  const { "src/index.js": _, ...partialActual } = actual;
  const result = run({ sbom, provenance, actual: partialActual });
  return result.status === "failed" && result.reason.includes("no actual hash for declared component");
});

console.log("# summary PASS=" + pass + " FAIL=" + fail + " total=" + (pass + fail));
process.exitCode = fail === 0 ? 0 : 1;
