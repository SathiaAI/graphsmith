/* GraphSmith v0.4.0 Lane E / R5 — SBOM + SLSA-style build provenance verifier (checks/v040-provenance.js).
 * Verifies that a build's SBOM (hash-pinned source inventory) and its provenance attestation are
 * mutually consistent and match the ACTUAL artifact hashes — the verifier RECOMPUTES the relationship
 * and never trusts a self-declared digest (D5). A tampered file, a provenance that attests a different
 * SBOM, or a material not covered by the SBOM fails closed (C2). Builder identity and build timestamps
 * are EVIDENCE, never decision inputs (C1). Pure decision path (no clock/random/network). Zero-dep CJS,
 * Node >= 18. sha256 matches scripts/gsa-verify.js (crypto SHA-256, hex) so produce/verify are single-source.
 */
"use strict";
const crypto = require("crypto");

function sha256Hex(buf) { return crypto.createHash("sha256").update(buf).digest("hex"); }
const isHex64 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);

/* Deterministic canonical JSON: object keys sorted recursively. Single-source for the SBOM digest so
 * the generator and this verifier compute the identical bytes. */
function canonicalize(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  return JSON.stringify(v === undefined ? null : v);
}

/* The SBOM digest is the hash of the canonicalized, path-sorted (path, sha256) pairs — the single value
 * the provenance subject must attest. A component's identity is its path + content hash ONLY; `bytes` is
 * evidence derivable from content and is deliberately excluded so the digest is stable against non-content
 * metadata (and inert to a hostile/BigInt bytes field). Ignores SBOM metadata (name/version/dates). */
function sbomDigest(components) {
  const norm = components
    .map((c) => ({ path: String(c.path), sha256: String(c.sha256) }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return sha256Hex(Buffer.from(canonicalize(norm), "utf8"));
}

/* ctx = {
 *   sbom:       { schema_version:"1.0", subject:{name,version}, components:[{path, sha256, bytes?}], complete?:bool },
 *   provenance: { schema_version:"1.0", build_type, builder:{id}, materials:[{path, sha256}],
 *                 subject:[{name, sha256}], build_started_at?, build_finished_at? },
 *   actual:     { "<path>": "<sha256hex>" }   // recomputed current hashes (CI/disk ground truth)
 * } */
function verifyProvenance(ctx) {
  const evidence = [];
  const assumptions = [
    "SBOM digest and provenance subject are recomputed here, never trusted as declared (D5). Builder identity and build timestamps are evidence, never decision inputs (C1). Pure decision path.",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  const unavailable = (msg) => ({ status: "unavailable", evidence, assumptions, failure_domain: "reconciliation-required", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const { sbom, provenance, actual } = ctx;

    // Absent attestation → cannot verify (reconciliation-required), never a silent pass.
    if (sbom == null && provenance == null) return unavailable("no SBOM and no provenance");
    if (sbom == null) return unavailable("no SBOM to verify provenance against");
    if (provenance == null) return unavailable("no provenance attestation for SBOM");

    // Structural validation — malformed trust artifacts fail closed (never coerce).
    if (typeof sbom !== "object" || Array.isArray(sbom)) return fail("SBOM not an object");
    if (typeof provenance !== "object" || Array.isArray(provenance)) return fail("provenance not an object");
    if (sbom.schema_version !== "1.0") return fail("SBOM schema_version must be '1.0'");
    if (provenance.schema_version !== "1.0") return fail("provenance schema_version must be '1.0'");
    if (!Array.isArray(sbom.components) || sbom.components.length === 0) return fail("SBOM components must be a non-empty array");
    if (!Array.isArray(provenance.subject) || provenance.subject.length === 0) return fail("provenance subject must be a non-empty array");
    if (!Array.isArray(provenance.materials)) return fail("provenance materials must be an array");
    const actualMap = (actual && typeof actual === "object" && !Array.isArray(actual)) ? actual : null;
    if (!actualMap) return fail("actual artifact-hash map required to recompute against declared");

    // 1. Every declared component must match the ACTUAL recomputed hash (tamper / missing evidence → fail-closed).
    const componentPaths = new Set();
    for (const c of sbom.components) {
      if (!c || typeof c !== "object" || typeof c.path !== "string" || !isHex64(c.sha256)) return fail("malformed SBOM component (path/sha256)");
      if (componentPaths.has(c.path)) return fail("duplicate SBOM component path: " + c.path);
      componentPaths.add(c.path);
      const have = actualMap[c.path];
      if (!isHex64(have)) return fail("no actual hash for declared component: " + c.path);
      if (have !== c.sha256) return fail("SBOM tamper: component '" + c.path + "' declared " + c.sha256.slice(0, 12) + "… but actual is " + String(have).slice(0, 12) + "…");
    }

    // 2. Optional completeness: a 'complete' SBOM must account for every actual file (no un-inventoried artifact).
    if (sbom.complete === true) {
      for (const p of Object.keys(actualMap)) {
        if (!componentPaths.has(p)) return fail("complete SBOM omits actual artifact: " + p);
      }
    }

    // 3. Provenance must attest THIS SBOM: recompute the SBOM digest and require it in the subject set (D5).
    const digest = sbomDigest(sbom.components);
    const subjectHashes = provenance.subject
      .filter((s) => s && typeof s === "object" && isHex64(s.sha256))
      .map((s) => s.sha256);
    if (!subjectHashes.includes(digest)) return fail("provenance does not attest this SBOM (recomputed digest " + digest.slice(0, 12) + "… absent from subject)");

    // 4. Every provenance material must be a component of the attested SBOM with a matching hash.
    for (const m of provenance.materials) {
      if (!m || typeof m !== "object" || typeof m.path !== "string" || !isHex64(m.sha256)) return fail("malformed provenance material");
      const c = sbom.components.find((x) => x.path === m.path);
      if (!c) return fail("provenance material not in SBOM: " + m.path);
      if (c.sha256 !== m.sha256) return fail("provenance material hash disagrees with SBOM: " + m.path);
    }

    // C1: builder identity + build timestamps are recorded as EVIDENCE, never gate the verdict.
    if (provenance.builder && typeof provenance.builder === "object" && typeof provenance.builder.id === "string") {
      evidence.push("provenance builder (evidence, non-deciding): " + provenance.builder.id);
    }
    if (typeof provenance.build_type === "string") evidence.push("build_type: " + provenance.build_type);
    evidence.push("SBOM digest " + digest.slice(0, 16) + "… attested by provenance; " + sbom.components.length + " components match actual hashes; " + provenance.materials.length + " materials consistent.");
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "v040-provenance",
  run(ctx) {
    const r = verifyProvenance(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) { out.reason = r.reason; out.evidence.push("reason: " + r.reason); }
    return out;
  },
};

module.exports = { ...check, verifyProvenance, sbomDigest, canonicalize, sha256Hex };

if (require.main === module && process.argv.includes("--selftest")) {
  // Build a consistent SBOM + provenance + actual, then attack it.
  const files = { "scripts/install.js": "console.log('install');\n", "checks/v040-provenance.js": "// self\n" };
  const actual = {};
  for (const [p, body] of Object.entries(files)) actual[p] = sha256Hex(Buffer.from(body, "utf8"));
  const components = Object.keys(files).map((p) => ({ path: p, sha256: actual[p], bytes: Buffer.byteLength(files[p], "utf8") }));
  const sbom = { schema_version: "1.0", subject: { name: "graphsmith-skill", version: "0.4.0" }, components, complete: true };
  const digest = sbomDigest(components);
  const provenance = {
    schema_version: "1.0", build_type: "https://graphsmith.dev/build/v1", builder: { id: "gh-actions/graphsmith" },
    materials: components.map((c) => ({ path: c.path, sha256: c.sha256 })), subject: [{ name: "sbom", sha256: digest }],
    build_started_at: "2026-07-24T00:00:00Z", build_finished_at: "2026-07-24T00:05:00Z",
  };

  const good = check.run({ sbom, provenance, actual });
  // Tamper: mutate one actual hash (a file changed after the SBOM was cut).
  const tampered = check.run({ sbom, provenance, actual: { ...actual, "scripts/install.js": sha256Hex(Buffer.from("malicious\n")) } });
  // Provenance attests a different SBOM (subject digest doesn't match).
  const wrongSubject = check.run({ sbom, provenance: { ...provenance, subject: [{ name: "sbom", sha256: sha256Hex(Buffer.from("other")) }] }, actual });
  // Material not present in the SBOM.
  const strayMaterial = check.run({ sbom, provenance: { ...provenance, materials: [...provenance.materials, { path: "evil.js", sha256: sha256Hex(Buffer.from("x")) }] }, actual });
  // C1: the verdict must be invariant to builder identity + timestamps.
  const c1 = check.run({ sbom, provenance: { ...provenance, builder: { id: "someone-else" }, build_started_at: "1999-01-01T00:00:00Z" }, actual });
  // Absent provenance → unavailable (reconciliation-required), never a silent pass.
  const noProv = check.run({ sbom, provenance: null, actual });
  // Completeness: an un-inventoried actual file under a 'complete' SBOM fails closed.
  const extraFile = check.run({ sbom, provenance, actual: { ...actual, "sneaked-in.js": sha256Hex(Buffer.from("y")) } });

  const pass = good.status === "verified" && tampered.status === "failed" && wrongSubject.status === "failed" &&
    strayMaterial.status === "failed" && c1.status === "verified" && noProv.status === "unavailable" && extraFile.status === "failed";
  console.log("v040-provenance selftest:", pass ? "OK" : "FAIL",
    "| good=" + good.status, "tamper=" + tampered.status, "wrong-subject=" + wrongSubject.status,
    "stray-material=" + strayMaterial.status, "c1-invariant=" + (c1.status === "verified"),
    "no-prov=" + noProv.status, "extra-file=" + extraFile.status);
  process.exit(pass ? 0 : 1);
}
