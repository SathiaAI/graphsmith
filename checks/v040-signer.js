/* GraphSmith v0.4.0 Lane R3 — signer trust lifecycle + attestation recall (checks/v040-signer.js).
 * Verifies a bundle's signer against the approved-signer registry (active / rotated / revoked) and
 * the attestation-recall list. Fail-closed: a REVOKED signer or a RECALLED bundle never re-verifies
 * as valid; an unknown signer is `unavailable` (trust cannot be established), never green. A ROTATED
 * key is honoured only if its rotation chain resolves to a live successor (no cycle, no revoked/
 * missing link). Trust of the registry is the verifier's policy (GSA-SPEC §5.5). Pure; C1
 * (added_at/recalled_at are evidence, never decision inputs); C2 fail-closed.
 * Schemas: signer-registry, attestation-recall. Zero-dep CJS, Node >= 18.
 */
"use strict";

/* Resolve a signer's effective status by following the rotation chain. Returns
 * "active" | "revoked" | "rotated-live" | "rotated-broken" | "unknown". */
function resolveSigner(registry, signerId) {
  const byId = {};
  for (const s of registry.signers) if (s && typeof s.signer_id === "string") byId[s.signer_id] = s;
  let cur = byId[signerId];
  if (!cur) return "unknown";
  if (cur.status === "revoked") return "revoked";
  if (cur.status === "active") return "active";
  // rotated: follow rotated_to to a live successor; detect cycles / revoked / missing.
  const seen = new Set();
  while (cur && cur.status === "rotated") {
    if (seen.has(cur.signer_id)) return "rotated-broken";   // cycle
    seen.add(cur.signer_id);
    const next = typeof cur.rotated_to === "string" ? byId[cur.rotated_to] : undefined;
    if (!next) return "rotated-broken";                     // dangling successor
    if (next.status === "revoked") return "rotated-broken"; // rotated into a revoked key
    if (next.status === "active") return "rotated-live";
    cur = next;                                             // keep following a chain of rotations
  }
  return "rotated-broken";
}

/* ctx = { signer, registry: signer-registry, recalls?: attestation-recall, bundle_id?, manifest_sha256? } */
function verifySigner(ctx) {
  const evidence = [];
  const assumptions = [
    "Trust of the registry is the verifier's policy (GSA-SPEC §5.5). added_at/recalled_at are evidence, never decision inputs (C1).",
    "Pure decision path — no clock/random/network.",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const registry = ctx.registry;
    if (!registry || typeof registry !== "object" || registry.schema_version !== "1.0" || !Array.isArray(registry.signers)) return fail("signer-registry missing/invalid");
    if (typeof ctx.signer !== "string" || ctx.signer.length < 1) return fail("no signer to verify");

    // Attestation recall — a recalled bundle never re-verifies (fail-closed).
    const recalls = ctx.recalls;
    if (recalls) {
      if (typeof recalls !== "object" || recalls.schema_version !== "1.0" || !Array.isArray(recalls.recalls)) return fail("attestation-recall list malformed");
      for (const r of recalls.recalls) {
        if (r && r.bundle_id === ctx.bundle_id && typeof ctx.manifest_sha256 === "string" && r.manifest_sha256 === ctx.manifest_sha256) {
          return fail("bundle '" + ctx.bundle_id + "' is RECALLED (" + (r.reason || "?") + ") — refusing (fail-closed)", "trusted-core");
        }
      }
    }

    const state = resolveSigner(registry, ctx.signer);
    if (state === "unknown") return { status: "unavailable", evidence, assumptions, reason: "signer '" + ctx.signer + "' not in the registry — trust not establishable (not a pass)" };
    if (state === "revoked") return fail("signer '" + ctx.signer + "' is REVOKED — refusing (fail-closed)", "trusted-core");
    if (state === "rotated-broken") return fail("signer '" + ctx.signer + "' rotation chain is broken (cycle / dangling / revoked successor) — refusing", "trusted-core");
    evidence.push("signer '" + ctx.signer + "': " + state + "; not recalled.");
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "v040-signer",
  run(ctx) {
    const r = verifySigner(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) { out.reason = r.reason; out.evidence.push("reason: " + r.reason); }
    return out;
  },
};

module.exports = { ...check, verifySigner, resolveSigner };

if (require.main === module && process.argv.includes("--selftest")) {
  const reg = { schema_version: "1.0", signers: [
    { signer_id: "k1", public_key_pem: "PEM1", status: "active" },
    { signer_id: "k2", public_key_pem: "PEM2", status: "revoked" },
    { signer_id: "k3", public_key_pem: "PEM3", status: "rotated", rotated_to: "k1" },   // rotated into live k1
    { signer_id: "k4", public_key_pem: "PEM4", status: "rotated", rotated_to: "k2" },   // rotated into revoked k2
    { signer_id: "k5", public_key_pem: "PEM5", status: "rotated", rotated_to: "nope" }, // dangling
  ] };
  const recalls = { schema_version: "1.0", recalls: [{ bundle_id: "gsa-" + "a".repeat(16), manifest_sha256: "b".repeat(64), reason: "defect-found" }] };
  const active = check.run({ signer: "k1", registry: reg });
  const revoked = check.run({ signer: "k2", registry: reg });
  const rotatedLive = check.run({ signer: "k3", registry: reg });
  const rotatedRevoked = check.run({ signer: "k4", registry: reg });
  const rotatedDangling = check.run({ signer: "k5", registry: reg });
  const unknown = check.run({ signer: "kX", registry: reg });
  const recalled = check.run({ signer: "k1", registry: reg, recalls, bundle_id: "gsa-" + "a".repeat(16), manifest_sha256: "b".repeat(64) });
  const pass = active.status === "verified" && revoked.status === "failed" && rotatedLive.status === "verified" &&
    rotatedRevoked.status === "failed" && rotatedDangling.status === "failed" && unknown.status === "unavailable" && recalled.status === "failed";
  console.log("v040-signer selftest:", pass ? "OK" : "FAIL",
    "| active=" + (active.status === "verified"), "revoked-failed=" + (revoked.status === "failed"), "rotated-live=" + (rotatedLive.status === "verified"),
    "rotated-into-revoked-failed=" + (rotatedRevoked.status === "failed"), "dangling-failed=" + (rotatedDangling.status === "failed"),
    "unknown-unavailable=" + (unknown.status === "unavailable"), "recalled-failed=" + (recalled.status === "failed"));
  process.exit(pass ? 0 : 1);
}
