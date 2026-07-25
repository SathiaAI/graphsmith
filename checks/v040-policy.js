/* GraphSmith v0.4.0 Lane E / R8 — declarative, versioned policy-as-code verifier (checks/v040-policy.js).
 * Enterprise-safe profiles expressed as a versioned policy document (beyond register-policy.json +
 * capability-policy): each profile declares the controls it REQUIRES and FORBIDS. This verifier decides
 * whether a configuration satisfies a requested profile — a required control that is absent OR declared
 * but NOT enforced fails closed (D1: enforced-only), an unknown profile fails closed (never default-allow),
 * a forbidden-yet-enforced control fails closed (C2). The policy round-trips through a canonical form.
 * Identity/timestamps are never decision inputs (C1). Pure decision path. Zero-dep CJS, Node >= 18.
 */
"use strict";

/* Deterministic canonical serialization so a policy round-trips (serialize → parse → identical decision). */
function canonicalize(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  return JSON.stringify(v === undefined ? null : v);
}
function serializePolicy(policy) { return canonicalize(policy); }
function parsePolicy(text) { return JSON.parse(text); }

const isSemver = (s) => typeof s === "string" && /^\d+\.\d+\.\d+$/.test(s);
const isControlId = (s) => typeof s === "string" && s.length > 0 && s.length <= 128;

/* ctx = {
 *   policy:  { schema_version:"1.0", policy_version:"x.y.z",
 *              profiles: { "<name>": { requires:[<control-id>], forbids?:[<control-id>] } } },
 *   profile: "<name>",                          // requested enterprise-safe profile
 *   controls:{ "<control-id>": { enforced:bool } }  // the configuration's actual controls
 * } */
function verifyPolicy(ctx) {
  const evidence = [];
  const assumptions = [
    "A required control counts only when ENFORCED (D1); declared-but-unenforced is treated as absent. Unknown profile fails closed (never default-allow). Verdict is independent of identity/timestamps (C1). Pure decision path.",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const { policy, profile, controls } = ctx;

    // Structural validation — malformed policy is untrustworthy config; fail closed, never coerce.
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) return fail("policy not an object");
    if (policy.schema_version !== "1.0") return fail("policy schema_version must be '1.0'");
    if (!isSemver(policy.policy_version)) return fail("policy_version must be semver x.y.z");
    if (!policy.profiles || typeof policy.profiles !== "object" || Array.isArray(policy.profiles)) return fail("policy.profiles must be an object");
    if (typeof profile !== "string" || profile.length === 0) return fail("requested profile must be a non-empty string");

    // Unknown profile → fail closed (an enterprise-safe layer must not default-allow an unrecognized profile).
    if (!Object.prototype.hasOwnProperty.call(policy.profiles, profile)) return fail("unknown profile '" + profile + "' — no default-allow");
    const prof = policy.profiles[profile];
    if (!prof || typeof prof !== "object" || Array.isArray(prof)) return fail("profile '" + profile + "' malformed");
    if (!Array.isArray(prof.requires)) return fail("profile '" + profile + "' requires[] must be an array");
    if (prof.forbids !== undefined && !Array.isArray(prof.forbids)) return fail("profile '" + profile + "' forbids[] must be an array");

    const ctrlMap = (controls && typeof controls === "object" && !Array.isArray(controls)) ? controls : {};
    const enforced = (id) => {
      const c = ctrlMap[id];
      return !!(c && typeof c === "object" && c.enforced === true);
    };

    // Required controls: each must be present AND enforced (D1). Declared-but-unenforced == absent.
    const missing = [];
    for (const id of prof.requires) {
      if (!isControlId(id)) return fail("profile '" + profile + "' requires[] has a malformed control id");
      if (!enforced(id)) missing.push(id);
    }
    if (missing.length) return fail("profile '" + profile + "' unsatisfied — required control(s) absent or unenforced: " + missing.join(", "));

    // Forbidden controls: an enforced forbidden control violates the profile (C2).
    const violated = [];
    for (const id of (prof.forbids || [])) {
      if (!isControlId(id)) return fail("profile '" + profile + "' forbids[] has a malformed control id");
      if (enforced(id)) violated.push(id);
    }
    if (violated.length) return fail("profile '" + profile + "' violated — forbidden control(s) enforced: " + violated.join(", "));

    evidence.push("profile '" + profile + "' (policy v" + policy.policy_version + ") satisfied: " + prof.requires.length + " required control(s) enforced" + ((prof.forbids || []).length ? ", " + prof.forbids.length + " forbidden absent" : "") + ".");
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "v040-policy",
  run(ctx) {
    const r = verifyPolicy(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) { out.reason = r.reason; out.evidence.push("reason: " + r.reason); }
    return out;
  },
};

module.exports = { ...check, verifyPolicy, serializePolicy, parsePolicy, canonicalize };

if (require.main === module && process.argv.includes("--selftest")) {
  const policy = {
    schema_version: "1.0", policy_version: "1.0.0",
    profiles: {
      "enterprise-safe": { requires: ["capability-containment", "signer-trust", "trace-redaction"], forbids: ["network-egress-open"] },
      "open-dev": { requires: [] },
    },
  };
  const enforcedAll = { "capability-containment": { enforced: true }, "signer-trust": { enforced: true }, "trace-redaction": { enforced: true } };

  const good = check.run({ policy, profile: "enterprise-safe", controls: enforcedAll });
  // A required control declared but NOT enforced == absent (D1) → fail closed.
  const unenforced = check.run({ policy, profile: "enterprise-safe", controls: { ...enforcedAll, "trace-redaction": { enforced: false } } });
  // Unknown profile → fail closed (no default-allow).
  const unknown = check.run({ policy, profile: "root-yolo", controls: enforcedAll });
  // Forbidden control enforced → violated.
  const forbidden = check.run({ policy, profile: "enterprise-safe", controls: { ...enforcedAll, "network-egress-open": { enforced: true } } });
  // Round-trip: serialize → parse → identical decision.
  const rt = check.run({ policy: parsePolicy(serializePolicy(policy)), profile: "enterprise-safe", controls: enforcedAll });
  const roundTrips = serializePolicy(policy) === serializePolicy(parsePolicy(serializePolicy(policy))) && rt.status === good.status;
  // Malformed policy_version → fail closed.
  const badVersion = check.run({ policy: { ...policy, policy_version: "v1" }, profile: "enterprise-safe", controls: enforcedAll });
  // Empty-requires profile with no controls → verified (nothing required).
  const openDev = check.run({ policy, profile: "open-dev", controls: {} });

  const pass = good.status === "verified" && unenforced.status === "failed" && unknown.status === "failed" &&
    forbidden.status === "failed" && roundTrips && badVersion.status === "failed" && openDev.status === "verified";
  console.log("v040-policy selftest:", pass ? "OK" : "FAIL",
    "| good=" + good.status, "unenforced=" + unenforced.status, "unknown-profile=" + unknown.status,
    "forbidden=" + forbidden.status, "round-trips=" + roundTrips, "bad-version=" + badVersion.status, "open-dev=" + openDev.status);
  process.exit(pass ? 0 : 1);
}
