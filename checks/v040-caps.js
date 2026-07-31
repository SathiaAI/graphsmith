/* GraphSmith v0.4.0 Lane R1 — per-skill capability conformance check (checks/v040-caps.js).
 * Recomputes `requested ⊆ granted` per resource class (filesystem / model / subprocess / network)
 * and enforces the D1 HONESTY LINE: a class may be attested "satisfied" ONLY if it is in the grant's
 * `enforced` list AND requested ⊆ granted. A bundle that attests a class it did not actually enforce
 * (a fail-open engine claiming "requested ≤ granted: satisfied") MUST fail — never vouch for a
 * boundary that isn't enforced. Pure decision path (no clock/random/network); C1; fail-closed.
 * Schema: schemas/capability-grant.schema.json. Zero-dep CJS, Node >= 18.
 */
"use strict";

const CLASSES = ["filesystem", "model", "subprocess", "network"];

/* Is `req` (a requested resource set for one class) within `grant` (the granted envelope)? */
function subsetOk(cls, req, grant) {
  if (!req) return true;                              // nothing requested for this class
  grant = grant || {};
  const within = (reqList, grantList) => {
    // Absent is legitimate: a filesystem request may set `read` and not `write`.
    if (reqList === undefined || reqList === null) return true;
    // Present-but-not-a-list is NOT "requested nothing" -- it is a request we cannot
    // read, and this module's stated posture is never coerce, fail closed. Returning
    // true here made any malformed request vacuously within grant.
    if (!Array.isArray(reqList)) return false;
    const g = Array.isArray(grantList) ? grantList : [];
    if (cls === "filesystem") return reqList.every((p) => {
      if (typeof p !== "string") return false;
      // Canonical paths only: reject any "." or ".." segment (defeats traversal + normalization tricks).
      if (p.split("/").some((s) => s === "." || s === "..")) return false;
      // Segment-boundary containment: exactly the grant, or strictly under grant + "/".
      // (Plain startsWith would let "/inputs-evil" pass a grant of "/inputs".)
      return g.some((gp) => typeof gp === "string" && (p === gp || p.startsWith(gp.endsWith("/") ? gp : gp + "/")));
    });
    return reqList.every((x) => g.indexOf(x) !== -1); // exact-match allowlist (model/subprocess/network)
  };
  if (cls === "filesystem") return within(req.read, grant.read) && within(req.write, grant.write);
  if (cls === "model") return within(req.allowed, grant.allowed);
  if (cls === "subprocess") return within(req.allowed, grant.allowed);
  if (cls === "network") return within(req.destinations, grant.destinations);
  return false;
}

/* ctx = {
 *   grant:      capability-grant object ({ grants:{...}, enforced:[classes] }),
 *   requested:  { filesystem?, model?, subprocess?, network? }  // what the run actually requested/used
 *   attested:   { filesystem?:bool, model?:bool, subprocess?:bool, network?:bool }  // what the bundle claims satisfied
 * } */
function verifyCapabilities(ctx) {
  const evidence = [];
  const assumptions = [
    "Only classes the running engine ENFORCES this release are attested; a declared-but-unenforced class is reported, never vouched for (D1).",
    "Pure decision path — no clock/random/network; identity/timestamps are evidence, never decision inputs (C1).",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const grant = ctx.grant;
    if (!grant || typeof grant !== "object" || grant.schema_version !== "1.0") return fail("capability-grant missing/invalid");
    // NOTE: skill_id is IDENTITY — validated as evidence elsewhere, but deliberately NOT a decision
    // input here (C1). The capability verdict must be invariant to skill_id's value/type; gating on it
    // would violate C1 (confirmed by the DeepSeek Lane-R1 C1 test).
    const enforced = new Set(Array.isArray(grant.enforced) ? grant.enforced : []);
    const grants = grant.grants || {};
    const requested = ctx.requested || {};
    const attested = ctx.attested || {};

    for (const cls of CLASSES) {
      if (Object.prototype.hasOwnProperty.call(attested, cls) && typeof attested[cls] !== "boolean") return fail("attested['" + cls + "'] is present but not a boolean — refusing malformed attestation (fail-closed)");
      const claimsSatisfied = attested[cls] === true;
      const req = requested[cls];
      const within = subsetOk(cls, req, grants[cls]);

      // Requested outside the granted envelope → the run should have halted pre-execution. Fail-closed.
      if (req && !within) return fail("class '" + cls + "': requested ⊄ granted — must halt pre-execution, not attest", "untrusted-input");

      // D1: attesting a class as satisfied that the engine does not enforce is the credibility-ending lie.
      if (claimsSatisfied && !enforced.has(cls)) {
        return fail("class '" + cls + "' attested 'satisfied' but is NOT in the enforced set — refusing to vouch for an unenforced boundary (D1)", "trusted-core");
      }
      if (claimsSatisfied) evidence.push("class '" + cls + "': enforced + requested ⊆ granted — satisfied.");
      else if (enforced.has(cls)) evidence.push("class '" + cls + "': enforced; not claimed satisfied.");
      else evidence.push("class '" + cls + "': not enforced this release — declared only, not attested (unavailable).");
    }
    // Verified only if at least one class is enforced-and-satisfied and nothing failed.
    const anySatisfied = CLASSES.some((c) => attested[c] === true && enforced.has(c));
    return { status: anySatisfied ? "verified" : "unavailable", evidence, assumptions,
      reason: anySatisfied ? undefined : "no capability class is both enforced and attested satisfied — nothing to vouch for (not a pass)" };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "v040-caps",
  run(ctx) {
    const r = verifyCapabilities(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) { out.reason = r.reason; out.evidence.push("reason: " + r.reason); }
    return out;
  },
};

module.exports = { ...check, verifyCapabilities, subsetOk };

if (require.main === module && process.argv.includes("--selftest")) {
  const grant = { schema_version: "1.0", skill_id: "s1", grants: { filesystem: { read: ["/inputs"], write: ["/outputs"] }, network: { destinations: ["api.example.com"] } }, enforced: ["filesystem"] };
  // 1. filesystem requested within grant + enforced + attested → verified.
  const good = check.run({ grant, requested: { filesystem: { read: ["/inputs/x.txt"], write: ["/outputs/y"] } }, attested: { filesystem: true } });
  // 2. requested outside grant (write to /etc) → failed (should have halted).
  const escalate = check.run({ grant, requested: { filesystem: { write: ["/etc/passwd"] } }, attested: { filesystem: true } });
  // 3. D1 fail-open: attest network satisfied but network NOT in enforced → failed.
  const failOpen = check.run({ grant, requested: { network: { destinations: ["api.example.com"] } }, attested: { network: true } });
  // 4. network requested within grant but not enforced + not attested → unavailable for network; fs not claimed → overall unavailable.
  const declaredOnly = check.run({ grant, requested: { network: { destinations: ["api.example.com"] } }, attested: {} });
  const pass = good.status === "verified" && escalate.status === "failed" && failOpen.status === "failed" && declaredOnly.status === "unavailable";
  console.log("v040-caps selftest:", pass ? "OK" : "FAIL",
    "| within-grant-enforced=" + (good.status === "verified"), "escalation-halts=" + (escalate.status === "failed"),
    "D1-unenforced-attest-refused=" + (failOpen.status === "failed"), "declared-not-attested=" + (declaredOnly.status === "unavailable"));
  process.exit(pass ? 0 : 1);
}
