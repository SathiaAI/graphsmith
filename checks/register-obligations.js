/* GraphSmith register Lane B — obligations -> controls reconciler (checks/register-obligations.js).
 * THE MAKE-OR-BREAK. Maps each regulatory obligation to the GraphSmith control(s) that
 * produce evidence for it, and reports coverage HONESTLY. Produces evidence + an honest
 * coverage map — NEVER a "compliant" verdict.
 *
 * Discipline (frozen Contract 13):
 *   - C2 fail-closed (PB-8): coverage is RECOMPUTED from the actual evidence in the packet;
 *     the register's DECLARED `coverage` is never trusted (mirrors D5 mode-recompute). An
 *     obligation with no executable control is `manual-only` and can NEVER be `covered`.
 *     Unmapped / partial / misplaced / over-claimed => resolves down, loudly. Regulated mode
 *     activates ONLY on a complete, clean register.
 *   - C1: no clock/randomness; identity is evidence, never a decision input. Pure.
 *   - Report contract (D3): { status, evidence[], assumptions[], failure_domain? }, plus a
 *     per-obligation coverage_map and a regulated_mode_may_activate boolean.
 * Zero-dep CJS, Node >= 18. Schema: schemas/obligations.schema.json.
 */
"use strict";

const COVERAGE = new Set(["covered", "partial", "manual-only", "not-covered"]);

/* Recompute the ACTUAL coverage of one obligation from real evidence.
 * evidence = { profiles:{name:status}, replayHashes:[hex], redteamSuites:{name:{blocked,total}} }
 * Returns "covered" | "partial" | "manual-only" | "not-covered". Never throws. */
function recomputeCoverage(ob, evidence) {
  const controls = Array.isArray(ob.controls) ? ob.controls : [];
  if (controls.length === 0) return "manual-only"; // no executable control — human judgment only
  const ea = ob.evidence_artifact;
  if (!ea || typeof ea !== "object" || typeof ea.type !== "string" || typeof ea.ref !== "string") {
    return "not-covered"; // a control is claimed but no concrete evidence artifact is cited
  }
  const ev = evidence && typeof evidence === "object" ? evidence : {};
  if (ea.type === "profile-result") {
    const st = (ev.profiles || {})[ea.ref];
    return st === "verified" ? "covered" : "not-covered";
  }
  if (ea.type === "scenario-replay-hash") {
    const hashes = Array.isArray(ev.replayHashes) ? ev.replayHashes : [];
    return hashes.indexOf(ea.ref) !== -1 ? "covered" : "not-covered";
  }
  if (ea.type === "redteam-packet") {
    const s = (ev.redteamSuites || {})[ea.ref];
    if (!s || typeof s.blocked !== "number" || typeof s.total !== "number" || s.total <= 0) return "not-covered";
    if (s.blocked >= s.total) return "covered";
    if (s.blocked > 0) return "partial";
    return "not-covered";
  }
  return "not-covered"; // unknown evidence type => fail closed
}

/* Reconcile a whole obligations register against packet evidence.
 * ctx = { register: <obligations.schema object>, evidence: {...} } */
function reconcile(ctx) {
  const assumptions = [
    "Coverage is recomputed from evidence in the packet; the register's declared coverage is not trusted (C2).",
    "This is an evidence + honest-coverage map, NOT a compliance verdict. Obligations without an executable control are manual-only and require human judgment (PB-8).",
    "No clock/randomness; identity is evidence, never a decision input (C1).",
  ];
  const fail = (msg) => ({ status: "failed", evidence: [], assumptions, failure_domain: "untrusted-input", coverage_map: [], regulated_mode_may_activate: false, reason: msg });

  if (!ctx || typeof ctx !== "object") return fail("no reconciliation context");
  const register = ctx.register;
  if (!register || typeof register !== "object" || register.schema_version !== "1.0") return fail("register missing or schema_version != '1.0'");
  if (typeof register.obligation_set_id !== "string" || register.obligation_set_id.length < 1) return fail("register.obligation_set_id missing");
  if (!Array.isArray(register.obligations)) return fail("register.obligations must be an array");
  if (register.obligations.length === 0) {
    return { status: "not-applicable", evidence: ["register is empty — no obligations to reconcile"], assumptions, coverage_map: [], regulated_mode_may_activate: false };
  }

  const evidence = ctx.evidence || {};
  const coverage_map = [];
  const violations = [];
  const seenIds = new Set();

  for (const ob of register.obligations) {
    if (!ob || typeof ob !== "object" || typeof ob.obligation_id !== "string") {
      violations.push({ severity: "HIGH", obligation_id: "(malformed)", issue: "malformed obligation entry" });
      continue;
    }
    if (seenIds.has(ob.obligation_id)) {
      violations.push({ severity: "HIGH", obligation_id: ob.obligation_id, issue: "duplicate obligation_id (a register that lists the same obligation twice can hide a gap)" });
    }
    seenIds.add(ob.obligation_id);

    const declared = COVERAGE.has(ob.declared_coverage) ? ob.declared_coverage : (COVERAGE.has(ob.coverage) ? ob.coverage : null);
    const actual = recomputeCoverage(ob, evidence);

    // C2 CRITICAL: a manual-only obligation (no executable control) can NEVER be covered.
    if (actual === "manual-only" && declared === "covered") {
      violations.push({ severity: "CRITICAL", obligation_id: ob.obligation_id, issue: "manual-only obligation (no executable control) declared 'covered' — the exact PB-8 fail-open; rejected" });
    } else if (declared === "covered" && actual !== "covered") {
      violations.push({ severity: "HIGH", obligation_id: ob.obligation_id, issue: "over-claimed: declared 'covered' but evidence recomputes to '" + actual + "'" });
    }

    // Honesty of the evidence-vs-judgment split.
    const split = ob.evidence_vs_judgment;
    const hasSplit = split && typeof split === "object" && typeof split.graphsmith_evidence === "string" && typeof split.human_judgment === "string";
    if (actual === "manual-only" && (!hasSplit || split.human_judgment.trim().length === 0)) {
      violations.push({ severity: "MEDIUM", obligation_id: ob.obligation_id, issue: "manual-only obligation lacks a stated human_judgment — incomplete, cannot count toward a complete register" });
    }

    coverage_map.push({
      obligation_id: ob.obligation_id,
      source: ob.source || null,
      declared_coverage: declared,
      actual_coverage: actual, // the honest, recomputed verdict — this is what counts
      evidence_vs_judgment: hasSplit ? split : null,
    });
  }

  // Completeness: every obligation must be either 'covered' by evidence, or 'manual-only'
  // WITH a stated human_judgment; zero violations. Anything else => cannot activate (fail-closed).
  const anyViolation = violations.length > 0;
  const allResolved = coverage_map.every((c) => {
    if (c.actual_coverage === "covered") return true;
    if (c.actual_coverage === "manual-only") return !!(c.evidence_vs_judgment && c.evidence_vs_judgment.human_judgment && c.evidence_vs_judgment.human_judgment.trim().length > 0);
    return false; // partial / not-covered => not resolved
  });
  const complete = allResolved && !anyViolation;

  const evidenceLines = [];
  const counts = coverage_map.reduce((a, c) => { a[c.actual_coverage] = (a[c.actual_coverage] || 0) + 1; return a; }, {});
  evidenceLines.push("recomputed coverage: " + JSON.stringify(counts) + " over " + coverage_map.length + " obligation(s) in set '" + register.obligation_set_id + "'.");
  for (const v of violations) evidenceLines.push("VIOLATION [" + v.severity + "] " + v.obligation_id + ": " + v.issue);
  evidenceLines.push("regulated_mode_may_activate: " + (complete ? "true (complete, clean register)" : "false (fail-closed — incomplete or has violations)") + ".");

  let status;
  if (anyViolation) status = "failed";
  else if (complete) status = "verified";
  else status = "unavailable"; // honest: coverage incomplete; not a pass, not a failure of the register's shape

  const out = { status, evidence: evidenceLines, assumptions, coverage_map, regulated_mode_may_activate: complete };
  if (anyViolation) out.failure_domain = "untrusted-input";
  return out;
}

const check = {
  id: "register-obligations",
  run(ctx) {
    const r = reconcile(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice(), coverage_map: r.coverage_map, regulated_mode_may_activate: r.regulated_mode_may_activate };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) out.evidence.push("reason: " + r.reason);
    return out;
  },
};

module.exports = { ...check, reconcile, recomputeCoverage };

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    const base = (over) => ({ schema_version: "1.0", obligation_set_id: "set-1", obligations: [], ...over });
    const split = { graphsmith_evidence: "T profile verified offline", human_judgment: "auditor confirms scope" };
    // 1. manual-only declared covered => CRITICAL, rejected.
    const attack = base({ obligations: [{ obligation_id: "o1", source: { framework: "X", clause: "1" }, controls: [], coverage: "covered", evidence_vs_judgment: split }] });
    const rAttack = check.run({ register: attack, evidence: {} });
    const caught = rAttack.status === "failed" && !rAttack.regulated_mode_may_activate;
    // 2. over-claimed covered with no verified profile => HIGH, not activated.
    const over = base({ obligations: [{ obligation_id: "o2", source: { framework: "X", clause: "2" }, controls: [{ type: "profile", ref: "T" }], evidence_artifact: { type: "profile-result", ref: "T" }, coverage: "covered", evidence_vs_judgment: split }] });
    const rOver = check.run({ register: over, evidence: { profiles: { T: "unavailable" } } });
    const overCaught = rOver.status === "failed" && rOver.coverage_map[0].actual_coverage === "not-covered";
    // 3. genuinely covered (profile verified) + a manual-only w/ judgment => complete => activate.
    const good = base({ obligations: [
      { obligation_id: "o3", source: { framework: "X", clause: "3" }, controls: [{ type: "profile", ref: "T" }], evidence_artifact: { type: "profile-result", ref: "T" }, coverage: "covered", evidence_vs_judgment: split },
      { obligation_id: "o4", source: { framework: "X", clause: "4" }, controls: [], coverage: "manual-only", evidence_vs_judgment: split },
    ] });
    const rGood = check.run({ register: good, evidence: { profiles: { T: "verified" } } });
    const goodOk = rGood.status === "verified" && rGood.regulated_mode_may_activate === true;
    // 4. partial redteam => unavailable, not activated.
    const part = base({ obligations: [{ obligation_id: "o5", source: { framework: "X", clause: "5" }, controls: [{ type: "harness", ref: "redteam" }], evidence_artifact: { type: "redteam-packet", ref: "redteam" }, coverage: "partial", evidence_vs_judgment: split }] });
    const rPart = check.run({ register: part, evidence: { redteamSuites: { redteam: { blocked: 3, total: 10 } } } });
    const partOk = rPart.status === "unavailable" && rPart.regulated_mode_may_activate === false && rPart.coverage_map[0].actual_coverage === "partial";

    const pass = caught && overCaught && goodOk && partOk;
    console.log("register-obligations selftest:", pass ? "OK" : "FAIL",
      "| manual-marked-covered-caught=" + caught, "over-claim-caught=" + overCaught, "complete-activates=" + goodOk, "partial-blocks=" + partOk);
    process.exit(pass ? 0 : 1);
  } else {
    console.error("Usage: node checks/register-obligations.js --selftest");
    process.exit(1);
  }
}
