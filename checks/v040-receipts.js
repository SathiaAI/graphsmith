/* GraphSmith v0.4.0 Lane R2 — side-effect receipt reconciliation (checks/v040-receipts.js).
 * Reconciles recorded external effects against the receipts adapters return, extending the E
 * (effect-reconciled) profile. HONEST BOUNDARY: this is run-once, replay-verified reconciliation of
 * RECORDED effects — NOT end-to-end single-delivery (which still needs an idempotency key the
 * external system honours, an adapter-author property GSA does not verify).
 *
 * Rules: status "success" counts as reconciled ONLY with a present `external_id` (the external
 * system's returned confirmation) — a bare "success" with no external evidence is treated as
 * UNKNOWN (reconciliation-required), so a forged evidence-less "success" cannot upgrade an effect.
 * "unknown" => UNKNOWN_EFFECT (reconciliation-required, fail-closed). "failed" => the effect failed.
 * Pure (no clock/random/network); C1 (`ts` is evidence, never a decision input); C2 fail-closed.
 * Schema: schemas/side-effect-receipt.schema.json. Zero-dep CJS, Node >= 18.
 */
"use strict";


/* ctx = { effects: [ { action, receipt?: side-effect-receipt } ] } */
function reconcileEffects(ctx) {
  const evidence = [];
  const assumptions = [
    "Run-once, replay-verified reconciliation of RECORDED effects — not end-to-end single-delivery, which needs the external system's idempotency key (adapter-author property, not verified here).",
    "Pure decision path — no clock/random/network; `ts` is evidence, never a decision input (C1).",
  ];
  const fail = (msg) => ({ status: "failed", evidence, assumptions, failure_domain: "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const effects = ctx.effects;
    if (!Array.isArray(effects)) return fail("effects must be an array");
    if (effects.length === 0) return { status: "not-applicable", evidence, assumptions, reason: "no recorded external effects" };

    let reconciled = 0, unknown = 0, failed = 0;
    for (let i = 0; i < effects.length; i++) {
      const e = effects[i];
      if (!e || typeof e !== "object") return fail("effect[" + i + "] malformed");
      const r = e.receipt;
      // No receipt at all => UNKNOWN_EFFECT (reconciliation-required, fail-closed — never assume success).
      if (r === undefined || r === null) { unknown++; evidence.push("effect[" + i + "] '" + (e.action || "?") + "': no receipt → UNKNOWN_EFFECT (reconciliation-required)."); continue; }
      if (typeof r !== "object" || r.schema_version !== "1.0") return fail("effect[" + i + "] receipt malformed/invalid");
      if (typeof r.action !== "string" || typeof r.adapter_id !== "string") return fail("effect[" + i + "] receipt missing action/adapter_id");
      if (["success", "unknown", "failed"].indexOf(r.status) === -1) return fail("effect[" + i + "] receipt.status not in enum — refusing malformed status");
      // An invalid external_id VALUE (null/number/BigInt/absent) is not valid external evidence — the
      // effect is UNKNOWN (reconciliation-required, below), never "failed" (it may have succeeded; we
      // just can't confirm). Only a structurally malformed RECEIPT (above) fails closed.

      if (r.status === "failed") { failed++; evidence.push("effect[" + i + "] '" + r.action + "': receipt failed."); continue; }
      // "success" reconciles ONLY with genuine external evidence (external_id). A bare success is UNKNOWN.
      if (r.status === "success" && typeof r.external_id === "string" && r.external_id.length > 0) {
        reconciled++; evidence.push("effect[" + i + "] '" + r.action + "': reconciled (external_id present).");
      } else {
        unknown++; evidence.push("effect[" + i + "] '" + r.action + "': status='" + r.status + "' without external evidence → UNKNOWN_EFFECT (reconciliation-required).");
      }
    }

    evidence.push("effects: reconciled=" + reconciled + " unknown=" + unknown + " failed=" + failed + " of " + effects.length + ".");
    // E-reconciled (verified) only if EVERY effect is reconciled with evidence and none failed/unknown.
    if (failed > 0) return { status: "failed", evidence, assumptions, failure_domain: "evolvable-surface", reason: failed + " effect(s) failed at the external system" };
    if (unknown > 0) return { status: "unavailable", evidence, assumptions, reason: unknown + " effect(s) are UNKNOWN — reconciliation-required, not a pass (C2 fail-closed)" };
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "v040-receipts",
  run(ctx) {
    const r = reconcileEffects(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) { out.reason = r.reason; out.evidence.push("reason: " + r.reason); }
    return out;
  },
};

module.exports = { ...check, reconcileEffects };

if (require.main === module && process.argv.includes("--selftest")) {
  const R = (over) => ({ schema_version: "1.0", adapter_id: "email", action: "email.send", status: "success", external_id: "msg-abc123", ...over });
  const allGood = check.run({ effects: [{ action: "email.send", receipt: R({}) }, { action: "ticket.create", receipt: R({ adapter_id: "jira", action: "ticket.create", external_id: "PROJ-42" }) }] });
  const noReceipt = check.run({ effects: [{ action: "email.send" }] });                                   // UNKNOWN_EFFECT
  const forgedSuccess = check.run({ effects: [{ action: "email.send", receipt: R({ external_id: undefined }) }] }); // success w/o external_id → unknown
  const failedEffect = check.run({ effects: [{ action: "pay", receipt: R({ status: "failed", external_id: undefined }) }] });
  const badStatus = check.run({ effects: [{ action: "x", receipt: R({ status: "maybe" }) }] });           // malformed status → failed
  const pass = allGood.status === "verified" && noReceipt.status === "unavailable" &&
    forgedSuccess.status === "unavailable" && failedEffect.status === "failed" && badStatus.status === "failed";
  console.log("v040-receipts selftest:", pass ? "OK" : "FAIL",
    "| all-reconciled=" + (allGood.status === "verified"), "no-receipt-unknown=" + (noReceipt.status === "unavailable"),
    "forged-success-blocked=" + (forgedSuccess.status === "unavailable"), "failed-effect=" + (failedEffect.status === "failed"), "bad-status-rejected=" + (badStatus.status === "failed"));
  process.exit(pass ? 0 : 1);
}
