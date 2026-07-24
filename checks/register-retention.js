/* GraphSmith register Lane C — evidence retention integrity walk (checks/register-retention.js).
 * Verifies the append-only, hash-chained retention log: each assure packet chained to the
 * prior packet's hash, sequence-monotonic, anchored to the adoption-log head. A mutated middle
 * entry breaks the walk. Verifiable offline by a third party.
 *
 * Discipline (frozen Contract 13):
 *   - C2 fail-closed: any broken link, sequence gap, bad shape, or anchored-head mismatch => failed.
 *   - C1: no clock/randomness in the decision path; identity/timestamps are evidence only.
 *   - Report contract (D3): { status, evidence[], assumptions[], failure_domain? }; pure.
 *   - Honest limit (A6): a privileged local attacker who rewrites BOTH the store and the anchor
 *     is out of scope; remote/CI anchoring (push the head to a trusted remote) is the mitigation
 *     for shared/regulated use. Stated, not hidden.
 * Zero-dep CJS, Node >= 18. Schema: schemas/retention-entry.schema.json.
 */
"use strict";

const HEX64 = /^[0-9a-f]{64}$/;
const ENTRY_KEYS = ["schema_version", "seq", "prev_packet_sha256", "packet_sha256", "anchored_head", "recorded_at"];

function entryShapeOk(e) {
  if (!e || typeof e !== "object") return false;
  for (const k of ["schema_version", "seq", "prev_packet_sha256", "packet_sha256", "anchored_head"]) {
    if (!Object.prototype.hasOwnProperty.call(e, k)) return false;
  }
  for (const k of Object.keys(e)) if (ENTRY_KEYS.indexOf(k) === -1) return false;
  if (e.schema_version !== "1.0") return false;
  if (typeof e.seq !== "number" || !Number.isInteger(e.seq) || e.seq < 1) return false;
  if (!(e.prev_packet_sha256 === null || (typeof e.prev_packet_sha256 === "string" && HEX64.test(e.prev_packet_sha256)))) return false;
  if (typeof e.packet_sha256 !== "string" || !HEX64.test(e.packet_sha256)) return false;
  if (typeof e.anchored_head !== "string" || !HEX64.test(e.anchored_head)) return false;
  return true;
}

/* ctx = {
 *   chain: [retention-entry],          // ordered append-only log
 *   expected_anchored_head?: hex64     // the current adoption-log head the latest entry must match
 * } */
function walkRetention(ctx) {
  const evidence = [];
  const assumptions = [
    "Chain integrity is verified offline (no network/clock/random in the decision path, C1).",
    "Honest limit (A6): a privileged local attacker who rewrites both the store and the anchor is out of scope; remote/CI anchoring of the head is the mitigation for shared/regulated use.",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const chain = ctx.chain;
    if (!Array.isArray(chain)) return fail("chain must be an array");
    if (chain.length === 0) return { status: "not-applicable", evidence, assumptions, reason: "empty retention log — nothing to verify" };

    let prevHash = null;
    let prevSeq = null;
    for (let i = 0; i < chain.length; i++) {
      const e = chain[i];
      if (!entryShapeOk(e)) return fail("entry[" + i + "] has an invalid shape/type — refusing (fail-closed)");
      if (i === 0) {
        if (e.prev_packet_sha256 !== null) return fail("entry[0].prev_packet_sha256 must be null (chain root)");
      } else {
        // Contiguous append-only: seq increments by exactly 1. A gap/reorder while the hash chains
        // contiguously means a manipulated sequence. The starting seq may be any int>=1 (a rotated
        // or global counter need not begin at 1 — Mistral Lane-C finding).
        if (e.seq !== prevSeq + 1) return fail("entry[" + i + "] seq=" + e.seq + " expected " + (prevSeq + 1) + " — sequence gap/reorder (append-only violated)");
        if (e.prev_packet_sha256 !== prevHash) return fail("entry[" + i + "] does not chain to entry[" + (i - 1) + "] — broken/mutated link");
      }
      prevHash = e.packet_sha256;
      prevSeq = e.seq;
    }
    evidence.push("hash chain intact across " + chain.length + " entry(ies); seq contiguous (append-only), starting at " + chain[0].seq + ".");

    // Anchored-head binding: the latest entry must match the current adoption-log head, when supplied.
    const last = chain[chain.length - 1];
    if (typeof ctx.expected_anchored_head === "string") {
      if (!HEX64.test(ctx.expected_anchored_head)) return fail("expected_anchored_head is not a 64-hex string");
      if (last.anchored_head !== ctx.expected_anchored_head) {
        return fail("latest entry's anchored_head does not match the adoption-log head — retention not bound to the live head", "untrusted-input");
      }
      evidence.push("latest anchored_head matches the adoption-log head (" + last.anchored_head.slice(0, 12) + "…).");
    } else {
      evidence.push("anchored_head present on the latest entry (" + last.anchored_head.slice(0, 12) + "…); no expected head supplied to bind against.");
    }
    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception during retention walk — failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "register-retention",
  run(ctx) {
    const r = walkRetention(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) out.evidence.push("reason: " + r.reason);
    return out;
  },
};

module.exports = { ...check, walkRetention };

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    const h = (n) => String(n).padStart(2, "0").repeat(32); // deterministic 64-hex fixtures
    const head = "f".repeat(64);
    const mk = (seq, prev, pkt) => ({ schema_version: "1.0", seq, prev_packet_sha256: prev, packet_sha256: pkt, anchored_head: head });
    const chain = [mk(1, null, h(1)), mk(2, h(1), h(2)), mk(3, h(2), h(3))];
    const good = check.run({ chain, expected_anchored_head: head });
    // mutate the middle entry's packet hash — breaks the link to entry[2].
    const mutated = [mk(1, null, h(1)), mk(2, h(1), h(9)), mk(3, h(2), h(3))];
    const broken = check.run({ chain: mutated, expected_anchored_head: head });
    // wrong anchored head.
    const wrongHead = check.run({ chain, expected_anchored_head: "a".repeat(64) });
    // sequence gap.
    const gap = check.run({ chain: [mk(1, null, h(1)), mk(3, h(1), h(3))], expected_anchored_head: head });
    const pass = good.status === "verified" && broken.status === "failed" && wrongHead.status === "failed" && gap.status === "failed";
    console.log("register-retention selftest:", pass ? "OK" : "FAIL", "| chain=" + (good.status === "verified"), "mutated-breaks=" + (broken.status === "failed"), "wrong-head=" + (wrongHead.status === "failed"), "seq-gap=" + (gap.status === "failed"));
    process.exit(pass ? 0 : 1);
  } else {
    console.error("Usage: node checks/register-retention.js --selftest");
    process.exit(1);
  }
}
