/* GraphSmith gateway-session chain integrity walk (checks/register-gateway-sessions.js).
 * SG-FR-7 from the Standalone Gateway TRD (.plans/v0.5.0/STANDALONE-GATEWAY-TRD-2026-08-22.md
 * SS3.6/SS8): verifies the append-only, hash-chained gateway-session log SG-FR-5 writes
 * (scripts/gateway/chain.js) -- same shape and discipline as checks/register-retention.js's
 * walkRetention(), deliberately, per the TRD's own instruction ("A walkGatewaySessions(ctx)
 * function, same shape as walkRetention"). This is a SEPARATE chain from adoption/retention
 * (Standalone Gateway TRD SS0's grounding finding: no code connects gateway-session activity
 * to the pre-existing adoption/retention system), so this is new, comparable-in-size work,
 * not a byproduct of SG-FR-5 -- not a thin wrapper around register-retention.js.
 *
 * One real difference from retention-entry's design, stated because it changes what this
 * verifier can catch that register-retention.js's cannot: gateway-session-entry's
 * entry_sha256 is SELF-REFERENTIAL (a hash of the entry's own other fields -- see
 * scripts/gateway/chain.js#computeEntrySha256), unlike retention-entry's packet_sha256 (an
 * externally-supplied hash of a packet the entry merely retains, which register-retention.js
 * has no way to recompute from the entry alone). That lets this walk distinguish, per the
 * Standalone Gateway TRD's test plan items 16/17:
 *   - a TAMPERED entry (its own entry_sha256 no longer matches its own recomputed content,
 *     OR the next entry's prev_entry_sha256 no longer matches it) -- "broken link"
 *   - a DELETED entry (a sequence gap, e.g. seq 5 then seq 7, no 6) -- "sequence gap",
 *     reported with a DISTINCT reason so an operator can tell "something was removed" from
 *     "something was tampered with" (test plan item 17's explicit requirement).
 * It also checks HEAD.json consistency against the chain's own tail (test plan item 12: a
 * crash between chain.jsonl's append and HEAD.json's update, per SS3.6's specified write
 * order, must be reported as an incomplete append needing recovery, never silently treated
 * as "chain is fine, just short") and, when a bundle-existence check is supplied, that every
 * chained bundle_id has a corresponding bundle file on disk.
 *
 * Discipline (mirrors register-retention.js exactly):
 *   - fail-closed: any broken link, sequence gap, bad shape, or head mismatch => failed.
 *   - no clock/randomness in the decision path; timestamps are evidence only, if present.
 *   - Report contract: { status, evidence[], assumptions[], failure_domain? }; pure.
 *   - Honest limit (A6, same as register-retention.js's): a privileged local attacker who
 *     rewrites both the chain and its own HEAD.json is out of scope for THIS verifier alone
 *     -- SG-FR-6 (remote anchoring, not yet implemented -- see scripts/gateway/chain.js's
 *     pushChainTailToRemoteAnchor stub) is the intended mitigation, same class as
 *     register-retention.js's own stated A6 limit.
 * Zero-dep CJS, Node >= 18. Schema: schemas/gateway-session-entry.schema.json.
 */
"use strict";

const HEX64 = /^[0-9a-f]{64}$/;
const ENTRY_KEYS = ["schema_version", "seq", "bundle_id", "prev_entry_sha256", "entry_sha256"];

function entryShapeOk(e) {
  if (!e || typeof e !== "object") return false;
  for (const k of ENTRY_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(e, k)) return false;
  }
  for (const k of Object.keys(e)) if (ENTRY_KEYS.indexOf(k) === -1) return false;
  if (e.schema_version !== "1.0") return false;
  if (typeof e.seq !== "number" || !Number.isInteger(e.seq) || e.seq < 1) return false;
  if (typeof e.bundle_id !== "string" || e.bundle_id.length === 0) return false;
  if (!(e.prev_entry_sha256 === null || (typeof e.prev_entry_sha256 === "string" && HEX64.test(e.prev_entry_sha256)))) return false;
  if (typeof e.entry_sha256 !== "string" || !HEX64.test(e.entry_sha256)) return false;
  return true;
}

/* ctx = {
 *   chain: [gateway-session-entry],   // ordered append-only log, as read from chain.jsonl
 *   head: { schema_version, seq, bundle_id, entry_sha256 } | null,   // HEAD.json's content
 *   computeEntrySha256: (entry) => hex64,   // scripts/gateway/chain.js's function, injected
 *                                            // rather than required(), keeping this module
 *                                            // dependency-free like register-retention.js
 *   bundleExists?: (bundle_id) => boolean,  // optional: checked against each chain entry
 * } */
function walkGatewaySessions(ctx) {
  const evidence = [];
  const assumptions = [
    "Chain integrity is verified offline (no network/clock/random in the decision path).",
    "Honest limit (A6, mirrors register-retention.js's): a privileged local attacker who rewrites both the chain and HEAD.json together is out of scope for this verifier alone; SG-FR-6 remote anchoring (not yet implemented) is the intended mitigation for that class.",
  ];
  const fail = (msg, domain) => ({ status: "failed", evidence, assumptions, failure_domain: domain || "untrusted-input", reason: msg });
  try {
    if (!ctx || typeof ctx !== "object") return fail("no context");
    const chain = ctx.chain;
    if (!Array.isArray(chain)) return fail("chain must be an array");
    if (typeof ctx.computeEntrySha256 !== "function") return fail("ctx.computeEntrySha256 function is required");

    if (chain.length === 0) {
      if (ctx.head) return fail("HEAD.json names a chain tail but chain.jsonl is empty -- incomplete/corrupt state", "trusted-core");
      return { status: "not-applicable", evidence, assumptions, reason: "empty gateway-session log -- nothing to verify" };
    }

    let prevHash = null;
    let prevSeq = null;
    for (let i = 0; i < chain.length; i++) {
      const e = chain[i];
      if (!entryShapeOk(e)) return fail(`entry[${i}] has an invalid shape/type -- refusing (fail-closed)`);

      const recomputed = ctx.computeEntrySha256({ schema_version: e.schema_version, seq: e.seq, bundle_id: e.bundle_id, prev_entry_sha256: e.prev_entry_sha256 });
      if (recomputed !== e.entry_sha256) {
        return fail(`entry[${i}] (seq=${e.seq}) entry_sha256 does not match its own recomputed content -- TAMPERED entry, distinct from a sequence gap`, "untrusted-input");
      }

      if (i === 0) {
        if (e.prev_entry_sha256 !== null) return fail("entry[0].prev_entry_sha256 must be null (chain root)");
      } else {
        if (e.seq !== prevSeq + 1) {
          return fail(`entry[${i}] seq=${e.seq} expected ${prevSeq + 1} -- SEQUENCE GAP (an entry was removed), distinct from a broken hash link`, "untrusted-input");
        }
        if (e.prev_entry_sha256 !== prevHash) {
          return fail(`entry[${i}] does not chain to entry[${i - 1}] -- broken/mutated link, distinct from a sequence gap`, "untrusted-input");
        }
      }
      if (typeof ctx.bundleExists === "function" && !ctx.bundleExists(e.bundle_id)) {
        return fail(`entry[${i}] (seq=${e.seq}) references bundle_id "${e.bundle_id}" with no corresponding bundle file on disk -- incomplete append or a deleted bundle`, "trusted-core");
      }
      prevHash = e.entry_sha256;
      prevSeq = e.seq;
    }
    evidence.push(`hash chain intact across ${chain.length} entry(ies); seq contiguous (append-only), starting at ${chain[0].seq}.`);

    const last = chain[chain.length - 1];
    if (!ctx.head) {
      return fail(`chain.jsonl has ${chain.length} entry(ies) but HEAD.json is missing -- incomplete append (crash between the chain.jsonl write and the HEAD.json update), needs recovery`, "trusted-core");
    }
    if (!(ctx.head.seq === last.seq && ctx.head.bundle_id === last.bundle_id && ctx.head.entry_sha256 === last.entry_sha256)) {
      return fail("HEAD.json does not match the chain's own tail entry -- incomplete append (crash between the chain.jsonl write and the HEAD.json update), needs recovery, never treated as merely short-but-fine", "trusted-core");
    }
    evidence.push(`HEAD.json matches the chain tail (seq=${last.seq}, bundle_id=${last.bundle_id}).`);

    return { status: "verified", evidence, assumptions };
  } catch (e) {
    return { status: "failed", evidence, assumptions, failure_domain: "trusted-core", reason: "exception during gateway-session walk -- failing closed: " + (e && e.message ? e.message : String(e)) };
  }
}

const check = {
  id: "register-gateway-sessions",
  run(ctx) {
    const r = walkGatewaySessions(ctx || {});
    const out = { status: r.status, evidence: r.evidence.slice(), assumptions: r.assumptions.slice() };
    if (r.failure_domain) out.failure_domain = r.failure_domain;
    if (r.reason) out.evidence.push("reason: " + r.reason);
    return out;
  },
};

module.exports = { ...check, walkGatewaySessions, entryShapeOk };

if (require.main === module) {
  if (process.argv.includes("--selftest")) {
    const { computeEntrySha256 } = require("../scripts/gateway/chain.js");
    const h = (n) => String(n).padStart(2, "0").repeat(32);
    const mk = (seq, prev, bundleId) => {
      const partial = { schema_version: "1.0", seq, bundle_id: bundleId, prev_entry_sha256: prev };
      return { ...partial, entry_sha256: computeEntrySha256(partial) };
    };
    const e1 = mk(1, null, "gsa-0000000000000001");
    const e2 = mk(2, e1.entry_sha256, "gsa-0000000000000002");
    const e3 = mk(3, e2.entry_sha256, "gsa-0000000000000003");
    const chain = [e1, e2, e3];
    const head = { schema_version: "1.0", seq: 3, bundle_id: e3.bundle_id, entry_sha256: e3.entry_sha256 };

    const good = check.run({ chain, head, computeEntrySha256 });
    // tamper the middle entry's own hash (does not recompute).
    const tampered = [e1, { ...e2, entry_sha256: h(9) }, e3];
    const brokenSelf = check.run({ chain: tampered, head, computeEntrySha256 });
    // delete the middle entry -> sequence gap, distinct failure text from brokenSelf.
    const gapChain = [e1, e3];
    const gap = check.run({ chain: gapChain, head: { ...head, seq: 3 }, computeEntrySha256 });
    // HEAD.json missing -> incomplete append.
    const noHead = check.run({ chain, head: null, computeEntrySha256 });
    // HEAD.json stale (crash before update) -> incomplete append.
    const staleHead = check.run({ chain, head: { schema_version: "1.0", seq: 2, bundle_id: e2.bundle_id, entry_sha256: e2.entry_sha256 }, computeEntrySha256 });
    // bundle file missing for a chained entry.
    const missingBundle = check.run({ chain, head, computeEntrySha256, bundleExists: (id) => id !== e2.bundle_id });

    const pass =
      good.status === "verified" &&
      brokenSelf.status === "failed" && /TAMPERED/.test(brokenSelf.evidence.join(" ")) &&
      gap.status === "failed" && /SEQUENCE GAP/.test(gap.evidence.join(" ")) &&
      noHead.status === "failed" && /incomplete append/.test(noHead.evidence.join(" ")) &&
      staleHead.status === "failed" && /incomplete append/.test(staleHead.evidence.join(" ")) &&
      missingBundle.status === "failed" && /no corresponding bundle file/.test(missingBundle.evidence.join(" "));

    console.log(
      "register-gateway-sessions selftest:", pass ? "OK" : "FAIL",
      "| chain=" + (good.status === "verified"),
      "tampered-detected=" + (brokenSelf.status === "failed"),
      "gap-detected=" + (gap.status === "failed"),
      "no-head-detected=" + (noHead.status === "failed"),
      "stale-head-detected=" + (staleHead.status === "failed"),
      "missing-bundle-detected=" + (missingBundle.status === "failed")
    );
    process.exit(pass ? 0 : 1);
  } else {
    console.error("Usage: node checks/register-gateway-sessions.js --selftest");
    process.exit(1);
  }
}
