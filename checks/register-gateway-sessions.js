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
 * order, must be reported explicitly, never silently treated as "chain is fine, just short")
 * and, when a bundle-existence check is supplied, that every chained bundle_id has a
 * corresponding bundle file on disk.
 *
 * Round-2 fix-round follow-up (docs/contracts/chain-validity.md, "C2 -- Canonical Chain
 * Validity", SS5 "one implementation, not three copies"): the structural walk below --
 * per-entry hash/link/sequence/genesis verification and the HEAD-vs-tail comparison -- no
 * longer hand-rolls that logic. It delegates entirely to `chain.validateChain` (and, via
 * that function, `chain.readChainTail`'s own torn-record handling), the SAME canonical
 * validator `chain.reconcileHead` (startup reconciliation) and the append-time check inside
 * `chain.appendSession` / `chain.repairMissingChainEntry` already use. C2 SS5 names this walk
 * as the third of three call sites that must never quietly diverge on what "valid" means;
 * this was the last of the three still re-deriving its own subset of the definition.
 * `entryShapeOk` and `headShapeOk` below stay as intentionally-duplicated, hand-rolled
 * copies of chain.js's own functions of the same name -- C2 SS5 explicitly permits this
 * ("provably identical hand-rolled copies," the same convention this codebase already uses
 * for register-retention.js vs register-gateway-sessions.js) -- they are used here only to
 * filter the entries this module's own bundle-existence check (see below, outside C2's
 * structural scope) walks, not to re-derive any hash/link/sequence verdict
 * chain.validateChain already owns.
 *
 * A NOTE ON THE LEASE-KEEPALIVE LOOP BELOW (round-1 fix-plan item 1, landed the same
 * round as this delegation; round-3 fix pass corrects a defect an independent verifier
 * found in the round-2 landing described below): before the round-2 delegation,
 * `ctx.maybeRenew()` was called once per chain entry from INSIDE this module's own
 * hand-rolled hash/link/sequence loop. Round-2 replaced that loop with a small,
 * decoupled pre-pass over `ctx.chain`, run BEFORE `chain.validateChain` was ever
 * called -- reasoning that `chain.validateChain` should not be handed a caller-specific
 * lease-renewal callback. That was wrong in practice: `maybeRenew()` is time-gated
 * (scripts/writer-claim.js fires it at most once per heartbeatMs interval), so calling
 * it N times in a tight synchronous pre-pass loop performs at most ONE real renewal, and
 * the actual expensive validation work inside `chain.validateChain` then ran with
 * effectively zero renewal coverage -- exactly the lease-starvation this fix exists to
 * prevent.
 *
 * Fixed here (round-3) by giving `chain.validateChain` an optional `onEntry` hook (see
 * its own doc comment in scripts/gateway/chain.js) that IT invokes once per entry, in
 * order, from INSIDE its own per-entry hash/link/sequence loop -- `ctx.maybeRenew` is
 * passed straight through as that hook below. This still keeps `chain.validateChain` the
 * one canonical structural validator (C2 SS5) free of any lease-specific logic of its
 * own: an injected callback is exactly the same shape `ctx.computeEntrySha256` and
 * `ctx.bundleExists` already are at this call site, not a new mechanism. Renewal is now
 * genuinely interleaved with the real per-entry work (see
 * tests/gateway/chain/run-tests.js's new
 * `walkGatewaySessionsMaybeRenewInterleavedWithValidateChainNotFrontLoaded`, which proves
 * the call count is bounded by how far the walk actually got, not by `rawChain.length`),
 * and a thrown lease-loss error aborts the walk at exactly the entry `onEntry` was called
 * for -- STRICTLY no later, and often earlier, than the round-2 pre-pass could ever
 * abort, so the pre-existing "abort immediately, mid-walk, on a detected lease loss"
 * contract (`walkGatewaySessionsCallsMaybeRenewOncePerEntry` and
 * `walkAbortsOnLeaseTakeoverMidWalkNotDowngradedToAFailedReport`) holds more strongly
 * than before, not less.
 *
 * Discipline (mirrors register-retention.js exactly):
 *   - fail-closed for genuine structural/integrity problems: bad entry/HEAD shape, a
 *     sequence gap, a broken or tampered link, an invalid genesis, a fork (equal seq with
 *     differing hash), HEAD ahead of a verified tail, or any HEAD lag worse than the exact
 *     single-step/hash-matching case => `failed`. A lagging or rebuildable HEAD that IS a
 *     genuine, hash-verified single-step ancestor of the verified chain tail -- or its
 *     torn-final-record counterpart -- is NOT corruption (docs/contracts/chain-validity.md
 *     (C2) SS2 rows 1/3/4/7/9, SS3's two-failure-class split): reported as `reconcilable`,
 *     distinct from both `failed` and `verified`, so a caller (an operator, or this same
 *     round's own divergence test comparing this walk against the append-time check) never
 *     conflates a self-healing pointer lag with genuine corruption. This walk never writes
 *     anything either way -- see the next bullet.
 *   - no clock/randomness in the decision path; timestamps are evidence only, if present.
 *   - Report contract: { status, evidence[], assumptions[], failure_domain? }; pure.
 *   - Round-1 fix-plan commit 6 / docs/contracts/chain-validity.md SS5: this walk (run
 *     by gateway.js#buildHealthStatus roughly every STATUS_WRITE_INTERVAL_MS) reports
 *     EVIDENCE ONLY and never mutates chain.js's own process-local admission latch
 *     (getChainIntegrityFailure) -- only chain.js's own detectors (the O(1) append-time
 *     checkHeadAgainstTailOrRepair, and reconcileHead's full walk at startup) ever latch.
 *     Concretely: a HEAD/tail POINTER divergence this walk finds is redundant with (and
 *     slower than) the append-time check, which already catches it immediately -- and,
 *     since round-2, is guaranteed to receive the identical classification, because both
 *     now delegate to the same chain.validateChain. Mid-chain INTERIOR corruption (a
 *     tampered/gap/broken-link entry where HEAD and the chain's own tail already agree)
 *     IS visible in this walk's own evidence, but nothing consumes that to stop admission
 *     -- an operator reading the written status output has to notice and act (restart,
 *     which re-runs reconcileHead's own full walk and hard-fails startup per Paul's
 *     2026-09-15 decision), or a future, separately-scheduled deep walk would have to be
 *     built to close that gap. This is not an oversight to route around here: mixing a
 *     second, independent classification into the admission-latch path would violate
 *     SS5's "one authoritative structural validator" contract.
 *   - Round-1 fix-plan item 1 (generalized keepalive), round-2 fix pass: a lease loss
 *     DETECTED by this walk's own maybeRenew() call (see below) must not be downgraded to
 *     this module's own ordinary fail-closed "report it, evidence only" contract -- that is
 *     exactly the ban createLeaseGuard's own doc comment (scripts/gateway/gateway.js)
 *     states: a detected lease loss must never be relabeled as "flag for operator review,
 *     continue" handling. `ctx.isLeaseError`, injected by the same caller that injects
 *     `ctx.maybeRenew`, lets that caller's own leaseGuard recognize (by reference identity,
 *     not error.code) that a caught exception IS the one its own maybeRenew() just threw,
 *     and rethrow it so it propagates out of this walk entirely rather than being absorbed
 *     into a status object, mirroring recoverCrashedSessions'/reconcileHead's own
 *     rethrow-not-downgrade handling of the identical error class.
 *   - Honest limit (A6, same as register-retention.js's): a privileged local attacker who
 *     rewrites both the chain and its own HEAD.json is out of scope for THIS verifier alone
 *     -- SG-FR-6 (remote anchoring, not yet implemented -- see scripts/gateway/chain.js's
 *     pushChainTailToRemoteAnchor stub) is the intended mitigation, same class as
 *     register-retention.js's own stated A6 limit.
 * Zero external-package dependencies (Node core plus the sibling scripts/gateway/chain.js
 * for the canonical validator -- see above), Node >= 18. Schema:
 * schemas/gateway-session-entry.schema.json.
 */
"use strict";

const chain = require("../scripts/gateway/chain.js");

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

const HEAD_KEYS = ["schema_version", "seq", "bundle_id", "entry_sha256"];

/** Same strict, fail-closed shape discipline as entryShapeOk (and scripts/gateway/
 * chain.js's own headShapeOk, which this deliberately mirrors -- an intentionally-
 * duplicated, provably-identical copy per C2 SS5, kept here only so this module's own
 * bundle-existence pass below can be self-contained; it plays no part in the
 * hash/link/sequence/HEAD verdict itself, which is entirely chain.validateChain's). */
function headShapeOk(h) {
  if (!h || typeof h !== "object") return false;
  for (const k of HEAD_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(h, k)) return false;
  }
  for (const k of Object.keys(h)) if (HEAD_KEYS.indexOf(k) === -1) return false;
  if (h.schema_version !== "1.0") return false;
  if (typeof h.seq !== "number" || !Number.isInteger(h.seq) || h.seq < 1) return false;
  if (typeof h.bundle_id !== "string" || h.bundle_id.length === 0) return false;
  if (typeof h.entry_sha256 !== "string" || !HEX64.test(h.entry_sha256)) return false;
  return true;
}

/* Which of this module's two failure_domains a chain.validateChain "refuse" class maps
 * to. "trusted-core" (mirrors this module's own pre-existing convention for a HEAD.json
 * problem): the on-disk HEAD pointer itself disagrees with a verified tail in a way that
 * is not the auto-catch-up case -- empty chain naming a HEAD, HEAD claiming a seq past the
 * real tail, or a lag worse than the single exact-hash-verified step. "untrusted-input"
 * (the fail() default, kept explicit here for clarity): a problem in chain.jsonl's own
 * entries -- shape, genesis, sequence, link, hash, or a fork. */
const REFUSE_DOMAIN_BY_CLASS = {
  "empty-chain-with-head": "trusted-core",
  "head-ahead-of-tail": "trusted-core",
  "multi-step-lag": "trusted-core",
  "head-not-ancestor": "trusted-core",
  // Round-3 fix pass (verifier-flagged gap): not currently emitted by
  // chain.validateChain itself (only by checkHeadAgainstTailOrRepair's append-time
  // check and chain.reconcileHead's startup walk, neither of which this status walk
  // calls) -- classified explicitly anyway so this map never silently falls through to
  // the untrusted-input default for either class below if that ever changes.
  // operational/trusted-core: chain.jsonl's tail could not be read at all -- a
  // HEAD/tail-plumbing problem, mirroring this module's own HEAD.json convention, not
  // evidence of tampered chain.jsonl content.
  "tail-unreadable": "trusted-core",
  "invalid-genesis": "untrusted-input",
  "sequence-gap": "untrusted-input",
  "broken-link": "untrusted-input",
  "tampered": "untrusted-input",
  "fork": "untrusted-input",
  "malformed-interior": "untrusted-input",
  // untrusted-input/refuse: a torn physical tail is chain.jsonl CONTENT that only
  // startup reconciliation, under the exclusive writer-claim lease, may repair.
  "torn-tail-requires-manual-truncation": "untrusted-input",
};

/* ctx = {
 *   chain: [gateway-session-entry],   // ordered append-only log, as read from chain.jsonl
 *   head: { schema_version, seq, bundle_id, entry_sha256 } | null,   // HEAD.json's content
 *   computeEntrySha256: (entry) => hex64,   // scripts/gateway/chain.js's function. No
 *                                            // longer used internally (chain.validateChain
 *                                            // uses its own copy) -- still required on ctx
 *                                            // for API back-compat with every existing
 *                                            // caller/test, and as a basic shape guard.
 *   bundleExists?: (bundle_id) => boolean,  // optional: checked against each chain entry
 *                                            // that survived chain.validateChain's own walk
 *                                            // (outside C2's structural scope -- this
 *                                            // module's own addition, same as before).
 *   maybeRenew?: () => void,   // optional, round-1 fix-plan item 1: the caller's own
 *                              // writer-claim keepalive (via gateway.js's createLeaseGuard),
 *                              // passed straight through as chain.validateChain's own
 *                              // onEntry hook (round-3 fix pass) so it fires once per chain
 *                              // entry, genuinely interleaved with chain.validateChain's own
 *                              // per-entry work -- same injection discipline as
 *                              // computeEntrySha256/bundleExists above, never required() here
 *   isLeaseError?: (error) => boolean,   // optional, paired with maybeRenew: lets the
 *                              // catch-all below recognize (by reference identity) that a
 *                              // caught exception IS a detected lease loss and rethrow it
 *                              // rather than report it as an ordinary failed walk
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
    const rawChain = ctx.chain;
    if (!Array.isArray(rawChain)) return fail("chain must be an array");
    if (typeof ctx.computeEntrySha256 !== "function") return fail("ctx.computeEntrySha256 function is required");

    // The one canonical structural validator (C2 SS1/SS5) -- the same function
    // chain.reconcileHead and the append-time check (chain.appendSession /
    // chain.repairMissingChainEntry) already delegate to. `ctx.head` is passed through
    // as-is; chain.validateChain's own documented contract collapses "absent," "not an
    // object," and "fails headShapeOk" to the same `null` case, exactly like its other
    // two callers already do (see chain.js#reconcileHead's own head-read try/catch).
    //
    // Round-1 fix-plan item 1 (lease keepalive, generalized), round-3 fix pass (fixes
    // the defect described in this file's header note above): `ctx.maybeRenew`, when
    // provided, is passed straight through as chain.validateChain's own `onEntry` hook
    // rather than run in a separate, disconnected pre-pass -- so it fires once per
    // entry, genuinely interleaved with chain.validateChain's own hash/link/sequence
    // work as that work actually happens, and a thrown lease-loss error aborts the walk
    // at exactly the entry chain.validateChain had reached, never after the fact.
    const validateOptions = typeof ctx.maybeRenew === "function" ? { onEntry: ctx.maybeRenew } : undefined;
    const result = chain.validateChain(rawChain, ctx.head === undefined ? null : ctx.head, validateOptions);

    if (result.status === "empty") {
      return { status: "not-applicable", evidence, assumptions, reason: "empty gateway-session log -- nothing to verify" };
    }

    if (result.status === "refuse") {
      return fail(result.reason, REFUSE_DOMAIN_BY_CLASS[result.class]);
    }

    // result.status is "valid" or "reconcilable" here: the chain itself hashed, linked,
    // and sequenced correctly end to end (C2 SS1) -- only HEAD's relationship to that
    // verified tail still differs between the two. Bundle-file existence is entirely
    // this module's own addition, outside C2's structural scope (a moved/archived
    // bundle says nothing about the CHAIN's own integrity) -- checked here, against
    // every entry that survived chain.validateChain's own walk. entryShapeOk mirrors
    // validateChain's own torn-tail carve-out (only the physical last element is ever
    // exempt from the shape check), so this reproduces exactly the same "effective
    // chain" validateChain itself just verified, without re-deriving its verdict.
    const survivingEntries = rawChain.filter(entryShapeOk);
    evidence.push(
      `hash chain intact across ${survivingEntries.length} entry(ies); seq contiguous (append-only)` +
        (survivingEntries.length > 0 ? `, starting at ${survivingEntries[0].seq}.` : ".")
    );
    if (typeof ctx.bundleExists === "function") {
      for (const e of survivingEntries) {
        if (!ctx.bundleExists(e.bundle_id)) {
          return fail(`entry (seq=${e.seq}) references bundle_id "${e.bundle_id}" with no corresponding bundle file on disk -- incomplete append or a deleted bundle`, "trusted-core");
        }
      }
    }

    if (result.status === "valid") {
      evidence.push(`HEAD.json matches the chain tail (seq=${result.tail.seq}, bundle_id=${result.tail.bundle_id}).`);
      return { status: "verified", evidence, assumptions };
    }

    // result.status === "reconcilable": a lagging/rebuildable HEAD, or a torn final
    // record, that chain.validateChain itself classifies as NOT corruption (C2 SS2 rows
    // 1/3/4/7/9; SS3's second bullet, "repair and continue, loudly"). Reported as its
    // own distinct status, never folded into `failed` -- this walk still never repairs
    // anything itself (only chain.reconcileHead, under the writer-claim lease, writes
    // HEAD.json); it only makes sure this state is visible, and visibly DIFFERENT from
    // genuine corruption, per C2 SS3's "two failure classes stay distinct everywhere."
    if (result.anomaly) evidence.push(`anomaly: ${result.anomaly}`);

    // Round-3 fix pass (defect 2, docs/contracts/chain-validity.md C2 SS2 row 4): a
    // headAction of "rebuild" means chain.validateChain found HEAD.json absent/unusable
    // with no prior pointer to advance -- row 4 says only STARTUP RECONCILIATION, under
    // the exclusive writer-claim lease (chain.reconcileHead), may treat that as
    // repairable; every other call site, including this lease-less, periodic status
    // walk, must REFUSE it instead. chain.reconcileHead's own use of "rebuild" stays
    // correct and is untouched by this -- the mapping below exists only at THIS call
    // site's own reporting boundary, per C2's explicit per-call-site distinction. The
    // row-7 single-step-lag case (headAction: "advance", a genuine hash-verified
    // ancestor with a real prior pointer to advance) is unaffected and stays
    // "reconcilable" below, exactly as before.
    if (result.headAction === "rebuild") {
      return fail(result.reason, "trusted-core");
    }
    return {
      status: "reconcilable",
      evidence,
      assumptions,
      reason: result.reason,
      headAction: result.headAction,
      truncatedTail: Boolean(result.truncatedTail),
    };
  } catch (e) {
    /* Round-1 fix-plan item 1 (generalized keepalive), round-2 fix pass: a lease loss
     * DETECTED by this walk's own maybeRenew() call above must not be downgraded to this
     * function's own ordinary fail-closed "report it, evidence only" contract -- that is
     * exactly the ban createLeaseGuard's own doc comment (scripts/gateway/gateway.js)
     * states: a detected lease loss must never be relabeled as "flag for operator
     * review, continue" handling. `ctx.isLeaseError`, injected by the same caller that
     * injects `ctx.maybeRenew`, lets that caller's own leaseGuard recognize (by
     * reference identity, not error.code -- see createLeaseGuard's own doc comment for
     * why) that THIS exception is the one its own maybeRenew() just threw, and rethrow
     * it here so it propagates out of this walk entirely rather than being absorbed into
     * a status object, exactly mirroring recoverCrashedSessions'/reconcileHead's own
     * rethrow-not-downgrade handling of the identical error class. Optional, like
     * `ctx.maybeRenew` itself: a caller with no writer-claim in play never sets it, and
     * every exception (this walk's own, or any other injected function's) keeps falling
     * through to the ordinary fail-closed report below, unchanged. */
    if (typeof ctx.isLeaseError === "function" && ctx.isLeaseError(e)) throw e;
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

module.exports = { ...check, walkGatewaySessions, entryShapeOk, headShapeOk };

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
    const chainEntries = [e1, e2, e3];
    const head = { schema_version: "1.0", seq: 3, bundle_id: e3.bundle_id, entry_sha256: e3.entry_sha256 };

    const good = check.run({ chain: chainEntries, head, computeEntrySha256 });
    // tamper the middle entry's own hash (does not recompute).
    const tampered = [e1, { ...e2, entry_sha256: h(9) }, e3];
    const brokenSelf = check.run({ chain: tampered, head, computeEntrySha256 });
    // delete the middle entry -> sequence gap, distinct failure text from brokenSelf.
    const gapChain = [e1, e3];
    const gap = check.run({ chain: gapChain, head: { ...head, seq: 3 }, computeEntrySha256 });
    // HEAD.json missing entirely, but the chain itself is fully valid -- C2 row 3/4:
    // chain.validateChain itself classifies this as headAction "rebuild", but this
    // call site's own round-3 defect-2 fix (see above) maps that to `failed`: only
    // startup reconciliation under the exclusive writer-claim lease may treat an absent
    // HEAD as repairable, never this lease-less status walk.
    const noHead = check.run({ chain: chainEntries, head: null, computeEntrySha256 });
    // HEAD.json stale by exactly one hash-verified step (crash before the HEAD update)
    // -- C2 row 7: reconcilable (auto-advance), not corruption.
    const staleHead = check.run({ chain: chainEntries, head: { schema_version: "1.0", seq: 2, bundle_id: e2.bundle_id, entry_sha256: e2.entry_sha256 }, computeEntrySha256 });
    // bundle file missing for a chained entry.
    const missingBundle = check.run({ chain: chainEntries, head, computeEntrySha256, bundleExists: (id) => id !== e2.bundle_id });

    const pass =
      good.status === "verified" &&
      brokenSelf.status === "failed" && /TAMPERED/.test(brokenSelf.evidence.join(" ")) &&
      gap.status === "failed" && /SEQUENCE GAP/.test(gap.evidence.join(" ")) &&
      noHead.status === "failed" && /HEAD\.json is absent/.test(noHead.evidence.join(" ")) &&
      staleHead.status === "reconcilable" &&
      missingBundle.status === "failed" && /no corresponding bundle file/.test(missingBundle.evidence.join(" "));

    console.log(
      "register-gateway-sessions selftest:", pass ? "OK" : "FAIL",
      "| chain=" + (good.status === "verified"),
      "tampered-detected=" + (brokenSelf.status === "failed"),
      "gap-detected=" + (gap.status === "failed"),
      "no-head-detected=" + (noHead.status === "failed"),
      "stale-head-reconcilable=" + (staleHead.status === "reconcilable"),
      "missing-bundle-detected=" + (missingBundle.status === "failed")
    );
    process.exit(pass ? 0 : 1);
  } else {
    console.error("Usage: node checks/register-gateway-sessions.js --selftest");
    process.exit(1);
  }
}
