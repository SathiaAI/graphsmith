#!/usr/bin/env node
"use strict";

/* writer-claim.js coverage-gap triage suite.
 *
 * Origin: Decision G Option 2 (2026-08-27) systematic triage of scripts/writer-claim.js's
 * survived mutants from its first mutation baseline (2026-08-26, 60.33%: 292 killed / 0
 * timeout / 192 survived / 484 total), re-measured fresh on 2026-08-29 as 289/0/195/484
 * (the +3 survived / -3 killed delta vs the original baseline is the disclosed,
 * expected win32-only fallout of commit 821a071's platform skip on 4
 * cr-renew-toctou-* checks in tests/state-store/writer-claim/run-tests.js -- NOT
 * something this suite tries to re-cover; see that commit and this repo's Decision G
 * Option 2 task spec for why).
 *
 * Method: same as gate.js's round 6 and promote.js's round 7 -- for every function with
 * survived mutants, enumerate every distinct branch/error-code/boundary it has, grep the
 * existing suites (tests/state-store/writer-claim/run-tests.js,
 * tests/state-store/writer-claim-shared-storage/run-tests.js) to confirm whether that
 * SPECIFIC scenario is exercised, and write a new test here for any confirmed real gap.
 * A survivor determined genuinely equivalent (no observable behavioral difference) or
 * purely cosmetic (message-text-only, in an already-behaviorally-covered branch) is
 * documented below and NOT forced with a test.
 *
 * Explicitly deprioritized, not chased in this round (documented, not silently dropped):
 *   - selftest()'s own internals (~36 survivors, lines ~595-631): test/self-check
 *     infrastructure invoked only via `--selftest`, not product logic -- same
 *     reasoning promote.js's round-7 triage applied to its own selftest cluster.
 *     selftest() already has dedicated coverage confirming it runs successfully and is
 *     audited (clockEnforcement_selftestAuditBreadcrumb in the main suite).
 *   - Most of the CLI dispatch block's exact usage/error message text (lines ~633-648):
 *     covered behaviorally below (cliStatusCommandProducesValidStatusJson,
 *     cliUnknownCommandPrintsUsageAndExits2), but the individual StringLiteral mutants
 *     for console.error's literal text are message copy, not decision logic.
 *   - stopHeartbeat()'s `if (this._timer)` guard (line 512): calling
 *     clearInterval(null) is a documented no-op in Node.js, so guarded vs unguarded
 *     stopHeartbeat() on a never-started instance is genuinely behaviorally
 *     indistinguishable -- equivalent mutant, not chased.
 *   - fail()'s default `code = "WRITER_CLAIM_ERROR"` parameter (line 72): grepped every
 *     call site in scripts/writer-claim.js -- every single one passes an explicit code
 *     argument, so this default is dead code, unreachable from this file's own call
 *     sites, not merely untested.
 *   - _unlinkIfToken's dev-mismatch-in-isolation mutant (`onPath.dev !== heldInode.dev`
 *     alone forced to `false`, line 334 start col 11-39): on one local filesystem/tmp
 *     dir, `dev` is identical for every file, so a scenario where the OR's left operand
 *     alone determines the result (dev differs, ino same) is not portably constructible
 *     -- same class of gap as promote.js round 7's noted-not-chased EXDEV
 *     cross-device-rename branch.
 *   - startHeartbeat's `typeof this._timer.unref === "function"` guard (line 507):
 *     real Node.js setInterval() return values always carry `.unref`, so exercising the
 *     false branch needs replacing global setInterval with a non-standard timer object,
 *     which would also break the heartbeat behavior the rest of this suite needs to
 *     observe -- a defensive guard for a non-Node runtime, not reachable product logic.
 *   - readClaimFile's JSON.parse-failure catch block emptied (`catch (error) {}`, line
 *     124): with the catch a no-op, `record` stays `undefined` and the *next* line
 *     (`stateStore.validateNamedRecord(undefined, ...)`) throws its own error, caught by
 *     the OUTER catch at line 126, converting it to the identical CORRUPT_CLAIM outcome
 *     -- both code paths converge on the same observable {code: "CORRUPT_CLAIM"} either
 *     way, verified by reading the two catch blocks together, not merely assumed.
 *
 * Zero-dep CJS, same check()/record()/SUMMARY house style as
 * tests/state-store/writer-claim/run-tests.js and tests/state-store/atomic-primitives/
 * run-tests.js. EXIT 1 if any FAIL.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../../../..");
const WRITER_CLAIM_SCRIPT = path.join(ROOT, "scripts", "writer-claim.js");
const {
  WriterClaim, decideOnExisting, claimPath, readStatus,
  DEFAULT_HEARTBEAT_MS, DEFAULT_MISSED_HEARTBEATS_STALE, CLAIM_CLOCK_SKEW_TOLERANCE_MS,
} = require(WRITER_CLAIM_SCRIPT);
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));
const { createManualClock } = require("../../../_harness/clock.js");

const HEARTBEAT_MS = 1000;
const STALE_AFTER_MS = HEARTBEAT_MS * 3;
const DEAD_PID = 999999; // above default pid_max everywhere in the CI matrix; matches sibling suites

let failures = 0;
const results = [];

function record(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-writer-claim-triage-${prefix}-`));
}

function newClaim(root, overrides = {}) {
  return new WriterClaim(root, {
    hostId: "host-local",
    instanceId: overrides.instanceId,
    clock: overrides.clock,
    heartbeatMs: HEARTBEAT_MS,
    staleAfterMs: STALE_AFTER_MS,
    ...overrides,
  });
}

function withPatchedReadFileSync(onFdRead, fn) {
  const real = fs.readFileSync;
  let fired = false;
  fs.readFileSync = function (...args) {
    if (!fired && typeof args[0] === "number") {
      fired = true;
      fs.readFileSync = real;
      return onFdRead(args, real);
    }
    return real.apply(fs, args);
  };
  try { return fn(); } finally { fs.readFileSync = real; }
}

/* =========================================================================
 * decideOnExisting: boundary conditions and a real branch gap. Two of the
 * mutation-testing survivors here (170:18 age<=0, 180:7 the
 * !ownerAlive && !unrenewed refuse branch) turn out to be the SAME confirmed
 * gap in disguise: a dead owner whose claim has NOT yet passed staleAfterMs
 * must still refuse (grace period), not be immediately stealable just
 * because the pid check reads dead. decideOnExistingDeadOwnerWithinGraceStillRefuses
 * below pins that directly.
 * ========================================================================= */

function decideOnExistingFutureBoundaryIsExclusive() {
  // age === 0 exactly (renewed_at === now) must NOT be treated as "future" --
  // `future = age < 0`, so age===0 takes the ordinary unrenewed/ownerAlive path,
  // not the future-owner-death fast path. Distinguishing case: a DEAD owner at
  // age===0 (fresh, not stale) must still REFUSE (grace period), not steal --
  // the `age<=0` boundary mutant would misclassify this as "future" and, combined
  // with a dead owner, incorrectly fast-path to "steal".
  const now = 1_700_000_300_000;
  const ctx = {
    localHostId: "host-local", localInstanceId: "attacker".padEnd(32, "0"),
    now, staleAfterMs: STALE_AFTER_MS, skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
  };
  const rec = {
    schema_version: "1.0", host_id: "host-local", instance_id: "owner".padEnd(32, "1"),
    pid: DEAD_PID, claimed_at: now - 10_000, renewed_at: now, claim_token: "c".repeat(32),
  };
  const decision = decideOnExisting(rec, ctx);
  check("decide-future-boundary-age-zero-dead-owner-refuses-not-steals",
    decision.outcome === "refuse" && decision.code === "WRITER_CLAIM_HELD",
    `age===0 (exactly "now") with a dead owner must still be within grace and refuse, got ${JSON.stringify(decision)}`);
}

function decideOnExistingClockSkewBoundaryIsExclusive() {
  // age === -skewToleranceMs exactly must NOT be reported as clock skew --
  // `age < -ctx.skewToleranceMs` is a strict inequality, so sitting exactly at the
  // tolerance edge is still "inside tolerance", an ordinary refusal.
  const now = 1_700_000_300_000;
  const ctx = {
    localHostId: "host-local", localInstanceId: "attacker".padEnd(32, "0"),
    now, staleAfterMs: STALE_AFTER_MS, skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
  };
  const rec = {
    schema_version: "1.0", host_id: "host-local", instance_id: "owner".padEnd(32, "1"),
    pid: process.pid, claimed_at: now - 10_000, renewed_at: now + CLAIM_CLOCK_SKEW_TOLERANCE_MS,
    claim_token: "c".repeat(32),
  };
  const decision = decideOnExisting(rec, ctx);
  check("decide-clock-skew-boundary-exactly-at-tolerance-is-not-skew",
    decision.outcome === "refuse" && decision.code === "WRITER_CLAIM_HELD",
    `renewed_at exactly skewToleranceMs ahead must be an ordinary refusal, not WRITER_CLAIM_CLOCK_SKEW, got ${JSON.stringify(decision)}`);
}

function decideOnExistingStaleBoundaryIsExclusive() {
  // age === staleAfterMs exactly must NOT yet be "unrenewed" -- `age > ctx.staleAfterMs`
  // is a strict inequality, so a claim renewed EXACTLY staleAfterMs ago is still live.
  const now = 1_700_000_300_000;
  const ctx = {
    localHostId: "host-local", localInstanceId: "attacker".padEnd(32, "0"),
    now, staleAfterMs: STALE_AFTER_MS, skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
  };
  const rec = {
    schema_version: "1.0", host_id: "host-local", instance_id: "owner".padEnd(32, "1"),
    pid: process.pid, claimed_at: now - 20_000, renewed_at: now - STALE_AFTER_MS,
    claim_token: "c".repeat(32),
  };
  const decision = decideOnExisting(rec, ctx);
  check("decide-stale-boundary-exactly-staleAfterMs-still-live",
    decision.outcome === "refuse" && decision.code === "WRITER_CLAIM_HELD",
    `age exactly staleAfterMs must not yet be stealable, got ${JSON.stringify(decision)}`);
}

function decideOnExistingDeadOwnerWithinGraceStillRefuses() {
  // A non-boundary case of the same gap as decideOnExistingFutureBoundaryIsExclusive:
  // a dead owner whose claim is comfortably within staleAfterMs (not a boundary value)
  // must still refuse, proving the `!ownerAlive` half of the grace-period check is
  // load-bearing and not redundant with the `ownerAlive` half.
  const now = 1_700_000_300_000;
  const ctx = {
    localHostId: "host-local", localInstanceId: "attacker".padEnd(32, "0"),
    now, staleAfterMs: STALE_AFTER_MS, skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
  };
  const rec = {
    schema_version: "1.0", host_id: "host-local", instance_id: "owner".padEnd(32, "1"),
    pid: DEAD_PID, claimed_at: now - 20_000, renewed_at: now - Math.floor(STALE_AFTER_MS / 2),
    claim_token: "c".repeat(32),
  };
  const decision = decideOnExisting(rec, ctx);
  check("decide-dead-owner-well-within-grace-still-refuses",
    decision.outcome === "refuse" && decision.code === "WRITER_CLAIM_HELD",
    `a dead owner whose claim is well within staleAfterMs must still refuse (grace period), got ${JSON.stringify(decision)}`);
}

/* =========================================================================
 * refusalMessage: two real, confirmed gaps.
 *   (1) The CLOCK_SKEW branch's message text is never generated end-to-end by
 *       ANY existing test -- ac3_clockSkewDecisionTable in the main suite pins
 *       decideOnExisting()'s CODE directly but never drives an actual
 *       WriterClaim.acquire() call through refusalMessage's CLOCK_SKEW branch.
 *   (2) Nothing distinguishes the default WRITER_CLAIM_HELD message from the
 *       FOREIGN_HOST message by content -- both happen to include the
 *       instance_id and "single-writer" substrings the existing ac1 test
 *       checks, so a mutant that always takes the FOREIGN_HOST branch survives
 *       that test unnoticed.
 * ========================================================================= */

function refusalMessageClockSkewEndToEnd() {
  const root = freshRoot("refusal-clock-skew");
  // The OWNER's clock is advanced well ahead before it acquires/writes renewed_at, so
  // the record's renewed_at sits far in the future relative to a challenger reading
  // the UNADVANCED baseline instant -- but the owner's pid (this test process) is
  // alive, so the "future && !ownerAlive" steal shortcut must not fire first.
  const ownerClock = createManualClock();
  ownerClock.advance(CLAIM_CLOCK_SKEW_TOLERANCE_MS * 10);
  const owner = newClaim(root, { instanceId: "a".repeat(32), clock: ownerClock });
  owner.acquire();

  const challengerClock = createManualClock();   // same fixed baseline epoch, never advanced
  const challenger = newClaim(root, { instanceId: "b".repeat(32), clock: challengerClock });
  let thrown = null;
  try { challenger.acquire(); } catch (error) { thrown = error; }

  check("refusal-clock-skew-e2e-throws", Boolean(thrown), "expected acquire() to throw under injected clock skew");
  check("refusal-clock-skew-e2e-specific-code",
    Boolean(thrown) && thrown.code === "WRITER_CLAIM_CLOCK_SKEW",
    `expected WRITER_CLAIM_CLOCK_SKEW, got ${thrown && thrown.code}`);
  const msg = thrown ? thrown.message : "";
  check("refusal-clock-skew-e2e-names-clock-skew", /CLOCK SKEW/.test(msg), "message must name this as a CLOCK SKEW, not a busy writer");
  check("refusal-clock-skew-e2e-names-future", /FUTURE/.test(msg), "message must call out that renewed_at is in the FUTURE");
  check("refusal-clock-skew-e2e-mentions-backward-time-correction", /backward time correction/.test(msg), "message must suggest a backward time correction as a cause");
  check("refusal-clock-skew-e2e-names-instance-and-host",
    msg.includes("a".repeat(32)) && msg.includes("host-local"), "message must name the conflicting instance_id and host");
  check("refusal-clock-skew-e2e-names-pid", msg.includes(`pid ${process.pid}`), "message must name the still-alive owner pid");
}

function refusalMessageHeldNotConfusedWithForeignHost() {
  const root = freshRoot("refusal-held-not-foreign");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "a".repeat(32), clock });
  owner.acquire();
  const second = newClaim(root, { instanceId: "b".repeat(32), clock });
  let thrown = null;
  try { second.acquire(); } catch (error) { thrown = error; }

  check("refusal-held-not-foreign-throws-held", Boolean(thrown) && thrown.code === "WRITER_CLAIM_HELD",
    `expected WRITER_CLAIM_HELD, got ${thrown && thrown.code}`);
  const msg = thrown ? thrown.message : "";
  check("refusal-held-does-not-say-different-host", !/DIFFERENT host/.test(msg),
    "a same-host HELD refusal must never use the FOREIGN_HOST message's DIFFERENT-host wording");
  check("refusal-held-says-not-generic-lock-contention", /NOT a generic lock-contention error/.test(msg),
    "the HELD message's own distinguishing text must actually be present");
}

/* =========================================================================
 * WriterClaim constructor: input-validation branches that no existing test
 * ever exercises (every existing construction passes a well-formed stateDir
 * and instanceId), plus the DEFAULT (production, no-explicit-clock) code path,
 * which -- perhaps counter-intuitively -- was NEVER constructed by any test
 * anywhere in either sibling suite (every test passes an explicit clock for
 * determinism). That silence is exactly why the whole
 * `GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK==="1"` sub-expression could be
 * forced to `true` in isolation and nothing noticed: no test ever took the
 * "no explicit clock, flag not set" path this mutant would have broken.
 * ========================================================================= */

function ctorRejectsEmptyStateDir() {
  let thrown = null;
  try { new WriterClaim("", { instanceId: "a".repeat(32), clock: createManualClock() }); }
  catch (error) { thrown = error; }
  check("ctor-rejects-empty-stateDir",
    Boolean(thrown) && thrown.code === "INVALID_ARGUMENT" && /non-empty string/.test(thrown.message),
    `expected INVALID_ARGUMENT for an empty stateDir, got ${thrown && thrown.code}`);
}

function ctorRejectsNonStringStateDir() {
  let thrown = null;
  try { new WriterClaim(42, { instanceId: "b".repeat(32), clock: createManualClock() }); }
  catch (error) { thrown = error; }
  check("ctor-rejects-non-string-stateDir",
    Boolean(thrown) && thrown.code === "INVALID_ARGUMENT",
    `expected INVALID_ARGUMENT for a non-string stateDir, got ${thrown && thrown.code}`);
}

function ctorEmptyHostIdOptionFallsBackToDefault() {
  // hostId: "" is a well-formed string but zero-length -- must fall through to
  // defaultHostId(), not be used verbatim as an empty hostId.
  const w = new WriterClaim(freshRoot("ctor-empty-hostid"), { hostId: "", instanceId: "c".repeat(32), clock: createManualClock() });
  check("ctor-empty-hostid-option-falls-back",
    typeof w.hostId === "string" && w.hostId.length > 0 && w.hostId === os.hostname(),
    `expected hostId:"" to fall back to os.hostname(), got ${JSON.stringify(w.hostId)}`);
}

function ctorDefaultHostIdRejectsNonStringHostname() {
  // The other half of defaultHostId()'s guard: os.hostname() returning a non-string
  // (not just an empty string) must also fail closed.
  const realHostname = os.hostname;
  os.hostname = () => null;
  let thrown = null;
  try { new WriterClaim(freshRoot("ctor-hostname-nonstring"), { instanceId: "d".repeat(32), clock: createManualClock() }); }
  catch (error) { thrown = error; }
  finally { os.hostname = realHostname; }
  check("ctor-default-hostid-rejects-non-string-hostname",
    Boolean(thrown) && thrown.code === "WRITER_CLAIM_NO_HOST_ID",
    `expected WRITER_CLAIM_NO_HOST_ID for a non-string os.hostname(), got ${thrown && thrown.code}`);
}

function ctorInstanceIdRegexRejectsLeadingGarbage() {
  let thrown = null;
  try { new WriterClaim(freshRoot("ctor-instanceid-leading"), { instanceId: "z" + "a".repeat(32), clock: createManualClock() }); }
  catch (error) { thrown = error; }
  check("ctor-instanceid-rejects-leading-garbage-before-valid-hex",
    Boolean(thrown) && thrown.code === "INVALID_ARGUMENT",
    `a 33-char instanceId with a valid 32-hex SUFFIX must still be rejected (no ^ escape), got ${thrown && thrown.code}`);
}

function ctorInstanceIdRegexRejectsTrailingGarbage() {
  let thrown = null;
  try { new WriterClaim(freshRoot("ctor-instanceid-trailing"), { instanceId: "a".repeat(32) + "z", clock: createManualClock() }); }
  catch (error) { thrown = error; }
  check("ctor-instanceid-rejects-trailing-garbage-after-valid-hex",
    Boolean(thrown) && thrown.code === "INVALID_ARGUMENT",
    `a 33-char instanceId with a valid 32-hex PREFIX must still be rejected (no $ escape), got ${thrown && thrown.code}`);
}

function ctorNoExplicitClockNoFlagUsesRealWallClock() {
  // The actual PRODUCTION default: no { clock } option, and
  // GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK unset. Must succeed and fall back to a
  // real wall clock (Date.now()), never throw LEASE_CLOCK_REQUIRED -- that flag only
  // fires when explicitly set to "1". Suppress the lease-clock audit env var for this
  // one deliberate wall-clock construction, same isolation the main suite's own
  // clockEnforcement_requireExplicitFlag uses for its probes.
  const FLAG = "GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK";
  const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";
  const prevFlag = process.env[FLAG];
  const prevAudit = process.env[AUDIT_ENV];
  let w = null;
  let thrown = null;
  try {
    delete process.env[FLAG];
    delete process.env[AUDIT_ENV];
    w = new WriterClaim(freshRoot("ctor-no-clock-no-flag"), { instanceId: "e".repeat(32) });
  } catch (error) { thrown = error; }
  finally {
    if (prevFlag === undefined) delete process.env[FLAG]; else process.env[FLAG] = prevFlag;
    if (prevAudit === undefined) delete process.env[AUDIT_ENV]; else process.env[AUDIT_ENV] = prevAudit;
  }
  check("ctor-no-explicit-clock-no-flag-does-not-throw", thrown === null,
    `constructing without an explicit clock and without the flag must succeed, got ${thrown && thrown.code}`);
  const before = Date.now();
  const sample = w ? w.clock.now() : null;
  const after = Date.now();
  check("ctor-no-explicit-clock-no-flag-uses-real-wall-clock",
    typeof sample === "number" && sample >= before - 1000 && sample <= after + 1000,
    `expected the fallback clock to read a real wall-clock instant near Date.now(), got ${sample}`);
}

function ctorStaleAfterMsDefaultIsHeartbeatTimesMissedHeartbeats() {
  // No test anywhere passes staleAfterMs omitted while ALSO passing a non-default
  // heartbeatMs -- every sibling-suite helper always supplies both explicitly. This
  // is the only place the DEFAULT_MISSED_HEARTBEATS_STALE multiplication is checked
  // for its actual arithmetic (vs. a division, which would produce a wildly
  // different, wrong number).
  const w = new WriterClaim(freshRoot("ctor-staleAfterMs-default"), {
    instanceId: "f".repeat(32), clock: createManualClock(), heartbeatMs: 4000,
  });
  check("ctor-staleAfterMs-default-is-heartbeat-times-missed",
    w.staleAfterMs === 4000 * DEFAULT_MISSED_HEARTBEATS_STALE,
    `expected staleAfterMs===${4000 * DEFAULT_MISSED_HEARTBEATS_STALE}, got ${w.staleAfterMs}`);
}

function ctorHeartbeatMsZeroFallsBackToDefault() {
  // positiveInteger()'s `parsed > 0` boundary: an explicit 0 (or negative) must be
  // rejected as invalid input and fall back to the default, not be accepted as a
  // valid (degenerate) heartbeat interval.
  const w = new WriterClaim(freshRoot("ctor-heartbeat-zero"), { instanceId: "0".repeat(32), clock: createManualClock(), heartbeatMs: 0 });
  check("ctor-heartbeatMs-zero-falls-back-to-default",
    w.heartbeatMs === DEFAULT_HEARTBEAT_MS,
    `heartbeatMs:0 must fall back to DEFAULT_HEARTBEAT_MS (${DEFAULT_HEARTBEAT_MS}), got ${w.heartbeatMs}`);

  const wNeg = new WriterClaim(freshRoot("ctor-heartbeat-negative"), { instanceId: "1".repeat(32), clock: createManualClock(), heartbeatMs: -50 });
  check("ctor-heartbeatMs-negative-falls-back-to-default",
    wNeg.heartbeatMs === DEFAULT_HEARTBEAT_MS,
    `heartbeatMs:-50 must fall back to DEFAULT_HEARTBEAT_MS, got ${wNeg.heartbeatMs}`);
}

function ctorOnClaimLostNonFunctionFallsBackToNull() {
  const w = new WriterClaim(freshRoot("ctor-onclaimlost-nonfn"), {
    instanceId: "2".repeat(32), clock: createManualClock(), onClaimLost: "not-a-function",
  });
  check("ctor-onClaimLost-non-function-falls-back-to-null",
    w.onClaimLost === null,
    `a non-function onClaimLost must be stored as null, got ${JSON.stringify(w.onClaimLost)}`);
}

function ctorClockNowExactlyZeroIsValid() {
  // _now()'s `t < 0` boundary: epoch-zero is a valid (if unusual) instant, must not
  // be rejected the way negative/fractional/NaN/string instants correctly are.
  const zeroClock = { now: () => 0 };
  const w = newClaim(freshRoot("ctor-clock-zero"), { instanceId: "3".repeat(32), clock: zeroClock });
  let thrown = null;
  try { w.acquire(); } catch (error) { thrown = error; }
  check("clock-now-exactly-zero-is-a-valid-instant", thrown === null,
    `a clock reading exactly 0 must be accepted as a valid epoch-ms instant, got ${thrown && thrown.code}`);
}

/* =========================================================================
 * acquire(): the bounded-contention retry loop, non-EEXIST propagation, the
 * observed-vanished retry, the "own" idempotent-adoption path (must reuse the
 * existing token, not destructively steal+recreate its own claim), and the
 * steal path's own error-propagation guard.
 * ========================================================================= */

function acquireBoundedContentionThrowsAfterAttempts() {
  const root = freshRoot("acquire-contention");
  fs.mkdirSync(root, { recursive: true });
  // A claim that will NEVER read as ownable/stealable-and-gone: plant a record with a
  // DIFFERENT host_id so decideOnExisting always refuses outright -- but force
  // atomicCreateExclusive to keep throwing EEXIST regardless, so acquire() never even
  // reaches the refuse branch's throw and instead just keeps retrying until it gives up.
  const record_ = {
    schema_version: "1.0", host_id: "host-local", instance_id: "9".repeat(32),
    pid: DEAD_PID, claimed_at: 1, renewed_at: 1, claim_token: "d".repeat(32),
  };
  fs.writeFileSync(claimPath(root), JSON.stringify(record_));
  const realAtomicCreate = stateStore.atomicCreateExclusive;
  stateStore.atomicCreateExclusive = () => { const e = new Error("simulated permanent contention"); e.code = "EEXIST"; throw e; };
  const clock = createManualClock();
  const claimant = newClaim(root, { instanceId: "8".repeat(32), clock });
  let thrown = null;
  try { claimant.acquire(); } catch (error) { thrown = error; }
  finally { stateStore.atomicCreateExclusive = realAtomicCreate; }
  check("acquire-bounded-contention-throws-writer-claim-contention",
    Boolean(thrown) && thrown.code === "WRITER_CLAIM_CONTENTION",
    `expected WRITER_CLAIM_CONTENTION after exhausting the bounded retry loop, got ${thrown && thrown.code}`);
  check("acquire-bounded-contention-message-names-bounded-contention",
    Boolean(thrown) && /bounded contention/.test(thrown.message),
    "the exhausted-retry message must say so");
}

function acquireNonEexistErrorPropagatesUnchanged() {
  const root = freshRoot("acquire-non-eexist");
  const realAtomicCreate = stateStore.atomicCreateExclusive;
  stateStore.atomicCreateExclusive = () => { const e = new Error("simulated disk full"); e.code = "ENOSPC"; throw e; };
  const clock = createManualClock();
  const claimant = newClaim(root, { instanceId: "7".repeat(32), clock });
  let thrown = null;
  try { claimant.acquire(); } catch (error) { thrown = error; }
  finally { stateStore.atomicCreateExclusive = realAtomicCreate; }
  check("acquire-non-eexist-error-propagates-unchanged",
    Boolean(thrown) && thrown.code === "ENOSPC",
    `a non-EEXIST error from atomicCreateExclusive must propagate unchanged, got ${thrown && thrown.code}`);
}

function acquireObservedVanishedBetweenEexistAndReadRetries() {
  const root = freshRoot("acquire-vanished");
  fs.mkdirSync(root, { recursive: true });
  const realAtomicCreate = stateStore.atomicCreateExclusive;
  let calls = 0;
  stateStore.atomicCreateExclusive = (targetPath, content) => {
    calls++;
    if (calls === 1) { const e = new Error("simulated race: claim existed a moment ago"); e.code = "EEXIST"; throw e; }
    return realAtomicCreate(targetPath, content);
  };
  const clock = createManualClock();
  const claimant = newClaim(root, { instanceId: "6".repeat(32), clock });
  let thrown = null;
  try { claimant.acquire(); } catch (error) { thrown = error; }
  finally { stateStore.atomicCreateExclusive = realAtomicCreate; }
  check("acquire-observed-vanished-retries-instead-of-crashing", thrown === null,
    `a claim that vanished between EEXIST and the retry-read must be retried cleanly (no claim file existed on disk), got ${thrown && (thrown.message || thrown.code)}`);
  check("acquire-observed-vanished-eventually-succeeds",
    claimant.status().held_by_this_instance === true,
    "the retry after a vanished observation must go on to acquire normally");
}

function acquireOwnPathReusesExistingTokenNotDestructiveRecreate() {
  // The "own" outcome (matching instance_id, same/dead pid) must ADOPT the existing
  // on-disk claim_token, not silently steal-and-recreate a new one. A forced-false
  // mutant on the "own" branch still ends up NOT throwing (falls through to the steal
  // path, which also succeeds) -- the only way to see the difference is to check that
  // the claim_token on disk is UNCHANGED after the second acquire().
  const root = freshRoot("acquire-own-token-reuse");
  const clock = createManualClock();
  const first = newClaim(root, { instanceId: "a".repeat(32), clock });
  first.acquire();
  const tokenBefore = JSON.parse(fs.readFileSync(claimPath(root), "utf8")).claim_token;

  const rejoin = newClaim(root, { instanceId: "a".repeat(32), clock });
  let thrown = null;
  try { rejoin.acquire(); } catch (error) { thrown = error; }
  const tokenAfter = JSON.parse(fs.readFileSync(claimPath(root), "utf8")).claim_token;

  check("acquire-own-does-not-throw", thrown === null, `re-acquiring one's own claim must not throw, got ${thrown && thrown.message}`);
  check("acquire-own-reuses-existing-token-not-destructive-recreate",
    tokenAfter === tokenBefore,
    `the "own" outcome must ADOPT the existing claim_token, not steal+recreate a new one; before=${tokenBefore} after=${tokenAfter}`);
  check("acquire-own-in-memory-token-matches-disk",
    rejoin._claimToken === tokenBefore,
    `the rejoining instance's own in-memory token must match what is actually on disk, got ${rejoin._claimToken}`);
}

function acquireStealPathPropagatesNonEnoentUnlinkError() {
  const root = freshRoot("acquire-steal-unlink-error");
  fs.mkdirSync(root, { recursive: true });
  const clock = createManualClock();
  const staleRecord = {
    schema_version: "1.0", host_id: "host-local", instance_id: "9".repeat(32),
    pid: DEAD_PID, claimed_at: clock.now() - 100_000, renewed_at: clock.now() - 100_000,
    claim_token: "d".repeat(32),
  };
  fs.writeFileSync(claimPath(root), JSON.stringify(staleRecord));

  const claimant = newClaim(root, { instanceId: "8".repeat(32), clock, staleAfterMs: 1000 });
  let thrown = null;
  withPatchedReadFileSync(
    () => "{ this is not valid json for the steal-path unlink read",
    () => { try { claimant.acquire(); } catch (error) { thrown = error; } },
  );
  check("acquire-steal-unlink-nonenoent-error-propagates",
    Boolean(thrown) && thrown.code !== "WRITER_CLAIM_CONTENTION" && thrown.code !== "WRITER_CLAIM_HELD",
    `a genuine parse failure encountered mid-steal must propagate, not be swallowed into a generic contention/held error; got ${thrown && (thrown.code || thrown.name)}`);
  check("acquire-steal-unlink-nonenoent-error-is-the-real-parse-failure",
    Boolean(thrown) && (thrown.name === "SyntaxError" || /JSON/i.test(thrown.message || "")),
    `expected the underlying JSON parse failure to surface, got ${thrown && thrown.message}`);
}

/* =========================================================================
 * _unlinkIfToken: the token-mismatch guard tested with a SAME-inode, in-place
 * overwrite (distinct from the existing TOCTOU tests, which only ever exercise
 * the inode-swap path where `current` still reflects the ORIGINAL owner's own
 * data -- the plain same-path token mismatch was never exercised at all), plus
 * the openSync ENOENT-vs-other-error split.
 * ========================================================================= */

function unlinkIfTokenSameInodeDifferentTokenRefusesToDelete() {
  const root = freshRoot("unlink-same-inode-token-mismatch");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "a".repeat(32), clock });
  owner.acquire();
  const originalToken = owner._claimToken;

  // Overwrite the SAME file, in place, with a different valid record bearing a
  // DIFFERENT token -- no unlink/recreate, so this is the same path AND (typically)
  // the same inode, isolating the token check from the inode check.
  const swapped = {
    schema_version: "1.0", host_id: "host-local", instance_id: "b".repeat(32),
    pid: process.pid, claimed_at: clock.now(), renewed_at: clock.now(), claim_token: "f".repeat(32),
  };
  fs.writeFileSync(owner.path, JSON.stringify(swapped));

  let released = null;
  let threw = null;
  try { released = owner.release(); } catch (error) { threw = error; }

  check("unlink-same-inode-release-does-not-throw", threw === null, `release() should complete cleanly, got ${threw && threw.message}`);
  check("unlink-same-inode-release-reports-false", released === false,
    `release() must refuse to delete a file whose token no longer matches, even at the SAME path/inode; got ${released}`);
  const onDisk = JSON.parse(fs.readFileSync(owner.path, "utf8"));
  check("unlink-same-inode-swapped-content-survives",
    onDisk.claim_token === swapped.claim_token,
    `the swapped-in record must survive untouched; got token ${onDisk.claim_token}, expected ${swapped.claim_token}`);
  check("unlink-same-inode-original-token-was-actually-different",
    originalToken !== swapped.claim_token, "test setup sanity: the tokens must genuinely differ");
}

function unlinkIfTokenOpenSyncNonEnoentErrorPropagates() {
  const root = freshRoot("unlink-opensync-nonenoent");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "c".repeat(32), clock });
  owner.acquire();

  const realOpenSync = fs.openSync;
  fs.openSync = (targetPath, ...rest) => {
    if (targetPath === owner.path) { const e = new Error("simulated permission denied"); e.code = "EACCES"; throw e; }
    return realOpenSync(targetPath, ...rest);
  };
  let threw = null;
  try { owner.release(); } catch (error) { threw = error; }
  finally { fs.openSync = realOpenSync; }
  check("unlink-opensync-non-enoent-error-propagates",
    Boolean(threw) && threw.code === "EACCES",
    `a non-ENOENT openSync failure must propagate, not be silently treated as "nothing to remove"; got ${threw && threw.code}`);
}

function releaseNeverAcquiredShortCircuitsWithoutTouchingDisk() {
  // release() on an instance that never successfully acquired anything
  // (this._claimToken is null) must short-circuit to false WITHOUT ever touching the
  // filesystem via _unlinkIfToken -- spy on fs.openSync (the only I/O _unlinkIfToken
  // performs before any content check) to prove the guard actually short-circuits
  // rather than merely happening to return the same value some other way.
  const root = freshRoot("release-never-acquired");
  const w = newClaim(root, { instanceId: "e".repeat(32), clock: createManualClock() });
  const realOpenSync = fs.openSync;
  let openSyncCalled = false;
  fs.openSync = (...args) => { openSyncCalled = true; return realOpenSync(...args); };
  let released = null;
  let threw = null;
  try { released = w.release(); } catch (error) { threw = error; }
  finally { fs.openSync = realOpenSync; }
  check("release-never-acquired-does-not-throw", threw === null, `got ${threw && threw.message}`);
  check("release-never-acquired-returns-false", released === false, `expected false, got ${released}`);
  check("release-never-acquired-short-circuits-no-filesystem-touch", openSyncCalled === false,
    "release() on an instance with no held token must never call fs.openSync at all (the !this._claimToken guard must short-circuit before _unlinkIfToken)");
}

function unlinkIfTokenOpenSyncEnoentReturnsFalseNotThrow() {
  const root = freshRoot("unlink-opensync-enoent");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "d".repeat(32), clock });
  owner.acquire();
  fs.unlinkSync(owner.path);   // out-of-band removal, so openSync will genuinely ENOENT

  let released = null;
  let threw = null;
  try { released = owner.release(); } catch (error) { threw = error; }
  check("unlink-opensync-enoent-does-not-throw", threw === null, `an already-gone claim file must not make release() throw, got ${threw && threw.message}`);
  check("unlink-opensync-enoent-reports-false", released === false, `release() on an already-gone claim must report false, got ${released}`);
}

/* =========================================================================
 * renew(): the not-held guard, ENOENT-vs-other-error on openSync, corrupt
 * content encountered mid-renewal, a portable (non-win32-simulation) way to
 * exercise the token-mismatch WRITER_CLAIM_LOST branch, and the actual
 * written bytes round-tripping correctly.
 * ========================================================================= */

function renewWithoutHavingAcquiredThrowsNotHeld() {
  const w = newClaim(freshRoot("renew-not-held"), { instanceId: "a".repeat(32), clock: createManualClock() });
  let thrown = null;
  try { w.renew(); } catch (error) { thrown = error; }
  check("renew-without-acquire-throws-not-held",
    Boolean(thrown) && thrown.code === "WRITER_CLAIM_NOT_HELD",
    `renew() with no claim ever acquired must throw WRITER_CLAIM_NOT_HELD, got ${thrown && thrown.code}`);
}

function renewOpenSyncNonEnoentErrorPropagates() {
  const root = freshRoot("renew-opensync-nonenoent");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "b".repeat(32), clock });
  owner.acquire();

  const realOpenSync = fs.openSync;
  fs.openSync = (targetPath, ...rest) => {
    if (targetPath === owner.path && rest[0] === "r+") { const e = new Error("simulated permission denied"); e.code = "EACCES"; throw e; }
    return realOpenSync(targetPath, ...rest);
  };
  let thrown = null;
  try { owner.renew(); } catch (error) { thrown = error; }
  finally { fs.openSync = realOpenSync; }
  check("renew-opensync-non-enoent-error-propagates",
    Boolean(thrown) && thrown.code === "EACCES",
    `a non-ENOENT openSync failure during renew() must propagate, not be misreported as "claim file is gone"; got ${thrown && thrown.code}`);
}

function renewCorruptContentThrowsCorruptClaim() {
  const root = freshRoot("renew-corrupt");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "c".repeat(32), clock });
  owner.acquire();
  fs.writeFileSync(owner.path, "{ not valid json at all");

  let thrown = null;
  try { owner.renew(); } catch (error) { thrown = error; }
  check("renew-corrupt-content-throws-corrupt-claim",
    Boolean(thrown) && thrown.code === "CORRUPT_CLAIM",
    `renew() encountering invalid JSON on disk must throw CORRUPT_CLAIM, got ${thrown && thrown.code}`);
}

function renewTokenMismatchThrowsLostPortably() {
  // Same behavioral gap as the win32-skipped cr-renew-toctou-* checks in the main
  // suite, exercised via a portable, non-race technique: a plain in-place overwrite
  // with a different valid record (no unlink+recreate, so this needs none of the
  // Windows file-sharing semantics the skipped TOCTOU simulation depends on).
  const root = freshRoot("renew-token-mismatch");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "d".repeat(32), clock });
  owner.acquire();

  const contenderRecord = {
    schema_version: "1.0", host_id: "host-local", instance_id: "e".repeat(32),
    pid: process.pid, claimed_at: clock.now(), renewed_at: clock.now(), claim_token: "9".repeat(32),
  };
  fs.writeFileSync(owner.path, JSON.stringify(contenderRecord));

  let thrown = null;
  try { owner.renew(); } catch (error) { thrown = error; }
  check("renew-token-mismatch-throws-lost", Boolean(thrown) && thrown.code === "WRITER_CLAIM_LOST",
    `renew() must detect a token mismatch and throw WRITER_CLAIM_LOST, got ${thrown && thrown.code}`);
  check("renew-token-mismatch-message-names-new-owner",
    Boolean(thrown) && thrown.message.includes("e".repeat(32)) && thrown.message.includes("host-local"),
    "the WRITER_CLAIM_LOST message must name the new owner that took over");

  const onDisk = JSON.parse(fs.readFileSync(owner.path, "utf8"));
  check("renew-token-mismatch-does-not-clobber-new-owner",
    onDisk.claim_token === contenderRecord.claim_token,
    "renew() must never have written over the new owner's claim before detecting the mismatch");
}

function renewWrittenContentRoundTripsExactly() {
  const root = freshRoot("renew-roundtrip");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "f".repeat(32), clock });
  owner.acquire();
  clock.advance(HEARTBEAT_MS);
  const updated = owner.renew();

  const onDisk = JSON.parse(fs.readFileSync(owner.path, "utf8"));
  check("renew-written-content-round-trips-exactly",
    JSON.stringify(onDisk) === JSON.stringify(updated),
    `the bytes actually written to disk must exactly match renew()'s returned record; disk=${JSON.stringify(onDisk)} returned=${JSON.stringify(updated)}`);
  check("renew-written-content-renewed-at-updated",
    onDisk.renewed_at === clock.now(), `expected renewed_at===${clock.now()}, got ${onDisk.renewed_at}`);
}

function renewClosesFileDescriptorEvenOnSuccess() {
  // Same spy-on-cleanup technique already established in this repo's
  // tests/state-store/atomic-primitives/run-tests.js for atomicCreateExclusive's own
  // fd handling -- renew()'s `finally { fs.closeSync(fd); }` has no OTHER externally
  // observable effect on success, so a call-count spy is the house-style way to pin it.
  const root = freshRoot("renew-closes-fd");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "4".repeat(32), clock });
  owner.acquire();

  const realCloseSync = fs.closeSync;
  let closed = false;
  fs.closeSync = (fd) => { closed = true; return realCloseSync(fd); };
  try { owner.renew(); } finally { fs.closeSync = realCloseSync; }
  check("renew-closes-file-descriptor-on-success", closed === true, "renew() must close its file descriptor even on a successful renewal");
}

/* =========================================================================
 * status(): a "never held anything, but the claim on disk is corrupt" case
 * distinct from the existing corrupt-claim test (which always checks status()
 * from an instance that HAD tried to acquire), an in-place token swap
 * (portable, same technique as the renew()/_unlinkIfToken tests above) to pin
 * held_by_this_instance/lost under a genuine mismatch, and an exact age_ms
 * arithmetic check (the existing tests only check `typeof age_ms === "number"`).
 * ========================================================================= */

function statusNeverAcquiredCorruptClaimReportsNotLost() {
  const root = freshRoot("status-never-acquired-corrupt");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(claimPath(root), "{ not valid json");
  const fresh = newClaim(root, { instanceId: "a".repeat(32), clock: createManualClock() });
  const status = fresh.status();
  check("status-never-acquired-corrupt-claimed-false", status.claimed === false, "a corrupt claim's status must report claimed:false");
  check("status-never-acquired-corrupt-not-lost",
    status.lost === false,
    `an instance that never held any claim cannot report lost:true just because the on-disk file is corrupt; got ${JSON.stringify(status)}`);
}

function statusTokenMismatchReportsLostNotHeld() {
  const root = freshRoot("status-token-mismatch");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "b".repeat(32), clock });
  owner.acquire();
  const contenderRecord = {
    schema_version: "1.0", host_id: "host-local", instance_id: "c".repeat(32),
    pid: process.pid, claimed_at: clock.now(), renewed_at: clock.now(), claim_token: "9".repeat(32),
  };
  fs.writeFileSync(owner.path, JSON.stringify(contenderRecord));

  const status = owner.status();
  check("status-token-mismatch-claimed-true", status.claimed === true, "a claim (someone else's now) still exists on disk");
  check("status-token-mismatch-not-held-by-this-instance", status.held_by_this_instance === false,
    `a token that no longer matches must report held_by_this_instance:false, got ${JSON.stringify(status)}`);
  check("status-token-mismatch-lost-true", status.lost === true,
    `an instance that held a token now superseded on disk must report lost:true, got ${JSON.stringify(status)}`);
}

function statusAgeMsIsExactArithmetic() {
  const root = freshRoot("status-age-ms-exact");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "d".repeat(32), clock });
  owner.acquire();
  clock.advance(12345);
  const status = owner.status();
  check("status-age-ms-is-exact-subtraction", status.age_ms === 12345,
    `expected age_ms===12345 (now - renewed_at), got ${status.age_ms}`);
}

/* =========================================================================
 * startHeartbeat(): idempotent double-start (must not leak a second timer),
 * and a NON-claim-loss renew() error during a heartbeat tick (must not stop
 * the heartbeat or invoke onClaimLost -- only WRITER_CLAIM_LOST should).
 * ========================================================================= */

function startHeartbeatIsIdempotent() {
  const root = freshRoot("heartbeat-idempotent");
  const clock = createManualClock();
  const w = newClaim(root, { instanceId: "a".repeat(32), clock, heartbeatMs: 50 });
  w.acquire();
  const first = w.startHeartbeat();
  const second = w.startHeartbeat();
  w.stopHeartbeat();
  check("start-heartbeat-idempotent-returns-same-timer", first === second,
    "calling startHeartbeat() twice must return the SAME timer, not silently leak a second one");
}

function waitUntil(conditionFn, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const poll = setInterval(() => {
      if (conditionFn() || Date.now() - start > timeoutMs) { clearInterval(poll); resolve(); }
    }, 10);
  });
}

async function startHeartbeatNonLossErrorDoesNotStopTimer() {
  const root = freshRoot("heartbeat-non-loss-error");
  const clock = createManualClock();
  let onClaimLostCalls = 0;
  const w = newClaim(root, {
    instanceId: "b".repeat(32), clock, heartbeatMs: 20,
    onClaimLost: () => { onClaimLostCalls++; },
  });
  w.acquire();
  fs.writeFileSync(w.path, "{ not valid json, simulating transient corruption");
  w.startHeartbeat();

  await waitUntil(() => w._lastHeartbeatError !== null, 500);
  check("heartbeat-non-loss-error-recorded",
    Boolean(w._lastHeartbeatError) && w._lastHeartbeatError.code === "CORRUPT_CLAIM",
    `expected a recorded CORRUPT_CLAIM heartbeat error, got ${w._lastHeartbeatError && w._lastHeartbeatError.code}`);
  check("heartbeat-non-loss-error-does-not-invoke-onClaimLost", onClaimLostCalls === 0,
    "a non-WRITER_CLAIM_LOST renew() error must not trigger onClaimLost");
  check("heartbeat-non-loss-error-timer-still-running", w._timer !== null,
    "a transient (non-loss) heartbeat error must not stop the timer");

  // Repair the file and confirm the heartbeat self-heals on the next tick.
  fs.writeFileSync(w.path, JSON.stringify({
    schema_version: "1.0", host_id: "host-local", instance_id: "b".repeat(32),
    pid: process.pid, claimed_at: clock.now(), renewed_at: clock.now(), claim_token: w._claimToken,
  }));
  await waitUntil(() => w._lastHeartbeatError === null, 500);
  w.stopHeartbeat();
  check("heartbeat-non-loss-error-self-heals-on-next-successful-tick", w._lastHeartbeatError === null,
    "once the transient error condition clears, the next successful renew() must clear _lastHeartbeatError");
}

/* =========================================================================
 * CLI dispatch (require.main === module): the `status` and unknown-command
 * paths, driven as real subprocesses -- selftest's own CLI path already has
 * dedicated coverage (clockEnforcement_selftestAuditBreadcrumb in the main
 * suite); this covers the other two branches of the same dispatch.
 * ========================================================================= */

function cliStatusCommandProducesValidStatusJson() {
  const root = freshRoot("cli-status");
  const r = spawnSync(process.execPath, [WRITER_CLAIM_SCRIPT, "status"], {
    encoding: "utf8",
    cwd: root,
  });
  let parsed = null;
  try { parsed = JSON.parse(r.stdout.trim().split("\n").pop()); } catch (error) { /* checked below */ }
  check("cli-status-exits-zero", r.status === 0, `expected exit 0, got ${r.status}, stderr=${r.stderr}`);
  check("cli-status-produces-valid-json", parsed !== null, `expected valid JSON on stdout, got ${r.stdout}`);
  check("cli-status-reports-unclaimed", Boolean(parsed) && parsed.claimed === false,
    `a fresh, never-claimed directory's status must report claimed:false, got ${JSON.stringify(parsed)}`);
}

function cliUnknownCommandPrintsUsageAndExits2() {
  const r = spawnSync(process.execPath, [WRITER_CLAIM_SCRIPT, "bogus-command"], { encoding: "utf8" });
  check("cli-unknown-command-exits-2", r.status === 2, `expected exit code 2 for an unrecognized command, got ${r.status}`);
  check("cli-unknown-command-prints-usage", /Usage:/.test(r.stderr), `expected a Usage: message on stderr, got ${r.stderr}`);
}

async function main() {
  decideOnExistingFutureBoundaryIsExclusive();
  decideOnExistingClockSkewBoundaryIsExclusive();
  decideOnExistingStaleBoundaryIsExclusive();
  decideOnExistingDeadOwnerWithinGraceStillRefuses();

  refusalMessageClockSkewEndToEnd();
  refusalMessageHeldNotConfusedWithForeignHost();

  ctorRejectsEmptyStateDir();
  ctorRejectsNonStringStateDir();
  ctorEmptyHostIdOptionFallsBackToDefault();
  ctorDefaultHostIdRejectsNonStringHostname();
  ctorInstanceIdRegexRejectsLeadingGarbage();
  ctorInstanceIdRegexRejectsTrailingGarbage();
  ctorNoExplicitClockNoFlagUsesRealWallClock();
  ctorStaleAfterMsDefaultIsHeartbeatTimesMissedHeartbeats();
  ctorHeartbeatMsZeroFallsBackToDefault();
  ctorOnClaimLostNonFunctionFallsBackToNull();
  ctorClockNowExactlyZeroIsValid();

  acquireBoundedContentionThrowsAfterAttempts();
  acquireNonEexistErrorPropagatesUnchanged();
  acquireObservedVanishedBetweenEexistAndReadRetries();
  acquireOwnPathReusesExistingTokenNotDestructiveRecreate();
  acquireStealPathPropagatesNonEnoentUnlinkError();

  unlinkIfTokenSameInodeDifferentTokenRefusesToDelete();
  unlinkIfTokenOpenSyncNonEnoentErrorPropagates();
  releaseNeverAcquiredShortCircuitsWithoutTouchingDisk();
  unlinkIfTokenOpenSyncEnoentReturnsFalseNotThrow();

  renewWithoutHavingAcquiredThrowsNotHeld();
  renewOpenSyncNonEnoentErrorPropagates();
  renewCorruptContentThrowsCorruptClaim();
  renewTokenMismatchThrowsLostPortably();
  renewWrittenContentRoundTripsExactly();
  renewClosesFileDescriptorEvenOnSuccess();

  statusNeverAcquiredCorruptClaimReportsNotLost();
  statusTokenMismatchReportsLostNotHeld();
  statusAgeMsIsExactArithmetic();

  startHeartbeatIsIdempotent();
  await startHeartbeatNonLossErrorDoesNotStopTimer();

  cliStatusCommandProducesValidStatusJson();
  cliUnknownCommandPrintsUsageAndExits2();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main();
