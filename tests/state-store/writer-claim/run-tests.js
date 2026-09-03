#!/usr/bin/env node
/* GraphSmith gateway-integration writer-claim: AC-1, AC-3, AC-4 from
 * .plans/v0.5.0/GATEWAY-MULTI-INSTANCE-HANDOFF.md §6.4.
 *
 * AC-1: a second instance refused by a live, differently-identified claim gets a
 *       SPECIFIC, named error (the conflicting instance_id), not a generic
 *       lock-contention message.
 * AC-3: a live, actively-renewed claim is never displaced, including under the same
 *       clock-skew shapes already pinned for the per-mutation lock in
 *       tests/state-store/clock-skew/ (retargeted here at the claim's own
 *       self-reported `renewed_at`, not an OS mtime -- see scripts/writer-claim.js's
 *       module header for why that retargeting is deliberate).
 * AC-4: the health-check/status surface correctly reports writer status under normal
 *       operation, startup refusal, and mid-run claim loss (file removed out-of-band).
 *
 * AC-2 (shared/networked storage + cross-host clock skew) is the single
 * highest-priority scenario per the handoff doc and gets its own dedicated suite:
 * tests/state-store/writer-claim-shared-storage/run-tests.js -- mirroring how
 * tests/state-store/clock-skew/ is split out from the general state-store suites.
 *
 * Same no-framework, no-process-spawn harness style as tests/state-store/clock-skew/:
 * a manual clock (this mechanism's staleness math is arithmetic on a self-reported
 * `renewed_at` field, not an OS-written mtime, so -- unlike state.lock's steal gate --
 * it can be fully pinned with a chosen instant, exactly like lease arithmetic). */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../../..");
const WRITER_CLAIM_SCRIPT = path.join(ROOT, "scripts", "writer-claim.js");
const { WriterClaim, decideOnExisting, claimPath, readStatus, CLAIM_CLOCK_SKEW_TOLERANCE_MS } = require(WRITER_CLAIM_SCRIPT);
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));
const { createManualClock } = require("../../_harness/clock.js");

const HEARTBEAT_MS = 1000;
const STALE_AFTER_MS = HEARTBEAT_MS * 3;
const DEAD_PID = 999999; // above default pid_max everywhere in the CI matrix; see clock-skew's own note

let failures = 0;
const results = [];

function record(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}`
    : status === "SKIPPED" ? `SKIPPED ${name}: ${reason || "unknown"}`
      : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) record(name, "PASS"); else record(name, "FAIL", reason);
}

function skip(name, reason) {
  record(name, "SKIPPED", reason);
}

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-writer-claim-${prefix}-`));
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

/* ---------------------------------------------------------------------------------
 * AC-1: a second, differently-identified instance is refused with a SPECIFIC error
 * naming the conflicting instance_id -- not a generic lock-contention message.
 * ------------------------------------------------------------------------------- */

function ac1_namedRefusalNotGeneric() {
  const root = freshRoot("ac1");
  const clock = createManualClock();
  const first = newClaim(root, { instanceId: "a".repeat(32), clock });
  first.acquire();

  const second = newClaim(root, { instanceId: "b".repeat(32), clock });
  let thrown = null;
  try { second.acquire(); } catch (error) { thrown = error; }

  check("ac1-refused-with-specific-code",
    Boolean(thrown) && thrown.code === "WRITER_CLAIM_HELD",
    `expected code WRITER_CLAIM_HELD, got ${thrown && thrown.code}`);
  check("ac1-not-generic-lock-contention-code",
    Boolean(thrown) && thrown.code !== "LOCKED" && thrown.code !== "LOCK_CONTENTION" && thrown.code !== "TIMEOUT",
    `refusal reused a generic lock-contention code: ${thrown && thrown.code}`);
  check("ac1-message-names-conflicting-instance-id",
    Boolean(thrown) && thrown.message.includes("a".repeat(32)),
    "refusal message did not name the conflicting instance_id");
  check("ac1-message-states-single-writer-constraint",
    Boolean(thrown) && /single-writer/i.test(thrown.message),
    "refusal message did not name the single-writer constraint");

  // A THIRD instance with the SAME instance_id as the first is the "am I already the
  // owner" idempotent path, not a conflict -- must not be refused.
  const rejoin = newClaim(root, { instanceId: "a".repeat(32), clock });
  let rejoinError = null;
  try { rejoin.acquire(); } catch (error) { rejoinError = error; }
  check("ac1-matching-instance-id-is-not-a-conflict", rejoinError === null,
    `same instance_id re-acquiring its own claim should not be refused: ${rejoinError && rejoinError.message}`);
}

/* ---------------------------------------------------------------------------------
 * AC-3: a live, renewed claim is never displaced -- including the clock-skew shapes
 * already pinned for the per-mutation lock (small forward skew inside tolerance stays
 * an ordinary refusal; skew beyond tolerance is NAMED as skew, never silently ignored
 * or silently stolen from a live owner; a DEAD owner is decisive regardless of skew).
 * ------------------------------------------------------------------------------- */

function ac3_liveClaimNeverDisplaced() {
  const root = freshRoot("ac3");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "1".repeat(32), clock });
  owner.acquire();

  // Advance time and renew repeatedly, like a real heartbeat -- must never become
  // stealable while renewals keep landing.
  for (let i = 0; i < 5; i++) {
    clock.advance(HEARTBEAT_MS);
    owner.renew();
    const challenger = newClaim(root, { instanceId: "2".repeat(32), clock });
    let displaced = false;
    try { challenger.acquire(); displaced = true; } catch (error) { /* expected */ }
    check(`ac3-not-displaced-after-renewal-${i}`, !displaced, "a live, renewed claim was displaced");
  }

  // Now stop renewing and let the claim go stale -- it MUST become stealable once
  // genuinely abandoned (this is FR-2's self-healing counterpart to AC-3, and pins
  // that "never displaced while live" does not regress into "never displaced, ever").
  clock.advance(STALE_AFTER_MS + HEARTBEAT_MS);
  // The owner's pid is this test process, which IS alive, so liveness alone would
  // wedge it forever -- self-healing here depends on the unrenewed gate, not pid death.
  const afterAbandon = newClaim(root, { instanceId: "3".repeat(32), clock });
  let stole = false;
  try { afterAbandon.acquire(); stole = true; } catch (error) { /* not expected */ }
  check("ac3-genuinely-abandoned-claim-is-stealable", stole, "an unrenewed claim past staleAfterMs did not self-heal");
}

/* decideOnExisting is exported specifically so the clock-skew decision table can be
 * pinned directly, the same way tests/state-store/clock-skew/ pins _acquireLock's
 * gates -- one call per state, no process spawning, fully deterministic. */
function ac3_clockSkewDecisionTable() {
  const now = 1_700_000_100_000;
  const ctx = (overrides) => ({
    localHostId: "host-local",
    localInstanceId: "attacker".padEnd(32, "0"),
    now,
    staleAfterMs: STALE_AFTER_MS,
    skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
    ...overrides,
  });
  const recordFor = (overrides) => ({
    schema_version: "1.0",
    host_id: "host-local",
    instance_id: "owner".padEnd(32, "1"),
    pid: process.pid,
    claimed_at: now - 10_000,
    renewed_at: now,
    claim_token: "c".repeat(32),
    ...overrides,
  });

  check("skew-live-owner-fresh-refused",
    decideOnExisting(recordFor({}), ctx({})).outcome === "refuse",
    "a fresh, live-owner claim must refuse");

  check("skew-live-owner-1s-ahead-not-skew-still-refused",
    decideOnExisting(recordFor({ renewed_at: now + 1000 }), ctx({})).outcome === "refuse"
    && decideOnExisting(recordFor({ renewed_at: now + 1000 }), ctx({})).code !== "WRITER_CLAIM_CLOCK_SKEW",
    "1s ahead is inside tolerance and must be an ordinary refusal, not a named skew");

  check("skew-live-owner-30s-ahead-reports-skew",
    decideOnExisting(recordFor({ renewed_at: now + 30_000 }), ctx({})).code === "WRITER_CLAIM_CLOCK_SKEW",
    "30s ahead is outside tolerance and must be named as clock skew");

  check("skew-dead-owner-unrenewed-stealable",
    decideOnExisting(recordFor({ pid: DEAD_PID, renewed_at: now - (STALE_AFTER_MS + 1) }), ctx({})).outcome === "steal",
    "a dead owner past staleAfterMs must be stealable");

  check("skew-dead-owner-24h-ahead-still-stealable",
    decideOnExisting(recordFor({ pid: DEAD_PID, renewed_at: now + 24 * 60 * 60 * 1000 }), ctx({})).outcome === "steal",
    "owner death must be decisive regardless of a future renewed_at -- must not wedge");

  check("skew-live-owner-unrenewed-past-stale-still-stealable",
    decideOnExisting(recordFor({ renewed_at: now - (STALE_AFTER_MS + 1) }), ctx({})).outcome === "steal",
    "a live pid that has simply stopped heartbeating past staleAfterMs must self-heal");
}

/* ---------------------------------------------------------------------------------
 * AC-4: health-check / log-line surface correctly reports writer status under normal
 * operation, startup refusal, and mid-run claim loss (file removed out-of-band).
 * ------------------------------------------------------------------------------- */

function ac4_healthCheckSurface() {
  const root = freshRoot("ac4");
  const clock = createManualClock();

  // (1) Normal single-instance operation.
  const owner = newClaim(root, { instanceId: "a".repeat(32), clock });
  owner.acquire();
  const normal = owner.status();
  check("ac4-normal-claimed-true", normal.claimed === true, `expected claimed:true, got ${JSON.stringify(normal)}`);
  check("ac4-normal-held-by-this-instance", normal.held_by_this_instance === true, "owner's own status must report held_by_this_instance");
  check("ac4-normal-not-lost", normal.lost === false, "a healthy claim must not report lost");
  check("ac4-normal-has-age-ms", typeof normal.age_ms === "number", "status must report an age");

  // (2) Startup refusal: a second instance's status (read-only, never acquired) must
  // report the claim exists and is held by someone else, naming that identity.
  const second = newClaim(root, { instanceId: "b".repeat(32), clock });
  let refusalError = null;
  try { second.acquire(); } catch (error) { refusalError = error; }
  check("ac4-refusal-actually-threw", Boolean(refusalError), "setup: second instance must have been refused");
  const refusedStatus = second.status();
  check("ac4-refused-claimed-true", refusedStatus.claimed === true, "a refused instance's status must still show the directory as claimed");
  check("ac4-refused-not-held-by-this-instance", refusedStatus.held_by_this_instance === false, "a refused instance must not report itself as holder");
  check("ac4-refused-names-other-instance", refusedStatus.instance_id === "a".repeat(32), "refused status must name the actual holder's instance_id");

  // (3) Mid-run claim loss: the underlying file removed out-of-band.
  fs.unlinkSync(owner.path);
  const lost = owner.status();
  check("ac4-lost-claimed-false", lost.claimed === false, "status after out-of-band removal must report claimed:false");
  check("ac4-lost-flag-set", lost.lost === true, "status after out-of-band removal must set lost:true");
  check("ac4-lost-not-held-by-this-instance", lost.held_by_this_instance === false, "a lost claim cannot be held by this instance");
}

function ac4_corruptClaimFailsClosed() {
  const root = freshRoot("ac4-corrupt");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "writer-claim.json"), "{not valid json");
  const clock = createManualClock();
  const instance = newClaim(root, { instanceId: "a".repeat(32), clock });
  let thrown = null;
  try { instance.acquire(); } catch (error) { thrown = error; }
  check("ac4-corrupt-claim-refuses-not-proceeds", Boolean(thrown), "a corrupt claim file must refuse acquisition, never proceed as unclaimed");
  check("ac4-corrupt-claim-named-code", Boolean(thrown) && thrown.code === "WRITER_CLAIM_AMBIGUOUS",
    `expected WRITER_CLAIM_AMBIGUOUS, got ${thrown && thrown.code}`);

  const status = instance.status();
  check("ac4-corrupt-status-not-claimed-true", status.claimed === false, "a corrupt claim must not be reported as a healthy claimed:true");
  check("ac4-corrupt-status-carries-error", Boolean(status.error), "a corrupt claim's status must surface the error, not go silent");
}

/* ---------------------------------------------------------------------------------
 * Clock enforcement: GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK and the malformed-clock
 * guard added by the SAT-1086/SAT-1087 lease-clock audit wiring fix, then hardened by
 * adversarial review (correctness-1: a truthy-but-malformed explicit clock such as
 * `{}` bypassed the flag and silently fell back to the wall clock; correctness-2: the
 * audit breadcrumb call ran after the instanceId validation throw, so an invalid
 * construction left no breadcrumb). test_quality-2/test_quality-3 flagged that none of
 * this had permanent test coverage -- only the manual reproduction recorded in this
 * run's validation/ records. These four checks are that permanent coverage.
 * ------------------------------------------------------------------------------- */

function clockEnforcement_requireExplicitFlag() {
  const root = freshRoot("clock-enforcement");
  const FLAG = "GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK";
  const prevFlag = process.env[FLAG];
  try {
    process.env[FLAG] = "1";

    /* This construction is EXPECTED to refuse before ever touching a clock -- it is not
     * a stand-in for a real no-clock call site. If this file runs under
     * tests/harness-honesty/lease-determinism's own enforced-clock sweep (which sets
     * GRAPHSMITH_LEASE_CLOCK_AUDIT for the whole process to catch real wall-clock wiring
     * gaps), the pre-throw audit breadcrumb this deliberately-bad construction produces
     * would otherwise misreport as a wiring gap in code that never actually used the
     * wall clock. Suppressing the audit env var for just this one call keeps that
     * sweep meaningful without weakening it. */
    const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";
    const prevAuditForRefusalProbe = process.env[AUDIT_ENV];
    let thrown = null;
    try {
      delete process.env[AUDIT_ENV];
      try { newClaim(root, { instanceId: "1".repeat(32) }); } catch (error) { thrown = error; }
    } finally {
      if (prevAuditForRefusalProbe !== undefined) process.env[AUDIT_ENV] = prevAuditForRefusalProbe;
    }
    check("clock-enforcement-no-clock-refused-under-flag",
      Boolean(thrown) && thrown.code === "LEASE_CLOCK_REQUIRED",
      `expected LEASE_CLOCK_REQUIRED, got ${thrown && thrown.code}`);

    let malformedThrown = null;
    try { newClaim(root, { instanceId: "2".repeat(32), clock: {} }); } catch (error) { malformedThrown = error; }
    check("clock-enforcement-malformed-truthy-clock-refused-under-flag",
      Boolean(malformedThrown) && malformedThrown.code === "BAD_LEASE_CLOCK",
      `expected BAD_LEASE_CLOCK, got ${malformedThrown && malformedThrown.code}`);

    let explicitOk = false;
    try {
      const clock = createManualClock();
      const claim = newClaim(root, { instanceId: "3".repeat(32), clock });
      explicitOk = claim.clock.now() === clock.now();
    } catch (error) { explicitOk = false; }
    check("clock-enforcement-explicit-clock-accepted-under-flag", explicitOk === true,
      "a well-formed explicit clock must still construct successfully under the flag");
  } finally {
    if (prevFlag === undefined) delete process.env[FLAG]; else process.env[FLAG] = prevFlag;
  }
}

function clockEnforcement_malformedClockUnconditional() {
  // Same BAD_LEASE_CLOCK rejection must hold even without the flag -- StateStore's
  // equivalent check (scripts/state-store.js) is unconditional, and WriterClaim's is
  // now written to match it exactly, not only the flagged branch above.
  const root = freshRoot("clock-enforcement-unflagged");
  let thrown = null;
  try { newClaim(root, { instanceId: "4".repeat(32), clock: { now: "not-a-function" } }); }
  catch (error) { thrown = error; }
  check("clock-enforcement-malformed-clock-refused-without-flag",
    Boolean(thrown) && thrown.code === "BAD_LEASE_CLOCK",
    `expected BAD_LEASE_CLOCK even without the flag, got ${thrown && thrown.code}`);
}

function clockEnforcement_auditBreadcrumbOrdering() {
  // correctness-2: the audit breadcrumb must be written even when a LATER validation
  // (instanceId format) throws -- recordLeaseClockConstruction must run first.
  const root = freshRoot("clock-enforcement-audit");
  const auditPath = path.join(root, "audit.jsonl");
  const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";
  const prevAudit = process.env[AUDIT_ENV];
  try {
    process.env[AUDIT_ENV] = auditPath;
    let thrown = null;
    try { newClaim(root, { instanceId: "not-valid-hex" }); } catch (error) { thrown = error; }
    check("clock-enforcement-invalid-instance-id-still-throws",
      Boolean(thrown) && thrown.code === "INVALID_ARGUMENT",
      `expected INVALID_ARGUMENT, got ${thrown && thrown.code}`);
    const written = fs.existsSync(auditPath) ? fs.readFileSync(auditPath, "utf8").trim() : "";
    check("clock-enforcement-audit-breadcrumb-written-before-instanceid-throw",
      written.length > 0,
      "recordLeaseClockConstruction must run before instanceId validation can throw, or the audit is structurally blind to invalid constructions");
  } finally {
    if (prevAudit === undefined) delete process.env[AUDIT_ENV]; else process.env[AUDIT_ENV] = prevAudit;
  }
}

function clockEnforcement_selftestAuditBreadcrumb() {
  // test_quality-3: selftest() constructs WriterClaim with a manual clock, but nothing
  // previously asserted that construction is actually audited when audit mode is on --
  // spawned as a subprocess (matching tests/state-store/grok/run-tests.js's own
  // `--selftest` CLI-floor check) since selftest() is not exported for direct call.
  const auditDir = freshRoot("clock-enforcement-selftest-audit");
  const auditPath = path.join(auditDir, "audit.jsonl");
  const r = spawnSync(process.execPath, [WRITER_CLAIM_SCRIPT, "--selftest"], {
    encoding: "utf8",
    env: { ...process.env, GRAPHSMITH_LEASE_CLOCK_AUDIT: auditPath },
  });
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch (error) { /* checked below */ }
  check("clock-enforcement-selftest-still-passes-under-audit-mode",
    r.status === 0 && parsed && parsed.status === "pass",
    `selftest failed or errored while GRAPHSMITH_LEASE_CLOCK_AUDIT was set: exit=${r.status} stdout=${r.stdout} stderr=${r.stderr}`);
  const written = fs.existsSync(auditPath) ? fs.readFileSync(auditPath, "utf8").trim() : "";
  check("clock-enforcement-selftest-writes-audit-breadcrumb",
    written.length > 0,
    "selftest()'s WriterClaim construction(s) produced no audit breadcrumb -- audit coverage for this class could silently regress without any test catching it");
}

/* =========================================================================
 * CodeRabbit + Codex review regressions (PR #27, 2026-08-22). One function
 * per distinct, independently-verified finding -- see the fix comments in
 * scripts/writer-claim.js and schemas/state-store.schema.json for the full
 * reasoning each test pins.
 * ========================================================================= */

function crCodex_pidRequiredInSchema() {
  const root = freshRoot("cr-pid-required");
  // Write a claim record missing `pid` directly (bypassing WriterClaim's own
  // always-writes-pid constructor path) to prove the SCHEMA itself rejects it,
  // not just this class's current write path.
  const record = {
    schema_version: "1.0",
    host_id: "host-local",
    instance_id: "7".repeat(32),
    claimed_at: 1,
    renewed_at: 1,
    claim_token: "8".repeat(32),
  };
  let threw = null;
  try { stateStore.validateNamedRecord(record, "writerClaim", "writer-claim.json"); }
  catch (error) { threw = error; }
  check("cr-pid-required-schema-rejects-pidless-record", Boolean(threw),
    "schema accepted a writerClaim record with no pid field");

  // And end-to-end: a pid-less record on disk is read as CORRUPT_CLAIM, which
  // acquire() already converts to WRITER_CLAIM_AMBIGUOUS -- fail-closed, not a
  // silently-accepted dead-owner record.
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(claimPath(root), JSON.stringify(record));
  const status = readStatus(root, { clock: createManualClock() });
  check("cr-pid-required-status-reports-corrupt-not-unclaimed",
    status.claimed === false && Boolean(status.error) && status.error.code === "CORRUPT_CLAIM",
    `expected a corrupt-claim status for a pid-less record, got ${JSON.stringify(status)}`);
}

function crCodex_instanceIdReuseByDifferentLivePid() {
  const now = 1_700_000_200_000;
  const sameInstance = "9".repeat(32);
  const recordFor = (pid) => ({
    schema_version: "1.0", host_id: "host-local", instance_id: sameInstance,
    pid, claimed_at: now - 1000, renewed_at: now, claim_token: "c".repeat(32),
  });
  const ctxFor = (localPid) => ({
    localHostId: "host-local", localInstanceId: sameInstance, localPid,
    now, staleAfterMs: STALE_AFTER_MS, skewToleranceMs: CLAIM_CLOCK_SKEW_TOLERANCE_MS,
  });

  // Same instance_id, DIFFERENT live pid: two real processes started with the same
  // caller-supplied instanceId must be treated as a conflict, not an idempotent
  // re-acquire -- this is exactly what CodeRabbit found was missing. record.pid is
  // this test process's own real, genuinely-alive pid; localPid is a distinct value
  // standing in for "a different process" (it need not itself be alive -- pidAlive()
  // is only ever checked against record.pid).
  const conflict = decideOnExisting(recordFor(process.pid), ctxFor(process.pid + 1));
  check("cr-instanceid-reuse-different-live-pid-is-conflict", conflict.outcome === "refuse" && conflict.code === "WRITER_CLAIM_HELD",
    `expected a refusal for a matching instance_id but different live pid, got ${JSON.stringify(conflict)}`);

  // Same instance_id, SAME pid: the genuine idempotent re-acquire path (e.g. this
  // process re-reading its own claim) must still be unaffected.
  const same = decideOnExisting(recordFor(process.pid), ctxFor(process.pid));
  check("cr-instanceid-reuse-same-pid-still-own", same.outcome === "own",
    `same instance_id AND same pid must still be treated as owning it, got ${JSON.stringify(same)}`);

  // Same instance_id, different but DEAD pid: a crashed process's leftover record
  // under the same instanceId must still be re-ownable, not permanently wedged.
  const dead = decideOnExisting(recordFor(DEAD_PID), ctxFor(process.pid));
  check("cr-instanceid-reuse-different-dead-pid-still-own", dead.outcome === "own",
    `same instance_id with a DEAD foreign pid should still be re-ownable, got ${JSON.stringify(dead)}`);
}

function crCodex_defaultHostIdFailsClosed() {
  // defaultHostId() is only reached when no explicit hostId is given, so drive it
  // through the public constructor with hostId omitted, monkey-patching
  // os.hostname() (its only input) for the duration of this one call.
  const realHostname = os.hostname;
  os.hostname = () => "";
  let threw = null;
  try { new WriterClaim(freshRoot("cr-hostid"), { instanceId: "a".repeat(32), clock: createManualClock() }); }
  catch (error) { threw = error; }
  finally { os.hostname = realHostname; }
  check("cr-hostid-empty-hostname-fails-closed",
    Boolean(threw) && threw.code === "WRITER_CLAIM_NO_HOST_ID",
    `expected WRITER_CLAIM_NO_HOST_ID for an empty os.hostname(), got ${threw && threw.code}`);

  // No regression: an explicit hostId always wins regardless of os.hostname().
  os.hostname = () => "";
  let explicitOk = false;
  try {
    const w = new WriterClaim(freshRoot("cr-hostid-explicit"), { hostId: "given-host", instanceId: "b".repeat(32), clock: createManualClock() });
    explicitOk = w.hostId === "given-host";
  } finally { os.hostname = realHostname; }
  check("cr-hostid-explicit-hostid-still-works", explicitOk,
    "an explicitly-supplied hostId should bypass os.hostname() entirely");
}

function crCodex_clockInstantValidated() {
  const root = freshRoot("cr-clock-validate");
  const badClocks = [
    { label: "fractional", now: () => 1.5 },
    { label: "negative", now: () => -1 },
    { label: "NaN", now: () => NaN },
    { label: "string", now: () => "1700000000000" },
  ];
  // These clocks are deliberately malformed probes for THIS validation, not a real
  // lease-clock choice -- suppress the lease-clock audit env var around them (same
  // isolation clockEnforcement_requireExplicitFlag already uses for its own
  // deliberate-refusal probe) so the meta-audit's real-time measurement heuristic,
  // which compares `now() !== now()` to detect a moving clock, doesn't misfire on the
  // NaN case specifically (`NaN !== NaN` is always true in JS regardless of whether
  // real time passed, which would otherwise misclassify this as a wall-clock site).
  const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";
  const prevAudit = process.env[AUDIT_ENV];
  try {
    delete process.env[AUDIT_ENV];
    for (const { label, now } of badClocks) {
      const w = newClaim(root + "-" + label, { instanceId: "d".repeat(32), clock: { now } });
      let threw = null;
      try { w.acquire(); } catch (error) { threw = error; }
      check(`cr-clock-validate-acquire-rejects-${label}`,
        Boolean(threw) && threw.code === "BAD_CLAIM_CLOCK",
        `expected BAD_CLAIM_CLOCK for a ${label} clock instant, got ${threw && threw.code}`);
    }
  } finally {
    if (prevAudit === undefined) delete process.env[AUDIT_ENV]; else process.env[AUDIT_ENV] = prevAudit;
  }

  // renew() must reject a clock that goes bad AFTER a valid acquire(), not just at
  // construction/acquire time. Construction itself uses a genuine createManualClock(),
  // so no audit suppression is needed here -- only the later in-place mutation to a bad
  // instant, which happens post-construction and is never itself audited.
  const clock = createManualClock();
  const w = newClaim(freshRoot("cr-clock-validate-renew"), { instanceId: "e".repeat(32), clock });
  w.acquire();
  const realNow = clock.now.bind(clock);
  clock.now = () => -1;
  let renewThrew = null;
  try { w.renew(); } catch (error) { renewThrew = error; }
  clock.now = realNow;
  check("cr-clock-validate-renew-rejects-bad-instant",
    Boolean(renewThrew) && renewThrew.code === "BAD_CLAIM_CLOCK",
    `expected BAD_CLAIM_CLOCK from renew() with a negative clock instant, got ${renewThrew && renewThrew.code}`);
}

function crCodex_releaseKeepsTokenOnThrow() {
  const root = freshRoot("cr-release-throw");
  const clock = createManualClock();
  const w = newClaim(root, { instanceId: "f".repeat(32), clock });
  w.acquire();
  const heldToken = w._claimToken;

  // Corrupt the claim file in place (still same path/inode) so _unlinkIfToken's
  // JSON.parse/validateNamedRecord throws instead of returning cleanly.
  fs.writeFileSync(w.path, "{ not valid json");

  let released = null;
  let threw = null;
  try { released = w.release(); } catch (error) { threw = error; }

  check("cr-release-throw-on-corrupt-file", Boolean(threw), "release() should propagate a corrupt-claim read failure, not swallow it");
  check("cr-release-throw-keeps-token", w._claimToken === heldToken,
    `release() must NOT discard _claimToken when the underlying unlink attempt threw -- ` +
    `got ${JSON.stringify(w._claimToken)}, expected the original token to survive so the ` +
    `orphan can be diagnosed/retried instead of silently losing the only proof of ownership`);
}

function waitUntil(conditionFn, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const poll = setInterval(() => {
      if (conditionFn() || Date.now() - start > timeoutMs) {
        clearInterval(poll);
        resolve();
      }
    }, 10);
  });
}

async function crCodex_heartbeatSurfacesClaimLoss() {
  const root = freshRoot("cr-heartbeat-loss");
  const clock = createManualClock();
  let lostError = null;
  const w = newClaim(root, {
    instanceId: "1".repeat(32), clock, heartbeatMs: 20,
    onClaimLost: (error) => { lostError = error; },
  });
  w.acquire();
  fs.unlinkSync(w.path);   // simulate an out-of-band loss (another writer took over)
  w.startHeartbeat();

  // heartbeatMs is a real, unfaked 20ms (only the claim instants use the manual
  // clock) -- setInterval genuinely fires; wait on the actual event loop rather than
  // busy-waiting, which would starve that same timer in this single-threaded process.
  await waitUntil(() => lostError !== null, 2000);
  w.stopHeartbeat();

  check("cr-heartbeat-claim-loss-invokes-callback",
    Boolean(lostError) && lostError.code === "WRITER_CLAIM_LOST",
    `onClaimLost was not invoked with WRITER_CLAIM_LOST within the deadline (got ${lostError && lostError.code})`);
  check("cr-heartbeat-claim-loss-clears-token", w._claimToken === null,
    "the in-memory claim token must be cleared once the heartbeat observes the claim as lost");
  check("cr-heartbeat-claim-loss-stops-timer", w._timer === null,
    "the heartbeat timer must stop itself once the claim is confirmed lost");

  // No handler configured: the same loss must be thrown, not silently absorbed.
  const root2 = freshRoot("cr-heartbeat-loss-unhandled");
  const w2 = newClaim(root2, { instanceId: "2".repeat(32), clock: createManualClock(), heartbeatMs: 20 });
  w2.acquire();
  fs.unlinkSync(w2.path);
  const realListeners = process.listeners("uncaughtException").slice();
  let uncaught = null;
  process.removeAllListeners("uncaughtException");
  process.on("uncaughtException", (error) => { uncaught = error; });
  w2.startHeartbeat();
  await waitUntil(() => uncaught !== null, 2000);
  w2.stopHeartbeat();
  process.removeAllListeners("uncaughtException");
  for (const listener of realListeners) process.on("uncaughtException", listener);
  check("cr-heartbeat-claim-loss-unhandled-surfaces-loudly",
    Boolean(uncaught) && uncaught.code === "WRITER_CLAIM_LOST",
    `expected an uncaught WRITER_CLAIM_LOST when no onClaimLost handler was given, got ${uncaught && uncaught.code}`);
}

function crCodex_renewToctouDoesNotClobberContender() {
  /* [inferring] SKIPPED on win32: this technique unlinks owner.path while renew()'s own
   * fd (fs.openSync(this.path, "r+"), held open across the whole check-then-write per
   * scripts/writer-claim.js's renew()) is still open, then immediately recreates a new
   * file at the same path for the contender. On POSIX that unlink leaves the open fd
   * pointing at an orphaned-but-still-readable/writable inode (harmless -- see renew()'s
   * own doc comment) while the new path entry is untouched. GitHub Actions'
   * windows-latest runner fails this same way on node 18 every time it has run (checked
   * CI history back to commit c12d76f, 2026-08-28, before this session touched anything
   * here) -- the contender's swap never completes, so this is inferred to be Windows'
   * file-sharing semantics (no FILE_SHARE_DELETE on Node's default fs.openSync handle)
   * refusing the delete/recreate-at-same-path sequence this simulation depends on, not a
   * bug in renew() itself. Marked [inferring] because this could not be reproduced and
   * confirmed on a real Windows host from this environment (no native Windows execution
   * available, only Linux) -- this conclusion rests on CI log evidence and code reading,
   * not a local repro. crCodex_unlinkIfTokenDoesNotClobberSwappedFile below uses the same
   * technique via a different code path (_unlinkIfToken's read-only fd). An earlier version
   * of this comment said it had passed on windows-latest in every CI run checked and left it
   * unskipped -- that was based on a single historical sample and turned out to be wrong: it
   * failed the same way on the very next CI run after this fix landed. It is now skipped
   * below for the same reason and with the same evidentiary caveat. */
  if (process.platform === "win32") {
    skip("cr-renew-toctou-swap-actually-happened",
      "unverified on this platform: unlinking owner.path while renew()'s own fd is open " +
      "does not appear to permit the immediate same-path recreate this simulation needs " +
      "on Windows (see comment above this function)");
    skip("cr-renew-toctou-owner-renew-does-not-throw", "see prior skip");
    skip("cr-renew-toctou-contenders-claim-not-clobbered", "see prior skip");
    skip("cr-renew-toctou-stale-owner-self-heals-to-lost", "see prior skip");
    return;
  }

  const root = freshRoot("cr-renew-toctou");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "3".repeat(32), clock });
  owner.acquire();

  // Simulate a contender unlinking the owner's stale claim and acquiring a NEW one
  // (different token) in the exact window between renew()'s token-check read and its
  // write, by monkey-patching fs.readFileSync -- renew()'s only fd-based read -- to
  // perform that swap as a side effect the first time it fires, then restoring fs
  // immediately.
  const realReadFileSync = fs.readFileSync;
  let contenderToken = null;
  fs.readFileSync = function (...args) {
    const result = realReadFileSync.apply(fs, args);
    if (contenderToken === null && typeof args[0] === "number") {
      fs.readFileSync = realReadFileSync;   // restore before doing any further real I/O
      fs.unlinkSync(owner.path);
      const contender = newClaim(root, { instanceId: "4".repeat(32), clock });
      contender.acquire();
      contenderToken = contender._claimToken;
    }
    return result;
  };

  let renewThrew = null;
  try { owner.renew(); } catch (error) { renewThrew = error; }
  fs.readFileSync = realReadFileSync;   // safety net if the swap branch never ran

  check("cr-renew-toctou-swap-actually-happened", contenderToken !== null,
    "test setup failed: the monkey-patched contender swap never ran");
  check("cr-renew-toctou-owner-renew-does-not-throw",
    renewThrew === null,
    `owner's renew() should complete without throwing even though it landed on an ` +
    `orphaned inode (harmless) -- got ${renewThrew && renewThrew.message}`);

  const onDisk = JSON.parse(fs.readFileSync(claimPath(root), "utf8"));
  check("cr-renew-toctou-contenders-claim-not-clobbered", onDisk.claim_token === contenderToken,
    `the contender's live claim must survive the race untouched; got token ${onDisk.claim_token}, expected ${contenderToken}`);

  const staleStatus = owner.status();
  check("cr-renew-toctou-stale-owner-self-heals-to-lost",
    staleStatus.lost === true && staleStatus.held_by_this_instance === false,
    `the stale owner's own status() must report the claim as lost once the live path no ` +
    `longer matches its token, not silently ownership; got ${JSON.stringify(staleStatus)}`);
}

function crCodex_unlinkIfTokenDoesNotClobberSwappedFile() {
  /* [inferring] SKIPPED on win32 -- see the comment on crCodex_renewToctouDoesNotClobberContender
   * above for the full reasoning (same unlink-under-open-fd technique, same inferred Windows
   * file-sharing cause, same "no native Windows execution available to confirm directly"
   * caveat). This function's own fd comes from _unlinkIfToken's fs.openSync(this.path, "r")
   * (read-only) rather than renew()'s "r+", so it is a distinct code path -- but the CI
   * failure signature (contender swap never completes, then EPERM) is identical, confirming
   * this is the same platform limitation, not a coincidence. */
  if (process.platform === "win32") {
    skip("cr-unlink-toctou-swap-actually-happened",
      "unverified on this platform: unlinking owner.path while _unlinkIfToken's own fd is " +
      "open does not appear to permit the immediate same-path recreate this simulation " +
      "needs on Windows (see comment above crCodex_renewToctouDoesNotClobberContender)");
    skip("cr-unlink-toctou-release-does-not-throw", "see prior skip");
    skip("cr-unlink-toctou-release-reports-false", "see prior skip");
    skip("cr-unlink-toctou-contenders-claim-not-deleted", "see prior skip");
    return;
  }

  const root = freshRoot("cr-unlink-toctou");
  const clock = createManualClock();
  const owner = newClaim(root, { instanceId: "5".repeat(32), clock });
  owner.acquire();

  const realReadFileSync = fs.readFileSync;
  let contenderToken = null;
  fs.readFileSync = function (...args) {
    const result = realReadFileSync.apply(fs, args);
    if (contenderToken === null && typeof args[0] === "number") {
      fs.readFileSync = realReadFileSync;
      fs.unlinkSync(owner.path);
      const contender = newClaim(root, { instanceId: "6".repeat(32), clock });
      contender.acquire();
      contenderToken = contender._claimToken;
    }
    return result;
  };

  let released = null;
  let releaseThrew = null;
  try { released = owner.release(); } catch (error) { releaseThrew = error; }
  fs.readFileSync = realReadFileSync;

  check("cr-unlink-toctou-swap-actually-happened", contenderToken !== null,
    "test setup failed: the monkey-patched contender swap never ran");
  check("cr-unlink-toctou-release-does-not-throw", releaseThrew === null,
    `release() should complete cleanly (reporting no-op) rather than throw when the path ` +
    `was swapped out from under it; got ${releaseThrew && releaseThrew.message}`);
  check("cr-unlink-toctou-release-reports-false", released === false,
    `release() must report false (nothing of ours was removed), not true, when the file ` +
    `it found on the path was not the one it verified moments earlier; got ${released}`);

  const onDisk = JSON.parse(fs.readFileSync(claimPath(root), "utf8"));
  check("cr-unlink-toctou-contenders-claim-not-deleted", onDisk.claim_token === contenderToken,
    `the contender's live claim must survive the race, not be deleted by the stale ` +
    `owner's release(); got token ${onDisk.claim_token}, expected ${contenderToken}`);
}

async function main() {
  ac1_namedRefusalNotGeneric();
  ac3_liveClaimNeverDisplaced();
  ac3_clockSkewDecisionTable();
  ac4_healthCheckSurface();
  ac4_corruptClaimFailsClosed();
  clockEnforcement_requireExplicitFlag();
  clockEnforcement_malformedClockUnconditional();
  clockEnforcement_auditBreadcrumbOrdering();
  clockEnforcement_selftestAuditBreadcrumb();
  crCodex_pidRequiredInSchema();
  crCodex_instanceIdReuseByDifferentLivePid();
  crCodex_defaultHostIdFailsClosed();
  crCodex_clockInstantValidated();
  crCodex_releaseKeepsTokenOnThrow();
  await crCodex_heartbeatSurfacesClaimLoss();
  crCodex_renewToctouDoesNotClobberContender();
  crCodex_unlinkIfTokenDoesNotClobberSwappedFile();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIPPED").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main();
