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

const ROOT = path.resolve(__dirname, "../../..");
const { WriterClaim, decideOnExisting, CLAIM_CLOCK_SKEW_TOLERANCE_MS } = require(path.join(ROOT, "scripts", "writer-claim.js"));
const { createManualClock } = require("../../_harness/clock.js");

const HEARTBEAT_MS = 1000;
const STALE_AFTER_MS = HEARTBEAT_MS * 3;
const DEAD_PID = 999999; // above default pid_max everywhere in the CI matrix; see clock-skew's own note

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

function main() {
  ac1_namedRefusalNotGeneric();
  ac3_liveClaimNeverDisplaced();
  ac3_clockSkewDecisionTable();
  ac4_healthCheckSurface();
  ac4_corruptClaimFailsClosed();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
