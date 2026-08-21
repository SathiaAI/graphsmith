#!/usr/bin/env node
/* AC-2 from .plans/v0.5.0/GATEWAY-MULTI-INSTANCE-HANDOFF.md §6.4 -- "the single
 * highest-priority test in the whole plan": starting two instances against the SAME
 * directory over a simulated shared/networked volume must fail loudly for the second
 * instance -- NEVER silently proceed, NEVER corrupt either chain -- even under injected
 * cross-host clock skew. This suite is split out from tests/state-store/writer-claim/
 * on purpose, the same way tests/state-store/clock-skew/ is split out from the general
 * state-store suites: this is the scenario most likely to occur BY ACCIDENT (§4, danger
 * 3 -- the ordinary Kubernetes `replicas: 2` default pointed at one shared volume), so
 * it gets undiluted, dedicated coverage rather than being one case among many.
 *
 * "Simulated shared/networked volume": scripts/writer-claim.js never talks to a real
 * network filesystem here (this repo's CI does not have one) -- the simulation is a
 * single directory on local disk, exactly as an NFS mount or shared volume would
 * present to both instances, with each instance's `hostId` and clock injected
 * independently to stand in for two genuinely different hosts. That is precisely the
 * seam the mechanism's design uses to answer "is this the same host" (see the module
 * header in scripts/writer-claim.js) -- the ONLY signal that can be trusted, since
 * mtime/wall-clock comparisons across two real hosts are exactly what danger 2 (§4)
 * says cannot be trusted. "Injected cross-host clock skew" is a large, deliberately
 * unusual clock offset between the two instances' own clocks (hours, not milliseconds)
 * -- large enough that a naive same-host-style staleness comparison would misfire
 * badly in either direction, which is exactly what proves the mechanism does not
 * attempt that comparison at all across hosts. */

"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const { WriterClaim, decideOnExisting, claimPath } = require(path.join(ROOT, "scripts", "writer-claim.js"));
const WORKER = path.join(__dirname, "_worker.js");

const DEAD_PID = 999999; // above default pid_max everywhere in the CI matrix

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
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-writer-claim-shared-${prefix}-`));
}

function planClaim(root, overrides) {
  fs.mkdirSync(root, { recursive: true });
  const record_ = {
    schema_version: "1.0",
    host_id: "host-A-real-owner",
    instance_id: "1".repeat(32),
    pid: process.pid,
    claimed_at: Date.now(),
    renewed_at: Date.now(),
    claim_token: "c".repeat(32),
    ...overrides,
  };
  fs.writeFileSync(claimPath(root), JSON.stringify(record_));
  return record_;
}

function strayTempFiles(root) {
  return fs.readdirSync(root).filter((entry) => entry.includes(".new-") || entry.includes(".tmp-"));
}

/* -----------------------------------------------------------------------------------
 * Direct decision-table checks: a foreign host_id refuses UNCONDITIONALLY, regardless
 * of how the injected clock skew makes the claim's apparent age look -- far in the
 * past (would be stealable if this were a same-host check), far in the future (would
 * be a "clock skew" case if this were a same-host check), or a dead pid (decisive for
 * a same-host claim, irrelevant for a foreign-host one). No staleness arithmetic is
 * attempted at all once host_id differs -- these cases prove that by construction.
 * --------------------------------------------------------------------------------- */

function foreignHostNeverStealableUnderAnySkew() {
  const now = 1_700_000_500_000;
  const localCtx = (skewMs, overrides) => decideOnExisting(
    { host_id: "host-B-shared-volume", instance_id: "owner-on-b".padEnd(32, "1"), pid: DEAD_PID, claimed_at: now - 60_000, renewed_at: now + skewMs, ...overrides },
    { localHostId: "host-A-this-instance", localInstanceId: "attacker".padEnd(32, "0"), now, staleAfterMs: 3000, skewToleranceMs: 5000 },
  );

  const cases = [
    ["renewed-far-in-the-past", -365 * 24 * 60 * 60 * 1000],   // would be trivially stealable same-host
    ["renewed-far-in-the-future", 365 * 24 * 60 * 60 * 1000],  // would be a same-host "clock skew" case
    ["renewed-just-now", 0],
    ["renewed-inside-normal-tolerance", 1000],
    ["renewed-outside-normal-tolerance", 30_000],
  ];
  for (const [label, skewMs] of cases) {
    const decision = localCtx(skewMs);
    check(`ac2-foreign-host-refuses-${label}`,
      decision.outcome === "refuse" && decision.code === "WRITER_CLAIM_FOREIGN_HOST",
      `expected refuse/WRITER_CLAIM_FOREIGN_HOST for skew ${skewMs}ms, got ${JSON.stringify(decision)}`);
  }

  // Same check again with a LIVE pid (this test process's own) on the foreign host --
  // liveness must not matter either; only host identity gates this branch.
  const liveForeign = decideOnExisting(
    { host_id: "host-B-shared-volume", instance_id: "owner-on-b".padEnd(32, "1"), pid: process.pid, claimed_at: now - 60_000, renewed_at: now - 999_999_999 },
    { localHostId: "host-A-this-instance", localInstanceId: "attacker".padEnd(32, "0"), now, staleAfterMs: 3000, skewToleranceMs: 5000 },
  );
  check("ac2-foreign-host-refuses-even-with-live-pid-and-huge-past-skew",
    liveForeign.outcome === "refuse" && liveForeign.code === "WRITER_CLAIM_FOREIGN_HOST",
    `expected refuse/WRITER_CLAIM_FOREIGN_HOST, got ${JSON.stringify(liveForeign)}`);
}

/* -----------------------------------------------------------------------------------
 * End-to-end (real fs, real WriterClaim.acquire()) on a single shared directory: plant
 * a claim as if written by a genuinely different host under large injected clock
 * skew, then attempt to acquire from "this host" and confirm: loud, specific refusal;
 * the claim file is completely untouched (never corrupted, never silently replaced);
 * no stray temp files are left behind (mirrors state-store.js's own atomicity check).
 * --------------------------------------------------------------------------------- */

function endToEndSharedVolumeNeverSilentlyProceeds() {
  const skews = [
    ["clock-far-behind", -6 * 60 * 60 * 1000],   // this "host" thinks the remote claim is from 6h in its future
    ["clock-far-ahead", 6 * 60 * 60 * 1000],     // this "host" thinks the remote claim is 6h stale
  ];
  for (const [label, skewMs] of skews) {
    const root = freshRoot(`e2e-${label}`);
    const planted = planClaim(root, { host_id: "host-remote-nfs-writer", renewed_at: Date.now() + skewMs });
    const rawBefore = fs.readFileSync(claimPath(root), "utf8");

    const local = new WriterClaim(root, { hostId: "host-this-machine", instanceId: "2".repeat(32) });
    let thrown = null;
    try { local.acquire(); } catch (error) { thrown = error; }

    check(`ac2-e2e-${label}-refuses`, Boolean(thrown), "acquisition against a foreign-host claim under clock skew must throw, never succeed silently");
    check(`ac2-e2e-${label}-specific-code`, Boolean(thrown) && thrown.code === "WRITER_CLAIM_FOREIGN_HOST",
      `expected WRITER_CLAIM_FOREIGN_HOST, got ${thrown && thrown.code}`);
    check(`ac2-e2e-${label}-names-both-hosts`,
      Boolean(thrown) && thrown.message.includes("host-remote-nfs-writer") && thrown.message.includes("host-this-machine"),
      "refusal must name both the foreign claim's host and this host");

    const rawAfter = fs.readFileSync(claimPath(root), "utf8");
    check(`ac2-e2e-${label}-claim-file-untouched`, rawAfter === rawBefore, "the original claim record must be byte-identical after a refused acquisition attempt");
    check(`ac2-e2e-${label}-no-stray-temp-files`, strayTempFiles(root).length === 0, `stray temp file(s) left behind: ${strayTempFiles(root).join(", ")}`);
  }
}

/* -----------------------------------------------------------------------------------
 * Real multi-process race over ONE shared directory (not just sequential in-process
 * calls) -- two independent OS processes, each stamped with a DIFFERENT hostId to
 * simulate two real hosts pointed at one shared/networked volume, both attempting
 * acquire() at nearly the same instant. The invariant: EXACTLY one process reports
 * success; the other is refused with a specific, attributable error; the on-disk
 * claim afterward is schema-valid and matches whichever process actually won. Never
 * both, never neither, never a corrupt/partial file. Run across several trials, per
 * this repo's own convention (see tests/state-store/grok's concurrency battery) that
 * a single race outcome does not prove the invariant holds under real scheduling
 * variance.
 * --------------------------------------------------------------------------------- */

function runWorker(stateDir, hostId, instanceId) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [WORKER, stateDir, hostId, instanceId], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.on("close", (code) => {
      let parsed = null;
      try { parsed = JSON.parse(out.trim().split("\n").pop()); } catch (error) { /* leave null */ }
      resolve({ exitCode: code, parsed });
    });
  });
}

async function realProcessRaceOverSharedDirectory() {
  const TRIALS = 5;
  for (let trial = 0; trial < TRIALS; trial++) {
    const root = freshRoot(`race-${trial}`);
    fs.mkdirSync(root, { recursive: true });

    const [a, b] = await Promise.all([
      runWorker(root, "host-A", "a".repeat(32)),
      runWorker(root, "host-B", "b".repeat(32)),
    ]);

    const outcomes = [a, b];
    const wins = outcomes.filter((o) => o.parsed && o.parsed.ok === true);
    const losses = outcomes.filter((o) => o.parsed && o.parsed.ok === false);

    check(`ac2-race-${trial}-exactly-one-winner`, wins.length === 1,
      `expected exactly one winner, got ${wins.length}: ${JSON.stringify(outcomes)}`);
    check(`ac2-race-${trial}-exactly-one-loser`, losses.length === 1,
      `expected exactly one loser, got ${losses.length}: ${JSON.stringify(outcomes)}`);
    if (losses.length === 1) {
      check(`ac2-race-${trial}-loser-specific-code`,
        losses[0].parsed.code === "WRITER_CLAIM_FOREIGN_HOST" || losses[0].parsed.code === "WRITER_CLAIM_HELD",
        `loser must report a specific writer-claim code, got ${losses[0].parsed.code}`);
    }

    // Never-corrupted: the file on disk parses, validates, and names the actual winner.
    let onDisk = null;
    let readError = null;
    try { onDisk = JSON.parse(fs.readFileSync(claimPath(root), "utf8")); } catch (error) { readError = error; }
    check(`ac2-race-${trial}-final-claim-parses`, Boolean(onDisk) && !readError, `claim file did not parse after the race: ${readError && readError.message}`);
    if (onDisk && wins.length === 1) {
      check(`ac2-race-${trial}-final-claim-matches-winner`, onDisk.instance_id === wins[0].parsed.instanceId,
        `on-disk claim instance_id ${onDisk.instance_id} did not match the reported winner ${wins[0].parsed.instanceId}`);
    }
    check(`ac2-race-${trial}-no-stray-temp-files`, strayTempFiles(root).length === 0,
      `stray temp file(s) left behind after the race: ${strayTempFiles(root).join(", ")}`);
  }
}

async function main() {
  foreignHostNeverStealableUnderAnySkew();
  endToEndSharedVolumeNeverSilentlyProceeds();
  await realProcessRaceOverSharedDirectory();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
