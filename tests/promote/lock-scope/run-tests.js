#!/usr/bin/env node
"use strict";

/* Does `promote()` hold the state-store lock while it copies and hashes the tree?
 *
 * It used to. The lock is only renewed at the durable writes inside `_commit`, so a holder
 * doing long work that never touches the store renews nothing -- and staging is a full
 * recursive copy plus two full-tree hash passes. On a large tree the hold outlasted the 30s
 * lease, a second promoter legally stole the lock, and BOTH then reached `appendEntry` on
 * the permanent adoption log before either touched the store and found out it had been
 * superseded.
 *
 * The property under test is not "staging is fast". It is "the lock is available to someone
 * else while staging runs", which is a thing that can be observed rather than inferred.
 *
 * HOW, without a sleep racing a copy: a preload wraps `fs.cpSync` so the child announces it
 * has entered the copy and then blocks until the parent releases it. The parent observes the
 * announcement, tries to take the state lock, records what happened, and releases the child.
 * No timing assumption survives in the assertion -- the handshake is file-based, and the
 * only deadline is the harness's own, which is reported as INCONCLUSIVE rather than as a
 * product verdict if it is ever hit.
 *
 * Reading the source for `acquire` appearing after `stageUnlocked` would be cheaper and
 * would prove nothing: that is a substring standing in for a behaviour, which is the defect
 * class this repository keeps finding. */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const { harnessDeadline } = require("../../_harness/deadline.js");

const ROOT = path.resolve(__dirname, "../../..");
const PROMOTE = path.join(ROOT, "scripts", "promote.js");
const { createStore } = require(path.join(ROOT, "scripts", "state-store.js"));
const promoteModule = require(PROMOTE);

let failures = 0;
const results = [];

function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : `${status} ${name}+${reason || "unknown"}`);
  results.push({ name, status });
  if (status === "FAIL") failures++;
}
function check(name, cond, reason) { record(name, cond ? "PASS" : "FAIL", reason); }
function inconclusive(name, reason) {
  /* Fail-closed but never attributed to the product: the convention from
   * tests/harness-honesty/starvation/. A handshake that never completes is a harness fact. */
  record(name, "FAIL", `INCONCLUSIVE (harness): ${reason}`);
}

function mkRoot(tag) { return fs.mkdtempSync(path.join(os.tmpdir(), `gs-lockscope-${tag}-`)); }
function paths(root) {
  const state = path.join(root, ".graphsmith", "state");
  return { state, staging: path.join(root, ".graphsmith", "staging"), lock: path.join(state, "state.lock") };
}

function fixture(tag) {
  const root = mkRoot(tag);
  promoteModule.__testing.createFixture(root);
  return root;
}

/* ---------- the headline: the lock is free while staging runs ---------- */

const PRELOAD = `
const fs = require("fs");
const announce = process.env.GS_STAGE_ANNOUNCE;
const release = process.env.GS_STAGE_RELEASE;
const realCp = fs.cpSync;
fs.cpSync = function (...args) {
  fs.writeFileSync(announce, "in-cpSync");
  const until = Date.now() + 60000;
  while (!fs.existsSync(release) && Date.now() < until) {
    try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5); } catch (e) {}
  }
  return realCp.apply(this, args);
};
`;

function lockIsFreeDuringStaging() {
  const name = "state-lock-is-acquirable-while-a-promotion-is-staging";
  const root = fixture("free");
  const p = paths(root);
  const announce = path.join(root, "announce");
  const release = path.join(root, "release");
  const preloadFile = path.join(root, "preload.js");
  fs.writeFileSync(preloadFile, PRELOAD);

  /* The driver reports through a FILE, not an exit code. This whole check runs in a
   * synchronous busy-wait, so Node's event loop never turns and `child.exitCode` stays null
   * however long the child has actually been finished -- an earlier version of this case
   * failed on exactly that and reported a healthy promotion as broken. A file is visible to
   * `existsSync` without the loop. */
  const outcome = path.join(root, "outcome");
  const driver = path.join(root, "driver.js");
  fs.writeFileSync(driver, `
    const fs = require("fs");
    const { promote, __testing } = require(${JSON.stringify(PROMOTE)});
    let result;
    try { result = "STATE:" + promote(__testing.testPacket(${JSON.stringify(root)}, "slow")).state; }
    catch (e) { result = "CODE:" + e.code + " " + e.message; }
    fs.writeFileSync(${JSON.stringify(outcome)}, result);
  `);

  const child = spawn(process.execPath, ["--require", preloadFile, driver], {
    env: { ...process.env, GS_STAGE_ANNOUNCE: announce, GS_STAGE_RELEASE: release, GRAPHSMITH_TEST_MODE: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += d; });

  const deadline = Date.now() + harnessDeadline(30000);
  while (!fs.existsSync(announce) && Date.now() < deadline && child.exitCode === null) {
    try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10); } catch (e) {}
  }

  if (!fs.existsSync(announce)) {
    try { fs.writeFileSync(release, "go"); } catch (e) {}
    try { child.kill("SIGKILL"); } catch (e) {}
    inconclusive(name, `the child never reached fs.cpSync (exit=${child.exitCode}, stderr=${stderr.slice(0, 200)})`);
    return;
  }

  /* The child is inside the tree copy, right now. Before the split it held the lock here. */
  let observed;
  try {
    const store = createStore(root, { leaseMs: 30000 });
    store._testing.acquireLock();
    observed = "ACQUIRED";
    try { store._testing.releaseLock(store._heldOwnerToken); } catch (e) {}
  } catch (error) {
    observed = error.code || "UNKNOWN";
  }

  fs.writeFileSync(release, "go");
  const done = Date.now() + harnessDeadline(60000);
  while (!fs.existsSync(outcome) && Date.now() < done) {
    try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10); } catch (e) {}
  }

  check(name, observed === "ACQUIRED",
    `while the promotion was inside fs.cpSync the state lock was ${observed}, so staging still ` +
    "holds it -- a copy longer than the lease can still be stolen from mid-transaction");

  if (!fs.existsSync(outcome)) {
    try { child.kill("SIGKILL"); } catch (e) {}
    inconclusive("the-staging-promotion-still-completes-after-the-lock-was-taken-and-released",
      `the promotion never reported an outcome (stderr: ${stderr.slice(0, 200)})`);
    return;
  }
  const reported = fs.readFileSync(outcome, "utf8").trim();
  check("the-staging-promotion-still-completes-after-the-lock-was-taken-and-released",
    reported === "STATE:DONE",
    `the promotion reported ${JSON.stringify(reported)}. Taking and releasing the state lock ` +
    "while another promotion is staging must not break that promotion.");
}

/* ---------- recovery must not delete work someone is still doing ---------- */

function recoverSparesALiveStagingDirectory() {
  const root = fixture("spare");
  const p = paths(root);
  fs.mkdirSync(p.staging, { recursive: true });

  const live = path.join(p.staging, "aaaaaaaaaaaaaaaa.deadbeefdeadbeef");
  fs.mkdirSync(live, { recursive: true });
  fs.writeFileSync(path.join(live, ".claim.json"), `${JSON.stringify({
    schema_version: "1.0", txid: "aaaaaaaaaaaaaaaa", claim: "deadbeefdeadbeef", pid: process.pid,
  })}\n`);
  fs.writeFileSync(path.join(live, "marker"), "work in progress");

  const dead = path.join(p.staging, "bbbbbbbbbbbbbbbb.cafecafecafecafe");
  fs.mkdirSync(dead, { recursive: true });
  fs.writeFileSync(path.join(dead, ".claim.json"), `${JSON.stringify({
    schema_version: "1.0", txid: "bbbbbbbbbbbbbbbb", claim: "cafecafecafecafe", pid: 999999,
  })}\n`);

  const unclaimed = path.join(p.staging, "cccccccccccccccc.0123456789abcdef");
  fs.mkdirSync(unclaimed, { recursive: true });

  promoteModule.recover(root);

  /* THE case the whole restructure turns on. `cleanupAbandonedStaging` deleted every
   * `.staging-*` it found, which was safe only while staging held the lock. Unlocked
   * staging plus a glob delete means a concurrent recover() erases live work. */
  check("recover-spares-a-staging-directory-whose-owner-is-alive",
    fs.existsSync(live) && fs.existsSync(path.join(live, "marker")),
    "recover() deleted a staging directory claimed by a live process");

  check("recover-reclaims-a-staging-directory-whose-owner-is-dead",
    !fs.existsSync(dead),
    "a staging directory owned by a pid that cannot be running was left behind, so an " +
    "interrupted promotion leaks disk with no command able to clear it");

  /* A directory created but never claimed is the crash window between `mkdirSync` and the
   * claim write. Nobody can be running against it. Refusing forever would grow the disk
   * with nothing able to clear it, which is the worse failure. */
  check("recover-reclaims-an-unclaimed-staging-directory",
    !fs.existsSync(unclaimed),
    "a staging directory with no claim file survived reclamation");
}

/* ---------- a crash during staging must leave nothing that blocks the next run ---------- */

function crashDuringStagingLeavesAReclaimableOrphan() {
  const root = fixture("crash");
  const p = paths(root);
  const preloadFile = path.join(root, "crash-preload.js");
  fs.writeFileSync(preloadFile, `
    const fs = require("fs");
    const realCp = fs.cpSync;
    fs.cpSync = function (...args) { const r = realCp.apply(this, args); process.kill(process.pid, "SIGKILL"); return r; };
  `);
  const driver = path.join(root, "crash-driver.js");
  fs.writeFileSync(driver, `
    const { promote, __testing } = require(${JSON.stringify(PROMOTE)});
    try { promote(__testing.testPacket(${JSON.stringify(root)}, "boom")); } catch (e) {}
  `);

  const r = require("child_process").spawnSync(process.execPath, ["--require", preloadFile, driver], {
    env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" }, timeout: harnessDeadline(60000), encoding: "utf8",
  });
  if (r.error && r.error.code === "ETIMEDOUT") {
    inconclusive("crash-during-staging-leaves-no-journal-record", "the crash driver exceeded the harness timeout");
    return;
  }

  /* Nothing was promised, so nothing should be owed. A crash before TX_BEGIN must not make
   * the next promotion demand a recover(). */
  const journal = path.join(p.state, "journal.jsonl");
  const raw = fs.existsSync(journal) ? fs.readFileSync(journal, "utf8") : "";
  check("crash-during-staging-writes-no-journal-record",
    !/TX_BEGIN/.test(raw),
    "a crash during staging left a TX_BEGIN, so the next promotion is blocked on recovering " +
    "a transaction that never began");

  const before = fs.existsSync(p.staging) ? fs.readdirSync(p.staging) : [];
  promoteModule.recover(root);
  const after = fs.existsSync(p.staging) ? fs.readdirSync(p.staging) : [];
  check("crash-during-staging-is-reclaimed-by-recover",
    after.length === 0,
    `staging still holds ${JSON.stringify(after)} after recover() (was ${JSON.stringify(before)})`);

  /* And the store is usable afterwards, which is the point of reclaiming at all. */
  let promoted = null;
  try { promoted = promoteModule.promote(promoteModule.__testing.testPacket(root, "after-crash")); }
  catch (error) { promoted = { state: `THREW ${error.code}` }; }
  check("a-promotion-succeeds-after-a-staging-crash",
    promoted && promoted.state === "DONE",
    `the next promotion returned ${JSON.stringify(promoted)}`);
}

/* ---------- staging against a base that moved must not publish ---------- */

function stagingAgainstAStaleBaseRefuses() {
  const name = "a-tree-staged-against-a-superseded-ACTIVE-is-refused";
  const root = fixture("stale");
  /* Land a real promotion so ACTIVE moves, then hand promote() a staged plan built against
   * the OLD ACTIVE by rewriting nothing -- the second promotion re-reads ACTIVE in phase 1,
   * so the honest way to force the race is to move ACTIVE between phase 1 and phase 2. That
   * is what the preload does: it advances ACTIVE from inside the copy, i.e. after phase 1
   * read it and before phase 2 re-reads it. */
  const preloadFile = path.join(root, "stale-preload.js");
  fs.writeFileSync(preloadFile, `
    const fs = require("fs");
    const realCp = fs.cpSync;
    let fired = false;
    fs.cpSync = function (...args) {
      const r = realCp.apply(this, args);
      if (!fired) {
        fired = true;
        const active = ${JSON.stringify(path.join(root, ".graphsmith", "evolvable", "ACTIVE"))};
        const raw = JSON.parse(fs.readFileSync(active, "utf8"));
        raw.txid = "0000000000000000";
        fs.writeFileSync(active, JSON.stringify(raw));
      }
      return r;
    };
  `);
  const driver = path.join(root, "stale-driver.js");
  fs.writeFileSync(driver, `
    const { promote, __testing } = require(${JSON.stringify(PROMOTE)});
    try { const r = promote(__testing.testPacket(${JSON.stringify(root)}, "stale")); console.log("STATE:" + r.state); }
    catch (e) { console.log("CODE:" + e.code); }
  `);
  const r = require("child_process").spawnSync(process.execPath, ["--require", preloadFile, driver], {
    env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" }, timeout: harnessDeadline(60000), encoding: "utf8",
  });
  if (r.error && r.error.code === "ETIMEDOUT") { inconclusive(name, "driver exceeded the harness timeout"); return; }

  const out = `${r.stdout || ""}`.trim();
  check(name, /CODE:(STALE_STAGING|HALT|CORRUPT_STATE|STALE_PROPOSAL)/.test(out),
    `expected a refusal once ACTIVE moved during staging, got ${JSON.stringify(out)} ` +
    `(stderr ${String(r.stderr || "").slice(0, 200)}). Publishing a tree built from a base ` +
    "that is no longer current silently drops whatever landed in between.");
}

/* ---------- a refusal must not cost a tree copy, and must say the right thing ---------- */

function preconditionsRefuseBeforeStaging() {
  /* Moving staging out of the lock also moved it in FRONT of the cheap precondition checks,
   * and staging is not read-only -- `applyEdits` rewrites the copied tree. A second
   * promotion of the same packet then died with "Edit anchor must occur exactly once" from
   * inside staging instead of WINDOW_EXISTS from the top: the caller was told the wrong
   * thing, and only after paying for a full tree copy and two hash passes.
   *
   * It was caught by tests/promote/{deepseek,grok}, which is lucky rather than designed --
   * neither is about lock scope, and a future change to this file would not run them first.
   * Pinned here, next to the change that caused it. */
  const root = fixture("precond");
  const first = promoteModule.promote(promoteModule.__testing.testPacket(root, "one"));
  check("the-first-promotion-lands", first.state === "DONE", `first promotion returned ${JSON.stringify(first)}`);

  const stagingBefore = fs.existsSync(paths(root).staging) ? fs.readdirSync(paths(root).staging) : [];
  let code = null;
  try { promoteModule.promote(promoteModule.__testing.testPacket(root, "two")); }
  catch (error) { code = error.code; }

  check("a-second-promotion-is-refused-with-WINDOW_EXISTS-not-a-staging-error",
    code === "WINDOW_EXISTS",
    `expected WINDOW_EXISTS, got ${code}. A refusal that surfaces as a staging/validation ` +
    "error tells the caller the wrong thing about the wrong thing.");

  const stagingAfter = fs.existsSync(paths(root).staging) ? fs.readdirSync(paths(root).staging) : [];
  check("a-refused-promotion-leaves-no-staging-behind",
    stagingAfter.length <= stagingBefore.length,
    `staging grew from ${JSON.stringify(stagingBefore)} to ${JSON.stringify(stagingAfter)} on a ` +
    "promotion that was refused -- the refusal should have happened before any copying");
}

function main() {
  lockIsFreeDuringStaging();
  preconditionsRefuseBeforeStaging();
  recoverSparesALiveStagingDirectory();
  crashDuringStagingLeavesAReclaimableOrphan();
  stagingAgainstAStaleBaseRefuses();

  const passed = results.filter((r) => r.status === "PASS").length;
  console.log(`SUMMARY passed=${passed} failed=${failures} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
