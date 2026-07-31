#!/usr/bin/env node
/* Lease determinism — the mechanical replacement for "I read the file and it looked fine".
 *
 * THE DEFECT THIS ENDS
 *
 * Six defects on this branch shared one shape: a test needed a run to still be live (or to
 * have just lapsed) when it asserted, and established that by hoping the machine was fast
 * enough. Every StateStore operation sweeps lapsed leases before doing anything, and a
 * lock+fsync cycle costs ~200ms on a contended Windows runner, so the hope failed and the
 * case reported losing that race as a PRODUCT defect. One accused a fail-closed refusal of
 * letting a window close over active slots. Another accused the component's own sweep of
 * missing a run it had already swept.
 *
 * WHY A SWEEP RATHER THAN MORE GUARDS
 *
 * The previous answer was per-case honesty guards: detect the lost race, report
 * INCONCLUSIVE. That is containment, and it has two failure modes this repo has already
 * hit. First, judgement about WHICH cases need a guard was wrong repeatedly -- the engineer
 * read the neighbouring case in this very directory, judged it safe, and it was the next
 * defect. Second, a guard is a place a real bug can hide: one draft checked a condition
 * true in BOTH branches and would have swallowed a genuine "sweepExpired returns the wrong
 * ids" defect.
 *
 * So the fix was structural: `StateStore` takes an injected lease clock, and lease-dependent
 * tests CHOOSE their instants instead of racing for them. This file is what makes that
 * claim checkable rather than asserted.
 *
 * WHAT IT PROVES, PRECISELY
 *
 *   CHECK 1 (execution)  Every target suite passes with
 *                        GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK=1, under which StateStore
 *                        THROWS if constructed without an explicit clock. This is a runtime
 *                        guarantee, not a source heuristic: it sees through aliasing, helper
 *                        factories, and stores built inside spawned worker scripts written
 *                        to temp files -- all three of which the target suites do, and none
 *                        of which a grep can follow. It also holds on every platform, which
 *                        closes the Windows-only blind spot a Linux-only audit cannot see.
 *
 *   CHECK 2 (inventory)  The residual wall-clock surface cannot grow silently. Some cases
 *                        legitimately need the real clock -- a manual clock cannot cross a
 *                        process boundary, and lock staleness compares against an mtime the
 *                        OS wrote. Those opt in visibly via systemLeaseClock(), and every
 *                        opt-in must be declared here. A new one fails this suite until it
 *                        is declared and justified.
 *
 *   CHECK 3 (control)    The enforcement in CHECK 1 must actually fire. A gate that cannot
 *                        fail proves nothing, so this constructs a store without a clock
 *                        under the flag and requires the documented refusal.
 *
 * WHAT IT DOES NOT PROVE
 *
 * That a case declared under CHECK 2 is safe. Those are the residual set, and real
 * filesystem-latency injection is their instrument -- see the nightly sweep. This file
 * bounds that set and proves everything outside it is deterministic by construction.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const ENV_FLAG = "GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK";

/* Suites that build a StateStore. Discovered rather than hand-listed, so a new
 * state-store suite is covered the day it lands instead of the day someone remembers. */
function discoverTargets() {
  const base = path.join(ROOT, "tests", "state-store");
  const found = [];
  for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const candidate = path.join(base, entry.name, "run-tests.js");
    if (fs.existsSync(candidate)) found.push(path.relative(ROOT, candidate).split(path.sep).join("/"));
  }
  return found.sort();
}

/* CHECK 2's declared residual set: cases that must keep the real clock, and why.
 * Keyed by suite; the value is the number of distinct real-clock opt-ins expected in it.
 * A mismatch in EITHER direction fails -- a new undeclared opt-in is the regression this
 * catches, and a stale declaration means the justification below no longer describes the
 * code. */
const DECLARED_REAL_CLOCK_USES = {
  "tests/state-store/grok/run-tests.js": {
    count: 6,
    why: [
      "crash.journal-roll-forward-monotonic-no-tear and " +
        "concurrency.two-process-register-deregister: both spawn children. A clock thunk does " +
        "not survive a spawn, and a parent on a frozen clock reading records a child stamped " +
        "with the real one is strictly worse -- the child's sweep sees every parent-written " +
        "lease as expired by decades and terminalizes it. Measured, not assumed: that mismatch " +
        "made a crash-injection hook fire on the recovery sweep instead of on the operation " +
        "under test. Both assert journal INVARIANTS, never lease liveness, at a 10-minute lease.",
      "CHILD_REAL_CLOCK, injected into the two generated worker scripts so the children are " +
        "explicit about their clock too.",
    ],
  },
  "tests/state-store/deepseek/run-tests.js": {
    count: 5,
    why: [
      "test 3 (crash recovery) and test 7 (two-process contention), both Windows-only and " +
        "both spawning children -- same reasoning as grok, same 10-minute lease, same " +
        "invariant-only assertions. These are exactly the cases a Linux audit cannot see, " +
        "which is why CHECK 1 is runtime enforcement rather than a source scan.",
      "CHILD_REAL_CLOCK, injected into the two generated worker scripts.",
    ],
  },
};

const results = [];
function record(name, status, detail) {
  const line = status === "PASS" ? `PASS ${name}${detail ? " - " + detail : ""}`
    : status === "SKIPPED" ? `SKIPPED ${name} - ${detail}`
      : `FAIL ${name} - ${detail}`;
  console.log(line);
  results.push({ name, status, detail: detail || "" });
}

/* ---- CHECK 1: every target passes with wall-clock lease construction forbidden ---- */

function checkEnforcedRun(target) {
  const name = `enforced-clock/${target}`;
  const started = Date.now();
  const res = spawnSync(process.execPath, [path.join(ROOT, target)], {
    cwd: ROOT,
    encoding: "utf8",
    env: Object.assign({}, process.env, { [ENV_FLAG]: "1" }),
    maxBuffer: 64 * 1024 * 1024,
    timeout: 900000,
  });
  const out = String(res.stdout || "") + String(res.stderr || "");

  if (res.error && res.error.code === "ETIMEDOUT") {
    record(name, "FAIL", "INCONCLUSIVE (harness): the target did not finish inside this " +
      "sweep's own timeout, so nothing was observed about its clock discipline");
    return;
  }
  /* The specific refusal, wherever it surfaced -- thrown in-process, or from a spawned
   * worker whose stderr the target relayed. Either way it means a store was built on the
   * wall clock somewhere on the executed path. */
  if (out.indexOf("LEASE_CLOCK_REQUIRED") !== -1 || out.indexOf("without an explicit lease clock") !== -1) {
    const line = out.split("\n").filter((l) => l.indexOf("lease clock") !== -1)[0] || "";
    record(name, "FAIL",
      "WIRING GAP: a StateStore was constructed without an explicit lease clock while " +
      ENV_FLAG + "=1, so some executed path still derives lease expiry from the wall clock " +
      "and can be raced by a slow disk. First refusal: " + line.trim().slice(0, 300));
    return;
  }
  if (res.status !== 0) {
    record(name, "FAIL",
      `the target exited ${res.status} under ${ENV_FLAG}=1 while passing without it, so the ` +
      "flag changed its behaviour in some way other than the documented refusal. Tail: " +
      out.split("\n").filter(Boolean).slice(-3).join(" | ").slice(0, 300));
    return;
  }
  record(name, "PASS", `no wall-clock lease construction on any executed path (${Date.now() - started}ms)`);
}

/* ---- CHECK 2: the residual real-clock set is declared and has not grown ---- */

function checkDeclaredResidual(target) {
  const name = `declared-residual/${target}`;
  const src = fs.readFileSync(path.join(ROOT, target), "utf8");
  const uses = (src.match(/systemLeaseClock|CHILD_REAL_CLOCK/g) || []).length;
  const declared = DECLARED_REAL_CLOCK_USES[target];
  if (!declared) {
    if (uses === 0) { record(name, "PASS", "no real-clock opt-in, nothing to declare"); return; }
    record(name, "FAIL",
      `${uses} real-clock opt-in(s) with no entry in DECLARED_REAL_CLOCK_USES. Every case that ` +
      "keeps the wall clock is residual surface for the defect this suite exists to end; it has " +
      "to be named and justified here, not merely written.");
    return;
  }
  if (uses !== declared.count) {
    record(name, "FAIL",
      `real-clock opt-ins changed: found ${uses}, declared ${declared.count}. If this is a new ` +
      "case keeping the wall clock, justify it in DECLARED_REAL_CLOCK_USES and say why a manual " +
      "clock cannot serve. If an opt-in was removed, drop the declaration so the justification " +
      "does not outlive the code it describes.");
    return;
  }
  record(name, "PASS", `${uses} declared real-clock opt-in(s), unchanged`);
}

/* ---- CHECK 3: the enforcement can actually fail ---- */

function checkEnforcementFires() {
  const name = "control/enforcement-actually-fires";
  const probe = [
    'const { StateStore } = require(' + JSON.stringify(STATE_STORE) + ');',
    'const os = require("os"), fs = require("fs"), path = require("path");',
    'const d = fs.mkdtempSync(path.join(os.tmpdir(), "lease-ctl-"));',
    'try { new StateStore(d); console.log("NO_THROW"); }',
    'catch (e) { console.log("THREW:" + e.code); }',
  ].join("\n");
  const res = spawnSync(process.execPath, ["-e", probe], {
    cwd: ROOT, encoding: "utf8",
    env: Object.assign({}, process.env, { [ENV_FLAG]: "1" }),
  });
  const out = String(res.stdout || "").trim();
  if (out.indexOf("THREW:LEASE_CLOCK_REQUIRED") === -1) {
    record(name, "FAIL",
      `constructing a StateStore with no clock under ${ENV_FLAG}=1 did not produce the ` +
      `documented refusal (got ${JSON.stringify(out || String(res.stderr || "").slice(0, 200))}). ` +
      "CHECK 1 is therefore vacuous: it would pass whether or not the targets chose their clocks.");
    return;
  }
  /* And the other direction: the flag must be inert when off, or every ordinary run of the
   * product would be refusing to start. */
  const off = spawnSync(process.execPath, ["-e", probe], { cwd: ROOT, encoding: "utf8" });
  if (String(off.stdout || "").trim() !== "NO_THROW") {
    record(name, "FAIL",
      "the enforcement fired with the flag OFF, so it is not test-only and production " +
      `construction is affected (got ${JSON.stringify(String(off.stdout || "").trim())})`);
    return;
  }
  record(name, "PASS", "refuses without a clock under the flag, inert without it");
}

/* ---- main ---- */

function main() {
  const targets = discoverTargets();
  console.log(`lease determinism: ${targets.length} state-store suite(s) discovered\n`);
  if (targets.length === 0) {
    record("discovery", "FAIL",
      "no tests/state-store/*/run-tests.js found. This sweep is the only mechanical proof that " +
      "lease preconditions are chosen rather than raced; discovering nothing makes it vacuous.");
  }

  checkEnforcementFires();
  for (const t of targets) checkDeclaredResidual(t);
  for (const t of targets) checkEnforcedRun(t);

  const failed = results.filter((r) => r.status === "FAIL");
  const passed = results.filter((r) => r.status === "PASS");
  console.log(`\nSUMMARY PASS=${passed.length} FAIL=${failed.length}`);
  if (failed.length) {
    console.log("FAILING: " + failed.map((r) => r.name).join(", "));
    process.exit(1);
  }
}

main();
