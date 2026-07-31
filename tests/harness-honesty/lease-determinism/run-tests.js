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
 *   CHECK 1 (execution)  Every StateStore CONSTRUCTION on an executed path passed an
 *                        explicit clock. Evidence is an append-only audit the store writes
 *                        at construction time, not the target's output: the first version
 *                        grepped stderr for the refusal, and an adversarial review defeated
 *                        it with a single inverted `catch` that swallowed the throw. The
 *                        audit sees through aliasing, helper factories, and stores built
 *                        inside generated worker scripts -- none of which a grep can follow
 *                        -- and it records constructions the platform actually ran.
 *
 *   CHECK 2 (inventory)  The residual real-clock surface cannot grow silently, counted from
 *                        the same audit rather than from substrings in the source. The
 *                        earlier substring count was gameable (an inline
 *                        `{ now: () => Date.now() }` left it unchanged while adding a real
 *                        wall-clock construction) and fragile (it counted the import, a
 *                        constant's definition, and a block of dead code). An untagged
 *                        clock now fails outright: presence of a clock is not the property,
 *                        determinism is.
 *
 *   CHECK 2b (baseline)  Each target is also run with NO flag set. The earlier version
 *                        printed "exited N under the flag while passing without it" without
 *                        ever running it without the flag -- a confident claim about
 *                        something unobserved, which is this directory's own defect class
 *                        one level up.
 *
 *   CHECK 3 (control)    The enforcement must actually fire, and must be inert when off. A
 *                        gate that cannot fail proves nothing.
 *
 * WHAT IT DOES NOT PROVE
 *
 * That a construction declared under CHECK 2 is safe. Those are the residual set -- real
 * filesystem-latency injection is their instrument. This file bounds that set and proves
 * everything outside it chose its instants rather than racing for them.
 *
 * It also proves this only for the platform it RUNS on. That is why it is in the gating
 * manifest across the ubuntu/macos/windows matrix: two of the residual cases are
 * Windows-only and never execute on a Linux leg.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const STATE_STORE = path.join(ROOT, "scripts", "state-store.js");
const ENV_FLAG = "GRAPHSMITH_REQUIRE_EXPLICIT_LEASE_CLOCK";
const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";

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

const results = [];
function record(name, status, detail) {
  const line = status === "PASS" ? `PASS ${name}${detail ? " - " + detail : ""}`
    : status === "SKIPPED" ? `SKIPPED ${name} - ${detail}`
      : `FAIL ${name} - ${detail}`;
  console.log(line);
  results.push({ name, status, detail: detail || "" });
}

/* ---- CHECK 1: no wall-clock construction on any executed path (audit-based) ---- */

/* Detection does NOT read the target's output.
 *
 * The first version of this check grepped stdout+stderr for the refusal message. An
 * adversarial review defeated it in one line: a case in tests/state-store/grok caught ANY
 * exception as its success signal, so the refusal was swallowed, the suite exited 0, and
 * this sweep certified "no wall-clock lease construction on any executed path" while one
 * was happening on that path. A detector a `catch` can defeat is not a detector.
 *
 * StateStore now appends one record per construction to GRAPHSMITH_LEASE_CLOCK_AUDIT,
 * written before the refusal and unconditional on it, so a swallowed throw still leaves
 * the evidence. Children inherit the env var, so constructions inside spawned worker
 * scripts land in the same file -- which is the case a source scan cannot reach at all. */
function readAudit(auditPath) {
  let raw = "";
  try { raw = fs.readFileSync(auditPath, "utf8"); } catch (e) { if (e.code !== "ENOENT") throw e; }
  return raw.split("\n").filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch (e) { return { kind: "unparseable", site: line.slice(0, 120) }; }
  });
}

function runTarget(target, extraEnv) {
  return spawnSync(process.execPath, [path.join(ROOT, target)], {
    cwd: ROOT, encoding: "utf8",
    env: Object.assign({}, process.env, extraEnv),
    maxBuffer: 64 * 1024 * 1024,
    timeout: 900000,
  });
}

function checkEnforcedRun(target) {
  const name = `enforced-clock/${target}`;
  const auditPath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "lease-audit-")), "constructions.jsonl");
  const started = Date.now();
  const res = runTarget(target, { [ENV_FLAG]: "1", [AUDIT_ENV]: auditPath });
  const elapsed = Date.now() - started;

  if (res.error && res.error.code === "ETIMEDOUT") {
    record(name, "FAIL", "INCONCLUSIVE (harness): the target did not finish inside this " +
      "sweep's own timeout, so nothing was observed about its clock discipline");
    return null;
  }

  const audit = readAudit(auditPath);
  if (audit.length === 0) {
    record(name, "FAIL",
      "the audit recorded ZERO StateStore constructions. Either the breadcrumb is not " +
      "wired (in which case this check proves nothing and is worse than absent), or the " +
      "target built no store at all. Both make the PASS this would otherwise print a lie.");
    return null;
  }
  const wall = audit.filter((r) => r.explicit === false || r.kind === "wall");
  if (wall.length) {
    record(name, "FAIL",
      `WIRING GAP: ${wall.length} of ${audit.length} StateStore construction(s) used the ` +
      "wall clock for lease expiry, so those paths can be raced by a slow disk. First: " +
      (wall[0].site || "(no site)"));
    return null;
  }
  /* Exit status is checked only AFTER the audit, so a target that fails for an unrelated
   * reason is not reported as a clock-discipline problem. */
  if (res.status !== 0) {
    record(name, "FAIL",
      `the target exited ${res.status} under ${ENV_FLAG}=1. Every one of its ` +
      `${audit.length} construction(s) passed an explicit clock, so this is NOT a clock ` +
      "finding -- run the target directly to see its own failure. Tail: " +
      (String(res.stdout || "") + String(res.stderr || "")).split("\n").filter(Boolean).slice(-2).join(" | ").slice(0, 240));
    return null;
  }
  record(name, "PASS",
    `${audit.length} construction(s), all with an explicit clock (${elapsed}ms)`);
  return audit;
}

/* ---- CHECK 2: the residual real-clock set, from the audit rather than from substrings ---- */

/* This counted occurrences of `systemLeaseClock|CHILD_REAL_CLOCK` in the source and
 * compared to a hardcoded number. The same adversarial review showed that was theatre:
 * an inline `{ now: () => Date.now() }` added a real wall-clock construction on an
 * executed path with the token count unchanged, and three of the six counted "opt-ins"
 * were the import, the constant's definition, and a block of dead code. It was gameable
 * and fragile at once, and a comment edit could break the build.
 *
 * The audit reports what was actually CONSTRUCTED, so this now counts real-clock stores
 * on executed paths. `custom` -- a clock object with no kind tag, i.e. an inline one --
 * is treated as undeclared: presence of a clock is not the property, determinism is. */
/* Declared by SITE, not by count.
 *
 * A count ceiling was the first attempt and it was wrong on first contact with another
 * platform: deepseek records 0 real-clock constructions on linux (its cross-process cases
 * are windows-only and return before building a store) and 33 on windows, because a worker
 * loop constructs a store per iteration. Twenty constructions from one loop is not twenty
 * risks -- it is one. The regression worth catching is a NEW PLACE that keeps the wall
 * clock, which is stable across platforms and immune to loop counts.
 *
 * Sites normalise to a basename so a worker script written into a random temp directory
 * (/tmp/gs-ss-grok-conc-XXXX/hammer.js) is stable run to run. */
const DECLARED_REAL_CLOCK_SITES = {
  "tests/state-store/grok/run-tests.js": {
    sites: ["run-tests.js", "hammer.js", "child-crash.js"],
    why:
      "crash.journal-roll-forward-monotonic-no-tear and concurrency.two-process-register-" +
      "deregister spawn children. A clock thunk does not survive a spawn, and a parent " +
      "frozen while a child stamps real time is strictly worse -- measured, the child's " +
      "sweep saw every parent-written lease as expired by decades and fired a crash hook " +
      "on the recovery sweep instead of the operation under test. Both assert journal " +
      "INVARIANTS, never lease liveness, at a 10-minute lease. The two non-repo sites are " +
      "generated worker scripts, which is the case a source scan cannot reach at all.",
  },
  "tests/state-store/deepseek/run-tests.js": {
    sites: ["run-tests.js", "child-crash.js", "worker-concurrency.js"],
    why:
      "test 3 (crash recovery) and test 7 (two-process contention), both windows-only, both " +
      "spawning children. Same reasoning, same 10-minute lease, same invariant-only " +
      "assertions. On a non-windows leg these cases return before building a store, so the " +
      "observed site set there is empty -- a subset is fine, a NEW site is not.",
  },
};

/* The file is the identity of a construction site; absolute paths and temp-directory names
 * are per-run noise. */
function normaliseSite(site) {
  const m = String(site || "").match(/([^\\/(\s]+\.js):\d+:\d+/);
  return m ? m[1] : "(unknown)";
}

function checkDeclaredResidual(target, audit) {
  const name = `declared-residual/${target}`;
  if (!audit) { record(name, "SKIPPED", "no audit: the enforced run did not complete"); return; }
  const custom = audit.filter((r) => r.kind === "custom" || r.kind === "unparseable");
  if (custom.length) {
    record(name, "FAIL",
      `${custom.length} construction(s) passed an UNTAGGED clock. An inline ` +
      "`{ now: () => Date.now() }` satisfies the enforcement flag while reintroducing " +
      "exactly the wall-clock race this suite exists to end. Use createManualClock() or " +
      "systemLeaseClock() from tests/_harness/clock.js so the kind is recorded. First: " +
      (custom[0].site || "(no site)"));
    return;
  }
  const observed = [...new Set(audit.filter((r) => r.kind === "system").map((r) => normaliseSite(r.site)))].sort();
  const declared = DECLARED_REAL_CLOCK_SITES[target];
  if (!declared) {
    if (observed.length === 0) { record(name, "PASS", "no real-clock construction, nothing to declare"); return; }
    record(name, "FAIL",
      `real-clock construction at ${observed.join(", ")} with no entry in ` +
      "DECLARED_REAL_CLOCK_SITES. Every place that keeps the wall clock is residual surface " +
      "for the defect this suite exists to end; it has to be named and justified.");
    return;
  }
  const undeclared = observed.filter((sitename) => declared.sites.indexOf(sitename) === -1);
  if (undeclared.length) {
    record(name, "FAIL",
      `NEW real-clock construction site(s): ${undeclared.join(", ")}. Declared: ` +
      `${declared.sites.join(", ")}. If that place genuinely needs the wall clock, add it to ` +
      "DECLARED_REAL_CLOCK_SITES and say why a manual clock cannot serve there.");
    return;
  }
  record(name, "PASS",
    observed.length === 0
      ? "no real-clock construction on this platform (a subset of the declared set is fine)"
      : `real-clock sites [${observed.join(", ")}], all declared`);
}

/* ---- CHECK 2b: the flag is not what broke a failing target ---- */

/* The previous version printed "the target exited N under FLAG=1 while passing without it"
 * without ever running the target without the flag -- a confident claim about something it
 * had not observed, which is the exact defect class this directory exists to catch, one
 * level up. Reported by an adversarial review after it hit that message twice while the
 * flag was doing nothing. Now the comparison run is real. */
function checkUnflaggedBaseline(target) {
  const name = `baseline-unflagged/${target}`;
  const res = runTarget(target, {});
  if (res.error && res.error.code === "ETIMEDOUT") {
    record(name, "FAIL", "INCONCLUSIVE (harness): the target did not finish inside this " +
      "sweep's own timeout without the flag either");
    return;
  }
  if (res.status !== 0) {
    record(name, "FAIL",
      `the target exits ${res.status} with NO flag set, so it is broken independently of ` +
      "clock discipline. Fix that first; nothing this suite reports about it is meaningful " +
      "until it does.");
    return;
  }
  record(name, "PASS", "target is green with no flag set, so any flagged failure is attributable");
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

/* ---- CHECK 4: no second writer of a lease-compared field on the wall clock ---- */

/* Narrow and specific, and a source scan rather than runtime -- which is a weaker
 * instrument, used here because the property is about a FIELD rather than a construction
 * and the audit cannot see it.
 *
 * `window.created_at` is read back by _sweepExpiredLocked and compared against the store's
 * own instant for the max_window_wall_time cap. state-store.js writes it through the
 * injected clock; scripts/promote.js builds the same record by hand and committed it with
 * Date.now(), so the cap would have been evaluated across two time bases. An adversarial
 * review found that second writer after the store's four sites were converted, and a
 * mutation control then showed the audit-based checks above do NOT catch it -- their scope
 * is tests/state-store/*, and promote.js is not in it.
 *
 * Scoped to one field with one known second writer. It is not a general lint and does not
 * pretend to be: a general "no Date.now in lease code" scan cannot follow aliasing, which
 * is why the primary proof is runtime. */
const LEASE_COMPARED_FIELDS = ["created_at", "lease_expires_at"];
function checkNoWallClockFieldWriters() {
  const name = "no-wall-clock-field-writers";
  const offenders = [];
  const scan = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { if (entry.name !== "node_modules") scan(full); continue; }
      if (!entry.name.endsWith(".js")) continue;
      if (full === STATE_STORE) continue;
      const rel = path.relative(ROOT, full).split(path.sep).join("/");
      const lines = fs.readFileSync(full, "utf8").split("\n");
      lines.forEach((line, i) => {
        for (const field of LEASE_COMPARED_FIELDS) {
          if (line.indexOf(field + ":") === -1) continue;
          if (line.indexOf("Date.now()") === -1 && line.indexOf("new Date(") === -1) continue;
          offenders.push(`${rel}:${i + 1} ${line.trim().slice(0, 100)}`);
        }
      });
    }
  };
  scan(path.join(ROOT, "scripts"));
  if (offenders.length) {
    record(name, "FAIL",
      `${offenders.length} wall-clock writer(s) of a field the store compares against its ` +
      "own lease clock, outside state-store.js. Those records are then evaluated across two " +
      "time bases. Route them through the store's leaseNow(). " + offenders.join(" | ").slice(0, 400));
    return;
  }
  record(name, "PASS",
    `no wall-clock writer of ${LEASE_COMPARED_FIELDS.join("/")} outside state-store.js`);
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
  checkNoWallClockFieldWriters();
  for (const t of targets) {
    checkUnflaggedBaseline(t);
    const audit = checkEnforcedRun(t);
    checkDeclaredResidual(t, audit);
  }

  const failed = results.filter((r) => r.status === "FAIL");
  const passed = results.filter((r) => r.status === "PASS");
  console.log(`\nSUMMARY PASS=${passed.length} FAIL=${failed.length}`);
  if (failed.length) {
    console.log("FAILING: " + failed.map((r) => r.name).join(", "));
    process.exit(1);
  }
}

main();
