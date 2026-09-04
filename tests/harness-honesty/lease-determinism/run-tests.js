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

/* Discovered suites that legitimately construct ZERO StateStore instances.
 *
 * discoverTargets() assumes every discovered tests/state-store subdirectory's run-tests.js
 * builds a StateStore -- true when this suite was written, false the day Track 3.4 and
 * Track 3.6 landed suites
 * that test free functions the module exports directly (atomicCreateExclusive,
 * atomicOverwriteFile, validateNamedRecord, pidAlive) without ever instantiating the
 * class. checkEnforcedRun's zero-audit branch exists to catch a broken breadcrumb wire or
 * a target that silently built nothing; treating these two the same way misattributes
 * "this suite doesn't test what I audit" as "the audit is broken", which is a false FAIL,
 * not a passed check narrowed to fit -- the suites still get their exit status checked, so
 * a genuine regression in either one is still caught, just not mislabeled as a clock-
 * discipline wiring gap. Declared by SITE (the target path), same as
 * DECLARED_REAL_CLOCK_SITES below, so this list is only ever wrong by omission, never by
 * silently widening to cover a target that DOES construct a store. */
const NO_STORE_CONSTRUCTION_TARGETS = {
  "tests/state-store/atomic-primitives/run-tests.js":
    "tests atomicCreateExclusive, atomicOverwriteFile, and validateNamedRecord -- exported " +
    "free functions -- directly, never `new StateStore(...)`.",
  "tests/state-store/pidalive-zombie/run-tests.js":
    "requires state-store.js only to call the exported free function pidAlive directly " +
    "against a forged real Linux zombie process; never constructs the class.",
  "tests/state-store/pidalive-crossplatform/run-tests.js":
    "tests pidAlive directly (Round 9, 2026-08-29) with process.kill and fs.readFileSync " +
    "mocked, closing the gap left by pidalive-zombie's whole-suite platform guard; never " +
    "constructs the class.",
  "tests/state-store/lease-clock-audit/run-tests.js":
    "tests the exported recordLeaseClockConstruction directly (Round 9, 2026-08-29) with " +
    "GRAPHSMITH_LEASE_CLOCK_AUDIT pointed at its own temp file and various clockOption " +
    "shapes, reading back the audit JSON; never constructs StateStore or WriterClaim.",
};

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
  /* Both variables are DELETED first, then re-applied from extraEnv. Inheriting
   * process.env meant a gate launched with the flag already set produced a
   * "baseline-unflagged" run that still had the flag -- a check named for a condition it
   * did not establish. Reported by an adversarial review; the same inheritance bug was in
   * the flag-off half of the control below. */
  const env = Object.assign({}, process.env);
  delete env[ENV_FLAG];
  delete env[AUDIT_ENV];
  return spawnSync(process.execPath, [path.join(ROOT, target)], {
    cwd: ROOT, encoding: "utf8",
    env: Object.assign(env, extraEnv),
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
    if (NO_STORE_CONSTRUCTION_TARGETS[target]) {
      /* Exit status is still checked below like every other target -- a declared
       * zero-construction suite that starts crashing is still a real failure, just not a
       * clock-discipline one. */
      if (res.status !== 0) {
        const out = String(res.stdout || "") + String(res.stderr || "");
        const failing = out.split("\n")
          .filter((line) => /^\s*(FAIL|FAILED)\b|^FAIL[: ]/.test(line))
          .slice(0, 4).map((line) => line.trim().slice(0, 200));
        record(name, "FAIL",
          `the target exited ${res.status} under ${ENV_FLAG}=1. It is a declared zero-` +
          "construction suite (tests free functions, never `new StateStore(...)`), so this " +
          "is NOT a clock finding -- the target failed for its own reasons. Its failing " +
          "case(s): " + (failing.length ? failing.join(" || ") : "(none matched a FAIL " +
            "pattern; tail: " + out.split("\n").filter(Boolean).slice(-3).join(" | ")
              .slice(0, 200) + ")"));
        return null;
      }
      record(name, "PASS",
        "0 construction(s) -- declared: " + NO_STORE_CONSTRUCTION_TARGETS[target] +
        ` (${elapsed}ms)`);
      return [];
    }
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
    /* Surface the TARGET'S OWN failing lines, not the last two lines of its output.
     * The tail was `PASS: 11 FAIL: 1 | crashed:SIMULATED_CRASH` -- which says a case failed
     * and refuses to say which, so the log could not be diagnosed without re-running by
     * hand. A gate that reports "something failed" is only marginally better than a gate
     * that says nothing. */
    const out = String(res.stdout || "") + String(res.stderr || "");
    const failing = out.split("\n")
      .filter((line) => /^\s*(FAIL|FAILED)\b|^FAIL[: ]/.test(line))
      .slice(0, 4).map((line) => line.trim().slice(0, 200));
    record(name, "FAIL",
      `the target exited ${res.status} under ${ENV_FLAG}=1. Every one of its ` +
      `${audit.length} construction(s) passed an explicit clock, so this is NOT a clock ` +
      "finding -- the target failed for its own reasons. Its failing case(s): " +
      (failing.length ? failing.join(" || ") : "(none matched a FAIL pattern; tail: " +
        out.split("\n").filter(Boolean).slice(-3).join(" | ").slice(0, 200) + ")"));
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
    sites: [
      "child-crash.js#anon",
      "hammer.js#anon",
      "tests/state-store/grok/run-tests.js#createRealClockStore <- tests/state-store/grok/run-tests.js#anon",
      "tests/state-store/grok/run-tests.js#createRealClockStore <- tests/state-store/grok/run-tests.js#mk",
      "(unknown)",
    ],
    why:
      "crash.journal-roll-forward-monotonic-no-tear and concurrency.two-process-register-" +
      "deregister spawn children. A clock thunk does not survive a spawn, and a parent " +
      "frozen while a child stamps real time is strictly worse -- measured, the child's " +
      "sweep saw every parent-written lease as expired by decades and fired a crash hook " +
      "on the recovery sweep instead of the operation under test. Both assert journal " +
      "INVARIANTS, never lease liveness, at a 10-minute lease. The two non-repo sites are " +
      "generated worker scripts, which is the case a source scan cannot reach at all. " +
      "'(unknown)' is state-store.js's own --selftest CLI mode, which this suite's " +
      "XTRA/state-store-selftest-cli-floor case spawns as `node scripts/state-store.js " +
      "--selftest`: selftest() sleeps real milliseconds and asserts against real elapsed " +
      "time (registry-lease-sweep), so it genuinely needs systemLeaseClock(). Every frame " +
      "from the constructor up through the CLI dispatch lives inside state-store.js itself, " +
      "so the breadcrumb's cross-file caller filter -- built for tests calling INTO the " +
      "store, not the store calling itself -- has nothing external to name past the node " +
      "module loader; that is the honest limit of a heuristic normalising on file+function.",
  },
  "tests/state-store/deepseek/run-tests.js": {
    sites: [
      "child-crash.js#anon",
      "worker-concurrency.js#anon",
      "tests/state-store/deepseek/run-tests.js#requireRealClockStore <- tests/state-store/deepseek/run-tests.js#test2_pidReuseAndTestMode",
      "tests/state-store/deepseek/run-tests.js#requireRealClockStore <- tests/state-store/deepseek/run-tests.js#test3_crashRecovery",
      "tests/state-store/deepseek/run-tests.js#requireRealClockStore <- tests/state-store/deepseek/run-tests.js#test7_concurrency",
    ],
    why:
      "test 3 (crash recovery) and test 7 (two-process contention) spawn children, so a " +
      "manual clock cannot reach them; both are windows-only, so a linux leg observes " +
      "neither. test 2's busy-owner check is real-clock on purpose: it asserts that a lock " +
      "being RENEWED is not stolen, and lock renewal writes an mtime the OS stamps -- there " +
      "is nothing to inject. All three assert invariants, never lease liveness.",
  },
  "tests/state-store/writer-claim-shared-storage/run-tests.js": {
    sites: [
      "tests/state-store/writer-claim-shared-storage/_worker.js#anon",
      "tests/state-store/writer-claim-shared-storage/run-tests.js#endToEndSharedVolumeNeverSilentlyProceeds <- tests/state-store/writer-claim-shared-storage/run-tests.js#main",
    ],
    why:
      "AC-2's whole point is a SECOND host racing the same shared directory, so both " +
      "sites stand in for that second host's own clock and have to be real to reproduce " +
      "the cross-host skew under test. endToEndSharedVolumeNeverSilentlyProceeds reads a " +
      "planted claim record whose renewed_at was stamped from real Date.now() +/- a large " +
      "skew; a frozen clock could not reproduce that skew relationship. _worker.js is a " +
      "spawned second process racing acquire() against the first (realProcessRaceOverShared" +
      "Directory) -- a clock thunk does not survive a spawn, same as grok's cross-process " +
      "sites above. Neither asserts lease liveness; both assert single-writer refusal.",
  },
};

/* Site identity: FILE plus FUNCTION, no line numbers.
 *
 * This has now been wrong twice in opposite directions. A basename bounded file names
 * rather than sites -- a new wall-clock construction inside an already-declared
 * run-tests.js was accepted. Adding line numbers fixed that and made the declaration
 * unmaintainable: every edit above a site shifts its line, so an unrelated change to a
 * comment invalidates the inventory and the next person "fixes" it by pasting in whatever
 * the run printed, which is how a gate becomes a rubber stamp.
 *
 * The function is the stable identity of a construction site. A new factory, a new file, or
 * a new named caller of an existing factory is caught; a second construction inside an
 * already-declared function is not, and that is the honest limit of this check. */
function normaliseSite(site) {
  const raw = String(site || "");
  const fileMatch = raw.match(/([^()\s]+\.js):\d+:\d+/);
  if (!fileMatch) return "(unknown)";
  const file = fileMatch[1];
  const rel = path.relative(ROOT, file);
  const inRepo = rel && !rel.startsWith("..") && !path.isAbsolute(rel);
  const name = inRepo ? rel.split(path.sep).join("/") : path.basename(file);
  const fnMatch = raw.match(/^\s*at\s+([^\s(]+)\s+\(/);
  const fn = fnMatch && fnMatch[1] !== "Object.<anonymous>" ? fnMatch[1] : "anon";
  return `${name}#${fn}`;
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
  /* Identity is the construction site AND its caller. A test-local factory would otherwise
   * collapse every caller into one site, so a new case reusing an existing real-clock
   * factory would be invisible -- the same hole, one level out, that the two-frame capture
   * in state-store.js exists to close. */
  const identify = (r) => {
    const at = normaliseSite(r.site);
    const from = r.caller ? normaliseSite(r.caller) : "";
    /* A node-internal caller (module loader for a generated worker's top level) carries no
     * information; the site alone is the identity there. */
    const useful = from && from !== "(unknown)" && from.indexOf("node:") === -1 && from.indexOf("loader.js") === -1;
    return useful ? `${at} <- ${from}` : at;
  };
  const observed = [...new Set(audit.filter((r) => r.kind === "system" || r.kind === "system-frozen").map(identify))].sort();
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
  const offEnv = Object.assign({}, process.env);
  delete offEnv[ENV_FLAG];
  delete offEnv[AUDIT_ENV];
  const off = spawnSync(process.execPath, ["-e", probe], { cwd: ROOT, encoding: "utf8", env: offEnv });
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
