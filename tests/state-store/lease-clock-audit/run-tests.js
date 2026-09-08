#!/usr/bin/env node
"use strict";

/* tests/state-store/lease-clock-audit/run-tests.js
 *
 * Round 9 (2026-08-29) Option-2 triage on state-store.js. `recordLeaseClockConstruction()`
 * (scripts/state-store.js:353-435) is the second-largest concentration of surviving mutants
 * after the schema validator -- every existing suite only ever exercises it INDIRECTLY, by
 * constructing a StateStore or WriterClaim with GRAPHSMITH_LEASE_CLOCK_AUDIT set (see
 * tests/state-store/writer-claim's clockEnforcement_* cases and tests/harness-honesty/
 * lease-determinism). None of those ever inspects the audit file's actual JSON content --
 * they only check whether a line was written at all. The function's real job is
 * CLASSIFICATION (wall / malformed / system / system-frozen / manual / custom, "observed
 * wins over claimed"), and nothing has ever read back a single field of what it records.
 *
 * `recordLeaseClockConstruction` is exported specifically so callers other than StateStore's
 * own constructor (writer-claim.js) can share it (see its own doc comment) -- which means
 * this suite can call it directly, with a controlled clockOption and a controlled
 * GRAPHSMITH_LEASE_CLOCK_AUDIT path, and read back exactly what it wrote. No StateStore
 * construction needed at all. */

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));

const AUDIT_ENV = "GRAPHSMITH_LEASE_CLOCK_AUDIT";

let failures = 0;
const results = [];
const tempDirs = [];

function report(name, status, reason) {
  const line = status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`;
  console.log(line);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}

function check(name, cond, reason) {
  if (cond) report(name, "PASS"); else report(name, "FAIL", reason);
}

function freshAuditPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-lease-clock-audit-"));
  tempDirs.push(dir);
  return path.join(dir, "audit.jsonl");
}

/* Runs recordLeaseClockConstruction(clockOption) with GRAPHSMITH_LEASE_CLOCK_AUDIT pointed
 * at a fresh file, restores the env var afterward, and returns the parsed last line (or null
 * if nothing was written). */
function recordAndRead(clockOption, auditPath) {
  const prev = process.env[AUDIT_ENV];
  const target = auditPath || freshAuditPath();
  process.env[AUDIT_ENV] = target;
  try {
    stateStore.recordLeaseClockConstruction(clockOption);
  } finally {
    if (prev === undefined) delete process.env[AUDIT_ENV]; else process.env[AUDIT_ENV] = prev;
  }
  if (!fs.existsSync(target)) return { path: target, lines: [], last: null };
  const lines = fs.readFileSync(target, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return { path: target, lines, last: lines[lines.length - 1] || null };
}

/* ---- the early return: no audit env var set -> writes nothing at all ---- */
function noAuditEnvWritesNothing() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-lease-clock-audit-none-"));
  tempDirs.push(dir);
  const target = path.join(dir, "never-created.jsonl");
  const prev = process.env[AUDIT_ENV];
  delete process.env[AUDIT_ENV];
  try {
    stateStore.recordLeaseClockConstruction({ now: () => 1 });
  } finally {
    if (prev !== undefined) process.env[AUDIT_ENV] = prev;
  }
  check("no-audit-env-writes-nothing", !fs.existsSync(target),
    "recordLeaseClockConstruction must write nothing at all when the audit env var is unset");
}

/* ---- claimed/kind classification: "wall" (no clockOption at all) ---- */
function undefinedClockOptionIsWall() {
  const { last } = recordAndRead(undefined);
  check("undefined-clock-is-explicit-false", Boolean(last) && last.explicit === false, `expected explicit:false, got ${JSON.stringify(last)}`);
  check("undefined-clock-claimed-wall", Boolean(last) && last.claimed === "wall", `expected claimed:"wall", got ${last && last.claimed}`);
  check("undefined-clock-kind-wall", Boolean(last) && last.kind === "wall", `expected kind:"wall", got ${last && last.kind}`);
  check("undefined-clock-advancedUnderRealTime-null", Boolean(last) && last.advancedUnderRealTime === null,
    `an absent clock must never be measured; expected advancedUnderRealTime:null, got ${last && JSON.stringify(last.advancedUnderRealTime)}`);
}

/* ---- claimed/kind classification: "malformed" (now is not a function) ---- */
function nonFunctionNowIsMalformed() {
  const { last } = recordAndRead({ now: "not-a-function" });
  check("malformed-clock-explicit-true", Boolean(last) && last.explicit === true, `expected explicit:true, got ${JSON.stringify(last)}`);
  check("malformed-clock-claimed-malformed", Boolean(last) && last.claimed === "malformed", `expected claimed:"malformed", got ${last && last.claimed}`);
  check("malformed-clock-kind-malformed", Boolean(last) && last.kind === "malformed", `expected kind:"malformed", got ${last && last.kind}`);
  check("malformed-clock-never-measured", Boolean(last) && last.advancedUnderRealTime === null,
    `a malformed .now must never be measured; expected null, got ${last && JSON.stringify(last.advancedUnderRealTime)}`);
}

/* ---- "system": tagged __leaseClockKind:"system" AND genuinely advances under real time ---- */
function realAdvancingSystemTagIsSystem() {
  const { last } = recordAndRead({ __leaseClockKind: "system", now: () => Date.now() });
  check("real-system-clock-claimed-system", Boolean(last) && last.claimed === "system", `expected claimed:"system", got ${last && last.claimed}`);
  check("real-system-clock-advanced-true", Boolean(last) && last.advancedUnderRealTime === true, `expected advancedUnderRealTime:true, got ${last && JSON.stringify(last.advancedUnderRealTime)}`);
  check("real-system-clock-kind-system", Boolean(last) && last.kind === "system", `expected kind:"system", got ${last && last.kind}`);
}

/* ---- OBSERVED WINS OVER CLAIMED: an UNTAGGED clock that genuinely advances is still
 * classified "system" by measurement, not left as "custom" merely because it lacks the tag.
 * This is the exact defect the module's own header comment describes fixing. ---- */
function untaggedButGenuinelyAdvancingClockIsClassifiedSystem() {
  const { last } = recordAndRead({ now: () => Date.now() }); // no __leaseClockKind at all
  check("untagged-advancing-clock-claimed-custom", Boolean(last) && last.claimed === "custom",
    `an untagged function-valued clock must be CLAIMED "custom" (${JSON.stringify(last)})`);
  check("untagged-advancing-clock-measured-true", Boolean(last) && last.advancedUnderRealTime === true,
    `it must be MEASURED as advancing, got ${last && JSON.stringify(last.advancedUnderRealTime)}`);
  check("untagged-advancing-clock-kind-is-system-not-custom", Boolean(last) && last.kind === "system",
    `observed behavior must win over the missing tag: expected kind:"system" despite claimed:"custom", got ${last && last.kind}`);
}

/* ---- "manual": tagged (or untagged) clock that does NOT advance under real time ---- */
function frozenTaggedManualClockIsManual() {
  const { last } = recordAndRead({ __leaseClockKind: "manual", now: () => 12345 });
  check("frozen-manual-clock-claimed-manual", Boolean(last) && last.claimed === "manual", `expected claimed:"manual", got ${last && last.claimed}`);
  check("frozen-manual-clock-advanced-false", Boolean(last) && last.advancedUnderRealTime === false, `expected advancedUnderRealTime:false, got ${last && JSON.stringify(last.advancedUnderRealTime)}`);
  check("frozen-manual-clock-kind-manual", Boolean(last) && last.kind === "manual", `expected kind:"manual", got ${last && last.kind}`);
}

function frozenUntaggedClockIsAlsoManual() {
  const { last } = recordAndRead({ now: () => 999 }); // no tag at all, but frozen
  check("frozen-untagged-clock-claimed-custom", Boolean(last) && last.claimed === "custom", `expected claimed:"custom", got ${last && last.claimed}`);
  check("frozen-untagged-clock-kind-manual", Boolean(last) && last.kind === "manual",
    `an untagged frozen clock must still be classified "manual" (not "custom"), got ${last && last.kind}`);
}

/* ---- "system-frozen": the ONE combination that is neither trusted at face value nor
 * folded into plain "manual" -- a clock that LIES about being "system" but demonstrably does
 * not move. A forged tag must not silently pass as the real thing. ---- */
function taggedSystemButFrozenIsSystemFrozen() {
  const { last } = recordAndRead({ __leaseClockKind: "system", now: () => 42 });
  check("lying-system-tag-claimed-system", Boolean(last) && last.claimed === "system", `expected claimed:"system", got ${last && last.claimed}`);
  check("lying-system-tag-advanced-false", Boolean(last) && last.advancedUnderRealTime === false, `expected advancedUnderRealTime:false, got ${last && JSON.stringify(last.advancedUnderRealTime)}`);
  check("lying-system-tag-kind-system-frozen", Boolean(last) && last.kind === "system-frozen",
    `a clock tagged "system" that does not advance must be named "system-frozen", distinct from plain "manual"; got ${last && last.kind}`);
}

/* ---- "custom": measurement itself failed (the .now() call threw) ---- */
function throwingNowFunctionIsCustom() {
  const { last } = recordAndRead({ __leaseClockKind: "manual", now: () => { throw new Error("boom"); } });
  check("throwing-now-advancedUnderRealTime-null", Boolean(last) && last.advancedUnderRealTime === null,
    `a throwing .now() must be caught and leave advancedUnderRealTime null, got ${last && JSON.stringify(last)}`);
  check("throwing-now-kind-custom", Boolean(last) && last.kind === "custom",
    `an unmeasurable clock (advancedUnderRealTime null) must fall through to kind:"custom", got ${last && last.kind}`);
}

/* ---- CLOCK_PROVENANCE caching: measuring the SAME clock object twice must reuse the first
 * measurement, not re-measure. Proven by mutating the object's .now AFTER the first call --
 * if the second call re-measured, it would see the NEW behavior; caching proves it does not. */
function sameClockObjectIsMeasuredOnlyOnce() {
  const auditPath = freshAuditPath();
  const clockObject = { __leaseClockKind: "manual", now: () => 5 }; // frozen the first time
  const first = recordAndRead(clockObject, auditPath);
  check("provenance-cache-first-call-manual", first.last && first.last.advancedUnderRealTime === false,
    `sanity: first measurement of a frozen clock must be false, got ${JSON.stringify(first.last)}`);

  // Now make the SAME object object's .now() genuinely advance with real time.
  clockObject.now = () => Date.now();
  const second = recordAndRead(clockObject, auditPath);
  check("provenance-cache-reuses-first-measurement", second.last && second.last.advancedUnderRealTime === false,
    `a second construction of the SAME clock object must reuse the cached (false) measurement ` +
    `rather than re-measure the now-advancing .now(), got ${JSON.stringify(second.last)}`);
  check("provenance-cache-two-lines-written", second.lines.length === 2,
    `expected exactly 2 audit lines (one per construction) from the same audit file, got ${second.lines.length}`);
}

/* ---- site/caller extraction: the first two stack frames OUTSIDE state-store.js/writer-
 * claim.js, filtered by basename, truncated to 240 chars. ---- */
function siteAndCallerNameThisTestFile() {
  function innerCaller() {
    return recordAndRead({ now: () => 1 });
  }
  const { last } = innerCaller();
  check("site-names-this-test-file", Boolean(last) && last.site.includes("lease-clock-audit"),
    `expected the recorded site to name this test file, got ${last && last.site}`);
  check("site-is-not-inside-state-store.js", Boolean(last) && !last.site.includes("state-store.js"),
    `the library-file filter must exclude state-store.js itself from the site, got ${last && last.site}`);
  check("caller-is-a-string-field", Boolean(last) && typeof last.caller === "string",
    `expected a string caller field, got ${last && JSON.stringify(last.caller)}`);
}

/* ---- the record always carries the current process pid ---- */
function recordCarriesProcessPid() {
  const { last } = recordAndRead({ now: () => 1 });
  check("record-carries-process-pid", Boolean(last) && last.pid === process.pid,
    `expected pid:${process.pid}, got ${last && last.pid}`);
}

function main() {
  try {
    noAuditEnvWritesNothing();
    undefinedClockOptionIsWall();
    nonFunctionNowIsMalformed();
    realAdvancingSystemTagIsSystem();
    untaggedButGenuinelyAdvancingClockIsClassifiedSystem();
    frozenTaggedManualClockIsManual();
    frozenUntaggedClockIsAlsoManual();
    taggedSystemButFrozenIsSystemFrozen();
    throwingNowFunctionIsCustom();
    sameClockObjectIsMeasuredOnlyOnce();
    siteAndCallerNameThisTestFile();
    recordCarriesProcessPid();
  } finally {
    for (const dir of tempDirs) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (_err) {
        /* best-effort cleanup; never let it mask the real test result */
      }
    }
  }

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
