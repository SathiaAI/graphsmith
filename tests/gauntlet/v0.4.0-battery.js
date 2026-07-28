/* GraphSmith v0.4.0 gauntlet — tests/gauntlet/v0.4.0-battery.js.
 * Aggregates every v0.4.0 control's adversarial suite (R1–R5, R8) + the GSA §9.11 integration council
 * + module selftests + the §9.11 regression + the conformance kit into one gating battery, reporting
 * HOLD / BREAK. A scenario HOLDs when the COMPONENT behaved correctly — whether the tester's assertion
 * passed, or it was an ADJUDICATED false-positive where the component is actually right (per each
 * tests/<lane>/ADJUDICATION.md). A BREAK is a component that behaved wrongly: a failing test whose
 * IDENTITY is not one of that suite's adjudicated false-positives (matched by name, never by count —
 * see adjudicate.js), a suite that errored, or a failing selftest. Complements (does not replace) the
 * v0.3.0 gauntlet — a release gate runs both. Reproduce: node tests/gauntlet/v0.4.0-battery.js
 */
"use strict";
const cp = require("child_process");
const path = require("path");
const { adjudicate } = require("./adjudicate");
const root = path.join(__dirname, "..", "..");

// Adversarial suite + the IDENTITY of every adjudicated false-positive it is documented
// to still report (see each tests/<lane>/ADJUDICATION.md). Matched by NAME, never by
// count, so a documented FP that gets fixed cannot pay for a NEW real failure appearing
// in the same run. Identity = the FAIL line after "FAIL ", truncated at the first "{"
// (the component's own JSON verdict) — see adjudicate.js.
const SUITES = [
  // tests/v040/caps/ADJUDICATION.md
  ["tests/v040/caps/deepseek/run-tests.js", []],
  ["tests/v040/caps/mistral/run-tests.js", []],
  // tests/v040/receipts/ADJUDICATION.md
  ["tests/v040/receipts/deepseek/run-tests.js", []],
  ["tests/v040/receipts/mistral/run-tests.js", []],
  // tests/v040/signer/ADJUDICATION.md — malformed-registry hostile inputs (C1/C2).
  ["tests/v040/signer/mistral/run-tests.js", []],
  ["tests/v040/signer/qwen/run-tests.js", []],
  // tests/v040/trace/ADJUDICATION.md — declared recall/precision boundary + inert input.
  ["tests/v040/trace/mistral/run-tests.js", []],
  ["tests/v040/trace/deepseek/run-tests.js", []],
  // tests/v040/provenance/ADJUDICATION.md
  ["tests/v040/provenance/mistral/run-tests.js", []],
  ["tests/v040/provenance/deepseek/run-tests.js", []],
  // tests/v040/policy/ADJUDICATION.md — reason-string over-specification of correct fail-closed verdicts.
  ["tests/v040/policy/mistral/run-tests.js", []],
  ["tests/v040/policy/deepseek/run-tests.js", []],
  // tests/gsa-ext/ADJUDICATION.md — Mistral's own harness-usage errors.
  ["tests/gsa-ext/mistral/run-tests.js", []],
  ["tests/gsa-ext/deepseek/run-tests.js", []],
  // Orchestrator §9.11 integration regression (all-true valid + per-control lie + malformed/backward-compat).
  ["tests/gsa-ext/validate.js", []],
];
// Module selftests — each a gating scenario; must exit 0 with "OK". {rel path from root}.
const SELFTESTS = [
  "checks/v040-caps.js", "checks/v040-receipts.js", "checks/v040-signer.js",
  "checks/v040-trace.js", "checks/v040-provenance.js", "checks/v040-policy.js",
  "scripts/gsa-verify.js", // now recomputes the five §9.11 extended controls
];

function runNode(args) {
  const r = cp.spawnSync(process.execPath, args, { cwd: root, encoding: "utf8" });
  return { out: (r.stdout || "") + (r.stderr || ""), code: r.status };
}
const count = (s, re) => (s.match(re) || []).length;

let scenarios = 0, hold = 0, adjudicated = 0;
const breaks = [];
const rows = [];
const staleNotes = [];

// 1) Adversarial suites + the §9.11 regression.
for (const [rel, adj] of SUITES) {
  const { out, code } = runNode([path.join(root, rel)]);
  const pass = count(out, /^PASS /gm);
  const verdict = adjudicate(out, adj);
  const fail = verdict.failCount;
  if (pass + fail === 0) { breaks.push(rel + " — produced no PASS/FAIL lines (suite error, exit " + code + ")"); rows.push([rel, "ERROR", 0, 0, adj.length]); continue; }
  scenarios += pass + fail;
  hold += pass;
  const expectedFail = fail - verdict.unexpected.length;   // matched an adjudicated identity
  adjudicated += expectedFail;
  hold += expectedFail;
  if (verdict.unexpected.length)
    breaks.push(rel + " — " + verdict.unexpected.length + " UNEXPECTED failure(s), not adjudicated in ADJUDICATION.md: " +
      verdict.unexpected.map((n) => '"' + n.slice(0, 90) + '"').join(", "));
  if (verdict.stale.length)
    staleNotes.push(rel + " — adjudicated FP(s) no longer failing (adjudication is stale, not a regression): " +
      verdict.stale.map((n) => '"' + n.slice(0, 90) + '"').join(", "));
  rows.push([rel, verdict.unexpected.length ? "BREAK" : "hold", pass, fail, adj.length]);
}

// 2) Module selftests (each a gating scenario; must exit 0). The adjudication
// matcher is one of them — if it stopped distinguishing identities, every verdict
// above would be worthless.
{
  const { out, code } = runNode([path.join(__dirname, "adjudicate.js"), "--selftest"]);
  scenarios += 1;
  if (code === 0 && /OK/.test(out)) { hold += 1; rows.push(["selftest:gauntlet-adjudicate", "hold", 1, 0, 0]); }
  else { breaks.push("selftest:gauntlet-adjudicate — FAILED (exit " + code + "); the HOLD/BREAK matcher is untrustworthy:\n" + out.slice(-500)); rows.push(["selftest:gauntlet-adjudicate", "BREAK", 0, 1, 0]); }
}
for (const rel of SELFTESTS) {
  const { out, code } = runNode([path.join(root, rel), "--selftest"]);
  scenarios += 1;
  if (code === 0 && /OK/.test(out)) { hold += 1; rows.push(["selftest:" + rel, "hold", 1, 0, 0]); }
  else { breaks.push("selftest:" + rel + " — FAILED (exit " + code + ")"); rows.push(["selftest:" + rel, "BREAK", 0, 1, 0]); }
}

// 3) Conformance kit — includes the v0.4.0 §9.11 vectors; each a gating scenario.
{
  const { out, code } = runNode([path.join(root, "scripts", "gsa-conformance.js")]);
  const ok = count(out, /^\s*ok\s/gm), xx = count(out, /^\s*XX\s/gm);
  scenarios += ok + xx;
  hold += ok;
  if (xx > 0 || code !== 0) breaks.push("conformance — " + xx + " vector mismatch(es)");
  rows.push(["conformance-vectors", xx > 0 ? "BREAK" : "hold", ok, xx, 0]);
}

// Report
console.log("GraphSmith v0.4.0 gauntlet — " + rows.length + " suites/selftests, Node " + process.version + " " + process.platform);
console.log("");
for (const [name, status, pass, fail, adj] of rows) {
  console.log("  " + (status === "BREAK" ? "BREAK " : status === "ERROR" ? "ERROR " : "hold  ") + name.replace("tests/", "").padEnd(44) + " pass=" + pass + " fail=" + fail + (adj ? " (adj=" + adj + ")" : ""));
}
console.log("");
console.log("  TOTAL scenarios: " + scenarios);
console.log("  HOLD:            " + hold + "  (component behaved correctly)");
console.log("  adjudicated FP:  " + adjudicated + "  (documented tester false-positives; component is correct — see ADJUDICATION.md)");
console.log("  BREAK:           " + breaks.length + "  (unexpected component failures)");
console.log("");
/* A stale adjudication GATES. It used to print "informational" and pass.
 *
 * Every entry here says "this named assertion is a known tester false-positive;
 * when it fails, classify HOLD rather than BREAK". Stale means the name no
 * longer fails, so the entry currently matches nothing -- harmless today, and a
 * live hole tomorrow: a GENUINELY NEW failure carrying that exact name gets
 * absorbed as HOLD instead of gating. The names in question were the ones you
 * least want pre-absorbed -- proto-pollution, split-secret-bypass,
 * fail-open-signer_registry-missing.
 *
 * Reported-but-not-gating made pruning a chore, and chores do not get done: 36
 * dead entries had accumulated across the two batteries. This is the same
 * discriminator the starvation sweep applies to a WIRING GAP, and the same rule
 * as contract 10 List C rule 5 -- detection, not inspection. Fixing a tester
 * assertion is still progress; it just is not finished until its adjudication
 * goes with it. */
if (staleNotes.length) {
  console.log("STALE ADJUDICATIONS — an adjudicated name no longer fails, so its entry now matches");
  console.log("nothing and would absorb a FUTURE failure of that same name as HOLD. Delete the entry");
  console.log("from this battery's SUITES table (fixing the assertion is only half the change):");
  for (const s of staleNotes) console.log("  - " + s);
  console.log("");
  console.log("RESULT: FAIL — " + staleNotes.length + " stale adjudication(s)");
  process.exit(1);
}
if (breaks.length) { console.log("BREAKS:"); for (const b of breaks) console.log("  - " + b); console.log(""); console.log("RESULT: FAIL — " + breaks.length + " BREAK(s)"); process.exit(1); }
console.log("RESULT: " + scenarios + " scenarios, all HOLD, 0 BREAK" + (scenarios >= 100 ? " (>=100 target met)" : " (below 100 target)"));
process.exit(scenarios >= 100 ? 0 : 1);
