/* GraphSmith v0.3.0 gauntlet — tests/gauntlet/v0.3.0-battery.js.
 * Aggregates every v0.3.0 component's adversarial suite + module selftests + the conformance kit
 * into one battery and reports HOLD / BREAK. A scenario HOLDs when the COMPONENT behaved correctly
 * — whether the tester's assertion passed, or the assertion was an ADJUDICATED false-positive where
 * the component is actually right (per each the per-component ADJUDICATION.md). A BREAK is a component that
 * behaved wrongly: a failing test whose IDENTITY is not one of that suite's adjudicated false-positives
 * (matched by name, never by count — see adjudicate.js), a suite that errored, or a failing selftest.
 * Target >= 180 scenarios, 0 BREAK. Reproduce: node tests/gauntlet/v0.3.0-battery.js
 */
"use strict";
const cp = require("child_process");
const path = require("path");
const { adjudicate } = require("./adjudicate");
const root = path.join(__dirname, "..", "..");

// Each adversarial suite + the IDENTITY of every adjudicated false-positive it is
// documented to still report (see the per-lane ADJUDICATION.md). Matching by name
// instead of by count means a documented FP that gets fixed can no longer pay for
// a NEW real failure that appears in the same run. Identity = the FAIL line after
// "FAIL ", truncated at the first "{" (component JSON output) — see adjudicate.js.
const SUITES = [
  ["tests/gsa-mcp/deepseek/run-tests.js", []],
  ["tests/gsa-mcp/mistral/run-tests.js", []],
  // tests/gsa-register/ADJUDICATION.md — inert __proto__ on an otherwise-clean input.
  ["tests/gsa-register/deepseek/run-tests.js", ["proto-pollution unexpected activation"]],
  ["tests/gsa-register/mistral/run-tests.js", ["crash - proto pollution unexpected activation"]],
  // tests/gsa/ADJUDICATION.md — profile-confusion assertions.
  ["tests/gsa/deepseek/run-tests.js", ["profile_confusion"]],
  ["tests/gsa/mistral/run-tests.js", ["profile-confusion-X-without-evidence keys is not defined"]],
  // tests/register/airgap/ADJUDICATION.md
  ["tests/register/airgap/codex/run-tests.js", []],
  ["tests/register/airgap/deepseek/run-tests.js", ["inherited signature fields rejected Expected failed, got verified"]],
  // tests/register/approver/ADJUDICATION.md — hostile-input crash cases.
  ["tests/register/approver/deepseek/run-tests.js", []],
  ["tests/register/approver/mistral/run-tests.js", [
    "crash-bigint BigInt proposer_id did not fail gracefully",
    "crash-proto-pollution Proto pollution did not fail gracefully",
  ]],
  // tests/register/obligations/ADJUDICATION.md
  ["tests/register/obligations/deepseek/run-tests.js", ["proto pollution Proto pollution should not affect verification"]],
  ["tests/register/obligations/qwen/run-tests.js", []],
  // tests/register/retention/ADJUDICATION.md — identity-invariant hostile inputs.
  ["tests/register/retention/mistral/run-tests.js", []],
  ["tests/register/retention/qwen/run-tests.js", ["proto-pollution", "proxy"]],
];
const SELFTESTS = ["gsa-verify", "gsa-produce", "gsa-plan", "gsa-mcp-shim", "gsa-conformance", "gsa-register"];

function runNode(args) {
  const r = cp.spawnSync(process.execPath, args, { cwd: root, encoding: "utf8" });
  return { out: (r.stdout || "") + (r.stderr || ""), code: r.status };
}
const count = (s, re) => (s.match(re) || []).length;

let scenarios = 0, hold = 0, adjudicated = 0;
const breaks = [];
const rows = [];
const staleNotes = [];

// 1) Adversarial suites.
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
// matcher itself is one of them: if it stopped distinguishing identities, every
// verdict above would be worthless.
{
  const { out, code } = runNode([path.join(__dirname, "adjudicate.js"), "--selftest"]);
  scenarios += 1;
  if (code === 0 && /OK/.test(out)) { hold += 1; rows.push(["selftest:gauntlet-adjudicate", "hold", 1, 0, 0]); }
  else { breaks.push("selftest:gauntlet-adjudicate — FAILED (exit " + code + "); the HOLD/BREAK matcher is untrustworthy:\n" + out.slice(-500)); rows.push(["selftest:gauntlet-adjudicate", "BREAK", 0, 1, 0]); }
}
for (const s of SELFTESTS) {
  const { out, code } = runNode([path.join(root, "scripts", s + ".js"), "--selftest"]);
  scenarios += 1;
  if (code === 0 && /OK/.test(out)) { hold += 1; rows.push(["selftest:" + s, "hold", 1, 0, 0]); }
  else { breaks.push("selftest:" + s + " — FAILED (exit " + code + ")"); rows.push(["selftest:" + s, "BREAK", 0, 1, 0]); }
}

// 3) Conformance kit — 10 vectors, each a gating scenario.
{
  const { out, code } = runNode([path.join(root, "scripts", "gsa-conformance.js")]);
  const ok = count(out, /^\s*ok\s/gm), xx = count(out, /^\s*XX\s/gm);
  scenarios += ok + xx;
  hold += ok;
  if (xx > 0 || code !== 0) breaks.push("conformance — " + xx + " vector mismatch(es)");
  rows.push(["conformance-vectors", xx > 0 ? "BREAK" : "hold", ok, xx, 0]);
}

// Report
console.log("GraphSmith v0.3.0 gauntlet — " + rows.length + " suites/selftests, Node " + process.version + " " + process.platform);
console.log("");
for (const [name, status, pass, fail, adj] of rows) {
  console.log("  " + (status === "BREAK" ? "BREAK " : status === "ERROR" ? "ERROR " : "hold  ") + name.replace("tests/", "").padEnd(42) + " pass=" + pass + " fail=" + fail + (adj ? " (adj=" + adj + ")" : ""));
}
console.log("");
console.log("  TOTAL scenarios: " + scenarios);
console.log("  HOLD:            " + hold + "  (component behaved correctly)");
console.log("  adjudicated FP:  " + adjudicated + "  (documented tester false-positives; component is correct — see ADJUDICATION.md)");
console.log("  BREAK:           " + breaks.length + "  (unexpected component failures)");
console.log("");
if (staleNotes.length) { console.log("STALE ADJUDICATIONS (informational — a tester assertion was fixed; prune the entry in this battery):"); for (const s of staleNotes) console.log("  - " + s); console.log(""); }
if (breaks.length) { console.log("BREAKS:"); for (const b of breaks) console.log("  - " + b); console.log(""); console.log("RESULT: FAIL — " + breaks.length + " BREAK(s)"); process.exit(1); }
console.log("RESULT: " + scenarios + " scenarios, all HOLD, 0 BREAK" + (scenarios >= 180 ? " (>=180 target met)" : " (below 180 target)"));
process.exit(scenarios >= 180 ? 0 : 1);
