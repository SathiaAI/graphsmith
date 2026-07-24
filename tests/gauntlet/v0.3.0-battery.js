/* GraphSmith v0.3.0 gauntlet — tests/gauntlet/v0.3.0-battery.js.
 * Aggregates every v0.3.0 component's adversarial suite + module selftests + the conformance kit
 * into one battery and reports HOLD / BREAK. A scenario HOLDs when the COMPONENT behaved correctly
 * — whether the tester's assertion passed, or the assertion was an ADJUDICATED false-positive where
 * the component is actually right (per each the per-component ADJUDICATION.md). A BREAK is a component that
 * behaved wrongly: a NEW failure beyond the adjudicated count, a suite that errored, or a failing
 * selftest. Target >= 180 scenarios, 0 BREAK. Reproduce: node tests/gauntlet/v0.3.0-battery.js
 */
"use strict";
const cp = require("child_process");
const path = require("path");
const root = path.join(__dirname, "..", "..");

// Each adversarial suite + its documented adjudicated-false-positive FAIL count (see ADJUDICATION.md).
const SUITES = [
  ["tests/gsa-mcp/deepseek/run-tests.js", 0], ["tests/gsa-mcp/mistral/run-tests.js", 0],
  ["tests/gsa-register/deepseek/run-tests.js", 1], ["tests/gsa-register/mistral/run-tests.js", 1],
  ["tests/gsa/deepseek/run-tests.js", 1], ["tests/gsa/mistral/run-tests.js", 1],
  ["tests/register/airgap/codex/run-tests.js", 0], ["tests/register/airgap/deepseek/run-tests.js", 1],
  ["tests/register/approver/deepseek/run-tests.js", 0], ["tests/register/approver/mistral/run-tests.js", 2],
  ["tests/register/obligations/deepseek/run-tests.js", 1], ["tests/register/obligations/qwen/run-tests.js", 0],
  ["tests/register/retention/mistral/run-tests.js", 0], ["tests/register/retention/qwen/run-tests.js", 2],
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

// 1) Adversarial suites.
for (const [rel, adj] of SUITES) {
  const { out, code } = runNode([path.join(root, rel)]);
  const pass = count(out, /^PASS /gm), fail = count(out, /^FAIL /gm);
  if (pass + fail === 0) { breaks.push(rel + " — produced no PASS/FAIL lines (suite error, exit " + code + ")"); rows.push([rel, "ERROR", 0, 0, adj]); continue; }
  scenarios += pass + fail;
  hold += pass;
  const expectedFail = Math.min(fail, adj);
  adjudicated += expectedFail;
  hold += expectedFail;
  const unexpected = fail - adj;
  if (unexpected > 0) breaks.push(rel + " — " + unexpected + " UNEXPECTED failure(s) beyond " + adj + " adjudicated");
  rows.push([rel, unexpected > 0 ? "BREAK" : "hold", pass, fail, adj]);
}

// 2) Module selftests (each a gating scenario; must exit 0).
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
if (breaks.length) { console.log("BREAKS:"); for (const b of breaks) console.log("  - " + b); console.log(""); console.log("RESULT: FAIL — " + breaks.length + " BREAK(s)"); process.exit(1); }
console.log("RESULT: " + scenarios + " scenarios, all HOLD, 0 BREAK" + (scenarios >= 180 ? " (>=180 target met)" : " (below 180 target)"));
process.exit(scenarios >= 180 ? 0 : 1);
