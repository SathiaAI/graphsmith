/* GraphSmith v0.4.0 gauntlet — tests/gauntlet/v0.4.0-battery.js.
 * Aggregates every v0.4.0 control's adversarial suite (R1–R5, R8) + the GSA §9.11 integration council
 * + module selftests + the §9.11 regression + the conformance kit into one gating battery, reporting
 * HOLD / BREAK. A scenario HOLDs when the COMPONENT behaved correctly — whether the tester's assertion
 * passed, or it was an ADJUDICATED false-positive where the component is actually right (per each
 * tests/<lane>/ADJUDICATION.md). A BREAK is a component that behaved wrongly: a NEW failure beyond the
 * adjudicated count, a suite that errored, or a failing selftest. Complements (does not replace) the
 * v0.3.0 gauntlet — a release gate runs both. Reproduce: node tests/gauntlet/v0.4.0-battery.js
 */
"use strict";
const cp = require("child_process");
const path = require("path");
const root = path.join(__dirname, "..", "..");

// Adversarial suite + its documented adjudicated-false-positive FAIL count (see each ADJUDICATION.md).
const SUITES = [
  ["tests/v040/caps/deepseek/run-tests.js", 1], ["tests/v040/caps/mistral/run-tests.js", 1],
  ["tests/v040/receipts/deepseek/run-tests.js", 1], ["tests/v040/receipts/mistral/run-tests.js", 1],
  ["tests/v040/signer/mistral/run-tests.js", 0], ["tests/v040/signer/qwen/run-tests.js", 4],
  ["tests/v040/trace/mistral/run-tests.js", 4], ["tests/v040/trace/deepseek/run-tests.js", 6],
  ["tests/v040/provenance/mistral/run-tests.js", 0], ["tests/v040/provenance/deepseek/run-tests.js", 1],
  ["tests/v040/policy/mistral/run-tests.js", 3], ["tests/v040/policy/deepseek/run-tests.js", 0],
  ["tests/gsa-ext/mistral/run-tests.js", 6], ["tests/gsa-ext/deepseek/run-tests.js", 0],
  // Orchestrator §9.11 integration regression (all-true valid + per-control lie + malformed/backward-compat).
  ["tests/gsa-ext/validate.js", 0],
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

// 1) Adversarial suites + the §9.11 regression.
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
if (breaks.length) { console.log("BREAKS:"); for (const b of breaks) console.log("  - " + b); console.log(""); console.log("RESULT: FAIL — " + breaks.length + " BREAK(s)"); process.exit(1); }
console.log("RESULT: " + scenarios + " scenarios, all HOLD, 0 BREAK" + (scenarios >= 100 ? " (>=100 target met)" : " (below 100 target)"));
process.exit(scenarios >= 100 ? 0 : 1);
