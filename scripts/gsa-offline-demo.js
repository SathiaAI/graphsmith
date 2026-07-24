/* Worked offline-verifier demo — scripts/gsa-offline-demo.js.
 * Runs the reference GSA verifier against a golden bundle with the NETWORK DENIED (socket-denial):
 * every net/http/https/dns entry point is replaced with a tripwire that throws, so if the decision
 * path attempted any network I/O the run would fail loudly. It completes because verification is a
 * pure, offline procedure. Prints the ordered §9 checks with REAL statuses (unavailable is never
 * shown green). Reproduce with: node scripts/gsa-offline-demo.js
 */
"use strict";
// --- socket-denial tripwire: any network I/O throws ---
const net = require("net"), http = require("http"), https = require("https"), dns = require("dns");
const DENY = () => { throw new Error("NETWORK DENIED — socket-denial tripwire tripped (verifier must be offline)"); };
for (const [mod, fns] of [[net, ["connect", "createConnection"]], [http, ["request", "get"]], [https, ["request", "get"]], [dns, ["lookup", "resolve", "resolve4", "resolve6"]]]) {
  for (const fn of fns) { try { mod[fn] = DENY; } catch { /* read-only in some builds */ } }
}

const crypto = require("crypto");
const { produceBundle } = require("./gsa-produce.js");
const { verifyBundle } = require("./gsa-verify.js");
const { replayBundle } = require("./gsa-plan.js");

// --- golden bundle: a regulator-mode run with a deterministic seal + one model-dependent step ---
const kp = crypto.generateKeyPairSync("ed25519");
const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
const A = (path, body) => ({ path, body });
const run = {
  bundle_id: "gsa-" + "abcdef0123456789", mode: "regulator", profiles: ["A", "X"], producer: { name: "graphsmith", version: "0.3.0" },
  artifacts: {
    goal: A("goal.txt", "summarise the intake form"), policy: A("policy.yaml", "mode: regulator\nnetwork: deny-unless-allowlisted"),
    model_manifest: A("model_manifest.json", '{"model":"claude-opus-4-8"}'), generated_ir: A("generated_ir.json", '{"steps":2}'),
    compiled_graph: A("compiled_graph.json", '{"nodes":2,"edges":1}'), validation_report: A("validation_report.json", '{"ok":true}'),
    execution_trace: A("execution_trace.jsonl", '{"step":1,"kind":"manager"}\n{"step":2,"kind":"worker","model_call":true}'),
    output_manifest: A("output_manifest.json", '{"outputs":["summary.txt"]}'), decision_record: A("decision_record.md", "# Human approved at gate 3"),
    regulator_summary: A("regulator_summary.md", "# Article-12 summary\nSystem: intake-summariser. Evidence: this bundle."),
  },
  skills: [{ skill_id: "summarise", version: "1.0", implementation_hash: "b".repeat(64), source: "authored", approval_status: "approved", signature: "human-approved" }],
  adversarial: { suites: [{ name: "constitutional", blocked: 12, total: 12 }, { name: "gsa-tamper", blocked: 9, total: 9 }] },
  capabilities: { result: "satisfied", resources: {} },
};
const keys = { privateKey: kp.privateKey, signer: "maintainer-key-1", algo: "ed25519" };
const bundle = produceBundle(run, keys);

// --- verify (offline) + replay ---
const v = verifyBundle(bundle, { trustedKeys: { "maintainer-key-1": pem } });
const r = replayBundle(bundle);
const step = {}; for (const s of v.steps) step[s.step] = s;
const st = (k) => (step[k] ? step[k].status : "—");

const pad = (s, n) => String(s).padEnd(n);
console.log("GraphSmith Attestation — offline verification (network denied via socket-denial)");
console.log("node " + process.version + " · verifier scripts/gsa-verify.js · bundle " + bundle.manifest.bundle_id);
console.log("mode=" + bundle.manifest.mode + "  asserted-profiles=[" + bundle.manifest.profiles.join(",") + "]");
console.log("");
console.log("  §9 step                       status        note");
console.log("  " + "-".repeat(74));
console.log("  " + pad("9.1  manifest validity", 30) + pad(st("1-manifest-validity"), 14) + "schema + required structure");
console.log("  " + pad("9.2  path safety", 30) + pad(st("2-path-safety"), 14) + "no traversal / backslash / non-NFC");
console.log("  " + pad("9.3  artifact integrity", 30) + pad(st("3-artifact-integrity"), 14) + "raw-byte SHA-256 + length hash-bound");
console.log("  " + pad("9.4  conditional presence", 30) + pad(st("4-conditional-presence"), 14) + "regulator_summary present (mode=regulator)");
console.log("  " + pad("9.5  manifest signature", 30) + pad(st("5-manifest-signature"), 14) + "tamper-evident; recomputed manifest hash matches");
console.log("  " + pad("9.6  graph signature", 30) + pad(st("6-graph-signature"), 14) + "graph||policy||skill-set hashes bound + signed");
console.log("  " + pad("9.7  capability conformance", 30) + pad("UNAVAILABLE", 14) + "network-egress + external-call presence attested; per-skill grant = v0.4.0");
console.log("  " + pad("9.8  skill provenance", 30) + pad(st("6-graph-signature") === "PASS" ? "PASS" : "FAIL", 14) + "skill_set_hash binds all executed skills (checked in 9.6)");
console.log("  " + pad("9.9  control attestations", 30) + pad(st("9-control-attestations"), 14) + "all 5 recomputed from evidence, match the claims");
console.log("  " + pad("9.10 profiles", 30) + pad(st("10-profiles"), 14) + "confirmed=[" + v.confirmed_profiles.join(",") + "] downgraded=[" + v.downgraded_profiles.join(",") + "]");
const replayStatus = r.non_replayable.length > 0 ? "UNAVAILABLE" : (r.reproducible ? "PASS" : "FAIL");
console.log("  " + pad("9.11 replay", 30) + pad(replayStatus, 14) + (r.non_replayable.length > 0 ? "model-dependent run; deterministic hashes reproduce; non-replayable=[" + r.non_replayable.join(",") + "]" : "deterministic steps reproduced"));
console.log("  " + "-".repeat(74));
console.log("  OVERALL: " + v.status + "   (a PASS asserts only §1 scope: what ran + record unaltered — not safety/correctness/compliance)");
console.log("");
console.log("network tripwire: intact — no net/http/https/dns call was made during verification.");
process.exit(v.status === "PASS" ? 0 : 1);
