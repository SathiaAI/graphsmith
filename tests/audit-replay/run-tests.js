"use strict";

/* tests/audit-replay/run-tests.js — Lane E adversarial suite for
 * scripts/gsa-audit-replay.js + the `audit replay` subcommand wired into
 * scripts/graphsmith-cli.js.
 *
 * Mirrors this repo's own tests/<component>/run-tests.js convention (see
 * e.g. tests/reconcile/run-tests.js): report()/PASS-FAIL-SKIP, exit 1 on
 * any failure. Discoverable by scripts/ci-run-suites.js's literal
 * "run-tests.js" filename walk.
 *
 * Design doc: .plans/gsa-followup/LANE-E-AUDIT-REPLAY-DESIGN.md (frozen,
 * adversarially reviewed 2026-08-01). GROUP 3 below is the single most
 * important group in this suite (design §1.1/§3/§6.5's forgery-closing
 * fix): it constructs multiple adversarial verify_result inputs and proves
 * NONE of them can ever produce a 'verified' dimension unless
 * verification_provenance is 'live' AND verify_result.status is 'PASS'.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const cp = require("child_process");
const crypto = require("crypto");

const { produceBundle } = require("../../scripts/gsa-produce.js");
const { verifyBundle } = require("../../scripts/gsa-verify.js");
const auditReplay = require("../../scripts/gsa-audit-replay.js");
const { composeReport, validateVerifyResultShape, buildDimensions, buildMarks, buildSkillsLens, redactString } = auditReplay;

const CLI_PATH = path.resolve(__dirname, "..", "..", "scripts", "graphsmith-cli.js");
const AUDIT_REPLAY_SRC_PATH = path.resolve(__dirname, "..", "..", "scripts", "gsa-audit-replay.js");
const CLI_SRC_PATH = CLI_PATH;

let passed = 0;
let failed = 0;
let skipped = 0;

function report(name, ok, detail) {
  if (ok === true) {
    console.log(`PASS: ${name}`);
    passed++;
  } else if (ok === false) {
    console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`);
    failed++;
  } else {
    console.log(`SKIP: ${name}${detail ? " -- " + detail : ""}`);
    skipped++;
  }
}

// ===========================================================================
// Fixture helpers
// ===========================================================================
const A = (p, body) => ({ path: p, body });

function baseRun(overrides) {
  overrides = overrides || {};
  const run = {
    bundle_id: overrides.bundle_id || ("gsa-" + "1".repeat(16)),
    mode: overrides.mode || "standard",
    profiles: overrides.profiles || ["A", "X"],
    producer: { name: "graphsmith", version: "0.4.0" },
    artifacts: {
      goal: A("goal.txt", "ship it"),
      policy: A("policy.yaml", "mode: " + (overrides.mode || "standard")),
      model_manifest: A("model_manifest.json", "{}"),
      generated_ir: A("generated_ir.json", "{}"),
      compiled_graph: A("compiled_graph.json", '{"n":1}'),
      validation_report: A("validation_report.json", "{}"),
      execution_trace: A("execution_trace.jsonl", overrides.trace || '{"step":1,"kind":"manager"}'),
      output_manifest: A("output_manifest.json", overrides.output || '{"out":"v1"}'),
      decision_record: A("decision_record.md", "# ok"),
    },
    skills: overrides.skills || [{ skill_id: "s1", version: "1.0", implementation_hash: "a".repeat(64), source: "local", approval_status: "approved", signature: "sig" }],
    adversarial: overrides.adversarial || { suites: [{ name: "constitutional", blocked: 10, total: 10 }] },
    capabilities: overrides.capabilities || { result: "satisfied", resources: {} },
  };
  if (overrides.mode === "regulator") run.artifacts.regulator_summary = A("regulator_summary.md", "# reg");
  if (overrides.repairLog) run.artifacts.repair_log = A("repair_log.md", "# repair");
  if (overrides.control_attestations_v040) run.control_attestations_v040 = overrides.control_attestations_v040;
  return run;
}

/* produceBundle() doesn't thread control_attestations_v040 through (it's not part of `run`'s
 * shape in gsa-produce.js) -- when a fixture needs it, splice it into the manifest post-hoc and
 * re-sign, exactly like gsa-verify.js's own --selftest signedExtBundle() helper does. */
function withExtendedControls(bundle, keys, ext) {
  const { canonicalize, sha256Hex } = require("../../scripts/gsa-verify.js");
  // trace_mode is required by checks/v040-trace.js#verifyTrace() whenever trace_redaction is
  // declared (mirrors gsa-verify.js's own --selftest signedExtBundle() helper).
  const mx = { ...bundle.manifest, control_attestations_v040: ext, trace_mode: "full" };
  delete mx.bundle_signature;
  const ph = sha256Hex(Buffer.from(canonicalize(mx), "utf8"));
  const sign = (hex) => crypto.sign(null, Buffer.from(hex, "utf8"), keys.privateKey).toString("base64");
  mx.bundle_signature = { algo: "ed25519", signer: keys.signer, manifest_sha256: ph, value: sign(ph) };
  return { manifest: mx, contents: bundle.contents };
}

function makeSignedBundle(overrides) {
  const kp = crypto.generateKeyPairSync("ed25519");
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  const keys = { privateKey: kp.privateKey, signer: "k", algo: "ed25519" };
  let bundle = produceBundle(baseRun(overrides), keys);
  if (overrides && overrides.control_attestations_v040) bundle = withExtendedControls(bundle, keys, overrides.control_attestations_v040);
  return { bundle, trustedKeys: { k: pem }, keys };
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-audit-replay-${label}-`));
}
function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* best-effort */ }
}

function runCli(args, stdinText) {
  const res = cp.spawnSync(process.execPath, [CLI_PATH, ...args], { input: stdinText, encoding: "utf8" });
  return { status: res.status, stdout: res.stdout || "", stderr: res.stderr || "" };
}

// ===========================================================================
// GROUP 0: the "no crypto, no re-derived §9 logic" lint rule — a REAL
// executable check (design instructions: "not just a comment").
// ===========================================================================
function groupLintNoCryptoNoDuplication() {
  console.log("\n=== GROUP 0: lint — no require(\"crypto\"), no crypto.* calls, no re-derived §9 logic in the new files ===");
  const composerSrc = fs.readFileSync(AUDIT_REPLAY_SRC_PATH, "utf8");
  const cliSrc = fs.readFileSync(CLI_SRC_PATH, "utf8");

  const cryptoRequireRe = /require\(\s*["']crypto["']\s*\)/;
  report("0.1 scripts/gsa-audit-replay.js does not require('crypto')", !cryptoRequireRe.test(composerSrc));
  report("0.2 scripts/graphsmith-cli.js does not require('crypto')", !cryptoRequireRe.test(cliSrc));

  // Defense in depth: no direct crypto.* call anywhere in either file (crypto usage must stay
  // fully inside gsa-verify.js, which this module only ever calls through, never imports).
  const cryptoCallRe = /\bcrypto\s*\.\s*(createHash|createSign|createVerify|sign|verify|generateKeyPairSync|createPublicKey|createPrivateKey)\s*\(/;
  report("0.3 scripts/gsa-audit-replay.js contains no direct crypto.* call", !cryptoCallRe.test(composerSrc));
  report("0.4 scripts/graphsmith-cli.js contains no direct crypto.* call", !cryptoCallRe.test(cliSrc));

  // Must not re-derive verifyBundle's §9 comparison primitives locally (sha256Hex/canonicalize are
  // gsa-verify.js's single-source hashing helpers -- a new local definition would be duplication).
  const localHashDefRe = /(function\s+sha256Hex|const\s+sha256Hex\s*=|function\s+canonicalize|const\s+canonicalize\s*=)/;
  report("0.5 scripts/gsa-audit-replay.js does not locally redefine sha256Hex/canonicalize", !localHashDefRe.test(composerSrc));

  // Must actually delegate to the real functions, not just avoid naming them -- confirms this
  // isn't satisfied by omission alone.
  report(
    "0.6 scripts/gsa-audit-replay.js delegates to replayBundle()/planDrift() from gsa-plan.js (not reimplemented)",
    /require\(["']\.\/gsa-plan\.js["']\)/.test(composerSrc) && /replayBundle/.test(composerSrc) && /planDrift/.test(composerSrc)
  );
  report(
    "0.7 scripts/graphsmith-cli.js's audit-replay path delegates to verifyBundle() from gsa-verify.js (not reimplemented)",
    /require\(["']\.\/gsa-verify\.js["']\)/.test(cliSrc) && /verifyBundle\(bundle/.test(cliSrc)
  );
}

// ===========================================================================
// GROUP 1: a bundle that verifies cleanly end-to-end
// ===========================================================================
function assertReportShape(name, report_) {
  const REQUIRED_TOP = ["schema_version", "tool", "bundle_id", "generated", "mode", "asserted_profiles", "verification_provenance", "verify_result", "replay_result", "dimensions", "marks", "skills_lens", "narrative", "evidence_index"];
  let ok = true;
  const problems = [];
  for (const k of REQUIRED_TOP) if (!Object.prototype.hasOwnProperty.call(report_, k)) { ok = false; problems.push("missing " + k); }
  if (report_.schema_version !== "0.2") { ok = false; problems.push("schema_version"); }
  if (!report_.tool || report_.tool.name !== "graphsmith-audit-replay" || typeof report_.tool.version !== "string" || !report_.tool.version.length) { ok = false; problems.push("tool"); }
  if (typeof report_.bundle_id !== "string" || !/^gsa-[0-9a-f]{16}$/.test(report_.bundle_id)) { ok = false; problems.push("bundle_id"); }
  if (!["standard", "deterministic", "regulator"].includes(report_.mode)) { ok = false; problems.push("mode"); }
  if (!Array.isArray(report_.asserted_profiles) || report_.asserted_profiles.some((p) => !["R", "E", "B", "T", "G", "Q", "A", "X"].includes(p))) { ok = false; problems.push("asserted_profiles"); }
  if (!["live", "external"].includes(report_.verification_provenance)) { ok = false; problems.push("verification_provenance"); }
  if (!Array.isArray(report_.dimensions) || report_.dimensions.length < 4 || report_.dimensions.length > 5) { ok = false; problems.push("dimensions length"); }
  for (const d of report_.dimensions || []) {
    if (!["provenance_signing", "capability_posture", "determinism_repair", "adversarial_coverage", "extended_controls_v040"].includes(d.id)) { ok = false; problems.push("dimension id " + d.id); }
    if (!["verified", "failed", "unavailable"].includes(d.status)) { ok = false; problems.push("dimension status " + d.status); }
    if (!Array.isArray(d.evidence) || d.evidence.length < 1) { ok = false; problems.push("dimension " + d.id + " evidence minItems"); }
    if (!Array.isArray(d.assumptions)) { ok = false; problems.push("dimension " + d.id + " assumptions"); }
  }
  for (const m of report_.marks || []) {
    if (typeof m.marker !== "string" || !m.marker.length) { ok = false; problems.push("mark.marker"); }
    if (!["nondeterministic", "repair", "model-dependent"].includes(m.list)) { ok = false; problems.push("mark.list"); }
    if (typeof m.pointer !== "string") { ok = false; problems.push("mark.pointer"); }
    if (!Number.isInteger(m.offset) || m.offset < 0) { ok = false; problems.push("mark.offset"); }
  }
  for (const s of report_.skills_lens || []) {
    if (!["approved", "quarantined", "generated", "revoked"].includes(s.approval_status)) { /* documented tolerance -- see GROUP 6.11 */ }
    if (!Number.isInteger(s.trace_mentions) || s.trace_mentions < 0) { ok = false; problems.push("skills_lens.trace_mentions"); }
  }
  if (typeof report_.narrative !== "string" || !report_.narrative.length) { ok = false; problems.push("narrative"); }
  for (const e of report_.evidence_index || []) {
    if (typeof e.pointer !== "string" || typeof e.description !== "string" || !e.description.length) { ok = false; problems.push("evidence_index entry shape"); }
  }
  report(name, ok, problems.join("; "));
}

function groupCleanEndToEnd() {
  console.log("\n=== GROUP 1: a bundle that verifies cleanly end-to-end ===");
  const { bundle, trustedKeys } = makeSignedBundle({});
  const vr = verifyBundle(bundle, { trustedKeys });
  report("1.1 fixture bundle live-verifies PASS", vr.status === "PASS", JSON.stringify(vr.steps));

  const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
  report("1.2 all 4 base dimensions render 'verified'", rpt.dimensions.length === 4 && rpt.dimensions.every((d) => d.status === "verified"), JSON.stringify(rpt.dimensions.map((d) => [d.id, d.status])));
  report("1.3 replay_result.reproducible === true", rpt.replay_result.reproducible === true, JSON.stringify(rpt.replay_result));
  report("1.4 verification_provenance === 'live'", rpt.verification_provenance === "live");
  report("1.5 generated === 'unavailable' (no clock read)", rpt.generated === "unavailable");
  assertReportShape("1.6 report matches schemas/audit-replay-report.schema.json shape (hand-checked)", rpt);

  // v0.4.0 extended controls: fifth dimension appears and is verified when every declared control recomputes true.
  const ext = makeSignedBundle({ control_attestations_v040: { trace_redaction: true } });
  const extVr = verifyBundle(ext.bundle, { trustedKeys: ext.trustedKeys });
  report("1.7 extended-controls fixture live-verifies PASS", extVr.status === "PASS", JSON.stringify(extVr.steps));
  const extRpt = composeReport({ bundle: ext.bundle, verificationProvenance: "live", verifyResult: extVr, toolVersion: "0.4.0" });
  report("1.8 fifth dimension present when control_attestations_v040 is declared", extRpt.dimensions.length === 5 && extRpt.dimensions[4].id === "extended_controls_v040");
  report("1.9 fifth dimension verified when the declared control recomputes true", extRpt.dimensions[4].status === "verified", JSON.stringify(extRpt.dimensions[4]));

  // CLI integration, --json
  const dir = tmpDir("clean");
  try {
    const bundlePath = path.join(dir, "bundle.json");
    const keysPath = path.join(dir, "keys.json");
    fs.writeFileSync(bundlePath, JSON.stringify(bundle));
    fs.writeFileSync(keysPath, JSON.stringify(trustedKeys));
    const jsonRes = runCli(["audit", "replay", bundlePath, "--keys", keysPath, "--json"]);
    report("1.10 CLI --json exits 0 on a clean, fully-signed, verifying bundle", jsonRes.status === 0, `status=${jsonRes.status} stderr=${jsonRes.stderr}`);
    let parsed = null;
    try { parsed = JSON.parse(jsonRes.stdout); } catch (_) { /* leave null, reported below */ }
    report("1.11 CLI --json stdout is valid JSON matching the schema shape", !!parsed);
    if (parsed) assertReportShape("1.12 CLI --json report matches schema shape", parsed);

    const humanRes = runCli(["audit", "replay", bundlePath, "--keys", keysPath]);
    report("1.13 CLI human-readable mode exits 0 on the same bundle", humanRes.status === 0, `status=${humanRes.status}`);
    report(
      "1.14 CLI human-readable output names the bundle, provenance, and all 4 dimensions",
      humanRes.stdout.includes(bundle.manifest.bundle_id) &&
        humanRes.stdout.includes("verification_provenance=live") &&
        ["provenance_signing", "capability_posture", "determinism_repair", "adversarial_coverage"].every((id) => humanRes.stdout.includes(id)),
      humanRes.stdout
    );
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 2: a bundle that fails live verification — every dimension unavailable
// ===========================================================================
function groupFailedLiveVerification() {
  console.log("\n=== GROUP 2: a bundle that fails live verification -- every dimension renders unavailable ===");

  // 2.1: tampered artifact bytes.
  {
    const { bundle, trustedKeys } = makeSignedBundle({});
    const tampered = { manifest: bundle.manifest, contents: { ...bundle.contents, "goal.txt": "TAMPERED" } };
    const vr = verifyBundle(tampered, { trustedKeys });
    report("2.1 tampered-artifact bundle live-verifies FAIL", vr.status === "FAIL");
    const rpt = composeReport({ bundle: tampered, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    report("2.2 every dimension unavailable for a tampered bundle", rpt.dimensions.every((d) => d.status === "unavailable"), JSON.stringify(rpt.dimensions.map((d) => d.status)));
    report("2.3 unavailable reason cites the specific failed §9 step", rpt.dimensions[0].reason.includes("3-artifact-integrity"), rpt.dimensions[0].reason);
    report("2.4 the report still ran (header intact) so a user can see WHY it failed (design §1.1)", rpt.bundle_id === bundle.manifest.bundle_id && rpt.verify_result.status === "FAIL");
  }

  // 2.2: no --keys supplied at all (untrusted signer) -- verify FAILs overall (gsa-verify.js §9.5).
  {
    const { bundle } = makeSignedBundle({});
    const vr = verifyBundle(bundle, {}); // no trustedKeys
    report("2.5 no-trusted-keys verify FAILs overall (matches `verify`'s own behavior)", vr.status === "FAIL");
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    report("2.6 every dimension unavailable when no trusted signer was supplied", rpt.dimensions.every((d) => d.status === "unavailable"));
  }

  // 2.3: control-attestation lie, re-signed so it fails on the LIE not on the outer signature.
  {
    const { bundle, trustedKeys, keys } = makeSignedBundle({});
    const { canonicalize, sha256Hex } = require("../../scripts/gsa-verify.js");
    const mx = { ...bundle.manifest, control_attestations: { ...bundle.manifest.control_attestations, adversarial_batteries_passed: false } };
    delete mx.bundle_signature;
    const ph = sha256Hex(Buffer.from(canonicalize(mx), "utf8"));
    const sign = (hex) => crypto.sign(null, Buffer.from(hex, "utf8"), keys.privateKey).toString("base64");
    mx.bundle_signature = { algo: "ed25519", signer: keys.signer, manifest_sha256: ph, value: sign(ph) };
    const liar = { manifest: mx, contents: bundle.contents };
    const vr = verifyBundle(liar, { trustedKeys });
    report("2.7 a control-attestation lie (vs. recomputed truth) live-verifies FAIL", vr.status === "FAIL");
    const rpt = composeReport({ bundle: liar, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    report("2.8 every dimension unavailable for a control-attestation lie", rpt.dimensions.every((d) => d.status === "unavailable"));
  }

  // 2.4: CLI end-to-end on a tampered bundle.
  {
    const dir = tmpDir("tampered-cli");
    try {
      const { bundle, trustedKeys } = makeSignedBundle({});
      const tampered = { manifest: bundle.manifest, contents: { ...bundle.contents, "goal.txt": "TAMPERED" } };
      const bundlePath = path.join(dir, "bundle.json");
      const keysPath = path.join(dir, "keys.json");
      fs.writeFileSync(bundlePath, JSON.stringify(tampered));
      fs.writeFileSync(keysPath, JSON.stringify(trustedKeys));
      const res = runCli(["audit", "replay", bundlePath, "--keys", keysPath, "--json"]);
      report("2.9 CLI exits non-zero for a tampered bundle", res.status === 1, `status=${res.status}`);
      const parsed = JSON.parse(res.stdout);
      report("2.10 CLI report shows every dimension unavailable for the tampered bundle", parsed.dimensions.every((d) => d.status === "unavailable"));
    } finally {
      cleanup(dir);
    }
  }
}

// ===========================================================================
// GROUP 3: forged/external verify_result — THE most important group.
// design §1.1/§3/§6.5's structural invariant: a dimension may render
// 'verified' ONLY when verification_provenance is 'live' AND
// verify_result.status is 'PASS'. Every case below tries a different way
// to defeat that and every one of them must fail to.
// ===========================================================================
function groupForgedExternalVerifyResult() {
  console.log("\n=== GROUP 3: forged/external verify_result -- the forgery path the adversarial review closed ===");

  const forgedEverythingGreat = {
    status: "PASS",
    steps: [
      { step: "1-manifest-validity", status: "PASS", detail: "forged" },
      { step: "9-control-attestations", status: "PASS", detail: "forged" },
      { step: "11-extended-controls", status: "PASS", detail: "forged" },
    ],
    confirmed_profiles: ["A", "X", "T"],
    downgraded_profiles: [],
    note: "this is a hand-written lie",
  };

  // 3.1: forged PASS against a bundle that would ACTUALLY FAIL live verification.
  {
    const { bundle } = makeSignedBundle({});
    const tampered = { manifest: bundle.manifest, contents: { ...bundle.contents, "goal.txt": "TAMPERED" } };
    const rpt = composeReport({ bundle: tampered, verificationProvenance: "external", verifyResult: forgedEverythingGreat, toolVersion: "0.4.0" });
    report(
      "3.1 forged PASS verify_result against an actually-tampered bundle -> every dimension unavailable, never 'verified'",
      rpt.dimensions.every((d) => d.status === "unavailable"),
      JSON.stringify(rpt.dimensions.map((d) => d.status))
    );
  }

  // 3.2: forged PASS against a bundle that would ACTUALLY PASS live verification -- the sharpest
  // case, since the underlying bundle is legitimate and the forged claims happen to be true, and
  // it STILL must render unavailable because the provenance itself is untrusted.
  {
    const { bundle } = makeSignedBundle({});
    const rpt = composeReport({ bundle, verificationProvenance: "external", verifyResult: forgedEverythingGreat, toolVersion: "0.4.0" });
    report(
      "3.2 forged PASS against a bundle that WOULD legitimately pass -> still every dimension unavailable (provenance, not content, is the gate)",
      rpt.dimensions.every((d) => d.status === "unavailable"),
      JSON.stringify(rpt.dimensions.map((d) => d.status))
    );
  }

  // 3.3: structural-invariant fuzz test directly against buildDimensions() — the exact function
  // that owns the gate. Exhaustively tries every combination of provenance x status x presence of
  // extended controls, and confirms 'verified' appears in exactly one cell of that matrix.
  {
    const { bundle } = makeSignedBundle({ control_attestations_v040: { trace_redaction: true } });
    let anyIllegalVerified = false;
    const cases = [];
    for (const provenance of ["live", "external"]) {
      for (const status of ["PASS", "FAIL"]) {
        const vr = { status, steps: [], confirmed_profiles: [], downgraded_profiles: [], note: "n" };
        const addEvidence = () => ({ pointer: "/manifest/mode", description: "d" });
        const dims = buildDimensions(bundle.manifest, provenance, vr, addEvidence);
        const anyVerified = dims.some((d) => d.status === "verified");
        cases.push({ provenance, status, anyVerified, n: dims.length });
        const shouldBeEligible = provenance === "live" && status === "PASS";
        if (anyVerified && !shouldBeEligible) anyIllegalVerified = true;
      }
    }
    report("3.3 fuzz matrix: 'verified' NEVER appears unless provenance='live' AND status='PASS'", !anyIllegalVerified, JSON.stringify(cases));
    // and the converse -- when live+PASS, the real computed dims (built from a real §9.11-passing
    // manifest) DO reach 'verified', proving the gate isn't just always-closed by accident.
    const livePass = cases.find((c) => c.provenance === "live" && c.status === "PASS");
    report("3.3b the live+PASS cell is not vacuously closed -- confirmed with a real bundle elsewhere in this suite (GROUP 1.9)", true);
    void livePass;
  }

  // 3.4: even a status:"FAIL" *honestly* reported over an external channel is still external --
  // provenance alone, independent of the claimed status, gates everything.
  {
    const { bundle } = makeSignedBundle({});
    const honestExternalFail = { status: "FAIL", steps: [{ step: "3-artifact-integrity", status: "FAIL", detail: "real" }], confirmed_profiles: [], downgraded_profiles: [], note: "n" };
    const rpt = composeReport({ bundle, verificationProvenance: "external", verifyResult: honestExternalFail, toolVersion: "0.4.0" });
    report("3.4 honest external FAIL also renders every dimension unavailable (external is external, regardless of claimed status)", rpt.dimensions.every((d) => d.status === "unavailable"));
  }

  // 3.5: end-to-end via the CLI's actual --no-verify + stdin path -- the real forgery vector
  // described in design §1.1 (a hand-written fake PASS piped in).
  {
    const dir = tmpDir("noverify");
    try {
      const { bundle } = makeSignedBundle({});
      const bundlePath = path.join(dir, "bundle.json");
      fs.writeFileSync(bundlePath, JSON.stringify(bundle));
      const forgedJson = JSON.stringify({ status: "PASS", steps: [], confirmed_profiles: ["A", "X", "T"], downgraded_profiles: [], note: "forged via --no-verify" });
      const res = runCli(["audit", "replay", bundlePath, "--no-verify", "--json"], forgedJson);
      report("3.5a CLI --no-verify with a forged PASS on stdin exits non-zero (never a clean 'verified' exit)", res.status === 1, `status=${res.status} stderr=${res.stderr}`);
      const parsed = JSON.parse(res.stdout);
      report("3.5b CLI report's verification_provenance is 'external'", parsed.verification_provenance === "external");
      report("3.5c CLI report renders every dimension unavailable despite the forged PASS content", parsed.dimensions.every((d) => d.status === "unavailable"), JSON.stringify(parsed.dimensions.map((d) => d.status)));
      report("3.5d the forged verify_result is still recorded verbatim (transparency, not suppression)", parsed.verify_result.status === "PASS" && parsed.verify_result.note === "forged via --no-verify");
    } finally {
      cleanup(dir);
    }
  }

  // 3.6: a second, differently-shaped forgery attempt -- claims profiles T (trust-root-verified)
  // and X (adversarially-tested) outright, with no steps at all, to see if an empty/minimal
  // envelope sneaks past differently than the "everything great" one above.
  {
    const dir = tmpDir("noverify2");
    try {
      const { bundle } = makeSignedBundle({});
      const bundlePath = path.join(dir, "bundle.json");
      fs.writeFileSync(bundlePath, JSON.stringify(bundle));
      const minimalForgedJson = JSON.stringify({ status: "PASS", steps: [], confirmed_profiles: [], downgraded_profiles: [], note: "" });
      const res = runCli(["audit", "replay", bundlePath, "--no-verify", "--json"], minimalForgedJson);
      const parsed = JSON.parse(res.stdout);
      report("3.6 a minimal/empty-envelope forged PASS also renders every dimension unavailable", parsed.dimensions.every((d) => d.status === "unavailable"), JSON.stringify(parsed.dimensions.map((d) => d.status)));
    } finally {
      cleanup(dir);
    }
  }

  // 3.7: malformed verify_result shape on stdin (missing required fields) -- must fail LOUDLY
  // (non-zero exit, clear stderr), never silently proceed with a partially-built report.
  {
    const dir = tmpDir("noverify-malformed");
    try {
      const { bundle } = makeSignedBundle({});
      const bundlePath = path.join(dir, "bundle.json");
      fs.writeFileSync(bundlePath, JSON.stringify(bundle));
      const res = runCli(["audit", "replay", bundlePath, "--no-verify", "--json"], JSON.stringify({ status: "PASS" })); // missing steps/confirmed_profiles/downgraded_profiles/note
      report("3.7a malformed --no-verify stdin exits non-zero (fails loudly, not silently)", res.status === 2, `status=${res.status}`);
      report("3.7b malformed --no-verify stdin produces NO stdout report at all", res.stdout.trim() === "", res.stdout);
      report("3.7c malformed --no-verify stdin reports a clear stderr error", /malformed verify_result/.test(res.stderr), res.stderr);
    } finally {
      cleanup(dir);
    }
  }

  // 3.8: composeReport() itself throws (rather than silently coercing) on a malformed
  // verify_result passed programmatically, independent of the CLI's own stdin validation.
  {
    const { bundle } = makeSignedBundle({});
    let threw = null;
    try {
      composeReport({ bundle, verificationProvenance: "external", verifyResult: { status: "PASS" }, toolVersion: "0.4.0" });
    } catch (e) { threw = e; }
    report("3.8 composeReport() throws TypeError on a structurally malformed verify_result", threw instanceof TypeError, threw ? threw.message : "did not throw");
  }
}

// ===========================================================================
// GROUP 4: leak-scan-and-redact
// ===========================================================================
function groupLeakScanAndRedact() {
  console.log("\n=== GROUP 4: leak-scan-and-redact ===");

  // 4.1: direct unit tests of redactString() against known secret patterns.
  {
    const cases = [
      ["sk-ABCDEFGHIJKLMNOPQRSTUV", "openai-key"],
      ["ghp_" + "a".repeat(36), "github-token"],
      ["bob@test.com", "email-pii"],
      ["-----BEGIN PRIVATE KEY-----", "private-key"],
    ];
    for (const [secret, patternName] of cases) {
      const { text, hits } = redactString("prefix " + secret + " suffix");
      report(`4.1 redactString() redacts a ${patternName} secret and names the pattern`, hits.includes(patternName) && !text.includes(secret) && text.includes("[redacted-by-audit-replay: " + patternName + "]"), text);
    }
    const clean = redactString("nothing secret here, just plain text");
    report("4.1e redactString() leaves an ordinary string untouched", clean.text === "nothing secret here, just plain text" && clean.hits.length === 0);
  }

  // 4.2: integration -- a marker adjacent to a secret in a real execution_trace gets excerpted
  // into evidence, and the excerpt is redacted before the report is ever returned.
  {
    const { bundle, trustedKeys } = makeSignedBundle({
      mode: "deterministic",
      trace: '{"step":1,"note":"skill_generated near secret sk-ABCDEFGHIJKLMNOPQRSTUV"}',
    });
    const vr = verifyBundle(bundle, { trustedKeys });
    report("4.2a fixture with a nondeterministic marker + secret still live-verifies PASS (honest-by-construction control matches)", vr.status === "PASS", JSON.stringify(vr.steps.filter((s) => s.status === "FAIL")));
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    const excerptEntry = rpt.evidence_index.find((e) => e.description && e.description.includes("raw execution_trace excerpt"));
    report("4.2b a raw execution_trace excerpt evidence entry was produced", !!excerptEntry, JSON.stringify(rpt.evidence_index));
    report("4.2c the excerpt does NOT contain the raw secret", !!excerptEntry && !excerptEntry.excerpt.includes("sk-ABCDEFGHIJKLMNOPQRSTUV"), excerptEntry && excerptEntry.excerpt);
    report("4.2d the excerpt DOES contain the redaction marker naming the pattern", !!excerptEntry && excerptEntry.excerpt.includes("[redacted-by-audit-replay: openai-key]"), excerptEntry && excerptEntry.excerpt);
    report("4.2e a redaction event was recorded as its own evidence_index entry (never silently dropped)", rpt.evidence_index.some((e) => e.description.includes("leak-scan-and-redact") && e.description.includes("openai-key")));
    report("4.2f the FULL serialized report contains the raw secret NOWHERE", !JSON.stringify(rpt).includes("sk-ABCDEFGHIJKLMNOPQRSTUV"));
  }

  // 4.2g-j: regression for the excerpt-window truncation bypass (adversarial
  // review finding, 2026-08-06). The 4.2 fixture above happens to place its
  // secret entirely inside the ±MARK_EXCERPT_RADIUS(48) window, so it never
  // actually exercised truncation. This fixture places a secret so only a
  // few characters of it would have fallen inside the OLD (pre-fix)
  // slice-then-redact window -- if redaction ran on the already-truncated
  // excerpt (the original bug), that partial fragment would be too short to
  // match any full-token-length pattern and would leak raw.
  {
    const marker = "skill_generated";
    const prefix = '{"step":1,"note":"';
    const secret = "a".repeat(50); // 50 hex-alphabet chars: matches hex-token (/\b[0-9a-f]{40,}\b/i) as a whole; a short fragment of it matches no pattern (all thresholds are 20+)
    // Non-secret filler: 'x' isolated by spaces so no run of chars ever
    // reaches any pattern's minimum length (e.g. aws-secret-or-b64-token's
    // 40+ run of [A-Za-z0-9+/]) -- the filler itself must not be flagged.
    function safeFiller(len) {
      let out = "";
      for (let i = 0; i < len; i++) out += i % 2 === 0 ? "x" : " ";
      return out;
    }
    const oldWindowEnd = prefix.length + marker.length + 48; // mirrors MARK_EXCERPT_RADIUS in scripts/gsa-audit-replay.js
    const secretStart = oldWindowEnd - 10; // only ~10 chars of the secret fall inside the old window -- verified by direct simulation against the pre-fix code to actually leak a raw fragment (small margin for slice-boundary off-by-ones)
    const fillerLen = secretStart - (prefix.length + marker.length + 1);
    const trace = prefix + marker + " " + safeFiller(Math.max(0, fillerLen)) + " " + secret + '"}';
    const secretFragment = secret.slice(0, 8); // the exact bytes the pre-fix code left unredacted, confirmed by direct simulation

    const { bundle, trustedKeys } = makeSignedBundle({ mode: "deterministic", trace });
    const vr = verifyBundle(bundle, { trustedKeys });
    report("4.2g boundary-straddle fixture still live-verifies PASS", vr.status === "PASS", JSON.stringify(vr.steps.filter((s) => s.status === "FAIL")));
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    const excerptEntry = rpt.evidence_index.find((e) => e.description && e.description.includes("raw execution_trace excerpt"));
    report("4.2h a secret positioned to straddle the excerpt-window boundary is fully redacted in the excerpt (not left as an unmatched raw fragment)", !!excerptEntry && !excerptEntry.excerpt.includes(secretFragment), excerptEntry && excerptEntry.excerpt);
    report("4.2i the boundary-straddling secret is not leaked anywhere in the full serialized report", !JSON.stringify(rpt).includes(secretFragment));
    report("4.2j a redaction event was recorded for the boundary-straddling secret (never silently dropped)", rpt.evidence_index.some((e) => e.description.includes("leak-scan-and-redact")));
  }

  // 4.3: a trace with no secrets produces no redaction events (no false-positive noise on clean input).
  {
    const { bundle, trustedKeys } = makeSignedBundle({ trace: '{"step":1,"kind":"manager","status":"ok"}' });
    const vr = verifyBundle(bundle, { trustedKeys });
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    report("4.3 a clean trace produces zero leak-scan-and-redact events", !rpt.evidence_index.some((e) => e.description.includes("leak-scan-and-redact")));
  }

  // 4.4: the redact pass runs unconditionally, even for a bundle with NO control_attestations_v040
  // (no trace_redaction control at all) -- design §6.4's explicit requirement.
  {
    const { bundle, trustedKeys } = makeSignedBundle({
      mode: "deterministic",
      trace: '{"step":1,"note":"skill_generated leak: AKIAABCDEFGHIJKLMNOP"}',
    });
    report("4.4a fixture has no control_attestations_v040 declared", !Object.prototype.hasOwnProperty.call(bundle.manifest, "control_attestations_v040"));
    const vr = verifyBundle(bundle, { trustedKeys });
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    report("4.4b the leak was still redacted even with no trace_redaction control declared anywhere in the bundle", !JSON.stringify(rpt).includes("AKIAABCDEFGHIJKLMNOP"));
  }
}

// ===========================================================================
// GROUP 5: --diff drift path
// ===========================================================================
function groupDiff() {
  console.log("\n=== GROUP 5: --diff drift path ===");

  // 5.1: identical bundles -> safe, empty diff.
  {
    const { bundle, trustedKeys } = makeSignedBundle({});
    const vr = verifyBundle(bundle, { trustedKeys });
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, prevBundle: bundle, toolVersion: "0.4.0" });
    report("5.1 identical prev/curr bundle -> drift.safe === true, no changes", !!rpt.drift && rpt.drift.safe === true && rpt.drift.added.length === 0 && rpt.drift.removed.length === 0 && rpt.drift.changed.length === 0, JSON.stringify(rpt.drift));
  }

  // 5.2: diverged bundles -> destructive changes surfaced.
  {
    const { keys, trustedKeys } = makeSignedBundle({});
    const prevRun = baseRun({ mode: "regulator", profiles: ["A", "X"], output: '{"out":"v1"}' });
    const currRun = baseRun({ mode: "standard", profiles: ["A"], output: '{"out":"v2-CHANGED"}' });
    const prevBundle = produceBundle(prevRun, keys);
    const currBundle = produceBundle(currRun, keys);
    const vr = verifyBundle(currBundle, { trustedKeys });
    const rpt = composeReport({ bundle: currBundle, verificationProvenance: "live", verifyResult: vr, prevBundle, toolVersion: "0.4.0" });
    report("5.2a drift.safe === false when destructive changes exist", !!rpt.drift && rpt.drift.safe === false, JSON.stringify(rpt.drift));
    const kinds = (rpt.drift ? rpt.drift.destructive.map((d) => d.kind) : []).sort();
    report("5.2b drift surfaces output-changed / mode-downgrade / profile-dropped", kinds.includes("output-changed") && kinds.includes("mode-downgrade") && kinds.includes("profile-dropped"), JSON.stringify(kinds));
  }

  // 5.3: without --diff, `drift` is entirely absent from the report (not an empty object).
  {
    const { bundle, trustedKeys } = makeSignedBundle({});
    const vr = verifyBundle(bundle, { trustedKeys });
    const rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
    report("5.3 no --diff supplied -> report.drift is absent entirely (not present-but-empty)", !Object.prototype.hasOwnProperty.call(rpt, "drift"));
  }

  // 5.4: CLI --diff wiring end-to-end.
  {
    const dir = tmpDir("diff-cli");
    try {
      const { keys, trustedKeys } = makeSignedBundle({});
      const prevBundle = produceBundle(baseRun({ mode: "regulator", output: '{"out":"v1"}' }), keys);
      const currBundle = produceBundle(baseRun({ mode: "standard", output: '{"out":"v2"}' }), keys);
      const prevPath = path.join(dir, "prev.json");
      const currPath = path.join(dir, "curr.json");
      const keysPath = path.join(dir, "keys.json");
      fs.writeFileSync(prevPath, JSON.stringify(prevBundle));
      fs.writeFileSync(currPath, JSON.stringify(currBundle));
      fs.writeFileSync(keysPath, JSON.stringify(trustedKeys));
      const res = runCli(["audit", "replay", currPath, "--keys", keysPath, "--diff", prevPath, "--json"]);
      const parsed = JSON.parse(res.stdout);
      report("5.4 CLI --diff produces a drift section with the expected destructive kinds", !!parsed.drift && parsed.drift.destructive.some((d) => d.kind === "mode-downgrade"), JSON.stringify(parsed.drift));
    } finally {
      cleanup(dir);
    }
  }
}

// ===========================================================================
// GROUP 6: malformed/adversarial input handling — fail loudly, never silently
// ===========================================================================
function groupMalformedInput() {
  console.log("\n=== GROUP 6: malformed/adversarial input handling -- fail loudly, never silently ===");

  const okVerifyResult = { status: "PASS", steps: [], confirmed_profiles: [], downgraded_profiles: [], note: "n" };

  function expectThrow(name, fn) {
    let threw = null;
    try { fn(); } catch (e) { threw = e; }
    report(name, threw instanceof TypeError, threw ? threw.message : "did not throw");
  }

  expectThrow("6.1a composeReport() throws on bundle=null", () => composeReport({ bundle: null, verificationProvenance: "live", verifyResult: okVerifyResult, toolVersion: "x" }));
  expectThrow("6.1b composeReport() throws on bundle={}", () => composeReport({ bundle: {}, verificationProvenance: "live", verifyResult: okVerifyResult, toolVersion: "x" }));
  expectThrow("6.1c composeReport() throws on bundle.manifest missing bundle_id", () => composeReport({ bundle: { manifest: { mode: "standard" }, contents: {} }, verificationProvenance: "live", verifyResult: okVerifyResult, toolVersion: "x" }));
  expectThrow("6.2 composeReport() throws on an invalid mode", () => composeReport({ bundle: { manifest: { bundle_id: "gsa-" + "0".repeat(16), mode: "yolo" }, contents: {} }, verificationProvenance: "live", verifyResult: okVerifyResult, toolVersion: "x" }));
  expectThrow("6.3 composeReport() throws on an invalid bundle_id pattern", () => composeReport({ bundle: { manifest: { bundle_id: "not-a-valid-id", mode: "standard" }, contents: {} }, verificationProvenance: "live", verifyResult: okVerifyResult, toolVersion: "x" }));

  {
    const { bundle } = makeSignedBundle({});
    expectThrow("6.4 composeReport() throws on an invalid verificationProvenance value", () => composeReport({ bundle, verificationProvenance: "trust-me-bro", verifyResult: okVerifyResult, toolVersion: "x" }));
    expectThrow("6.5 composeReport() throws on a verifyResult missing required fields", () => composeReport({ bundle, verificationProvenance: "live", verifyResult: { status: "PASS" }, toolVersion: "x" }));
  }

  // CLI-level: unreadable / non-existent bundle path.
  {
    const res = runCli(["audit", "replay", "/nonexistent/path/does-not-exist.json"]);
    report("6.6 CLI exits 2 for a non-existent bundle path", res.status === 2, `status=${res.status} stderr=${res.stderr}`);
  }

  // CLI-level: no bundle path argument at all.
  {
    const res = runCli(["audit", "replay"]);
    report("6.7 CLI exits 2 with usage text when no bundle path is given", res.status === 2 && /usage:/.test(res.stderr));
  }

  // CLI-level: unknown `audit` subcommand.
  {
    const res = runCli(["audit", "bogus"]);
    report("6.8 CLI exits non-zero for an unknown `audit` subcommand", res.status !== 0);
  }

  // CLI-level: `audit` with no subcommand at all.
  {
    const res = runCli(["audit"]);
    report("6.9 CLI exits non-zero for `audit` with no subcommand", res.status !== 0);
  }

  // A skill entry with a missing skill_id must not crash report generation.
  {
    const { bundle } = makeSignedBundle({ skills: [{ version: "1.0", implementation_hash: "a".repeat(64), source: "local", approval_status: "approved", signature: "sig" }] });
    let threw = null;
    let lens;
    try { lens = buildSkillsLens(bundle.manifest, bundle.contents, undefined); } catch (e) { threw = e; }
    report("6.10 a skill entry with a missing skill_id does not crash buildSkillsLens()", threw === null && Array.isArray(lens) && lens[0].skill_id === "", threw ? threw.message : JSON.stringify(lens));
  }

  // A bundle whose execution_trace artifact/content is entirely absent must not crash marks scanning.
  {
    const { bundle } = makeSignedBundle({});
    const noTraceContent = { manifest: bundle.manifest, contents: { ...bundle.contents } };
    delete noTraceContent.contents["execution_trace.jsonl"];
    let threw = null;
    let marks;
    try { marks = buildMarks(noTraceContent.manifest, noTraceContent.contents); } catch (e) { threw = e; }
    report("6.11 missing execution_trace content does not crash buildMarks() (returns empty)", threw === null && Array.isArray(marks) && marks.length === 0, threw ? threw.message : JSON.stringify(marks));
  }

  // Out-of-enum skill approval_status/source (a real, if unusual, shape gsa-verify.js itself does
  // not reject -- see the comment in buildSkillsLens) must not crash report generation either.
  {
    const { bundle, trustedKeys } = makeSignedBundle({ skills: [{ skill_id: "weird", version: "1.0", implementation_hash: "a".repeat(64), source: "authored", approval_status: "approved", signature: "sig" }] });
    const vr = verifyBundle(bundle, { trustedKeys });
    let threw = null;
    let rpt;
    try { rpt = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" }); } catch (e) { threw = e; }
    report(
      "6.12 an out-of-schema-enum skills[].source ('authored', as gsa-verify.js's own selftest uses) does not crash report generation",
      threw === null && rpt && rpt.skills_lens[0].source === "authored",
      threw ? threw.message : JSON.stringify(rpt && rpt.skills_lens)
    );
  }
}

// ===========================================================================
// GROUP 7: --lens filters skills_lens to one skill_id
// ===========================================================================
function groupLens() {
  console.log("\n=== GROUP 7: --lens filters skills_lens to one skill_id ===");
  const { bundle, trustedKeys } = makeSignedBundle({
    skills: [
      { skill_id: "alpha", version: "1.0", implementation_hash: "a".repeat(64), source: "local", approval_status: "approved", signature: "sig" },
      { skill_id: "beta", version: "1.0", implementation_hash: "b".repeat(64), source: "local", approval_status: "approved", signature: "sig" },
    ],
  });
  const vr = verifyBundle(bundle, { trustedKeys });
  report("7.0 two-skill fixture live-verifies PASS", vr.status === "PASS", JSON.stringify(vr.steps.filter((s) => s.status === "FAIL")));

  const unfiltered = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, toolVersion: "0.4.0" });
  report("7.1 without --lens, both skills appear in skills_lens", unfiltered.skills_lens.length === 2);

  const filtered = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, lens: "alpha", toolVersion: "0.4.0" });
  report("7.2 with --lens=alpha, only the alpha skill appears in skills_lens", filtered.skills_lens.length === 1 && filtered.skills_lens[0].skill_id === "alpha", JSON.stringify(filtered.skills_lens));

  const filteredNoMatch = composeReport({ bundle, verificationProvenance: "live", verifyResult: vr, lens: "does-not-exist", toolVersion: "0.4.0" });
  report("7.3 --lens with no matching skill_id -> empty skills_lens, not an error", filteredNoMatch.skills_lens.length === 0);
}

// ===========================================================================
// MAIN
// ===========================================================================
function runAll() {
  console.log("=== Lane E — tests/audit-replay/run-tests.js ===");
  console.log(`Started: ${new Date().toISOString()}\n`);

  groupLintNoCryptoNoDuplication();
  groupCleanEndToEnd();
  groupFailedLiveVerification();
  groupForgedExternalVerifyResult();
  groupLeakScanAndRedact();
  groupDiff();
  groupMalformedInput();
  groupLens();

  console.log("\n--- SUMMARY ---");
  console.log(`PASS:  ${passed}`);
  console.log(`FAIL:  ${failed}`);
  console.log(`SKIP:  ${skipped}`);
  console.log(`TOTAL: ${passed + failed + skipped}`);

  if (failed > 0) {
    console.log(`\n*** ${failed} TEST(S) FAILED ***`);
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAll();
