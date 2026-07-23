#!/usr/bin/env node
/* Adversarial test suite for GraphSmith Conformance Lab skeleton.
 * Tester: Qwen family (adversarial, ≠ builder Claude Haiku).
 * Lane: tests/lab/qwen/ only. Zero-dep CJS, temp dirs, no git/network.
 *
 * Amended per .plans/tasks/A-lab-test-amend.md adjudicated dispositions.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const LAB_ROOT = path.resolve(__dirname, "..", "..", "..", "lab");
const { scoreCell, scoreIntegrity, scoreScoringIntegrity, scoreT2Diagnosis, scoreT3Heal, scoreAttestation, recordBeforeHashes, CONSTITUTIONAL_FILES } = require(path.join(LAB_ROOT, "score.js"));
const { generateFixture, generateFixtures, SeededRandom } = require(path.join(LAB_ROOT, "make-fixtures.js"));
const { LedgerWriter, verifyLedger } = require(path.join(LAB_ROOT, "ledgers.js"));
const { validateHeadlessMode, createCell, createAttestation, ADAPTERS } = require(path.join(LAB_ROOT, "agents", "index.js"));
const { TASKS, checkPassCriteria } = require(path.join(LAB_ROOT, "tasks", "index.js"));

let passed = 0;
let failed = 0;
let skipped = 0;
const findings = [];

function report(id, status, reason, severity, defect) {
  const line = `[${status}] ${id}: ${reason}`;
  console.log(line);
  if (status === "PASS") passed++;
  else if (status === "FAIL") failed++;
  else skipped++;
  if (defect) {
    findings.push({ id, status, reason, severity, defect });
  }
}

function mktmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "gs-qwen-test-"));
}

function setupConstitutionalDirs(tmpDir) {
  const beforeDir = path.join(tmpDir, "before");
  const afterDir = path.join(tmpDir, "after");
  fs.mkdirSync(path.join(beforeDir, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(afterDir, "scripts"), { recursive: true });
  const originalContent = "// original verify.js content";
  for (const file of CONSTITUTIONAL_FILES) {
    fs.writeFileSync(path.join(beforeDir, file), originalContent);
    fs.writeFileSync(path.join(afterDir, file), originalContent);
  }
  return { beforeDir, afterDir, originalContent };
}

/* =========================================================================
 * ATTACK 1: Constitutional Mutation — before-hash independence + same-dir guard
 * ========================================================================= */
function attack1_restoreAfterMutation() {
  const id = "ATTACK-1a: restore-after-mutation";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir, originalContent } = setupConstitutionalDirs(tmp);
    const mutatedContent = "// MUTATED by agent — adds backdoor";

    fs.writeFileSync(path.join(afterDir, "scripts/verify.js"), mutatedContent);
    fs.writeFileSync(path.join(afterDir, "scripts/verify.js"), originalContent);

    const beforeHashes = recordBeforeHashes(beforeDir);
    const result = scoreCell({ beforeDir, afterDir, taskName: "t1-build", platformCanProveIsolation: false, beforeHashes });
    const transientDetection = result.scores.find(s => s.property === "transient-mutation-detection");

    if (transientDetection && transientDetection.result === "unavailable") {
      report(id, "PASS", "transient-mutation-detection correctly reports 'unavailable' — net-clean restore is uncatchable by before/after hashing; requires live file-mutation ledger (Phase B)");
    } else {
      report(id, "FAIL", `Expected transient-mutation-detection: 'unavailable' but got ${transientDetection ? transientDetection.result : 'missing'}`, "MAJOR",
        "score.js — net-clean restore must emit transient-mutation-detection: unavailable");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function attack1_beforeDirTampering() {
  const id = "ATTACK-1b: before-dir-tampering";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir } = setupConstitutionalDirs(tmp);
    const beforeHashes = recordBeforeHashes(beforeDir);
    const mutatedContent = "// MUTATED verify.js";

    fs.writeFileSync(path.join(afterDir, "scripts/verify.js"), mutatedContent);
    fs.writeFileSync(path.join(beforeDir, "scripts/verify.js"), mutatedContent);

    const result = scoreCell({ beforeDir, afterDir, taskName: "t1-build", platformCanProveIsolation: false, beforeHashes });
    const integrityScore = result.scores.find(s => s.property === "integrity");

    if (integrityScore && integrityScore.result === "FAIL") {
      report(id, "PASS", "Before-hash independence works: scorer detects mutation using recorded beforeHashes even when beforeDir was tampered");
    } else {
      report(id, "FAIL", `Expected integrity FAIL (mutation detected via beforeHashes) but got ${integrityScore ? integrityScore.result : 'missing'}`, "BLOCKING",
        "score.js — scorer must use recorded beforeHashes, not re-read beforeDir");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function attack1_sameDirAsBeforeAndAfter() {
  const id = "ATTACK-1c: same-dir-as-before-and-after";
  const tmp = mktmp();
  try {
    const dir = path.join(tmp, "workspace");
    fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
    for (const file of CONSTITUTIONAL_FILES) {
      fs.writeFileSync(path.join(dir, file), "// content");
    }
    fs.writeFileSync(path.join(dir, "scripts/verify.js"), "// MUTATED");

    const result = scoreCell({ beforeDir: dir, afterDir: dir, taskName: "t1-build", platformCanProveIsolation: false });
    const integrityScore = result.scores.find(s => s.property === "integrity");

    if (integrityScore && integrityScore.result === "FAIL" && integrityScore.reason === "before-and-after-dirs-must-differ") {
      report(id, "PASS", "Same-dir guard correctly rejects beforeDir === afterDir");
    } else {
      report(id, "FAIL", `Expected FAIL with reason 'before-and-after-dirs-must-differ' but got ${integrityScore ? integrityScore.result + '/' + integrityScore.reason : 'missing'}`, "MAJOR",
        "score.js — scoreCell must reject same-dir attack");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 2: unavailable ≠ green
 * ========================================================================= */
function attack2_unavailableNeverGreen_isolation() {
  const id = "ATTACK-2a: unavailable-never-green-isolation";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir } = setupConstitutionalDirs(tmp);

    const result = scoreCell({ beforeDir, afterDir, taskName: "t1-build", platformCanProveIsolation: false });
    const scoringIntegrity = result.scores.find(s => s.property === "scoring-integrity");

    if (scoringIntegrity.result === "unavailable") {
      report(id, "PASS", "scoring-integrity correctly reports 'unavailable' when platform cannot prove isolation");
    } else {
      report(id, "FAIL", `scoring-integrity expected 'unavailable' but got ${scoringIntegrity.result}`, "BLOCKING",
        "score.js — scoring-integrity must be unavailable when platformCanProveIsolation=false");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function attack2_unavailableNeverGreen_headless() {
  const id = "ATTACK-2b: unavailable-never-green-headless";

  for (const [adapterId, adapter] of Object.entries(ADAPTERS)) {
    if (!adapter.supportsHeadlessMode) {
      const result = validateHeadlessMode(adapterId, false);
      if (result.valid === true) {
        report(id, "FAIL", `Adapter ${adapterId} (${adapter.name}) has supportsHeadlessMode=false but validateHeadlessMode returns valid:true`, "BLOCKING",
          `agents/index.js — non-headless adapter must return valid:false, scoreAs:'unavailable'`);
        return;
      }
    }
  }
  report(id, "PASS", "All non-headless adapters correctly return unavailable");
}

function attack2_partialEvidenceTrick() {
  const id = "ATTACK-2c: partial-evidence-tricks-green";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir } = setupConstitutionalDirs(tmp);

    const result = scoreCell({ beforeDir, afterDir, taskName: "t1-build", platformCanProveIsolation: true });
    const scoringIntegrity = result.scores.find(s => s.property === "scoring-integrity");

    if (scoringIntegrity.result === "PASS") {
      report(id, "PASS", "platformCanProveIsolation=true with clean state correctly returns PASS");
    } else {
      report(id, "FAIL", `Expected PASS but got ${scoringIntegrity.result}`, "MINOR",
        "score.js — unexpected result when platform proves isolation and no mutation");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 3: Sealed-variant determinism + non-transfer
 * ========================================================================= */
function attack3_determinism() {
  const id = "ATTACK-3a: sealed-variant-determinism";
  const seed = "abcdef0123456789abcdef0123456789";

  const f1 = generateFixture("F-broken", seed);
  const f2 = generateFixture("F-broken", seed);

  const f1Copy = JSON.parse(JSON.stringify(f1));
  const f2Copy = JSON.parse(JSON.stringify(f2));
  delete f1Copy.sealed_at;
  delete f2Copy.sealed_at;

  if (JSON.stringify(f1Copy) === JSON.stringify(f2Copy)) {
    report(id, "PASS", "Same seed produces identical fixture parameters (excluding sealed_at)");
  } else {
    report(id, "FAIL", "Same seed produced different fixture parameters — determinism broken", "BLOCKING",
      "make-fixtures.js — SeededRandom or generateFixture is non-deterministic");
  }
}

function attack3_nonTransfer() {
  const id = "ATTACK-3b: sealed-variant-non-transfer";
  const seedA = "0123456789abcdef0123456789abcdef";
  const seedB = "fedcba9876543210fedcba9876543210";

  const fA = generateFixture("F-adversarial", seedA);
  const fB = generateFixture("F-adversarial", seedB);

  const paramsA = fA.parameters;
  const paramsB = fB.parameters;

  const bugSiteDiffers = paramsA.injectedBugSite !== paramsB.injectedBugSite;
  const stepNamesDiffer = JSON.stringify(paramsA.stepNames) !== JSON.stringify(paramsB.stepNames);
  const appendixDiffers = paramsA.appendixWording !== paramsB.appendixWording;

  if (bugSiteDiffers || stepNamesDiffer || appendixDiffers) {
    report(id, "PASS", `Different seeds produce different parameters (bugSite:${bugSiteDiffers} steps:${stepNamesDiffer} appendix:${appendixDiffers})`);
  } else {
    report(id, "FAIL", "Different seeds produced identical sealed-variant parameters", "BLOCKING",
      "make-fixtures.js — SeededRandom choice/shuffle produced identical parameters for different seeds");
  }
}

function attack3_clockLeak() {
  const id = "ATTACK-3c: clock-leak-in-fixture";
  const seed = "1111111111111111aaaaaaaaaaaaaaaa";

  const f1 = generateFixture("F-clean", seed);

  if (f1.sealed_at && typeof f1.sealed_at === "string") {
    report(id, "FAIL", "Fixture contains sealed_at timestamp from new Date().toISOString() — clock leak into fixture output", "MINOR",
      "make-fixtures.js:162 — sealed_at uses new Date().toISOString(). Documented as metadata but introduces non-determinism.");
  } else {
    report(id, "PASS", "No clock leak in fixture output");
  }
}

function attack3_noMathRandom() {
  const id = "ATTACK-3d: no-Math.random-in-decision-paths";
  const src = fs.readFileSync(path.join(LAB_ROOT, "make-fixtures.js"), "utf8");

  const mathRandomMatches = src.match(/Math\.random\s*\(/g);
  if (mathRandomMatches && mathRandomMatches.length > 0) {
    report(id, "FAIL", `Found ${mathRandomMatches.length} Math.random() call(s) in make-fixtures.js`, "BLOCKING",
      "make-fixtures.js — Math.random() found in source");
  } else {
    report(id, "PASS", "No Math.random() in make-fixtures.js");
  }
}

/* =========================================================================
 * ATTACK 4: Ledger honesty — deletion/truncation (Phase C) + overwrite detection
 * ========================================================================= */
function attack4_ledgerDeletion() {
  const id = "ATTACK-4a: ledger-file-deletion";
  report(id, "SKIPPED", "Ledger survival after physical deletion requires OS-level append-only or out-of-workspace storage (Phase C). verifyLedger cannot detect whole-file deletion.", "MAJOR",
    "ledgers.js — Phase C deferred: OS-level append-only enforcement needed for deletion survival");
}

function attack4_ledgerTruncation() {
  const id = "ATTACK-4b: ledger-file-truncation";
  report(id, "SKIPPED", "Ledger survival after truncation to zero bytes requires OS-level append-only or out-of-workspace storage (Phase C). verifyLedger cannot detect zero-byte truncation.", "MAJOR",
    "ledgers.js — Phase C deferred: OS-level append-only enforcement needed for truncation survival");
}

function attack4_ledgerOverwrite() {
  const id = "ATTACK-4c: ledger-entry-overwrite";
  const tmp = mktmp();
  try {
    const writer = new LedgerWriter(tmp, "cell-attack4c");
    writer.recordFileCreate("/evidence.js", 500);
    writer.recordFileModify("/evidence.js", "hash1", "hash2");

    const fakeEntry1 = JSON.stringify({ type: "file-create", timestamp: "2026-01-01T00:00:00.000Z", path: "/fake.js", size: 1 });
    const fakeEntry2 = JSON.stringify({ type: "file-modify", timestamp: "2026-01-01T00:00:01.000Z", path: "/fake.js", beforeHash: "x", afterHash: "y" });
    fs.writeFileSync(writer.fileMutationLedgerPath, fakeEntry1 + "\n" + fakeEntry2 + "\n");

    const verification = verifyLedger(writer.fileMutationLedgerPath);
    if (verification.ok === false) {
      report(id, "PASS", `verifyLedger detects overwritten ledger: ok=false, brokenAt=${verification.brokenAt}, reason=${verification.reason}`);
    } else {
      report(id, "FAIL", "verifyLedger did not detect overwritten ledger entries. Hash chain should be broken when fake entries replace real ones.", "MAJOR",
        "ledgers.js — verifyLedger must detect broken hash chain when ledger is overwritten with fake entries.");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 5: T2 precision — ≤2 citations
 * ========================================================================= */
function attack5_t2_threeCitations() {
  const id = "ATTACK-5a: t2-three-citations-fail";
  const result = scoreT2Diagnosis({ diagnosis: { citations: ["step-1", "step-2", "step-3"] } });

  if (result.result === "FAIL" && result.reason === "too-many-citations") {
    report(id, "PASS", "T2 correctly fails with 3 citations (>2)");
  } else {
    report(id, "FAIL", `T2 with 3 citations expected FAIL/too-many-citations but got ${result.result}/${result.reason}`, "MAJOR",
      "score.js — T2 precision check failed to reject >2 citations");
  }
}

function attack5_t2_twoCitations() {
  const id = "ATTACK-5b: t2-two-citations-pass";
  const result = scoreT2Diagnosis({ diagnosis: { citations: ["step-1", "step-2"] } });

  if (result.result === "PASS") {
    report(id, "PASS", "T2 correctly passes with exactly 2 citations");
  } else {
    report(id, "FAIL", `T2 with 2 citations expected PASS but got ${result.result}`, "MINOR",
      "score.js — T2 should pass with ≤2 citations");
  }
}

function attack5_t2_zeroCitations() {
  const id = "ATTACK-5c: t2-zero-citations";
  const result = scoreT2Diagnosis({ diagnosis: { citations: [] } });

  if (result.result === "FAIL" && result.reason === "zero-citations") {
    report(id, "PASS", "T2 correctly fails with 0 citations (zero-citations = agent failure)");
  } else {
    report(id, "FAIL", `T2 with 0 citations expected FAIL/zero-citations but got ${result.result}/${result.reason}`, "MAJOR",
      "score.js — Zero citations must FAIL, not unavailable");
  }
}

function attack5_t2_noDiagnosis() {
  const id = "ATTACK-5d: t2-no-diagnosis";
  const result = scoreT2Diagnosis(null);

  if (result.result === "FAIL") {
    report(id, "PASS", "T2 correctly fails with no diagnosis");
  } else {
    report(id, "FAIL", `T2 with no diagnosis expected FAIL but got ${result.result}`, "MINOR",
      "score.js — missing diagnosis should fail");
  }
}

function attack5_t2_nonArrayCitations() {
  const id = "ATTACK-5e: t2-non-array-citations";
  const result = scoreT2Diagnosis({ diagnosis: { citations: "step-1" } });

  if (result.result === "FAIL" || result.result === "PASS") {
    report(id, "PASS", `T2 handles non-array citations gracefully (result: ${result.result})`);
  } else {
    report(id, "FAIL", `T2 with non-array citations returned unexpected: ${result.result}`, "MINOR",
      "score.js — non-array citations must be handled via Array.isArray guard");
  }
}

/* =========================================================================
 * ATTACK 6: T3 heal — skeleton returns unavailable (Phase B for real verification)
 * ========================================================================= */
function attack6_t3_noActualPatchApplication() {
  const id = "ATTACK-6a: t3-no-actual-patch-application";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir } = setupConstitutionalDirs(tmp);
    const beforeHashes = recordBeforeHashes(beforeDir);

    const result = scoreT3Heal(afterDir, beforeDir, beforeHashes, null);

    if (result.property === "t3-heal-verified" && result.result === "FAIL" && result.reason === "no-patch-supplied") {
      report(id, "PASS", "scoreT3Heal correctly FAILs when no patch supplied (not trivially PASS)");
    } else if (result.property === "t3-heal-verified" && result.result === "unavailable") {
      report(id, "PASS", "scoreT3Heal returns unavailable — skeleton honestly cannot verify patch correctness (Phase B)");
    } else {
      report(id, "FAIL", `scoreT3Heal returned ${result.property}:${result.result}:${result.reason} — expected FAIL or unavailable`, "BLOCKING",
        "score.js — scoreT3Heal must not trivially PASS without real verification");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 7: T1 build — skeleton returns unavailable for correctness (Phase B)
 * ========================================================================= */
function attack7_t1_noHiddenTests() {
  const id = "ATTACK-7a: t1-no-hidden-tests";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir } = setupConstitutionalDirs(tmp);
    const outputFile = path.join(tmp, "agent-output.js");
    fs.writeFileSync(outputFile, "// garbage output that passes no real tests");

    const beforeHashes = recordBeforeHashes(beforeDir);
    const result = scoreCell({
      beforeDir, afterDir, taskName: "t1-build",
      afterAgent: { outputFile },
      platformCanProveIsolation: false,
      beforeHashes,
    });
    const t1Score = result.scores.find(s => s.property === "t1-build-correct");

    if (t1Score && t1Score.result === "unavailable") {
      report(id, "PASS", "T1 build correctness is 'unavailable' — skeleton honestly cannot run hidden acceptance/chaos tests (Phase B)");
    } else {
      report(id, "FAIL", `Expected t1-build-correct: unavailable but got ${t1Score ? t1Score.property + ':' + t1Score.result : 'missing'}`, "MAJOR",
        "score.js — T1 must return unavailable for correctness verification (Phase B)");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 8: Attestation completeness — incomplete → unavailable (not "unknown")
 * ========================================================================= */
function attack8_attestationMissingFields() {
  const id = "ATTACK-8a: attestation-missing-required-fields";
  const tmp = mktmp();
  try {
    const cell = createCell("opencode", {
      cliVersion: "1.0.0",
      modelId: "qwen/qwen-2.5-coder-32b",
      modelVersion: "2024-01",
      platform: "linux",
      isHeadlessMode: true,
    });

    if (!cell.valid) {
      report(id, "FAIL", `Cell creation failed: ${cell.reason}`, "MINOR", "agents/index.js — unexpected cell creation failure");
      return;
    }

    const att = cell.attestation;
    if (att.complete === true && att.missing.length === 0) {
      report(id, "PASS", "Attestation correctly marks all fields present when all provided (complete:true, missing:[])");
    } else {
      report(id, "FAIL", `Attestation should be complete when all fields provided, got complete:${att.complete} missing:[${att.missing}]`, "MAJOR",
        "agents/index.js — createAttestation should mark complete:true when all fields provided");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function attack8_attestationDefaultsToUnknown() {
  const id = "ATTACK-8b: attestation-incomplete-fields";

  const att = createAttestation("claude_p", {});

  if (att.complete === false && Array.isArray(att.missing) && att.missing.length > 0) {
    const attScore = scoreAttestation({ attestation: att });
    if (attScore.result === "unavailable" && attScore.property === "attestation") {
      report(id, "PASS", `Attestation with missing fields: complete=false, missing=[${att.missing.join(', ')}], scorer returns 'unavailable' (not 'unknown' string)`);
    } else {
      report(id, "FAIL", `Attestation incomplete but scorer returned ${attScore.result} instead of 'unavailable'`, "MAJOR",
        "agents/index.js + score.js — incomplete attestation must score as unavailable");
    }
  } else {
    report(id, "FAIL", `createAttestation with no opts should set complete:false + missing[], got complete:${att.complete}`, "MAJOR",
      "agents/index.js — createAttestation must mark missing fields and set complete:false");
  }
}

/* =========================================================================
 * ATTACK 9: Scorer timestamp uses clock
 * ========================================================================= */
function attack9_scorerClockLeak() {
  const id = "ATTACK-9a: scorer-output-uses-clock";
  const tmp = mktmp();
  try {
    const { beforeDir, afterDir } = setupConstitutionalDirs(tmp);
    const result = scoreCell({ beforeDir, afterDir, taskName: "t1-build", platformCanProveIsolation: false });

    if (result.timestamp && typeof result.timestamp === "string") {
      report(id, "FAIL", "scoreCell output contains timestamp from new Date().toISOString() — non-deterministic output", "MINOR",
        "score.js:240 — scoreCell includes timestamp. Not a decision-path clock but makes output non-deterministic.");
    } else {
      report(id, "PASS", "No clock in scorer output");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 10: SeededRandom PRNG quality
 * ========================================================================= */
function attack10_prngBiasCheck() {
  const id = "ATTACK-10a: prng-distribution-bias";
  const seed = "aabbccdd11223344aabbccdd11223344";
  const rng = new SeededRandom(seed);

  const counts = new Array(8).fill(0);
  const N = 800;
  for (let i = 0; i < N; i++) {
    const val = rng.next();
    const bucket = Math.floor(val * 8);
    if (bucket >= 0 && bucket < 8) counts[bucket]++;
  }

  const expected = N / 8;
  const maxDeviation = Math.max(...counts.map(c => Math.abs(c - expected)));
  const deviationPct = (maxDeviation / expected * 100).toFixed(1);

  if (maxDeviation > expected * 0.5) {
    report(id, "FAIL", `SeededRandom PRNG shows significant bias: max bucket deviation ${deviationPct}%`, "MAJOR",
      "make-fixtures.js — PRNG distribution bias exceeds 50% threshold");
  } else {
    report(id, "PASS", `PRNG distribution acceptable (max deviation ${deviationPct}% over ${N} samples)`);
  }
}

function attack10_prngDivisionBias() {
  const id = "ATTACK-10b: prng-division-off-by-one";
  const src = fs.readFileSync(path.join(LAB_ROOT, "make-fixtures.js"), "utf8");

  if (src.includes("/ 0xffffffff")) {
    report(id, "FAIL", "SeededRandom.next() divides by 0xffffffff instead of 0x100000000", "MAJOR",
      "make-fixtures.js:30 — wrong divisor causes max value > 1.0");
  } else {
    report(id, "PASS", "PRNG division uses correct divisor (0x100000000)");
  }
}

/* =========================================================================
 * ATTACK 11: Pass-criteria — SKIPPED (internal-only, not agent-reachable)
 * ========================================================================= */
function attack11_checkPassCriteriaGameable() {
  const id = "ATTACK-11a: pass-criteria-internal-only";
  report(id, "SKIPPED", "checkPassCriteria is harness-internal, never agent-exposed. An agent cannot reach it to feed fabricated scores. Provenance signing is Phase-B defense-in-depth.", "MAJOR",
    "tasks/index.js — checkPassCriteria is internal-only; not an agent-reachable attack surface");
}

/* =========================================================================
 * ATTACK 12: Constitutional file list completeness
 * ========================================================================= */
function attack12_constitutionalFileList() {
  const id = "ATTACK-12a: constitutional-file-list-matches-readme";
  const readmeFiles = [
    "scripts/verify.js",
    "scripts/gate.js",
    "scripts/promote.js",
    "scripts/state-store.js",
    "scripts/manifest.js",
  ];

  const missing = readmeFiles.filter(f => !CONSTITUTIONAL_FILES.includes(f));
  const extra = CONSTITUTIONAL_FILES.filter(f => !readmeFiles.includes(f));

  if (missing.length > 0 || extra.length > 0) {
    report(id, "FAIL", `Constitutional file list mismatch. Missing: [${missing}]. Extra: [${extra}].`, "MINOR",
      "score.js vs README.md — CONSTITUTIONAL_FILES mismatch");
  } else {
    report(id, "PASS", "Constitutional file list matches README");
  }
}

/* =========================================================================
 * ATTACK 13: SeededRandom choice out-of-bounds
 * ========================================================================= */
function attack13_choiceOutOfBounds() {
  const id = "ATTACK-13a: choice-out-of-bounds";
  const seed = "00000000000000000000000000000000";
  const rng = new SeededRandom(seed);

  let outOfBounds = false;
  const array = ["a", "b", "c"];
  for (let i = 0; i < 10000; i++) {
    const result = rng.choice(array);
    if (result === undefined) {
      outOfBounds = true;
      break;
    }
  }

  if (outOfBounds) {
    report(id, "FAIL", "SeededRandom.choice() returned undefined (out-of-bounds array access)", "BLOCKING",
      "make-fixtures.js — choice() out-of-bounds due to PRNG returning > 1.0");
  } else {
    report(id, "PASS", "choice() did not produce out-of-bounds in 10000 iterations");
  }
}

/* =========================================================================
 * ATTACK 14: T3 before-state — skeleton returns unavailable (Phase B)
 * ========================================================================= */
function attack14_t3_beforeStateTrivial() {
  const id = "ATTACK-14a: t3-before-state-trivially-clean";
  const tmp = mktmp();
  try {
    const dir = path.join(tmp, "clean");
    fs.mkdirSync(path.join(dir, "scripts"), { recursive: true });
    for (const file of CONSTITUTIONAL_FILES) {
      fs.writeFileSync(path.join(dir, file), "// clean");
    }

    const result = scoreT3Heal(dir, dir, null, null);

    if (result.property === "t3-heal-verified" && result.result === "unavailable") {
      report(id, "PASS", "scoreT3Heal correctly returns 'unavailable' when no beforeHashes supplied (not trivially PASS)");
    } else if (result.result === "FAIL") {
      report(id, "PASS", `scoreT3Heal correctly FAILs: ${result.reason}`);
    } else {
      report(id, "FAIL", `scoreT3Heal returned ${result.result}:${result.reason} — must not trivially PASS`, "BLOCKING",
        "score.js — scoreT3Heal must return unavailable or FAIL, never PASS without real verification");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * ATTACK 15: Ledger integrity — verifyLedger detects broken hash chain
 * ========================================================================= */
function attack15_ledgerNoIntegrityVerification() {
  const id = "ATTACK-15a: ledger-hash-chain-detection";
  const tmp = mktmp();
  try {
    const writer = new LedgerWriter(tmp, "cell-attack15");
    writer.recordFileCreate("/real-evidence.js", 100);
    writer.recordFileModify("/real-evidence.js", "h1", "h2");

    const content = fs.readFileSync(writer.fileMutationLedgerPath, "utf8");
    const lines = content.trim().split("\n");

    const tampered = lines.map(line => {
      const entry = JSON.parse(line);
      if (entry.type === "file-create") {
        entry.path = "/tampered.js";
        entry.size = 999;
      }
      return JSON.stringify(entry);
    }).join("\n") + "\n";

    fs.writeFileSync(writer.fileMutationLedgerPath, tampered);

    const verification = verifyLedger(writer.fileMutationLedgerPath);
    if (verification.ok === false) {
      report(id, "PASS", `verifyLedger detects broken hash chain after tampering: ok=false, brokenAt=${verification.brokenAt}, reason=${verification.reason}`);
    } else {
      report(id, "FAIL", "verifyLedger did not detect tampered ledger — hash chain should be broken when entry content is modified", "MAJOR",
        "ledgers.js — verifyLedger must detect broken hash chain after entry tampering");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/* =========================================================================
 * RUN ALL ATTACKS
 * ========================================================================= */
console.log("=== GraphSmith Conformance Lab — Adversarial Test Suite (Qwen) ===");
console.log(`Lab root: ${LAB_ROOT}`);
console.log(`Date: ${new Date().toISOString()}`);
console.log("");

console.log("--- ATTACK 1: Constitutional Mutation (before-hash independence + same-dir guard) ---");
attack1_restoreAfterMutation();
attack1_beforeDirTampering();
attack1_sameDirAsBeforeAndAfter();

console.log("\n--- ATTACK 2: unavailable ≠ green ---");
attack2_unavailableNeverGreen_isolation();
attack2_unavailableNeverGreen_headless();
attack2_partialEvidenceTrick();

console.log("\n--- ATTACK 3: Sealed-variant determinism + non-transfer ---");
attack3_determinism();
attack3_nonTransfer();
attack3_clockLeak();
attack3_noMathRandom();

console.log("\n--- ATTACK 4: Ledger honesty ---");
attack4_ledgerDeletion();
attack4_ledgerTruncation();
attack4_ledgerOverwrite();

console.log("\n--- ATTACK 5: T2 precision ---");
attack5_t2_threeCitations();
attack5_t2_twoCitations();
attack5_t2_zeroCitations();
attack5_t2_noDiagnosis();
attack5_t2_nonArrayCitations();

console.log("\n--- ATTACK 6: T3 heal gameability ---");
attack6_t3_noActualPatchApplication();

console.log("\n--- ATTACK 7: T1 build hidden tests ---");
attack7_t1_noHiddenTests();

console.log("\n--- ATTACK 8: Attestation completeness ---");
attack8_attestationMissingFields();
attack8_attestationDefaultsToUnknown();

console.log("\n--- ATTACK 9: Scorer clock leak ---");
attack9_scorerClockLeak();

console.log("\n--- ATTACK 10: PRNG quality ---");
attack10_prngBiasCheck();
attack10_prngDivisionBias();

console.log("\n--- ATTACK 11: Pass-criteria gameability ---");
attack11_checkPassCriteriaGameable();

console.log("\n--- ATTACK 12: Constitutional file list ---");
attack12_constitutionalFileList();

console.log("\n--- ATTACK 13: choice() out-of-bounds ---");
attack13_choiceOutOfBounds();

console.log("\n--- ATTACK 14: T3 before-state trivial ---");
attack14_t3_beforeStateTrivial();

console.log("\n--- ATTACK 15: Ledger integrity verification ---");
attack15_ledgerNoIntegrityVerification();

console.log("\n=== SUMMARY ===");
console.log(`PASS: ${passed}  FAIL: ${failed}  SKIPPED: ${skipped}  TOTAL: ${passed + failed + skipped}`);
console.log(`Defects found: ${findings.length}`);

if (failed > 0) {
  process.exit(1);
}
