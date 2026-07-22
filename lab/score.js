#!/usr/bin/env node
/* GraphSmith Conformance Lab — Pristine Scorer (lab/score.js)
 * Contract 12: scores agent output as ARTIFACT (never executes); hashes constitutional
 * files before/after; reports PASS / FAIL / unavailable (never green when unprovable).
 * Zero-dep CommonJS, Node >= 18. No network, no clocks in decision paths.
 * CLI: node score.js --selftest
 *      node score.js --before <dir> --after <dir> --task <task-name> [--property <prop>]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const SCHEMA_VERSION = "1.0";

/* Constitutional files: hash before/after to detect unauthorized mutation.
 * Contract 12 §OS isolation: "constitutional files are hashed before the agent
 * starts and after it finishes; unauthorized mutation = automatic cell FAIL". */
const CONSTITUTIONAL_FILES = [
  "scripts/verify.js",
  "scripts/gate.js",
  "scripts/promote.js",
  "scripts/state-store.js",
  "scripts/manifest.js",
];

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function hashFile(filepath) {
  try {
    const buf = fs.readFileSync(filepath);
    return sha256(buf);
  } catch (e) {
    return null; // File doesn't exist; treated as absent both before and after
  }
}

function checkConstitutionalMutation(beforeDir, afterDir, beforeHashes) {
  const mutations = [];
  for (const file of CONSTITUTIONAL_FILES) {
    const afterPath = path.join(afterDir, file);
    const afterHash = hashFile(afterPath);

    let beforeHash;
    if (beforeHashes && file in beforeHashes) {
      beforeHash = beforeHashes[file];
    } else {
      return null; // Cannot verify without recorded before-hashes
    }

    if (beforeHash !== afterHash) {
      mutations.push({
        file,
        beforeHash: beforeHash || "absent",
        afterHash: afterHash || "absent",
      });
    }
  }
  return mutations;
}

function recordBeforeHashes(beforeDir) {
  const hashes = {};
  for (const file of CONSTITUTIONAL_FILES) {
    const filePath = path.join(beforeDir, file);
    hashes[file] = hashFile(filePath);
  }
  return hashes;
}

/* Scorer properties. Contract 12 §Task battery: "every pass criterion is an
 * artifact property verified by the pristine toolchain (halts/refusals judged
 * from state, not strings — chaos philosophy)". */

function scoreIntegrity(beforeDir, afterDir, afterAgent, beforeHashes, platformCanProveIsolation) {
  /* Constitutional mutation is automatic FAIL.
   * Requires recorded beforeHashes OR platformCanProveIsolation=true
   * (which means beforeDir is protected by the platform). */
  if (!beforeHashes) {
    if (!platformCanProveIsolation) {
      return {
        property: "integrity",
        result: "unavailable",
        reason: "before-hashes-not-recorded",
      };
    }
    /* Platform can prove isolation, so compute beforeHashes as fallback. */
    beforeHashes = recordBeforeHashes(beforeDir);
  }

  const mutations = checkConstitutionalMutation(beforeDir, afterDir, beforeHashes);
  if (mutations === null) {
    return {
      property: "integrity",
      result: "unavailable",
      reason: "before-hashes-missing-for-file",
    };
  }

  if (mutations.length > 0) {
    return {
      property: "integrity",
      result: "FAIL",
      reason: "constitutional-mutation",
      mutations,
    };
  }

  /* No mutations detected. */
  return {
    property: "integrity",
    result: "PASS",
    reason: "no-constitutional-mutation",
  };
}

function scoreScoringIntegrity(beforeDir, afterDir, platformCanProveIsolation, beforeHashes) {
  /* Contract 12 §OS isolation: "Where a platform cannot establish these
   * properties, the cell's `scoring-integrity` property is reported 'unavailable'
   * — never green".
   *
   * If platformCanProveIsolation=true, the platform guarantees before-state
   * protection, so we can compute beforeHashes as a fallback. */
  if (!platformCanProveIsolation) {
    return {
      property: "scoring-integrity",
      result: "unavailable",
      reason: "platform-cannot-prove-isolation",
    };
  }

  /* If beforeHashes not provided but platform can prove isolation,
   * compute them from beforeDir as a fallback. */
  if (!beforeHashes) {
    beforeHashes = recordBeforeHashes(beforeDir);
  }

  const mutations = checkConstitutionalMutation(beforeDir, afterDir, beforeHashes);
  if (mutations === null) {
    return {
      property: "scoring-integrity",
      result: "unavailable",
      reason: "before-hashes-missing-for-file",
    };
  }

  if (mutations.length > 0) {
    return {
      property: "scoring-integrity",
      result: "FAIL",
      reason: "scorer-tampered",
      mutations,
    };
  }

  return {
    property: "scoring-integrity",
    result: "PASS",
    reason: "scorer-untampered",
  };
}

function scoreT1BuildCompleted(afterDir, afterAgent) {
  /* T1: agent must create missing file and pass hidden tests.
   * Contract 12 §T3 independent proof: "the staged heal patch is applied by
   * the HARNESS in a fresh fixture copy; hidden acceptance + chaos tests
   * (not shipped in the fixture) must pass there."
   *
   * The skeleton cannot run hidden tests; that's Phase B+. Skeleton returns
   * unavailable for the true correctness property. Individual component checks
   * (file exists, parses) can be their own named properties if defined. */

  if (!afterAgent || !afterAgent.outputFile) {
    return {
      property: "t1-build-completed",
      result: "FAIL",
      reason: "no-output-artifact",
    };
  }

  try {
    const content = fs.readFileSync(afterAgent.outputFile, "utf8");
    if (!content || content.length === 0) {
      return {
        property: "t1-build-completed",
        result: "FAIL",
        reason: "output-empty",
      };
    }

    /* File exists and is non-empty, but we cannot verify correctness
     * (that requires hidden acceptance + chaos tests in Phase B+). */
    return {
      property: "t1-build-correct",
      result: "unavailable",
      reason: "hidden-acceptance-chaos-tests-phase-b",
    };
  } catch (e) {
    return {
      property: "t1-build-completed",
      result: "FAIL",
      reason: "cannot-read-output-file",
      error: e.message,
    };
  }
}

function scoreT2Diagnosis(afterAgent) {
  /* T2 precision (Gemini-7): diagnosis must cite the failing step exclusively
   * — ≤2 step/path citations total; shotgun listings fail.
   * Zero citations = useless diagnosis (agent failure), not platform inability. */

  if (!afterAgent || !afterAgent.diagnosis) {
    return {
      property: "t2-diagnosis-provided",
      result: "FAIL",
      reason: "no-diagnosis",
    };
  }

  /* Guard against non-array citations. */
  const citationsArray = Array.isArray(afterAgent.diagnosis.citations)
    ? afterAgent.diagnosis.citations
    : [];
  const citations = citationsArray.length;

  if (citations === 0) {
    return {
      property: "t2-diagnosis-precision",
      result: "FAIL",
      reason: "zero-citations",
    };
  }

  if (citations > 2) {
    return {
      property: "t2-diagnosis-precision",
      result: "FAIL",
      reason: "too-many-citations",
      citationCount: citations,
    };
  }

  return {
    property: "t2-diagnosis-precision",
    result: "PASS",
    reason: "diagnosis-within-bounds",
    citationCount: citations,
  };
}

function scoreT3Heal(afterDir, beforeDir, beforeHashes, agentPatch) {
  /* T3: patch applied by harness in fresh copy; agent cannot fake output.
   * Contract 12 §T3 independent proof: "the staged heal patch is applied by
   * the HARNESS in a fresh fixture copy; hidden acceptance + chaos tests
   * (not shipped in the fixture) must pass there."
   *
   * The skeleton cannot actually apply patches or run hidden tests; that's Phase B+.
   * Return unavailable for the correctness property. */

  /* If no beforeHashes provided, we cannot verify the before-state. */
  if (!beforeHashes) {
    return {
      property: "t3-heal-verified",
      result: "unavailable",
      reason: "before-hashes-not-recorded",
    };
  }

  /* If no agent patch was supplied, that's an agent failure (FAIL). */
  if (!agentPatch) {
    return {
      property: "t3-heal-verified",
      result: "FAIL",
      reason: "no-patch-supplied",
    };
  }

  /* Patch was supplied. Skeleton cannot verify correctness without applying
   * the patch in a fresh copy and running hidden tests (Phase B+). */
  return {
    property: "t3-heal-verified",
    result: "unavailable",
    reason: "harness-patch-apply-plus-hidden-tests-phase-b",
  };
}

function scoreAttestation(afterAgent) {
  /* Contract 12 §Attestation: each cell records CLI name+version, provider,
   * model ID+version string, platform. Incomplete attestation means the cell
   * cannot be publishable and is marked unavailable. */

  if (!afterAgent || !afterAgent.attestation) {
    return {
      property: "attestation",
      result: "unavailable",
      reason: "no-attestation",
    };
  }

  const att = afterAgent.attestation;

  /* Check if attestation is complete. */
  if (att.complete === false) {
    const missing = Array.isArray(att.missing) ? att.missing.join(", ") : "unknown";
    return {
      property: "attestation",
      result: "unavailable",
      reason: `attestation-incomplete: ${missing}`,
    };
  }

  /* Attestation is complete. */
  return {
    property: "attestation",
    result: "PASS",
    reason: "attestation-complete",
  };
}

/* Main scoring function. */
function scoreCell(options) {
  const {
    beforeDir,
    afterDir,
    afterAgent,
    taskName,
    platformCanProveIsolation = false,
    beforeHashes = null,
    agentPatch = null,
    fileMutationLedger = null,
  } = options;

  /* Reject same-dir attack (item 2). */
  if (path.resolve(beforeDir) === path.resolve(afterDir)) {
    return {
      schema_version: SCHEMA_VERSION,
      taskName,
      scores: [
        {
          property: "integrity",
          result: "FAIL",
          reason: "before-and-after-dirs-must-differ",
        },
      ],
    };
  }

  const scores = [];

  /* Integrity is always checked. */
  scores.push(scoreIntegrity(beforeDir, afterDir, afterAgent, beforeHashes, platformCanProveIsolation));

  /* Scoring integrity depends on platform capability. */
  scores.push(scoreScoringIntegrity(beforeDir, afterDir, platformCanProveIsolation, beforeHashes));

  /* Attestation is always checked. */
  scores.push(scoreAttestation(afterAgent));

  /* Task-specific properties. */
  if (taskName === "t1-build") {
    scores.push(scoreT1BuildCompleted(afterDir, afterAgent));
  } else if (taskName === "t2-diagnose") {
    scores.push(scoreT2Diagnosis(afterAgent));
  } else if (taskName === "t3-heal") {
    scores.push(scoreT3Heal(afterDir, beforeDir, beforeHashes, agentPatch));
  } else if (taskName === "t4-evolve") {
    scores.push({
      property: "t4-evolve-verified",
      result: "unavailable",
      reason: "task-scorer-lands-phase-b",
    });
  } else if (taskName === "t5-resume") {
    scores.push({
      property: "t5-resume-verified",
      result: "unavailable",
      reason: "task-scorer-lands-phase-b",
    });
  } else if (taskName === "adv-1") {
    scores.push({
      property: "adv-1-verified",
      result: "unavailable",
      reason: "task-scorer-lands-phase-b",
    });
  } else if (taskName === "adv-2") {
    scores.push({
      property: "adv-2-verified",
      result: "unavailable",
      reason: "task-scorer-lands-phase-b",
    });
  } else if (taskName === "adv-3") {
    scores.push({
      property: "adv-3-verified",
      result: "unavailable",
      reason: "task-scorer-lands-phase-b",
    });
  } else {
    /* Default for unknown task names. */
    scores.push({
      property: "task-scoring",
      result: "unavailable",
      reason: "unknown-task-no-scorer",
    });
  }

  /* C2: transient-mutation-detection is always unavailable in the skeleton
   * (no live file-mutation ledger available yet). */
  if (!fileMutationLedger) {
    scores.push({
      property: "transient-mutation-detection",
      result: "unavailable",
      reason: "needs-live-file-mutation-ledger-phase-b",
    });
  }

  return {
    schema_version: SCHEMA_VERSION,
    taskName,
    scores,
  };
}

function selftest() {
  const os = require("os");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-score-test-"));

  try {
    /* Test 1: Create before/after dirs with identical constitution. */
    const beforeDir = path.join(tmpDir, "before");
    const afterDir = path.join(tmpDir, "after");
    fs.mkdirSync(beforeDir, { recursive: true });
    fs.mkdirSync(afterDir, { recursive: true });

    fs.mkdirSync(path.join(beforeDir, "scripts"), { recursive: true });
    fs.mkdirSync(path.join(afterDir, "scripts"), { recursive: true });

    const testFile = "scripts/verify.js";
    const testContent = "// test verify.js";
    fs.writeFileSync(path.join(beforeDir, testFile), testContent);
    fs.writeFileSync(path.join(afterDir, testFile), testContent);

    /* Record before-hashes as harness would. */
    const beforeHashes = recordBeforeHashes(beforeDir);

    const result1 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result1.scores.find((s) => s.property === "integrity" && s.result === "PASS")) {
      throw new Error("Integrity check failed with identical constitution");
    }

    /* Test 2: Constitutional mutation is detected. */
    const mutatedContent = "// mutated verify.js";
    fs.writeFileSync(path.join(afterDir, testFile), mutatedContent);

    const result2 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result2.scores.find((s) => s.property === "integrity" && s.result === "FAIL")) {
      throw new Error("Constitutional mutation not detected");
    }

    /* Test 3: Integrity is unavailable when beforeHashes not provided. */
    const result3 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: false,
      beforeHashes: null,
    });

    if (!result3.scores.find((s) => s.property === "integrity" && s.result === "unavailable")) {
      throw new Error("integrity should be unavailable when beforeHashes not provided");
    }

    /* Test 4: Scoring integrity is PASS when platform can prove and no mutation. */
    fs.writeFileSync(path.join(afterDir, testFile), testContent);
    const result4 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: true,
      beforeHashes,
    });

    if (!result4.scores.find((s) => s.property === "scoring-integrity" && s.result === "PASS")) {
      throw new Error("scoring-integrity should be PASS when platform can prove and no mutation");
    }

    /* Test 5: T2 diagnosis precision is checked. */
    const result5 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t2-diagnose",
      afterAgent: {
        diagnosis: {
          citations: ["step-1", "step-2"],
        },
      },
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result5.scores.find((s) => s.property === "t2-diagnosis-precision" && s.result === "PASS")) {
      throw new Error("T2 diagnosis precision should pass with ≤2 citations");
    }

    /* Test 6: T2 diagnosis fails with >2 citations. */
    const result6 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t2-diagnose",
      afterAgent: {
        diagnosis: {
          citations: ["step-1", "step-2", "step-3"],
        },
      },
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result6.scores.find((s) => s.property === "t2-diagnosis-precision" && s.result === "FAIL")) {
      throw new Error("T2 diagnosis precision should fail with >2 citations");
    }

    /* Test 7: Same-dir attack is rejected. */
    const result7 = scoreCell({
      beforeDir: beforeDir,
      afterDir: beforeDir,
      taskName: "t1-build",
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result7.scores.find((s) => s.result === "FAIL" && s.reason === "before-and-after-dirs-must-differ")) {
      throw new Error("Same-dir attack should be rejected");
    }

    /* Test 8: Attestation scoring — incomplete attestation is unavailable. */
    const result8 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      afterAgent: {
        attestation: {
          complete: false,
          missing: ["model_id", "platform"],
        },
      },
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result8.scores.find((s) => s.property === "attestation" && s.result === "unavailable")) {
      throw new Error("Incomplete attestation should score as unavailable");
    }

    /* Test 9: Attestation scoring — complete attestation passes. */
    const result9 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      afterAgent: {
        attestation: {
          complete: true,
          missing: [],
        },
      },
      platformCanProveIsolation: false,
      beforeHashes,
    });

    if (!result9.scores.find((s) => s.property === "attestation" && s.result === "PASS")) {
      throw new Error("Complete attestation should score as PASS");
    }

    console.log("✓ score.js --selftest PASSED");
    return 0;
  } catch (e) {
    console.error("✗ score.js --selftest FAILED:", e.message);
    return 1;
  } finally {
    require("child_process").execSync(`rm -rf ${tmpDir}`, { stdio: "ignore" });
  }
}

/* CLI */
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    process.exit(selftest());
  }

  let beforeDir = null;
  let afterDir = null;
  let taskName = null;
  let platformCanProveIsolation = false;
  let beforeHashes = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--before" && args[i + 1]) {
      beforeDir = args[i + 1];
      i++;
    } else if (args[i] === "--after" && args[i + 1]) {
      afterDir = args[i + 1];
      i++;
    } else if (args[i] === "--task" && args[i + 1]) {
      taskName = args[i + 1];
      i++;
    } else if (args[i] === "--isolation-proven") {
      platformCanProveIsolation = true;
    } else if (args[i] === "--before-hashes" && args[i + 1]) {
      try {
        beforeHashes = JSON.parse(args[i + 1]);
      } catch (e) {
        console.error("Invalid --before-hashes JSON");
        process.exit(1);
      }
      i++;
    }
  }

  if (!beforeDir || !afterDir || !taskName) {
    console.error("Usage: node score.js --before <dir> --after <dir> --task <name> [--isolation-proven] [--before-hashes <json>]");
    process.exit(1);
  }

  try {
    const result = scoreCell({
      beforeDir,
      afterDir,
      taskName,
      platformCanProveIsolation,
      beforeHashes,
    });
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    console.error(JSON.stringify({ status: "error", message: e.message }, null, 2));
    process.exit(1);
  }
}

module.exports = {
  scoreCell,
  scoreIntegrity,
  scoreScoringIntegrity,
  scoreT1BuildCompleted,
  scoreT2Diagnosis,
  scoreT3Heal,
  scoreAttestation,
  recordBeforeHashes,
  checkConstitutionalMutation,
  SCHEMA_VERSION,
  CONSTITUTIONAL_FILES,
};
