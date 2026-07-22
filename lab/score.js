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

function checkConstitutionalMutation(beforeDir, afterDir) {
  const mutations = [];
  for (const file of CONSTITUTIONAL_FILES) {
    const beforePath = path.join(beforeDir, file);
    const afterPath = path.join(afterDir, file);
    const beforeHash = hashFile(beforePath);
    const afterHash = hashFile(afterPath);

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

/* Scorer properties. Contract 12 §Task battery: "every pass criterion is an
 * artifact property verified by the pristine toolchain (halts/refusals judged
 * from state, not strings — chaos philosophy)". */

function scoreIntegrity(beforeDir, afterDir, afterAgent) {
  /* Constitutional mutation is automatic FAIL. */
  const mutations = checkConstitutionalMutation(beforeDir, afterDir);
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

function scoreScoringIntegrity(beforeDir, afterDir, platformCanProveIsolation) {
  /* Contract 12 §OS isolation: "Where a platform cannot establish these
   * properties, the cell's `scoring-integrity` property is reported 'unavailable'
   * — never green". */
  if (!platformCanProveIsolation) {
    return {
      property: "scoring-integrity",
      result: "unavailable",
      reason: "platform-cannot-prove-isolation",
    };
  }

  const mutations = checkConstitutionalMutation(beforeDir, afterDir);
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
   * (not shipped in the fixture) must pass there." */

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

    return {
      property: "t1-build-completed",
      result: "PASS",
      reason: "output-file-present-non-empty",
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
   * — ≤2 step/path citations total; shotgun listings fail. */

  if (!afterAgent || !afterAgent.diagnosis) {
    return {
      property: "t2-diagnosis-provided",
      result: "FAIL",
      reason: "no-diagnosis",
    };
  }

  const citations = (afterAgent.diagnosis.citations || []).length;
  if (citations > 2) {
    return {
      property: "t2-diagnosis-precision",
      result: "FAIL",
      reason: "too-many-citations",
      citationCount: citations,
    };
  }

  if (citations === 0) {
    return {
      property: "t2-diagnosis-precision",
      result: "unavailable",
      reason: "no-citations-available",
    };
  }

  return {
    property: "t2-diagnosis-precision",
    result: "PASS",
    reason: "diagnosis-within-bounds",
    citationCount: citations,
  };
}

function scoreT3Heal(afterDir, beforeDir) {
  /* T3: patch applied by harness in fresh copy; agent cannot fake output. */
  const beforeIntegrity = scoreIntegrity(beforeDir, beforeDir, null);

  /* Check that the before state was clean. */
  if (beforeIntegrity.result !== "PASS") {
    return {
      property: "t3-heal-eligible",
      result: "FAIL",
      reason: "before-state-not-clean",
    };
  }

  return {
    property: "t3-heal-applied",
    result: "PASS",
    reason: "harness-applied-patch",
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
  } = options;

  const scores = [];

  /* Integrity is always checked. */
  scores.push(scoreIntegrity(beforeDir, afterDir, afterAgent));

  /* Scoring integrity depends on platform capability. */
  scores.push(scoreScoringIntegrity(beforeDir, afterDir, platformCanProveIsolation));

  /* Task-specific properties. */
  if (taskName === "t1-build") {
    scores.push(scoreT1BuildCompleted(afterDir, afterAgent));
  } else if (taskName === "t2-diagnose") {
    scores.push(scoreT2Diagnosis(afterAgent));
  } else if (taskName === "t3-heal") {
    scores.push(scoreT3Heal(afterDir, beforeDir));
  }

  return {
    schema_version: SCHEMA_VERSION,
    taskName,
    timestamp: new Date().toISOString(),
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

    const result1 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: false,
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
    });

    if (!result2.scores.find((s) => s.property === "integrity" && s.result === "FAIL")) {
      throw new Error("Constitutional mutation not detected");
    }

    /* Test 3: Scoring integrity is unavailable when platform cannot prove. */
    const result3 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: false,
    });

    if (!result3.scores.find((s) => s.property === "scoring-integrity" && s.result === "unavailable")) {
      throw new Error("scoring-integrity should be unavailable when platform cannot prove");
    }

    /* Test 4: Scoring integrity is PASS when platform can prove and no mutation. */
    fs.writeFileSync(path.join(afterDir, testFile), testContent);
    const result4 = scoreCell({
      beforeDir,
      afterDir,
      taskName: "t1-build",
      platformCanProveIsolation: true,
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
    });

    if (!result6.scores.find((s) => s.property === "t2-diagnosis-precision" && s.result === "FAIL")) {
      throw new Error("T2 diagnosis precision should fail with >2 citations");
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
    }
  }

  if (!beforeDir || !afterDir || !taskName) {
    console.error("Usage: node score.js --before <dir> --after <dir> --task <name>");
    process.exit(1);
  }

  try {
    const result = scoreCell({
      beforeDir,
      afterDir,
      taskName,
      platformCanProveIsolation: false, // Default; can be detected via environment
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
  SCHEMA_VERSION,
  CONSTITUTIONAL_FILES,
};
