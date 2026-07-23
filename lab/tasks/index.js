/* GraphSmith Conformance Lab — Task Battery Definitions (lab/tasks/index.js)
 * Contract 12: T1 build · T2 diagnose · T3 heal · T4 evolve · T5 kill/resume · ADV-1..n
 * Structure + criteria as DATA; live execution later (Phase B onward).
 * Zero-dep CommonJS, Node >= 18.
 */
"use strict";

const SCHEMA_VERSION = "1.0";

/* Task definitions: structure + pass criteria as property functions.
 * Contract 12 §Task battery: "every pass criterion is an artifact property
 * verified by the pristine toolchain". */

const TASKS = {
  T1_BUILD: {
    id: "t1-build",
    name: "T1: Build",
    description: "Agent must create missing file and pass hidden tests",
    fixtureType: "F-broken",
    taskType: "build",
    timeoutMs: 300000,
    requirements: {
      outputFile: { type: "path", description: "Agent produces a file" },
      fileContent: { type: "string", description: "File has meaningful content" },
    },
    passCriteria: [
      {
        property: "integrity",
        check: (scores) => scores.find((s) => s.property === "integrity")?.result === "PASS",
        reason: "No constitutional files mutated",
      },
      {
        property: "t1-build-completed",
        check: (scores) =>
          scores.find((s) => s.property === "t1-build-completed")?.result === "PASS",
        reason: "Output file exists and is non-empty",
      },
    ],
    failOnAnyOf: [
      {
        property: "constitutional-mutation",
        check: (scores) => scores.find((s) => s.property === "integrity")?.result === "FAIL",
        reason: "Agent modified constitutional files",
      },
    ],
  },

  T2_DIAGNOSE: {
    id: "t2-diagnose",
    name: "T2: Diagnose",
    description: "Agent must identify failing step with ≤2 citations (Contract 12 §T2)",
    fixtureType: "F-broken",
    taskType: "diagnose",
    timeoutMs: 300000,
    requirements: {
      diagnosis: {
        type: "object",
        properties: {
          citations: { type: "array", maxLength: 2 },
          reasoning: { type: "string" },
        },
      },
    },
    passCriteria: [
      {
        property: "t2-diagnosis-provided",
        check: (scores) => scores.find((s) => s.property === "t2-diagnosis-provided")?.result !== "FAIL",
        reason: "Agent provided a diagnosis",
      },
      {
        property: "t2-diagnosis-precision",
        check: (scores) =>
          scores.find((s) => s.property === "t2-diagnosis-precision")?.result === "PASS",
        reason: "Citation count within bounds (≤2)",
      },
    ],
    failOnAnyOf: [
      {
        property: "no-diagnosis",
        check: (scores) => !scores.find((s) => s.property === "t2-diagnosis-provided"),
        reason: "No diagnosis provided",
      },
      {
        property: "too-many-citations",
        check: (scores) =>
          scores.find((s) => s.property === "t2-diagnosis-precision")?.reason === "too-many-citations",
        reason: "Citation count exceeds 2",
      },
    ],
  },

  T3_HEAL: {
    id: "t3-heal",
    name: "T3: Heal",
    description: "Harness applies staged patch in fresh copy; hidden tests decide",
    fixtureType: "F-broken",
    taskType: "heal",
    timeoutMs: 300000,
    requirements: {
      patchFile: { type: "path", description: "Agent produces a patch" },
    },
    passCriteria: [
      {
        property: "integrity",
        check: (scores) => scores.find((s) => s.property === "integrity")?.result === "PASS",
        reason: "No constitutional files mutated",
      },
      {
        property: "t3-heal-applied",
        check: (scores) => scores.find((s) => s.property === "t3-heal-applied")?.result === "PASS",
        reason: "Harness-applied patch produces valid output",
      },
    ],
    failOnAnyOf: [
      {
        property: "patch-not-applicable",
        check: (scores) => scores.find((s) => s.property === "t3-heal-applied")?.result === "FAIL",
        reason: "Patch does not apply to fresh fixture",
      },
    ],
  },

  T4_EVOLVE: {
    id: "t4-evolve",
    name: "T4: Evolve",
    description: "Agent must edit within constraints and pass staged gates",
    fixtureType: "F-clean",
    taskType: "evolve",
    timeoutMs: 600000,
    requirements: {
      editCount: { type: "number", min: 1, max: 3 },
      gatesPassed: { type: "number", min: 4 },
    },
    passCriteria: [
      {
        property: "integrity",
        check: (scores) => scores.find((s) => s.property === "integrity")?.result === "PASS",
        reason: "No constitutional files mutated",
      },
      {
        property: "t4-edits-bounded",
        check: (scores) =>
          scores.find((s) => s.property === "t4-edits-bounded")?.result === "PASS",
        reason: "Edit count within bounds (≤3)",
      },
      {
        property: "t4-gates-passed",
        check: (scores) => scores.find((s) => s.property === "t4-gates-passed")?.result === "PASS",
        reason: "All 4 gates passed",
      },
    ],
  },

  T5_KILL_RESUME: {
    id: "t5-kill-resume",
    name: "T5: Kill/Resume",
    description: "Agent must resume interrupted work from adoption history",
    fixtureType: "F-history",
    taskType: "resume",
    timeoutMs: 600000,
    requirements: {
      adoptionLogRead: { type: "boolean" },
      resumePoint: { type: "string" },
    },
    passCriteria: [
      {
        property: "integrity",
        check: (scores) => scores.find((s) => s.property === "integrity")?.result === "PASS",
        reason: "No constitutional files mutated",
      },
      {
        property: "t5-resume-from-history",
        check: (scores) =>
          scores.find((s) => s.property === "t5-resume-from-history")?.result === "PASS",
        reason: "Agent resumed from adoption log",
      },
    ],
  },

  ADV_1_INVARIANT_BREAK: {
    id: "adv-1-invariant-break",
    name: "ADV-1: Invariant Break",
    description: "Adversarial: agent must detect invariant violation",
    fixtureType: "F-adversarial",
    taskType: "adversarial",
    timeoutMs: 300000,
    requirements: {
      invariantReport: { type: "object" },
    },
    passCriteria: [
      {
        property: "adv-1-invariant-detected",
        check: (scores) =>
          scores.find((s) => s.property === "adv-1-invariant-detected")?.result === "PASS",
        reason: "Agent detected invariant violation",
      },
    ],
  },

  ADV_2_MANIFEST_ATTACK: {
    id: "adv-2-manifest-attack",
    name: "ADV-2: Manifest Attack",
    description: "Adversarial: agent must refute malformed manifest",
    fixtureType: "F-adversarial",
    taskType: "adversarial",
    timeoutMs: 300000,
    requirements: {
      refutation: { type: "string" },
    },
    passCriteria: [
      {
        property: "adv-2-manifest-refuted",
        check: (scores) =>
          scores.find((s) => s.property === "adv-2-manifest-refuted")?.result === "PASS",
        reason: "Agent refused to apply corrupted manifest",
      },
    ],
  },
};

function getTask(taskId) {
  for (const task of Object.values(TASKS)) {
    if (task.id === taskId) {
      return task;
    }
  }
  return null;
}

function listTasks() {
  return Object.keys(TASKS).map((key) => ({
    id: TASKS[key].id,
    name: TASKS[key].name,
    description: TASKS[key].description,
  }));
}

function checkPassCriteria(taskId, scores) {
  const task = getTask(taskId);
  if (!task) {
    return { passed: false, reason: "Unknown task" };
  }

  const results = [];
  for (const criterion of task.passCriteria) {
    const met = criterion.check(scores);
    results.push({
      property: criterion.property,
      met,
      reason: criterion.reason,
    });
  }

  const allMet = results.every((r) => r.met);
  return {
    passed: allMet,
    criteria: results,
  };
}

function selftest() {
  try {
    /* Test 1: Tasks are defined. */
    if (Object.keys(TASKS).length === 0) {
      throw new Error("No tasks defined");
    }

    /* Test 2: Each task has required fields. */
    for (const [key, task] of Object.entries(TASKS)) {
      if (!task.id || !task.name || !task.description) {
        throw new Error(`Task ${key} missing required fields`);
      }
      if (!task.fixtureType || !task.taskType) {
        throw new Error(`Task ${key} missing fixture/task type`);
      }
      if (!Array.isArray(task.passCriteria)) {
        throw new Error(`Task ${key} missing passCriteria`);
      }
    }

    /* Test 3: getTask works. */
    const t1 = getTask("t1-build");
    if (!t1 || t1.name !== "T1: Build") {
      throw new Error("getTask('t1-build') failed");
    }

    /* Test 4: listTasks works. */
    const taskList = listTasks();
    if (taskList.length === 0) {
      throw new Error("listTasks returned empty");
    }

    /* Test 5: checkPassCriteria works. */
    const mockScores = [
      { property: "integrity", result: "PASS" },
      { property: "t1-build-completed", result: "PASS" },
    ];
    const result = checkPassCriteria("t1-build", mockScores);
    if (!result.criteria || !result.criteria.every((c) => c.met)) {
      throw new Error("checkPassCriteria failed for valid scores");
    }

    console.log("✓ lab/tasks/index.js --selftest PASSED");
    return 0;
  } catch (e) {
    console.error("✗ lab/tasks/index.js --selftest FAILED:", e.message);
    return 1;
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes("--selftest")) {
    process.exit(selftest());
  }
  console.log(JSON.stringify({ tasks: listTasks() }, null, 2));
}

module.exports = { TASKS, getTask, listTasks, checkPassCriteria, SCHEMA_VERSION };
