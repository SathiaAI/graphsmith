#!/usr/bin/env node
/* GraphSmith Conformance Lab — Fixtures Generator (lab/make-fixtures.js)
 * Contract 12: sealed variant mechanism, parameterized surface details.
 * Zero-dep CommonJS, Node >= 18. No network, no clocks in decision paths.
 * CLI: node make-fixtures.js [--selftest] [--seed <hex>] [--base-dir <dir>]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const SCHEMA_VERSION = "1.0";

/* Deterministic PRNG seeded from injected seed (never Math.random or clock).
 * Contract 12: "the seed is an input, never Math.random/clock". */
class SeededRandom {
  constructor(seed) {
    this.seed = Buffer.from(seed, "hex");
    this.state = this.seed;
    this.counter = 0;
  }

  next() {
    const h = crypto.createHash("sha256");
    h.update(this.seed);
    h.update(String(this.counter).padStart(16, "0"));
    const digest = h.digest();
    this.counter++;
    return digest.readUInt32BE(0) / 0x100000000;
  }

  choice(array) {
    const idx = Math.floor(this.next() * array.length);
    return array[idx];
  }

  shuffle(array) {
    const copy = [...array];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(this.next() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }
}

/* Base fixture templates. Contract 12 §Fixtures: F-clean / F-broken / F-adversarial / F-history */
const FIXTURE_TEMPLATES = {
  "F-clean": {
    type: "F-clean",
    description: "Clean project with no defects",
    initialState: {
      status: "healthy",
      fileCount: 42,
      manifestValid: true,
      adoptionLogChain: true,
    },
    operations: [],
  },
  "F-broken": {
    type: "F-broken",
    description: "Project with introduced defect for T1 build task",
    initialState: {
      status: "broken",
      fileCount: 41,
      manifestValid: true,
      adoptionLogChain: true,
      missingFile: "workers/intent-guard.js",
    },
    operations: [
      { op: "remove-file", target: "workers/intent-guard.js", step: 5 },
    ],
  },
  "F-adversarial": {
    type: "F-adversarial",
    description: "Adversarially-crafted project for T4 evolve task",
    initialState: {
      status: "hostile",
      fileCount: 43,
      manifestValid: false,
      adoptionLogChain: false,
      tamperSite: "workers/manager.js",
    },
    operations: [
      { op: "inject-bug", target: "workers/manager.js", site: "event-dispatch", step: 3 },
      { op: "mutate-manifest", corruption: "hash-mismatch", step: 7 },
    ],
  },
  "F-history": {
    type: "F-history",
    description: "Project with long adoption history for T5 resume task",
    initialState: {
      status: "active",
      fileCount: 42,
      manifestValid: true,
      adoptionLogChain: true,
      adoptionEntries: 12,
    },
    operations: [
      { op: "add-adoption-entry", timestamp: "T+0h", entry: "initial-setup", step: 1 },
      { op: "add-adoption-entry", timestamp: "T+24h", entry: "feature-A", step: 2 },
      { op: "add-adoption-entry", timestamp: "T+48h", entry: "bugfix-B", step: 3 },
    ],
  },
};

/* Sealed variant parameters: surface details chosen per-run from harness seed.
 * Contract 12 §Fixtures: "verbatim-memorized answers must not transfer; the seed
 * is an input, never Math.random/clock". */
const PARAMETERIZABLE_DETAILS = {
  stepNames: [
    "initialize",
    "prepare",
    "validate",
    "execute",
    "finalize",
    "verify",
    "audit",
    "reconcile",
  ],
  fileNames: [
    "manager.js",
    "intent-guard.js",
    "supervisor.js",
    "worker-A.js",
    "worker-B.js",
    "config.json",
    "manifest.json",
  ],
  injectedBugSites: [
    "event-dispatch",
    "process-spawn",
    "file-mutation",
    "state-store-write",
    "adoption-log-append",
    "manifest-hash",
  ],
  appendixWordings: [
    "stable",
    "experimental",
    "deprecated",
    "legacy",
    "enhanced",
    "optimized",
  ],
};

function generateFixture(baseType, seed, opts) {
  const template = FIXTURE_TEMPLATES[baseType];
  if (!template) {
    throw new Error(`Unknown fixture type: ${baseType}`);
  }

  opts = opts || {};
  const rng = new SeededRandom(seed);

  /* Sealed variant: choose surface details from RNG. */
  const variant = {
    schema_version: SCHEMA_VERSION,
    type: baseType,
    seed: seed,
    description: template.description,
    initialState: JSON.parse(JSON.stringify(template.initialState)),
    operations: template.operations.map((op) => JSON.parse(JSON.stringify(op))),
    parameters: {
      stepNames: rng.shuffle(PARAMETERIZABLE_DETAILS.stepNames).slice(0, 3),
      fileNames: rng.shuffle(PARAMETERIZABLE_DETAILS.fileNames).slice(0, 2),
      injectedBugSite: rng.choice(PARAMETERIZABLE_DETAILS.injectedBugSites),
      appendixWording: rng.choice(PARAMETERIZABLE_DETAILS.appendixWordings),
    },
  };

  /* Only include sealed_at if explicitly provided (harness-supplied timestamp). */
  if (opts.sealedAt) {
    variant.sealed_at = opts.sealedAt;
  }

  return variant;
}

function generateFixtures(baseDir, seed, opts) {
  opts = opts || {};
  const fixtureDir = path.join(baseDir, "fixtures");
  if (!fs.existsSync(fixtureDir)) {
    fs.mkdirSync(fixtureDir, { recursive: true });
  }

  const fixtures = {};
  for (const fixtureType of Object.keys(FIXTURE_TEMPLATES)) {
    const fixture = generateFixture(fixtureType, seed, opts);
    const filename = path.join(fixtureDir, `${fixtureType}.json`);
    fs.writeFileSync(filename, JSON.stringify(fixture, null, 2));
    fixtures[fixtureType] = fixture;
  }

  return fixtures;
}

function selftest() {
  const os = require("os");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-fixtures-test-"));
  const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "gs-fixtures-test-"));
  const tmpDir3 = fs.mkdtempSync(path.join(os.tmpdir(), "gs-fixtures-test-"));

  try {
    /* Test 1: Generate fixtures with a fixed seed. */
    const seed1 = "0123456789abcdef0123456789abcdef";
    const fixtures1 = generateFixtures(tmpDir, seed1);

    if (!fixtures1["F-clean"]) {
      throw new Error("F-clean not generated");
    }
    if (fixtures1["F-clean"].seed !== seed1) {
      throw new Error("Seed not recorded");
    }

    /* Test 2: Same seed produces identical fixtures (determinism). */
    const fixtures2 = generateFixtures(tmpDir2, seed1);

    const f1Clean = JSON.stringify(fixtures1["F-clean"]);
    const f2Clean = JSON.stringify(fixtures2["F-clean"]);

    if (f1Clean !== f2Clean) {
      throw new Error("Determinism failed: same seed produced different fixtures");
    }

    /* Test 3: Different seed produces different sealed variants. */
    const seed2 = "fedcba9876543210fedcba9876543210";
    const fixtures3 = generateFixtures(tmpDir3, seed2);

    const f1CleanVsDiff = JSON.stringify(fixtures1["F-clean"]);
    const f3Clean = JSON.stringify(fixtures3["F-clean"]);

    if (f1CleanVsDiff === f3Clean) {
      throw new Error("Different seeds produced identical fixtures");
    }

    /* Test 4: All fixture types are generated. */
    for (const fixtureType of Object.keys(FIXTURE_TEMPLATES)) {
      if (!fixtures1[fixtureType]) {
        throw new Error(`Missing fixture type: ${fixtureType}`);
      }
    }

    /* Test 5: Parametrizable details are sealed variants (not empty). */
    if (fixtures1["F-clean"].parameters.stepNames.length === 0) {
      throw new Error("No stepNames sealed");
    }
    if (fixtures1["F-clean"].parameters.fileNames.length === 0) {
      throw new Error("No fileNames sealed");
    }

    console.log("✓ make-fixtures.js --selftest PASSED");
    return 0;
  } catch (e) {
    console.error("✗ make-fixtures.js --selftest FAILED:", e.message);
    return 1;
  } finally {
    try {
      require("child_process").execSync(`rm -rf ${tmpDir} ${tmpDir2} ${tmpDir3}`, {
        stdio: "ignore",
      });
    } catch (e) {
      // Cleanup failure is not a test failure
    }
  }
}

/* CLI */
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    process.exit(selftest());
  }

  let seed = "0000000000000000000000000000000";
  let baseDir = process.cwd();

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--seed" && args[i + 1]) {
      seed = args[i + 1];
      i++;
    } else if (args[i] === "--base-dir" && args[i + 1]) {
      baseDir = args[i + 1];
      i++;
    }
  }

  if (seed.length !== 32 || !/^[0-9a-f]+$/i.test(seed)) {
    console.error("Invalid seed (must be 32-char hex)");
    process.exit(1);
  }

  try {
    const fixtures = generateFixtures(baseDir, seed);
    console.log(JSON.stringify({ status: "ok", fixtures: Object.keys(fixtures) }, null, 2));
  } catch (e) {
    console.error(JSON.stringify({ status: "error", message: e.message }, null, 2));
    process.exit(1);
  }
}

module.exports = { generateFixture, generateFixtures, SeededRandom, SCHEMA_VERSION };
