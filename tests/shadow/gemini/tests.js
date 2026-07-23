const fs = require("fs");
const { execSync } = require("child_process");

const shadow = require("../../../scripts/shadow.js");
const gate = require("../../../scripts/gate.js");

const findings = [];
const errors = [];

function check(name, cond, detail) {
  if (cond) {
    findings.push("PASS: " + name + (detail ? " - " + detail : ""));
  } else {
    errors.push("FAIL: " + name + (detail ? " - " + detail : ""));
  }
}

function runTests() {
  console.log("--- STARTING ADVERSARIAL TESTS FOR shadow.js ---");

  // Attack 1: SHADOW-ONLY
  const projectRoot = "./.tmp-gs-shadow-test-" + Date.now();
  fs.mkdirSync(projectRoot + "/.graphsmith/evolvable", { recursive: true });
  fs.mkdirSync(projectRoot + "/.graphsmith/state", { recursive: true });
  const activePath = projectRoot + "/.graphsmith/evolvable/ACTIVE";
  const logPath = projectRoot + "/.graphsmith/state/adoption-log.jsonl";

  fs.writeFileSync(activePath, "before\n");
  fs.writeFileSync(logPath, "log\n");

  try {
    // Trick it into writing to ACTIVE by using --out
    const shadowScript = "scripts/shadow.js";
    execSync(`node ${shadowScript} --out "${activePath}" --project-root "${projectRoot}"`, { stdio: 'pipe' });
    errors.push("FAIL: shadow-only-abort - CLI did not abort when ACTIVE was modified");
  } catch (e) {
    check("shadow-only-abort", e.status === 3, "CLI aborted. Expected 3, got " + e.status + ". stderr: " + (e.stderr ? e.stderr.toString().trim() : "none"));
  }

  // Ensure log is unchanged
  const logContent = fs.readFileSync(logPath, 'utf8');
  check("shadow-only-log", logContent === "log\n", "adoption-log was byte-unchanged after shadow run");

  // Source scan for network APIs
  const src = fs.readFileSync("scripts/shadow.js", 'utf8');
  const netFindings = shadow.scanSourceForNetworkAPIs(src);
  check("shadow-only-no-network", netFindings.length === 0, "Source has zero network APIs");
  
  const requiresPromote = src.includes('require("./promote.js")') || src.includes('require("./adopt.js")');
  check("shadow-only-no-adopt", !requiresPromote, "Source never requires promote/adopt");

  fs.rmSync(projectRoot, { recursive: true, force: true });


  // Attack 2 & 3 & 5 Setup: Intercept gate2Behavioral
  const originalGate2 = gate.gate2Behavioral;
  let m;

  // Attack 2: FLAT-IS-FLAT INTEGRITY
  // Inject a real improvement into the null bundle
  gate.gate2Behavioral = function(candId, opts) {
    if (candId === "shadow-null") {
      return {
        pass: true, tier: 3, verdict: "promote",
        primary: { n: 10, n_d: 10, wins: 10, losses: 0, p: 0.001, verdict: "promote", lowerBound: 1.0 }
      };
    }
    return originalGate2.apply(this, arguments);
  };
  m = shadow.runShadow({ seeds: [1] });
  check("flat-is-flat-detects-real-change", m.flat_is_flat.holds === false && m.flat_is_flat.any_promote === true, "Null change with injected improvement was correctly flagged as NOT flat");

  // Restore and check true null
  gate.gate2Behavioral = originalGate2;
  m = shadow.runShadow({ seeds: [1] });
  check("flat-is-flat-true-null", m.flat_is_flat.holds === true, "True null change reads as flat");


  // Attack 3: REGRESSION DETECTION IS REAL
  // Try a regression the harness might miss: a Tier 3 regression
  gate.gate2Behavioral = function(candId, opts) {
    if (candId === "shadow-regression") {
      return {
        pass: false, tier: 3, verdict: "reject",
        primary: { n: 10, n_d: 10, wins: 0, losses: 10, p: 1.0, verdict: "reject", lowerBound: -1.0 }
      };
    }
    return originalGate2.apply(this, arguments);
  };
  m = shadow.runShadow({ seeds: [1] });
  // The harness expects tier <= 2 for its synthetic regression. Let's see if it misses this tier 3 regression.
  const missed = m.falsification.injected_regression_detected === false;
  check("regression-detection-misses-tier3", missed, "Harness misses a Tier 3 regression because it strictly looks for critical-slice regressions (tier <= 2)");
  if (missed) {
    findings.push("FINDING: The shadow harness falsification check requires a Tier 1/2 regression to trigger `injected_regression_detected`. It does not flag a Tier 3 statistical loss.");
  }


  // Attack 4: DETERMINISM / NO-CLOCK
  gate.gate2Behavioral = originalGate2;
  const origRandom = Math.random;
  const origNow = Date.now;

  Math.random = () => 0.1;
  Date.now = () => 1000;
  const m1 = shadow.runShadow({ seeds: [1, 2, 3] });

  Math.random = () => 0.9;
  Date.now = () => 9000;
  const m2 = shadow.runShadow({ seeds: [1, 2, 3] });

  Math.random = origRandom;
  Date.now = origNow;

  check("determinism-no-clock", JSON.stringify(m1) === JSON.stringify(m2), "Same seeds yield identical machine state regardless of Date.now() / Math.random()");


  // Attack 5: NOISE-FLOOR HONESTY
  gate.gate2Behavioral = function(candId, opts) {
    if (candId === "shadow-null") {
      const seed = opts.cycleSeed;
      const val = seed * 0.1; // seed 1 -> 0.1, seed 2 -> 0.2, seed 3 -> 0.3
      return {
        pass: true, tier: 3, verdict: "reject",
        primary: { n: 10, n_d: 10, wins: 5, losses: 5, p: 0.5, verdict: "reject", lowerBound: val }
      };
    }
    return originalGate2.apply(this, arguments);
  };
  const mNoise = shadow.runShadow({ seeds: [1, 2, 3] });
  // Spread should be max(0.3) - min(0.1) = 0.2
  check("noise-floor-responds-honestly", mNoise.noise_floor.value > 0 && Math.abs(mNoise.noise_floor.value - 0.2) < 0.001, "Noise floor responds to seed-based perturbations (calculated spread: " + mNoise.noise_floor.value + ")");

  gate.gate2Behavioral = originalGate2;


  // Report
  console.log("\n--- FINDINGS & ERRORS ---");
  findings.forEach(f => console.log(f));
  errors.forEach(e => console.error(e));

  if (errors.length > 0) {
    console.log("\nOVERALL: FAIL");
    process.exit(1);
  } else {
    console.log("\nOVERALL: PASS");
    process.exit(0);
  }
}

runTests();
