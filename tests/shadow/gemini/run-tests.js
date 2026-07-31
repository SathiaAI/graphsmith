const fs = require("fs");
const os = require("os");
const path = require("path");
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
  // Was "./.tmp-gs-shadow-test-<ts>", relative to CWD -- run from the repo root, as
  // anyone would, that lands the temp tree directly in the REPO ROOT, and there is
  // no try/finally, so an early failure leaves it there.
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gs-shadow-gemini-"));
  fs.mkdirSync(projectRoot + "/.graphsmith/evolvable", { recursive: true });
  fs.mkdirSync(projectRoot + "/.graphsmith/state", { recursive: true });
  const activePath = projectRoot + "/.graphsmith/evolvable/ACTIVE";
  const logPath = projectRoot + "/.graphsmith/state/adoption-log.jsonl";

  fs.writeFileSync(activePath, "before\n");
  fs.writeFileSync(logPath, "log\n");

  try {
    // Trick it into writing to ACTIVE by using --out
    /* __dirname-relative, not CWD-relative. The old form only worked because
     * ci-run-suites.js happens to spawn suites with the repo root as cwd; running
     * this file from anywhere else died with ENOENT. A test whose result depends
     * on the caller's working directory is a test that will one day be "flaky". */
    const shadowScript = path.join(__dirname, "..", "..", "..", "scripts", "shadow.js");
    execSync(`node ${shadowScript} --out "${activePath}" --project-root "${projectRoot}"`, { stdio: 'pipe' });
    errors.push("FAIL: shadow-only-abort - CLI did not abort when ACTIVE was modified");
  } catch (e) {
    check("shadow-only-abort", e.status === 3, "CLI aborted. Expected 3, got " + e.status + ". stderr: " + (e.stderr ? e.stderr.toString().trim() : "none"));
  }

  // Ensure log is unchanged
  const logContent = fs.readFileSync(logPath, 'utf8');
  check("shadow-only-log", logContent === "log\n", "adoption-log was byte-unchanged after shadow run");

  // Source scan for network APIs
  const src = fs.readFileSync(path.join(__dirname, "..", "..", "..", "scripts", "shadow.js"), 'utf8');
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

  /* This case used to assert `injected_regression_detected === false` -- that the
   * harness FAILS to flag a Tier-3 loss -- and pushed a "FINDING:" line on every
   * green run.
   *
   * Pinning the absence of a detection is backwards. Tier-3 insensitivity is a
   * DISCLOSED property of the frozen evaluator (contract 03: one predeclared
   * primary endpoint, one-sided sign test, so a losing candidate reads as
   * inconclusive rather than as a detected regression), not a defect. Written the
   * old way, anyone who strengthened shadow.js to also flag Tier-3 losses -- a
   * strict improvement in sensitivity -- would turn this suite RED for making the
   * product better. Same inverted-expectation shape as a test asserting that an
   * escaping function does not escape.
   *
   * What is actually worth gating is that the boundary stays DISCLOSED. A silent
   * narrowing of sensitivity is the real risk; a documented one is the contract.
   * So: assert the disclosure exists and still describes this boundary, and stay
   * agnostic about whether detection fires. */
  const scope = m.falsification.regression_sensitivity_scope;
  check(
    "regression-sensitivity-boundary-disclosed",
    typeof scope === "string" &&
      /tier[- ]?3/i.test(scope) &&
      /one-sided/i.test(scope) &&
      /NOT/.test(scope),
    "falsification.regression_sensitivity_scope must state plainly that a Tier-3 one-sided " +
      "statistical loss is NOT reported as a regression. Detection may legitimately be " +
      "widened later; the disclosure disappearing is the regression this guards. Got: " +
      (typeof scope === "string" ? JSON.stringify(scope.slice(0, 120)) : String(scope))
  );


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
