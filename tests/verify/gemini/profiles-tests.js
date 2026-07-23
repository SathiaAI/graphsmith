const fs = require("fs");
const path = require("path");
const os = require("os");
const verify = require("../../../scripts/verify");
const scaffold = require("../../../scripts/scaffold");

const results = [];
let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    passCount++;
    console.log(`[PASS] ${message}`);
    results.push({ message, pass: true });
  } else {
    failCount++;
    console.error(`[FAIL] ${message}`);
    results.push({ message, pass: false });
  }
}

async function runTests() {
  console.log("=== ADVERSARIAL TESTS FOR PROFILES ===\n");

  // 1. UNAVAILABLE-NEVER-GREEN & HONEST NEGATIVES (E, Q, X)
  fs.mkdirSync(".tmp", { recursive: true });
  const rootEmpty = fs.mkdtempSync(".tmp/graphsmith-verify-empty-");
  try {
    const eRes = verify.profileEffectReconciliation(rootEmpty);
    assert(eRes.status === "unavailable", `E with zero adapters must be unavailable, got ${eRes.status}`);
    
    const qRes = verify.profileAssuranceTested(rootEmpty);
    assert(qRes.status === "unavailable", `Q with zero workflow must be unavailable, got ${qRes.status}`);
    
    const xRes = verify.profileAdversariallyTested(rootEmpty);
    assert(xRes.status === "unavailable", `X with zero workflow must be unavailable, got ${xRes.status}`);
  } finally {
    fs.rmSync(rootEmpty, { recursive: true, force: true });
  }

  // 2. FALSE-VERIFIED attacks

  // 2a. Attack G (Gated Learning): What if ACTIVE is mutated? (Auto-adoption happened)
  const adopt = require("../../../scripts/adopt");
  const origAdopt = adopt.adopt;
  adopt.adopt = function(root, id, opts) {
    // Attack: simulate an auto-adoption by changing ACTIVE pointer!
    const activePath = path.join(root, ".graphsmith", "evolvable", "ACTIVE");
    fs.writeFileSync(activePath, "TAMPERED_ACTIVE_POINTER");
    return { refused: false, adopted: true, reason: "Auto-adopted (ATTACK)" };
  };
  const gRes = verify.profileGatedLearning();
  assert(gRes.status === "failed", `G should fail if ACTIVE is mutated (auto-adoption), got ${gRes.status}`);
  assert(gRes.evidence.find(e => e.check === "active-pointer-unchanged")?.unchanged === false, "G evidence should flag active pointer change");
  adopt.adopt = origAdopt; // Restore

  // 2b. Attack B (Budget): What if supervisor doesn't halt?
  const origScaffoldProject = scaffold.scaffoldProject;
  scaffold.scaffoldProject = function(dir, name) {
    origScaffoldProject(dir, name);
    // Tamper the generated supervisor.js to NOT throw on budget breach
    const supPath = path.join(dir, "supervisor.js");
    let content = fs.readFileSync(supPath, "utf8");
    content = content.replace("throw err;", "return err; // NO THROW");
    fs.writeFileSync(supPath, content);
  };
  const bRes = verify.profileBudgetEnforced();
  assert(bRes.status === "failed", `B should fail if supervisor doesn't throw halt, got ${bRes.status}`);
  scaffold.scaffoldProject = origScaffoldProject; // Restore

  // 3. INDEPENDENT AXES
  const rootAnother = fs.mkdtempSync(".tmp/graphsmith-verify-indep-");
  try {
    const profilesRes = verify.runProfiles(rootAnother, { evaluatedAt: "2023-01-01T00:00:00Z" });
    assert(profilesRes.profiles.T !== undefined, "Profile T must be present");
    assert(profilesRes.profiles.T.release_verified !== undefined && profilesRes.profiles.T.self_consistent !== undefined, 
           "T must surface release_verified and self_consistent as separate axes");
    assert(profilesRes.profiles.T.status !== "verified", "T should not be verified on an empty project");
  } finally {
    fs.rmSync(rootAnother, { recursive: true, force: true });
  }

  // 4. NO CLOCK/RANDOM
  const scriptContent = fs.readFileSync("scripts/verify.js", "utf8");
  const profileEngineContent = scriptContent.split("// ===========================================================================")[1];
  assert(!profileEngineContent.match(/Date\.now\(\)/), "profile engine must not call Date.now()");
  assert(!profileEngineContent.match(/Math\.random\(\)/), "profile engine must not call Math.random()");
  
  const origEnv = process.env.GRAPHSMITH_EVALUATED_AT;
  const origEpoch = process.env.SOURCE_DATE_EPOCH;
  delete process.env.GRAPHSMITH_EVALUATED_AT;
  delete process.env.SOURCE_DATE_EPOCH;
  
  const rootTime = fs.mkdtempSync(".tmp/graphsmith-verify-time-");
  try {
    const pNoTime = verify.runProfiles(rootTime);
    assert(pNoTime.evaluated_at === "unavailable", `evaluated_at must be 'unavailable' when not injected, got ${pNoTime.evaluated_at}`);
    assert(!pNoTime.evaluated_at.match(/^\d{4}-\d{2}-\d{2}/), "evaluated_at must not be a generated timestamp");
    
    // Test injection works
    const pWithOpts = verify.runProfiles(rootTime, { evaluatedAt: "2026-07-23T00:00:00.000Z" });
    assert(pWithOpts.evaluated_at === "2026-07-23T00:00:00.000Z", "evaluated_at should accept injected opts");

    process.env.SOURCE_DATE_EPOCH = "1700000000";
    const pWithEpoch = verify.runProfiles(rootTime);
    assert(pWithEpoch.evaluated_at === new Date(1700000000 * 1000).toISOString(), "evaluated_at should parse SOURCE_DATE_EPOCH correctly");
  } finally {
    if (origEnv !== undefined) process.env.GRAPHSMITH_EVALUATED_AT = origEnv;
    else delete process.env.GRAPHSMITH_EVALUATED_AT;
    
    if (origEpoch !== undefined) process.env.SOURCE_DATE_EPOCH = origEpoch;
    else delete process.env.SOURCE_DATE_EPOCH;

    fs.rmSync(rootTime, { recursive: true, force: true });
  }

  // 5. EVIDENCE INTEGRITY
  const rootHostile = fs.mkdtempSync(".tmp/graphsmith-verify-hostile-");
  try {
    fs.mkdirSync(path.join(rootHostile, "adapters"), { recursive: true });
    fs.writeFileSync(path.join(rootHostile, "adapters", "hostile.capability.json"), JSON.stringify({
      schema_version: "1.0",
      adapter_id: "hostile-adapter",
      version: "1.0",
      effects: [
        {
          effect_id: "xss-attack",
          effect_type: "<script>alert(1)</script>",
          capability: { variant: "read-only" }
        }
      ]
    }));
    const eHostileRes = verify.profileEffectReconciliation(rootHostile);
    assert(eHostileRes.status === "verified", "E should be verified because shape is valid, despite hostile strings");
    // Verify evidence is unredacted
    const effectEvidence = eHostileRes.evidence.find(e => e.check === "effect-reconciliation-mapping");
    const injectedEffect = effectEvidence.adapters[0].effects[0];
    assert(injectedEffect.effect_type === "<script>alert(1)</script>", "Hostile evidence must be preserved unredacted in the evidence array");
  } finally {
    fs.rmSync(rootHostile, { recursive: true, force: true });
  }

  // 6. FALSE-VERIFIED R (Resumable State)
  const stateStore = require("../../../scripts/state-store");
  if (stateStore.createStore) {
    const origCreate = stateStore.createStore;
    stateStore.createStore = function(...args) {
      const store = origCreate(...args);
      const origRegister = store.runRegistry.register;
      store.runRegistry.register = function(id, tree) {
        // Attack: If the test simulates a crash with id "run-torn", we WON'T throw!
        // This simulates a scenario where state store fails to simulate a mid-mutation crash.
        if (id === "run-torn") {
          return; // No crash!
        }
        return origRegister.call(this, id, tree);
      };
      return store;
    };
    
    const rRes = verify.profileResumableState();
    assert(rRes.status === "failed", `R should fail if recovery doesn't happen (simulate no crash), got ${rRes.status}`);
    
    stateStore.createStore = origCreate; // Restore
  } else {
    console.log("[SKIP] Cannot patch state-store for R profile attack");
  }

  console.log("\n=== FINDINGS ===");
  if (failCount === 0) {
    console.log("All adversarial tests passed! The guarantees are robust against these attacks.");
  } else {
    console.error(`Found ${failCount} defect(s) where guarantees were broken!`);
    results.filter(r => !r.pass).forEach(r => console.error(`- ${r.message}`));
  }
}

runTests().catch(e => {
  console.error(e);
  process.exit(1);
});
