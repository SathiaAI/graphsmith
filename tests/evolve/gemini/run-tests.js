const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const child_process = require('child_process');

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function makeSyntheticRunLog(runDir, lines, runId) {
  fs.mkdirSync(runDir, { recursive: true });
  const records = [];
  let prevHash = "genesis";
  for (let i = 0; i < lines.length; i++) {
    const body = lines[i];
    body.run_id = runId;
    const bodyStr = JSON.stringify(body, Object.keys(body).sort());
    const lineHash = sha256(prevHash + "|" + bodyStr);
    records.push(JSON.stringify({ prev_hash: prevHash, line_hash: lineHash, ...body }));
    prevHash = lineHash;
  }
  fs.writeFileSync(path.join(runDir, "run.jsonl"), records.join("\n") + "\n");
  return prevHash;
}

function runTests() {
  const evolvePath = path.resolve(__dirname, '../../../scripts/evolve.js');
  const migratePath = path.resolve(__dirname, '../../../scripts/migrate.js');
  const eventCompilerPath = path.resolve(__dirname, '../../../scripts/event-compiler.js');
  
  const evolve = require(evolvePath);
  const migrate = require(migratePath);
  const eventCompiler = require(eventCompilerPath);

  const findings = [];
  let failCount = 0;
  
  function check(name, condition, details) {
    if (condition) {
      console.log(`[PASS] ${name}`);
      findings.push(`- **PASS:** ${name}`);
    } else {
      console.log(`[FAIL] ${name} - ${details}`);
      findings.push(`- **FAIL:** ${name} — ${details}`);
      failCount++;
    }
  }

  const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "gemini-evolve-test-"));
  
  try {
    console.log(`Running tests in temp dir: ${baseDir}`);
    
    // Attack 1: Staged-only / never-live
    {
      const p1Dir = path.join(baseDir, "p1-staged-only");
      fs.mkdirSync(p1Dir, { recursive: true });
      
      const seedDir = path.join(p1Dir, ".graphsmith", "evolvable", "seed");
      fs.mkdirSync(seedDir, { recursive: true });
      const learnedPath = path.join(seedDir, "graphsmith.learned.md");
      const originalLearnedContent = "# Learned\n__GS_EVOLVE_SLOT__\n";
      fs.writeFileSync(learnedPath, originalLearnedContent);
      const originalHash = sha256(originalLearnedContent);
      
      const manifestPath = path.join(seedDir, "tree.manifest.json");
      const manifestBytes = Buffer.from(JSON.stringify({ kind: "tree", files: [] }, null, 2) + "\n");
      fs.writeFileSync(manifestPath, manifestBytes);
      const treeHash = sha256(manifestBytes);
      const treeName = "v-" + treeHash;
      fs.renameSync(seedDir, path.join(p1Dir, ".graphsmith", "evolvable", treeName));
      const newLearnedPath = path.join(p1Dir, ".graphsmith", "evolvable", treeName, "graphsmith.learned.md");
      
      const activePath = path.join(p1Dir, ".graphsmith", "evolvable", "ACTIVE");
      fs.writeFileSync(activePath, JSON.stringify({ schema_version: "1.0", txid: "0".repeat(16), tree: treeName, tree_manifest_sha256: treeHash }) + "\n");
      
      const stateDir = path.join(p1Dir, ".graphsmith", "state");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(path.join(stateDir, "project.manifest.json"), JSON.stringify({
        schema_version: "1.0", kind: "project", parent_release_sha256: null, adoption_log_head: null, generated_at: "selftest", active_tree: treeName, active_tree_manifest_sha256: treeHash, files: [], workflow_manifests: []
      }) + "\n");
      
      const runDir = path.join(p1Dir, "runs", "run1");
      const chainHead = makeSyntheticRunLog(runDir, [
        { seq: 0, step: "test", type: "run_halt", code: "unknown_halt", delta_ms: 0, lossy: false },
        { seq: 1, step: "test2", type: "run_halt", code: "unknown_halt", delta_ms: 100, lossy: false }
      ], "run1");
      
      const anchor = { schema_version: "1.0", state_rev: 1, record_type: "ANCHOR_SET", run_id: "run1", chain_head: chainHead, expected_terminal_status: "run_halt" };
      fs.writeFileSync(path.join(stateDir, "run-anchors.jsonl"), JSON.stringify(anchor) + "\n");
      
      const result = evolve.cycle([runDir], { projectRoot: p1Dir });
      
      const afterHash = sha256(fs.readFileSync(newLearnedPath, "utf8"));
      
      check("Attack 1: Staged-only (learned file hash unchanged)", originalHash === afterHash, "Hash changed, evolve modified learned.md directly!");
      check("Attack 1: Staged proposals exist", result.proposals > 0 && result.staged.length > 0, "No proposals staged");
      
      // Auto-adopt path check (scan script code)
      const evolveCode = fs.readFileSync(evolvePath, "utf8");
      check("Attack 1: No auto-adopt path exists", !evolveCode.includes("auto_adopt = true") && !evolveCode.includes("auto_adopt: true"), "Found auto-adopt true flag in evolve.js");
    }

    // Attack 2: Proposer-view isolation
    {
      const p2Dir = path.join(baseDir, "p2-isolation");
      fs.mkdirSync(p2Dir, { recursive: true });
      // We will create events-proposer.jsonl in harvest dir with malicious string.
      const harvestDir = path.join(p2Dir, ".graphsmith", "harvest");
      fs.mkdirSync(harvestDir, { recursive: true });
      
      const maliciousProducerString = "MALICIOUS_INJECTION_PRODUCER_STRING";
      
      const proposerEvents = [
        { type: "run_halt", code: "err2", step_ref: maliciousProducerString, run_ref: "run2" },
        { type: "run_halt", code: "err2", step_ref: maliciousProducerString, run_ref: "run2" }
      ];
      fs.writeFileSync(path.join(harvestDir, "events-proposer.jsonl"), proposerEvents.map(e => JSON.stringify(e)).join("\n"));
      
      // evolve.mine expects an array of events directly
      const candidates = evolve.mine(proposerEvents);
      
      const maliciousFound = candidates.some(c => JSON.stringify(c).includes(maliciousProducerString));
      
      check("Attack 2: Proposer-view isolation", !maliciousFound, "Malicious producer string reached proposal output!");
    }

    // Attack 3: harvest_invalid -> 0 proposals
    {
      const p3Dir = path.join(baseDir, "p3-invalid");
      fs.mkdirSync(p3Dir, { recursive: true });
      const stateDir = path.join(p3Dir, ".graphsmith", "state");
      fs.mkdirSync(stateDir, { recursive: true });

      const runDir = path.join(p3Dir, "runs", "run3");
      fs.mkdirSync(runDir, { recursive: true });
      const b1 = { seq: 0, step: "ok", type: "run_halt", code: "err", delta_ms: 0, lossy: false, run_id: "run3" };
      const b2 = { seq: 1, step: "bad", type: "budget_breach", code: "max", delta_ms: 10, lossy: false, run_id: "run3" }; // Broken prev_hash
      fs.writeFileSync(path.join(runDir, "run.jsonl"), 
        JSON.stringify({ prev_hash: "genesis", line_hash: "h1", ...b1 }) + "\n" +
        JSON.stringify({ prev_hash: "wrong_hash", line_hash: "h2", ...b2 }) + "\n");
      
      const result = evolve.cycle([runDir], { projectRoot: p3Dir });
      check("Attack 3: harvest_invalid -> 0 proposals", result.proposals === 0 && result.reason === "harvest_invalid", "Evolve made proposals despite invalid harvest");
    }

    // Attack 4: ≤3 bounded edits + rejected buffer
    {
      const p4Dir = path.join(baseDir, "p4-bounds");
      const events = [
        { type: "run_halt", code: "errA", run_ref: "run4", step_ref: "s" },
        { type: "run_halt", code: "errA", run_ref: "run4", step_ref: "s" },
        { type: "budget_breach", code: "errB", run_ref: "run4", step_ref: "s" },
        { type: "budget_breach", code: "errB", run_ref: "run4", step_ref: "s" },
        { type: "tripwire", code: "errC", run_ref: "run4", step_ref: "s" },
        { type: "tripwire", code: "errC", run_ref: "run4", step_ref: "s" },
        { type: "scenario_fail", code: "errD", run_ref: "run4", step_ref: "s" },
        { type: "scenario_fail", code: "errD", run_ref: "run4", step_ref: "s" }
      ];
      const candidates = evolve.mine(events);
      check("Attack 4: ≤3 bounded edits", candidates.length <= 3, `Expected <= 3 candidates, got ${candidates.length}`);
      
      const p4Project = path.join(baseDir, "p4-project");
      fs.mkdirSync(path.join(p4Project, ".graphsmith", "state"), { recursive: true });
      const { createStore } = require(path.resolve(__dirname, '../../../scripts/state-store.js'));
      const store = createStore(p4Project);
      
      const dupSfp = evolve.semanticFingerprint("run_halt", "unknown_halt");
      store.rejectedBuffer.push({ fingerprint: "some-fp", value: { reason: "test", semanticFingerprint: dupSfp } });
      
      // Seed project files
      const seedDir = path.join(p4Project, ".graphsmith", "evolvable", "seed");
      fs.mkdirSync(seedDir, { recursive: true });
      fs.writeFileSync(path.join(seedDir, "graphsmith.learned.md"), "# Learned\n__GS_EVOLVE_SLOT__\n");
      const manifestBytes = Buffer.from(JSON.stringify({ kind: "tree", files: [] }, null, 2) + "\n");
      fs.writeFileSync(path.join(seedDir, "tree.manifest.json"), manifestBytes);
      const treeHash = sha256(manifestBytes);
      const treeName = "v-" + treeHash;
      fs.renameSync(seedDir, path.join(p4Project, ".graphsmith", "evolvable", treeName));
      fs.writeFileSync(path.join(p4Project, ".graphsmith", "evolvable", "ACTIVE"), JSON.stringify({ schema_version: "1.0", txid: "0".repeat(16), tree: treeName, tree_manifest_sha256: treeHash }) + "\n");
      fs.writeFileSync(path.join(p4Project, ".graphsmith", "state", "project.manifest.json"), JSON.stringify({
        schema_version: "1.0", kind: "project", parent_release_sha256: null, adoption_log_head: null, generated_at: "test", active_tree: treeName, active_tree_manifest_sha256: treeHash, files: [], workflow_manifests: []
      }) + "\n");

      const runDir = path.join(p4Project, "runs", "run4");
      const chainHead = makeSyntheticRunLog(runDir, [
        { seq: 0, step: "ok", type: "run_halt", code: "unknown_halt", delta_ms: 0, lossy: false },
        { seq: 1, step: "ok2", type: "run_halt", code: "unknown_halt", delta_ms: 100, lossy: false }
      ], "run4");
      fs.writeFileSync(path.join(p4Project, ".graphsmith", "state", "run-anchors.jsonl"), JSON.stringify({ schema_version: "1.0", state_rev: 1, record_type: "ANCHOR_SET", run_id: "run4", chain_head: chainHead, expected_terminal_status: "run_halt" }) + "\n");
      
      const result = evolve.cycle([runDir], { projectRoot: p4Project });
      check("Attack 4: rejected buffer refutes near-dup", result.filteredByBuffer >= 1, "Near-dup was not refused by rejected buffer!");
    }

    // Attack 5: F16 redaction in migrate
    {
      const p5Dir = path.join(baseDir, "p5-migrate");
      const harvestDir = path.join(p5Dir, ".graphsmith", "harvest");
      fs.mkdirSync(harvestDir, { recursive: true });
      const evidencePath = path.join(harvestDir, "events-evidence.jsonl");
      
      const maliciousEvents = [
        { secret: "api_key=sk-abc123def456ghi789jkl012mno345pqr", data: "ok" },
        { nested: { password: "password=supersecretpassword" } }
      ];
      fs.writeFileSync(evidencePath, maliciousEvents.map(e => JSON.stringify(e)).join("\n"));
      
      const migrateResult = migrate.migrate(p5Dir);
      check("Attack 5: migrate completed", migrateResult.migrated, "Migration failed");
      
      const migratedContent = fs.readFileSync(evidencePath, "utf8");
      check("Attack 5: F16 redaction", migratedContent.includes("[REDACTED]") && !migratedContent.includes("sk-abc123def456ghi789jkl012mno345pqr"), "Secret survived migration!");
    }

    // Attack 6: Lease-lock & Gates
    {
      const p6Dir = path.join(baseDir, "p6-leaselock");
      fs.mkdirSync(p6Dir, { recursive: true });
      const stateDir = path.join(p6Dir, ".graphsmith", "state");
      fs.mkdirSync(stateDir, { recursive: true });
      
      // Simulate another process holding the state lock
      const lockPath = path.join(stateDir, "state.lock");
      fs.writeFileSync(lockPath, JSON.stringify({
        schema_version: "1.0",
        pid: 999999, // Fake PID
        proc_start_hint: "test",
        owner_token: "fake-token"
      }));
      // Manually set mtime to now so it is fresh
      fs.utimesSync(lockPath, new Date(), new Date());
      
      const { createStore } = require(path.resolve(__dirname, '../../../scripts/state-store.js'));
      const lockedStore = createStore(p6Dir);
      
      let lockContended = false;
      try {
        lockedStore.rejectedBuffer.push({ fingerprint: "lock-fp", value: "test" });
      } catch (err) {
        if (err.code === "LOCKED" || err.message.includes("lock") || err.code === "LOCK_CONTENTION") {
          lockContended = true;
        }
      }
      check("Attack 6: Lease-lock prevents concurrent mutation", lockContended, "Lock contention was not thrown!");

      // A fence-violating proposal should be rejected by Gate 1
      const gatePath = path.resolve(__dirname, '../../../scripts/gate.js');
      const gate = require(gatePath);
      const maliciousCandidate = {
        kind: "doc",
        fingerprint: "bad-fp",
        semanticFingerprint: "bad-sfp",
        edits: [{ file: "scripts/evolve.js", op: "replace", payload: "console.log('hacked')" }]
      };
      const gate1Result = gate.gate1Static(maliciousCandidate, { aliasesResolved: true });
      const stringifiedFindings = JSON.stringify(gate1Result.findings);
      check("Attack 6: Gate 1 prevents script modification", !gate1Result.pass && (stringifiedFindings.includes("fence") || stringifiedFindings.includes("outside")), "Gate 1 allowed script modification!");
    }
    
    // Save Findings
    const findingsPath = path.join(__dirname, "FINDINGS.md");
    const findingsContent = `# FINDINGS - Evolve Adversarial Tests
    
${findings.join("\n")}

### Conclusion
Tests completed. Failure Count: ${failCount}
`;
    fs.writeFileSync(findingsPath, findingsContent);
    
    console.log(`\nAll checks executed. Failures: ${failCount}`);
    
    if (failCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.error("Test execution failed:", err);
    process.exit(1);
  } finally {
    fs.rmSync(baseDir, { recursive: true, force: true });
  }
}

runTests();
