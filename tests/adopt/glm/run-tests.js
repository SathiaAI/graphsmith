#!/usr/bin/env node
/* GraphSmith adopt.js adversarial test suite — GLM family tester
 * Zero-dep CJS, Node >= 18. Tests run in TEMP project dirs only.
 * Exit code 1 if any FAIL. Verdicts from on-disk state only.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { execSync } = require("child_process");

const TEST_ROOT = path.resolve(__dirname);
const ADOPT_SCRIPT = path.resolve(__dirname, "../../../scripts/adopt.js");
const EVOLVE_SCRIPT = path.resolve(__dirname, "../../../scripts/evolve.js");
const PROMOTE_SCRIPT = path.resolve(__dirname, "../../../scripts/promote.js");

const SCHEMA_VERSION = "1.0";

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

function fail(message, code) {
  const err = new Error(message);
  err.code = code || "TEST_ERROR";
  return err;
}

function mktemp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix || "graphsmith-glm-test-"));
}

function createFixtureTree(root) {
  const stateDir = path.join(root, ".graphsmith", "state");
  const evolvableDir = path.join(root, ".graphsmith", "evolvable");
  fs.mkdirSync(stateDir, { recursive: true });
  fs.mkdirSync(evolvableDir, { recursive: true });

  const seedDir = path.join(evolvableDir, "seed");
  fs.mkdirSync(seedDir);
  fs.writeFileSync(path.join(seedDir, "graphsmith.learned.md"), "# GraphSmith Learned Rules\n\n__GS_EVOLVE_SLOT__\n");
  fs.writeFileSync(path.join(seedDir, "tunables.json"), JSON.stringify({ limit: 42 }, null, 2));

  const manifest = {
    schema_version: SCHEMA_VERSION,
    kind: "tree",
    generated_at: new Date().toISOString(),
    files: [
      { path: "graphsmith.learned.md", size: 42, sha256: sha256("# GraphSmith Learned Rules\n\n__GS_EVOLVE_SLOT__\n") },
      { path: "tunables.json", size: 20, sha256: sha256(JSON.stringify({ limit: 42 })) },
    ],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n");
  fs.writeFileSync(path.join(seedDir, "tree.manifest.json"), manifestBytes);

  const treeHash = sha256(manifestBytes);
  const treeName = "v-" + treeHash;
  fs.renameSync(seedDir, path.join(evolvableDir, treeName));

  const pointer = {
    schema_version: SCHEMA_VERSION,
    txid: "0".repeat(16),
    tree: treeName,
    tree_manifest_sha256: treeHash,
  };
  fs.writeFileSync(path.join(evolvableDir, "ACTIVE"), Buffer.from(JSON.stringify(pointer, null, 2) + "\n", "utf8"));

  const projectManifest = {
    schema_version: SCHEMA_VERSION,
    kind: "project",
    generated_at: "selftest",
    parent_release_sha256: null,
    adoption_log_head: null,
    active_tree: treeName,
    active_tree_manifest_sha256: treeHash,
    files: [],
    workflow_manifests: [],
  };
  fs.writeFileSync(path.join(stateDir, "project.manifest.json"), JSON.stringify(projectManifest, null, 2) + "\n");

  return { treeName, treeHash };
}

function createPendingProposal(root, overrides = {}) {
  const pendingPath = path.join(root, ".graphsmith", "state", "pending-proposals.jsonl");
  fs.mkdirSync(path.dirname(pendingPath), { recursive: true });

  const proposalId = overrides.proposal_id || sha256("glm-test-proposal-" + Date.now());
  const fingerprint = overrides.fingerprint || proposalId;

  const record = {
    schema_version: SCHEMA_VERSION,
    proposal_id: proposalId,
    fingerprint: fingerprint,
    kind: overrides.kind || "doc",
    status: "PENDING_HUMAN_REVIEW",
    gate3: {
      diff: overrides.diff || [{ file: "graphsmith.learned.md", anchor: "__GS_EVOLVE_SLOT__", op: "replace", payload: "\n## Test Rule\n__GS_EVOLVE_SLOT__\n" }],
      plainEnglish: overrides.plainEnglish || "Add a test rule for GLM adoption testing",
      inverse: overrides.inverse || [{ file: "graphsmith.learned.md", anchor: "## Test Rule", op: "replace", payload: "__GS_EVOLVE_SLOT__\n" }],
      reversible: overrides.reversible !== undefined ? overrides.reversible : true,
      autoRollbackEligible: overrides.autoRollbackEligible !== undefined ? overrides.autoRollbackEligible : true,
    },
    edits: overrides.edits || [{ 
      file: "graphsmith.learned.md", 
      anchor: "__GS_EVOLVE_SLOT__", 
      op: "replace", 
      payload: "\n## Test Rule\n__GS_EVOLVE_SLOT__\n", 
      schema_ref: "test/v1", 
      schema_version: SCHEMA_VERSION 
    }],
    created_at: new Date().toISOString(),
    ...overrides,
  };

  fs.appendFileSync(pendingPath, JSON.stringify(record) + "\n");
  return record;
}

function readActivePointer(root) {
  const activePath = path.join(root, ".graphsmith", "evolvable", "ACTIVE");
  if (!fs.existsSync(activePath)) return null;
  const raw = fs.readFileSync(activePath, "utf8");
  return JSON.parse(raw);
}

function readAdoptionLog(root) {
  const logPath = path.join(root, ".graphsmith", "state", "adoption-log.jsonl");
  if (!fs.existsSync(logPath)) return [];
  const raw = fs.readFileSync(logPath, "utf8");
  return raw.split("\n").filter(Boolean).map(line => JSON.parse(line));
}

function readPendingProposals(root) {
  const pendingPath = path.join(root, ".graphsmith", "state", "pending-proposals.jsonl");
  if (!fs.existsSync(pendingPath)) return [];
  const raw = fs.readFileSync(pendingPath, "utf8");
  return raw.split("\n").filter(Boolean).map(line => JSON.parse(line));
}

function loadAdoptModule() {
  const adoptPath = path.resolve(__dirname, "../../../scripts/adopt.js");
  delete require.cache[require.resolve(adoptPath)];
  return require(adoptPath);
}

function runCli(args) {
  try {
    const output = execSync(`node "${ADOPT_SCRIPT}" ${args}`, { encoding: "utf8", cwd: TEST_ROOT });
    return { success: true, output, exitCode: 0 };
  } catch (error) {
    return { success: false, output: error.stdout || error.stderr || "", exitCode: error.status || 1 };
  }
}

function assertEq(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw fail(`${message}\nExpected: ${JSON.stringify(expected)}\nActual: ${JSON.stringify(actual)}`, "ASSERTION_FAILED");
  }
}

function assertTrue(condition, message) {
  if (!condition) {
    throw fail(message, "ASSERTION_FAILED");
  }
}

function assertFalse(condition, message) {
  if (condition) {
    throw fail(message, "ASSERTION_FAILED");
  }
}

class TestRunner {
  constructor() {
    this.tests = [];
    this.failures = [];
    this.passes = [];
    this.skipped = [];
  }

  test(name, fn) {
    this.tests.push({ name, fn });
  }

  async run() {
    for (const { name, fn } of this.tests) {
      let tempDir = null;
      try {
        tempDir = mktemp("graphsmith-glm-adopt-");
        await fn(tempDir);
        this.passes.push({ name, status: "PASS" });
        console.log(`✓ PASS: ${name}`);
      } catch (error) {
        this.failures.push({ name, status: "FAIL", reason: error.message, code: error.code });
        console.log(`✗ FAIL: ${name} - ${error.message} (${error.code || "UNKNOWN"})`);
      } finally {
        if (tempDir && fs.existsSync(tempDir)) {
          try {
            fs.rmSync(tempDir, { recursive: true, force: true });
          } catch (cleanupError) {
            console.log(`  ! Failed to cleanup temp dir: ${cleanupError.message}`);
          }
        }
      }
    }

    return this.report();
  }

  report() {
    const total = this.tests.length;
    const passed = this.passes.length;
    const failed = this.failures.length;
    const skipped = this.skipped.length;

    console.log(`\n=== TEST SUMMARY ===`);
    console.log(`Total: ${total}, Passed: ${passed}, Failed: ${failed}, Skipped: ${skipped}`);
    
    if (this.failures.length > 0) {
      console.log(`\n=== FAILURES ===`);
      for (const { name, reason, code } of this.failures) {
        console.log(`- ${name}: ${reason} (${code})`);
      }
    }

    return {
      schema_version: SCHEMA_VERSION,
      total,
      passed,
      failed,
      skipped,
      status: failed === 0 ? "PASS" : "FAIL",
      exitCode: failed === 0 ? 0 : 1,
      failures: this.failures,
    };
  }
}

const runner = new TestRunner();

// ============================================================================
// ATTACK 1: Confirmation cannot be bypassed (THE guarantee)
// ============================================================================

runner.test("adopt-without-confirm-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id);

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertFalse(result.adopted, "Adoption should not succeed without confirmation");
  assertTrue(result.refused, "Adoption should be refused without confirmation");
  assertEq(result.reason, "ADOPTION_REQUIRES_HUMAN_CONFIRMATION", "Reason should be correct");
  assertEq(beforeActive, afterActive, "ACTIVE pointer should not change");
  assertEq(beforeLog, afterLog, "Adoption log should not change");
});

runner.test("adopt-with-confirm-false-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: false });

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertFalse(result.adopted, "Adoption should not succeed with confirm=false");
  assertTrue(result.refused, "Adoption should be refused with confirm=false");
  assertEq(beforeActive, afterActive, "ACTIVE pointer should not change");
  assertEq(beforeLog, afterLog, "Adoption log should not change");
});

runner.test("adopt-with-yes-false-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { yes: false });

  assertFalse(result.adopted, "Adoption should not succeed with yes=false");
  assertTrue(result.refused, "Adoption should be refused with yes=false");
});

runner.test("adopt-with-undefined-confirm-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: undefined });

  assertFalse(result.adopted, "Adoption should not succeed with undefined confirm");
  assertTrue(result.refused, "Adoption should be refused with undefined confirm");
});

runner.test("adopt-with-null-confirm-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: null });

  assertFalse(result.adopted, "Adoption should not succeed with null confirm");
  assertTrue(result.refused, "Adoption should be refused with null confirm");
});

runner.test("adopt-with-string-yes-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: "yes" });

  assertFalse(result.adopted, "Adoption should not succeed with string 'yes'");
  assertTrue(result.refused, "Adoption should be refused with string 'yes'");
});

runner.test("adopt-with-string-false-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: "false" });

  assertFalse(result.adopted, "Adoption should not succeed with string 'false'");
  assertTrue(result.refused, "Adoption should be refused with string 'false'");
});

runner.test("adopt-with-number-1-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: 1 });

  assertFalse(result.adopted, "Adoption should not succeed with number 1");
  assertTrue(result.refused, "Adoption should be refused with number 1");
});

runner.test("adopt-with-number-0-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: 0 });

  assertFalse(result.adopted, "Adoption should not succeed with number 0");
  assertTrue(result.refused, "Adoption should be refused with number 0");
});

runner.test("adopt-with-empty-string-confirm-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: "" });

  assertFalse(result.adopted, "Adoption should not succeed with empty string confirm");
  assertTrue(result.refused, "Adoption should be refused with empty string confirm");
});

runner.test("cli-without-yes-flag-refused", async (tempDir) => {
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = runCli(`adopt "${proposal.proposal_id}" --project-root "${tempDir}"`);

  assertFalse(result.success, "CLI should fail without --yes flag");
  assertTrue(result.exitCode !== 0, "CLI should exit with non-zero code without --yes");
  assertTrue(result.output.includes("refused") || result.output.includes("ADOPTION_REQUIRES_HUMAN_CONFIRMATION"), 
    "CLI output should indicate refusal");
});

runner.test("cli-with-yes-flag-succeeds", async (tempDir) => {
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = runCli(`adopt "${proposal.proposal_id}" --yes --project-root "${tempDir}"`);

  assertTrue(result.success, "CLI should succeed with --yes flag");
  assertTrue(result.exitCode === 0, "CLI should exit with zero code with --yes");
  assertTrue(result.output.includes("adopted"), "CLI output should mention adoption");
});

runner.test("cli-with-y-flag-succeeds", async (tempDir) => {
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = runCli(`adopt "${proposal.proposal_id}" -y --project-root "${tempDir}"`);

  assertTrue(result.success, "CLI should succeed with -y flag");
  assertTrue(result.exitCode === 0, "CLI should exit with zero code with -y flag");
});

runner.test("adopt-with-true-confirm-succeeds", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });

  assertTrue(result.adopted, "Adoption should succeed with confirm=true");
  assertFalse(result.refused, "Adoption should not be refused with confirm=true");
});

runner.test("adopt-with-true-yes-succeeds", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { yes: true });

  assertTrue(result.adopted, "Adoption should succeed with yes=true");
  assertFalse(result.refused, "Adoption should not be refused with yes=true");
});

runner.test("adopt-with-extra-args-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true, extra: "ignored" });

  assertTrue(result.adopted, "Adoption should succeed with confirm=true even with extra args");
});

// ============================================================================
// ATTACK 2: Only-path / no side-channel
// ============================================================================

runner.test("listPending-never-mutates", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);
  const beforePending = readPendingProposals(tempDir);

  adopt.listPending(tempDir);

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);
  const afterPending = readPendingProposals(tempDir);

  assertEq(beforeActive, afterActive, "ACTIVE should not change after listPending");
  assertEq(beforeLog, afterLog, "Adoption log should not change after listPending");
  assertEq(beforePending, afterPending, "Pending proposals should not change after listPending");
});

runner.test("observe-never-adopts", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  try {
    adopt.observe(tempDir, "test-run-id", "test-tree-id");
  } catch (error) {
    // observe might fail due to missing state, but should never adopt
  }

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertEq(beforeActive, afterActive, "ACTIVE should not change after observe");
  assertEq(beforeLog, afterLog, "Adoption log should not change after observe");

  const pending = readPendingProposals(tempDir);
  assertTrue(pending.some(p => p.proposal_id === proposal.proposal_id && p.status === "PENDING_HUMAN_REVIEW"),
    "Proposal should still be pending after observe");
});

runner.test("close-never-adopts", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  try {
    adopt.close(tempDir, "test-window-id", "pass");
  } catch (error) {
    // close might fail due to missing window, but should never adopt
  }

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertEq(beforeActive, afterActive, "ACTIVE should not change after close");
  assertEq(beforeLog, afterLog, "Adoption log should not change after close");

  const pending = readPendingProposals(tempDir);
  assertTrue(pending.some(p => p.proposal_id === proposal.proposal_id && p.status === "PENDING_HUMAN_REVIEW"),
    "Proposal should still be pending after close");
});

// ============================================================================
// ATTACK 3: Idempotency / double-adopt
// ============================================================================

runner.test("double-adopt-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const firstResult = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });
  assertTrue(firstResult.adopted, "First adoption should succeed");

  const secondResult = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });
  assertFalse(secondResult.adopted, "Second adoption should be refused");
  assertTrue(secondResult.refused, "Second adoption should be refused");
  assertEq(secondResult.reason, "PROPOSAL_NOT_PENDING", "Reason should be PROPOSAL_NOT_PENDING");
});

runner.test("adopt-consumes-proposal", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const pendingBefore = adopt.listPending(tempDir);
  assertTrue(pendingBefore.some(p => p.proposal_id === proposal.proposal_id), 
    "Proposal should be pending before adoption");

  adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });

  const pendingAfter = adopt.listPending(tempDir);
  assertFalse(pendingAfter.some(p => p.proposal_id === proposal.proposal_id), 
    "Proposal should not be pending after adoption");
});

runner.test("adopt-creates-tombstone", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });

  const allRecords = readPendingProposals(tempDir);
  const adoptedRecord = allRecords.find(r => r.proposal_id === proposal.proposal_id && r.status === "ADOPTED");
  assertTrue(adoptedRecord !== undefined, "Adopted tombstone record should exist");
  assertEq(adoptedRecord.adopted_txid.length, 16, "Tombstone should have txid");
  assertTrue(typeof adoptedRecord.adopted_at === "string", "Tombstone should have adopted_at timestamp");
});

runner.test("adopt-does-not-corrupt-other-proposals", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal1 = createPendingProposal(tempDir, { proposal_id: sha256("proposal-1"), fingerprint: sha256("proposal-1") });
  const proposal2 = createPendingProposal(tempDir, { proposal_id: sha256("proposal-2"), fingerprint: sha256("proposal-2") });
  const proposal3 = createPendingProposal(tempDir, { proposal_id: sha256("proposal-3"), fingerprint: sha256("proposal-3") });

  adopt.adopt(tempDir, proposal1.proposal_id, { confirm: true });

  const pending = adopt.listPending(tempDir);
  assertTrue(pending.length === 2, "Should have 2 pending proposals left");
  assertTrue(pending.some(p => p.proposal_id === proposal2.proposal_id), "Proposal 2 should still be pending");
  assertTrue(pending.some(p => p.proposal_id === proposal3.proposal_id), "Proposal 3 should still be pending");

  const allRecords = readPendingProposals(tempDir);
  assertTrue(allRecords.length === 4, "Should have 4 total records (3 initial + 1 tombstone)");
  assertTrue(allRecords.some(r => r.proposal_id === proposal2.proposal_id && r.status === "PENDING_HUMAN_REVIEW"),
    "Proposal 2 record should still be PENDING_HUMAN_REVIEW");
  assertTrue(allRecords.some(r => r.proposal_id === proposal3.proposal_id && r.status === "PENDING_HUMAN_REVIEW"),
    "Proposal 3 record should still be PENDING_HUMAN_REVIEW");
});

// ============================================================================
// ATTACK 4: End-to-end correctness
// ============================================================================

runner.test("end-to-end-adopt-promote-observe-close-pass", async (tempDir) => {
  const adopt = loadAdoptModule();
  const { treeName } = createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);

  // Adopt with window_n=1 so we only need to complete 1 slot
  const adoptResult = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true, windowN: 1 });
  assertTrue(adoptResult.adopted, "Adoption should succeed");
  assertTrue(typeof adoptResult.txid === "string", "Should have txid");
  assertEq(adoptResult.state, "DONE", "State should be DONE");

  // Check ACTIVE pointer changed
  const afterActive = readActivePointer(tempDir);
  assertFalse(beforeActive.tree === afterActive.tree, "ACTIVE tree should change");
  assertEq(afterActive.txid, adoptResult.txid, "ACTIVE txid should match adopted txid");

  // Check adoption-log has effective entry
  const log = readAdoptionLog(tempDir);
  assertTrue(log.length > 0, "Adoption log should have entries");
  const effectiveEntry = log[log.length - 1];
  assertEq(effectiveEntry.status, "effective", "Last entry should be effective");
  assertEq(effectiveEntry.txid, adoptResult.txid, "Entry txid should match");

  // Check window state
  const store = require("../../../scripts/state-store.js").createStore(tempDir);
  const window = store.window.get();
  assertTrue(window.state === "OBSERVING", "Window should be OBSERVING");
  assertTrue(window.window !== null, "Window should exist");
  assertEq(window.window.window_id, adoptResult.txid, "Window id should match txid");

  // Since we set window_n=1, we just need to complete that single slot
  adopt.observe(tempDir, "test-run-1", afterActive.tree);
  
  // Complete the run (this simulates a successful observation)
  store.runRegistry.deregister("test-run-1", { 
    disposition: "completed_pass", 
    terminal: true 
  });

  // Close with pass
  const closeResult = adopt.close(tempDir, adoptResult.txid, "pass");
  assertEq(closeResult.state, "CLOSED_PASS", "Window should close with pass");

  // Check ACTIVE still points to adopted tree
  const finalActive = readActivePointer(tempDir);
  assertEq(finalActive.tree, afterActive.tree, "ACTIVE should still point to adopted tree after close(pass)");
});

runner.test("close-pass-keeps-adoption", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const adoptResult = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true, windowN: 1 });
  const adoptedActive = readActivePointer(tempDir);

  // Make window closable by completing the observation slot
  const store = require("../../../scripts/state-store.js").createStore(tempDir);
  adopt.observe(tempDir, "test-run-2", adoptedActive.tree);
  
  // Complete the run
  store.runRegistry.deregister("test-run-2", { 
    disposition: "completed_pass", 
    terminal: true 
  });

  const closeResult = adopt.close(tempDir, adoptResult.txid, "pass");
  assertEq(closeResult.state, "CLOSED_PASS", "Should close with pass");

  const finalActive = readActivePointer(tempDir);
  assertEq(finalActive.tree, adoptedActive.tree, "ACTIVE should still point to adopted tree");
});

// ============================================================================
// ATTACK 5: Malformed / hostile pending file
// ============================================================================

runner.test("malformed-json-in-pending-file-fails-closed", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const pendingPath = path.join(tempDir, ".graphsmith", "state", "pending-proposals.jsonl");
  fs.appendFileSync(pendingPath, "{malformed json without closing brace\n");

  let result;
  try {
    result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });
  } catch (error) {
    result = { adopted: false, refused: true, error: error.message };
  }

  assertFalse(result.adopted, "Adoption should fail with malformed JSON");
  assertTrue(result.refused || result.adopted === false, "Should be refused or not adopted");

  const active = readActivePointer(tempDir);
  const log = readAdoptionLog(tempDir);
  assertTrue(active !== null, "ACTIVE should still exist");
  assertTrue(log.length === 0, "Adoption log should be empty");
});

runner.test("truncated-pending-file-fails-closed", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const pendingPath = path.join(tempDir, ".graphsmith", "state", "pending-proposals.jsonl");
  const content = fs.readFileSync(pendingPath, "utf8");
  fs.writeFileSync(pendingPath, content.slice(0, -10)); // Truncate last part

  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });

  assertFalse(result.adopted, "Adoption should fail with truncated file");
  assertTrue(result.refused || result.adopted === false, "Should be refused or not adopted");
});

runner.test("missing-fields-in-proposal-fails-closed", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  
  const proposalId = sha256("incomplete-proposal");
  const pendingPath = path.join(tempDir, ".graphsmith", "state", "pending-proposals.jsonl");
  fs.appendFileSync(pendingPath, JSON.stringify({
    proposal_id: proposalId,
    status: "PENDING_HUMAN_REVIEW",
    fingerprint: sha256("incomplete"),
    kind: "doc",
    // Missing required fields like gate3, edits
  }) + "\n");

  let result;
  try {
    result = adopt.adopt(tempDir, proposalId, { confirm: true });
  } catch (error) {
    result = { adopted: false, refused: true, error: error.message };
  }

  assertFalse(result.adopted === true, "Adoption should fail with incomplete proposal");
});

runner.test("non-existent-tree-reference-fails-closed", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir, {
    edits: [{ 
      file: "non-existent-file.md", 
      anchor: "test", 
      op: "replace", 
      payload: "test",
      schema_ref: "test/v1",
      schema_version: SCHEMA_VERSION
    }]
  });

  let result;
  try {
    result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });
  } catch (error) {
    result = { adopted: false, refused: true, error: error.message };
  }

  // This might fail at different stages but should never succeed
  assertFalse(result.adopted === true, "Adoption should not succeed with non-existent file reference");
});

runner.test("injection-attempt-in-proposal-fields-fails-closed", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir, {
    plainEnglish: "<script>alert('xss')</script>",
    diff: [{ 
      file: "../../../etc/passwd", 
      anchor: "test", 
      op: "replace", 
      payload: "malicious" 
    }],
    edits: [{ 
      file: "../../../etc/passwd", 
      anchor: "test", 
      op: "replace", 
      payload: "malicious",
      schema_ref: "test/v1",
      schema_version: SCHEMA_VERSION
    }]
  });

  let result;
  try {
    result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });
  } catch (error) {
    result = { adopted: false, refused: true, error: error.message };
  }

  // Should fail either at validation or promotion stage
  assertFalse(result.adopted === true, "Adoption should not succeed with injection attempt");
  assertTrue(result.error !== undefined || result.refused === true, "Should have error or be refused");
});

// ============================================================================
// ATTACK 6: No auto-adopt regression
// ============================================================================

runner.test("listPending-does-not-auto-adopt", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  adopt.listPending(tempDir);

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertEq(beforeActive, afterActive, "listPending should not modify ACTIVE");
  assertEq(beforeLog, afterLog, "listPending should not modify adoption-log");

  const pending = readPendingProposals(tempDir);
  assertTrue(pending.some(p => p.proposal_id === proposal.proposal_id && p.status === "PENDING_HUMAN_REVIEW"),
    "Proposal should still be pending after listPending");
});

runner.test("observe-does-not-auto-adopt", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  try {
    adopt.observe(tempDir, "run-1", "tree-1");
  } catch (error) {
    // Expected to fail, but should not adopt
  }

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertEq(beforeActive, afterActive, "observe should not modify ACTIVE");
  assertEq(beforeLog, afterLog, "observe should not modify adoption-log");

  const pending = readPendingProposals(tempDir);
  assertTrue(pending.some(p => p.proposal_id === proposal.proposal_id && p.status === "PENDING_HUMAN_REVIEW"),
    "Proposal should still be pending after observe");
});

runner.test("close-does-not-auto-adopt", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  const proposal = createPendingProposal(tempDir);

  const beforeActive = readActivePointer(tempDir);
  const beforeLog = readAdoptionLog(tempDir);

  try {
    adopt.close(tempDir, "window-1", "pass");
  } catch (error) {
    // Expected to fail, but should not adopt
  }

  const afterActive = readActivePointer(tempDir);
  const afterLog = readAdoptionLog(tempDir);

  assertEq(beforeActive, afterActive, "close should not modify ACTIVE");
  assertEq(beforeLog, afterLog, "close should not modify adoption-log");

  const pending = readPendingProposals(tempDir);
  assertTrue(pending.some(p => p.proposal_id === proposal.proposal_id && p.status === "PENDING_HUMAN_REVIEW"),
    "Proposal should still be pending after close");
});

// ============================================================================
// Additional edge case tests
// ============================================================================

runner.test("adopt-non-existent-proposal-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);

  const result = adopt.adopt(tempDir, "non-existent-proposal-id", { confirm: true });

  assertFalse(result.adopted, "Adoption should fail for non-existent proposal");
  assertTrue(result.refused, "Should be refused");
  assertEq(result.reason, "PROPOSAL_NOT_FOUND", "Reason should be PROPOSAL_NOT_FOUND");
});

runner.test("adopt-already-adopted-proposal-refused", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);
  
  // Create and adopt a proposal
  const proposal = createPendingProposal(tempDir);
  adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });

  // Try to adopt again
  const result = adopt.adopt(tempDir, proposal.proposal_id, { confirm: true });

  assertFalse(result.adopted, "Adoption should fail for already-adopted proposal");
  assertTrue(result.refused, "Should be refused");
  assertEq(result.reason, "PROPOSAL_NOT_PENDING", "Reason should be PROPOSAL_NOT_PENDING");
});

runner.test("empty-pending-file-handled-gracefully", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);

  const pendingPath = path.join(tempDir, ".graphsmith", "state", "pending-proposals.jsonl");
  fs.writeFileSync(pendingPath, "");

  const pending = adopt.listPending(tempDir);
  assertTrue(Array.isArray(pending), "Should return array");
  assertTrue(pending.length === 0, "Should return empty array");
});

runner.test("missing-pending-file-handled-gracefully", async (tempDir) => {
  const adopt = loadAdoptModule();
  createFixtureTree(tempDir);

  const pending = adopt.listPending(tempDir);
  assertTrue(Array.isArray(pending), "Should return array");
  assertTrue(pending.length === 0, "Should return empty array");
});

// ============================================================================
// MAIN ENTRY
// ============================================================================

async function main() {
  console.log("=== GLM Adversarial Test Suite for scripts/adopt.js ===\n");
  
  const report = await runner.run();
  
  console.log(`\n=== FINAL RESULT ===`);
  console.log(`Status: ${report.status}`);
  console.log(`Exit Code: ${report.exitCode}`);
  
  process.exit(report.exitCode);
}

if (require.main === module) {
  main().catch(error => {
    console.error("FATAL ERROR:", error);
    process.exit(1);
  });
}

module.exports = { runner, TestRunner };