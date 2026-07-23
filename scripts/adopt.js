#!/usr/bin/env node
/* GraphSmith adopt.js — Phase C (gates-wiring builder). Zero-dep CJS, Node >= 18.
 *
 * The separate, human-driven adoption step that bridges evolve's staged
 * Gate-3 packets (.graphsmith/state/pending-proposals.jsonl) to promote()'s
 * Gate-4 canary window.
 *
 *   listPending(projectRoot)                     — read-only, show staged packets
 *   adopt(projectRoot, proposalId, {confirm})     — human-confirmed adoption of ONE proposal
 *   observe(projectRoot, runId, treeId)           — thin delegate to gate.gate4Observe
 *   close(projectRoot, windowId, outcome)         — thin delegate to gate.gate4Close
 *
 * adopt.js is the ONLY path from a staged proposal to an adopted change.
 * evolve.js NEVER adopts. Adoption REQUIRES explicit human confirmation
 * (confirm:true / --yes) — it is never silent.
 *
 * No LLM/clock/random in decision paths. Timestamps written into audit
 * metadata (human.ts, adopted_at) are NOT decision inputs — same posture as
 * manifest.js and state-store.js (clocks in metadata are fine; never in a
 * pass/fail decision).
 *
 * --selftest proves the END-TO-END chain: candidate -> gate1Static pass ->
 * gate2Behavioral (synthetic promote-worthy bundle) -> evolve stages a
 * Gate-3 packet -> listPending shows it -> adopt(...{confirm:true}) runs
 * promote -> Gate-4 window ADMITTED -> observe -> close(pass) keeps it
 * (ACTIVE now points at the new tree, adoption-log has the effective entry);
 * AND adopt WITHOUT confirm is REFUSED (nothing adopted).
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

const gate = require("./gate.js");
const promoteApi = require("./promote.js");
const { createStore } = require("./state-store.js");
const { generate } = require("./manifest.js");
const evolve = require("./evolve.js");

const SCHEMA_VERSION = "1.0";
const DEFAULT_WINDOW_N = 5;

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

function fail(message, code) {
  const err = new Error(message);
  err.code = code || "ADOPT_ERROR";
  return err;
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw fail(`${name} must be a non-empty string`, "INVALID_ARGUMENT");
  return value;
}

/* ---------------------------------------------------------------------------
 * Pending-proposals reading (append-only-safe; never rewrites past lines)
 * ------------------------------------------------------------------------- */

function pendingProposalsPath(projectRoot) {
  return path.join(projectRoot, ".graphsmith", "state", "pending-proposals.jsonl");
}

function readProposalRecords(projectRoot) {
  const filePath = pendingProposalsPath(projectRoot);
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
  const lines = raw.split("\n");
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      const isTornTail = i === lines.length - 1 && !raw.endsWith("\n");
      if (isTornTail) break;
      throw fail(`Corrupt JSONL in pending-proposals.jsonl at line ${i + 1}: ${err.message}`, "CORRUPT_STATE");
    }
  }
  return records;
}

/* Latest record per proposal_id — a later "ADOPTED" tombstone (appended by
 * adopt()) supersedes the earlier "PENDING_HUMAN_REVIEW" staging record.
 * Nothing is ever rewritten in place — the file stays append-only-safe. */
function latestByProposalId(records) {
  const map = new Map();
  for (const r of records) {
    if (!r || typeof r.proposal_id !== "string") continue;
    map.set(r.proposal_id, r);
  }
  return map;
}

function appendProposalRecord(projectRoot, record) {
  const filePath = pendingProposalsPath(projectRoot);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const fd = fs.openSync(filePath, "a");
  try {
    fs.writeSync(fd, JSON.stringify(record) + "\n");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/* ---------------------------------------------------------------------------
 * listPending — read-only, human review
 * ------------------------------------------------------------------------- */

function listPending(projectRoot) {
  const root = path.resolve(projectRoot || ".");
  const records = readProposalRecords(root);
  const latest = latestByProposalId(records);
  const seen = new Set();
  const out = [];
  for (const r of records) {
    if (!r || typeof r.proposal_id !== "string" || seen.has(r.proposal_id)) continue;
    seen.add(r.proposal_id);
    const current = latest.get(r.proposal_id);
    if (current && current.status === "PENDING_HUMAN_REVIEW") out.push(current);
  }
  return out;
}

/* ---------------------------------------------------------------------------
 * adopt — the ONLY path from a staged proposal to an adopted change.
 * REQUIRES explicit human confirmation. Never silent.
 * ------------------------------------------------------------------------- */

function buildPromotionPacket(projectRoot, record, opts) {
  const gate3 = record.gate3 || {};
  return {
    project_root: projectRoot,
    fingerprint: record.fingerprint,
    kind: record.kind,
    /* evidence_ref: a traceable pointer back to the staged packet that
     * carries the real Gate-3 evidence — never the raw evidence itself. */
    evidence_ref: record.proposal_id,
    human: {
      name: (opts && opts.humanName) || "graphsmith-adopt-cli",
      decision: "adopt",
      ts: new Date().toISOString(), /* audit metadata only — not a decision input */
    },
    edits: record.edits,
    reversible: gate3.reversible === true,
    auto_rollback_eligible: gate3.autoRollbackEligible === true,
    window_n: (opts && Number.isSafeInteger(opts.windowN) && opts.windowN > 0) ? opts.windowN : DEFAULT_WINDOW_N,
  };
}

function adopt(projectRoot, proposalId, opts = {}) {
  const root = path.resolve(projectRoot || ".");
  requiredString(proposalId, "proposalId");

  const confirmed = opts.confirm === true || opts.yes === true;
  if (!confirmed) {
    return {
      adopted: false,
      refused: true,
      reason: "ADOPTION_REQUIRES_HUMAN_CONFIRMATION",
      proposal_id: proposalId,
    };
  }

  const records = readProposalRecords(root);
  const latest = latestByProposalId(records);
  const record = latest.get(proposalId);

  if (!record) {
    return { adopted: false, refused: true, reason: "PROPOSAL_NOT_FOUND", proposal_id: proposalId };
  }
  if (record.status !== "PENDING_HUMAN_REVIEW") {
    return {
      adopted: false, refused: true, reason: "PROPOSAL_NOT_PENDING",
      proposal_id: proposalId, status: record.status,
    };
  }

  const packet = buildPromotionPacket(root, record, opts);
  const result = promoteApi.promote(packet); /* throws on failure — proposal stays PENDING, untouched */

  /* Mark consumed by APPENDING a tombstone — never rewrite/truncate the
   * staging file, so a crash mid-write cannot corrupt any other proposal. */
  appendProposalRecord(root, {
    ...record,
    status: "ADOPTED",
    adopted_txid: result.txid,
    adopted_state: result.state,
    adopted_by: packet.human.name,
    adopted_at: packet.human.ts,
  });

  return {
    adopted: true,
    refused: false,
    proposal_id: proposalId,
    txid: result.txid,
    window_id: result.txid,
    state: result.state,
  };
}

/* ---------------------------------------------------------------------------
 * Gate-4 observe/close — thin delegation to gate.js (via state-store).
 * No new gate logic lives here.
 * ------------------------------------------------------------------------- */

function observe(projectRoot, runId, treeId) {
  const root = path.resolve(projectRoot || ".");
  const store = createStore(root);
  /* gate.gate4Observe expects a `.register(runId, treeId)` surface (the
   * shape state-store.js's module-level singleton exposes) — adapt our
   * project-scoped StateStore instance (whose method is `.registerRun`)
   * rather than relying on the process-wide cwd-bound singleton, which
   * would silently ignore projectRoot. Delegation only — no gate logic. */
  const stateStoreAdapter = { register: (runId2, treeId2) => store.registerRun(runId2, treeId2) };
  return gate.gate4Observe({ runId, treeId }, stateStoreAdapter);
}

function close(projectRoot, windowId, outcome) {
  const root = path.resolve(projectRoot || ".");
  const stateStore = createStore(root);
  return gate.gate4Close(windowId, outcome, stateStore);
}

/* ---------------------------------------------------------------------------
 * Selftest infrastructure (fixture builders — mirrors evolve.js/promote.js
 * fixture conventions; adopt.js does not modify those files, only reuses
 * their exported APIs plus its own local fixture scaffolding).
 * ------------------------------------------------------------------------- */

function makeFixtureTree(root) {
  const stateDir = path.join(root, ".graphsmith", "state");
  const evolvableDir = path.join(root, ".graphsmith", "evolvable");
  fs.mkdirSync(stateDir, { recursive: true });
  fs.mkdirSync(evolvableDir, { recursive: true });

  const seedDir = path.join(evolvableDir, "seed");
  fs.mkdirSync(seedDir);
  fs.writeFileSync(path.join(seedDir, "graphsmith.learned.md"), "# GraphSmith Learned Rules\n\n__GS_EVOLVE_SLOT__\n");

  const manifest = generate("tree", { rootDir: seedDir });
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

function makeSyntheticAnchor(projectRoot, runId, chainHead, expectedTerminal) {
  const anchorPath = path.join(projectRoot, ".graphsmith", "state", "run-anchors.jsonl");
  const anchor = {
    schema_version: SCHEMA_VERSION,
    state_rev: 1,
    record_type: "ANCHOR_SET",
    run_id: runId,
    chain_head: chainHead,
    expected_terminal_status: expectedTerminal,
  };
  fs.appendFileSync(anchorPath, JSON.stringify(anchor) + "\n");
}

/* Synthetic Gate-2 bundle: n_d=6 confirmation pairs, candidate wins all —
 * 2^-6 = 0.015625 <= Bonferroni alpha (0.05/3 ~= 0.01667) => promote. Same
 * construction gate.js's own selftest uses for its "clear winner" proof. */
function makeConfirmationBundle(desiredND, candidateId) {
  const POOL_SIZE = 200;
  const allIds = Array.from({ length: POOL_SIZE }, (_, i) => "adopt-st-" + i);
  const corpusHash = sha256(allIds.sort().join("\n"));
  const confCandidates = allIds.filter((id) => gate.assignSplit(id, 0, corpusHash) === "confirmation");
  if (confCandidates.length < desiredND) throw new Error("selftest: not enough confirmation ids for desired n_d");
  const winSet = new Set(confCandidates.slice(0, desiredND));
  /* Discordant candidate-win pairs for the chosen confirmation ids; every
   * other id (selection-split or confirmation padding) is a concordant
   * ok/ok pair so it never contributes to n_d. */
  const makePair = (id, isWin) => ({
    scenario_id: id,
    seed: 0,
    cand: { pass: true, cause_code: "ok" },
    base: { pass: !isWin, cause_code: "ok" },
  });
  const pairs = allIds.map((id) => makePair(id, winSet.has(id)));
  const bundle = {
    schema_version: SCHEMA_VERSION,
    corpus_hash: corpusHash,
    evaluator_version: "1.0.0",
    model_versions: { candidate: candidateId, baseline: "selftest-base" },
    pairs,
    slices: [],
  };
  bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
  return bundle;
}

function selftest() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-adopt-"));
  const tests = [];
  const errors = [];

  function check(name, condition, detail) {
    if (!condition) {
      errors.push("FAIL: " + name + (detail ? " — " + detail : ""));
      return false;
    }
    tests.push({ name, status: "pass" });
    return true;
  }

  try {
    const projectRoot = path.join(base, "chain");
    makeFixtureTree(projectRoot);

    /* --- Step 1: candidate -> gate1Static pass --- */
    const candidate = {
      id: "adopt-selftest-candidate",
      kind: "doc",
      fingerprint: sha256("adopt-selftest-candidate"),
      edits: [{
        file: "graphsmith.learned.md",
        anchor: "__GS_EVOLVE_SLOT__",
        op: "replace",
        payload: "\n## Rule: adopt selftest\n- illustrative\n__GS_EVOLVE_SLOT__\n",
        schema_ref: "lesson-event/v1",
        schema_version: SCHEMA_VERSION,
      }],
    };
    const g1 = gate.gate1Static(candidate, { aliasesResolved: true });
    check("chain-step1-gate1Static-passes", g1.pass === true, JSON.stringify(g1.findings));

    /* --- Step 2: gate2Behavioral on a synthetic promote-worthy bundle --- */
    const bundle = makeConfirmationBundle(6, "adopt-selftest-candidate");
    const g2 = gate.gate2Behavioral("adopt-selftest-candidate", { bundle, cycleSeed: 0 });
    if (g2 && typeof g2.then === "function") {
      throw new Error("selftest: gate2Behavioral unexpectedly returned a Promise for a bundle-based call");
    }
    check("chain-step2-gate2Behavioral-promotes", g2.pass === true && g2.primary && g2.primary.verdict === "promote",
      JSON.stringify(g2.primary));

    /* --- Step 3: evolve stages a REAL Gate-3 packet from harvested events --- */
    const run1Dir = path.join(projectRoot, "runs", "run-1");
    const run2Dir = path.join(projectRoot, "runs", "run-2");
    const chain1 = makeSyntheticRunLog(run1Dir, [
      { seq: 0, step: "start", type: "step_failure", code: "worker_error", delta_ms: 0, lossy: false },
      { seq: 1, step: "mid", type: "step_failure", code: "worker_error", delta_ms: 100, lossy: false },
      { seq: 2, step: "end", type: "step_failure", code: "worker_error", delta_ms: 200, lossy: false },
    ], "run-1");
    const chain2 = makeSyntheticRunLog(run2Dir, [
      { seq: 0, step: "start", type: "step_failure", code: "worker_error", delta_ms: 0, lossy: false },
      { seq: 1, step: "end", type: "step_failure", code: "worker_error", delta_ms: 100, lossy: false },
    ], "run-2");
    makeSyntheticAnchor(projectRoot, "run-1", chain1, "step_failure");
    makeSyntheticAnchor(projectRoot, "run-2", chain2, "step_failure");

    const cycleResult = evolve.cycle([run1Dir, run2Dir], { projectRoot });
    check("chain-step3-evolve-stages-proposal", cycleResult.proposals >= 1 && cycleResult.staged.length >= 1,
      "proposals=" + cycleResult.proposals);

    const stagedFingerprint = cycleResult.staged[0].fingerprint;

    /* --- Step 4: listPending shows it (read-only) --- */
    const pendingBefore = listPending(projectRoot);
    check("chain-step4-listPending-shows-staged-proposal",
      pendingBefore.some((p) => p.proposal_id === stagedFingerprint),
      "pending ids: " + pendingBefore.map((p) => p.proposal_id).join(","));
    const pendingRecord = pendingBefore.find((p) => p.proposal_id === stagedFingerprint);
    check("chain-step4-pending-carries-gate3-fields",
      pendingRecord && Array.isArray(pendingRecord.gate3.diff) && typeof pendingRecord.gate3.plainEnglish === "string" &&
        Array.isArray(pendingRecord.gate3.inverse) && typeof pendingRecord.gate3.reversible === "boolean",
      JSON.stringify(pendingRecord && pendingRecord.gate3));

    /* --- Step 5: adopt WITHOUT confirm is REFUSED --- */
    const activePath = path.join(projectRoot, ".graphsmith", "evolvable", "ACTIVE");
    const adoptionLogPath = path.join(projectRoot, ".graphsmith", "state", "adoption-log.jsonl");
    const beforeActiveRaw = fs.readFileSync(activePath, "utf8");
    const beforeAdoptionLog = fs.existsSync(adoptionLogPath) ? fs.readFileSync(adoptionLogPath, "utf8") : null;

    const refusedNoOpts = adopt(projectRoot, stagedFingerprint);
    const refusedFalse = adopt(projectRoot, stagedFingerprint, { confirm: false });
    check("chain-step5-adopt-without-confirm-refused",
      refusedNoOpts.adopted === false && refusedNoOpts.refused === true &&
        refusedFalse.adopted === false && refusedFalse.refused === true,
      JSON.stringify({ refusedNoOpts, refusedFalse }));

    const afterActiveRaw = fs.readFileSync(activePath, "utf8");
    const afterAdoptionLog = fs.existsSync(adoptionLogPath) ? fs.readFileSync(adoptionLogPath, "utf8") : null;
    check("chain-step5-unconfirmed-adopt-touched-nothing",
      beforeActiveRaw === afterActiveRaw && beforeAdoptionLog === afterAdoptionLog,
      "ACTIVE or adoption-log changed without confirmation");

    const pendingStillPending = listPending(projectRoot).some((p) => p.proposal_id === stagedFingerprint);
    check("chain-step5-proposal-still-pending-after-refusal", pendingStillPending === true);

    /* --- Step 6: adopt(...{confirm:true}) runs promote -> Gate-4 window ADMITTED --- */
    const adopted = adopt(projectRoot, stagedFingerprint, { confirm: true, windowN: 1 });
    check("chain-step6-adopt-confirmed-succeeds", adopted.adopted === true && adopted.state === "DONE",
      JSON.stringify(adopted));

    const journalRaw = fs.readFileSync(path.join(projectRoot, ".graphsmith", "state", "journal.jsonl"), "utf8");
    const journalRecords = journalRaw.split("\n").filter(Boolean).map((l) => JSON.parse(l))
      .filter((r) => r.txid === adopted.txid);
    check("chain-step6-transaction-passed-through-window-pending-admission",
      journalRecords.some((r) => r.record_type === "WINDOW_PENDING"),
      "journal records: " + journalRecords.map((r) => r.record_type).join(","));

    const activeAfterAdopt = JSON.parse(fs.readFileSync(activePath, "utf8"));
    check("chain-step6-ACTIVE-points-at-new-tree", activeAfterAdopt.txid === adopted.txid);

    const adoptionLogAfter = fs.readFileSync(adoptionLogPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const effectiveEntry = adoptionLogAfter[adoptionLogAfter.length - 1];
    check("chain-step6-adoption-log-has-effective-entry",
      effectiveEntry && effectiveEntry.status === "effective" && effectiveEntry.fingerprint === stagedFingerprint,
      JSON.stringify(effectiveEntry));

    const windowAfterAdopt = createStore(projectRoot).window.get();
    check("chain-step6-window-observing-after-transaction-admitted-it",
      windowAfterAdopt.state === "OBSERVING" && windowAfterAdopt.window &&
        windowAfterAdopt.window.window_id === adopted.txid && windowAfterAdopt.window.n === 1,
      JSON.stringify(windowAfterAdopt));

    /* --- Step 6b: proposal now consumed, no longer listed pending --- */
    const pendingAfterAdopt = listPending(projectRoot);
    check("chain-step6-proposal-no-longer-pending",
      !pendingAfterAdopt.some((p) => p.proposal_id === stagedFingerprint),
      "still pending: " + pendingAfterAdopt.map((p) => p.proposal_id).join(","));

    /* --- Step 6c: re-adopting the same (now consumed) proposal is refused --- */
    const reAdopt = adopt(projectRoot, stagedFingerprint, { confirm: true });
    check("chain-step6-re-adopt-already-adopted-refused",
      reAdopt.adopted === false && reAdopt.refused === true && reAdopt.reason === "PROPOSAL_NOT_PENDING",
      JSON.stringify(reAdopt));

    /* --- Step 7: observe --- */
    const runId = "canary-run-1";
    const treeId = activeAfterAdopt.tree;
    const observed = observe(projectRoot, runId, treeId);
    check("chain-step7-observe-claims-a-slot",
      observed && observed.registration && observed.registration.tree_id === treeId,
      JSON.stringify(observed));

    const windowAfterObserve = createStore(projectRoot).window.get();
    check("chain-step7-window-has-one-active-slot",
      windowAfterObserve.window && windowAfterObserve.window.active === 1 &&
        windowAfterObserve.window.admitted === 1,
      JSON.stringify(windowAfterObserve.window));

    /* Terminalize the observed run (reusing the already-tested state-store
     * deregister API — same registry/window pairing gate4Observe used to
     * claim the slot; no new gate logic). */
    createStore(projectRoot).runRegistry.deregister(runId, {});

    /* --- Step 8: close(pass) keeps the adoption --- */
    const windowId = adopted.txid;
    const closed = close(projectRoot, windowId, "pass");
    check("chain-step8-close-pass-closes-window", closed.state === "CLOSED_PASS", JSON.stringify(closed));

    const finalActive = JSON.parse(fs.readFileSync(activePath, "utf8"));
    check("chain-step8-ACTIVE-still-points-at-adopted-tree", finalActive.tree === activeAfterAdopt.tree);

    const finalWindow = createStore(projectRoot).window.get();
    check("chain-step8-window-terminal-closed-pass", finalWindow.state === "CLOSED_PASS");

    return {
      schema_version: SCHEMA_VERSION,
      status: errors.length === 0 ? "pass" : "fail",
      tests,
      errors,
      exitCode: errors.length === 0 ? 0 : 1,
    };
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

function parseFlags(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--yes" || a === "-y") flags.yes = true;
    else if (a === "--project-root") flags.projectRoot = argv[++i];
    else if (a === "--run") flags.run = argv[++i];
    else if (a === "--tree") flags.tree = argv[++i];
    else if (a === "--outcome") flags.outcome = argv[++i];
    else if (a === "--human") flags.human = argv[++i];
    else if (a === "--window-n") flags.windowN = parseInt(argv[++i], 10);
    else if (a.startsWith("--")) flags[a.slice(2)] = true;
    else positional.push(a);
  }
  return { flags, positional };
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + "\n");
}

function usage() {
  process.stderr.write("Usage: node scripts/adopt.js list [--project-root <dir>]\n");
  process.stderr.write("       node scripts/adopt.js adopt <proposalId> --yes [--project-root <dir>] [--window-n <n>] [--human <name>]\n");
  process.stderr.write("       node scripts/adopt.js observe --run <runId> --tree <treeId> [--project-root <dir>]\n");
  process.stderr.write("       node scripts/adopt.js close <windowId> [--outcome <outcome>] [--project-root <dir>]\n");
  process.stderr.write("       node scripts/adopt.js --selftest\n");
}

function cli() {
  const argv = process.argv.slice(2);

  if (argv.includes("--selftest")) {
    const report = selftest();
    printJson(report);
    process.exit(report.exitCode || 0);
  }

  const cmd = argv[0];
  const { flags, positional } = parseFlags(argv.slice(1));
  const projectRoot = flags.projectRoot || ".";

  if (cmd === "list") {
    try {
      printJson({ schema_version: SCHEMA_VERSION, pending: listPending(projectRoot) });
      process.exit(0);
    } catch (err) {
      printJson({ error: err.message, code: err.code || "ERROR" });
      process.exit(1);
    }
  } else if (cmd === "adopt") {
    const proposalId = positional[0];
    if (!proposalId) { usage(); process.exit(2); }
    try {
      const result = adopt(projectRoot, proposalId, {
        confirm: flags.yes === true,
        windowN: flags.windowN,
        humanName: flags.human,
      });
      printJson(result);
      process.exit(result.adopted ? 0 : 1);
    } catch (err) {
      printJson({ error: err.message, code: err.code || "ERROR", proposal_id: proposalId });
      process.exit(err.code === "HALT" ? 3 : 1);
    }
  } else if (cmd === "observe") {
    if (!flags.run || !flags.tree) { usage(); process.exit(2); }
    try {
      printJson(observe(projectRoot, flags.run, flags.tree));
      process.exit(0);
    } catch (err) {
      printJson({ error: err.message, code: err.code || "ERROR" });
      process.exit(1);
    }
  } else if (cmd === "close") {
    const windowId = positional[0];
    if (!windowId) { usage(); process.exit(2); }
    try {
      printJson(close(projectRoot, windowId, flags.outcome));
      process.exit(0);
    } catch (err) {
      printJson({ error: err.message, code: err.code || "ERROR" });
      process.exit(1);
    }
  } else {
    usage();
    process.exit(2);
  }
}

/* ---------------------------------------------------------------------------
 * Exports
 * ------------------------------------------------------------------------- */

module.exports = {
  SCHEMA_VERSION,
  listPending,
  adopt,
  observe,
  close,
  pendingProposalsPath,
  selftest,
};

if (require.main === module) {
  cli();
}
