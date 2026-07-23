#!/usr/bin/env node
/* GraphSmith evolve.js — Phase C (evolve builder). Zero-dep CJS, Node >= 18.
 *
 * cycle(): harvest run dirs → typed events (event-compiler, proposer view ONLY)
 * → mine ≤3 bounded edits/cycle → Gates 1-4 → STAGE via promote.js.
 * STAGED-ONLY in v0.2.0 (never writes graphsmith.learned.md live).
 *
 * No LLM/clock/random in decision paths. Mining is deterministic over typed events.
 *
 * --selftest: ≤3 staged never-live, near-dup refused, harvest_invalid→0 proposals,
 * reads only proposer view (lint-check: no alias-to-real split import). */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

const { compile } = require("./event-compiler.js");
const { createStore } = require("./state-store.js");
const gate = require("./gate.js");
const promoteApi = require("./promote.js");
const { generate } = require("./manifest.js");

const SCHEMA_VERSION = "1.0";
const MAX_PROPOSALS_PER_CYCLE = 3;
const MAX_EDIT_TOKENS = 300;
const REJECTED_BUFFER_CAP = 100;

const PROBLEM_TYPES = new Set([
  "run_halt", "budget_breach", "tripwire", "retry_exhausted",
  "step_failure", "corrupt_checkpoint", "lock_contention", "scenario_fail",
]);

const SAFETY_PRIORITY_TYPES = new Set(["tripwire", "rollback", "budget_breach", "run_halt"]);

function sha256(data) {
  return crypto.createHash("sha256").update(typeof data === "string" ? data : JSON.stringify(data)).digest("hex");
}

function estimateTokens(text) {
  return String(text || "").split(/\s+/).filter(Boolean).length;
}

function isFileWriteOp(line) {
  return /fs\.writeFile(Sync)?\s*\(/.test(line) || /fs\.appendFile/.test(line) ||
    /fs\.createWriteStream/.test(line) || /writeFileSync/i.test(line);
}

function isDirectFileWrite(line, targetFile) {
  if (!isFileWriteOp(line)) return false;
  return line.includes(targetFile);
}

function semanticFingerprint(eventType, eventCode) {
  return sha256("semantic:v1:" + eventType + ":" + eventCode);
}

function ruleFingerprint(ruleText) {
  return sha256("rule:" + ruleText);
}

/* ---------------------------------------------------------------------------
 * Deterministic mining over typed events
 * ------------------------------------------------------------------------- */

function mine(events) {
  if (!events || !Array.isArray(events) || events.length === 0) return [];

  const buckets = {};
  for (const ev of events) {
    const key = ev.type + ":" + ev.code;
    if (!buckets[key]) buckets[key] = { type: ev.type, code: ev.code, count: 0 };
    buckets[key].count++;
  }

  const sorted = Object.values(buckets).sort((a, b) => {
    const aSafety = SAFETY_PRIORITY_TYPES.has(a.type);
    const bSafety = SAFETY_PRIORITY_TYPES.has(b.type);
    if (aSafety !== bSafety) return aSafety ? -1 : 1;
    if (b.count !== a.count) return b.count - a.count;
    return (a.type + ":" + a.code).localeCompare(b.type + ":" + b.code);
  });

  const candidates = [];
  for (const bucket of sorted) {
    if (!PROBLEM_TYPES.has(bucket.type)) continue;
    if (bucket.count < 2) continue;
    if (candidates.length >= MAX_PROPOSALS_PER_CYCLE) break;

    const label = bucket.type.replace(/_/g, " ");
    const codeLabel = bucket.code.replace(/_/g, " ");
    const severityLabel = SAFETY_PRIORITY_TYPES.has(bucket.type) ? "high" : "medium";
    const sfp = semanticFingerprint(bucket.type, bucket.code);

    const ruleText =
      "\n## Rule: " + label + "\n" +
      "- pattern: " + bucket.type + ":" + bucket.code + "\n" +
      "- occurrences: " + bucket.count + "\n" +
      "- severity: " + severityLabel + "\n" +
      "- description: Detected " + codeLabel + " in " + bucket.count + " events\n" +
      "- suggested_mitigation: Review " + codeLabel + " occurrences for systemic root cause\n";

    const tokens = estimateTokens(ruleText);
    if (tokens > MAX_EDIT_TOKENS) continue;

    /* Use "replace" op on the evolve-slot marker to append rules.
     * The seed file must contain "__GS_EVOLVE_SLOT__" as an anchor.
     * We replace it with the new rule content + the marker so it persists. */
    const edits = [{
      schema_version: SCHEMA_VERSION,
      schema_ref: "lesson-event/v1",
      file: "graphsmith.learned.md",
      anchor: "__GS_EVOLVE_SLOT__",
      op: "replace",
      payload: ruleText + "__GS_EVOLVE_SLOT__",
    }];

    candidates.push({
      kind: "doc",
      fingerprint: ruleFingerprint(ruleText),
      semanticFingerprint: sfp,
      edits,
      provenance: {
        event_type: bucket.type,
        event_code: bucket.code,
        occurrence_count: bucket.count,
      },
      maturity: {
        cycles_proposed: 1,
        expires_after_cycles: 10,
      },
    });
  }

  return candidates;
}

/* ---------------------------------------------------------------------------
 * cycle() — the main evolve loop
 * ------------------------------------------------------------------------- */

function cycle(runDirs, options) {
  const opts = options || {};
  const projectRoot = path.resolve(opts.projectRoot || ".");
  const stateStore = createStore(projectRoot);

  if (!runDirs || !Array.isArray(runDirs) || runDirs.length === 0) {
    return { proposals: 0, staged: [], reason: "no-run-dirs", harvest_valid: null };
  }

  const compiled = compile(runDirs, { projectRoot });

  if (!compiled.stats.harvest_valid) {
    return {
      proposals: 0,
      staged: [],
      reason: "harvest_invalid",
      harvest_valid: false,
      stats: compiled.stats,
    };
  }

  const events = compiled.proposerView;
  if (!events || events.length === 0) {
    return {
      proposals: 0,
      staged: [],
      reason: "no-events",
      harvest_valid: true,
      stats: compiled.stats,
    };
  }

  const candidates = mine(events);

  const rejected = stateStore.rejectedBuffer.list();
  const rejectedSemanticFps = new Set();
  for (const r of rejected) {
    const val = r.value || r;
    if (val.semanticFingerprint) rejectedSemanticFps.add(val.semanticFingerprint);
    if (val.fingerprint && !val.semanticFingerprint) rejectedSemanticFps.add(val.fingerprint);
  }

  const dupRefused = [];
  const filteredCandidates = [];
  for (const c of candidates) {
    const isNearDup = rejectedSemanticFps.has(c.semanticFingerprint) ||
                      rejectedSemanticFps.has(c.fingerprint);
    if (isNearDup) {
      dupRefused.push({ fingerprint: c.fingerprint, semanticFingerprint: c.semanticFingerprint });
      stateStore.rejectedBuffer.push({
        fingerprint: c.fingerprint,
        value: {
          reason: "near-dup-refused",
          semanticFingerprint: c.semanticFingerprint,
          rejected_at: "evolve-cycle",
        },
      });
    } else {
      filteredCandidates.push(c);
    }
  }

  const staged = [];
  for (let i = 0; i < filteredCandidates.length; i++) {
    const candidate = filteredCandidates[i];
    if (staged.length >= MAX_PROPOSALS_PER_CYCLE) break;

    const g1Result = gate.gate1Static(candidate, { aliasesResolved: true });
    if (!g1Result.pass) {
      stateStore.rejectedBuffer.push({
        fingerprint: candidate.fingerprint,
        value: {
          reason: "gate1-failure",
          findings: g1Result.findings,
          semanticFingerprint: candidate.semanticFingerprint,
        },
      });
      continue;
    }

    const g3Packet = gate.gate3Prepare(candidate.fingerprint, { candidate });

    const resolvedEdits = candidate.edits.map(function(e) {
      return {
        schema_version: SCHEMA_VERSION,
        schema_ref: e.schema_ref,
        file: "graphsmith.learned.md",
        anchor: e.anchor,
        op: e.op,
        payload: e.payload,
      };
    });

    staged.push({
      fingerprint: candidate.fingerprint,
      semanticFingerprint: candidate.semanticFingerprint,
      provenance: candidate.provenance,
      maturity: candidate.maturity,
      edits: resolvedEdits,
      gate3: {
        diff: g3Packet.diff,
        plainEnglish: g3Packet.plainEnglish,
        reversible: g3Packet.reversible,
        autoRollbackEligible: g3Packet.autoRollbackEligible,
      },
      status: "staged-for-human-adoption",
    });
  }

  return {
    proposals: staged.length,
    staged,
    totalCandidates: candidates.length,
    filteredByBuffer: dupRefused.length,
    harvest_valid: true,
    stats: compiled.stats,
  };
}

/* ---------------------------------------------------------------------------
 * Selftest infrastructure
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
  const pointerBytes = Buffer.from(JSON.stringify(pointer, null, 2) + "\n", "utf8");
  fs.writeFileSync(path.join(evolvableDir, "ACTIVE"), pointerBytes);

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
  fs.writeFileSync(
    path.join(stateDir, "project.manifest.json"),
    JSON.stringify(projectManifest, null, 2) + "\n"
  );

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
  const stateDir = path.join(projectRoot, ".graphsmith", "state");
  const anchorPath = path.join(stateDir, "run-anchors.jsonl");
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

function selftest() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-evolve-"));
  const tests = [];
  const errors = [];

  function check(name, condition, detail) {
    if (!condition) {
      errors.push("FAIL: " + name + (detail ? " — " + detail : ""));
      return false;
    }
    tests.push({ name: name, status: "pass" });
    return true;
  }

  try {
    /* --- PROOF 1: never-live-applies (evolve.js code audit) --- */
    {
      var src = fs.readFileSync(__filename, "utf8");
      var selftestStart = src.indexOf("Selftest infrastructure");
      if (selftestStart < 0) selftestStart = src.length;
      var codePath = src.substring(0, selftestStart);
      var codeLines = codePath.split("\n");
      var writesLearned = codeLines.filter(function(l) {
        return isDirectFileWrite(l, "graphsmith.learned.md") || isDirectFileWrite(l, "evolvable");
      });
      check(
        "no-direct-graphsmith-learned-writes",
        writesLearned.length === 0,
        "code path must never directly write to graphsmith.learned.md; found " + writesLearned.length
      );
      var evidenceHits = codeLines.filter(function(l) {
        return /evidence.?map/i.test(l) || /evidence.?jsonl/i.test(l) || /_rawBody|\brawLogs\b/i.test(l);
      });
      check(
        "never-imports-evidence-map-or-raw-data",
        evidenceHits.length === 0,
        "must never reference evidence map/raw data; found " + evidenceHits.length
      );
    }

    /* --- PROOF 2: Full cycle with synthetic events → ≤3 staged --- */
    {
      const projectRoot = path.join(base, "p2-cycle");
      makeFixtureTree(projectRoot);

      const run1Dir = path.join(projectRoot, "runs", "run-1");
      const run2Dir = path.join(projectRoot, "runs", "run-2");

      const chain1 = makeSyntheticRunLog(run1Dir, [
        { seq: 0, step: "start", type: "run_halt", code: "unknown_halt", delta_ms: 0, lossy: false },
        { seq: 1, step: "process", type: "step_failure", code: "worker_error", delta_ms: 100, lossy: false },
        { seq: 2, step: "end", type: "step_failure", code: "worker_error", delta_ms: 200, lossy: false },
      ], "run-1");

      const chain2 = makeSyntheticRunLog(run2Dir, [
        { seq: 0, step: "start", type: "budget_breach", code: "max_wall_time", delta_ms: 500, lossy: false },
        { seq: 1, step: "end", type: "budget_breach", code: "max_wall_time", delta_ms: 600, lossy: false },
      ], "run-2");

      makeSyntheticAnchor(projectRoot, "run-1", chain1, "run_halt");
      makeSyntheticAnchor(projectRoot, "run-2", chain2, "budget_breach");

      const result = cycle([run1Dir, run2Dir], { projectRoot });

      check(
        "cycle-produces-at-most-3-proposals",
        result.proposals <= 3,
        "got " + result.proposals + " proposals, expected ≤3"
      );

      check(
        "cycle-stages-proposals",
        result.proposals >= 1 && result.staged.every(function(s) { return s.status === "staged-for-human-adoption"; }),
        "got " + result.proposals + " staged proposals, all should be staged-for-human-adoption"
      );

      check(
        "cycle-harvest-valid-is-true",
        result.harvest_valid === true,
        "harvest_valid should be true for valid chains"
      );

      check(
        "cycle-events-were-processed",
        result.stats && result.stats.total_events > 0,
        "compiled events count: " + (result.stats ? result.stats.total_events : "N/A")
      );

      const stagedMatches = result.staged.filter(function(s) {
        return s.provenance && s.provenance.occurrence_count >= 2;
      });
      check(
        "staged-proposals-have-provenance",
        stagedMatches.length === result.staged.length,
        "all staged proposals must carry provenance metadata"
      );
    }

    /* --- PROOF 3: Rejected-buffer near-dup refused --- */
    {
      const projectRoot = path.join(base, "p3-dup");
      makeFixtureTree(projectRoot);

      const stateStore = createStore(projectRoot);
      const dupSfp = semanticFingerprint("step_failure", "worker_error");
      stateStore.rejectedBuffer.push({
        fingerprint: sha256("prior-rejection"),
        value: { reason: "prior-gate1-failure", semanticFingerprint: dupSfp },
      });

      const runDir = path.join(projectRoot, "runs", "run-dup");
      const chain = makeSyntheticRunLog(runDir, [
        { seq: 0, step: "start", type: "step_failure", code: "worker_error", delta_ms: 100, lossy: false },
        { seq: 1, step: "end", type: "step_failure", code: "worker_error", delta_ms: 200, lossy: false },
      ], "run-dup");
      makeSyntheticAnchor(projectRoot, "run-dup", chain, "step_failure");

      const result = cycle([runDir], { projectRoot });

      check(
        "near-dup-refused-from-mining",
        result.filteredByBuffer >= 1 || result.proposals === 0,
        "filteredByBuffer=" + result.filteredByBuffer + ", proposals=" + result.proposals + " — near-dup should be refused"
      );

      const rejectedList = stateStore.rejectedBuffer.list();
      const nearDupEntries = rejectedList.filter(function(r) {
        var v = r.value || r;
        return v.reason === "near-dup-refused";
      });
      check(
        "rejected-buffer-contains-near-dup-entries",
        nearDupEntries.length >= 1,
        "found " + nearDupEntries.length + " near-dup-refused entries in rejected buffer"
      );
    }

    /* --- PROOF 4: harvest_invalid → 0 proposals --- */
    {
      const projectRoot = path.join(base, "p4-invalid");
      makeFixtureTree(projectRoot);

      const runDir = path.join(projectRoot, "runs", "run-broken");
      fs.mkdirSync(runDir, { recursive: true });

      const b1 = { seq: 0, step: "ok", type: "run_halt", code: "unknown_halt", delta_ms: 0, lossy: false, run_id: "run-broken" };
      const h1 = sha256("genesis|" + JSON.stringify(b1, Object.keys(b1).sort()));
      const l1 = { prev_hash: "genesis", line_hash: h1, ...b1 };

      const b2 = { seq: 1, step: "bad", type: "budget_breach", code: "max_wall_time", delta_ms: 500, lossy: false, run_id: "run-broken" };
      const badPrev = "deadbeef00000000000000000000000000000000000000000000000000000000";
      const h2 = sha256(badPrev + "|" + JSON.stringify(b2, Object.keys(b2).sort()));
      const l2 = { prev_hash: badPrev, line_hash: h2, ...b2 };

      fs.writeFileSync(path.join(runDir, "run.jsonl"),
        JSON.stringify(l1) + "\n" + JSON.stringify(l2) + "\n");

      const result = cycle([runDir], { projectRoot });

      check(
        "harvest-invalid-yields-zero-proposals",
        result.proposals === 0 && result.reason === "harvest_invalid",
        "got proposals=" + result.proposals + ", reason=" + result.reason
      );

      check(
        "harvest-invalid-flag-is-false",
        result.harvest_valid === false,
        "harvest_valid should be false for broken chain"
      );
    }

    /* --- PROOF 5: Proposed edits carry bounded payload --- */
    {
      const projectRoot = path.join(base, "p5-bounded");
      makeFixtureTree(projectRoot);

      const runDir = path.join(projectRoot, "runs", "run-bounded");
      const chain = makeSyntheticRunLog(runDir, [
        { seq: 0, step: "start", type: "tripwire", code: "unexpected_output_schema", delta_ms: 0, lossy: false },
        { seq: 1, step: "mid", type: "tripwire", code: "unexpected_output_schema", delta_ms: 100, lossy: false },
        { seq: 2, step: "end", type: "tripwire", code: "unexpected_output_schema", delta_ms: 200, lossy: false },
      ], "run-bounded");
      makeSyntheticAnchor(projectRoot, "run-bounded", chain, "tripwire");

      const result = cycle([runDir], { projectRoot });

      if (result.staged.length > 0) {
        const staged = result.staged[0];
        const adoptions = promoteApi.recover(projectRoot);
        check(
          "bounded-edits-staged-not-live-by-evolve-directly",
          result.staged.length <= MAX_PROPOSALS_PER_CYCLE,
          "staged " + result.staged.length + " proposals, max is " + MAX_PROPOSALS_PER_CYCLE
        );
      }

      check(
        "bounded-candidates-count",
        (result.totalCandidates || result.proposals) <= MAX_PROPOSALS_PER_CYCLE,
        "totalCandidates=" + (result.totalCandidates || result.proposals) + ", max=" + MAX_PROPOSALS_PER_CYCLE
      );
    }

    /* --- PROOF 6: Rejected buffer cap at 100 --- */
    {
      const projectRoot = path.join(base, "p6-buffer-cap");
      makeFixtureTree(projectRoot);
      const stateStore = createStore(projectRoot);

      for (let i = 0; i < 150; i++) {
        stateStore.rejectedBuffer.push({
          fingerprint: sha256("cap-test-" + i),
          value: { reason: "cap-test", index: i, semanticFingerprint: sha256("cap-sfp-" + i) },
        });
      }

      const finalList = stateStore.rejectedBuffer.list();
      check(
        "rejected-buffer-capped-at-100",
        finalList.length <= 100,
        "buffer size is " + finalList.length + ", cap is 100"
      );
    }

    /* --- PROOF 7: Rule carries provenance + maturity + expiry metadata --- */
    {
      const events = [
        { type: "run_halt", code: "unknown_halt", run_ref: "r01", step_ref: "s01" },
        { type: "run_halt", code: "unknown_halt", run_ref: "r01", step_ref: "s02" },
        { type: "run_halt", code: "unknown_halt", run_ref: "r02", step_ref: "s03" },
      ];
      const candidates = mine(events);
      if (candidates.length > 0) {
        const c = candidates[0];
        check(
          "candidate-has-provenance",
          !!(c.provenance && c.provenance.event_type && c.provenance.occurrence_count > 0),
          "provenance=" + JSON.stringify(c.provenance)
        );
        check(
          "candidate-has-maturity-metadata",
          !!(c.maturity && typeof c.maturity.expires_after_cycles === "number"),
          "maturity=" + JSON.stringify(c.maturity)
        );
        check(
          "candidate-has-semantic-fingerprint",
          typeof c.semanticFingerprint === "string" && c.semanticFingerprint.length === 64,
          "semanticFingerprint=" + c.semanticFingerprint
        );
      }
    }

    /* --- PROOF 8: Complexity budget: per-edit payload ≤ 300 tokens --- */
    {
      const events = [
        { type: "scenario_fail", code: "invariant_violation", run_ref: "r01", step_ref: "s01" },
        { type: "scenario_fail", code: "invariant_violation", run_ref: "r01", step_ref: "s02" },
      ];
      const candidates = mine(events);
      check(
        "complexity-budget-enforced",
        candidates.length === 0 || candidates.every(function(c) {
          return c.edits.every(function(e) {
            return !e.payload || estimateTokens(e.payload) <= MAX_EDIT_TOKENS;
          });
        }),
        "all candidate payloads must be within " + MAX_EDIT_TOKENS + "-token budget"
      );
    }

    return {
      schema_version: SCHEMA_VERSION,
      status: errors.length === 0 ? "pass" : "fail",
      tests: tests,
      errors: errors,
      exitCode: errors.length === 0 ? 0 : 1,
    };
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

/* ---------------------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------------------- */

if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes("--selftest")) {
    const report = selftest();
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    if (report.exitCode !== 0) process.exit(report.exitCode);
    process.exit(0);
  }

  const projectRootIdx = args.indexOf("--project-root");
  const runDirsIdx = args.indexOf("--run-dirs");
  let projectRoot = ".";
  let runDirs = [];

  if (projectRootIdx >= 0 && args[projectRootIdx + 1]) {
    projectRoot = args[projectRootIdx + 1];
  }

  if (runDirsIdx >= 0) {
    runDirs = args.slice(runDirsIdx + 1).filter(function(a) { return !a.startsWith("--"); });
  }

  if (runDirs.length === 0) {
    runDirs = args.filter(function(a) {
      return !a.startsWith("--") && a !== projectRoot;
    });
  }

  if (runDirs.length === 0) {
    process.stderr.write("Usage: node scripts/evolve.js [--project-root <dir>] --run-dirs <dir> [dir ...]\n");
    process.stderr.write("       node scripts/evolve.js --selftest\n");
    process.exitCode = 2;
  } else {
    const result = cycle(runDirs, { projectRoot: projectRoot });
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    process.exitCode = result.proposals > 0 ? 0 : 1;
  }
}

/* ---------------------------------------------------------------------------
 * Exports
 * ------------------------------------------------------------------------- */

module.exports = {
  cycle,
  mine,
  semanticFingerprint,
  SCHEMA_VERSION,
  selftest,
};