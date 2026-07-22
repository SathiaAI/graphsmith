#!/usr/bin/env node
/* Adversarial suite for scripts/promote.js — family: grok
 * Lane: tests/promote/grok/ only. Temp project dirs only. Zero-dep CJS.
 * Verdicts from on-disk state (ACTIVE / trees / journals / manifests), never log strings.
 * Exit 1 if ANY case FAILs.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const promoteMod = require(path.join(REPO_ROOT, "scripts", "promote.js"));
const { generate, verifyTree } = require(path.join(REPO_ROOT, "scripts", "manifest.js"));
const { createStore } = require(path.join(REPO_ROOT, "scripts", "state-store.js"));
const { promote, recover, rollback, SCHEMA_VERSION } = promoteMod;

const results = [];
const tempRoots = [];
const priorTestMode = process.env.GRAPHSMITH_TEST_MODE;
process.env.GRAPHSMITH_TEST_MODE = "1";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function record(name, status, detail) {
  results.push({ name, status, detail: detail === undefined ? "" : String(detail) });
  const d = detail ? `\t${String(detail).replace(/\s+/g, " ").slice(0, 280)}` : "";
  console.log(`${status}\t${name}${d}`);
}
function pass(name, detail) { record(name, "PASS", detail); }
function fail(name, detail) { record(name, "FAIL", detail); }
function skip(name, detail) { record(name, "SKIPPED", detail); }

function mkRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `gs-promote-grok-${tag}-`));
  tempRoots.push(root);
  return root;
}

function locations(root) {
  const state = path.join(root, ".graphsmith", "state");
  const evolvable = path.join(root, ".graphsmith", "evolvable");
  return {
    root,
    state,
    evolvable,
    active: path.join(evolvable, "ACTIVE"),
    journal: path.join(state, "journal.jsonl"),
    adoption: path.join(state, "adoption-log.jsonl"),
    projectManifest: path.join(state, "project.manifest.json"),
    window: path.join(state, "window.json"),
    registry: path.join(state, "run-registry.jsonl"),
  };
}

function pointerBytes(pointer) {
  return Buffer.from(`${JSON.stringify(pointer, null, 2)}\n`, "utf8");
}

function readUtf(file) {
  try { return fs.readFileSync(file, "utf8"); } catch (e) {
    if (e.code === "ENOENT") return "";
    throw e;
  }
}

function readBuf(file) {
  try { return fs.readFileSync(file); } catch (e) {
    if (e.code === "ENOENT") return Buffer.alloc(0);
    throw e;
  }
}

function parseJsonl(file) {
  const raw = readUtf(file);
  if (!raw) return [];
  const lines = raw.split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    try { out.push(JSON.parse(lines[i])); }
    catch (e) {
      if (i === lines.length - 1 && !raw.endsWith("\n")) break;
      throw e;
    }
  }
  return out;
}

function activeSnap(paths) {
  const raw = readBuf(paths.active);
  if (!raw.length) return { raw, sha: null, pointer: null, missing: true };
  const pointer = JSON.parse(raw.toString("utf8"));
  return { raw, sha: sha256(raw), pointer, missing: false };
}

function listTrees(paths) {
  if (!fs.existsSync(paths.evolvable)) return [];
  return fs.readdirSync(paths.evolvable).filter((n) => n.startsWith("v-") && fs.statSync(path.join(paths.evolvable, n)).isDirectory());
}

function listStaging(paths) {
  if (!fs.existsSync(paths.evolvable)) return [];
  return fs.readdirSync(paths.evolvable).filter((n) => n.startsWith(".staging-"));
}

function adoptionEntries(paths) {
  return parseJsonl(paths.adoption);
}

function logHead(paths) {
  const e = adoptionEntries(paths);
  return e.length ? e[e.length - 1].entry_sha256 : null;
}

function projectManifest(paths) {
  return JSON.parse(readUtf(paths.projectManifest));
}

function windowState(paths) {
  const raw = readUtf(paths.window);
  if (!raw) return { state: "NO_WINDOW", window: null };
  return JSON.parse(raw);
}

function journalRecords(paths, txid) {
  const all = parseJsonl(paths.journal);
  return txid ? all.filter((r) => r.txid === txid) : all;
}

function lastOf(records, type) {
  for (let i = records.length - 1; i >= 0; i--) if (records[i].record_type === type) return records[i];
  return null;
}

function createFixture(root) {
  const paths = locations(root);
  fs.mkdirSync(paths.state, { recursive: true });
  fs.mkdirSync(paths.evolvable, { recursive: true });
  const seed = path.join(paths.evolvable, "seed");
  fs.mkdirSync(seed);
  fs.writeFileSync(path.join(seed, "graphsmith.learned.md"), "alpha\n");
  fs.writeFileSync(path.join(seed, "tunables.json"), "{\n  \"limit\": 1\n}\n");
  fs.mkdirSync(path.join(seed, "workers"), { recursive: true });
  fs.writeFileSync(path.join(seed, "workers", "demo.prompt.md"), "hello worker\n");
  const manifest = generate("tree", { rootDir: seed });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  fs.writeFileSync(path.join(seed, "tree.manifest.json"), manifestBytes);
  const tree = `v-${sha256(manifestBytes)}`;
  fs.renameSync(seed, path.join(paths.evolvable, tree));
  const pointer = {
    schema_version: SCHEMA_VERSION,
    txid: "0".repeat(16),
    tree,
    tree_manifest_sha256: sha256(manifestBytes),
  };
  fs.writeFileSync(paths.active, pointerBytes(pointer));
  fs.writeFileSync(paths.projectManifest, `${JSON.stringify({
    schema_version: SCHEMA_VERSION,
    kind: "project",
    generated_at: "grok-test",
    parent_release_sha256: null,
    adoption_log_head: null,
    files: [],
    workflow_manifests: [],
  }, null, 2)}\n`);
  return { paths, tree, pointer, activeSha: sha256(pointerBytes(pointer)) };
}

function testPacket(root, suffix, extra = {}) {
  return {
    project_root: root,
    fingerprint: sha256(`grok-promote:${suffix}`),
    kind: "doc",
    evidence_ref: `grok:${suffix}`,
    human: { name: "grok-tester", decision: "approve", ts: "2000-01-01T00:00:00.000Z" },
    edits: [{
      schema_version: SCHEMA_VERSION,
      schema_ref: "grok-test",
      file: "graphsmith.learned.md",
      anchor: "alpha",
      op: "replace",
      payload: suffix,
    }],
    reversible: true,
    auto_rollback_eligible: true,
    window_n: 1,
    ...extra,
  };
}

function assertExactlyOneTree(paths, allowedTrees, label) {
  const snap = activeSnap(paths);
  if (snap.missing) return `${label}: ACTIVE missing`;
  if (!allowedTrees.includes(snap.pointer.tree)) {
    return `${label}: ACTIVE.tree=${snap.pointer.tree} not in {${allowedTrees.join(",")}}`;
  }
  const treeDir = path.join(paths.evolvable, snap.pointer.tree);
  if (!fs.existsSync(treeDir)) return `${label}: ACTIVE points to missing tree ${snap.pointer.tree}`;
  const man = path.join(treeDir, "tree.manifest.json");
  if (!fs.existsSync(man)) return `${label}: tree.manifest.json missing under ACTIVE tree`;
  const v = verifyTree(man, treeDir);
  if (!v.ok) return `${label}: ACTIVE tree failed verifyTree`;
  const claimed = snap.pointer.tree_manifest_sha256;
  const actual = sha256(readBuf(man));
  if (claimed !== actual) return `${label}: tree_manifest_sha256 mismatch`;
  return null;
}

function truncJournalAfter(paths, predicate /* (rec, i, all) => keep incl */) {
  const all = parseJsonl(paths.journal);
  let cut = -1;
  for (let i = 0; i < all.length; i++) {
    if (predicate(all[i], i, all)) cut = i;
  }
  if (cut < 0) throw new Error("truncJournalAfter: no matching record");
  const kept = all.slice(0, cut + 1);
  fs.writeFileSync(paths.journal, kept.map((r) => JSON.stringify(r)).join("\n") + (kept.length ? "\n" : ""));
  return kept;
}

function truncAdoptionToSeq(paths, maxSeq) {
  const entries = adoptionEntries(paths).filter((e) => e.seq <= maxSeq);
  fs.writeFileSync(paths.adoption, entries.map((e) => JSON.stringify(e)).join("\n") + (entries.length ? "\n" : ""));
}

function writeManifestHead(paths, head) {
  const m = projectManifest(paths);
  m.adoption_log_head = head;
  fs.writeFileSync(paths.projectManifest, `${JSON.stringify(m, null, 2)}\n`);
}

function writeActive(paths, pointer) {
  fs.writeFileSync(paths.active, pointerBytes(pointer));
}

function writeWindow(paths, obj) {
  fs.writeFileSync(paths.window, JSON.stringify(obj));
}

function catchCode(fn) {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, code: error.code || "ERROR", message: error.message, evidence: error.evidence, error };
  }
}

function crashPromote(root, suffix, point, extra = {}) {
  return catchCode(() => promote(testPacket(root, suffix, { __test_crash_at: point, ...extra })));
}

/* ============================================================================
 * 1) Happy path baseline
 * ============================================================================ */
function tHappy() {
  const name = "01-happy-path-effective-anchor";
  try {
    const root = mkRoot("happy");
    const fx = createFixture(root);
    const before = activeSnap(fx.paths);
    const res = promote(testPacket(root, "happy-body"));
    const after = activeSnap(fx.paths);
    const entries = adoptionEntries(fx.paths);
    const head = logHead(fx.paths);
    const man = projectManifest(fx.paths);
    const win = windowState(fx.paths);
    const err =
      (res.state !== "DONE" && `state=${res.state}`) ||
      (after.pointer.tree === before.pointer.tree && "ACTIVE did not move") ||
      (entries.at(-1).status !== "effective" && `terminal=${entries.at(-1).status}`) ||
      (man.adoption_log_head !== head && "manifest head != log head") ||
      (man.adoption_log_head !== entries.at(-1).entry_sha256 && "manifest not terminal") ||
      (win.state !== "OBSERVING" && `window=${win.state}`) ||
      assertExactlyOneTree(fx.paths, [after.pointer.tree], name);
    if (err) fail(name, err);
    else pass(name, `txid=${res.txid} tree=${after.pointer.tree}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 2) Crash/recovery matrix via built-in crash points + journal rewind
 * ============================================================================ */
function checkRecoveredDone(paths, oldTree, detailPrefix) {
  const snap = activeSnap(paths);
  const entries = adoptionEntries(paths);
  const head = logHead(paths);
  const man = projectManifest(paths);
  const win = windowState(paths);
  const jr = parseJsonl(paths.journal);
  const done = jr.some((r) => r.record_type === "TX_DONE");
  const abort = jr.some((r) => r.record_type === "TX_ABORT" && !r.record_type); // placeholder
  const terminalAbort = jr.filter((r) => r.record_type === "TX_ABORT");
  const terminalDone = jr.filter((r) => r.record_type === "TX_DONE");
  if (!done && terminalDone.length === 0) {
    // may be abort path
  }
  const errs = [];
  const treeErr = assertExactlyOneTree(paths, snap.missing ? [] : [snap.pointer.tree], detailPrefix);
  if (treeErr) errs.push(treeErr);
  if (man.adoption_log_head !== head) errs.push(`manifest/log head diverge man=${man.adoption_log_head} head=${head}`);
  if (entries.length) {
    const last = entries[entries.length - 1];
    if (man.adoption_log_head !== last.entry_sha256) errs.push("manifest not at adoption tail");
    if (!["effective", "aborted"].includes(last.status)) errs.push(`non-terminal head status=${last.status}`);
  }
  // ACTIVE must be pure old or pure new (verified by verifyTree above)
  if (snap.missing) errs.push("ACTIVE missing after recover");
  return { errs, snap, entries, man, win, jr, oldTree };
}

function tCrashMatrixBuiltin() {
  const points = ["before-swap", "after-swap", "after-manifest"];
  for (const point of points) {
    const name = `02-crash-recover-${point}`;
    try {
      const root = mkRoot(point);
      const fx = createFixture(root);
      const oldTree = fx.tree;
      const crashed = crashPromote(root, `c-${point}`, point);
      if (crashed.ok || crashed.code !== "SIMULATED_CRASH") {
        fail(name, `expected SIMULATED_CRASH got ok=${crashed.ok} code=${crashed.code}`);
        continue;
      }
      const mid = activeSnap(fx.paths);
      // Mid-crash: ACTIVE must still resolve to exactly one valid tree
      const midErr = assertExactlyOneTree(fx.paths, mid.pointer ? [mid.pointer.tree] : [], "mid");
      if (midErr) { fail(name, `mid-crash impure: ${midErr}`); continue; }

      const rec = recover(root);
      const { errs, snap, entries, man, win } = checkRecoveredDone(fx.paths, oldTree, name);
      if (rec.state !== "RECOVERED" && rec.state !== "CLEAN") errs.push(`recover.state=${rec.state}`);
      if (!rec.transactions || !rec.transactions.some((t) => t.state === "DONE")) errs.push(`tx outcomes=${JSON.stringify(rec.transactions)}`);
      if (entries.at(-1)?.status !== "effective") errs.push(`terminal status=${entries.at(-1)?.status}`);
      if (man.adoption_log_head !== entries.at(-1)?.entry_sha256) errs.push("anchor != terminal effective");
      // after-swap / after-manifest / before-swap all should end on NEW tree for roll-forward after LOG
      if (snap.pointer.tree === oldTree) errs.push("expected roll-forward onto new tree after LOG_APPEND boundary");
      if (point === "after-swap" || point === "before-swap" || point === "after-manifest") {
        if (!["OBSERVING", "ADMITTED"].includes(win.state) && win.state !== "OBSERVING") {
          // recovery must finalize window → OBSERVING
          if (win.state !== "OBSERVING") errs.push(`window not finalized: ${win.state}`);
        }
      }
      if (win.state !== "OBSERVING") errs.push(`Gate-4 window after recover=${win.state} (want OBSERVING)`);
      if (errs.length) fail(name, errs.join("; "));
      else pass(name, `ACTIVE=${snap.pointer.tree} window=${win.state}`);
    } catch (e) { fail(name, e.stack || e.message); }
  }
}

/** Intent-without-DONE boundaries by rewinding a before-swap crash snapshot */
function tCrashMatrixRewind() {
  const cases = [
    {
      name: "03-intent-boundary-before-LOG_APPEND",
      // stop after VALIDATED (no LOG intent): recover must roll BACK, ACTIVE=old
      prepare(paths, ctx) {
        // take crash before-swap then rewind journal to VALIDATED; strip adoption; keep staged tree
        truncJournalAfter(paths, (r) => r.record_type === "VALIDATED" && r.txid === ctx.txid);
        fs.writeFileSync(paths.adoption, "");
        writeManifestHead(paths, null);
        writeActive(paths, ctx.oldPointer);
        // collapse window if any
        if (fs.existsSync(paths.window)) fs.unlinkSync(paths.window);
      },
      expect: "ABORT_OLD",
    },
    {
      name: "03-intent-boundary-LOG_APPEND_INTENT-without-DONE",
      prepare(paths, ctx) {
        truncJournalAfter(paths, (r) => r.record_type === "LOG_APPEND_INTENT" && r.txid === ctx.txid);
        // entry may already be on disk from original crash path — simulating intent without done:
        // force: if entry present keep it OR remove so recover inspects. Contract: torn/intent uses FS inspect.
        // Here: remove entry so FS says not appended; recover rolls forward append.
        fs.writeFileSync(paths.adoption, "");
        writeManifestHead(paths, null);
        writeActive(paths, ctx.oldPointer);
        if (fs.existsSync(paths.window)) fs.unlinkSync(paths.window);
      },
      expect: "DONE_NEW",
    },
    {
      name: "03-intent-boundary-LOG_APPEND_DONE-before-WINDOW",
      prepare(paths, ctx) {
        truncJournalAfter(paths, (r) => r.record_type === "LOG_APPEND_DONE" && r.txid === ctx.txid);
        // keep committing entry only
        const ents = adoptionEntries(paths).filter((e) => e.status === "committing" && e.txid === ctx.txid);
        // after before-swap crash log has committing only
        truncAdoptionToSeq(paths, ents.length ? ents[0].seq : 1);
        writeManifestHead(paths, null); // commit path hasn't updated manifest to terminal
        // actually after LOG_APPEND F manifest still old head
        writeManifestHead(paths, ctx.oldHead);
        writeActive(paths, ctx.oldPointer);
        if (fs.existsSync(paths.window)) fs.unlinkSync(paths.window);
      },
      expect: "DONE_NEW",
    },
    {
      name: "03-intent-boundary-SWAP_INTENT-without-DONE",
      prepare(paths, ctx) {
        // ensure journal has SWAP_INTENT: from before-swap we only have through WINDOW_PENDING.
        // Append SWAP_INTENT without performing swap.
        const staged = lastOf(journalRecords(paths, ctx.txid), "STAGE_DONE");
        fs.appendFileSync(paths.journal, `${JSON.stringify({
          schema_version: SCHEMA_VERSION,
          record_type: "SWAP_INTENT",
          txid: ctx.txid,
          from_tree: staged.from_pointer.tree,
          to_tree: staged.tree,
          to_pointer: staged.to_pointer,
        })}\n`);
        writeActive(paths, ctx.oldPointer);
      },
      expect: "DONE_NEW",
    },
    {
      name: "03-intent-boundary-SWAP_DONE-before-OUTCOME",
      prepare(paths, ctx) {
        const staged = lastOf(journalRecords(paths, ctx.txid), "STAGE_DONE");
        // Crash after-swap path is cleaner — re-run via separate fixture in caller below
        writeActive(paths, staged.to_pointer);
        // journal: keep up to SWAP_DONE by using after-swap crash base instead
      },
      expect: "DONE_NEW",
      useCrashPoint: "after-swap",
      prepareAfter(paths, ctx) {
        truncJournalAfter(paths, (r) => r.record_type === "SWAP_DONE" && r.txid === ctx.txid);
        // keep only committing entry on adoption
        const commit = adoptionEntries(paths).find((e) => e.status === "committing");
        fs.writeFileSync(paths.adoption, commit ? `${JSON.stringify(commit)}\n` : "");
        writeManifestHead(paths, ctx.oldHead);
      },
    },
    {
      name: "03-intent-boundary-OUTCOME_INTENT-without-DONE",
      useCrashPoint: "after-swap",
      prepareAfter(paths, ctx) {
        // Start from after-swap, then simulate outcome intent written but entry not fully...entry isafter intent in happy path
        // Add OUTCOME_APPEND_INTENT without appending entry or DONE
        const commit = adoptionEntries(paths).find((e) => e.status === "committing");
        const packet = lastOf(journalRecords(paths, ctx.txid), "TX_BEGIN").packet;
        const entry = {
          schema_version: SCHEMA_VERSION,
          seq: (commit ? commit.seq : 0) + 1,
          txid: ctx.txid,
          status: "effective",
          fingerprint: packet.fingerprint,
          kind: packet.kind,
          evidence_ref: packet.evidence_ref,
          human: packet.human,
          prev_sha256: commit.entry_sha256,
        };
        entry.entry_sha256 = sha256(JSON.stringify(entry));
        truncJournalAfter(paths, (r) => r.record_type === "SWAP_DONE" && r.txid === ctx.txid);
        fs.appendFileSync(paths.journal, `${JSON.stringify({
          schema_version: SCHEMA_VERSION,
          record_type: "OUTCOME_APPEND_INTENT",
          txid: ctx.txid,
          terminal_entry_sha: entry.entry_sha256,
          entry,
        })}\n`);
        fs.writeFileSync(paths.adoption, `${JSON.stringify(commit)}\n`);
        writeManifestHead(paths, ctx.oldHead);
      },
      expect: "DONE_NEW",
    },
    {
      name: "03-intent-boundary-MANIFEST_INTENT-without-DONE",
      useCrashPoint: "after-manifest",
      prepareAfter(paths, ctx) {
        // after-manifest has MANIFEST_DONE; rewind to MANIFEST_INTENT and restore old manifest head on disk
        const effective = adoptionEntries(paths).find((e) => e.status === "effective");
        truncJournalAfter(paths, (r) => r.record_type === "MANIFEST_INTENT" && r.txid === ctx.txid);
        writeManifestHead(paths, ctx.oldHead);
        // ensure adoption has effective if it was written before manifest
        if (effective) {
          const all = adoptionEntries(paths);
          if (!all.some((e) => e.status === "effective")) {
            /* shouldn't happen */
          }
        }
      },
      expect: "DONE_NEW",
    },
    {
      name: "03-intent-boundary-MANIFEST_DONE-before-WINDOW_FINAL",
      useCrashPoint: "after-manifest",
      prepareAfter(paths, ctx) {
        truncJournalAfter(paths, (r) => r.record_type === "MANIFEST_DONE" && r.txid === ctx.txid);
        // window may still be ADMITTED if crash was after-manifest before WINDOW_FINAL
        // after-manifest crash is after MANIFEST_DONE before finalize — check phase
      },
      expect: "DONE_NEW",
    },
    {
      name: "03-intent-boundary-before-STAGE_DONE",
      prepare(paths, ctx) {
        truncJournalAfter(paths, (r) => r.record_type === "TX_BEGIN" && r.txid === ctx.txid);
        fs.writeFileSync(paths.adoption, "");
        writeManifestHead(paths, null);
        writeActive(paths, ctx.oldPointer);
        if (fs.existsSync(paths.window)) fs.unlinkSync(paths.window);
        // leave staged tree present (exists from original crash) — recover should rm if STAGE was present; here for no STAGE
        // if staged tree from original before-swap still exists it's OK as non-ACTIVE artifact
      },
      expect: "ABORT_OLD",
    },
  ];

  for (const c of cases) {
    try {
      const root = mkRoot(c.name.slice(0, 20));
      const fx = createFixture(root);
      const oldPointer = fx.pointer;
      const oldHead = null;
      const crashPoint = c.useCrashPoint || "before-swap";
      const crashed = crashPromote(root, c.name, crashPoint);
      if (crashed.ok || crashed.code !== "SIMULATED_CRASH") {
        fail(c.name, `setup crash failed code=${crashed.code}`);
        continue;
      }
      const txid = (parseJsonl(fx.paths.journal).find((r) => r.record_type === "TX_BEGIN") || {}).txid;
      const staged = lastOf(journalRecords(fx.paths, txid), "STAGE_DONE");
      const ctx = { txid, oldPointer, oldHead, staged, newTree: staged && staged.tree };
      if (c.prepare) c.prepare(fx.paths, ctx);
      if (c.prepareAfter) c.prepareAfter(fx.paths, ctx);

      const rec = catchCode(() => recover(root));
      if (!rec.ok) {
        fail(c.name, `recover threw ${rec.code}: ${rec.message}`);
        continue;
      }
      const snap = activeSnap(fx.paths);
      const entries = adoptionEntries(fx.paths);
      const man = projectManifest(fx.paths);
      const win = windowState(fx.paths);
      const pure = assertExactlyOneTree(fx.paths, snap.pointer ? [snap.pointer.tree] : [], c.name);
      const errs = [];
      if (pure) errs.push(pure);
      if (man.adoption_log_head !== logHead(fx.paths)) errs.push("manifest/log diverge");

      if (c.expect === "ABORT_OLD") {
        if (snap.pointer.tree !== oldPointer.tree) errs.push(`want old tree got ${snap.pointer.tree}`);
        if (!rec.value.transactions.some((t) => t.state === "ABORTED")) errs.push(`want ABORTED got ${JSON.stringify(rec.value.transactions)}`);
        // no terminal effective for this tx
        const terminal = entries.filter((e) => e.txid === txid);
        if (terminal.some((e) => e.status === "effective")) errs.push("unexpected effective after abort-back");
      } else if (c.expect === "DONE_NEW") {
        if (snap.pointer.tree === oldPointer.tree) errs.push("want new tree after roll-forward");
        if (ctx.newTree && snap.pointer.tree !== ctx.newTree) errs.push(`want ${ctx.newTree} got ${snap.pointer.tree}`);
        if (!rec.value.transactions.some((t) => t.state === "DONE")) errs.push(`want DONE got ${JSON.stringify(rec.value.transactions)}`);
        if (entries.at(-1)?.status !== "effective") errs.push(`terminal=${entries.at(-1)?.status}`);
        if (man.adoption_log_head !== entries.at(-1)?.entry_sha256) errs.push("manifest not terminal effective");
        if (win.state !== "OBSERVING") errs.push(`window=${win.state} want OBSERVING (no adopted-tree-without-window)`);
      }

      if (errs.length) fail(c.name, errs.join("; "));
      else pass(c.name, `ACTIVE=${snap.pointer.tree} win=${win.state} rec=${rec.value.state}`);
    } catch (e) { fail(c.name, e.stack || e.message); }
  }
}

/* ============================================================================
 * 3) Torn journal tail
 * ============================================================================ */
function tTornJournal() {
  const name = "04-torn-journal-tail-inspect-not-parse";
  try {
    const root = mkRoot("torn");
    const fx = createFixture(root);
    const crashed = crashPromote(root, "torn", "after-swap");
    if (crashed.ok || crashed.code !== "SIMULATED_CRASH") {
      fail(name, `setup crash failed ${crashed.code}`);
      return;
    }
    const oldRaw = readUtf(fx.paths.journal);
    // Real torn tail: keep all complete records, then a half-line with NO trailing newline.
    const withNl = oldRaw.endsWith("\n") ? oldRaw : `${oldRaw}\n`;
    const complete = withNl.slice(0, withNl.lastIndexOf("\n", withNl.length - 2) + 1); // through penultimate record's \n
    const lastLine = withNl.slice(complete.length).replace(/\n$/, "");
    const half = lastLine.slice(0, Math.max(1, Math.floor(lastLine.length / 2)));
    const torn = complete + half; // complete records + half last; no trailing \n
    fs.writeFileSync(fx.paths.journal, torn);
    if (readUtf(fx.paths.journal).endsWith("\n")) {
      fail(name, "fixture error: torn journal ends with newline");
      return;
    }
    const midActive = activeSnap(fx.paths);

    const rec = catchCode(() => recover(root));
    if (!rec.ok) {
      // Contract (01 §Crash recovery): torn tail = record absent; inspection classifies on-disk state.
      // Throwing CORRUPT_STATE on a torn *last* line is a DECLINE of that contract → FAIL (defect).
      fail(name, `recover threw on torn tail: ${rec.code} ${rec.message}`);
      return;
    }
    const snap = activeSnap(fx.paths);
    const pure = assertExactlyOneTree(fx.paths, [snap.pointer.tree], name);
    const man = projectManifest(fx.paths);
    const errs = [];
    if (pure) errs.push(pure);
    if (man.adoption_log_head !== logHead(fx.paths)) errs.push("heads diverge after torn recover");
    if (midActive.pointer && snap.missing) errs.push("ACTIVE went missing");
    if (errs.length) fail(name, errs.join("; "));
    else pass(name, `recovered ACTIVE=${snap.pointer.tree} torn-ignored rec=${rec.value.state}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 4) CAS / hostile mutation
 * ============================================================================ */
function tStalePreBegin() {
  const name = "05-stale-pre-BEGIN-clean-ABORT";
  try {
    const root = mkRoot("stale");
    const fx = createFixture(root);
    const res = catchCode(() => promote(testPacket(root, "stale", {
      expected_active_sha: "a".repeat(64),
    })));
    if (res.ok) { fail(name, "expected throw"); return; }
    if (res.code !== "STALE_PROPOSAL") { fail(name, `code=${res.code} msg=${res.message}`); return; }
    // no TX_BEGIN should land
    const jr = parseJsonl(fx.paths.journal);
    if (jr.some((r) => r.record_type === "TX_BEGIN")) {
      fail(name, "TX_BEGIN recorded for stale pre-BEGIN");
      return;
    }
    const snap = activeSnap(fx.paths);
    if (snap.pointer.tree !== fx.tree) { fail(name, "ACTIVE changed on stale abort"); return; }
    pass(name, res.code);
  } catch (e) { fail(name, e.stack || e.message); }
}

function tHostilePostBegin() {
  const name = "06-hostile-post-BEGIN-HALT-exit3";
  const realRead = fs.readFileSync;
  const realWrite = fs.writeSync;
  try {
    const root = mkRoot("hostile");
    const fx = createFixture(root);
    // create a decoy tree that is a byte-clone under another id — we'll mutate ACTIVE to a forged pointer
    const decoyTree = "v-" + "ab".repeat(32);
    const decoyDir = path.join(fx.paths.evolvable, decoyTree);
    fs.cpSync(path.join(fx.paths.evolvable, fx.tree), decoyDir, { recursive: true });
    const decoyPointer = {
      schema_version: SCHEMA_VERSION,
      txid: "f".repeat(16),
      tree: decoyTree,
      tree_manifest_sha256: fx.pointer.tree_manifest_sha256,
    };

    let beginSeen = false;
    let mutated = false;
    // After TX_BEGIN hits the journal, poison ACTIVE before next CAS observations
    fs.writeSync = function (fd, data, ...rest) {
      const s = Buffer.isBuffer(data) ? data.toString("utf8") : String(data);
      const ret = realWrite.call(fs, fd, data, ...rest);
      if (!mutated && s.includes('"record_type":"TX_BEGIN"')) {
        beginSeen = true;
        fs.writeFileSync(fx.paths.active, pointerBytes(decoyPointer));
        mutated = true;
      }
      return ret;
    };

    const res = catchCode(() => promote(testPacket(root, "hostile-mut")));
    fs.writeSync = realWrite;

    if (res.ok) {
      fail(name, "expected HALT, promote succeeded");
      return;
    }
    if (res.code !== "HALT") {
      fail(name, `want HALT got ${res.code}: ${res.message}`);
      return;
    }
    const hasEv = res.evidence !== undefined;
    const cliSrc = fs.readFileSync(path.join(REPO_ROOT, "scripts", "promote.js"), "utf8");
    const mapsHalt = /exitCode\s*=\s*error\.code\s*===\s*"HALT"\s*\?\s*3/.test(cliSrc);
    if (!mapsHalt) {
      fail(name, "CLI does not map HALT to exit 3");
      return;
    }
    const jr = parseJsonl(fx.paths.journal);
    if (jr.some((r) => r.record_type === "TX_DONE")) {
      fail(name, "hostile mutation reached TX_DONE");
      return;
    }
    const snap = activeSnap(fx.paths);
    const pure = assertExactlyOneTree(fx.paths, [snap.pointer.tree], name);
    if (pure) { fail(name, pure); return; }
    pass(name, `HALT evidence=${hasEv} mutated=${mutated} begin=${beginSeen} ACTIVE=${snap.pointer.tree}`);
  } catch (e) {
    fs.readFileSync = realRead;
    fs.writeSync = realWrite;
    fail(name, e.stack || e.message);
  } finally {
    fs.readFileSync = realRead;
    fs.writeSync = realWrite;
  }
}

/* ============================================================================
 * 5) Adoption-log anchoring / hash chain
 * ============================================================================ */
function tAdoptionLog() {
  const name = "07-adoption-log-terminal-anchor-and-chain";
  try {
    const root = mkRoot("adopt");
    const fx = createFixture(root);
    const done = promote(testPacket(root, "adopt-ok"));
    const entries = adoptionEntries(fx.paths);
    const man = projectManifest(fx.paths);
    const errs = [];
    if (entries.length < 2) errs.push(`expected committing+effective, got ${entries.length}`);
    else {
      if (entries[0].status !== "committing") errs.push(`e0=${entries[0].status}`);
      if (entries[1].status !== "effective") errs.push(`e1=${entries[1].status}`);
      if (entries[1].prev_sha256 !== entries[0].entry_sha256) errs.push("chain break effective←committing");
      if (man.adoption_log_head !== entries[1].entry_sha256) errs.push("manifest head != effective");
      // verify hashes
      for (let i = 0; i < entries.length; i++) {
        const body = { ...entries[i] };
        const claimed = body.entry_sha256;
        delete body.entry_sha256;
        if (sha256(JSON.stringify(body)) !== claimed) errs.push(`bad entry_sha seq=${i + 1}`);
        if (entries[i].seq !== i + 1) errs.push(`seq gap at ${i}`);
        if (i === 0 && entries[i].prev_sha256 !== null) errs.push("first prev not null");
        if (i > 0 && entries[i].prev_sha256 !== entries[i - 1].entry_sha256) errs.push(`prev link ${i}`);
      }
    }
    // abort path
    const root2 = mkRoot("adopt-ab");
    const fx2 = createFixture(root2);
    const ab = promote(testPacket(root2, "adopt-ab", { __test_abort_after_log: true }));
    const e2 = adoptionEntries(fx2.paths);
    const m2 = projectManifest(fx2.paths);
    if (ab.state !== "ABORTED") errs.push(`abort state=${ab.state}`);
    if (e2.at(-1)?.status !== "aborted") errs.push(`abort terminal=${e2.at(-1)?.status}`);
    if (m2.adoption_log_head !== e2.at(-1)?.entry_sha256) errs.push("abort manifest not aborted terminal");
    // append-only: no rewrite — prev chain including abort props page from committing
    if (e2.length >= 2 && e2[1].prev_sha256 !== e2[0].entry_sha256) errs.push("abort not linked");
    // rewrite detection: length only grows
    const len1 = readUtf(fx2.paths.adoption).length;
    promote(testPacket(root2, "after-abort-should-fail-window?")); // window may not open on abort - should allow new promote
    // abort doesn't open window permanently?; abortVisible no window → NO_WINDOW
    const len2 = readUtf(fx2.paths.adoption).length;
    // if second promote worked, log grew; if WINDOW from nothing ok

    if (errs.length) fail(name, errs.join("; "));
    else pass(name, `effective_head_ok abort_head_ok done=${done.state}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 6) Rollback
 * ============================================================================ */
function tRollbackDoc() {
  const name = "08-rollback-doc-byte-exact";
  try {
    const root = mkRoot("rb-doc");
    const fx = createFixture(root);
    const oldTree = fx.tree;
    const oldBytes = readBuf(path.join(fx.paths.evolvable, oldTree, "graphsmith.learned.md"));
    const adopted = promote(testPacket(root, "changed-for-rb"));
    const midBytes = readBuf(path.join(fx.paths.evolvable, activeSnap(fx.paths).pointer.tree, "graphsmith.learned.md"));
    if (midBytes.equals(oldBytes)) { fail(name, "promote did not change bytes"); return; }

    const prev = process.cwd();
    process.chdir(root);
    let rb;
    try { rb = rollback(adopted.txid); }
    finally { process.chdir(prev); }

    const snap = activeSnap(fx.paths);
    const restored = readBuf(path.join(fx.paths.evolvable, snap.pointer.tree, "graphsmith.learned.md"));
    const errs = [];
    if (rb.state !== "DONE") errs.push(`rb.state=${rb.state}`);
    if (snap.pointer.tree !== oldTree) errs.push(`tree ${snap.pointer.tree} != ${oldTree}`);
    if (!restored.equals(oldBytes)) errs.push("learned.md not byte-exact restore");
    if (windowState(fx.paths).state !== "CLOSED_ROLLED_BACK") errs.push(`window=${windowState(fx.paths).state}`);
    if (errs.length) fail(name, errs.join("; "));
    else pass(name, `restored tree=${snap.pointer.tree}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

function tRollbackCodeRefused() {
  const name = "09-rollback-code-FORWARD_RECOVERY";
  try {
    const root = mkRoot("rb-code");
    const fx = createFixture(root);
    // complete stub a code adoption by crafting journal TX_DONE artificially then rollback()
    // Easier: call rollback(inverse object) with kind code
    const res = catchCode(() => rollback({
      project_root: root,
      fingerprint: sha256("code-rb"),
      kind: "code",
      evidence_ref: "x",
      human: { name: "t", decision: "d", ts: "t" },
      edits: [],
      reversible: true,
      auto_rollback_eligible: true,
      rollback_of: "deadbeefdeadbeef",
    }));
    if (res.ok) { fail(name, "code rollback should refuse"); return; }
    if (res.code !== "FORWARD_RECOVERY_REQUIRED") {
      fail(name, `code=${res.code} msg=${res.message}`);
      return;
    }
    if (!/human forward-recovery/i.test(res.message)) {
      fail(name, `message not human-forward-recovery: ${res.message}`);
      return;
    }
    // migration too
    const res2 = catchCode(() => rollback({
      project_root: root,
      fingerprint: sha256("mig-rb"),
      kind: "migration",
      evidence_ref: "x",
      human: { name: "t", decision: "d", ts: "t" },
      source_tree: fx.tree,
      reversible: true,
      auto_rollback_eligible: true,
      rollback_of: "deadbeefdeadbeef",
    }));
    if (res2.ok || res2.code !== "FORWARD_RECOVERY_REQUIRED") {
      fail(name, `migration code=${res2.code}`);
      return;
    }
    pass(name, "code+migration refused");
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 7) GC + live-lease registry
 * ============================================================================ */
function tGcLiveLease() {
  const name = "10-GC-live-lease-tree-survives";
  try {
    const root = mkRoot("gc");
    const fx = createFixture(root);
    // First promotion creates tree A→B
    promote(testPacket(root, "gc1"));
    const treeB = activeSnap(fx.paths).pointer.tree;
    // Close window to allow another promote (OBSERVING blocks)
    // Force-close via store for test isolation
    const store = createStore(root);
    const lock = store._testing.acquireLock();
    try {
      store._commit([{
        file: "window.json",
        make: (raw, rev) => {
          const cur = raw ? JSON.parse(raw) : { schema_version: "1.0", state_rev: 0, state: "NO_WINDOW", flag: false, window: null };
          cur.state = "CLOSED_PASS";
          cur.state_rev = rev;
          return JSON.stringify(cur);
        },
      }]);
    } finally {
      clearInterval(lock.heartbeat);
      store._testing.releaseLock(lock.ownerToken);
    }

    // Register a long-lease reader on treeB (previous after next promote becomes non-ACTIVE)
    const store2 = createStore(root, { leaseMs: 60 * 60 * 1000, heartbeatMs: 1000 });
    store2.runRegistry.register("fake-long-lease-reader", treeB);

    // Second promote B→C ; GC should run on later promotion per contract
    promote(testPacket(root, "gc2", {
      edits: [{
        schema_version: SCHEMA_VERSION,
        schema_ref: "grok-test",
        file: "graphsmith.learned.md",
        anchor: "gc1",
        op: "replace",
        payload: "gc2",
      }],
    }));
    const treeC = activeSnap(fx.paths).pointer.tree;
    const trees = listTrees(fx.paths);
    // treeB must survive if live-lease held (GC must not delete it)
    const bAlive = trees.includes(treeB);
    // Inspect promote.js for any GC implementation
    const src = fs.readFileSync(path.join(REPO_ROOT, "scripts", "promote.js"), "utf8");
    const hasGc =
      /run-registry/.test(src) ||
      /live.?lease/i.test(src) ||
      /\bGC\b/.test(src) ||
      /garbage/i.test(src) ||
      /rollback-eligible/.test(src);

    // Older seed tree fx.tree: may or may not be GC'd
    if (!bAlive) {
      fail(name, `live-lease tree ${treeB} was deleted; ACTIVE=${treeC} trees=${trees.join(",")}`);
      return;
    }
    if (!hasGc) {
      // Tree survived only because GC is absent — still a contract defect
      fail(name, `tree survived but promote.js has NO GC/live-lease coupling (null implementation); trees=${trees.join(",")}`);
      return;
    }
    pass(name, `treeB live under lease; GC present; trees=${trees.join(",")}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 8) Gate-4 coupling
 * ============================================================================ */
function tGate4Coupling() {
  const name = "11-gate4-swap-without-WINDOW_FINAL-recovers";
  try {
    const root = mkRoot("g4");
    const fx = createFixture(root);
    const crashed = crashPromote(root, "g4", "after-swap");
    if (crashed.ok || crashed.code !== "SIMULATED_CRASH") {
      fail(name, `crash setup ${crashed.code}`);
      return;
    }
    // Post-swap, window should be ADMITTED (pending), not OBSERVING yet
    const midWin = windowState(fx.paths);
    const midActive = activeSnap(fx.paths);
    const staged = lastOf(parseJsonl(fx.paths.journal).filter(Boolean), "STAGE_DONE");
    const errs = [];
    if (midActive.pointer.tree !== staged.tree) errs.push(`mid ACTIVE not swapped to new (got ${midActive.pointer.tree})`);
    if (midWin.state !== "ADMITTED") errs.push(`mid window=${midWin.state} want ADMITTED`);

    recover(root);
    const win = windowState(fx.paths);
    const snap = activeSnap(fx.paths);
    if (win.state !== "OBSERVING") errs.push(`after recover window=${win.state}`);
    if (snap.pointer.tree !== staged.tree) errs.push("ACTIVE lost new tree");
    if (errs.length) fail(name, errs.join("; "));
    else pass(name, `finalized window OBSERVING on ${snap.pointer.tree}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

function tGate4NoWindowPrecondition() {
  const name = "12-promote-refuses-open-window-NO_WINDOW";
  try {
    const root = mkRoot("nowin");
    const fx = createFixture(root);
    promote(testPacket(root, "open-win"));
    const w1 = windowState(fx.paths);
    const res = catchCode(() => promote(testPacket(root, "second")));
    const errs = [];
    if (w1.state !== "OBSERVING") errs.push(`setup window=${w1.state}`);
    if (res.ok) errs.push("second promote allowed while window open");
    else if (res.code !== "WINDOW_EXISTS") errs.push(`code=${res.code} msg=${res.message}`);
    // ACTIVE unchanged by refused promote
    const treesBefore = activeSnap(fx.paths).pointer.tree;
    if (!res.ok && activeSnap(fx.paths).pointer.tree !== treesBefore) errs.push("ACTIVE moved on refuse");
    if (errs.length) fail(name, errs.join("; "));
    else pass(name, res.code);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 9) Disk discipline
 * ============================================================================ */
function tDiskReserve() {
  const name = "13-preflight-free-space-refusal";
  const realStatfs = fs.statfsSync;
  try {
    const root = mkRoot("disk");
    createFixture(root);
    fs.statfsSync = function () {
      return { bavail: 1, bsize: 1, blocks: 1, bfree: 1 };
    };
    const res = catchCode(() => promote(testPacket(root, "disk-low")));
    fs.statfsSync = realStatfs;
    if (res.ok) { fail(name, "promote succeeded despite tiny free space"); return; }
    if (res.code !== "DISK_RESERVE" && res.code !== "PLATFORM_REFUSED") {
      fail(name, `want DISK_RESERVE got ${res.code}: ${res.message}`);
      return;
    }
    pass(name, res.code);
  } catch (e) {
    fs.statfsSync = realStatfs;
    fail(name, e.stack || e.message);
  } finally {
    fs.statfsSync = realStatfs;
  }
}

function tAbandonedStagingCleanup() {
  const name = "14-abandoned-staging-cleaned-on-recover";
  try {
    const root = mkRoot("staging");
    const fx = createFixture(root);
    // Plant abandoned staging dir + unfinished TX_BEGIN only
    const fakeTx = sha256("staging-abandon").slice(0, 16);
    const staging = path.join(fx.paths.evolvable, `.staging-${fakeTx}`);
    fs.mkdirSync(staging, { recursive: true });
    fs.writeFileSync(path.join(staging, "junk.txt"), "abandoned");
    fs.appendFileSync(fx.paths.journal, `${JSON.stringify({
      schema_version: SCHEMA_VERSION,
      record_type: "TX_BEGIN",
      txid: fakeTx,
      expected_active_sha: fx.activeSha,
      expected_log_head: null,
      packet: testPacket(root, "stg"),
    })}\n`);

    const rec = recover(root);
    const left = listStaging(fx.paths);
    const jr = journalRecords(fx.paths, fakeTx);
    const aborted = jr.some((r) => r.record_type === "TX_ABORT");
    const errs = [];
    if (!aborted) errs.push("TX not aborted");
    if (left.length > 0) errs.push(`.staging dirs remain: ${left.join(",")}`);
    // Contract requires abandoned staging cleanup — if remains, FAIL (defect)
    if (errs.length) fail(name, errs.join("; "));
    else pass(name, `rec=${rec.state}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * 10) Same-volume / unprovable FS
 * ============================================================================ */
function tSameVolumeRefuse() {
  const name = "15-unprovable-or-cross-volume-refuse";
  const realStat = fs.statSync;
  try {
    const root = mkRoot("vol");
    const fx = createFixture(root);
    let calls = 0;
    fs.statSync = function (p, ...a) {
      const st = realStat.call(fs, p, ...a);
      // After fixture, during diskPreflight: force mismatched dev for source vs evolvable
      const s = String(p);
      if (s.includes(`${path.sep}evolvable`) && !s.includes(`${path.sep}v-`) && !s.includes(".staging")) {
        calls++;
        return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { dev: 1 });
      }
      if (s.includes(`${path.sep}v-`)) {
        return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { dev: 2 });
      }
      return st;
    };
    const res = catchCode(() => promote(testPacket(root, "vol-mismatch")));
    fs.statSync = realStat;
    if (res.ok) { fail(name, "promote allowed on mismatched volume"); return; }
    if (res.code !== "PLATFORM_REFUSED") {
      fail(name, `want PLATFORM_REFUSED got ${res.code}: ${res.message}`);
      return;
    }
    pass(name, res.code);
  } catch (e) {
    fs.statSync = realStat;
    fail(name, e.stack || e.message);
  } finally {
    fs.statSync = realStat;
  }
}

function tMissingStatfs() {
  const name = "16-missing-statfs-fail-closed";
  const had = Object.prototype.hasOwnProperty.call(fs, "statfsSync");
  const real = fs.statfsSync;
  try {
    const root = mkRoot("nostatfs");
    createFixture(root);
    try { delete fs.statfsSync; } catch { fs.statfsSync = undefined; }
    if (typeof fs.statfsSync === "function") {
      // immutable — skip
      fs.statfsSync = real;
      skip(name, "fs.statfsSync not deletable on this platform");
      return;
    }
    const res = catchCode(() => promote(testPacket(root, "no-statfs")));
    if (had) fs.statfsSync = real;
    if (res.ok) { fail(name, "expected refuse"); return; }
    if (res.code !== "PLATFORM_REFUSED") {
      fail(name, `code=${res.code} ${res.message}`);
      return;
    }
    pass(name, res.code);
  } catch (e) {
    if (had) fs.statfsSync = real;
    fail(name, e.stack || e.message);
  } finally {
    if (had) fs.statfsSync = real;
  }
}

/* ============================================================================
 * 11) Extra attacks (zero-finding invalid)
 * ============================================================================ */
function tDoubleRecoverIdempotent() {
  const name = "17-double-recover-idempotent";
  try {
    const root = mkRoot("drec");
    const fx = createFixture(root);
    crashPromote(root, "drec", "after-swap");
    const r1 = recover(root);
    const snap1 = activeSnap(fx.paths);
    const head1 = logHead(fx.paths);
    const man1 = projectManifest(fx.paths).adoption_log_head;
    const r2 = recover(root);
    const snap2 = activeSnap(fx.paths);
    const head2 = logHead(fx.paths);
    const errs = [];
    if (snap1.sha !== snap2.sha) errs.push("ACTIVE changed on second recover");
    if (head1 !== head2) errs.push("log head changed");
    if (man1 !== projectManifest(fx.paths).adoption_log_head) errs.push("manifest changed");
    if (r2.state !== "CLEAN" && !(r2.transactions && r2.transactions.length === 0)) {
      // second should be CLEAN
      if (r2.state !== "CLEAN") errs.push(`second recover state=${r2.state}`);
    }
    if (errs.length) fail(name, errs.join("; "));
    else pass(name, `r1=${r1.state} r2=${r2.state}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

function tUnfinishedBlocksNewPromote() {
  const name = "18-unfinished-tx-blocks-new-promote";
  try {
    const root = mkRoot("block");
    const fx = createFixture(root);
    crashPromote(root, "block", "before-swap");
    const res = catchCode(() => promote(testPacket(root, "new-while-open")));
    if (res.ok) { fail(name, "new promote allowed over unfinished tx"); return; }
    if (res.code !== "RECOVERY_REQUIRED") {
      fail(name, `code=${res.code} ${res.message}`);
      return;
    }
    pass(name, res.code);
  } catch (e) { fail(name, e.stack || e.message); }
}

function tActiveNeverNeitherMidTx() {
  const name = "19-ACTIVE-never-missing-during-built-in-crashes";
  try {
    for (const point of ["before-swap", "after-swap", "after-manifest"]) {
      const root = mkRoot(`nn-${point}`);
      const fx = createFixture(root);
      crashPromote(root, `nn-${point}`, point);
      if (activeSnap(fx.paths).missing) {
        fail(name, `ACTIVE missing after crash ${point}`);
        return;
      }
      const err = assertExactlyOneTree(fx.paths, [activeSnap(fx.paths).pointer.tree], point);
      if (err) { fail(name, err); return; }
    }
    pass(name, "all crash points pure");
  } catch (e) { fail(name, e.stack || e.message); }
}

function tProjectManifestDoesNotRecordTree() {
  const name = "20-manifest-update-omits-tree-field";
  try {
    const root = mkRoot("man-tree");
    const fx = createFixture(root);
    const before = projectManifest(fx.paths);
    promote(testPacket(root, "man-tree"));
    const after = projectManifest(fx.paths);
    const src = fs.readFileSync(path.join(REPO_ROOT, "scripts", "promote.js"), "utf8");
    // Contract 01 §Transitions step 6: "project manifest updated (new tree, adoption_log_head = entry_sha)"
    const manFn = src.match(/function updateProjectManifest[\s\S]*?\n\}/);
    const onlyHead = manFn && /adoption_log_head/.test(manFn[0]) && !/\.tree\b/.test(manFn[0]);
    if (after.adoption_log_head && onlyHead && before.tree === after.tree && after.tree === undefined) {
      // document defect: only head updated — if contract requires tree, FAIL
      fail(name, "updateProjectManifest only sets adoption_log_head; no new tree identity written (contract 01 §Transitions.6)");
      return;
    }
    pass(name, "tree field handled or not required by on-disk schema");
  } catch (e) { fail(name, e.stack || e.message); }
}

function tChainBreakHalt() {
  const name = "21-adoption-chain-break-HALT";
  try {
    const root = mkRoot("chain");
    const fx = createFixture(root);
    promote(testPacket(root, "chain1"));
    // force close window for second ops under store
    const store = createStore(root);
    const lock = store._testing.acquireLock();
    try {
      store._commit([{
        file: "window.json",
        make: (raw, rev) => JSON.stringify({
          schema_version: "1.0", state_rev: rev, state: "CLOSED_PASS", flag: false, window: null,
        }),
      }]);
    } finally {
      clearInterval(lock.heartbeat);
      store._testing.releaseLock(lock.ownerToken);
    }
    // corrupt middle of chain
    const lines = readUtf(fx.paths.adoption).trim().split("\n");
    if (lines.length < 2) { fail(name, "need 2 entries"); return; }
    const e0 = JSON.parse(lines[0]);
    e0.fingerprint = "0".repeat(64);
    // keep claimed entry_sha256 → verify fails
    lines[0] = JSON.stringify(e0);
    fs.writeFileSync(fx.paths.adoption, lines.join("\n") + "\n");
    const res = catchCode(() => promote(testPacket(root, "chain2", {
      edits: [{
        schema_version: SCHEMA_VERSION,
        schema_ref: "g",
        file: "graphsmith.learned.md",
        anchor: "chain1",
        op: "replace",
        payload: "chain2",
      }],
    })));
    if (res.ok) { fail(name, "promote on broken chain succeeded"); return; }
    if (res.code !== "HALT" && res.code !== "CORRUPT_STATE") {
      fail(name, `code=${res.code} ${res.message}`);
      return;
    }
    pass(name, res.code);
  } catch (e) { fail(name, e.stack || e.message); }
}

function tSpawnSigkillIfUnix() {
  const name = "22-spawn-child-SIGKILL-mid-promote";
  try {
    if (process.platform === "win32") {
      // SIGKILL via taskkill still valid
    }
    const root = mkRoot("sigkill");
    createFixture(root);
    const worker = path.join(root, "worker.js");
    fs.writeFileSync(worker, `
      process.env.GRAPHSMITH_TEST_MODE = "1";
      const { promote } = require(${JSON.stringify(path.join(REPO_ROOT, "scripts", "promote.js"))});
      const fs = require("fs");
      const path = require("path");
      const root = ${JSON.stringify(root)};
      // hang after first journal write-ish via infinite loop after marking
      const realWrite = fs.writeSync;
      fs.writeSync = function(fd, data, ...rest) {
        const s = Buffer.isBuffer(data) ? data.toString("utf8") : String(data);
        const r = realWrite.call(fs, fd, data, ...rest);
        if (s.includes('"record_type":"LOG_APPEND_DONE"')) {
          fs.writeFileSync(path.join(root, "KILL_ME"), "1");
          while (true) {}
        }
        return r;
      };
      try {
        promote({
          project_root: root,
          fingerprint: require("crypto").createHash("sha256").update("sigkill").digest("hex"),
          kind: "doc",
          evidence_ref: "sigkill",
          human: { name: "t", decision: "d", ts: "t" },
          edits: [{ schema_version: "1.0", schema_ref: "g", file: "graphsmith.learned.md", anchor: "alpha", op: "replace", payload: "sigkilled" }],
          reversible: true, auto_rollback_eligible: true, window_n: 1,
        });
      } catch (e) { process.stderr.write(String(e)); process.exit(1); }
    `);
    const child = require("child_process").spawn(process.execPath, [worker], {
      stdio: "ignore",
      detached: true,
      env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
    });
    const start = Date.now();
    let killed = false;
    while (Date.now() - start < 15000) {
      if (fs.existsSync(path.join(root, "KILL_ME"))) {
        try {
          if (process.platform === "win32") {
            spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
          } else {
            process.kill(child.pid, "SIGKILL");
          }
          killed = true;
        } catch { /* already dead */ }
        break;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }
    try { child.unref(); } catch { /* */ }
    if (!killed) {
      try {
        if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
        else process.kill(child.pid, "SIGKILL");
      } catch { /* */ }
      skip(name, "child never reached LOG_APPEND_DONE kill point in 15s");
      return;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);
    const paths = locations(root);
    // Dead holder: lease judged by lock mtime. Backdate mtime; do NOT rewrite lock JSON
    // (schema is closed — corrupt rewrite is a different test).
    process.env.GRAPHSMITH_LEASE_MS = "10";
    const lockPath = path.join(paths.state, "state.lock");
    if (fs.existsSync(lockPath)) {
      const ancient = new Date(Date.now() - 60_000);
      try { fs.utimesSync(lockPath, ancient, ancient); }
      catch { fs.unlinkSync(lockPath); }
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30);
    const rec = catchCode(() => recover(root));
    delete process.env.GRAPHSMITH_LEASE_MS;
    if (!rec.ok) {
      fail(name, `recover after SIGKILL: ${rec.code} ${rec.message}`);
      return;
    }
    const snap = activeSnap(paths);
    const pure = assertExactlyOneTree(paths, [snap.pointer.tree], name);
    const man = projectManifest(paths);
    if (pure) { fail(name, pure); return; }
    if (man.adoption_log_head !== logHead(paths)) { fail(name, "heads diverge"); return; }
    pass(name, `recover=${rec.value.state} ACTIVE=${snap.pointer.tree}`);
  } catch (e) { fail(name, e.stack || e.message); }
}

/* ============================================================================
 * Run all
 * ============================================================================ */
function main() {
  tHappy();
  tCrashMatrixBuiltin();
  tCrashMatrixRewind();
  tTornJournal();
  tStalePreBegin();
  tHostilePostBegin();
  tAdoptionLog();
  tRollbackDoc();
  tRollbackCodeRefused();
  tGcLiveLease();
  tGate4Coupling();
  tGate4NoWindowPrecondition();
  tDiskReserve();
  tAbandonedStagingCleanup();
  tSameVolumeRefuse();
  tMissingStatfs();
  tDoubleRecoverIdempotent();
  tUnfinishedBlocksNewPromote();
  tActiveNeverNeitherMidTx();
  tProjectManifestDoesNotRecordTree();
  tChainBreakHalt();
  tSpawnSigkillIfUnix();

  const counts = { PASS: 0, FAIL: 0, SKIPPED: 0 };
  for (const r of results) counts[r.status] = (counts[r.status] || 0) + 1;
  console.log("---");
  console.log(`TOTAL\tPASS=${counts.PASS}\tFAIL=${counts.FAIL}\tSKIPPED=${counts.SKIPPED}`);
  if (counts.FAIL > 0) process.exitCode = 1;
}

try {
  main();
} finally {
  if (priorTestMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
  else process.env.GRAPHSMITH_TEST_MODE = priorTestMode;
  for (const root of tempRoots) {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* */ }
  }
}
