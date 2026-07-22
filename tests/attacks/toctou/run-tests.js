#!/usr/bin/env node
/* TOCTOU race harness — contained.
 * Mutate ACTIVE / log head / staged tree BETWEEN check and use.
 * Simulates second writer via interleaving + direct fs mutation.
 * Verdicts from on-disk state / error.code / exit code — never log strings.
 * Exit 1 if any race silent-succeeds against a must-hold guarantee.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const promoteMod = require(path.join(REPO, "scripts", "promote.js"));
const verify = require(path.join(REPO, "scripts", "verify.js"));
const { generate, verifyTree } = require(path.join(REPO, "scripts", "manifest.js"));
const loaders = require(path.join(REPO, "scripts", "loaders.js"));
const { createStore } = require(path.join(REPO, "scripts", "state-store.js"));

const { promote, SCHEMA_VERSION } = promoteMod;
const { runIntegrity, integrityExitCode } = verify;
const { resolveActive } = loaders;

const results = [];
const temps = [];
const priorMode = process.env.GRAPHSMITH_TEST_MODE;
process.env.GRAPHSMITH_TEST_MODE = "1";

function sha256(v) {
  return crypto.createHash("sha256").update(typeof v === "string" || Buffer.isBuffer(v) ? v : JSON.stringify(v)).digest("hex");
}
function record(name, status, detail) {
  results.push({ name, status, detail: detail || "" });
  console.log(`${status}\t${name}${detail ? "\t" + String(detail).replace(/\s+/g, " ").slice(0, 300) : ""}`);
}
function pass(n, d) { record(n, "PASS", d); }
function fail(n, d) { record(n, "FAIL", d); }
function unavailable(n, d) { record(n, "UNAVAILABLE", d); }
function mk(tag) {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), `gs-atk-toctou-${tag}-`));
  temps.push(r);
  return r;
}
function rmAll() {
  for (const t of temps) {
    try { fs.rmSync(t, { recursive: true, force: true }); } catch (_) {}
  }
}

function pointerBytes(pointer) {
  return Buffer.from(`${JSON.stringify(pointer, null, 2)}\n`, "utf8");
}
function locations(root) {
  const state = path.join(root, ".graphsmith", "state");
  const evolvable = path.join(root, ".graphsmith", "evolvable");
  return {
    root, state, evolvable,
    active: path.join(evolvable, "ACTIVE"),
    adoption: path.join(state, "adoption-log.jsonl"),
    projectManifest: path.join(state, "project.manifest.json"),
    journal: path.join(state, "journal.jsonl"),
  };
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
    generated_at: "atk-toctou",
    parent_release_sha256: null,
    adoption_log_head: null,
    active_tree: tree,
    active_tree_manifest_sha256: sha256(manifestBytes),
    files: [],
    workflow_manifests: [],
  }, null, 2)}\n`);
  return { paths, tree, pointer, activeSha: sha256(pointerBytes(pointer)) };
}
function testPacket(root, suffix, extra = {}) {
  return {
    project_root: root,
    fingerprint: sha256(`atk-toctou:${suffix}`),
    kind: "doc",
    evidence_ref: `toctou:${suffix}`,
    human: { name: "toctou", decision: "approve", ts: "2000-01-01T00:00:00.000Z" },
    edits: [{
      schema_version: SCHEMA_VERSION,
      schema_ref: "toctou",
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
function catchPromote(fn) {
  try {
    return { ok: true, result: fn() };
  } catch (e) {
    return { ok: false, code: e.code, message: e.message, evidence: e.evidence };
  }
}
function closeWindow(root) {
  const store = createStore(root);
  const lock = store._testing.acquireLock();
  try {
    store._commit([{
      file: "window.json",
      make: (raw, rev) => {
        const cur = raw ? JSON.parse(raw) : {
          schema_version: SCHEMA_VERSION, state_rev: 0, state: "NO_WINDOW", flag: false, window: null,
        };
        cur.state = "CLOSED_PASS";
        cur.state_rev = rev;
        return JSON.stringify(cur);
      },
    }]);
  } finally {
    clearInterval(lock.heartbeat);
    store._testing.releaseLock(lock.ownerToken);
  }
}
function readActive(paths) {
  const raw = fs.readFileSync(paths.active);
  return { raw, sha: sha256(raw), pointer: JSON.parse(raw.toString("utf8")) };
}
function parseJsonl(file) {
  const raw = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  if (!raw) return [];
  return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

/* ------------------------------------------------------------------ */
/* 1. Hostile ACTIVE rewrite after TX_BEGIN (via crash hook + mutate) */
/* ------------------------------------------------------------------ */
function race_postBeginActiveMutation() {
  const name = "post-BEGIN-ACTIVE-mutation-HALT";
  try {
    const root = mk("post-begin");
    const { paths, pointer, activeSha } = createFixture(root);
    const hostilePointer = {
      schema_version: SCHEMA_VERSION,
      txid: "f".repeat(16),
      tree: pointer.tree,
      tree_manifest_sha256: pointer.tree_manifest_sha256,
    };
    /* Drive promote into post-BEGIN path then crash before swap; at crash
     * boundary inject a second-writer ACTIVE rewrite by re-running promote
     * after direct fs mutation of ACTIVE while an unfinished TX exists.
     * First path: use __test_crash_at before-swap after a real BEGIN so stage
     * exists, then mutate ACTIVE identity fields, then attempt continue/recover.
     */
    const crashRes = catchPromote(() =>
      promote(testPacket(root, "begin-crash", { __test_crash_at: "before-swap" }))
    );
    if (crashRes.ok || crashRes.code !== "SIMULATED_CRASH") {
      fail(name, `setup crash missing: ok=${crashRes.ok} code=${crashRes.code}`);
      return;
    }
    const beforeHostile = readActive(paths);
    /* Second writer: overwrite ACTIVE with hostile identity (same tree, different txid body) */
    fs.writeFileSync(paths.active, pointerBytes(hostilePointer));
    const afterHostile = readActive(paths);
    if (afterHostile.sha === beforeHostile.sha) {
      fail(name, "hostile ACTIVE write did not change pointer hash");
      return;
    }
    /* Attempt recover — unclassifiable ACTIVE vs journal expectations must HALT */
    let recoverRes;
    try {
      promoteMod.recover(root);
      recoverRes = { ok: true };
    } catch (e) {
      recoverRes = { ok: false, code: e.code, message: e.message, evidence: e.evidence };
    }
    const journal = parseJsonl(paths.journal);
    const hasHaltish =
      !recoverRes.ok &&
      (recoverRes.code === "HALT" || recoverRes.code === "CORRUPT_STATE");
    /* Or if recover aborts cleanly without installing hostile as "verified effective" */
    const activeNow = readActive(paths);
    const silentOverwrite =
      recoverRes.ok &&
      activeNow.sha === afterHostile.sha &&
      journal.some((r) => r.record_type === "TX_DONE");

    if (silentOverwrite) {
      fail(name, "SILENT OVERWRITE: recover DONE with hostile ACTIVE");
      return;
    }
    if (hasHaltish || (!recoverRes.ok && recoverRes.code)) {
      pass(name, `code=${recoverRes.code} activeSha=${activeNow.sha.slice(0, 12)} evidence=${!!recoverRes.evidence}`);
      return;
    }
    /* Full promote after hostile mutation while unclean journal */
    const second = catchPromote(() =>
      promote(testPacket(root, "second-after-hostile", {
        edits: [{
          schema_version: SCHEMA_VERSION,
          schema_ref: "toctou",
          file: "graphsmith.learned.md",
          anchor: "alpha",
          op: "replace",
          payload: "second",
        }],
      }))
    );
    if (second.ok && second.result.state === "DONE") {
      fail(name, "second promote DONE after hostile ACTIVE + unfinished journal");
    } else {
      pass(name, `recover=${recoverRes.code || "ok"} second=${second.code || (second.result && second.result.state)}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 2. Direct expectedState path: mutate ACTIVE between VALIDATE and SWAP */
/* ------------------------------------------------------------------ */
function race_mutateBetweenValidateAndSwap() {
  const name = "mutate-ACTIVE-between-validate-and-swap-HALT";
  try {
    const root = mk("val-swap");
    const { paths, pointer } = createFixture(root);

    /* Use crash after validated path: crash at before-swap means STAGE+VALIDATE done.
     * Mutate ACTIVE raw bytes (hostile) then continue via recover.
     */
    const crash = catchPromote(() =>
      promote(testPacket(root, "valswap", { __test_crash_at: "before-swap" }))
    );
    if (crash.code !== "SIMULATED_CRASH") {
      fail(name, `expected SIMULATED_CRASH got ${crash.code}`);
      return;
    }
    const snap = readActive(paths);
    const mutated = {
      ...snap.pointer,
      txid: "a1b2c3d4e5f60789",
    };
    fs.writeFileSync(paths.active, pointerBytes(mutated));
    const mutatedSha = sha256(pointerBytes(mutated));
    if (mutatedSha === snap.sha) {
      fail(name, "mutation did not change ACTIVE sha");
      return;
    }

    let rec;
    try {
      promoteMod.recover(root);
      rec = { ok: true };
    } catch (e) {
      rec = { ok: false, code: e.code, message: e.message, evidence: e.evidence };
    }

    const finalActive = readActive(paths);
    const journal = parseJsonl(paths.journal);
    const done = journal.filter((r) => r.record_type === "TX_DONE");
    /* Guarantee: must not silently complete WITH the hostile mid-flight identity
     * without detection. HALT with evidence is ideal; refusing completion is ok.
     */
    if (rec.ok && done.length && finalActive.sha === mutatedSha) {
      fail(name, "DONE with mid-flight mutated ACTIVE — silent overwrite");
      return;
    }
    if (!rec.ok && rec.code === "HALT") {
      pass(name, `HALT evidence=${!!rec.evidence} final=${finalActive.sha.slice(0, 12)}`);
      return;
    }
    if (!rec.ok) {
      pass(name, `refused code=${rec.code}`);
      return;
    }
    /* recover rolled back or rolled forward to CLASSIFIED identities only */
    const classified =
      finalActive.sha === snap.sha ||
      journal.some((r) => r.record_type === "SWAP_DONE" && r.observed_active_sha === finalActive.sha);
    if (classified && finalActive.sha !== mutatedSha) {
      pass(name, `recovered without hostile IDENTITY final=${finalActive.sha.slice(0, 12)}`);
    } else if (finalActive.sha === mutatedSha && !done.length) {
      pass(name, "hostile ACTIVE left but TX not DONE");
    } else {
      fail(name, `ambiguous recover ok=${rec.ok} final=${finalActive.sha.slice(0, 12)} done=${done.length}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 3. Adoption-log head mutated post-BEGIN                              */
/* ------------------------------------------------------------------ */
function race_logHeadMutation() {
  const name = "post-BEGIN-log-head-mutation-HALT";
  try {
    const root = mk("loghead");
    const { paths } = createFixture(root);
    const crash = catchPromote(() =>
      promote(testPacket(root, "loghead", { __test_crash_at: "before-swap" }))
    );
    if (crash.code !== "SIMULATED_CRASH") {
      fail(name, `setup crash failed: ${crash.code}`);
      return;
    }
    /* Keep locked window state aside; surgically corrupt adoption tail after a committing entry may exist */
    const entries = parseJsonl(paths.adoption);
    if (entries.length === 0) {
      /* before-swap crash may still have appended committing entry depending on phase — if none, inject garbage */
      fs.writeFileSync(paths.adoption, JSON.stringify({
        schema_version: "1.0",
        seq: 1,
        txid: "deadbeefdeadbeef",
        status: "effective",
        fingerprint: "b".repeat(64),
        kind: "doc",
        evidence_ref: "hostile",
        human: { name: "x", decision: "y", ts: "z" },
        prev_sha256: null,
        entry_sha256: "c".repeat(64),
      }) + "\n");
    } else {
      const last = { ...entries[entries.length - 1] };
      last.entry_sha256 = "d".repeat(64);
      const lines = entries.slice(0, -1).map((e) => JSON.stringify(e));
      lines.push(JSON.stringify(last));
      fs.writeFileSync(paths.adoption, lines.join("\n") + "\n");
    }

    let rec;
    try {
      promoteMod.recover(root);
      rec = { ok: true };
    } catch (e) {
      rec = { ok: false, code: e.code, message: e.message, evidence: e.evidence };
    }
    if (rec.ok) {
      /* Check whether chain is still used as trusted without re-verify — reading promote's own walk */
      const second = catchPromote(() => {
        closeWindow(root);
        return promote(testPacket(root, "after-corrupt-head", {
          edits: [{
            schema_version: SCHEMA_VERSION,
            schema_ref: "toctou",
            file: "graphsmith.learned.md",
            anchor: "alpha",
            op: "replace",
            payload: "after",
          }],
        }));
      });
      if (second.ok && second.result.state === "DONE") {
        fail(name, "promote DONE after corrupted adoption head (silent trust)");
      } else {
        pass(name, `recover ok but subsequent refused code=${second.code}`);
      }
    } else if (rec.code === "HALT" || rec.code === "CORRUPT_STATE") {
      pass(name, `code=${rec.code} evidence=${!!rec.evidence}`);
    } else {
      pass(name, `refused code=${rec.code}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 4. Staged tree mutated after STAGE_DONE / before validation         */
/* ------------------------------------------------------------------ */
function race_stagedTreeMutation() {
  const name = "staged-tree-mutation-detected";
  try {
    const root = mk("staged");
    const { paths } = createFixture(root);
    const crash = catchPromote(() =>
      promote(testPacket(root, "staged-mut", { __test_crash_at: "before-swap" }))
    );
    if (crash.code !== "SIMULATED_CRASH") {
      fail(name, `setup: ${crash.code}`);
      return;
    }
    const journal = parseJsonl(paths.journal);
    const staged = [...journal].reverse().find((r) => r.record_type === "STAGE_DONE");
    if (!staged || !staged.tree) {
      fail(name, "no STAGE_DONE in journal");
      return;
    }
    const treeDir = path.join(paths.evolvable, staged.tree);
    const learned = path.join(treeDir, "graphsmith.learned.md");
    if (!fs.existsSync(learned)) {
      fail(name, `staged learned missing at ${learned}`);
      return;
    }
    fs.writeFileSync(learned, "HOSTILE-STAGED-BYTES\n");
    const v = verifyTree(path.join(treeDir, "tree.manifest.json"), treeDir);
    if (v.ok === true) {
      fail(name, "verifyTree still ok after staged mutation");
      return;
    }
    let rec;
    try {
      promoteMod.recover(root);
      rec = { ok: true };
    } catch (e) {
      rec = { ok: false, code: e.code, message: e.message, evidence: e.evidence };
    }
    if (rec.ok) {
      const active = readActive(paths);
      if (active.pointer.tree === staged.tree) {
        fail(name, "recover DONE/ok installed mutated staged tree as ACTIVE");
      } else {
        pass(name, `did not install mutated tree; active=${active.pointer.tree}`);
      }
    } else if (rec.code === "HALT" || rec.code === "CORRUPT_STATE") {
      pass(name, `code=${rec.code} verifyOk=${v.ok}`);
    } else {
      pass(name, `refused code=${rec.code} verifyOk=${v.ok}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 5. verify never reports verified on mid-flight mutated tree          */
/* ------------------------------------------------------------------ */
function race_verifyMidFlight() {
  const name = "verify-never-ok-on-mutated-active-tree";
  try {
    const root = mk("ver-mid");
    const { paths, tree } = createFixture(root);
    /* Healthy verify is not the attack — mutate payload under ACTIVE again */
    const treeDir = path.join(paths.evolvable, tree);
    fs.writeFileSync(path.join(treeDir, "graphsmith.learned.md"), "MID-FLIGHT\n");
    const report = runIntegrity(root, {});
    const treeStatus = report.checks.active_tree.status;
    const exit = integrityExitCode(report);
    if (treeStatus === "ok" || report.failure_domain === "none" || exit === 0) {
      fail(name, `FALSE VERIFIED tree=${treeStatus} domain=${report.failure_domain} exit=${exit}`);
    } else {
      pass(name, `tree=${treeStatus} domain=${report.failure_domain} exit=${exit}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 6. expected_active_sha CAS (stale proposal) — control, not TOCTOU   */
/* ------------------------------------------------------------------ */
function race_staleProposal() {
  const name = "stale-expected-active-sha-refused";
  try {
    const root = mk("stale");
    createFixture(root);
    const res = catchPromote(() =>
      promote(testPacket(root, "stale", { expected_active_sha: "0".repeat(64) }))
    );
    if (!res.ok && res.code === "STALE_PROPOSAL") {
      pass(name, `code=${res.code}`);
    } else if (res.ok) {
      fail(name, "stale proposal accepted");
    } else {
      fail(name, `want STALE_PROPOSAL got ${res.code}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 7. Interleaved promote while lock held (second writer)               */
/* ------------------------------------------------------------------ */
function race_lockHeldSecondWriter() {
  const name = "second-writer-while-lock-held";
  try {
    const root = mk("lock");
    createFixture(root);
    const store = createStore(root);
    const lock = store._testing.acquireLock();
    let child;
    try {
      const packetPath = path.join(root, "p.json");
      fs.writeFileSync(packetPath, JSON.stringify(testPacket(root, "locked")));
      child = spawnSync(
        process.execPath,
        [path.join(REPO, "scripts", "promote.js"), "promote", packetPath],
        {
          encoding: "utf8",
          env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
          timeout: 15000,
        }
      );
    } finally {
      clearInterval(lock.heartbeat);
      store._testing.releaseLock(lock.ownerToken);
    }
    /* Second writer must not exit 0 DONE while lock held */
    if (child.status === 0) {
      fail(name, `second writer exit 0 while lock held stdout=${(child.stdout || "").slice(0, 80)}`);
    } else {
      pass(name, `exit=${child.status}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 8. resolveActive pinning: mutate ACTIVE after resolve, before load   */
/* ------------------------------------------------------------------ */
function race_resolveThenMutate() {
  const name = "resolveActive-pin-then-ACTIVE-swap";
  try {
    const root = mk("pin");
    const { paths, tree, pointer } = createFixture(root);
    const ctx = resolveActive(root);
    if (ctx.treeId !== tree) {
      fail(name, `resolve mismatch ${ctx.treeId}`);
      return;
    }
    /* Build a second tree and point ACTIVE at it AFTER resolve (simulates promotion mid-run) */
    const seed2 = path.join(paths.evolvable, "seed2");
    fs.mkdirSync(seed2, { recursive: true });
    fs.writeFileSync(path.join(seed2, "graphsmith.learned.md"), "beta\n");
    fs.writeFileSync(path.join(seed2, "tunables.json"), "{\n  \"limit\": 2\n}\n");
    fs.mkdirSync(path.join(seed2, "workers"), { recursive: true });
    fs.writeFileSync(path.join(seed2, "workers", "demo.prompt.md"), "other\n");
    const m2 = generate("tree", { rootDir: seed2 });
    const m2b = Buffer.from(`${JSON.stringify(m2, null, 2)}\n`);
    fs.writeFileSync(path.join(seed2, "tree.manifest.json"), m2b);
    const tree2 = `v-${sha256(m2b)}`;
    fs.renameSync(seed2, path.join(paths.evolvable, tree2));
    const p2 = {
      schema_version: SCHEMA_VERSION,
      txid: "1".repeat(16),
      tree: tree2,
      tree_manifest_sha256: sha256(m2b),
    };
    fs.writeFileSync(paths.active, pointerBytes(p2));
    /* Loader must still read FROM pinned ctx.treeDir, not re-resolve */
    const appendix = loaders.loadAppendix(ctx);
    const stillPinned =
      !appendix.quarantined &&
      ctx.treeDir.endsWith(tree) &&
      fs.readFileSync(path.join(ctx.treeDir, "graphsmith.learned.md"), "utf8") === "alpha\n";
    if (stillPinned && appendix.treeId === tree) {
      pass(name, `pinned treeId=${appendix.treeId} newACTIVE=${tree2}`);
    } else if (appendix.quarantined) {
      /* quarantine is also safe; must not return new tree content through old ctx */
      pass(name, `quarantined under pin reason=${appendix.reason}`);
    } else {
      fail(name, `ctx leaked or switched: treeId=${appendix.treeId}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 9. Platform-true concurrent rename races — document if unprovable    */
/* ------------------------------------------------------------------ */
function race_trueParallelRename() {
  const name = "true-parallel-rename-race";
  /* On Windows and single-threaded Node, simultaneous same-file renames
   * under two processes are not reliably schedulable inside this harness
   * without flaking. We probe whether the platform can express the race at
   * all; if not, mark UNAVAILABLE (never green).
   */
  try {
    const dir = mk("parallel");
    const a = path.join(dir, "a.txt");
    const b = path.join(dir, "b.txt");
    const t = path.join(dir, "target.txt");
    fs.writeFileSync(a, "A");
    fs.writeFileSync(b, "B");
    /* Sequential "race" is not a real race — declare unavailable rather than green */
    unavailable(
      name,
      "inherently unprovable in single-threaded interleaved harness; multi-process rename-vs-rename under open handles is platform-probe territory (verify --platform-probe), not claimed green here"
    );
  } catch (e) {
    unavailable(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
function main() {
  console.log("=== TOCTOU race harness ===");
  race_postBeginActiveMutation();
  race_mutateBetweenValidateAndSwap();
  race_logHeadMutation();
  race_stagedTreeMutation();
  race_verifyMidFlight();
  race_staleProposal();
  race_lockHeldSecondWriter();
  race_resolveThenMutate();
  race_trueParallelRename();

  const fails = results.filter((r) => r.status === "FAIL");
  const passes = results.filter((r) => r.status === "PASS");
  const unav = results.filter((r) => r.status === "UNAVAILABLE");
  console.log(`--- summary total=${results.length} pass=${passes.length} fail=${fails.length} unavailable=${unav.length} ---`);
  if (priorMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
  else process.env.GRAPHSMITH_TEST_MODE = priorMode;
  rmAll();
  process.exit(fails.length ? 1 : 0);
}

main();
