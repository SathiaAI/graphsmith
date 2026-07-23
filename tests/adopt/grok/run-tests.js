#!/usr/bin/env node
/* Adversarial suite for scripts/adopt.js — family: grok
 * Lane: tests/adopt/grok/ only. Do NOT modify scripts/.
 * Temp project dirs only. Zero-dep CJS. Exit 1 if ANY FAIL.
 * Verdicts from on-disk state (ACTIVE / adoption-log / pending), never log strings.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..").replace(/\\/g, "/");
const ADOPT_CLI = path.join(REPO_ROOT, "scripts", "adopt.js");
const adoptMod = require(path.join(REPO_ROOT, "scripts", "adopt.js"));
const { generate } = require(path.join(REPO_ROOT, "scripts", "manifest.js"));
const { createStore } = require(path.join(REPO_ROOT, "scripts", "state-store.js"));
const { SCHEMA_VERSION: PROMOTE_SCHEMA } = require(path.join(REPO_ROOT, "scripts", "promote.js"));

const { listPending, adopt, observe, close, pendingProposalsPath } = adoptMod;
const SCHEMA_VERSION = PROMOTE_SCHEMA || "1.0";

const results = [];
const tempRoots = [];
const priorTestMode = process.env.GRAPHSMITH_TEST_MODE;
process.env.GRAPHSMITH_TEST_MODE = "1";

function sha256(value) {
  return crypto.createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
}

function record(name, status, detail) {
  results.push({ name, status, detail: detail === undefined ? "" : String(detail) });
  const d = detail ? `\t${String(detail).replace(/\s+/g, " ").slice(0, 320)}` : "";
  console.log(`${status}\t${name}${d}`);
}
function pass(name, detail) { record(name, "PASS", detail); }
function fail(name, detail) { record(name, "FAIL", detail); }
function skip(name, detail) { record(name, "SKIPPED", detail); }

function mkRoot(tag) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `gs-adopt-grok-${tag}-`));
  tempRoots.push(root);
  return root;
}

function fwd(p) {
  return String(p).replace(/\\/g, "/");
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
    pending: path.join(state, "pending-proposals.jsonl"),
  };
}

function readUtf(file) {
  try { return fs.readFileSync(file, "utf8"); }
  catch (e) {
    if (e.code === "ENOENT") return "";
    throw e;
  }
}

function readBuf(file) {
  try { return fs.readFileSync(file); }
  catch (e) {
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

function snaphotDisk(paths) {
  return {
    active: readBuf(paths.active).toString("hex"),
    adoption: readUtf(paths.adoption),
    pending: readUtf(paths.pending),
    window: readUtf(paths.window),
    journal: readUtf(paths.journal),
    manifest: readUtf(paths.projectManifest),
  };
}

function diskUnchanged(before, after, keys) {
  const ks = keys || Object.keys(before);
  for (const k of ks) {
    if (before[k] !== after[k]) return `changed:${k}`;
  }
  return null;
}

function createFixture(root) {
  const paths = locations(root);
  fs.mkdirSync(paths.state, { recursive: true });
  fs.mkdirSync(paths.evolvable, { recursive: true });
  const seed = path.join(paths.evolvable, "seed");
  fs.mkdirSync(seed);
  fs.writeFileSync(path.join(seed, "graphsmith.learned.md"), "alpha\n__GS_SLOT__\n");
  fs.writeFileSync(path.join(seed, "tunables.json"), "{\n  \"limit\": 1\n}\n");
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
  fs.writeFileSync(paths.active, Buffer.from(`${JSON.stringify(pointer, null, 2)}\n`, "utf8"));
  fs.writeFileSync(paths.projectManifest, `${JSON.stringify({
    schema_version: SCHEMA_VERSION,
    kind: "project",
    generated_at: "grok-adopt-test",
    parent_release_sha256: null,
    adoption_log_head: null,
    active_tree: tree,
    active_tree_manifest_sha256: sha256(manifestBytes),
    files: [],
    workflow_manifests: [],
  }, null, 2)}\n`);
  return { paths, tree, pointer };
}

function stageProposal(paths, tag, extra = {}) {
  const fingerprint = sha256(`grok-adopt:${tag}`);
  const record = {
    schema_version: SCHEMA_VERSION,
    proposal_id: fingerprint,
    status: "PENDING_HUMAN_REVIEW",
    fingerprint,
    kind: "doc",
    edits: [{
      schema_version: SCHEMA_VERSION,
      schema_ref: "grok-adopt-test",
      file: "graphsmith.learned.md",
      anchor: "__GS_SLOT__",
      op: "replace",
      payload: `\n## adopted:${tag}\n__GS_SLOT__\n`,
    }],
    gate3: {
      diff: ["doc edit"],
      plainEnglish: `test proposal ${tag}`,
      evidence: { tag },
      inverse: [{
        schema_version: SCHEMA_VERSION,
        schema_ref: "grok-adopt-test",
        file: "graphsmith.learned.md",
        anchor: `__GS_SLOT__`,
        op: "replace",
        payload: "__GS_SLOT__",
      }],
      reversible: true,
      autoRollbackEligible: true,
    },
    ...extra,
  };
  fs.mkdirSync(path.dirname(paths.pending), { recursive: true });
  fs.appendFileSync(paths.pending, JSON.stringify(record) + "\n");
  return record;
}

function isRefusedClean(result, reasonHint) {
  if (!result || result.adopted !== false || result.refused !== true) return `not-refused:${JSON.stringify(result)}`;
  if (reasonHint && result.reason !== reasonHint && !String(result.reason || "").includes(reasonHint)) {
    /* reason may vary; disk checks are authoritative */
  }
  return null;
}

function runCli(args, projectRoot) {
  const full = ["adopt", ...args];
  const r = spawnSync(process.execPath, [ADOPT_CLI, ...full], {
    encoding: "utf8",
    env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
    cwd: projectRoot || process.cwd(),
    timeout: 60000,
  });
  return r;
}

function runCliRaw(argv, projectRoot) {
  return spawnSync(process.execPath, [ADOPT_CLI, ...argv], {
    encoding: "utf8",
    env: { ...process.env, GRAPHSMITH_TEST_MODE: "1" },
    cwd: projectRoot || process.cwd(),
    timeout: 60000,
  });
}

/* =========================================================================
 * 1. Confirmation cannot be bypassed (THE guarantee)
 * ========================================================================= */
function attack_confirmation_bypass() {
  const root = mkRoot("confirm");
  const { paths } = createFixture(root);
  const prop = stageProposal(paths, "confirm-base");
  const before = snaphotDisk(paths);

  const cases = [
    { name: "api-no-opts", call: () => adopt(root, prop.proposal_id) },
    { name: "api-empty-opts", call: () => adopt(root, prop.proposal_id, {}) },
    { name: "api-confirm-false", call: () => adopt(root, prop.proposal_id, { confirm: false }) },
    { name: "api-confirm-undefined", call: () => adopt(root, prop.proposal_id, { confirm: undefined }) },
    { name: "api-confirm-string-false", call: () => adopt(root, prop.proposal_id, { confirm: "false" }) },
    { name: "api-confirm-string-true", call: () => adopt(root, prop.proposal_id, { confirm: "true" }) },
    { name: "api-confirm-0", call: () => adopt(root, prop.proposal_id, { confirm: 0 }) },
    { name: "api-confirm-1", call: () => adopt(root, prop.proposal_id, { confirm: 1 }) },
    { name: "api-confirm-yes-string", call: () => adopt(root, prop.proposal_id, { confirm: "yes" }) },
    { name: "api-confirm-empty-object", call: () => adopt(root, prop.proposal_id, { confirm: {} }) },
    { name: "api-confirm-array-1", call: () => adopt(root, prop.proposal_id, { confirm: [1] }) },
    { name: "api-confirm-null", call: () => adopt(root, prop.proposal_id, { confirm: null }) },
    { name: "api-yes-false", call: () => adopt(root, prop.proposal_id, { yes: false }) },
    { name: "api-yes-string-true", call: () => adopt(root, prop.proposal_id, { yes: "true" }) },
    { name: "api-yes-1", call: () => adopt(root, prop.proposal_id, { yes: 1 }) },
    { name: "api-confirmTrue-as-string-key-smuggle", call: () => adopt(root, prop.proposal_id, { "confirm": "true", yes: "yes" }) },
    {
      name: "api-opts-null",
      call: () => {
        try {
          return adopt(root, prop.proposal_id, null);
        } catch (e) {
          return { __threw: true, message: e.message, code: e.code };
        }
      },
    },
    {
      name: "api-extra-arg-true-smuggle",
      call: () => adopt(root, prop.proposal_id, {}, true),
    },
    {
      name: "api-confirm-object-true-box",
      call: () => adopt(root, prop.proposal_id, { confirm: Object(true) }),
    },
  ];

  for (const c of cases) {
    let result;
    try {
      result = c.call();
    } catch (e) {
      result = { __threw: true, message: e.message, code: e.code };
    }
    const after = snaphotDisk(paths);
    const mutated = diskUnchanged(before, after, ["active", "adoption", "pending", "window", "journal", "manifest"]);
    if (result && result.adopted === true) {
      fail(`confirm-bypass:${c.name}`, `ADOPTED without strict confirm: ${JSON.stringify(result)}`);
      return;
    }
    if (mutated) {
      fail(`confirm-bypass:${c.name}`, `on-disk mutation without confirm (${mutated})`);
      return;
    }
    if (c.name === "api-opts-null") {
      /* Prefer clean refuse over throw; throw without mutation is fail-closed-ish but contract says refuse */
      if (result && result.__threw) {
        fail(`confirm-bypass:${c.name}`, `throws instead of refuse when opts=null: ${result.message}`);
      } else if (isRefusedClean(result)) {
        fail(`confirm-bypass:${c.name}`, isRefusedClean(result));
      } else {
        pass(`confirm-bypass:${c.name}`, result.reason || "refused");
      }
      continue;
    }
    const bad = isRefusedClean(result, "ADOPTION_REQUIRES_HUMAN_CONFIRMATION");
    if (bad && !(result && result.refused === true && result.adopted === false)) {
      fail(`confirm-bypass:${c.name}`, bad || JSON.stringify(result));
    } else if (result && result.reason && result.reason !== "ADOPTION_REQUIRES_HUMAN_CONFIRMATION") {
      /* still ok if refused + no disk change */
      if (result.adopted === false && result.refused === true) {
        pass(`confirm-bypass:${c.name}`, result.reason);
      } else {
        fail(`confirm-bypass:${c.name}`, JSON.stringify(result));
      }
    } else {
      pass(`confirm-bypass:${c.name}`, result && result.reason);
    }
  }

  /* still pending */
  const pending = listPending(root);
  if (!pending.some((p) => p.proposal_id === prop.proposal_id)) {
    fail("confirm-bypass:still-pending", "proposal disappeared without adopt");
  } else {
    pass("confirm-bypass:still-pending", "proposal remains PENDING_HUMAN_REVIEW");
  }
}

function attack_cli_without_yes() {
  const root = mkRoot("cli-no-yes");
  const { paths } = createFixture(root);
  const prop = stageProposal(paths, "cli-no-yes");
  const before = snaphotDisk(paths);

  const variants = [
    { name: "cli-adopt-no-flags", argv: ["adopt", prop.proposal_id, "--project-root", root] },
    { name: "cli-adopt-confirm-flag-only", argv: ["adopt", prop.proposal_id, "--confirm", "--project-root", root] },
    { name: "cli-adopt-yes-equals-true", argv: ["adopt", prop.proposal_id, "--yes=true", "--project-root", root] },
    { name: "cli-adopt-yes-false-token", argv: ["adopt", prop.proposal_id, "--yes", "false", "--project-root", root] },
  ];

  for (const v of variants) {
    const r = runCliRaw(v.argv, root);
    const after = snaphotDisk(paths);
    const mutated = diskUnchanged(before, after, ["active", "adoption", "pending", "window", "journal", "manifest"]);
    let body = null;
    try { body = JSON.parse((r.stdout || "").trim() || "null"); } catch (_) { body = null; }

    /* --yes with trailing "false": parseFlags sets yes=true on bare --yes and
     * treats "false" as a positional arg — real confirmation-trap if it adopts. */
    if (v.name === "cli-adopt-yes-false-token") {
      if ((body && body.adopted === true) || mutated) {
        fail(
          `cli-confirm:${v.name}`,
          `CONFIRMATION TRAP: argv [adopt, id, --yes, false] adopted (parseFlags ignores trailing false). adopted=${body && body.adopted} mut=${mutated || "none"} exit=${r.status}`
        );
      } else {
        pass(`cli-confirm:${v.name}`, `exit=${r.status} adopted=${body && body.adopted}`);
      }
      continue;
    }

    if (mutated) {
      fail(`cli-confirm:${v.name}`, `disk mutated without --yes (${mutated}); exit=${r.status}`);
      continue;
    }
    if (body && body.adopted === true) {
      fail(`cli-confirm:${v.name}`, `CLI adopted without --yes: ${JSON.stringify(body)}`);
    } else if (r.status === 0 && body && body.adopted) {
      fail(`cli-confirm:${v.name}`, `exit 0 adopted`);
    } else {
      pass(`cli-confirm:${v.name}`, `exit=${r.status} refused_or_error disk-clean`);
    }
  }

  /* Positive control: --yes must be able to adopt (separate root) */
  const root2 = mkRoot("cli-yes");
  const fx2 = createFixture(root2);
  const prop2 = stageProposal(fx2.paths, "cli-yes-ok");
  const before2 = snaphotDisk(fx2.paths);
  const r2 = runCliRaw(["adopt", prop2.proposal_id, "--yes", "--project-root", root2, "--window-n", "1"], root2);
  let body2 = null;
  try { body2 = JSON.parse((r2.stdout || "").trim() || "null"); } catch (_) {}
  const after2 = snaphotDisk(fx2.paths);
  if (!(body2 && body2.adopted === true && r2.status === 0)) {
    fail("cli-confirm:cli-with-yes-adopts", `expected adopt: exit=${r2.status} body=${JSON.stringify(body2)} err=${(r2.stderr || "").slice(0, 200)}`);
  } else if (before2.active === after2.active) {
    fail("cli-confirm:cli-with-yes-adopts", "ACTIVE unchanged after confirmed CLI adopt");
  } else {
    pass("cli-confirm:cli-with-yes-adopts", `txid=${body2.txid}`);
  }
}

/* =========================================================================
 * 2. Only-path / no side-channel: list/observe/close never adopt
 * ========================================================================= */
function attack_list_observe_close_no_adopt() {
  const root = mkRoot("sidefx");
  const { paths } = createFixture(root);
  const prop = stageProposal(paths, "sidefx");
  const before = snaphotDisk(paths);

  let listed;
  try {
    listed = listPending(root);
  } catch (e) {
    fail("sidefx:listPending", e.message);
    return;
  }
  const afterList = snaphotDisk(paths);
  const m1 = diskUnchanged(before, afterList, ["active", "adoption", "pending", "window", "journal", "manifest"]);
  if (m1) fail("sidefx:listPending-readonly", m1);
  else if (!listed.some((p) => p.proposal_id === prop.proposal_id)) fail("sidefx:listPending", "proposal not listed");
  else pass("sidefx:listPending-readonly", `n=${listed.length}`);

  /* CLI list */
  const rList = runCliRaw(["list", "--project-root", root], root);
  const afterCliList = snaphotDisk(paths);
  const mCli = diskUnchanged(before, afterCliList, ["active", "adoption", "pending", "window", "journal", "manifest"]);
  if (mCli) fail("sidefx:cli-list-readonly", mCli);
  else pass("sidefx:cli-list-readonly", `exit=${rList.status}`);

  /* observe with no window should not adopt / should not flip ACTIVE */
  let obsErr = null;
  try {
    observe(root, "run-x", paths.pointer ? paths.pointer.tree : "v-none");
  } catch (e) {
    obsErr = e;
  }
  /* re-read tree from ACTIVE */
  const treeId = JSON.parse(readUtf(paths.active)).tree;
  try {
    observe(root, "run-no-window", treeId);
  } catch (e) {
    obsErr = e;
  }
  const afterObs = snaphotDisk(paths);
  if (afterObs.active !== before.active || afterObs.adoption !== before.adoption || afterObs.pending !== before.pending) {
    fail("sidefx:observe-no-adopt", "observe mutated ACTIVE/adoption/pending");
  } else {
    pass("sidefx:observe-no-adopt", obsErr ? `threw:${obsErr.message}` : "ok");
  }

  /* close with no window should not adopt */
  let closeErr = null;
  try {
    close(root, "0".repeat(16), "pass");
  } catch (e) {
    closeErr = e;
  }
  const afterClose = snaphotDisk(paths);
  if (afterClose.active !== before.active || afterClose.adoption !== before.adoption || afterClose.pending !== before.pending) {
    fail("sidefx:close-no-adopt", "close mutated ACTIVE/adoption/pending");
  } else {
    pass("sidefx:close-no-adopt", closeErr ? `threw:${closeErr.code || closeErr.message}` : "ok");
  }

  /* propose that listPending path never calls promote: freeze pending content */
  if (afterClose.pending !== before.pending) {
    fail("sidefx:pending-immutable-via-list-obs-close", "pending file mutated");
  } else {
    pass("sidefx:pending-immutable-via-list-obs-close", "pending unchanged");
  }
}

/* Static only-path check: adopt.js is the only scripts/ caller of promoteApi.promote / promote(packet) from pending */
function attack_only_path_static() {
  const scriptsDir = path.join(REPO_ROOT, "scripts");
  const files = fs.readdirSync(scriptsDir).filter((f) => f.endsWith(".js"));
  const offenders = [];
  for (const f of files) {
    if (f === "adopt.js" || f === "promote.js") continue;
    const src = fs.readFileSync(path.join(scriptsDir, f), "utf8");
    /* Direct promote-from-pending channel: module promotes a staged proposal */
    const callsPromoteExport =
      /promoteApi\.promote\s*\(/.test(src) ||
      /require\s*\(\s*["']\.\/promote(?:\.js)?["']\s*\)[\s\S]{0,200}\.promote\s*\(/.test(src);
    if (f === "evolve.js") {
      if (callsPromoteExport || /\.promote\s*\(\s*\{/.test(src) && /pending-proposals/.test(src)) {
        offenders.push(`${f}:calls-promote-export`);
      }
      /* recover() is allowed for crash recovery; promote() is not */
      continue;
    }
    if (callsPromoteExport && /pending-proposals\.jsonl|PENDING_HUMAN_REVIEW/.test(src)) {
      offenders.push(`${f}:pending+promote`);
    }
  }
  if (offenders.length) fail("only-path:static-no-side-channel", offenders.join(","));
  else pass("only-path:static-no-side-channel", "no other script pairs pending+promote()");

  /* listPending source must not write */
  const adoptSrc = fs.readFileSync(path.join(scriptsDir, "adopt.js"), "utf8");
  const listFn = adoptSrc.match(/function listPending\([\s\S]*?\n\}/);
  if (!listFn) {
    fail("only-path:listPending-no-write", "could not locate listPending");
  } else if (/writeFile|appendFile|openSync\([^)]*["']a["']|renameSync|rmSync/.test(listFn[0])) {
    fail("only-path:listPending-no-write", "listPending contains write primitives");
  } else {
    pass("only-path:listPending-no-write", "read-only body");
  }

  /* evolve must not call promote() */
  const evolveSrc = fs.readFileSync(path.join(scriptsDir, "evolve.js"), "utf8");
  if (/promoteApi\.promote\s*\(/.test(evolveSrc)) {
    fail("only-path:evolve-never-promote", "evolve calls promoteApi.promote");
  } else {
    pass("only-path:evolve-never-promote", "evolve only recover() if anything");
  }
}

/* =========================================================================
 * 3. Double-adopt / tombstone / sibling integrity
 * ========================================================================= */
function attack_double_adopt() {
  const root = mkRoot("double");
  const { paths } = createFixture(root);
  const propA = stageProposal(paths, "double-A");
  const propB = stageProposal(paths, "double-B");
  const pendingBefore = readUtf(paths.pending);

  const first = adopt(root, propA.proposal_id, { confirm: true, windowN: 1 });
  if (!(first && first.adopted === true)) {
    fail("double-adopt:first", JSON.stringify(first));
    return;
  }
  pass("double-adopt:first", `txid=${first.txid}`);

  const pendingMid = parseJsonl(paths.pending);
  const aRecords = pendingMid.filter((r) => r.proposal_id === propA.proposal_id);
  const bRecords = pendingMid.filter((r) => r.proposal_id === propB.proposal_id);
  if (!aRecords.some((r) => r.status === "ADOPTED")) {
    fail("double-adopt:tombstone", `no ADOPTED tombstone: ${JSON.stringify(aRecords)}`);
  } else {
    pass("double-adopt:tombstone", `A records=${aRecords.length}`);
  }
  if (!(bRecords.length === 1 && bRecords[0].status === "PENDING_HUMAN_REVIEW")) {
    fail("double-adopt:sibling-intact", JSON.stringify(bRecords));
  } else {
    pass("double-adopt:sibling-intact", "B still pending");
  }

  /* original staging line retained (append-only) */
  if (!readUtf(paths.pending).includes(pendingBefore.trim().split("\n")[0])) {
    fail("double-adopt:append-only", "original pending line rewritten/removed");
  } else {
    pass("double-adopt:append-only", "staging lines preserved");
  }

  const activeAfterFirst = readUtf(paths.active);
  const adoptionAfterFirst = readUtf(paths.adoption);
  const second = adopt(root, propA.proposal_id, { confirm: true, windowN: 1 });
  if (!(second && second.adopted === false && second.refused === true)) {
    fail("double-adopt:second-refused", JSON.stringify(second));
  } else {
    pass("double-adopt:second-refused", second.reason || "refused");
  }
  if (readUtf(paths.active) !== activeAfterFirst || readUtf(paths.adoption) !== adoptionAfterFirst) {
    fail("double-adopt:second-no-mutate", "second adopt mutated ACTIVE or adoption-log");
  } else {
    pass("double-adopt:second-no-mutate", "ACTIVE+log stable");
  }

  const pendingList = listPending(root);
  if (pendingList.some((p) => p.proposal_id === propA.proposal_id)) {
    fail("double-adopt:A-not-listed", "adopted A still in listPending");
  } else if (!pendingList.some((p) => p.proposal_id === propB.proposal_id)) {
    fail("double-adopt:B-still-listed", "sibling B missing from listPending");
  } else {
    pass("double-adopt:list-consistency", "A gone, B pending");
  }
}

/* =========================================================================
 * 4. Malformed / hostile pending file
 * ========================================================================= */
function attack_malformed_pending() {
  /* mid-file corrupt JSONL */
  {
    const root = mkRoot("corrupt-mid");
    const { paths } = createFixture(root);
    const good = stageProposal(paths, "corrupt-good");
    fs.appendFileSync(paths.pending, "{not-json\n");
    fs.appendFileSync(paths.pending, JSON.stringify({
      proposal_id: sha256("after-corrupt"),
      status: "PENDING_HUMAN_REVIEW",
      fingerprint: sha256("after-corrupt"),
      kind: "doc",
      edits: [],
      gate3: { reversible: true, autoRollbackEligible: true, diff: [], plainEnglish: "x", inverse: [] },
    }) + "\n");
    const before = snaphotDisk(paths);
    let threw = null;
    let result = null;
    try {
      result = adopt(root, good.proposal_id, { confirm: true, windowN: 1 });
    } catch (e) {
      threw = e;
    }
    const after = snaphotDisk(paths);
    const mut = diskUnchanged(before, after, ["active", "adoption", "manifest"]);
    if (result && result.adopted === true) {
      fail("malformed:mid-file-corrupt", `partial adopt succeeded: ${JSON.stringify(result)}`);
    } else if (mut) {
      fail("malformed:mid-file-corrupt", `partial disk mutation: ${mut}`);
    } else if (threw && threw.code === "CORRUPT_STATE") {
      pass("malformed:mid-file-corrupt", "fail-closed CORRUPT_STATE");
    } else if (threw) {
      pass("malformed:mid-file-corrupt", `fail-closed throw:${threw.code || threw.message}`);
    } else if (result && result.refused) {
      pass("malformed:mid-file-corrupt", `refused:${result.reason}`);
    } else {
      fail("malformed:mid-file-corrupt", `unexpected: ${JSON.stringify(result)}`);
    }

    /* listPending should also fail-closed, not return partial silently-wrong */
    let listThrew = null;
    let listed = null;
    try { listed = listPending(root); } catch (e) { listThrew = e; }
    if (listThrew && listThrew.code === "CORRUPT_STATE") {
      pass("malformed:list-mid-corrupt-fail-closed", listThrew.message.slice(0, 120));
    } else if (listThrew) {
      pass("malformed:list-mid-corrupt-fail-closed", listThrew.message.slice(0, 120));
    } else {
      fail("malformed:list-mid-corrupt-fail-closed", `returned ${JSON.stringify(listed)}`);
    }
  }

  /* torn tail (incomplete last line) should not crash; prior good lines usable */
  {
    const root = mkRoot("torn-tail");
    const { paths } = createFixture(root);
    const good = stageProposal(paths, "torn-good");
    fs.appendFileSync(paths.pending, '{"proposal_id":"torn');
    const before = snaphotDisk(paths);
    let result;
    let threw = null;
    try {
      result = adopt(root, good.proposal_id, { confirm: true, windowN: 1 });
    } catch (e) {
      threw = e;
    }
    if (threw) {
      fail("malformed:torn-tail-no-crash", threw.message);
    } else if (!(result && result.adopted === true)) {
      /* torn trail ignored; good proposal should still adopt */
      fail("malformed:torn-tail-no-crash", `expected adopt of good line: ${JSON.stringify(result)}`);
    } else {
      pass("malformed:torn-tail-no-crash", `adopted good despite torn tail txid=${result.txid}`);
    }
    void before;
  }

  /* injection-shaped fields */
  {
    const root = mkRoot("inject");
    const { paths } = createFixture(root);
    const fp = sha256("inject-proto");
    /* write carefully without prototype pollution in this process */
    const line = JSON.stringify({
      schema_version: SCHEMA_VERSION,
      proposal_id: fp,
      status: "PENDING_HUMAN_REVIEW",
      fingerprint: fp,
      kind: "doc",
      edits: [{
        schema_version: SCHEMA_VERSION,
        schema_ref: "x",
        file: "graphsmith.learned.md",
        anchor: "__GS_SLOT__",
        op: "replace",
        payload: "ok-payload-inject",
      }],
      gate3: {
        reversible: true,
        autoRollbackEligible: true,
        diff: ["x"],
        plainEnglish: "<script>alert(1)</script>",
        inverse: [],
        evidence: { evil: "../../../etc/passwd" },
      },
      nested: { "__proto__": { x: 1 } },
    });
    fs.appendFileSync(paths.pending, line + "\n");
    const before = snaphotDisk(paths);
    let result;
    let threw = null;
    try {
      result = adopt(root, fp, { confirm: true, windowN: 1 });
    } catch (e) {
      threw = e;
    }
    const after = snaphotDisk(paths);
    /* either clean adopt of payload or clean refuse/throw — never inconsistent half-state */
    if (result && result.adopted === true) {
      const active = JSON.parse(readUtf(paths.active));
      const log = parseJsonl(paths.adoption);
      const eff = log.filter((e) => e.status === "effective");
      if (!active.tree || !eff.length) {
        fail("malformed:injection-shaped", "adopted but missing tree or effective log");
      } else {
        pass("malformed:injection-shaped", "adopt completed consistently despite hostile strings");
      }
    } else {
      const mut = diskUnchanged(before, after, ["active", "adoption", "manifest"]);
      if (mut) fail("malformed:injection-shaped", `partial mutation ${mut} threw=${threw && threw.message}`);
      else pass("malformed:injection-shaped", threw ? `fail-closed:${threw.message.slice(0, 80)}` : `refused:${JSON.stringify(result)}`);
    }
  }

  /* path traversal edit */
  {
    const root = mkRoot("trav");
    const { paths } = createFixture(root);
    const fp = sha256("path-trav");
    fs.appendFileSync(paths.pending, JSON.stringify({
      schema_version: SCHEMA_VERSION,
      proposal_id: fp,
      status: "PENDING_HUMAN_REVIEW",
      fingerprint: fp,
      kind: "doc",
      edits: [{
        schema_version: SCHEMA_VERSION,
        schema_ref: "x",
        file: "../../outside.txt",
        anchor: "a",
        op: "replace",
        payload: "pwn",
      }],
      gate3: { reversible: true, autoRollbackEligible: true, diff: [], plainEnglish: "t", inverse: [] },
    }) + "\n");
    const before = snaphotDisk(paths);
    let result;
    let threw = null;
    try {
      result = adopt(root, fp, { confirm: true, windowN: 1 });
    } catch (e) {
      threw = e;
    }
    const after = snaphotDisk(paths);
    const outside = path.join(root, "outside.txt");
    const escaped = fs.existsSync(outside);
    if (escaped) {
      fail("malformed:path-traversal-edit", "wrote outside tree");
    } else if (result && result.adopted === true) {
      fail("malformed:path-traversal-edit", "adopted traversal edit");
    } else {
      const mut = diskUnchanged(before, after, ["active", "adoption", "manifest"]);
      if (mut) fail("malformed:path-traversal-edit", `partial ${mut}`);
      else pass("malformed:path-traversal-edit", threw ? `threw:${threw.code || threw.message}` : `refused:${result && result.reason}`);
    }
  }

  /* proposal_id missing / non-string skipped by latest map; adopt NOT_FOUND */
  {
    const root = mkRoot("missing-id");
    const { paths } = createFixture(root);
    fs.appendFileSync(paths.pending, JSON.stringify({
      status: "PENDING_HUMAN_REVIEW",
      fingerprint: sha256("no-id"),
      kind: "doc",
      edits: [],
    }) + "\n");
    const before = snaphotDisk(paths);
    const result = adopt(root, sha256("no-id"), { confirm: true });
    const after = snaphotDisk(paths);
    if (result.adopted === true) fail("malformed:missing-proposal-id", "adopted phantom");
    else if (diskUnchanged(before, after, ["active", "adoption"])) fail("malformed:missing-proposal-id", "mutated");
    else pass("malformed:missing-proposal-id", result.reason || "not-found");
  }

  /* empty proposalId argument */
  {
    const root = mkRoot("empty-id");
    const { paths } = createFixture(root);
    const before = snaphotDisk(paths);
    let threw = null;
    try {
      adopt(root, "", { confirm: true });
    } catch (e) {
      threw = e;
    }
    const after = snaphotDisk(paths);
    if (!threw) fail("malformed:empty-proposalId", "did not throw");
    else if (diskUnchanged(before, after, ["active", "adoption", "pending"])) fail("malformed:empty-proposalId", "mutated");
    else pass("malformed:empty-proposalId", threw.code || threw.message);
  }

  /* status spoof: ADOPTED without going through adopt */
  {
    const root = mkRoot("spoof-status");
    const { paths } = createFixture(root);
    const fp = sha256("already-marked");
    fs.appendFileSync(paths.pending, JSON.stringify({
      schema_version: SCHEMA_VERSION,
      proposal_id: fp,
      status: "ADOPTED",
      fingerprint: fp,
      kind: "doc",
      edits: [{
        schema_version: SCHEMA_VERSION,
        schema_ref: "x",
        file: "graphsmith.learned.md",
        anchor: "__GS_SLOT__",
        op: "replace",
        payload: "nope",
      }],
      gate3: { reversible: true, autoRollbackEligible: true, diff: [], plainEnglish: "x", inverse: [] },
    }) + "\n");
    const before = snaphotDisk(paths);
    const result = adopt(root, fp, { confirm: true, windowN: 1 });
    const after = snaphotDisk(paths);
    if (result.adopted === true) fail("malformed:status-spoof-ADOPTED", "re-adopted spoofed record");
    else if (diskUnchanged(before, after, ["active", "adoption"])) fail("malformed:status-spoof-ADOPTED", "mutated");
    else pass("malformed:status-spoof-ADOPTED", result.reason || "refused");
  }
}

/* =========================================================================
 * 5. End-to-end confirmed adopt → Gate-4 → observe → close(pass)
 * ========================================================================= */
function attack_e2e_close_pass() {
  const root = mkRoot("e2e-pass");
  const { paths, tree: baseTree } = createFixture(root);
  const prop = stageProposal(paths, "e2e-pass");

  const refused = adopt(root, prop.proposal_id, { confirm: false });
  if (!(refused.adopted === false && refused.refused === true)) {
    fail("e2e:precheck-refuse", JSON.stringify(refused));
    return;
  }

  const adopted = adopt(root, prop.proposal_id, { confirm: true, windowN: 1, humanName: "grok-tester" });
  if (!(adopted && adopted.adopted === true && adopted.state === "DONE" && adopted.txid)) {
    fail("e2e:adopt-confirmed", JSON.stringify(adopted));
    return;
  }
  pass("e2e:adopt-confirmed", `txid=${adopted.txid}`);

  const active = JSON.parse(readUtf(paths.active));
  if (active.txid !== adopted.txid || active.tree === baseTree) {
    fail("e2e:ACTIVE-new-tree", JSON.stringify(active));
  } else {
    pass("e2e:ACTIVE-new-tree", active.tree);
  }

  const journal = parseJsonl(paths.journal).filter((r) => r.txid === adopted.txid);
  const types = journal.map((r) => r.record_type);
  if (!types.includes("WINDOW_PENDING") || !types.includes("TX_DONE")) {
    fail("e2e:journal-window-pending", types.join(","));
  } else {
    pass("e2e:journal-window-pending", "WINDOW_PENDING+TX_DONE");
  }

  const log = parseJsonl(paths.adoption);
  const effective = log.filter((e) => e.status === "effective");
  const lastEff = effective[effective.length - 1];
  if (!(lastEff && lastEff.fingerprint === prop.fingerprint)) {
    fail("e2e:adoption-log-effective", JSON.stringify(lastEff));
  } else {
    pass("e2e:adoption-log-effective", lastEff.entry_sha256 || "ok");
  }

  const store = createStore(root);
  const win = store.window.get();
  if (!(win.state === "OBSERVING" && win.window && win.window.window_id === adopted.txid && win.window.n === 1)) {
    fail("e2e:window-OBSERVING", JSON.stringify(win));
  } else {
    pass("e2e:window-OBSERVING", `window_id=${win.window.window_id}`);
  }

  /* ADMITTED transition is coupled inside promote; OBSERVING is post-finalize durable state */
  if (!types.includes("WINDOW_FINAL")) {
    fail("e2e:window-admitted-in-tx", "missing WINDOW_FINAL");
  } else {
    pass("e2e:window-admitted-in-tx", "WINDOW_FINAL present");
  }

  const obs = observe(root, "canary-1", active.tree);
  if (!(obs && obs.registration && obs.registration.tree_id === active.tree)) {
    fail("e2e:observe", JSON.stringify(obs));
  } else {
    pass("e2e:observe", "slot claimed");
  }

  const win2 = createStore(root).window.get();
  if (!(win2.window && win2.window.active >= 1 && win2.window.admitted >= 1)) {
    fail("e2e:observe-slot-accounting", JSON.stringify(win2.window));
  } else {
    pass("e2e:observe-slot-accounting", `active=${win2.window.active} admitted=${win2.window.admitted}`);
  }

  createStore(root).runRegistry.deregister("canary-1", {});

  const closed = close(root, adopted.txid, "pass");
  if (!(closed && closed.state === "CLOSED_PASS")) {
    fail("e2e:close-pass", JSON.stringify(closed));
  } else {
    pass("e2e:close-pass", closed.state);
  }

  const finalActive = JSON.parse(readUtf(paths.active));
  if (finalActive.tree !== active.tree) {
    fail("e2e:close-pass-keeps-tree", JSON.stringify(finalActive));
  } else {
    pass("e2e:close-pass-keeps-tree", finalActive.tree);
  }

  if (listPending(root).some((p) => p.proposal_id === prop.proposal_id)) {
    fail("e2e:not-pending-after", "still pending");
  } else {
    pass("e2e:not-pending-after", "consumed");
  }
}

/* =========================================================================
 * 6. close(fail) / rolled_back path semantics
 * ========================================================================= */
function attack_close_fail_semantics() {
  const root = mkRoot("e2e-fail");
  const { paths, tree: baseTree } = createFixture(root);
  const prop = stageProposal(paths, "e2e-fail");
  const adopted = adopt(root, prop.proposal_id, { confirm: true, windowN: 1 });
  if (!(adopted && adopted.adopted === true)) {
    fail("close-fail:setup-adopt", JSON.stringify(adopted));
    return;
  }
  const activeAfter = JSON.parse(readUtf(paths.active));
  const treeAfter = activeAfter.tree;

  /* Fill + terminalize slot so close is allowed */
  observe(root, "canary-fail-1", treeAfter);
  createStore(root).runRegistry.deregister("canary-fail-1", {});

  /* Literal outcome "fail" — contract 02 uses CLOSED_ROLLED_BACK / ROLLING_BACK / FLAG, not free-form "fail".
   * Document actual mapping: non-hard non-special outcomes become CLOSED_PASS (dangerous if callers expect fail). */
  let closedFail;
  let threwFail = null;
  try {
    closedFail = close(root, adopted.txid, "fail");
  } catch (e) {
    threwFail = e;
  }

  if (threwFail) {
    /* Window may already be closable only once; report */
    pass("close-fail:outcome-fail-literal", `threw:${threwFail.code || threwFail.message}`);
  } else if (closedFail && closedFail.state === "CLOSED_PASS") {
    fail(
      "close-fail:outcome-fail-literal",
      "close(..., 'fail') mapped to CLOSED_PASS — callers expecting rollback/fail get a silent pass (contract-02 gap in adopt close forwarding)"
    );
  } else if (closedFail && (closedFail.state === "CLOSED_ROLLED_BACK" || closedFail.state === "ROLLING_BACK" || closedFail.state === "CLOSED_FLAGGED")) {
    pass("close-fail:outcome-fail-literal", closedFail.state);
  } else {
    fail("close-fail:outcome-fail-literal", JSON.stringify(closedFail));
  }

  /* Fresh project for rolled_back outcome */
  const root2 = mkRoot("e2e-rb");
  const fx2 = createFixture(root2);
  const prop2 = stageProposal(fx2.paths, "e2e-rb");
  const ad2 = adopt(root2, prop2.proposal_id, { confirm: true, windowN: 1 });
  if (!(ad2 && ad2.adopted === true)) {
    fail("close-fail:rolled_back-setup", JSON.stringify(ad2));
    return;
  }
  const tree2 = JSON.parse(readUtf(fx2.paths.active)).tree;
  observe(root2, "canary-rb-1", tree2);
  createStore(root2).runRegistry.deregister("canary-rb-1", {});

  const activeBeforeClose = readUtf(fx2.paths.active);
  let closedRb;
  let threwRb = null;
  try {
    closedRb = close(root2, ad2.txid, "rolled_back");
  } catch (e) {
    threwRb = e;
  }
  if (threwRb) {
    fail("close-fail:outcome-rolled_back", threwRb.message);
  } else if (!(closedRb && closedRb.state === "CLOSED_ROLLED_BACK")) {
    fail("close-fail:outcome-rolled_back", JSON.stringify(closedRb));
  } else {
    pass("close-fail:outcome-rolled_back", closedRb.state);
  }

  /* Note: adopt.close only flips window state; inverse promote is a separate path per contract 01.
   * ACTIVE may still point at adopted tree after CLOSED_ROLLED_BACK unless rollback() is invoked. */
  const activeAfterClose = readUtf(fx2.paths.active);
  if (activeAfterClose !== activeBeforeClose) {
    pass("close-fail:rolled_back-ACTIVE-note", "ACTIVE changed during close(rolled_back)");
  } else {
    fail(
      "close-fail:rolled_back-ACTIVE-note",
      "close(rolled_back) left ACTIVE on adopted tree (window CLOSED_ROLLED_BACK only) — inverse promote not auto-invoked by adopt.close; doc/knob rollback must be explicit per contract 01"
    );
  }

  void baseTree;
  void treeAfter;
}

/* =========================================================================
 * 7. yes:true API alias (document intentional vs accidental bypass)
 * ========================================================================= */
function attack_yes_true_alias() {
  const root = mkRoot("yes-alias");
  const { paths } = createFixture(root);
  const prop = stageProposal(paths, "yes-alias");
  const result = adopt(root, prop.proposal_id, { yes: true, windowN: 1 });
  if (!(result && result.adopted === true)) {
    fail("alias:yes-true-adopts", JSON.stringify(result));
  } else {
    /* Intentional CLI binding. Record as PASS with note that API allows yes:true without confirm:true */
    pass("alias:yes-true-adopts", "API accepts yes:true (CLI --yes binding); confirm:true also works");
  }

  const root2 = mkRoot("confirm-true");
  const fx2 = createFixture(root2);
  const prop2 = stageProposal(fx2.paths, "confirm-true-only");
  const r2 = adopt(root2, prop2.proposal_id, { confirm: true, windowN: 1 });
  if (!(r2 && r2.adopted === true)) fail("alias:confirm-true-adopts", JSON.stringify(r2));
  else pass("alias:confirm-true-adopts", r2.txid);
}

/* =========================================================================
 * 8. Non-existent proposal / wrong id
 * ========================================================================= */
function attack_not_found() {
  const root = mkRoot("notfound");
  const { paths } = createFixture(root);
  stageProposal(paths, "exists");
  const before = snaphotDisk(paths);
  const result = adopt(root, sha256("does-not-exist"), { confirm: true });
  const after = snaphotDisk(paths);
  if (result.adopted === true) fail("not-found:missing-id", "adopted ghost");
  else if (diskUnchanged(before, after, ["active", "adoption", "pending"])) fail("not-found:missing-id", "mutated");
  else pass("not-found:missing-id", result.reason || "refused");
}

/* =========================================================================
 * 9. CLI list never writes adoption-log
 * ========================================================================= */
function attack_cli_list_observe_close() {
  const root = mkRoot("cli-ro");
  const { paths } = createFixture(root);
  const prop = stageProposal(paths, "cli-ro");
  const before = snaphotDisk(paths);

  runCliRaw(["list", "--project-root", root], root);
  const rObs = runCliRaw(["observe", "--run", "r1", "--tree", JSON.parse(readUtf(paths.active)).tree, "--project-root", root], root);
  const rClose = runCliRaw(["close", "deadbeefdeadbeef", "--outcome", "pass", "--project-root", root], root);
  const after = snaphotDisk(paths);

  if (after.active !== before.active || after.adoption !== before.adoption) {
    fail("cli-ro:list-obs-close", `ACTIVE/log changed list/obs/close exit obs=${rObs.status} close=${rClose.status}`);
  } else if (after.pending !== before.pending) {
    fail("cli-ro:list-obs-close", "pending changed");
  } else if (!listPending(root).some((p) => p.proposal_id === prop.proposal_id)) {
    fail("cli-ro:list-obs-close", "proposal vanished");
  } else {
    pass("cli-ro:list-obs-close", `obs_exit=${rObs.status} close_exit=${rClose.status}`);
  }
}

/* =========================================================================
 * 10. confirm true with smuggled promote-affecting opts still needs confirm
 * ========================================================================= */
function attack_opts_without_confirm() {
  const root = mkRoot("opts-smuggle");
  const { paths } = createFixture(root);
  const prop = stageProposal(paths, "opts-smuggle");
  const before = snaphotDisk(paths);
  const result = adopt(root, prop.proposal_id, {
    windowN: 1,
    humanName: "attacker",
    confirm: "TRUE",
    yes: "TRUE",
    __proto__: { confirm: true },
  });
  const after = snaphotDisk(paths);
  if (result.adopted === true) fail("smuggle:proto-confirm", "prototype/string smuggle adopted");
  else if (diskUnchanged(before, after, ["active", "adoption"])) fail("smuggle:proto-confirm", "mutated");
  else pass("smuggle:proto-confirm", result.reason || "refused");
}

function main() {
  const attacks = [
    attack_confirmation_bypass,
    attack_cli_without_yes,
    attack_list_observe_close_no_adopt,
    attack_only_path_static,
    attack_double_adopt,
    attack_malformed_pending,
    attack_e2e_close_pass,
    attack_close_fail_semantics,
    attack_yes_true_alias,
    attack_not_found,
    attack_cli_list_observe_close,
    attack_opts_without_confirm,
  ];

  for (const fn of attacks) {
    try {
      fn();
    } catch (e) {
      fail(`harness:${fn.name}`, e.stack || e.message);
    }
  }

  /* cleanup temps */
  for (const t of tempRoots) {
    try { fs.rmSync(t, { recursive: true, force: true }); } catch (_) {}
  }

  if (priorTestMode === undefined) delete process.env.GRAPHSMITH_TEST_MODE;
  else process.env.GRAPHSMITH_TEST_MODE = priorTestMode;

  const counts = { PASS: 0, FAIL: 0, SKIPPED: 0 };
  for (const r of results) counts[r.status] = (counts[r.status] || 0) + 1;
  console.log("---");
  console.log(`SUMMARY\tPASS=${counts.PASS || 0}\tFAIL=${counts.FAIL || 0}\tSKIPPED=${counts.SKIPPED || 0}`);
  const reportPath = path.join(__dirname, "last-run.json");
  fs.writeFileSync(reportPath, JSON.stringify({
    when: "disk-verdict-run",
    counts,
    results,
  }, null, 2) + "\n");

  process.exit((counts.FAIL || 0) > 0 ? 1 : 0);
}

main();
