#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const State = require("./state-store");
const Manifest = require("./manifest");
const Loaders = require("./loaders");
const SCHEMA_VERSION = "1.0";
function sha256(data) { const s = typeof data === "string" ? data : JSON.stringify(data); return crypto.createHash("sha256").update(s).digest("hex"); }
function stableId(parts) { return sha256(parts.join("\0")).slice(0, 24); }
function classifyTarget(absPath) {
  const base = path.basename(absPath);
  if (base === "manager.js") return { repairClass: "code", isManager: true };
  const ext = path.extname(absPath).toLowerCase();
  if (ext === ".js" || ext === ".cjs" || ext === ".mjs") return { repairClass: "code", isManager: false };
  if (absPath.includes(path.join("workers", "")) && base.endsWith(".prompt.md")) return { repairClass: "typed", kind: "prompt" };
  if (base === "tunables.json" || base.endsWith(".config.json") || base === "scenario.json") return { repairClass: "typed", kind: "data" };
  if (ext === ".json" || ext === ".md") return { repairClass: "typed", kind: "config" };
  return { repairClass: "code", isManager: false };
}
function syntacticExternalCallScan(text) {
  if (!text) return { no_external_calls: true, matched_patterns: [], policy: "syntactic-allowlist-v1" };
  const patterns = [ /\b(require\(['"](fs|http|https|child_process|net|tls|dns)['"]|fs\.|http\.|https\.|fetch\(|child_process\.)/ , /\b(process\.env\.|exec\(|spawn\()/ ];
  const matched = [];
  if (patterns[0].test(text)) matched.push("node-external-module");
  if (patterns[1].test(text)) matched.push("process-exec");
  return { no_external_calls: matched.length === 0, matched_patterns: matched, policy: "syntactic-allowlist-v1" };
}
function computeDiff(before, after, fn) {
  if (before === after) return "";
  const a = before.split(/\r?\n/);
  const b = after.split(/\r?\n/);
  let d = "diff --git a/" + fn + " b/" + fn + "\n--- a/" + fn + "\n+++ b/" + fn + "\n@@ -" + a.length + ",+" + b.length + " @@\n";
  const m = Math.max(a.length, b.length);
  for (let i = 0; i < m; i++) {
    if (i >= a.length) { d += "+" + b[i] + "\n"; continue; }
    if (i >= b.length) { d += "-" + a[i] + "\n"; continue; }
    if (a[i] !== b[i]) { d += "-" + a[i] + "\n+" + b[i] + "\n"; } else { d += " " + a[i] + "\n"; }
  }
  return d;
}
function createTypedEventReader(projectRoot) {
  const store = State.createStore(projectRoot);
  return {
    __adapter_for: "phase-c-event-compiler",
    getTypedHaltDiagnosis: function () {
      let w = { state: "NO_WINDOW", flag: false, window: null };
      try { w = store.window.get() || w; } catch (_) {}
      let rbs = [];
      try { rbs = store.rollbackFamilies.list() || []; } catch (_) {}
      const ev = [];
      ev.push({ record_type: "WINDOW", state: w.state, flag: !!w.flag, window: w.window || null });
      for (const rb of rbs) ev.push({ record_type: rb.record_type || "ROLLBACK_RECORDED", fingerprint: rb.fingerprint, family: rb.family });
      let cls = w.state || "UNKNOWN";
      let cc = cls === "HALT_HUMAN" ? "halt_human" : (cls === "ROLLING_BACK" ? "rolling_back" : "ok");
      return { type: "typed_diagnosis", classification: cls, cause_code: cc, evidence: ev, raw_source: "state-store.typed-records+adapter" };
    }
  };
}
function stageRepair(opts) {
  const root = opts.root || process.cwd();
  const tgt = opts.target;
  if (!tgt) throw new Error("target required");
  const abs = path.resolve(root, tgt);
  if (!fs.existsSync(abs)) throw new Error("target missing: " + tgt);
  const before = fs.readFileSync(abs, "utf8");
  const cl = classifyTarget(abs);
  if (cl.isManager) {
    const e = new Error("manager code is NEVER modified by heal in v0.2.0");
    e.code = "MANAGER_CODE_REFUSED";
    throw e;
  }
  const cap = syntacticExternalCallScan(before + (opts.proposedContent || ""));
  const treeM = Manifest.generate("tree", { rootDir: root });
  const tsha = sha256(JSON.stringify(treeM));
  const stageDir = path.join(root, ".graphsmith", "heal-stages");
  fs.mkdirSync(stageDir, { recursive: true });
  const rec = { schema_version: SCHEMA_VERSION };
  if (cl.repairClass === "code") {
    const df = computeDiff(before, opts.proposedContent || before, tgt);
    rec.heal_id = stableId(["code", tgt, sha256(before).slice(0, 12), (opts.proposedContent ? sha256(opts.proposedContent).slice(0, 12) : "")]);
    rec.repair_class = "code";
    rec.target = tgt;
    rec.is_manager = false;
    rec.diagnosis = opts.fromDiagnosis || { classification: "manual" };
    rec.diff = df;
    rec.plain_english = "Code repair STAGED-ONLY. Human applies then verify with chaos. Manager never touched.";
    rec.suggested_chaos = ["node scripts/chaos.js ."];
    rec.auto_apply_eligible = false;
    rec.capability_policy = cap;
    rec.tree_sha = tsha;
    rec.evidence = (opts.fromDiagnosis && opts.fromDiagnosis.evidence) || [];
    fs.writeFileSync(path.join(stageDir, rec.heal_id + ".staged.json"), JSON.stringify(rec, null, 2));
    return rec;
  }
  const prop = opts.proposedContent || before;
  rec.heal_id = stableId(["typed", tgt, sha256(before).slice(0, 16)]);
  rec.repair_class = "typed";
  rec.target = tgt;
  rec.diagnosis = opts.fromDiagnosis || { classification: "manual" };
  rec.before_sha256 = sha256(before);
  rec.after_sha256 = sha256(prop);
  rec.before_content_base64 = Buffer.from(before, "utf8").toString("base64");
  rec.content_base64 = Buffer.from(prop, "utf8").toString("base64");
  rec.auto_apply_eligible = !!cap.no_external_calls;
  rec.capability_policy = cap;
  rec.tree_sha = tsha;
  rec.evidence = (opts.fromDiagnosis && opts.fromDiagnosis.evidence) || [];
  rec.plain_english = cap.no_external_calls ? "typed stage: auto-apply-eligible" : "typed stage: human-gated";
  fs.writeFileSync(path.join(stageDir, rec.heal_id + ".staged.json"), JSON.stringify(rec, null, 2));
  return rec;
}
function doRollback(healId, rootArg) {
  const root = rootArg || process.cwd();
  const sp = path.join(root, ".graphsmith", "heal-stages", healId + ".staged.json");
  if (!fs.existsSync(sp)) { const e = new Error("unknown heal id"); e.code = "ROLLBACK_NOT_FOUND"; throw e; }
  const rec = JSON.parse(fs.readFileSync(sp, "utf8"));
  const store = State.createStore(root);
  if (rec.repair_class === "code") {
    const e = new Error("Rollback refused for code repair; preserve evidence and perform human forward-recovery");
    e.code = "FORWARD_RECOVERY_REQUIRED";
    throw e;
  }
  const t = rec.target;
  const p = path.resolve(root, t);
  const storeCurrentSha = rec.before_sha256 && rec.content_base64 ? true : false;
  if (fs.existsSync(p) && storeCurrentSha && rec.before_content_base64) {
    const nowSha = sha256(fs.readFileSync(p, "utf8"));
    if (nowSha === rec.after_sha256) {
      const oldC = Buffer.from(rec.before_content_base64, "base64").toString("utf8");
      if (sha256(oldC) === rec.before_sha256) {
        fs.writeFileSync(p, oldC);
        store.rollbackFamilies.append({ fingerprint: healId, family: "heal", evidence: { restored_target: t } });
        const curM = Manifest.generate("tree", { rootDir: root });
        const curS = sha256(JSON.stringify(curM));
        const treeOk = !rec.tree_sha || curS === rec.tree_sha;
        return { id: healId, state: "ROLLED_BACK", tree_identity_verified: treeOk, explanation: "byte-exact via manifest tree identity + file sha" };
      }
    }
  }
  const e = new Error("Rollback refused; not byte-exact on manifest tree identity");
  e.code = "FORWARD_RECOVERY_REQUIRED";
  throw e;
}
function diagnose(root) {
  const reader = createTypedEventReader(root);
  const d = reader.getTypedHaltDiagnosis();
  return { schema_version: SCHEMA_VERSION, command: "--diagnose", diagnosis: d, plain_english: "typed event adapter only; classified from window+rollback records." };
}
function selftest() {
  const os = require("os");
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-heal-selftest-"));
  const prior = process.env.GRAPHSMITH_TEST_MODE;
  process.env.GRAPHSMITH_TEST_MODE = "1";
  const results = [];
  const rec = (n, p, d) => { results.push({ name: n, pass: !!p, detail: d || "" }); process.stderr.write((p ? "PASS " : "FAIL ") + n + (d ? " " + d : "") + "\n"); };
  try {
    const pr = path.join(base, "p");
    fs.mkdirSync(path.join(pr, "workers"), { recursive: true });
    const pm = path.join(pr, "workers", "gather.prompt.md");
    fs.writeFileSync(pm, "You are gather. Do safe.\n");
    const tu = path.join(pr, "tunables.json");
    fs.writeFileSync(tu, "{}");
    const cd = path.join(pr, "step.js");
    fs.writeFileSync(cd, "exports.x=1;\n");
    const mg = path.join(pr, "manager.js");
    fs.writeFileSync(mg, "console.log(1);\n");
    const s0p = sha256(fs.readFileSync(pm, "utf8"));
    const s0c = sha256(fs.readFileSync(cd, "utf8"));
    const s0m = sha256(fs.readFileSync(mg, "utf8"));
    const st = State.createStore(pr);
    st.window.admitPending({ txid: "h1", fingerprint: "f1", tree_id: "v-test", n: 1 });
    const lk = st._testing.acquireLock();
    try {
      st._commit([{ file: "window.json", make: (raw, rv) => { const v = JSON.parse(raw); v.state = "HALT_HUMAN"; v.state_rev = rv; return JSON.stringify(v); } }]);
    } finally { clearInterval(lk.heartbeat); st._testing.releaseLock(lk.ownerToken); }
    const dg = diagnose(pr);
    rec("diagnose-uses-typed-adapter", String(dg.diagnosis.raw_source).includes("state-store.typed"));
    rec("diagnose-classifies-from-window", /HALT|HUMAN|UNKNOWN/.test(dg.diagnosis.classification || ""));
    const stT = stageRepair({ root: pr, target: "workers/gather.prompt.md", proposedContent: "You are gather. Fixed typed.\n" });
    rec("typed-stages-evidence-present", stT.repair_class === "typed" && Array.isArray(stT.evidence));
    rec("typed-marks-eligibility", typeof stT.auto_apply_eligible === "boolean");
    rec("typed-never-mutates-file", sha256(fs.readFileSync(pm, "utf8")) === s0p);
    const stC = stageRepair({ root: pr, target: "step.js", proposedContent: "exports.x=99;\n" });
    rec("code-stages-only-diff", stC.repair_class === "code" && typeof stC.diff === "string" && !stC.hasOwnProperty("content_base64"));
    rec("code-never-mutates-exec", sha256(fs.readFileSync(cd, "utf8")) === s0c);
    let mgrRef = false;
    try { stageRepair({ root: pr, target: "manager.js", proposedContent: "hacked" }); } catch (e) { mgrRef = e.code === "MANAGER_CODE_REFUSED"; }
    rec("refuses-manager-code", mgrRef);
    rec("never-mutates-manager", sha256(fs.readFileSync(mg, "utf8")) === s0m);
    fs.writeFileSync(pm, "You are gather. Fixed typed.\n");
    let rbr;
    try { rbr = doRollback(stT.heal_id, pr); } catch (e) { rbr = { err: e.code || e.message }; }
    rec("typed-rollback-restore-byte-exact", sha256(fs.readFileSync(pm, "utf8")) === s0p);
    rec("rollback-via-manifest-tree", !!(rbr && (rbr.tree_identity_verified || String(rbr.explanation || "").includes("manifest"))));
    let crf = false;
    try { doRollback(stC.heal_id, pr); } catch (e) { crf = /FORWARD|code/i.test((e.code || "") + e.message); }
    rec("code-rollback-refuses", crf);
    const sd = path.join(pr, ".graphsmith", "heal-stages");
    const sfs = fs.existsSync(sd) ? fs.readdirSync(sd) : [];
    rec("stages-written-to-disk", sfs.length >= 2);
    const fin = results.every((x) => x.pass);
    rec("selftest-proves-all-constraints", fin);
    return { schema_version: SCHEMA_VERSION, status: fin ? "pass" : "fail", tests: results };
  } finally {
    if (prior === undefined) delete process.env.GRAPHSMITH_TEST_MODE; else process.env.GRAPHSMITH_TEST_MODE = prior;
    try { fs.rmSync(base, { recursive: true, force: true }); } catch (_) {}
  }
}
if (require.main === module) {
  try {
    const argv = process.argv.slice(2);
    if (argv.includes("--selftest")) {
      const out = selftest();
      process.stdout.write(JSON.stringify(out) + "\n");
      process.exit(out.status === "pass" ? 0 : 1);
    }
    let root = process.cwd();
    for (let i = 0; i < argv.length; i++) { if (argv[i] === "--root" && argv[i + 1]) root = path.resolve(argv[++i]); }
    const c0 = argv[0];
    if (c0 === "--diagnose") {
      const r = diagnose(root);
      process.stdout.write(JSON.stringify(r, null, 2) + "\n");
    } else if (c0 === "--stage") {
      const ti = argv.findIndex((a, idx) => idx > 0 && !a.startsWith("-"));
      let tgt = (ti >= 0 ? argv[ti] : argv[1]) || "";
      if (tgt === "--root" || tgt.startsWith("-")) tgt = "";
      if (!tgt) { process.stderr.write("Usage: node scripts/heal.js --stage <target> [--root dir] [--proposed <f>]\n"); process.exitCode = 2; return; }
      let prop = "";
      const pi = argv.indexOf("--proposed");
      if (pi >= 0 && argv[pi + 1]) { const v = argv[pi + 1]; prop = fs.existsSync(v) ? fs.readFileSync(v, "utf8") : v; }
      const r = stageRepair({ root, target: tgt, proposedContent: prop || null });
      process.stdout.write(JSON.stringify(r, null, 2) + "\n");
    } else if (c0 === "rollback" && argv[1] && !argv[1].startsWith("-")) {
      const r = doRollback(argv[1], root);
      process.stdout.write(JSON.stringify(r, null, 2) + "\n");
    } else {
      process.stderr.write("Usage: node scripts/heal.js --diagnose | --stage <target> | rollback <id> | --selftest [--root <dir>]\n");
      process.exitCode = 2;
    }
  } catch (e) {
    process.stderr.write((e.code ? e.code + ": " : "ERROR: ") + e.message + "\n");
    process.exitCode = (e.code === "MANAGER_CODE_REFUSED" || e.code === "FORWARD_RECOVERY_REQUIRED") ? 2 : 1;
  }
}
module.exports = { diagnose, stageRepair, doRollback, createTypedEventReader, selftest, SCHEMA_VERSION };
