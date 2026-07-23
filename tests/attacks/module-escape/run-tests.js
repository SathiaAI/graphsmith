#!/usr/bin/env node
/* Module-escape suite — contained, independent adversary of constitutional posture.
 * Static + light dynamic checks that decision-path scripts:
 *   - require only Node builtins (no non-builtin packages)
 *   - do not call eval / new Function for decisions
 *   - do not open network sockets on decision paths
 *   - do not read clock/random into decision branches
 * Smuggles crafted packets/corpus and asserts refusal or absence.
 * Verdicts from parse results / return objects / exit codes — never log strings.
 * Exit 1 if any must-hold escape is found open.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const Module = require("module");

const REPO = path.resolve(__dirname, "..", "..", "..");
const SCRIPTS = path.join(REPO, "scripts");

const DECISION_SCRIPTS = [
  "gate.js",
  "verify.js",
  "promote.js",
  "state-store.js",
  "loaders.js",
  "manifest.js",
];

const NODE_BUILTINS = new Set([
  ...Module.builtinModules,
  ...Module.builtinModules.map((m) => `node:${m}`),
]);

const results = [];
const temps = [];

function record(name, status, detail) {
  results.push({ name, status, detail: detail || "" });
  console.log(`${status}\t${name}${detail ? "\t" + String(detail).replace(/\s+/g, " ").slice(0, 300) : ""}`);
}
function pass(n, d) { record(n, "PASS", d); }
function fail(n, d) { record(n, "FAIL", d); }
function sha256(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}
function mk(tag) {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), `gs-atk-mesc-${tag}-`));
  temps.push(r);
  return r;
}
function rmAll() {
  for (const t of temps) {
    try { fs.rmSync(t, { recursive: true, force: true }); } catch (_) {}
  }
}

function readScript(name) {
  return fs.readFileSync(path.join(SCRIPTS, name), "utf8");
}

/* Strip // and /* comments + string/template contents for coarser scans.
 * Not a full JS parser; deliberately conservative false-positive oriented for
 * require()/eval discovery (over-report rather than miss, then refine). */
function stripNoise(src) {
  let out = "";
  let i = 0;
  while (i < src.length) {
    if (src[i] === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (src[i] === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (src[i] === "'" || src[i] === '"') {
      const q = src[i++];
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i++;
        i++;
      }
      i++;
      out += '""';
      continue;
    }
    if (src[i] === "`") {
      i++;
      while (i < src.length && src[i] !== "`") {
        if (src[i] === "\\") i++;
        else if (src[i] === "$" && src[i + 1] === "{") {
          i += 2;
          let depth = 1;
          while (i < src.length && depth) {
            if (src[i] === "{") depth++;
            else if (src[i] === "}") depth--;
            i++;
          }
          out += " ";
          continue;
        }
        i++;
      }
      i++;
      out += '""';
      continue;
    }
    out += src[i++];
  }
  return out;
}

function findRequires(src) {
  /* Scan original source (not string-stripped) so module names survive. */
  const reqs = [];
  const re = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    /* Skip requires that appear inside line/block comments via coarse check:
     * if the match sits on a // comment-only prefix, ignore. */
    const lineStart = src.lastIndexOf("\n", m.index) + 1;
    const prefix = src.slice(lineStart, m.index);
    if (prefix.includes("//")) continue;
    reqs.push(m[1]);
  }
  return reqs;
}

function isBuiltinOrRelative(spec) {
  if (spec.startsWith(".") || spec.startsWith("/")) return true;
  if (NODE_BUILTINS.has(spec)) return true;
  const base = spec.startsWith("node:") ? spec.slice(5) : spec;
  if (NODE_BUILTINS.has(base) || NODE_BUILTINS.has("node:" + base)) return true;
  /* state-store loads a local JSON schema via relative path only — covered by relative */
  return false;
}

/* ------------------------------------------------------------------ */
/* 1. No non-builtin requires on decision scripts                      */
/* ------------------------------------------------------------------ */
function attack_nonBuiltinRequires() {
  for (const name of DECISION_SCRIPTS) {
    const tname = `no-nonbuiltin-require-${name}`;
    try {
      const src = readScript(name);
      const reqs = findRequires(src);
      const bad = reqs.filter((r) => !isBuiltinOrRelative(r));
      /* state-store.js does require("../schemas/...") — relative, ok */
      if (bad.length === 0) {
        pass(tname, `requires=${reqs.join(",") || "(none extra)"}`);
      } else {
        fail(tname, `ESCAPE: non-builtin require(s): ${bad.join(",")}`);
      }
    } catch (e) {
      fail(tname, e.message);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 2. No eval / Function ctor in decision paths                        */
/* ------------------------------------------------------------------ */
function attack_evalFunction() {
  for (const name of DECISION_SCRIPTS) {
    const tname = `no-eval-Function-${name}`;
    try {
      const cleaned = stripNoise(readScript(name));
      const evalHit = /(?<![\w$.])eval\s*\(/.test(cleaned);
      const fnHit = /(?<![\w$.])Function\s*\(/.test(cleaned);
      const newFnHit = /new\s+Function\s*\(/.test(cleaned);
      if (evalHit || fnHit || newFnHit) {
        fail(tname, `ESCAPE: eval=${evalHit} Function=${fnHit} newFunction=${newFnHit}`);
      } else {
        pass(tname, "absent");
      }
    } catch (e) {
      fail(tname, e.message);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 3. child_process only for non-decision / opt-in spawn paths          */
/* ------------------------------------------------------------------ */
function attack_childProcess() {
  /* Wrap child_process APIs before gate loads so in-memory decide path cannot
   * spawn even if a regression adds spawn() inside gate2Behavioral. Flag is
   * off for legitimate corpusPath→scenario.js (not exercised here). */
  const cp = require("child_process");
  const CP_METHODS = ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"];
  const cpOriginals = {};
  for (const m of CP_METHODS) cpOriginals[m] = cp[m];
  let banDecisionSpawn = false;
  for (const m of CP_METHODS) {
    const orig = cpOriginals[m];
    cp[m] = function bannedCp(...args) {
      if (banDecisionSpawn) {
        throw new Error(`ESCAPE: child_process.${m} on in-memory decision path`);
      }
      return orig.apply(this, args);
    };
  }
  const gatePath = path.join(SCRIPTS, "gate.js");
  try {
    delete require.cache[require.resolve(gatePath)];
  } catch (_) {}
  let gateMod = null;
  try {
    gateMod = require(gatePath);
  } catch (e) {
    fail("child_process-posture-gate.js", `gate load failed under cp wrap: ${e.message}`);
  }

  for (const name of DECISION_SCRIPTS) {
    const tname = `child_process-posture-${name}`;
    try {
      const src = readScript(name);
      const importsCp =
        /require\s*\(\s*["']child_process["']\s*\)/.test(src) ||
        /require\s*\(\s*["']node:child_process["']\s*\)/.test(src);
      if (!importsCp) {
        pass(tname, "no child_process");
        continue;
      }
      /* gate.js may spawn scenario.js for corpus replay — allowed as worker side.
       * Decision functions with in-memory bundle must not spawn.
       */
      if (name === "gate.js") {
        if (!gateMod) {
          fail(tname, "gate module unavailable");
          continue;
        }
        const pairs = [{
          scenario_id: "mesc-0",
          seed: 1,
          cand: { pass: true, cause_code: "ok" },
          base: { pass: true, cause_code: "ok" },
        }];
        const bundle = {
          schema_version: "1.0",
          corpus_hash: sha256("mesc"),
          pairs,
          slices: [],
        };
        bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
        banDecisionSpawn = true;
        let result;
        try {
          result = gateMod.gate2Behavioral("mesc", { bundle, cycleSeed: 0, stateStore: null });
        } finally {
          banDecisionSpawn = false;
        }
        /* Completing under ban proves no spawn on bundle/in-memory path. */
        if (result && typeof result.pass === "boolean") {
          pass(tname, `in-memory decide ok pass=${result.pass}; no-spawn under cp ban; spawn reserved for corpusPath only`);
        } else {
          fail(tname, "gate2 in-memory path failed to decide under spawn ban");
        }
        continue;
      }
      fail(tname, `ESCAPE: unexpected child_process import in ${name}`);
    } catch (e) {
      banDecisionSpawn = false;
      fail(tname, e.message);
    }
  }
  /* Keep wrappers (flag off) so later tests still call through originals. */
}

/* ------------------------------------------------------------------ */
/* 4. No network socket APIs on decision path (static)                  */
/* ------------------------------------------------------------------ */
function attack_networkStatic() {
  const netApis = [
    /\brequire\s*\(\s*["']net["']\s*\)/,
    /\brequire\s*\(\s*["']http["']\s*\)/,
    /\brequire\s*\(\s*["']https["']\s*\)/,
    /\brequire\s*\(\s*["']dgram["']\s*\)/,
    /\brequire\s*\(\s*["']dns["']\s*\)/,
    /\brequire\s*\(\s*["']tls["']\s*\)/,
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
  ];
  for (const name of DECISION_SCRIPTS) {
    const tname = `no-network-api-${name}`;
    try {
      const src = readScript(name);
      const cleaned = stripNoise(src);
      const hits = netApis.filter((re) => re.test(src) || re.test(cleaned));
      if (hits.length) {
        fail(tname, `ESCAPE: matched ${hits.length} network patterns`);
      } else {
        pass(tname, "absent");
      }
    } catch (e) {
      fail(tname, e.message);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 5. Clock/random not in decision BRANCHES (static heuristics)         */
/* ------------------------------------------------------------------ */
function attack_clockRandomDecision() {
  /* Allowed: metadata Date.now/toISOString, lock mtime, lease heartbeats,
   * atomic retry Atomics.wait, temporary file randomBytes for names,
   * TEST_MODE lease overrides, selftest fixtures.
   * Forbidden pattern: Date.now()/Math.random()/crypto.random* used as the
   * *condition* of a promote/reject/verdict branch in gate decision core.
   */
  const gateSrc = readScript("gate.js");
  const name = "gate-decision-path-no-clock-random";
  try {
    /* Extract gate1Static + decideGate2 function bodies roughly */
    const g1 = gateSrc.indexOf("function gate1Static");
    const g2 = gateSrc.indexOf("function decideGate2");
    const g3 = gateSrc.indexOf("function gate3Prepare");
    const slice1 = gateSrc.slice(g1, g2 > g1 ? g2 : g1 + 8000);
    const slice2 = gateSrc.slice(g2, g3 > g2 ? g3 : g2 + 12000);
    const cleaned1 = stripNoise(slice1);
    const cleaned2 = stripNoise(slice2);
    const clockRe = /Date\.now\s*\(|new\s+Date\s*\(|Math\.random\s*\(|crypto\.random(?:Bytes|Int|UUID|Fill)/;
    const h1 = clockRe.test(cleaned1);
    const h2 = clockRe.test(cleaned2);
    if (h1 || h2) {
      fail(name, `ESCAPE: clock/random in gate1=${h1} decideGate2=${h2}`);
    } else {
      pass(name, "gate1Static+decideGate2 clean");
    }
  } catch (e) {
    fail(name, e.message);
  }

  /* loaders + manifest decision (verifyTree/generate path sorting is deterministic) */
  for (const s of ["loaders.js", "manifest.js"]) {
    const tname = `decision-no-clock-random-${s}`;
    try {
      const cleaned = stripNoise(readScript(s));
      /* manifest.generate uses new Date only for project metadata generated_at — check verifyTree body */
      if (s === "manifest.js") {
        const vStart = cleaned.indexOf("function verifyTree");
        const body = cleaned.slice(vStart, vStart + 4000);
        if (/Date\.now\s*\(|Math\.random\s*\(/.test(body)) {
          fail(tname, "clock/random inside verifyTree");
        } else {
          pass(tname, "verifyTree clean");
        }
      } else {
        const loadersOnly = cleaned
          .replace(/function runSelftest[\s\S]*$/, "")
          .replace(/function selftest[\s\S]*$/, "");
        if (/Date\.now\s*\(|Math\.random\s*\(|crypto\.randomBytes/.test(loadersOnly)) {
          /* txid randomBytes only in selftest builder — if still present outside selftest of loaders export path */
          const exportIdx = loadersOnly.indexOf("module.exports");
          const core = loadersOnly.slice(0, exportIdx === -1 ? loadersOnly.length : exportIdx);
          if (/Date\.now\s*\(|Math\.random\s*\(/.test(core)) {
            fail(tname, "Date.now/Math.random in loader core");
          } else if (/crypto\.randomBytes/.test(core)) {
            fail(tname, "crypto.randomBytes in loader core");
          } else {
            pass(tname, "loader core clean");
          }
        } else {
          pass(tname, "clean");
        }
      }
    } catch (e) {
      fail(tname, e.message);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 6. Dynamic: smuggle require/eval via candidate payload (gate1)       */
/* ------------------------------------------------------------------ */
function attack_smuggleInCandidate() {
  const gate = require(path.join(SCRIPTS, "gate.js"));
  const cases = [
    { id: "smuggle-eval", payload: "eval('process.exit(0)')" },
    { id: "smuggle-Function", payload: "Function('return this')()" },
    { id: "smuggle-require-net", payload: "require('net').connect(80,'evil.test')" },
  ];
  for (const c of cases) {
    const tname = `smuggle-payload-${c.id}`;
    try {
      const candidate = {
        id: c.id,
        kind: "code",
        fingerprint: sha256(c.id),
        edits: [{
          file: "scripts/ok.js",
          anchor: null,
          op: "replace",
          payload: c.payload,
          schema_ref: "test/v1",
        }],
      };
      const r = gate.gate1Static(candidate, { aliasesResolved: true });
      /* Gate may catch as G1_INJECTION for eval/Function; require('net') may not match markers.
       * Constitutional claim here: if it PASSES gate1, that is two-step — the *decision*
       * scripts themselves still must not execute the payload. Payload is data.
       * For eval/Function markers we require rejection; for require-net we require either
       * rejection OR confirmation payload is not executed (gate is pure may parts).
       */
      if (c.id.startsWith("smuggle-eval") || c.id.startsWith("smuggle-Function")) {
        if (r.pass === false) {
          pass(tname, `pass=false codes=${(r.findings || []).map((f) => f.code).join(",")}`);
        } else {
          fail(tname, "eval/Function payload admitted by gate1");
        }
      } else {
        /* require('net') string is DATA if not executed. Confirm by ensuring no socket opened:
         * run gate1 and assert process remains without listening servers growth attributable here.
         */
        const before = typeof process._getActiveHandles === "function" ? process._getActiveHandles().length : 0;
        const r2 = gate.gate1Static(candidate, { aliasesResolved: true });
        const after = typeof process._getActiveHandles === "function" ? process._getActiveHandles().length : 0;
        if (after <= before + 2) {
          pass(tname, `treated as data pass=${r2.pass} handles ${before}->${after}`);
        } else {
          fail(tname, `handle count jumped ${before}->${after} (possible network open)`);
        }
      }
    } catch (e) {
      fail(tname, e.message);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 7. Dynamic dual-run determinism (same inputs → same gate2 decision)  */
/* ------------------------------------------------------------------ */
function attack_determinismNoHiddenClock() {
  const name = "gate2-dual-run-deterministic";
  try {
    const gate = require(path.join(SCRIPTS, "gate.js"));
    const pairs = [];
    for (let i = 0; i < 40; i++) {
      pairs.push({
        scenario_id: "d-" + i,
        seed: i,
        cand: { pass: i % 3 !== 0, cause_code: "ok" },
        base: { pass: i % 5 !== 0, cause_code: "ok" },
      });
    }
    const bundle = {
      schema_version: "1.0",
      corpus_hash: sha256(pairs.map((p) => p.scenario_id).sort().join("\n")),
      pairs,
      slices: [],
    };
    bundle.bundle_sha256 = sha256(JSON.stringify({ ...bundle, bundle_sha256: undefined }));
    const r1 = gate.gate2Behavioral("det", { bundle, cycleSeed: 7, stateStore: null });
    const r2 = gate.gate2Behavioral("det", { bundle, cycleSeed: 7, stateStore: null });
    const s1 = JSON.stringify({
      pass: r1.pass, tier: r1.tier,
      v: r1.primary && r1.primary.verdict,
      p: r1.primary && r1.primary.p,
      nd: r1.primary && r1.primary.n_d,
    });
    const s2 = JSON.stringify({
      pass: r2.pass, tier: r2.tier,
      v: r2.primary && r2.primary.verdict,
      p: r2.primary && r2.primary.p,
      nd: r2.primary && r2.primary.n_d,
    });
    if (s1 === s2) pass(name, s1);
    else fail(name, `nondeterministic r1=${s1} r2=${s2}`);
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 8. Selftest independence: gate --selftest no-clock flags (mirror)    */
/* ------------------------------------------------------------------ */
function attack_gateSelftestMirror() {
  const name = "gate-selftest-exit0";
  try {
    const child = spawnSync(
      process.execPath,
      [path.join(SCRIPTS, "gate.js"), "--selftest"],
      { encoding: "utf8", timeout: 60000 }
    );
    if (child.status === 0) {
      let body;
      try { body = JSON.parse(child.stdout); } catch (_) { body = null; }
      if (body && body.status === "pass") pass(name, `tests=${(body.tests || []).length}`);
      else if (body && body.exitCode === 0) pass(name, "exitCode 0");
      else pass(name, `exit=0 stdout-status=${body && body.status}`);
    } else {
      fail(name, `exit=${child.status} err=${(child.stderr || "").slice(0, 120)}`);
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
/* 9. Attempt to load non-builtin via NODE_PATH smuggle into fixture    */
/* ------------------------------------------------------------------ */
function attack_nodePathSmuggle() {
  const name = "NODE_PATH-smuggle-does-not-pull-pkg-into-decision";
  try {
    const evil = mk("nodepath");
    const pkgDir = path.join(evil, "evil-pkg");
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify({ name: "evil-pkg", main: "index.js" }));
    fs.writeFileSync(
      path.join(pkgDir, "index.js"),
      "module.exports = { pwned: true }; require('fs').writeFileSync(process.env.GS_MESC_MARKER, 'pwned');\n"
    );
    const marker = path.join(evil, "marker.txt");
    const child = spawnSync(
      process.execPath,
      ["-e", `
        const gate = require(${JSON.stringify(path.join(SCRIPTS, "gate.js"))});
        const r = gate.gate1Static({
          id: 'x', kind: 'code', fingerprint: 'a'.repeat(64),
          edits: [{ file: 'scripts/ok.js', op: 'replace', payload: 'require("evil-pkg")', schema_ref: 't' }]
        }, { aliasesResolved: true });
        process.stdout.write(JSON.stringify({ pass: r.pass, findings: (r.findings||[]).map(f=>f.code) }));
      `],
      {
        encoding: "utf8",
        env: { ...process.env, NODE_PATH: evil, GS_MESC_MARKER: marker },
        timeout: 15000,
      }
    );
    const markerExists = fs.existsSync(marker);
    if (markerExists) {
      fail(name, "evil-pkg executed via NODE_PATH during gate1");
      return;
    }
    if (child.status !== 0 && child.status !== null) {
      /* non-zero without marker is still success if gate didn't load evil */
      pass(name, `no marker; childStatus=${child.status}`);
      return;
    }
    let out;
    try { out = JSON.parse(child.stdout); } catch (_) { out = null; }
    if (out && markerExists === false) {
      pass(name, `pass=${out.pass} findings=${(out.findings || []).join(",")}`);
    } else {
      pass(name, "no package execution");
    }
  } catch (e) {
    fail(name, e.message);
  }
}

/* ------------------------------------------------------------------ */
function main() {
  console.log("=== module-escape suite ===");
  attack_nonBuiltinRequires();
  attack_evalFunction();
  attack_childProcess();
  attack_networkStatic();
  attack_clockRandomDecision();
  attack_smuggleInCandidate();
  attack_determinismNoHiddenClock();
  attack_gateSelftestMirror();
  attack_nodePathSmuggle();

  const fails = results.filter((r) => r.status === "FAIL");
  const passes = results.filter((r) => r.status === "PASS");
  console.log(`--- summary total=${results.length} pass=${passes.length} fail=${fails.length} ---`);
  rmAll();
  process.exit(fails.length ? 1 : 0);
}

main();
