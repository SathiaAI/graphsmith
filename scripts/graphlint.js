#!/usr/bin/env node
/* GraphSmith linter v2 — project-aware scan for loop-engineering violations.
 * v0.1.1 (post council review, PA-4/PA-5/PA-6):
 *   - PROJECT MODEL: builds an import graph, so a loop in a manager file that
 *     reaches an LLM through a worker file IS caught (the exact manager/worker
 *     split this skill promotes was structurally invisible to v0.1.0).
 *   - LOOP SEMANTICS: condition-variable loops (while(!done), while running:)
 *     count as unbounded; counter-bounded loops do not.
 *   - R4 FIXED: the v0.1.0 clock/randomness regex had a trailing \b after ")"
 *     and could never match — dead since day one. Now live, with a targeted
 *     exclusion for duration arithmetic (Date.now() - t0 is measurement).
 *   - KEYED GUARDS: an idempotency guard must reference a key (runId/step/id);
 *     a bare existsSync nearby no longer silences a charge (false-negative fix).
 *   - NARROWED WRITES: fetch() GETs and framework responses (res.send/json) are
 *     not "external writes"; bare .create( is REVIEW, not MEDIUM (false-positive fix).
 *   - --selftest: runs the shipped corpus (every council probe is a regression
 *     case) and asserts recall on planted violations + precision on clean files.
 * KNOWN BLIND SPOTS (documented; AST-free by design — a zero-dependency
 * constraint, so the tool stays auditable in minutes): dynamic
 * require(variable) / dispatch tables; loops built from recursion or
 * self-rescheduling setTimeout chains (setInterval IS detected); cross-file
 * or through-helper data flow (same-file clock/random variable tracking IS
 * done); non-relative module resolution; regex-literal contents; code inside
 * template ${interpolations} is treated as string content, not scanned. Guard
 * detection reads strings (Idempotency-Key headers), so a guard token in
 * prose can suppress a finding — verify suppressions too. Findings remain
 * HEURISTIC: verify each against the live file before acting.
 * Usage: node graphlint.js <path> | node graphlint.js --selftest */
const fs = require("fs");
const path = require("path");

const exts = new Set([".js", ".ts", ".mjs", ".py"]);
const SKIP = new Set(["node_modules", ".git", ".runs", "dist", "build", "__pycache__", ".venv", "venv"]);

const LLM = /\b(anthropic|openai|gemini|generativeai|litellm|chat\.completions|messages\.create|generate_content|invoke_model)\b/i;
const UNBOUNDED_LITERAL = /while\s*\(\s*(true|1)\s*\)|while\s+True\s*:|for\s*\(\s*;\s*;\s*\)/;
// A bare/negated variable condition has no visible bound; comparisons (i < n) do.
const UNBOUNDED_COND = /while\s*\(\s*!?\s*[A-Za-z_$][\w$.]*\s*\)|^\s*while\s+(?!True\b)not\s+\w+\s*:|^\s*while\s+(?!True\b)[A-Za-z_]\w*\s*:/;
const CAP = /\b(max_?(iter|retries|attempts|steps|loops)|attempt\s*<|retries\s*<|budget|deadline)\b/i;
const PERSIST = /\b(writeFile|appendFile|checkpoint|savepoint|\.save\(|pickle\.dump|json\.dump|INSERT INTO|\.set\(|put_item)\b/i;
// PA-4 fix: no trailing \b (after ")" it was unsatisfiable); require call parens.
const CLOCK_DICE = /(Date\.now|Math\.random|time\.time|random\.(random|choice|randint))\s*\(/;
const DURATION_MATH = /(Date\.now\(\)|time\.time\(\))\s*-\s*[\w$.]+|[\w$.]+\s*-\s*(Date\.now\(\)|time\.time\(\))/;
const ROUTING = /\b(if|switch|elif|match)\b/;
const WRITE_CALL = /\b(axios\.(post|put|patch|delete)|requests\.(post|put|patch|delete)|sendmail)\b|\.send\(/i;
const FRAMEWORK_RESP = /\b(res|resp|response|reply)\b[^;\n]*\.(send|json|render|end|status)\s*\(/;
const CREATE_CALL = /\.create\(/;
const FETCH_CALL = /\bfetch\(/;
const MUTATING_METHOD = /method\s*[:=]\s*["'`](POST|PUT|PATCH|DELETE)/i;
const GUARD_TOKENS = /\b(idempoten|Idempotency-Key|dedup|upsert|ON CONFLICT|if_not_exists)\b/i;
const GUARD_LOOKUP = /(\.includes\(|\.has\(|existsSync|readFileSync|SELECT\s+1|findOne|get\()/i;
const GUARD_KEY = /\b(runId|run_id|ctx\.step|jobId|job_id|messageId|message_id|eventId|event_id|dedupeKey|idempotencyKey|key)\b/;

// PD-4: rules must never fire on comments or string literals. Two views per
// file, both preserving line numbers: codeLines (comments stripped, strings
// kept — import names, "POST" methods and Idempotency-Key headers stay
// visible) and bareLines (comments AND string contents stripped — loop/clock
// keywords in prose can no longer masquerade as control flow).
function sanitize(src, isPy) {
  const n = src.length;
  const code = src.split(""), bare = src.split("");
  let i = 0;
  const blank = (arr, from, to) => { for (let k = from; k < to; k++) if (arr[k] !== "\n") arr[k] = " "; };
  while (i < n) {
    const c = src[i], c2 = src.slice(i, i + 2), c3 = src.slice(i, i + 3);
    if (!isPy && c2 === "//") { const e = src.indexOf("\n", i); const end = e === -1 ? n : e; blank(code, i, end); blank(bare, i, end); i = end; continue; }
    if (!isPy && c2 === "/*") { const e = src.indexOf("*/", i + 2); const end = e === -1 ? n : e + 2; blank(code, i, end); blank(bare, i, end); i = end; continue; }
    if (isPy && c === "#") { const e = src.indexOf("\n", i); const end = e === -1 ? n : e; blank(code, i, end); blank(bare, i, end); i = end; continue; }
    if (isPy && (c3 === "'''" || c3 === '"""')) {
      const e = src.indexOf(c3, i + 3); const end = e === -1 ? n : e + 3;
      blank(bare, i + 3, end - 3); i = end; continue;
    }
    if (c === "'" || c === '"' || (!isPy && c === "\u0060")) {
      const isTemplate = !isPy && c === "`"; // backticks span multiple lines
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === c) break;
        if (!isTemplate && src[j] === "\n") break;  // ' and " terminate at newline; backtick does NOT
        j++;
      }
      blank(bare, i + 1, Math.min(j, n));           // keep quotes, blank contents (incl. ${…} in templates)
      i = (j < n && src[j] === c) ? j + 1 : j; continue;
    }
    i++;
  }
  return { codeLines: code.join("").split("\n"), bareLines: bare.join("").split("\n") };
}

function collectFiles(root) {
  const files = [];
  if (!fs.statSync(root).isDirectory()) return [root]; // PD-11: file arg → that file only
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (SKIP.has(e.name)) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (exts.has(path.extname(e.name))) files.push(p);
    }
  })(root);
  return files;
}

function resolveImport(fromFile, spec) {
  if (!spec.startsWith(".")) return null; // only project-local edges
  const base = path.resolve(path.dirname(fromFile), spec);
  for (const cand of [base, base + ".js", base + ".ts", base + ".mjs", base + ".py",
                      path.join(base, "index.js"), path.join(base, "index.ts")])
    if (fs.existsSync(cand) && fs.statSync(cand).isFile()) return cand;
  return null;
}

function buildModel(files) {
  const model = new Map(); // file -> { src, lines, hasLLM, imports:[] }
  const IMPORT = /require\(\s*["']([^"']+)["']\s*\)|from\s+["']([^"']+)["']|^\s*from\s+\.?([\w.]+)\s+import|^\s*import\s+([\w.]+)/gm;
  for (const f of files) {
    const src = fs.readFileSync(f, "utf8");
    const imports = [];
    let m;
    while ((m = IMPORT.exec(src))) {
      const spec = m[1] || m[2] || (m[3] && "./" + m[3].replace(/^\./, "")) || (m[4] && "./" + m[4]);
      const r = spec && resolveImport(f, spec);
      if (r && files.includes(r)) imports.push(r);
    }
    const { codeLines, bareLines } = sanitize(src, path.extname(f) === ".py");
    const codeSrc = codeLines.join("\n"); // comments stripped, strings kept
    model.set(f, { src, lines: src.split("\n"), codeLines, bareLines, codeSrc,
                   hasLLM: LLM.test(codeSrc), imports });
  }
  // Transitive LLM reachability over the import graph (PA-5 cross-file fix)
  const reach = new Map();
  const reaches = (f, seen = new Set()) => {
    if (reach.has(f)) return reach.get(f);
    if (seen.has(f)) return false;
    seen.add(f);
    const node = model.get(f);
    const r = node.hasLLM || node.imports.some((i) => reaches(i, seen));
    reach.set(f, r);
    return r;
  };
  for (const f of files) reaches(f);
  return { model, reach };
}

function lintProject(root) {
  const files = collectFiles(path.resolve(root));
  const { model, reach } = buildModel(files);
  const findings = [];
  const rootAbs = path.resolve(root);
  const rootIsFile = !fs.statSync(rootAbs).isDirectory();
  const add = (file, line, rule, severity, fix) =>
    findings.push({ file: rootIsFile ? path.basename(file) : path.relative(rootAbs, file), line, rule, severity, fix });

  let anyLLM = false, anyPersist = false;
  for (const f of files) {
    const { codeLines, bareLines, codeSrc } = model.get(f);
    anyLLM ||= model.get(f).hasLLM; anyPersist ||= PERSIST.test(codeSrc);
    const llmReachable = reach.get(f);
    // PD-15: same-file value tracking — a clock/random value assigned to a
    // variable and later used in a branch is routing on nondeterminism, even
    // if the assignment and the branch are far apart.
    const taintedVars = new Map(); // name -> declaration line (0-based)
    bareLines.forEach((ln, li) => {
      const m = ln.match(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^=][^;]*\b(?:Date\.now|Math\.random|time\.time|random\.\w+)\s*\(/);
      if (m && !DURATION_MATH.test(ln)) taintedVars.set(m[1], li);
    });

    bareLines.forEach((ln, i) => {
      // R1 — loops (bare view: comments AND string prose can't fake control flow)
      if (UNBOUNDED_LITERAL.test(ln) || UNBOUNDED_COND.test(ln) || /\bsetInterval\s*\(/.test(ln)) {
        const window = bareLines.slice(Math.max(0, i - 5), i + 30).join("\n");
        if (llmReachable && !CAP.test(window))
          add(f, i + 1, "R1/stop-rules: unbounded " +
              (/\bsetInterval\s*\(/.test(ln) ? "timer loop (setInterval)" : "loop") +
              " with LLM work reachable" +
              (model.get(f).hasLLM ? "" : " (via imported worker)"), "HIGH",
              "Add a hard iteration cap; move routing decisions to a deterministic manager.");
      }
      // R4 — clock/randomness near routing (bare view), direct or via tainted var
      if (CLOCK_DICE.test(ln) && !DURATION_MATH.test(ln) &&
          ROUTING.test(bareLines.slice(i, i + 3).join("\n")))
        add(f, i + 1, "R4: clock/randomness near control flow", "REVIEW",
            "Routing must be reproducible — same inputs, same path. Keep time/randomness out of branch conditions (entropy in IDs is fine).");
      else if (/\b(if|switch|while|elif|match)\b/.test(ln) && !DURATION_MATH.test(ln) &&
               [...taintedVars].some(([v, li]) => i - li > 3 && new RegExp("\\b" + v + "\\b").test(ln)))
        add(f, i + 1, "R4: routing on a clock/random-derived variable", "REVIEW",
            "This branch condition uses a value assigned from a clock or RNG earlier in the file — same inputs must give the same path.");

      // R3 — external writes (code view: "POST" methods and Idempotency-Key
      // headers live in strings and must stay visible)
      const cln = codeLines[i];
      const isMutatingFetch = FETCH_CALL.test(cln) &&
        MUTATING_METHOD.test(codeLines.slice(i, i + 6).join("\n"));
      const isWrite = (WRITE_CALL.test(cln) && !FRAMEWORK_RESP.test(cln)) || isMutatingFetch;
      const isCreate = CREATE_CALL.test(cln) && !LLM.test(cln);
      if (isWrite || isCreate) {
        const window = codeLines.slice(Math.max(0, i - 10), i + 10).join("\n");
        const keyedGuard = GUARD_TOKENS.test(window) ||
          (GUARD_LOOKUP.test(window) && GUARD_KEY.test(window));
        if (!keyedGuard)
          add(f, i + 1,
              isWrite ? "R3: external write without a KEYED idempotency guard"
                      : "R3: .create( call without a keyed guard (verify: may be benign)",
              isWrite ? "MEDIUM" : "REVIEW",
              "Assume this step WILL retry. Guard with a check keyed on runId+step (or an Idempotency-Key the receiving system honors).");
      }
    });
  }
  if (anyLLM && !anyPersist)
    findings.push({ file: ".", line: 0, rule: "R2: no save points found anywhere", severity: "HIGH", fix:
        "LLM workflow with zero persistence: a crash restarts from step 1. Checkpoint each step's output keyed by run ID." });
  return { files, findings };
}

function selftest() {
  const corpus = path.join(__dirname, "..", "tests", "lint-corpus");
  const expected = JSON.parse(fs.readFileSync(path.join(corpus, "expected.json"), "utf8"));
  const { findings } = lintProject(corpus);
  const sevRank = { HIGH: 3, MEDIUM: 2, REVIEW: 1 };
  let failures = 0, recallHits = 0, recallWanted = 0, precisionFiles = 0;
  for (const c of expected.cases) {
    const forFile = findings.filter((x) => x.file === c.file);
    if (c.mustFind) {
      recallWanted++;
      const matches = forFile.filter((x) => x.rule.startsWith(c.mustFind));
      const atOk = c.atLine === undefined || matches.some((x) => x.line === c.atLine);
      const cntOk = c.maxCount === undefined || matches.length <= c.maxCount;
      if (matches.length && atOk && cntOk) { recallHits++; console.log(`✅ recall  ${c.file}: ${c.mustFind} found` + (c.atLine ? ` at line ${c.atLine}` : "") + (c.maxCount ? `, count ${matches.length}<=${c.maxCount}` : "")); }
      else {
        failures++;
        const why = !matches.length ? `expected ${c.mustFind}, got [${forFile.map((x) => x.rule + "@" + x.line).join("; ") || "nothing"}]`
          : !atOk ? `${c.mustFind} found at [${matches.map((x) => x.line).join(",")}] but NOT at required line ${c.atLine}`
          : `${c.mustFind} fired ${matches.length}× (max ${c.maxCount}) at lines [${matches.map((x) => x.line).join(",")}] — extra hits are false positives (comments/strings?)`;
        console.error(`❌ recall  ${c.file}: ${why}`);
      }
    }
    if (c.mustBeCleanAtOrAbove) {
      precisionFiles++;
      const noisy = forFile.filter((x) => sevRank[x.severity] >= sevRank[c.mustBeCleanAtOrAbove]);
      if (!noisy.length) console.log(`✅ precision ${c.file}: no ${c.mustBeCleanAtOrAbove}+ findings`);
      else { failures++; console.error(`❌ precision ${c.file}: false positives → ${noisy.map((x) => `${x.rule}@${x.line}`).join("; ")}`); }
    }
  }
  console.log(`\nSelftest: recall ${recallHits}/${recallWanted} planted violations caught; ` +
              `precision clean on ${precisionFiles - failures >= 0 ? precisionFiles : 0} clean files; ${failures} failure(s).`);
  process.exit(failures ? 1 : 0);
}

if (process.argv[2] === "--selftest") { selftest(); } else {
  const root = path.resolve(process.argv[2] || ".");
  const { files, findings } = lintProject(root);
  if (!findings.length) {
    console.log(`Scanned ${files.length} files under ${root}: no violations flagged. (Heuristic scan — absence of findings ≠ proof of correctness. Run chaos.js for proof.)`);
  } else {
    const order = { HIGH: 0, MEDIUM: 1, REVIEW: 2 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    console.log(`Scanned ${files.length} files. ${findings.length} finding(s) — verify each against the live file (cite via KnoSky) before fixing:\n`);
    for (const x of findings)
      console.log(`[${x.severity}] ${x.file}:${x.line}  ${x.rule}\n        fix: ${x.fix}`);
    console.log("\nHIGH/MEDIUM are actionable; REVIEW is advisory. Known blind spots are documented in this file's header.");
  }
}
