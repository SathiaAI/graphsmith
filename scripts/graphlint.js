#!/usr/bin/env node
/* GraphSmith linter — heuristic scan for loop-engineering violations.
 * Findings are HEURISTIC: verify each against the live file before acting.
 * Usage: node graphlint.js <path> */
const fs = require("fs");
const path = require("path");

const root = path.resolve(process.argv[2] || ".");
const exts = new Set([".js", ".ts", ".mjs", ".py"]);
const SKIP = new Set(["node_modules", ".git", ".runs", "dist", "build", "__pycache__", ".venv", "venv"]);

const LLM = /\b(anthropic|openai|gemini|generativeai|litellm|chat\.completions|messages\.create|generate_content|invoke_model)\b/i;
const UNBOUNDED = /while\s*\(\s*(true|1)\s*\)|while\s+True\s*:|for\s*\(\s*;\s*;\s*\)/;
const CAP = /\b(max_?(iter|retries|attempts|steps|loops)|attempt\s*<|retries\s*<)\b/i;
const PERSIST = /\b(writeFile|appendFile|checkpoint|savepoint|\.save\(|pickle\.dump|json\.dump|INSERT INTO|\.set\(|put_item)\b/i;
const CLOCK_DICE = /\b(Date\.now\(\)|Math\.random\(\)|time\.time\(\)|random\.(random|choice|randint))\b/;
const ROUTING = /\b(if|switch|elif|match)\b/;
const WRITE_CALL = /\b(fetch\(|axios\.(post|put)|requests\.(post|put)|\.send\(|sendmail|create\()/i;
const IDEMPO = /\b(idempoten|dedup|Idempotency-Key|upsert|ON CONFLICT|if_not_exists|existsSync)\b/i;

const files = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (exts.has(path.extname(e.name))) files.push(p);
  }
})(root);

const findings = [];
const add = (file, line, rule, severity, fix) =>
  findings.push({ file: path.relative(root, file), line, rule, severity, fix });

let anyLLM = false, anyPersist = false;
for (const f of files) {
  const src = fs.readFileSync(f, "utf8");
  const lines = src.split("\n");
  const hasLLM = LLM.test(src);
  anyLLM ||= hasLLM; anyPersist ||= PERSIST.test(src);

  lines.forEach((ln, i) => {
    if (UNBOUNDED.test(ln)) {
      const window = lines.slice(Math.max(0, i - 5), i + 30).join("\n");
      if (hasLLM && !CAP.test(window))
        add(f, i + 1, "R1/stop-rules: unbounded loop near LLM calls", "HIGH",
            "Add a hard iteration cap; move routing decisions to a deterministic manager.");
    }
    if (CLOCK_DICE.test(ln) && ROUTING.test(lines.slice(i, i + 3).join("\n")))
      add(f, i + 1, "R4: clock/randomness near control flow", "REVIEW",
          "Routing must be reproducible — same inputs, same path. Keep time/randomness out of branch conditions.");
    if (WRITE_CALL.test(ln) && !IDEMPO.test(lines.slice(Math.max(0, i - 10), i + 10).join("\n")))
      add(f, i + 1, "R3: external write without idempotency guard", "MEDIUM",
          "Assume this step WILL retry. Check-before-write, or derive a dedupe key from runId+step.");
  });
}
if (anyLLM && !anyPersist)
  add(".", 0, "R2: no save points found anywhere", "HIGH",
      "LLM workflow with zero persistence: a crash restarts from step 1. Checkpoint each step's output keyed by run ID.");

if (!findings.length) {
  console.log(`Scanned ${files.length} files under ${root}: no violations flagged. (Heuristic scan — absence of findings ≠ proof of correctness. Run chaos.js for proof.)`);
} else {
  const order = { HIGH: 0, MEDIUM: 1, REVIEW: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  console.log(`Scanned ${files.length} files. ${findings.length} finding(s) — verify each against the live file (cite via KnoSky) before fixing:\n`);
  for (const x of findings)
    console.log(`[${x.severity}] ${x.file}:${x.line}  ${x.rule}\n        fix: ${x.fix}`);
}
