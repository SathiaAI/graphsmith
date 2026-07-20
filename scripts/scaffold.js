#!/usr/bin/env node
/* GraphSmith scaffolder — generates a runnable, zero-dependency
 * multi-agent project with checkpointing, resume, idempotency, and logs.
 * Usage: node scaffold.js <project-name> */
const fs = require("fs");
const path = require("path");

const name = process.argv[2];
if (!name) { console.error("Usage: node scaffold.js <project-name>"); process.exit(1); }
const root = path.resolve(process.cwd(), name);
if (fs.existsSync(root)) { console.error(`Refusing to overwrite existing: ${root}`); process.exit(1); }

const files = {
"manager.js": `#!/usr/bin/env node
/* MANAGER — deterministic control flow. LLM calls belong in workers/, never here.
 * Rules enforced: save after every step, resume on restart, capped retries,
 * no clocks/randomness in routing, one log line per step. */
const fs = require("fs");
const path = require("path");

const PIPELINE = require("./pipeline.json"); // ordered steps: [{ step, worker }]
const MAX_RETRIES = 2;

const runId = process.argv[2] || "run-" + Date.now(); // ID may use time; ROUTING may not
const runDir = path.join(__dirname, ".runs", runId);
fs.mkdirSync(runDir, { recursive: true });

const log = (step, status, ms) =>
  console.log(JSON.stringify({ runId, step, status, ms }));

async function executeStep({ step, worker }, input) {
  const ckpt = path.join(runDir, step + ".json");
  if (fs.existsSync(ckpt)) {                       // resume + idempotency
    log(step, "skipped (checkpoint exists)", 0);
    return JSON.parse(fs.readFileSync(ckpt, "utf8"));
  }
  const fn = require("./workers/" + worker);
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const t0 = Date.now();
    try {
      const out = await fn.run(input, { runId, step, runDir });
      fs.writeFileSync(ckpt + ".tmp", JSON.stringify(out ?? null));
      fs.renameSync(ckpt + ".tmp", ckpt);          // atomic save point
      log(step, "ok", Date.now() - t0);
      return out;
    } catch (e) {
      log(step, \`error attempt \${attempt + 1}: \${e.message}\`, Date.now() - t0);
      if (attempt === MAX_RETRIES) throw e;        // stop rule: capped retries
    }
  }
}

(async () => {
  let carry = null;                                // minimal handoff: pass only prior output
  for (const stepDef of PIPELINE) carry = await executeStep(stepDef, carry);
  log("__done__", "complete", 0);
})().catch((e) => { console.error("Run failed:", e.message); process.exit(1); });
`,

"pipeline.json": JSON.stringify(
  [
    { step: "01-gather", worker: "gather.js" },
    { step: "02-process", worker: "process.js" },
    { step: "03-deliver", worker: "deliver.js" },
  ], null, 2),

"workers/gather.js": workerStub("gather", "Collect the inputs your job needs. Replace the body with real logic (API calls, file reads, an LLM call)."),
"workers/process.js": workerStub("process", "Transform gathered data. If you call an LLM, do it HERE — never in manager.js."),
"workers/deliver.js": workerStub("deliver", "Produce the final output (send, write, publish). MUST stay safe to re-run: check before you send twice."),

"README.md": `# ${name}

A multi-agent workflow with crash recovery built in. Runs with zero dependencies and zero API keys out of the box.

## Run it
\`\`\`bash
node manager.js            # new run
node manager.js my-run-1   # named run (resumable)
\`\`\`

## If it crashes
Run the same command with the same run name. Finished steps are skipped automatically — it picks up where it stopped. Progress lives in \`.runs/<runId>/\`, one JSON save point per step.

## Make it yours
Edit the workers in \`workers/\` (one job each) and the step order in \`pipeline.json\`. Keep decisions about "what runs next" in \`manager.js\`/\`pipeline.json\` — AI calls stay inside workers.

## Verify before trusting it
From the folder containing the GraphSmith skill:
\`\`\`bash
node scripts/chaos.js ${name}
\`\`\`
This kills a run mid-flight, restarts it, and proves it resumed without redoing finished work.
`,
".gitignore": ".runs/\nnode_modules/\n",
};

function workerStub(label, doc) {
  return `/* WORKER: ${label} — one job only. ${doc} */
const fs = require("fs");
const path = require("path");
module.exports.run = async (input, ctx) => {
  // RULE 3 — safe to re-run. A crash can interrupt this worker AFTER its side
  // effect but BEFORE its checkpoint, so it WILL sometimes run twice. Guard
  // every real side effect (send/write/charge) with a check-before-write keyed
  // by runId+step, like this. Delete this guard and the chaos harness fails you.
  const fx = path.join(ctx.runDir, "effects.log");
  const already = fs.existsSync(fx) && fs.readFileSync(fx, "utf8").split("\\n").includes(ctx.step);
  if (!already) {
    // <-- your real side effect goes here
    fs.appendFileSync(fx, ctx.step + "\\n"); // records the execution for chaos.js
  }
  await new Promise((r) => setTimeout(r, 300)); // simulate work; delete when real
  return { ...(input || {}), [ctx.step]: "done" };
};
`;
}

for (const [rel, content] of Object.entries(files)) {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}
console.log(`Created ${root}`);
console.log(`Next: cd ${name} && node manager.js`);
