#!/usr/bin/env node
/* GraphSmith scaffolder — generates a runnable, zero-dependency
 * multi-agent project with checkpointing, resume, idempotency, and logs.
 * v0.1.1: durable checkpoints (fsync + corrupt-recovery), collision-proof
 * default runIds, and a write-ahead intent pattern in worker stubs that
 * HALTS on uncertain side effects instead of silently re-sending (council
 * findings PA-1, PA-2, PA-7). Usage: node scaffold.js <project-name> */
const fs = require("fs");
const path = require("path");

const name = process.argv[2];
if (!name) { console.error("Usage: node scaffold.js <project-name>"); process.exit(1); }
const root = path.resolve(process.cwd(), name);
if (fs.existsSync(root)) { console.error(`Refusing to overwrite existing: ${root}`); process.exit(1); }

const files = {
"manager.js": `#!/usr/bin/env node
/* MANAGER — deterministic control flow. LLM calls belong in workers/, never here.
 * Rules enforced: save after every step (fsync'd, atomic), resume on restart,
 * corrupted-checkpoint recovery, capped retries, no clocks/randomness in
 * ROUTING (the default run ID uses time+entropy, which is allowed — IDs are
 * not routing), one log line per step. */
const fs = require("fs");
const path = require("path");

const PIPELINE = require("./pipeline.json"); // ordered steps: [{ step, worker }]
const MAX_RETRIES = 2;

// ID may use time+randomness; ROUTING may not. Entropy prevents two managers
// started in the same millisecond from sharing (and corrupting) one run dir.
const runId = process.argv[2] || "run-" + Date.now() + "-" + Math.random().toString(36).slice(2, 9);
const runDir = path.join(__dirname, ".runs", runId);
fs.mkdirSync(runDir, { recursive: true });

const log = (step, status, ms) =>
  console.log(JSON.stringify({ runId, step, status, ms }));

// STEP-NAME VALIDATION — a duplicate step name would share a checkpoint and be
// silently skipped (a run reporting success without doing the work); unsafe
// characters break the per-step files. Fail loudly at start, never mid-run.
{
  const seen = new Set();
  for (const { step } of PIPELINE) {
    if (!/^[A-Za-z0-9._-]+$/.test(step || ""))
      { console.error("Invalid step name " + JSON.stringify(step) + " — use letters, digits, dot, dash, underscore."); process.exit(1); }
    if (seen.has(step))
      { console.error("Duplicate step name \\"" + step + "\\" in pipeline.json — each step needs its own checkpoint."); process.exit(1); }
    seen.add(step);
  }
}

// RUN LOCK — the same claim-with-a-lease rule the coordination layer preaches
// (coordination rule 2: progress renews the lease), applied to the manager
// itself: one writer per run dir. A second manager on the SAME runId refuses
// loudly instead of racing the first (two concurrent readers of "not done yet"
// could both fire a side effect). Liveness is NOT pid-only: a live manager
// renews a heartbeat (the lockfile mtime) every HEARTBEAT_MS, and a holder is
// presumed dead only if its pid is gone OR its lease (last heartbeat) is older
// than LEASE_MS. So a RECYCLED pid — the OS handing a dead holder's number to
// some unrelated process — can no longer make a crashed run look alive forever;
// the lease expires and the run self-recovers with no manual file deletion.
// GRAPHSMITH_LEASE_MS / GRAPHSMITH_HEARTBEAT_MS override the timings (integer
// milliseconds) — documented test hooks used by the chaos harness.
const LEASE_MS = parseInt(process.env.GRAPHSMITH_LEASE_MS, 10) || 30000;
const HEARTBEAT_MS = parseInt(process.env.GRAPHSMITH_HEARTBEAT_MS, 10) || 5000;
const lockPath = path.join(runDir, ".lock");
function acquireLock() {
  for (let tryNo = 0; tryNo < 2; tryNo++) {
    try {
      const fd = fs.openSync(lockPath, "wx");
      fs.writeSync(fd, String(process.pid)); fs.fsyncSync(fd); fs.closeSync(fd);
      return;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      let holder = NaN;
      try { holder = parseInt(fs.readFileSync(lockPath, "utf8"), 10); } catch {}
      let alive = false;
      if (Number.isInteger(holder) && holder > 0) {
        try { process.kill(holder, 0); alive = holder !== process.pid; } catch { alive = false; }
      }
      if (!alive) {
        // Fast path: the recorded pid is simply not running.
        log("__lock__", "stale lock (pid " + (holder || "?") + " not running) — stolen", 0);
        try { fs.unlinkSync(lockPath); } catch {}
        continue;
      }
      // The pid is alive — but a live pid is not proof of a live RUN (it may be
      // a recycled/reused pid). Trust the lease: how long since the last
      // heartbeat renewed the lockfile mtime?
      let ageMs = Infinity;
      try { ageMs = Date.now() - fs.statSync(lockPath).mtimeMs; } catch {}
      if (ageMs <= LEASE_MS) {
        const ageS = Math.max(0, Math.round(ageMs / 1000));
        console.error("Run \\"" + runId + "\\" is actively locked (heartbeat " + ageS + "s ago, pid " + holder + "). If that process is real, wait for it; if this persists ~30s after a crash, re-run — the lease will expire and this run will take over.");
        process.exit(1);
      }
      // pid alive but the lease is stale — a crashed manager whose number was
      // reused, or one wedged past its lease. Steal it; the run resumes.
      log("__lock__", "expired lease (pid " + holder + " unresponsive or reused) — stolen", 0);
      try { fs.unlinkSync(lockPath); } catch {}
    }
  }
  console.error("Could not acquire run lock (contended) — try again."); process.exit(1);
}
acquireLock();
// Renew the lease: touch the lockfile mtime every heartbeat so a live run is
// never mistaken for a crashed one. .unref() so this timer alone never keeps
// the process alive. Cleared on release.
const heartbeat = setInterval(() => {
  try { const now = new Date(); fs.utimesSync(lockPath, now, now); } catch {}
}, HEARTBEAT_MS);
heartbeat.unref();
const releaseLock = () => { try { clearInterval(heartbeat); } catch {} try { fs.unlinkSync(lockPath); } catch {} };
process.on("exit", releaseLock);

function saveCheckpoint(ckpt, out) {
  // atomic AND durable: write temp, fsync, then rename. Without the fsync a
  // power loss can leave a 0-byte file after the rename — a permanent brick.
  const tmp = ckpt + ".tmp";
  const fd = fs.openSync(tmp, "w");
  try {
    fs.writeSync(fd, JSON.stringify(out ?? null));
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, ckpt);
}

function readCheckpoint(ckpt, step) {
  if (!fs.existsSync(ckpt)) return { done: false };
  try {
    return { done: true, out: JSON.parse(fs.readFileSync(ckpt, "utf8")) };
  } catch (e) {
    // A truncated/corrupt checkpoint must never brick the run forever:
    // back it up, warn, and treat the step as not-done (it will re-run —
    // which is exactly why workers must be safe to re-run).
    const bad = ckpt + ".corrupt-" + Date.now();
    try { fs.renameSync(ckpt, bad); } catch {}
    // keep only the 3 newest backups per step — evidence, not a landfill
    try {
      const base = path.basename(ckpt) + ".corrupt-";
      fs.readdirSync(runDir).filter((f) => f.startsWith(base)).sort().slice(0, -3)
        .forEach((f) => fs.unlinkSync(path.join(runDir, f)));
    } catch {}
    log(step, "warn: corrupt checkpoint backed up (" + path.basename(bad) + "); re-running step", 0);
    return { done: false };
  }
}

async function executeStep({ step, worker }, input) {
  const ckpt = path.join(runDir, step + ".json");
  const prior = readCheckpoint(ckpt, step);           // resume + idempotency
  if (prior.done) { log(step, "skipped (checkpoint exists)", 0); return prior.out; }
  const fn = require("./workers/" + worker);
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const t0 = Date.now();
    try {
      const out = await fn.run(input, { runId, step, runDir });
      saveCheckpoint(ckpt, out);                      // durable save point
      log(step, "ok", Date.now() - t0);
      return out;
    } catch (e) {
      log(step, \`error attempt \${attempt + 1}: \${e.message}\`, Date.now() - t0);
      if (e && e.unresolvedSideEffect) throw e;       // never retry into an unknown external state
      if (attempt === MAX_RETRIES) throw e;           // stop rule: capped retries
    }
  }
}

(async () => {
  let carry = null;                                   // minimal handoff: pass only prior output
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
"workers/deliver.js": workerStub("deliver", "Produce the final output (send, write, publish). MUST stay safe to re-run — read the intent-pattern comments below."),

"README.md": `# ${name}

A multi-agent workflow with crash recovery built in. Runs with zero dependencies and zero API keys out of the box.

## Run it
\`\`\`bash
node manager.js            # new run
node manager.js my-run-1   # named run (resumable)
\`\`\`

## If it crashes
Run the same command with the same run name. Finished steps are skipped automatically — it picks up where it stopped. Progress lives in \`.runs/<runId>/\`, one JSON save point per step. A corrupted save point (e.g. after power loss) is backed up automatically and the step re-runs.

## If it HALTS with "UNRESOLVED SIDE EFFECT"
A previous run crashed *inside* a side-effect window: the workflow recorded that it was about to act, but not that it finished. Rather than guess (and maybe double-send an email or double-charge a card), it stops and tells you. Check the external system, then follow the printed instructions: if the action did NOT happen, delete that step's line from \`.runs/<runId>/intents.log\`; if it DID happen, append the step name to \`.runs/<runId>/effects.log\`. Re-run — it continues from there. Halting loudly beats duplicating silently.

## What the recovery guarantees are (honestly)
Crash recovery, no duplicate *recorded* effects, power-loss halt behavior, and same-run locking are proven mechanically by the chaos harness: checkpoints AND the intent/effect logs are fsync'd, so even a power failure that eats the page cache leaves a state that HALTS instead of re-sending; a second manager on the same run refuses while the first is alive (its lease renewed by a heartbeat), and a holder that has died — or whose lease has expired, including a crashed run whose pid the OS later reused — has its lock stolen automatically. **A crashed run self-recovers within ~30 seconds: just re-run the same command. You never delete a lock file by hand.** Disclosed edge: a step that blocks the event loop synchronously for longer than the lease (~30s) stops the heartbeat and could be wrongly presumed dead — keep long-running work async (await I/O) so heartbeats keep flowing. True exactly-once delivery to an EXTERNAL system additionally requires that system to honor an idempotency key — the worker stubs construct one for you (\`runId + ":" + step\`); pass it to your API call (see \`references/graduation.md\` in the GraphSmith skill, rungs 3–4). Not covered: disk corruption beyond torn writes, and the correctness of your business logic.

## Make it yours
Edit the workers in \`workers/\` (one job each) and the step order in \`pipeline.json\`. Keep decisions about "what runs next" in \`manager.js\`/\`pipeline.json\` — AI calls stay inside workers.

## Verify before trusting it
From the folder containing the GraphSmith skill:
\`\`\`bash
node scripts/chaos.js ${name}
\`\`\`
This kills a run mid-flight, restarts it, and proves it resumed without redoing finished work — and that recorded effects ran exactly once. A loud safety-halt on an uncertain send also counts as a pass: that is the guard doing its job.
`,
".gitignore": ".runs/\nnode_modules/\n",
};

function workerStub(label, doc) {
  return `/* WORKER: ${label} — one job only. ${doc} */
const fs = require("fs");
const path = require("path");

/* RULE 3 — safe to re-run, with a WRITE-AHEAD INTENT pattern.
 * A crash can land in the window between doing a real side effect (send /
 * charge / post) and recording that it finished. No local trick can make that
 * window disappear — so this stub records INTENT before acting and COMPLETION
 * after. On resume:
 *   completion present    -> skip the effect (already done)
 *   intent w/o completion -> external state is UNKNOWN: HALT LOUDLY and ask
 *                            a human to check, instead of silently re-sending
 *   neither               -> proceed normally
 * True exactly-once requires the EXTERNAL system to honor an idempotency key —
 * pass it runId + ":" + step (see graduation.md rungs 3–4). Until then,
 * halting on uncertainty is the honest behavior. The chaos harness treats
 * this halt as a PASS of the safety property. */
const readLines = (p) => (fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\\n").filter(Boolean) : []);
// Durable append: fsync before returning, so an intent that precedes an external
// effect can never be lost to power failure while the effect survives. Without
// this, the write-ahead guarantee only covers process crashes.
function appendDurable(file, line) {
  const fd = fs.openSync(file, "a");
  try { fs.writeSync(fd, line + "\\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

module.exports.run = async (input, ctx) => {
  const intents = path.join(ctx.runDir, "intents.log");
  const effects = path.join(ctx.runDir, "effects.log");
  const doneAlready = readLines(effects).includes(ctx.step);
  const intended = readLines(intents).includes(ctx.step);

  if (!doneAlready && intended) {
    const err = new Error(
      \`UNRESOLVED SIDE EFFECT for step "\${ctx.step}" (run \${ctx.runId}): a previous run recorded intent but no completion — the external action may or may not have happened.\` +
      \`\\n  If it did NOT happen: delete the "\${ctx.step}" line from .runs/\${ctx.runId}/intents.log and re-run.\` +
      \`\\n  If it DID happen:     append "\${ctx.step}" to .runs/\${ctx.runId}/effects.log and re-run.\`);
    err.unresolvedSideEffect = true;                  // manager will NOT retry into this
    throw err;
  }
  if (!doneAlready) {
    appendDurable(intents, ctx.step);                 // 1) intent, BEFORE acting (fsync'd:
                                                      //    survives power loss, not just crashes)
    const idempotencyKey = ctx.runId + ":" + ctx.step; // PASS THIS to your external call if the
    // <-- your real side effect goes here; use idempotencyKey when the API supports one —
    //     that is what upgrades "halt on uncertainty" to true external exactly-once.
    void idempotencyKey; // remove when wired to a real call
    appendDurable(effects, ctx.step);                 // 2) completion, AFTER acting (fsync'd)
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
