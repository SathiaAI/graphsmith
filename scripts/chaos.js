#!/usr/bin/env node
/* GraphSmith chaos harness — proves crash recovery is real.
 * Works on any project following scaffold conventions:
 *   .runs/<runId>/<step>.json checkpoints + intents.log/effects.log per run.
 *
 * v0.1.1 (post council review):
 *   - PA-9: asserts the kill actually landed MID-FLIGHT; a run that finished
 *     before the kill is a loud FAILURE, never a hollow green.
 *   - PA-1: understands the write-ahead intent pattern. If the restart halts
 *     with UNRESOLVED SIDE EFFECT, that is a PASS of the safety property —
 *     the workflow refused to guess about external state instead of
 *     silently re-sending.
 *   - Honest scope: this proves (a) crash recovery and (b) exactly-once for
 *     RECORDED effects. Exactly-once delivery to an external system further
 *     requires an idempotency key that system honors (graduation.md 3–4).
 * Usage: node chaos.js <project-dir> */
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const dir = path.resolve(process.argv[2] || ".");
const managerPath = path.join(dir, "manager.js");
if (!fs.existsSync(managerPath)) { console.error(`No manager.js in ${dir}`); process.exit(1); }
const PIPELINE = JSON.parse(fs.readFileSync(path.join(dir, "pipeline.json"), "utf8"));
const totalSteps = PIPELINE.length;

const runId = "chaos-" + Date.now() + "-" + Math.random().toString(36).slice(2, 7);
const runDir = path.join(dir, ".runs", runId);
const fail = (msg) => { console.error("❌ FAIL: " + msg); process.exit(1); };
const pass = (msg) => console.log("✅ " + msg);

function startManager(extraArgs) {
  return spawn(process.execPath, ["manager.js", runId].concat(extraArgs || []),
    { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
}
const collect = (p) => {
  let out = "";
  p.stdout.on("data", (d) => (out += d));
  p.stderr.on("data", (d) => (out += d));
  return () => out;
};
const alivePid = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return false; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// A checkpoint is ONLY a completed-step save point: `.runs/<runId>/<step>.json`
// for a step named in pipeline.json (e.g. 01-gather.json). Everything else the
// run writes into that directory is RUNTIME STATE, not progress:
// `.watchdog-*` (capability snapshot / heartbeat), `budget-state.json`,
// `.lock`, and the logs. Counting runtime state as a checkpoint made the
// harness (a) mis-report how far the run got, (b) mis-fire the PA-9
// degenerate-run check, and (c) demand a `"status":"skipped"` line for a
// pseudo-step like `.watchdog-capability`, whose normal re-write on resume was
// then reported as a broken resume. Deriving the allowlist from pipeline.json
// (which this harness already reads) is exact: no naming heuristic to drift.
const STEP_CHECKPOINTS = new Set(PIPELINE.map((s) => s.step + ".json"));
const checkpoints = () =>
  fs.existsSync(runDir)
    ? fs.readdirSync(runDir).filter((f) => STEP_CHECKPOINTS.has(f) && !f.includes(".corrupt-"))
    : [];

(async () => {
  // --- Run 1: kill after the first checkpoint appears -----------------------
  const p1 = startManager();
  let p1Exited = false;
  p1.on("exit", () => (p1Exited = true));
  const p1Closed = new Promise((r) => p1.on("close", r)); // registered BEFORE the kill
  const killState = await new Promise((resolve) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      const cps = checkpoints();
      if (p1Exited) { clearInterval(iv); resolve({ landed: false, cps }); }
      else if (cps.length >= 1) { clearInterval(iv); p1.kill("SIGKILL"); resolve({ landed: true, cps }); }
      else if (Date.now() - t0 > 15000) { clearInterval(iv); p1.kill("SIGKILL"); resolve({ landed: false, cps, timeout: true }); }
    }, 25);
  });
  if (killState.timeout) fail("No checkpoint appeared within 15s — are save points implemented?");
  // PA-9: a kill that hit a finished (or already-dead) process proved nothing.
  if (!killState.landed || killState.cps.length >= totalSteps)
    fail(`Degenerate run: the workflow finished (${killState.cps.length}/${totalSteps} checkpoints) before the kill landed — nothing was interrupted, so this green would be hollow. Keep a small delay in workers while chaos-testing, or use a longer pipeline.`);
  const survivedSteps = killState.cps;
  pass(`Kill landed MID-FLIGHT after ${survivedSteps.length}/${totalSteps} checkpoint(s): ${survivedSteps.join(", ")}`);

  // --- GUARD DISPOSITION after the crash (D4 dead-man switch) ---------------
  // The scaffold's watchdog arms a dead-man switch (WATCHDOG-HALT.json) for the
  // whole run: if the GUARD dies, that file persists and the next start REFUSES
  // to resume without --acknowledge-budget. Killing the manager resolves one of
  // two legitimate ways, and which one depends on the OS, not on correctness:
  //   (a) the watchdog is orphaned but ALIVE — it sees its watched pid is gone,
  //       writes an `.orphan` marker and withdraws the switch (POSIX).
  //   (b) the kill takes the whole process tree, so the watchdog dies WITH the
  //       manager (observed on Windows) — the switch legitimately persists and a
  //       plain restart MUST refuse: from disk, "guard dead + run unfinished" is
  //       exactly the state D4 exists to catch.
  // Both are asserted. Acknowledging unconditionally instead would step over a
  // real halt, and assuming (a) everywhere turns a correct Windows refusal into
  // a red build; assuming (b) everywhere would let a guard that silently fails
  // to disarm pass unnoticed. A guard still ALIVE but not disarming is a defect
  // and fails below, as does real halt evidence (halt without dead_man_switch).
  await p1Closed;
  const haltFile = path.join(runDir, "WATCHDOG-HALT.json");
  const readHalt = () => { try { return JSON.parse(fs.readFileSync(haltFile, "utf8")); } catch (e) { return null; } };
  const disarmDeadline = Date.now() + 15000;
  let guard = { seen: false, disarmed: true, evidence: null };
  for (;;) {
    const armed = readHalt();
    if (armed === null) break;                            // withdrawn (or no watchdog in this project)
    if (armed.halt && !armed.dead_man_switch)
      fail("The watchdog reported a REAL halt during the crash test: " + (armed.kill_message || "") +
        "\n" + JSON.stringify(armed) + "\nThat is not the fault this harness injected — investigate before trusting any resume result.");
    guard = { seen: true, disarmed: false, evidence: armed };
    if (armed.watchdog_pid && !alivePid(armed.watchdog_pid)) break;   // case (b): guard died with the tree
    if (Date.now() > disarmDeadline)
      fail("The watchdog is still RUNNING (pid " + armed.watchdog_pid + ") 15s after its manager died but never withdrew its dead-man switch — the orphan hand-off is broken, so every crashed run needs a manual --acknowledge-budget. Evidence: " + JSON.stringify(armed));
    await sleep(50);
  }
  if (guard.seen && guard.disarmed === false && readHalt() === null) guard.disarmed = true;
  // The orphan marker is the guard's positive receipt for case (a): it withdrew
  // the switch BECAUSE its manager died, not because the switch was never armed.
  // On POSIX the hand-off usually completes before the manager's `close` event
  // even reaches us, so the marker — not a transient armed switch — is the
  // evidence to assert on.
  if (guard.disarmed && fs.existsSync(haltFile + ".orphan"))
    pass("Guard hand-off: the orphaned watchdog withdrew its dead-man switch and left an orphan marker after its manager died (D4 evidence intact; a stale switch does not block the resume)");
  if (guard.seen && !guard.disarmed) {
    // The kill took the guard too. Prove the switch is HONORED before using it:
    // a plain restart that resumed here would mean D4 is decorative.
    const refuse = startManager();
    const refuseOut = collect(refuse);
    const refuseCode = await new Promise((r) => refuse.on("close", r));
    if (refuseCode === 0 || !/--acknowledge-budget/.test(refuseOut()))
      fail("The kill killed the guard too (watchdog pid " + guard.evidence.watchdog_pid + " is gone) and its dead-man switch is still on disk, yet a plain restart did NOT refuse (exit " + refuseCode + ") — a dead guard was silently stepped over. Output:\n" + refuseOut().slice(0, 500));
    pass("Dead-man switch honored: the kill took the guard with the manager, and a plain restart REFUSED to resume past a dead guard (D4), demanding --acknowledge-budget");
  }

  // --- Run 2: restart — must resume and either complete or halt safely ------
  // When the guard died with the manager (case b) the operator's documented
  // move is --acknowledge-budget; the resume guarantees below must hold either
  // way. Acknowledging RECORDS the extension, it does not reset any budget.
  const p2 = startManager(guard.disarmed ? [] : ["--acknowledge-budget"]);
  let out2 = "", err2 = "";
  p2.stdout.on("data", (d) => (out2 += d));
  p2.stderr.on("data", (d) => (err2 += d));
  const code = await new Promise((r) => p2.on("close", r));

  if (code !== 0) {
    // PA-1: the intent pattern's designed response to a crash INSIDE the
    // side-effect window is a loud halt — that is the safety property working.
    if ((out2 + err2).includes("UNRESOLVED SIDE EFFECT")) {
      // PD-3 hardening: a halt is CERTIFIED only when the on-disk intent/effect
      // state justifies it. String-only gaming (emitting the magic string with
      // no unresolved intent) and forged logs (a duplicate already recorded in
      // effects.log) both FAIL the checks below — the verdict is earned by
      // state, never by a string. Deliberately OUT OF SCOPE: an external
      // re-send the logs never recorded is invisible to this proof, which
      // certifies RECORDED effects only — closing that gap is exactly the job
      // of an idempotency key the receiving system honors (graduation.md 3–4).
      const rd = (f) => { const p = path.join(runDir, f);
        return fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\n").filter(Boolean) : []; };
      const ints = rd("intents.log"), effs = rd("effects.log");
      const unresolved = ints.filter((s) => !effs.includes(s));
      if (!unresolved.length)
        fail("Restart claimed UNRESOLVED SIDE EFFECT but intents.log/effects.log show no unresolved intent — the halt string was emitted without the halt state (non-compliant worker, or a bug). A halt must be justified by on-disk evidence.");
      const cnt = {};
      for (const s of effs) cnt[s] = (cnt[s] || 0) + 1;
      const dup = Object.entries(cnt).filter(([, n]) => n > 1);
      if (dup.length)
        fail("Restart halted, but effects.log ALREADY shows duplicated effects: " + dup.map(([s, n]) => s + "\u00d7" + n).join(", ") + " — the halt came after a re-send, not instead of one.");
      pass("Halt-on-uncertainty: restart REFUSED to guess about " + unresolved.join(", ") + " — verified against on-disk intent/effect state (no duplicates, unresolved intent real). This is the designed safe behavior.");
      console.log("   → Follow the printed instructions in the run's output, resolve the intent, and re-run chaos for the resume path.");
      console.log("\n🏁 Chaos harness: SAFETY PASS for " + runId + " (halt path)");
      process.exit(0);
    }
    fail("Restarted run did not complete (exit " + code + ") and did not halt safely:\n" + err2.slice(0, 500));
  }
  if (!out2.includes("__done__")) fail("Restarted run finished without completion marker");

  // KILL TEST: pre-crash steps must have been skipped, not re-executed
  for (const c of survivedSteps) {
    const step = c.replace(/\.json$/, "");
    if (!out2.includes(`"step":"${step}","status":"skipped`))
      fail(`Step ${step} was re-executed after restart — resume is broken`);
  }
  pass("Kill test: restart resumed from save points (no finished work redone)");

  // DOUBLE-RUN TEST: each step's RECORDED side effects exactly once across both runs
  const effectsPath = path.join(runDir, "effects.log");
  if (!fs.existsSync(effectsPath)) fail("No effects.log — workers must record executions");
  const counts = {};
  for (const line of fs.readFileSync(effectsPath, "utf8").split("\n").filter(Boolean))
    counts[line] = (counts[line] || 0) + 1;
  const dupes = Object.entries(counts).filter(([, n]) => n > 1);
  if (dupes.length) fail("Recorded side effects executed more than once: " + dupes.map(([s, n]) => `${s}×${n}`).join(", ") +
    " — the intent/completion guard is broken (see worker stubs).");
  // consistency: every completion must have an intent
  const intents = fs.existsSync(path.join(runDir, "intents.log"))
    ? fs.readFileSync(path.join(runDir, "intents.log"), "utf8").split("\n").filter(Boolean) : [];
  for (const s of Object.keys(counts))
    if (!intents.includes(s)) fail(`Completion recorded for ${s} with no intent — write-ahead ordering violated`);
  pass("Double-run test: every recorded side effect executed exactly once (intent → effect → completion ordering intact)");

  // --- POWER-LOSS PROBE (PD-14): stage the on-disk state a power failure
  // leaves when the completion append is lost (intent fsync'd + effect fired,
  // completion gone) and prove the restart HALTS instead of re-sending. This
  // is the failure class SIGKILL alone can never exercise: the page cache
  // survives a process kill, so only a staged state can test flush loss.
  const plId = runId + "-powerloss";
  const plDir = path.join(dir, ".runs", plId);
  fs.mkdirSync(plDir, { recursive: true });
  fs.writeFileSync(path.join(plDir, "intents.log"), PIPELINE[0].step + "\n");
  const pl = spawn(process.execPath, ["manager.js", plId], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  let plOut = "";
  pl.stdout.on("data", (d) => (plOut += d)); pl.stderr.on("data", (d) => (plOut += d));
  const plCode = await new Promise((r2) => pl.on("close", r2));
  if (plCode === 0 || !plOut.includes("UNRESOLVED SIDE EFFECT"))
    fail("Power-loss probe: a staged intent-without-completion state did NOT halt the run (exit " + plCode + ") — a lost completion write would silently re-send. Are the write-ahead logs fsync'd and checked on resume?");
  pass("Power-loss probe: staged flush-loss state (intent recorded, completion lost) HALTED loudly instead of re-sending");

  // --- RUN-LOCK PROBES (PD-13 + PE-2): three checks. Same-run concurrency
  // must refuse; a dead holder's lock must be stolen so crashed runs stay
  // resumable; and a live-but-RECYCLED pid must be judged by its lease, not its
  // pid alone (expired → stolen, fresh → refused). See the pid-reuse probe below.
  const lkId = runId + "-lock";
  const lkLockPath = path.join(dir, ".runs", lkId, ".lock");
  const a = spawn(process.execPath, ["manager.js", lkId], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  // Poll for the ACTUAL precondition -- A's lock file existing on disk -- instead
  // of a fixed sleep. A fixed 150ms wait here was UNSAFE, not just tight: this
  // codebase's own measured node-startup jitter on a loaded 2-core box is
  // 187-211ms, and manager.js is heavier than whatever was measured to produce
  // that number -- it loads the state-store + tunables and runs step-name
  // validation before acquireLock() ever executes. So the margin was already
  // NEGATIVE relative to the codebase's own documented jitter floor: on a loaded
  // box A can plausibly still be mid-startup at t+150ms, in which case B finds no
  // lock file, acquires cleanly, and this probe fails on scheduler noise rather
  // than a real defect. Polling for the real precondition removes the race
  // entirely; the 5s deadline is generous (matches the other generous timeouts
  // in this file, e.g. the 15s checkpoint-wait above) and a timeout here is
  // reported as what it would actually be -- manager.js failing to acquire its
  // own lock -- never silently swallowed as a flake.
  const lockDeadline = Date.now() + 5000;
  while (!fs.existsSync(lkLockPath)) {
    if (Date.now() > lockDeadline) {
      a.kill("SIGKILL");
      fail("Lock probe: manager A never created its lock file (" + lkLockPath + ") within 5s of starting -- acquireLock() may be hanging or broken; this is not a timing fluke.");
    }
    await sleep(25);
  }
  const b = spawn(process.execPath, ["manager.js", lkId], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  let bErr = "";
  b.stderr.on("data", (d) => (bErr += d));
  const bCode = await new Promise((r2) => b.on("close", r2));
  a.kill("SIGKILL");
  if (bCode === 0 || !bErr.includes("actively locked"))
    fail("Lock probe: a second manager on the SAME run did not refuse (exit " + bCode + ") — concurrent same-run execution can double-fire effects.");
  pass("Lock probe: concurrent manager on the same run REFUSED (fresh lease) while the first held the lock");
  const stId = runId + "-stale";
  const stDir = path.join(dir, ".runs", stId);
  fs.mkdirSync(stDir, { recursive: true });
  fs.writeFileSync(path.join(stDir, ".lock"), "999999999");
  const st = spawn(process.execPath, ["manager.js", stId], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  let stOut = "";
  st.stdout.on("data", (d) => (stOut += d));
  const stCode = await new Promise((r2) => st.on("close", r2));
  if (stCode !== 0 || !stOut.includes("stolen") || !stOut.includes("__done__"))
    fail("Stale-lock probe: a lock held by a dead pid blocked the run (exit " + stCode + ") — crashed runs must stay resumable.");
  pass("Stale-lock probe: dead holder's lock stolen with a log line; run completed");

  // --- PID-REUSE PROBE (PE-2): a dead manager's pid can be recycled by the OS
  // for some unrelated LIVE process, so pid-liveness alone would refuse a
  // resumable run forever. The lease is the tie-breaker: a LIVE-but-reused pid
  // whose lock has not been heartbeat-renewed within the lease is stolen; the
  // same pid with a FRESH heartbeat is (correctly) presumed a real holder and
  // refused. We plant the HARNESS's own pid (alive, but not a manager) and
  // drive both directions with a short GRAPHSMITH_LEASE_MS test hook.
  //
  // leaseMs was 1000ms, which gave Direction B (fresh lease, below) a margin of
  // only ~800-850ms against this codebase's own measured 187-211ms node-startup
  // jitter floor -- freshMtime is captured in THIS process, then the child
  // manager has to spawn, load its state-store + tunables, and reach
  // acquireLock() before it reads the lockfile's mtime and computes ageMs; that
  // startup gap eats into the margin the same way it does in the run-lock probe
  // above. ~4x headroom is the same shape of margin as the lock-probe hazard
  // this session already found unsafe at ~150ms fixed vs ~200ms jitter, and load
  // can only shrink it further, never grow it -- so it is widened here in
  // keeping with the generous-margin convention this file uses everywhere else
  // (e.g. the 5s/15s deadlines above): leaseMs=5000ms puts Direction B's margin
  // at ~4800ms, roughly 23x the jitter floor, while costing zero extra wall-clock
  // time (the fresh direction never sleeps out the lease -- the child manager
  // reads the mtime and returns almost immediately either way).
  const leaseMs = 5000;
  const runLease = (label, mtimeMs) =>
    new Promise((res) => {
      const id = runId + "-" + label;
      const d = path.join(dir, ".runs", id);
      fs.mkdirSync(d, { recursive: true });
      const lk = path.join(d, ".lock");
      fs.writeFileSync(lk, String(process.pid));   // harness pid: alive, not a manager
      const when = new Date(mtimeMs);
      fs.utimesSync(lk, when, when);
      const child = spawn(process.execPath, ["manager.js", id],
        { cwd: dir, stdio: ["ignore", "pipe", "pipe"],
          env: { ...process.env, GRAPHSMITH_LEASE_MS: String(leaseMs) } });
      let o = "";
      child.stdout.on("data", (x) => (o += x));
      child.stderr.on("data", (x) => (o += x));
      child.on("close", (c) => res({ code: c, out: o }));
    });
  // Direction A — lease EXPIRED (mtime backdated by 2× the lease): must steal + finish.
  // This arithmetic is expressed relative to leaseMs, not a hardcoded number, so
  // it scales automatically with the leaseMs bump above: expiredMtime is always
  // 2×leaseMs (10000ms with leaseMs=5000) in the past, i.e. always at least
  // leaseMs (5000ms) further expired than the expiry threshold itself. The
  // manager-side startup gap that erodes Direction B's margin only ADDS to
  // ageMs here (more real time passes before the child reads the mtime), which
  // makes this direction MORE clearly expired, never less -- load helps this
  // direction, it cannot break it. Still reliably expires after the leaseMs
  // change.
  const expiredMtime = Date.now() - 2 * leaseMs;   // duration arithmetic, not a routing input
  const expired = await runLease("reuse-expired", expiredMtime);
  if (expired.code !== 0 || !/expired lease.*stolen/.test(expired.out) || !expired.out.includes("__done__"))
    fail("Pid-reuse probe (expired lease): a live-but-reused pid with a stale lease was NOT stolen (exit " +
      expired.code + ") — a recycled pid would block a resumable run forever. Output:\n" + expired.out.slice(0, 400));
  // Direction B — lease FRESH (mtime = now): a real live holder must be refused.
  const freshMtime = Date.now();
  // (the timestamp above is only a lockfile mtime — never a branch condition)
  const fresh = await runLease("reuse-fresh", freshMtime);
  if (fresh.code === 0 || !fresh.out.includes("actively locked"))
    fail("Pid-reuse probe (fresh lease): a live pid with a fresh heartbeat was NOT refused (exit " +
      fresh.code + ") — a real concurrent holder must never be stolen from. Output:\n" + fresh.out.slice(0, 400));
  pass("Pid-reuse probe: live-but-reused pid with an EXPIRED lease stolen (run resumed); the SAME pid with a FRESH heartbeat refused — lease, not pid alone, decides liveness");

  console.log("\n🏁 Chaos harness: ALL CHECKS PASSED for " + runId);
  console.log("Fault model: process crash (SIGKILL) executed live + power-loss/flush-loss via staged on-disk state + same-run concurrency + pid-reuse/lease-expiry. NOT covered: disk corruption beyond torn writes, clock skew, or the correctness of your business logic.");
  console.log("   Scope of this proof: crash recovery + exactly-once RECORDED effects. Exactly-once delivery to an external system additionally needs an idempotency key it honors (references/graduation.md, rungs 3–4).");
})();
