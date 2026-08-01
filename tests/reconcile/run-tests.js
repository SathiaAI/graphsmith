"use strict";

/* tests/reconcile/run-tests.js — Lane A adversarial suite for
 * scripts/reconcile.js.
 *
 * Standalone, framework-free, mirrors the repo's own
 * tests/<component>/<family>/run-tests.js convention (see e.g.
 * tests/verify/deepseek/run-tests.js): report()/PASS-FAIL-SKIP, exit 1 on
 * any failure. Discoverable by scripts/ci-run-suites.js's literal
 * "run-tests.js" filename walk.
 *
 * Every ADVERSARIAL TEST listed in the Lane A brief is implemented below as
 * an executable check, not a description:
 *   - symlink-out-of-tree write-through refusal
 *   - kill-mid-write atomicity (temp file + rename, never in-place)
 *   - marker-lookalike text in user prose is not misparsed as a real marker
 *     (GROUP 4a-4d), and a marker-lookalike line embedded in the CALLER'S OWN
 *     renderedBlock body is refused loudly at embed time rather than
 *     silently corrupting a later read (GROUP 4e-4g)
 *   - two concurrent reconcile processes against the same file, both for the
 *     SAME blockId (GROUP 5.1-5.2, torn/merged-file safety) and for
 *     DIFFERENT blockIds (GROUP 5.3-5.4, silent-data-loss safety -- see the
 *     CONCURRENCY note in scripts/reconcile.js)
 *   - CRLF / BOM / mixed line endings
 *   - old-schema-version call against an already-newer-spliced file, and the reverse
 *
 * Each of the "confirm this actually catches a regression" tests (atomicity,
 * symlink refusal, marker-lookalike-in-body refusal (GROUP 4e/4f), and
 * different-blockId concurrent data loss (GROUP 5.3/5.4)) was run once
 * against a DELIBERATELY BROKEN copy of scripts/reconcile.js and confirmed
 * to fail, then re-run against the real file and confirmed to pass -- see
 * the accompanying report, not encoded here (that check is inherently a
 * two-run manual process, not something a single automated suite run can
 * self-demonstrate).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const cp = require("child_process");

const RECONCILE_PATH = path.resolve(__dirname, "..", "..", "scripts", "reconcile.js");
const reconcileLib = require(RECONCILE_PATH);
const { reconcile } = reconcileLib;

let passed = 0;
let failed = 0;
let skipped = 0;

function report(name, ok, detail) {
  if (ok === true) {
    console.log(`PASS: ${name}`);
    passed++;
  } else if (ok === false) {
    console.log(`FAIL: ${name}${detail ? " -- " + detail : ""}`);
    failed++;
  } else {
    console.log(`SKIP: ${name}${detail ? " -- " + detail : ""}`);
    skipped++;
  }
}

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-reconcile-${label}-`));
}

function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best-effort */
  }
}

// ===========================================================================
// GROUP 1: core four-way state machine (sanity baseline the adversarial
// tests below build on)
// ===========================================================================
function groupCoreStateMachine() {
  console.log("\n=== GROUP 1: core four-way state machine ===");
  const dir = tmpDir("core");
  try {
    const target = path.join(dir, "AGENTS.md");

    // absent -> created
    let r = reconcile(target, "Hello from GraphSmith.", { blockId: "graphsmith" });
    report("1.1 absent -> created", r.status === "created", JSON.stringify(r));
    const afterCreate = fs.readFileSync(target, "utf8");
    report(
      "1.2 created content has well-formed markers",
      afterCreate ===
        '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nHello from GraphSmith.\n<!-- graphsmith:end id="graphsmith" -->\n',
      JSON.stringify(afterCreate)
    );

    // present-current -> no-op
    r = reconcile(target, "Hello from GraphSmith.", { blockId: "graphsmith" });
    report("1.3 present-current -> unchanged (no-op)", r.status === "unchanged" && r.bytesWritten === 0, JSON.stringify(r));
    const afterNoop = fs.readFileSync(target, "utf8");
    report("1.4 unchanged did not touch bytes", afterNoop === afterCreate);

    // present-drifted -> spliced in place
    r = reconcile(target, "Hello v2 from GraphSmith.", { blockId: "graphsmith" });
    report("1.5 present-drifted -> spliced", r.status === "spliced", JSON.stringify(r));
    const afterSplice = fs.readFileSync(target, "utf8");
    report(
      "1.6 splice replaced only the block body",
      afterSplice ===
        '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nHello v2 from GraphSmith.\n<!-- graphsmith:end id="graphsmith" -->\n'
    );

    // present-no-markers -> append, preserving existing content byte-for-byte
    const other = path.join(dir, "OTHER.md");
    fs.writeFileSync(other, "# My repo\n\nSome user prose that has nothing to do with GraphSmith.\n");
    const beforeAppend = fs.readFileSync(other, "utf8");
    r = reconcile(other, "Block content.", { blockId: "graphsmith" });
    report("1.7 present-no-markers -> appended", r.status === "appended", JSON.stringify(r));
    const afterAppend = fs.readFileSync(other, "utf8");
    report("1.8 append preserved original bytes as a prefix", afterAppend.startsWith(beforeAppend.replace(/\s+$/, "")));
    report(
      "1.9 append added a well-formed block",
      afterAppend.includes('<!-- graphsmith:begin id="graphsmith" schema_version="1" -->') &&
        afterAppend.includes('<!-- graphsmith:end id="graphsmith" -->')
    );

    // re-running reconcile against the appended file with the same block is idempotent
    r = reconcile(other, "Block content.", { blockId: "graphsmith" });
    report("1.10 re-reconciling appended file -> unchanged (idempotent)", r.status === "unchanged", JSON.stringify(r));

    // distinct blockIds coexist in one file without colliding
    r = reconcile(other, "A second, unrelated block.", { blockId: "cursor" });
    report("1.11 second distinct blockId -> appended alongside first", r.status === "appended", JSON.stringify(r));
    const afterSecond = fs.readFileSync(other, "utf8");
    report(
      "1.12 both blocks present and independently addressable",
      afterSecond.includes('id="graphsmith"') && afterSecond.includes('id="cursor"')
    );
    const rReread = reconcile(other, "Block content.", { blockId: "graphsmith" });
    report("1.13 first block still unchanged after second block added", rReread.status === "unchanged", JSON.stringify(rReread));
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 2: symlink-out-of-tree refusal (no write-through)
// ===========================================================================
function groupSymlinkRefusal() {
  console.log("\n=== GROUP 2: symlink out-of-tree refusal ===");
  const dir = tmpDir("symlink");
  try {
    const outsideDir = tmpDir("symlink-outside");
    try {
      const outsideFile = path.join(outsideDir, "secret.txt");
      const outsideOriginal = "THIS FILE MUST NEVER BE MODIFIED BY THE RECONCILER\n";
      fs.writeFileSync(outsideFile, outsideOriginal);

      const target = path.join(dir, "AGENTS.md");
      fs.symlinkSync(outsideFile, target);

      const r = reconcile(target, "Should never land anywhere.", { blockId: "graphsmith" });
      report("2.1 symlinked target refused, not written", r.status === "refused" && r.reason === "symlink-refused", JSON.stringify(r));

      const outsideAfter = fs.readFileSync(outsideFile, "utf8");
      report("2.2 the symlink's real target was never written through", outsideAfter === outsideOriginal);

      const lst = fs.lstatSync(target);
      report("2.3 the symlink itself was left in place (not unlinked/replaced)", lst.isSymbolicLink());
    } finally {
      cleanup(outsideDir);
    }
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 3: kill-mid-write atomicity. A real child process is started with
// GRAPHSMITH_RECONCILE_TEST_STALL_MS set (see scripts/reconcile.js's
// TEST-ONLY HOOK), stalled after the scratch temp file is fsynced but
// BEFORE the rename onto the target, then SIGKILLed. The target must be
// left exactly as it was before the run -- never partially written.
// ===========================================================================
function onExit(child) {
  return new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runChildReconcileAndKill(target, blockId, renderedBlock, stallMs, killAfterMs) {
  const script = [
    `const { reconcile } = require(${JSON.stringify(RECONCILE_PATH)});`,
    `reconcile(${JSON.stringify(target)}, ${JSON.stringify(renderedBlock)}, { blockId: ${JSON.stringify(blockId)} });`,
  ].join("\n");
  const child = cp.spawn(process.execPath, ["-e", script], {
    env: Object.assign({}, process.env, { GRAPHSMITH_RECONCILE_TEST_STALL_MS: String(stallMs) }),
    stdio: "ignore",
  });
  const exited = onExit(child); // must be attached before any await, so no 'exit' event is missed
  const killedAt = Date.now();
  await delay(killAfterMs); // a REAL (event-loop-yielding) sleep -- unlike Atomics.wait, this lets
  // libuv's own SIGCHLD/reap machinery run, which matters below: a busy
  // (event-loop-blocking) wait here previously left killed children as
  // permanent zombies (Node's async reap never got a turn to run), which
  // made the *next* liveness check see the OS process table entry as
  // "still alive" forever and hang the suite. Real awaits fixed that.
  let killSucceeded = false;
  try {
    child.kill("SIGKILL");
    killSucceeded = true;
  } catch (_) {
    /* process may have already exited (raced past the stall) -- surfaced via exit code below */
  }
  // Wait for the real 'exit' event (bounded) so no in-flight temp
  // file/handle from the child leaks into the next assertion.
  await Promise.race([exited, delay(2000)]);
  return { killSucceeded, elapsedMs: Date.now() - killedAt };
}

async function groupKillMidWrite() {
  console.log("\n=== GROUP 3: kill mid-write atomicity ===");
  const dir = tmpDir("killmidwrite");
  try {
    const target = path.join(dir, "AGENTS.md");
    const original = '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nORIGINAL CONTENT\n<!-- graphsmith:end id="graphsmith" -->\n';
    fs.writeFileSync(target, original);
    const beforeStat = fs.statSync(target);

    // Stall 1500ms before rename; kill after 300ms, well inside the stall
    // window, well before any rename can occur.
    const { killSucceeded } = await runChildReconcileAndKill(target, "graphsmith", "REPLACEMENT CONTENT that must never land", 1500, 300);
    if (!killSucceeded) {
      report("3.1 child process was killed mid-stall", "SKIP", "kill() threw; environment may not support SIGKILL delivery here");
    } else {
      report("3.1 child process was killed mid-stall", true);
    }

    const afterContent = fs.readFileSync(target, "utf8");
    report("3.2 target file is byte-identical to before the killed run (no partial/corrupted write)", afterContent === original);

    const afterStat = fs.statSync(target);
    report("3.3 target file size unchanged", afterStat.size === beforeStat.size);

    // No leftover scratch temp file should remain visible under the target's
    // directory with content from the killed run -- best-effort check; a
    // leaked temp file is a cleanliness issue, not a corruption issue, so
    // this is informational rather than a hard requirement of "atomic".
    const leftovers = fs.readdirSync(dir).filter((f) => f.includes(".graphsmith-reconcile."));
    report(
      "3.4 (informational) any leaked scratch temp file is NOT at the target path and target is untouched",
      afterContent === original,
      `leftover temp files present: ${leftovers.length}`
    );

    // Sanity: a NORMAL (non-killed) run after the killed one still
    // completes and produces the expected spliced content -- proves the
    // stall hook itself does not permanently break normal operation.
    const r = reconcile(target, "NEW CONTENT AFTER NORMAL RUN", { blockId: "graphsmith" });
    report("3.5 normal (non-killed) run after the killed one still succeeds", r.status === "spliced", JSON.stringify(r));
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 4: marker-lookalike text in user prose must not be misparsed
// ===========================================================================
function groupMarkerLookalike() {
  console.log("\n=== GROUP 4: marker-lookalike text is not misparsed ===");
  const dir = tmpDir("lookalike");
  try {
    // 4a: the exact marker text quoted mid-sentence (not alone on its own
    // line) must not be treated as a real marker.
    {
      const target = path.join(dir, "midsentence.md");
      const prose =
        "# Docs\n\nThe reconciler looks for a line like `<!-- graphsmith:begin id=\"graphsmith\" schema_version=\"1\" -->` in the file.\n\nMore prose after.\n";
      fs.writeFileSync(target, prose);
      const before = fs.readFileSync(target, "utf8");
      const r = reconcile(target, "Real block content.", { blockId: "graphsmith" });
      report("4a.1 mid-sentence lookalike -> treated as no-markers (appended)", r.status === "appended", JSON.stringify(r));
      const after = fs.readFileSync(target, "utf8");
      report("4a.2 original prose (including the lookalike text) preserved verbatim", after.startsWith(before.replace(/\s+$/, "")));
      report("4a.3 appended block is well-formed", after.includes('<!-- graphsmith:end id="graphsmith" -->'));
    }

    // 4b: case-difference lookalike on its own line must not match.
    {
      const target = path.join(dir, "wrongcase.md");
      const prose = '# Docs\n\n<!-- GRAPHSMITH:BEGIN id="graphsmith" schema_version="1" -->\nsome text someone pasted, wrong case\n<!-- GRAPHSMITH:END id="graphsmith" -->\n';
      fs.writeFileSync(target, prose);
      const before = fs.readFileSync(target, "utf8");
      const r = reconcile(target, "Real block content.", { blockId: "graphsmith" });
      report("4b.1 wrong-case lookalike -> treated as no-markers (appended)", r.status === "appended", JSON.stringify(r));
      const after = fs.readFileSync(target, "utf8");
      report("4b.2 original wrong-case text preserved untouched", after.startsWith(before.replace(/\s+$/, "")));
    }

    // 4c: begin marker for a DIFFERENT blockId must not be treated as a
    // match for this call's blockId -- it gets its own independent append.
    {
      const target = path.join(dir, "differentid.md");
      fs.writeFileSync(
        target,
        '<!-- graphsmith:begin id="cursor" schema_version="1" -->\ncursor block\n<!-- graphsmith:end id="cursor" -->\n'
      );
      const r = reconcile(target, "graphsmith block content.", { blockId: "graphsmith" });
      report("4c.1 different blockId's markers do not match this call", r.status === "appended", JSON.stringify(r));
      const after = fs.readFileSync(target, "utf8");
      report(
        "4c.2 both blocks present afterward, cursor block untouched",
        after.includes('id="cursor"') && after.includes("cursor block") && after.includes('id="graphsmith"')
      );
    }

    // 4d: a begin marker with no matching end (malformed/truncated paste)
    // must not be misparsed as a valid block to splice into -- falls back
    // to append, and nothing existing is deleted.
    {
      const target = path.join(dir, "unterminated.md");
      const prose = '# Docs\n\n<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\norphaned body, no end marker follows\n\nMore user prose after the orphan.\n';
      fs.writeFileSync(target, prose);
      const before = fs.readFileSync(target, "utf8");
      const r = reconcile(target, "Real block content.", { blockId: "graphsmith" });
      report("4d.1 unterminated begin marker -> treated as no valid block (appended)", r.status === "appended", JSON.stringify(r));
      const after = fs.readFileSync(target, "utf8");
      report("4d.2 nothing from the original file was deleted", after.startsWith(before.replace(/\s+$/, "")));
    }

    // 4e: a marker-lookalike line INSIDE the renderedBlock's own BODY (not
    // the surrounding file prose) must be refused loudly at embed time,
    // never silently written -- a naive future findBlock() scan over the
    // FILE cannot tell "the real end marker" apart from this lookalike line
    // once it's embedded, and would truncate the block on every subsequent
    // reconcile. This is the reverse direction of 4a-4d above: those cover
    // lookalikes already in the file/prose; this covers a lookalike this
    // module itself would be asked to embed.
    {
      const target = path.join(dir, "bodylookalike.md");
      const maliciousBody =
        'Some real content.\n<!-- graphsmith:end id="anything" -->\nMore content that would be silently orphaned.\n';
      let threw = null;
      try {
        reconcile(target, maliciousBody, { blockId: "graphsmith" });
      } catch (e) {
        threw = e;
      }
      report("4e.1 marker-lookalike line in body throws TypeError", threw instanceof TypeError, threw ? threw.message : "did not throw");
      report("4e.2 refused write left target file absent (nothing written)", !fs.existsSync(target));
    }

    // 4f: same as 4e, but the file ALREADY has a real block, and the drift
    // (splice) path is the one that would embed the malicious body. Must
    // refuse and leave the existing valid block completely untouched.
    {
      const target = path.join(dir, "bodylookalike-splice.md");
      const original = '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nORIGINAL SAFE BODY\n<!-- graphsmith:end id="graphsmith" -->\n';
      fs.writeFileSync(target, original);
      const maliciousBody = '<!-- graphsmith:begin id="other-id" schema_version="7" -->\nlooks like a begin marker for a totally different id\n';
      let threw = null;
      try {
        reconcile(target, maliciousBody, { blockId: "graphsmith" });
      } catch (e) {
        threw = e;
      }
      report("4f.1 marker-lookalike line in drifted-splice body throws TypeError", threw instanceof TypeError, threw ? threw.message : "did not throw");
      const after = fs.readFileSync(target, "utf8");
      report("4f.2 refused splice left the existing block completely untouched", after === original);
    }

    // 4g: a LEGITIMATE need to discuss the marker format in prose -- NOT
    // anchored at line-start in the exact marker shape -- must still work.
    // Over-broadening the refusal into rejecting anything that merely
    // mentions the marker syntax would itself be a regression.
    {
      // 4g-i: the marker text appears mid-sentence (inline), not alone on
      // its own line.
      const target1 = path.join(dir, "legit-inline.md");
      const legitBody1 =
        'Docs note that GraphSmith uses a line like `<!-- graphsmith:begin id="x" schema_version="1" -->` to delimit blocks.\n';
      let r1 = null;
      let threw1 = null;
      try {
        r1 = reconcile(target1, legitBody1, { blockId: "graphsmith" });
      } catch (e) {
        threw1 = e;
      }
      report(
        "4g.1 marker text mid-sentence (not anchored at column 0) is NOT rejected",
        threw1 === null && r1 && r1.status === "created",
        threw1 ? threw1.message : JSON.stringify(r1)
      );

      // 4g-ii: the marker text appears at the start of a line but with
      // extra leading whitespace, so it does not literally begin the line
      // at column 0 with "<!--".
      const target2 = path.join(dir, "legit-indented.md");
      const legitBody2 = 'Example marker syntax:\n\n    <!-- graphsmith:begin id="x" schema_version="1" -->\n\nThat is indented as a code sample.\n';
      let r2 = null;
      let threw2 = null;
      try {
        r2 = reconcile(target2, legitBody2, { blockId: "graphsmith" });
      } catch (e) {
        threw2 = e;
      }
      report(
        "4g.2 marker text with leading whitespace (not column-0-anchored) is NOT rejected",
        threw2 === null && r2 && r2.status === "created",
        threw2 ? threw2.message : JSON.stringify(r2)
      );
      if (r2 && r2.status === "created") {
        const after2 = fs.readFileSync(target2, "utf8");
        report("4g.3 the indented lookalike text made it into the file verbatim", after2.includes('    <!-- graphsmith:begin id="x" schema_version="1" -->'));
      } else {
        report("4g.3 the indented lookalike text made it into the file verbatim", "SKIP", "4g.2 did not create the file");
      }
    }
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 5: two concurrent reconcile processes against the same file
// ===========================================================================
async function groupConcurrentReconcile() {
  console.log("\n=== GROUP 5: concurrent reconcile processes ===");
  const dir = tmpDir("concurrent");
  try {
    const target = path.join(dir, "AGENTS.md");
    // Neither process races the other into a corrupted/merged file: each
    // computes and atomically installs a COMPLETE, well-formed file. The
    // final result must be exactly one of the two valid full outputs, never
    // a byte-level interleaving of both.
    const scriptFor = (content) =>
      [
        `const { reconcile } = require(${JSON.stringify(RECONCILE_PATH)});`,
        `reconcile(${JSON.stringify(target)}, ${JSON.stringify(content)}, { blockId: "graphsmith" });`,
      ].join("\n");

    const expectedA = '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nCONTENT FROM PROCESS A\n<!-- graphsmith:end id="graphsmith" -->\n';
    const expectedB = '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nCONTENT FROM PROCESS B\n<!-- graphsmith:end id="graphsmith" -->\n';

    const raceOutcomes = [];
    const TRIALS = 8;
    for (let trial = 0; trial < TRIALS; trial++) {
      if (fs.existsSync(target)) fs.rmSync(target);
      const pA = cp.spawn(process.execPath, ["-e", scriptFor("CONTENT FROM PROCESS A")], { stdio: "ignore" });
      const pB = cp.spawn(process.execPath, ["-e", scriptFor("CONTENT FROM PROCESS B")], { stdio: "ignore" });
      const exitedA = onExit(pA);
      const exitedB = onExit(pB);
      await Promise.race([Promise.all([exitedA, exitedB]), delay(5000)]);
      const finalContent = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : null;
      raceOutcomes.push(finalContent);
    }

    const allWellFormed = raceOutcomes.every((c) => c === expectedA || c === expectedB);
    report(
      "5.1 concurrent reconciles never produce a torn/merged file (always exactly one full valid output)",
      allWellFormed,
      `outcomes: ${JSON.stringify(raceOutcomes)}`
    );
    report("5.2 all trials completed and produced a result", raceOutcomes.every((c) => c !== null), `outcomes: ${JSON.stringify(raceOutcomes)}`);
  } finally {
    cleanup(dir);
  }

  // -------------------------------------------------------------------------
  // 5.3+: two concurrent reconcile processes against the same target file
  // with DIFFERENT blockIds. This is the data-loss bug: same-blockId racing
  // (above) only ever has to pick one of two equally-valid full outputs, but
  // a different-blockId race must end up with BOTH blocks present -- a plain
  // last-rename-wins primitive silently drops whichever call's rename lost,
  // with no error. The unfixed module reproduced this in roughly 30-60% of
  // trials; run enough real (child-process, not simulated) trials that a
  // real fix's pass rate is convincingly different from that base rate.
  // -------------------------------------------------------------------------
  const diffDir = tmpDir("concurrent-diffid");
  try {
    const target = path.join(diffDir, "AGENTS.md");
    const scriptForId = (blockId, content) =>
      [
        `const { reconcile } = require(${JSON.stringify(RECONCILE_PATH)});`,
        `reconcile(${JSON.stringify(target)}, ${JSON.stringify(content)}, { blockId: ${JSON.stringify(blockId)} });`,
      ].join("\n");

    const DIFF_TRIALS = 40;
    let bothPresentCount = 0;
    let dataLossCount = 0;
    const dataLossDetails = [];

    for (let trial = 0; trial < DIFF_TRIALS; trial++) {
      if (fs.existsSync(target)) fs.rmSync(target);
      const pAlpha = cp.spawn(process.execPath, ["-e", scriptForId("alpha", "CONTENT ALPHA")], { stdio: "ignore" });
      const pBeta = cp.spawn(process.execPath, ["-e", scriptForId("beta", "CONTENT BETA")], { stdio: "ignore" });
      const exitedAlpha = onExit(pAlpha);
      const exitedBeta = onExit(pBeta);
      await Promise.race([Promise.all([exitedAlpha, exitedBeta]), delay(5000)]);

      const finalContent = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : "";
      const hasAlpha = finalContent.includes('id="alpha"') && finalContent.includes("CONTENT ALPHA");
      const hasBeta = finalContent.includes('id="beta"') && finalContent.includes("CONTENT BETA");
      if (hasAlpha && hasBeta) {
        bothPresentCount++;
      } else {
        dataLossCount++;
        dataLossDetails.push({ trial, hasAlpha, hasBeta, finalContent });
      }
    }

    report(
      "5.3 concurrent reconciles with DIFFERENT blockIds never silently drop one block " +
        `(${bothPresentCount}/${DIFF_TRIALS} trials had both blocks present)`,
      dataLossCount === 0,
      dataLossCount === 0 ? undefined : `lost data in ${dataLossCount}/${DIFF_TRIALS} trials: ${JSON.stringify(dataLossDetails.slice(0, 3))}`
    );

    // Whichever trial's final content we still have on disk, it must also
    // parse as two well-formed, independently-extractable blocks via the
    // module's own findBlock() -- not just a string .includes() coincidence.
    if (fs.existsSync(target)) {
      const finalRaw = fs.readFileSync(target, "utf8");
      const alphaBlock = reconcileLib.findBlock(finalRaw, "alpha");
      const betaBlock = reconcileLib.findBlock(finalRaw, "beta");
      report(
        "5.4 final file's last trial output has both blocks well-formed per findBlock()",
        !!alphaBlock && !!betaBlock && alphaBlock.body === "CONTENT ALPHA\n" && betaBlock.body === "CONTENT BETA\n",
        JSON.stringify({ alphaBlock, betaBlock })
      );
    } else {
      report("5.4 final file's last trial output has both blocks well-formed per findBlock()", "SKIP", "no file left from last trial");
    }
  } finally {
    cleanup(diffDir);
  }
}

// ===========================================================================
// GROUP 6: CRLF, BOM, mixed line endings
// ===========================================================================
function groupLineEndingsAndBom() {
  console.log("\n=== GROUP 6: CRLF / BOM / mixed line endings ===");
  const dir = tmpDir("eol");
  try {
    // 6a: pure CRLF file, no existing block -> append; existing CRLF bytes preserved.
    {
      const target = path.join(dir, "crlf.md");
      const content = "# Title\r\n\r\nSome CRLF content.\r\n";
      fs.writeFileSync(target, content);
      const r = reconcile(target, "Block body.", { blockId: "graphsmith" });
      report("6a.1 CRLF file with no markers -> appended without crashing", r.status === "appended", JSON.stringify(r));
      const after = fs.readFileSync(target, "utf8");
      report("6a.2 original CRLF bytes preserved as a prefix", after.startsWith(content.replace(/[\r\n]+$/, "")));
      // Round trip: reconciling again with the same body must be a no-op.
      const r2 = reconcile(target, "Block body.", { blockId: "graphsmith" });
      report("6a.3 re-reconciling the CRLF-file result is idempotent (unchanged)", r2.status === "unchanged", JSON.stringify(r2));
    }

    // 6b: BOM-prefixed file -> BOM preserved across append and splice.
    {
      const target = path.join(dir, "bom.md");
      const content = "﻿# Title\n\nSome content.\n";
      fs.writeFileSync(target, content);
      let r = reconcile(target, "Block body.", { blockId: "graphsmith" });
      report("6b.1 BOM file -> appended", r.status === "appended", JSON.stringify(r));
      let after = fs.readFileSync(target, "utf8");
      report("6b.2 BOM preserved at byte 0 after append", after.charCodeAt(0) === 0xfeff);
      report("6b.3 rest of original content preserved", after.includes("# Title") && after.includes("Some content."));

      r = reconcile(target, "Block body v2.", { blockId: "graphsmith" });
      report("6b.4 BOM file -> spliced on drift", r.status === "spliced", JSON.stringify(r));
      after = fs.readFileSync(target, "utf8");
      report("6b.5 BOM still preserved after splice", after.charCodeAt(0) === 0xfeff);
    }

    // 6c: mixed line endings (some \n, some \r\n) in a file already carrying
    // a valid block -- splice must not corrupt the untouched surrounding
    // mixed-EOL content.
    {
      const target = path.join(dir, "mixed.md");
      const content =
        "# Title\r\n\nMixed line endings above/below.\r\n\n" +
        '<!-- graphsmith:begin id="graphsmith" schema_version="1" -->\nold body\n<!-- graphsmith:end id="graphsmith" -->\n' +
        "\r\nTrailing mixed content.\n";
      fs.writeFileSync(target, content);
      const r = reconcile(target, "new body", { blockId: "graphsmith" });
      report("6c.1 mixed-EOL file with existing block -> spliced", r.status === "spliced", JSON.stringify(r));
      const after = fs.readFileSync(target, "utf8");
      report("6c.2 content before the block preserved with its original EOLs", after.startsWith("# Title\r\n\nMixed line endings above/below.\r\n\n"));
      report("6c.3 content after the block preserved with its original EOLs", after.endsWith("\r\nTrailing mixed content.\n"));
      report("6c.4 block body actually updated", after.includes("new body") && !after.includes("old body"));
    }
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 7: schema-version compatibility, both directions
// ===========================================================================
function groupSchemaVersionCompat() {
  console.log("\n=== GROUP 7: schema-version compatibility (old vs. new, both directions) ===");
  const dir = tmpDir("schemaver");
  try {
    // Direction 1: an "old" call (schemaVersion "1") encounters a file
    // already spliced by a "newer" call (schemaVersion "2"). Must refuse,
    // must not write.
    {
      const target = path.join(dir, "newer-first.md");
      let r = reconcile(target, "content from the newer schema", { blockId: "graphsmith", schemaVersion: "2" });
      report("7.1 setup: newer-schema call creates the file", r.status === "created" && r.schemaVersion === "2", JSON.stringify(r));
      const before = fs.readFileSync(target, "utf8");

      r = reconcile(target, "content an older-schema caller would have written", { blockId: "graphsmith", schemaVersion: "1" });
      report(
        "7.2 older-schema call against a newer-spliced file is refused",
        r.status === "refused" && r.reason === "future-schema-version" && r.foundSchemaVersion === "2",
        JSON.stringify(r)
      );
      const after = fs.readFileSync(target, "utf8");
      report("7.3 refused call did not modify the file at all", after === before);
    }

    // Direction 2 (the reverse): a "newer" call (schemaVersion "2")
    // encounters a file written by an "older" call (schemaVersion "1").
    // Must succeed (compatible), splice in place, and re-stamp the version.
    {
      const target = path.join(dir, "older-first.md");
      let r = reconcile(target, "content from the older schema", { blockId: "graphsmith", schemaVersion: "1" });
      report("7.4 setup: older-schema call creates the file", r.status === "created" && r.schemaVersion === "1", JSON.stringify(r));

      r = reconcile(target, "content from the newer schema", { blockId: "graphsmith", schemaVersion: "2" });
      report(
        "7.5 newer-schema call against an older-schema file succeeds (splices, does not refuse)",
        r.status === "spliced" && r.previousSchemaVersion === "1" && r.schemaVersion === "2",
        JSON.stringify(r)
      );
      const after = fs.readFileSync(target, "utf8");
      report("7.6 file now stamped with the newer schema version", after.includes('schema_version="2"'));
      report("7.7 file body actually updated to the newer content", after.includes("content from the newer schema"));

      // And now the file is at version 2; an old (version 1) call against
      // it must again be refused -- confirms the upgrade "stuck" and isn't
      // silently reversible by an older caller.
      r = reconcile(target, "should not land", { blockId: "graphsmith", schemaVersion: "1" });
      report("7.8 after upgrade, an old-schema call is refused again", r.status === "refused" && r.reason === "future-schema-version", JSON.stringify(r));
    }

    // Same version + same body -> unchanged even across two separately-typed calls.
    {
      const target = path.join(dir, "same-version.md");
      reconcile(target, "stable content", { blockId: "graphsmith", schemaVersion: "3" });
      const r = reconcile(target, "stable content", { blockId: "graphsmith", schemaVersion: "3" });
      report("7.9 same schema version + identical body -> unchanged", r.status === "unchanged", JSON.stringify(r));
    }
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// GROUP 8: input validation / defensive checks
// ===========================================================================
function groupInputValidation() {
  console.log("\n=== GROUP 8: input validation ===");
  const dir = tmpDir("validation");
  try {
    const target = path.join(dir, "AGENTS.md");
    let threw = false;
    try {
      reconcile(target, "x", { blockId: "Not_Valid_ID" });
    } catch (e) {
      threw = e instanceof TypeError;
    }
    report("8.1 invalid blockId throws TypeError", threw);

    threw = false;
    try {
      reconcile(target, "x", { blockId: "graphsmith", schemaVersion: "not-a-number" });
    } catch (e) {
      threw = e instanceof TypeError;
    }
    report("8.2 invalid schemaVersion throws TypeError", threw);

    threw = false;
    try {
      reconcile(target, 12345, { blockId: "graphsmith" });
    } catch (e) {
      threw = e instanceof TypeError;
    }
    report("8.3 non-string renderedBlock throws TypeError", threw);

    // Refuse a directory target rather than crashing or writing through it.
    fs.mkdirSync(target);
    const r = reconcile(target, "x", { blockId: "graphsmith" });
    report("8.4 directory at target path is refused, not written into", r.status === "refused" && r.reason === "target-not-a-file", JSON.stringify(r));
  } finally {
    cleanup(dir);
  }
}

// ===========================================================================
// MAIN
// ===========================================================================
async function runAll() {
  console.log("=== Lane A — tests/reconcile/run-tests.js ===");
  console.log(`Started: ${new Date().toISOString()}\n`);

  groupCoreStateMachine();
  groupSymlinkRefusal();
  await groupKillMidWrite();
  groupMarkerLookalike();
  await groupConcurrentReconcile();
  groupLineEndingsAndBom();
  groupSchemaVersionCompat();
  groupInputValidation();

  console.log("\n--- SUMMARY ---");
  console.log(`PASS:  ${passed}`);
  console.log(`FAIL:  ${failed}`);
  console.log(`SKIP:  ${skipped}`);
  console.log(`TOTAL: ${passed + failed + skipped}`);

  if (failed > 0) {
    console.log(`\n*** ${failed} TEST(S) FAILED ***`);
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAll().catch((e) => {
  console.error("FATAL:", e && e.stack ? e.stack : e);
  process.exit(2);
});
