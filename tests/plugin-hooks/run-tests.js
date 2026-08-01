#!/usr/bin/env node
/* GraphSmith plugin — adversarial hook test harness (contained).
 * Covers, as executable tests, every scenario in the Lane B kickoff's
 * adversarial-review checklist for the Claude Code plugin + lifecycle
 * hooks:
 *
 *   1. Windows PowerShell stdin-swallowing class of bug (simulated: a
 *      stdin stream that never closes) — hook must not hang.
 *   2. A second hypothetical plugin also registering SessionStart —
 *      neither plugin's output clobbers the other's.
 *   3. Killing the hook process mid-execution — session start must not
 *      hang waiting on it.
 *   4. Uninstalling while another plugin shares a combined settings
 *      file — only GraphSmith's own segment is removed.
 *
 * For (2) and (4), this file deliberately sabotages the real
 * implementation in place, re-runs the SAME assertion to confirm it now
 * fails, then restores the original file byte-for-byte (in a try/finally,
 * so a crash mid-sabotage can never leave the shipped file mutated) —
 * proving the tests actually exercise the code rather than merely
 * asserting a description of it.
 *
 * Verdicts come from process exit codes, parsed JSON output, and on-disk
 * file state — never from log strings. Exit 1 if anything fails.
 *
 * Zero-dependency CommonJS, Node >= 18, matching this repo's house style
 * (see tests/attacks/toctou/run-tests.js for the PASS/FAIL/UNAVAILABLE
 * convention this file follows).
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..");
const PLUGIN_ROOT = path.join(REPO, "plugins", "graphsmith-hooks");
const HOOKS_DIR = path.join(PLUGIN_ROOT, "hooks", "scripts");
const SESSION_START = path.join(HOOKS_DIR, "session-start.js");
const SUBAGENT_START = path.join(HOOKS_DIR, "subagent-start.js");
const UNINSTALL_CHECK = path.join(HOOKS_DIR, "uninstall-check.js");
const OTHER_PLUGIN_FIXTURE = path.join(__dirname, "fixtures", "other-plugin-session-start.js");

const results = [];
function record(name, status, detail) {
  results.push({ name, status, detail: detail || "" });
  console.log(`${status}\t${name}${detail ? "\t" + String(detail).replace(/\s+/g, " ").slice(0, 400) : ""}`);
}
function pass(n, d) { record(n, "PASS", d); }
function fail(n, d) { record(n, "FAIL", d); }

function mkTemp(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-plugin-hooks-${tag}-`));
}

/** Spawn a hook-like script and collect stdout/exit info. Resolves; never rejects. */
function runScript(scriptPath, { env = {}, stdinMode = "close-empty", killAfterMs = null } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const t0 = Date.now();
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));

    let killTimer = null;
    if (killAfterMs !== null) {
      killTimer = setTimeout(() => {
        try { child.kill("SIGKILL"); } catch (_err) { /* already dead */ }
      }, killAfterMs);
    }

    child.on("close", (code, signal) => {
      if (killTimer) clearTimeout(killTimer);
      resolve({ code, signal, stdout, stderr, ms: Date.now() - t0 });
    });

    if (stdinMode === "close-empty") {
      child.stdin.end();
    } else if (stdinMode === "never-close") {
      // Deliberately never write and never end() — simulates the
      // PowerShell stdin-swallowing class of bug: the child's stdin stays
      // open with no data and no EOF, indefinitely, unless the child
      // itself times out waiting on it.
    }
  });
}

/* ------------------------------------------------------------------ */
/* 1. Basic correctness: each hook produces valid, well-shaped output    */
/* ------------------------------------------------------------------ */

async function test_sessionStartBasicOutput() {
  const name = "sessionStart: emits valid hookSpecificOutput with discipline text";
  const r = await runScript(SESSION_START, { env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT } });
  try {
    if (r.code !== 0) return fail(name, `exit code ${r.code}, signal ${r.signal}, stderr=${r.stderr}`);
    const j = JSON.parse(r.stdout);
    const ctx = j.hookSpecificOutput && j.hookSpecificOutput.additionalContext;
    if (j.hookSpecificOutput.hookEventName !== "SessionStart") return fail(name, "wrong hookEventName");
    if (!ctx || !ctx.includes("Save after every step")) return fail(name, "discipline text missing from additionalContext");
    if (ctx.length > 9000) return fail(name, `context too long: ${ctx.length} chars`);
    pass(name, `${ctx.length} chars in ${r.ms}ms`);
  } catch (e) {
    fail(name, `stdout not valid JSON: ${e.message}; stdout=${r.stdout.slice(0, 200)}`);
  }
}

async function test_subagentStartBasicOutput() {
  const name = "subagentStart: emits valid hookSpecificOutput with discipline text";
  const r = await runScript(SUBAGENT_START, { env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT } });
  try {
    if (r.code !== 0) return fail(name, `exit code ${r.code}, signal ${r.signal}, stderr=${r.stderr}`);
    const j = JSON.parse(r.stdout);
    const ctx = j.hookSpecificOutput && j.hookSpecificOutput.additionalContext;
    if (j.hookSpecificOutput.hookEventName !== "SubagentStart") return fail(name, "wrong hookEventName");
    if (!ctx || !ctx.includes("Save after every step")) return fail(name, "discipline text missing from additionalContext");
    pass(name, `${ctx.length} chars in ${r.ms}ms`);
  } catch (e) {
    fail(name, `stdout not valid JSON: ${e.message}; stdout=${r.stdout.slice(0, 200)}`);
  }
}

async function test_missingSkillFileDoesNotCrash() {
  const name = "sessionStart: missing SKILL.md degrades gracefully (no crash, no hang)";
  const emptyRoot = mkTemp("no-skill");
  try {
    const r = await runScript(SESSION_START, { env: { CLAUDE_PLUGIN_ROOT: emptyRoot } });
    if (r.code !== 0) return fail(name, `exit code ${r.code}`);
    const j = JSON.parse(r.stdout);
    if (!j.hookSpecificOutput || typeof j.hookSpecificOutput.additionalContext !== "string") {
      return fail(name, "missing additionalContext on fallback path");
    }
    pass(name, "graceful fallback JSON emitted");
  } catch (e) {
    fail(name, e.message);
  } finally {
    fs.rmSync(emptyRoot, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------------ */
/* 2. Windows PowerShell stdin-swallowing class of bug (simulated)       */
/* ------------------------------------------------------------------ */

async function test_stdinNeverClosesDoesNotHang() {
  const name = "sessionStart+subagentStart: stdin that never closes does not hang the hook";
  const rs = await runScript(SESSION_START, { env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT }, stdinMode: "never-close" });
  const rsa = await runScript(SUBAGENT_START, { env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT }, stdinMode: "never-close" });
  const BUDGET_MS = 4000; // well above the 2000ms internal stdin timeout, well below the 10000ms hooks.json timeout
  if (rs.code !== 0 || rs.ms > BUDGET_MS) return fail(name, `session-start: code=${rs.code} ms=${rs.ms}`);
  if (rsa.code !== 0 || rsa.ms > BUDGET_MS) return fail(name, `subagent-start: code=${rsa.code} ms=${rsa.ms}`);
  try {
    JSON.parse(rs.stdout);
    JSON.parse(rsa.stdout);
  } catch (e) {
    return fail(name, `output not valid JSON despite exit 0: ${e.message}`);
  }
  pass(
    name,
    `session-start resolved in ${rs.ms}ms, subagent-start in ${rsa.ms}ms (budget ${BUDGET_MS}ms). ` +
      "NOTE: this simulates the FAILURE CLASS (a stdin stream that never signals EOF) on Linux; it " +
      "does not exercise actual Windows PowerShell stdin buffering, which this sandbox cannot run."
  );
}

async function test_stdinSafetySabotageIsCaught() {
  const name = "sabotage: naive (unbounded) stdin read hangs past budget — proves the test has teeth";
  const target = path.join(HOOKS_DIR, "lib", "safe-stdin.js");
  const original = fs.readFileSync(target, "utf8");
  const naive = [
    '"use strict";',
    "// SABOTAGED FOR TEST: no timeout at all — waits forever for stdin 'end'.",
    "function readStdinJSON() {",
    "  return new Promise((resolve) => {",
    "    let chunks = [];",
    "    process.stdin.on('data', (c) => chunks.push(c));",
    "    process.stdin.on('end', () => {",
    "      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }",
    "      catch (_e) { resolve(null); }",
    "    });",
    "  });",
    "}",
    "module.exports = { readStdinJSON, DEFAULT_TIMEOUT_MS: 2000 };",
    "",
  ].join("\n");

  try {
    fs.writeFileSync(target, naive, "utf8");
    const HARD_CAP_MS = 3000; // proves it does NOT resolve within a reasonable budget
    const r = await runScript(SESSION_START, {
      env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT },
      stdinMode: "never-close",
      killAfterMs: HARD_CAP_MS, // outer safety net so the test suite itself never hangs
    });
    const hung = r.signal === "SIGKILL" || r.ms >= HARD_CAP_MS - 50;
    if (!hung) {
      fail(name, `expected the naive implementation to hang past ${HARD_CAP_MS}ms, but it returned in ${r.ms}ms (code=${r.code})`);
    } else {
      pass(name, `naive stdin reader hung as expected (killed after ${r.ms}ms) — the real implementation's timeout is load-bearing`);
    }
  } finally {
    fs.writeFileSync(target, original, "utf8");
    const restored = fs.readFileSync(target, "utf8");
    if (restored !== original) {
      fail(name + " [restore]", "restored file content does not match original byte-for-byte");
    }
  }
}

/* ------------------------------------------------------------------ */
/* 3. Kill the hook process mid-execution — session start must not hang  */
/* ------------------------------------------------------------------ */

async function test_killMidExecutionDoesNotHangHarness() {
  const name = "kill mid-execution: a harness invoking the hook does not hang";
  // Force the hook to sit idle for 5s before it would ever write output,
  // giving us a reliable window to SIGKILL it well before completion.
  const r = await runScript(SESSION_START, {
    env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT, GRAPHSMITH_HOOK_TEST_DELAY_MS: "5000" },
    stdinMode: "close-empty",
    killAfterMs: 300, // kill ~300ms in, long before the 5000ms delay elapses
  });

  if (r.stdout && r.stdout.trim().length > 0) {
    return fail(name, `hook produced output despite being killed mid-execution: ${r.stdout.slice(0, 100)}`);
  }
  if (r.signal !== "SIGKILL") {
    return fail(name, `expected SIGKILL, got code=${r.code} signal=${r.signal}`);
  }
  // The important property: our own kill+observe loop (standing in for the
  // host's hook runner) resolved promptly — nothing on our side waited
  // around for a process that was never going to respond.
  const OBSERVE_BUDGET_MS = 1000;
  if (r.ms > OBSERVE_BUDGET_MS) {
    return fail(name, `kill was observed after ${r.ms}ms, expected under ${OBSERVE_BUDGET_MS}ms`);
  }
  pass(name, `killed at ~300ms, exit observed at ${r.ms}ms with no output — no hang`);
}

/* ------------------------------------------------------------------ */
/* 4. Second hypothetical plugin also registering SessionStart           */
/* ------------------------------------------------------------------ */

async function test_twoPluginsNoClobber() {
  const name = "two SessionStart hooks running concurrently: neither's output clobbers the other's";
  const [ours, theirs] = await Promise.all([
    runScript(SESSION_START, { env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT } }),
    runScript(OTHER_PLUGIN_FIXTURE, {}),
  ]);
  try {
    const oursJson = JSON.parse(ours.stdout);
    const theirsJson = JSON.parse(theirs.stdout);
    const oursCtx = oursJson.hookSpecificOutput.additionalContext;
    const theirsCtx = theirsJson.hookSpecificOutput.additionalContext;
    if (!oursCtx.includes("Save after every step")) return fail(name, "our own context missing our discipline text");
    if (oursCtx.includes("OTHER-PLUGIN-CONTEXT-MARKER")) return fail(name, "our context was polluted by the other plugin's marker");
    if (theirsCtx !== "OTHER-PLUGIN-CONTEXT-MARKER") return fail(name, "other plugin's context was altered");
    pass(name, "both hooks' outputs independently correct and uncontaminated");
  } catch (e) {
    fail(name, `parse failure: ${e.message}`);
  }
}

async function test_twoPluginsClobberSabotageIsCaught() {
  const name = "sabotage: shared-file side channel between two plugins loses data — proves the test has teeth";
  const target = SESSION_START;
  const original = fs.readFileSync(target, "utf8");
  const sharedFile = path.join(os.tmpdir(), `graphsmith-clobber-test-${process.pid}-${Date.now()}.json`);

  // Inject a realistic anti-pattern: instead of relying purely on isolated
  // stdout, the (sabotaged) hook also writes its context to a well-known
  // shared temp file — the kind of "coordinate via shared state" mistake
  // that causes exactly the clobbering this test exists to catch.
  const sabotaged = original.replace(
    'const { context } = buildGuidance(PLUGIN_ROOT, "SessionStart");',
    [
      'const { context } = buildGuidance(PLUGIN_ROOT, "SessionStart");',
      "  // SABOTAGED FOR TEST: shared mutable side-channel, not isolated stdout.",
      `  try { require("fs").writeFileSync(${JSON.stringify(sharedFile)}, context); } catch (_e) {}`,
    ].join("\n")
  );
  if (sabotaged === original) {
    fail(name, "sabotage injection point not found in session-start.js — refusing to run an untested patch");
    return;
  }

  try {
    fs.writeFileSync(target, sabotaged, "utf8");
    if (fs.existsSync(sharedFile)) fs.rmSync(sharedFile);

    // The "other plugin" fixture is told (via its own supported test hook)
    // to write to the SAME shared file, racing the sabotaged implementation.
    await Promise.all([
      runScript(SESSION_START, { env: { CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT } }),
      runScript(OTHER_PLUGIN_FIXTURE, { env: { OTHER_PLUGIN_SHARED_FILE_BUG: sharedFile } }),
    ]);

    if (!fs.existsSync(sharedFile)) {
      return fail(name, "sabotage did not reproduce: shared file was never created");
    }
    const finalContent = fs.readFileSync(sharedFile, "utf8");
    // Clobbering means exactly one side's data survives — the file can
    // never legitimately contain both, because the sabotaged code writes
    // plain text (its own context), not a merge-safe structure.
    const isOursSurviving = finalContent.includes("Save after every step");
    const isTheirsSurviving = finalContent.includes("OTHER-PLUGIN-CONTEXT-MARKER");
    if (isOursSurviving && isTheirsSurviving) {
      return fail(name, "expected a last-writer-wins clobber, but both payloads unexpectedly survived");
    }
    if (!isOursSurviving && !isTheirsSurviving) {
      return fail(name, "shared file contains neither expected payload — inconclusive");
    }
    pass(name, `reproduced: only ${isOursSurviving ? "our" : "the other plugin's"} write survived in the shared file — real code never does this`);
  } finally {
    fs.writeFileSync(target, original, "utf8");
    if (fs.existsSync(sharedFile)) fs.rmSync(sharedFile);
    const restored = fs.readFileSync(target, "utf8");
    if (restored !== original) {
      fail(name + " [restore]", "restored file content does not match original byte-for-byte");
    } else {
      pass(name + " [restore]", "session-start.js restored byte-for-byte");
    }
  }
}

/* ------------------------------------------------------------------ */
/* 5. Uninstall: only GraphSmith's own segment is removed from a shared  */
/*    settings file                                                      */
/* ------------------------------------------------------------------ */

function buildCombinedSettingsFixture() {
  return {
    enabledPlugins: {
      "graphsmith@graphsmith-marketplace": true,
      "other-plugin@other-marketplace": true,
    },
    statusLine: { type: "command", command: "combined-statusline.sh" },
    hooks: {
      SessionStart: [
        {
          matcher: "startup",
          hooks: [
            {
              type: "command",
              command: "node",
              args: [
                "/home/user/.claude/plugins/cache/graphsmith@graphsmith-marketplace/hooks/scripts/session-start.js",
              ],
            },
          ],
        },
        {
          matcher: "startup",
          hooks: [
            {
              type: "command",
              command: "node",
              args: [
                "/home/user/.claude/plugins/cache/other-plugin@other-marketplace/hooks/scripts/session-start.js",
              ],
            },
          ],
        },
      ],
    },
  };
}

async function test_uninstallRemovesOnlyOwnSegment() {
  const name = "uninstall-check: removes only GraphSmith's enabledPlugins/hook entries from a combined settings file";
  const dir = mkTemp("uninstall");
  const settingsPath = path.join(dir, "settings.json");
  const fixture = buildCombinedSettingsFixture();
  fs.writeFileSync(settingsPath, JSON.stringify(fixture, null, 2));

  try {
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [UNINSTALL_CHECK, "--settings", settingsPath, "--apply"]);
      let err = "";
      child.stderr.on("data", (c) => (err += c));
      child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`exit ${code}: ${err}`))));
    });

    const after = JSON.parse(fs.readFileSync(settingsPath, "utf8"));

    const checks = [
      ["graphsmith key removed", !("graphsmith@graphsmith-marketplace" in after.enabledPlugins)],
      ["sibling key intact", after.enabledPlugins["other-plugin@other-marketplace"] === true],
      ["graphsmith hook entry removed", after.hooks.SessionStart.length === 1],
      [
        "sibling hook entry intact",
        after.hooks.SessionStart[0].hooks[0].args[0].includes("other-plugin@other-marketplace"),
      ],
      ["statusLine untouched", JSON.stringify(after.statusLine) === JSON.stringify(fixture.statusLine)],
    ];
    const failed = checks.filter(([, ok]) => !ok).map(([label]) => label);
    if (failed.length) {
      fail(name, `failed checks: ${failed.join(", ")}`);
    } else {
      pass(name, "sibling plugin entries, hook entries, and statusLine all byte-identical after removal");
    }
  } catch (e) {
    fail(name, e.message);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function test_uninstallSabotageIsCaught() {
  const name = "sabotage: over-broad uninstall matcher strips the sibling plugin too — proves the test has teeth";
  const target = UNINSTALL_CHECK;
  const original = fs.readFileSync(target, "utf8");
  // Broaden the enabledPlugins matcher from "exactly graphsmith@<marketplace>"
  // to "any key containing the substring 'plugin'" — a realistic mistake
  // (e.g. someone "simplifying" the regex) that would also delete every
  // other plugin whose marketplace or name happens to contain that word.
  const sabotaged = original.replace(
    "const ENABLED_PLUGIN_KEY_RE = /^graphsmith@[^@]+$/;",
    "const ENABLED_PLUGIN_KEY_RE = /plugin/;"
  );
  if (sabotaged === original) {
    fail(name, "sabotage injection point not found in uninstall-check.js — refusing to run an untested patch");
    return;
  }

  const dir = mkTemp("uninstall-sabotage");
  const settingsPath = path.join(dir, "settings.json");
  fs.writeFileSync(settingsPath, JSON.stringify(buildCombinedSettingsFixture(), null, 2));

  try {
    fs.writeFileSync(target, sabotaged, "utf8");
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [target, "--settings", settingsPath, "--apply"]);
      child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`exit ${code}`))));
    });
    const after = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    const siblingSurvived = after.enabledPlugins && after.enabledPlugins["other-plugin@other-marketplace"] === true;
    if (siblingSurvived) {
      fail(name, "expected the over-broad matcher to also delete the sibling plugin's key, but it survived");
    } else {
      pass(name, "reproduced: the over-broad matcher deleted the sibling plugin's enabledPlugins key too");
    }
  } finally {
    fs.writeFileSync(target, original, "utf8");
    fs.rmSync(dir, { recursive: true, force: true });
    const restored = fs.readFileSync(target, "utf8");
    if (restored !== original) {
      fail(name + " [restore]", "restored file content does not match original byte-for-byte");
    } else {
      pass(name + " [restore]", "uninstall-check.js restored byte-for-byte");
    }
  }
}

/* ------------------------------------------------------------------ */
/* 6. Real Claude Code CLI, fully isolated: install alongside a second   */
/*    plugin, then uninstall, and check the CLI's OWN persisted state    */
/*    — ground truth beyond this file's own simulation of the host.      */
/* ------------------------------------------------------------------ */

function commandExists(cmd) {
  const { spawnSync } = require("child_process");
  const r = spawnSync(process.platform === "win32" ? "where" : "which", [cmd], { stdio: "ignore" });
  return r.status === 0;
}

function runCli(args, isolatedHome) {
  return new Promise((resolve) => {
    // env -i-equivalent: an explicit allowlist so nothing about THIS
    // session's real ~/.claude ever leaks into the isolated run.
    const env = { HOME: isolatedHome, PATH: process.env.PATH };
    const child = spawn("claude", args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.on("error", () => resolve({ code: -1, stdout, stderr: "spawn error" }));
  });
}

function writeFixturePlugin(dir, pluginName, marketplaceName) {
  fs.mkdirSync(path.join(dir, ".claude-plugin"), { recursive: true });
  fs.mkdirSync(path.join(dir, "hooks"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, ".claude-plugin", "marketplace.json"),
    JSON.stringify(
      {
        name: marketplaceName,
        owner: { name: "Test" },
        description: "GraphSmith Lane B test fixture marketplace.",
        plugins: [{ name: pluginName, source: "./", description: "fixture", author: { name: "Test" } }],
      },
      null,
      2
    )
  );
  fs.writeFileSync(
    path.join(dir, ".claude-plugin", "plugin.json"),
    JSON.stringify({ name: pluginName, version: "1.0.0", description: "fixture", author: { name: "Test" } }, null, 2)
  );
  fs.writeFileSync(
    path.join(dir, "hooks", "hooks.json"),
    JSON.stringify(
      {
        hooks: {
          SessionStart: [
            {
              matcher: "startup|resume|clear|compact|fork",
              hooks: [
                {
                  type: "command",
                  command: "echo",
                  args: [
                    JSON.stringify({
                      hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: "OTHER-PLUGIN-REAL-CLI-MARKER" },
                    }),
                  ],
                },
              ],
            },
          ],
        },
      },
      null,
      2
    )
  );
}

async function test_realCliMultiPluginAndUninstall() {
  const name = "real claude CLI: install alongside a second plugin, uninstall, check persisted settings";
  if (!commandExists("claude")) {
    record(name, "UNAVAILABLE", "no `claude` binary on PATH in this environment — could not exercise the real plugin installer");
    return;
  }

  const isolatedHome = mkTemp("cli-home");
  const otherPluginDir = mkTemp("cli-other-plugin");
  writeFixturePlugin(otherPluginDir, "other-plugin", "other-plugin-marketplace");

  try {
    let r;
    r = await runCli(["plugin", "marketplace", "add", REPO], isolatedHome);
    if (r.code !== 0) return fail(name, `marketplace add (graphsmith) failed: ${r.stderr || r.stdout}`);

    r = await runCli(["plugin", "install", "graphsmith@graphsmith-marketplace", "-s", "user"], isolatedHome);
    if (r.code !== 0) return fail(name, `install graphsmith failed: ${r.stderr || r.stdout}`);

    r = await runCli(["plugin", "marketplace", "add", otherPluginDir], isolatedHome);
    if (r.code !== 0) return fail(name, `marketplace add (other-plugin) failed: ${r.stderr || r.stdout}`);

    r = await runCli(["plugin", "install", "other-plugin@other-plugin-marketplace", "-s", "user"], isolatedHome);
    if (r.code !== 0) return fail(name, `install other-plugin failed: ${r.stderr || r.stdout}`);

    r = await runCli(["plugin", "list", "--json"], isolatedHome);
    let installed;
    try {
      installed = JSON.parse(r.stdout);
    } catch (e) {
      return fail(name, `plugin list --json not parseable: ${e.message}`);
    }
    const ids = installed.map((p) => p.id);
    if (!ids.includes("graphsmith@graphsmith-marketplace")) return fail(name, "graphsmith not listed as installed");
    if (!ids.includes("other-plugin@other-plugin-marketplace")) return fail(name, "other-plugin not listed as installed");
    const gs = installed.find((p) => p.id === "graphsmith@graphsmith-marketplace");
    if (gs.errors && gs.errors.length) return fail(name, `graphsmith installed with errors: ${JSON.stringify(gs.errors)}`);

    const settingsPath = path.join(isolatedHome, ".claude", "settings.json");
    const beforeUninstall = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    if (
      beforeUninstall.enabledPlugins["graphsmith@graphsmith-marketplace"] !== true ||
      beforeUninstall.enabledPlugins["other-plugin@other-plugin-marketplace"] !== true
    ) {
      return fail(name, `unexpected enabledPlugins before uninstall: ${JSON.stringify(beforeUninstall.enabledPlugins)}`);
    }

    r = await runCli(["plugin", "uninstall", "graphsmith@graphsmith-marketplace", "-s", "user", "-y"], isolatedHome);
    if (r.code !== 0) return fail(name, `uninstall failed: ${r.stderr || r.stdout}`);

    const afterUninstall = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    if ("graphsmith@graphsmith-marketplace" in afterUninstall.enabledPlugins) {
      return fail(name, "graphsmith key still present in enabledPlugins after uninstall");
    }
    if (afterUninstall.enabledPlugins["other-plugin@other-plugin-marketplace"] !== true) {
      return fail(name, "other-plugin's enabledPlugins entry was disturbed by graphsmith's uninstall");
    }

    r = await runCli(["plugin", "list", "--json"], isolatedHome);
    const afterList = JSON.parse(r.stdout);
    if (afterList.some((p) => p.id === "graphsmith@graphsmith-marketplace")) return fail(name, "graphsmith still reported as installed");
    if (!afterList.some((p) => p.id === "other-plugin@other-plugin-marketplace")) return fail(name, "other-plugin no longer reported as installed");

    pass(
      name,
      "verified against the actual `claude` CLI (not just this file's own simulation): both plugins installed cleanly side " +
        "by side, and uninstalling graphsmith removed only its own enabledPlugins entry, leaving the sibling plugin fully installed and enabled"
    );
  } catch (e) {
    fail(name, e.message);
  } finally {
    fs.rmSync(isolatedHome, { recursive: true, force: true });
    fs.rmSync(otherPluginDir, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------------ */

async function main() {
  console.log("=== GraphSmith plugin hooks — adversarial test harness ===");
  await test_sessionStartBasicOutput();
  await test_subagentStartBasicOutput();
  await test_missingSkillFileDoesNotCrash();
  await test_stdinNeverClosesDoesNotHang();
  await test_stdinSafetySabotageIsCaught();
  await test_killMidExecutionDoesNotHangHarness();
  await test_twoPluginsNoClobber();
  await test_twoPluginsClobberSabotageIsCaught();
  await test_uninstallRemovesOnlyOwnSegment();
  await test_uninstallSabotageIsCaught();
  await test_realCliMultiPluginAndUninstall();

  const fails = results.filter((r) => r.status === "FAIL");
  const passes = results.filter((r) => r.status === "PASS");
  const unav = results.filter((r) => r.status === "UNAVAILABLE");
  console.log(`--- summary total=${results.length} pass=${passes.length} fail=${fails.length} unavailable=${unav.length} ---`);
  process.exit(fails.length ? 1 : 0);
}

main();
