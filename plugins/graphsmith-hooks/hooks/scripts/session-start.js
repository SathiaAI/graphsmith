#!/usr/bin/env node
"use strict";
/* GraphSmith plugin — SessionStart hook (hooks/scripts/session-start.js)
 *
 * Injects the GraphSmith multi-agent discipline into context at the start
 * of every session. Zero-dependency CommonJS, Node >= 18, matching this
 * repo's house conventions (see scripts/verify.js, scripts/gate.js).
 *
 * Writes nothing to disk and touches nothing in the target repo — all it
 * does is read this plugin's own bundled SKILL.md
 * (${CLAUDE_PLUGIN_ROOT}/SKILL.md, which for this plugin IS the repo root's
 * canonical SKILL.md) and print a JSON hook response to stdout.
 *
 * Never blocks on stdin: this hook doesn't need the SessionStart JSON
 * payload (session_id/cwd/source) to build its output, so the payload is
 * read defensively (bounded, non-blocking — see lib/safe-stdin.js) and
 * simply discarded. That defensiveness is what protects against the
 * Windows PowerShell stdin-swallowing class of bug: a hook that only reads
 * stdin because "the contract says a payload arrives on stdin" must never
 * let a stdin stream that never closes hang the session.
 *
 * GRAPHSMITH_HOOK_TEST_DELAY_MS: test-only. If set to a positive integer,
 * sleeps that many milliseconds before emitting output, purely so the test
 * suite has a reliable window to send SIGKILL mid-execution. Never set in
 * production use.
 */

const path = require("path");
const { readStdinJSON } = require("./lib/safe-stdin.js");
const { buildGuidance } = require("./lib/guidance.js");

const PLUGIN_ROOT = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, "..", "..");

function testDelay() {
  const raw = process.env.GRAPHSMITH_HOOK_TEST_DELAY_MS;
  const ms = raw ? parseInt(raw, 10) : 0;
  if (!ms || ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  // Read (and discard) the payload defensively. We don't currently branch
  // on session_id/cwd/source, but reading it here — hardened — means a
  // future revision that does can't reintroduce a stdin hang risk.
  await readStdinJSON();
  await testDelay();

  const { context } = buildGuidance(PLUGIN_ROOT, "SessionStart");

  // Wait for the write to actually flush before exiting. process.exit()
  // called right after process.stdout.write() can truncate output when
  // stdout is a pipe (writes to pipes are not guaranteed synchronous the
  // way TTY/file writes are) — the same "don't just call exit and hope"
  // class of mistake as the stdin-hang defensiveness above, applied to the
  // write side instead of the read side.
  await new Promise((resolve) => {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "SessionStart",
          additionalContext: context,
        },
      }),
      () => resolve()
    );
  });
  process.exitCode = 0;
}

main().catch(() => {
  // A SessionStart hook failing to inject guidance must never block the
  // session. Exit 0 with no output (non-blocking) rather than exit 2.
  process.exitCode = 0;
});
