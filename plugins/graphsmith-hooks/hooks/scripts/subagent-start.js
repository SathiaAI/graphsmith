#!/usr/bin/env node
"use strict";
/* GraphSmith plugin — SubagentStart hook (hooks/scripts/subagent-start.js)
 *
 * Injects the GraphSmith multi-agent discipline into context the moment a
 * Task-spawned subagent starts, so it never operates for even one turn
 * without the discipline the parent session already has. A comparable
 * project (ponytail) shipped subagent awareness as a late fix for its own
 * issue #252 — this plugin registers SubagentStart from day one instead of
 * treating SessionStart alone as sufficient.
 *
 * Zero-dependency CommonJS, Node >= 18, matching this repo's house
 * conventions (see scripts/verify.js, scripts/gate.js). Writes nothing to
 * disk and touches nothing in the target repo.
 *
 * Same stdin defensiveness as session-start.js (see that file's header and
 * lib/safe-stdin.js) — this hook doesn't need agent_id/agent_type/
 * agent_trigger from the payload to build its output, so the payload is
 * read with a bounded, non-blocking reader and discarded.
 *
 * GRAPHSMITH_HOOK_TEST_DELAY_MS: test-only, see session-start.js.
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
  await readStdinJSON();
  await testDelay();

  const { context } = buildGuidance(PLUGIN_ROOT, "SubagentStart");

  // See session-start.js for why we wait on the write callback instead of
  // calling process.exit() immediately after process.stdout.write().
  await new Promise((resolve) => {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "SubagentStart",
          additionalContext: context,
        },
      }),
      () => resolve()
    );
  });
  process.exitCode = 0;
}

main().catch(() => {
  process.exitCode = 0;
});
