#!/usr/bin/env node
"use strict";
/* Test fixture only — NOT part of the GraphSmith plugin.
 *
 * Stands in for a second, hypothetical plugin that also registers a
 * SessionStart command hook, so the test suite can verify GraphSmith's own
 * hook output is unaffected by another plugin's hook running concurrently
 * (per Claude Code's documented behavior: hooks for the same event run in
 * parallel and their outputs are collected independently, not merged into
 * one clobberable string).
 *
 * OTHER_PLUGIN_SHARED_FILE_BUG: test-only escape hatch. When set, this
 * fixture (mis)behaves like a hook that shares a single on-disk file with
 * another plugin instead of relying on its own isolated stdout — the
 * anti-pattern the test suite deliberately exercises to prove it can
 * detect real clobbering, not just assert its absence.
 */

const fs = require("fs");

const MARKER = "OTHER-PLUGIN-CONTEXT-MARKER";

function testDelay() {
  const ms = parseInt(process.env.GRAPHSMITH_HOOK_TEST_DELAY_MS || "0", 10);
  if (!ms) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  await testDelay();

  const payload = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: MARKER,
    },
  };

  const sharedFile = process.env.OTHER_PLUGIN_SHARED_FILE_BUG;
  if (sharedFile) {
    // Deliberately anti-pattern: last writer to the shared file wins,
    // simulating what clobbering would look like if hook output weren't
    // isolated per process/stdout.
    fs.writeFileSync(sharedFile, JSON.stringify(payload));
  }

  await new Promise((resolve) => process.stdout.write(JSON.stringify(payload), resolve));
  process.exitCode = 0;
}

main().catch(() => {
  process.exitCode = 0;
});
