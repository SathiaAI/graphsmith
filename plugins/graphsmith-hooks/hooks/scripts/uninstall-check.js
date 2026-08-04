#!/usr/bin/env node
"use strict";
/* GraphSmith plugin — hooks/scripts/uninstall-check.js
 *
 * Defensive uninstall helper. `claude plugin uninstall graphsmith@<marketplace>`
 * already cleanly removes this plugin's `enabledPlugins` entry and its
 * plugin-cache directory — each installed plugin's cache directory and
 * settings entry are independently addressable by Claude Code itself, so
 * the standard uninstall path does not touch a sibling plugin's entries.
 *
 * This script exists as a belt-and-suspenders cleanup for the case that
 * concerns the adversarial-review checklist for this plugin: a Claude Code
 * settings.json (or any file shaped like one) into which GraphSmith's
 * `enabledPlugins` entry and/or hook command entries ended up merged
 * alongside another plugin's — for example because a user or a scope-
 * flattening tool hand-merged hook config into one shared file rather than
 * installing GraphSmith purely through the marketplace. It must remove
 * ONLY GraphSmith's own segment and leave every other key — including a
 * sibling plugin's `enabledPlugins` entry, that plugin's hook entries, and
 * unrelated config such as `statusLine` — byte-for-byte untouched.
 *
 * Zero-dependency CommonJS, Node >= 18, matching this repo's house
 * conventions (see scripts/verify.js, scripts/gate.js). No network calls,
 * no clocks, no randomness in the removal decision.
 *
 * Usage:
 *   node hooks/scripts/uninstall-check.js --settings <path> [--apply]
 *
 * Without --apply, prints a dry-run summary of what would be removed and
 * makes no changes. With --apply, takes a `.bak` snapshot of the original
 * content alongside the target path, then writes the pruned settings back
 * to the same path via the same write-temp-then-rename atomic pattern this
 * repo already uses for its higher-frequency writes (see
 * atomicWriteFileSync() in scripts/reconcile.js at the repo root): the
 * complete new content is written to a scratch temp file in the same
 * directory, fsynced, then installed with a single fs.renameSync(). A
 * same-filesystem rename is one atomic directory-entry update at the OS
 * level, so a crash or kill at any point up to and including mid-write of
 * the temp file leaves the real settings.json completely untouched; only
 * a crash strictly AFTER the rename call itself has already been issued
 * can be a concern, and by then the new content is already durably
 * installed, not partial. This closes a gap an independent, non-Anthropic
 * adversarial review found in the previous two-step
 * ".bak-write-then-direct-overwrite" version (see claude/graphsmith-
 * v0.5.0-wave1-status-and-adversarial-findings-2026-08-01.md, "LANE B
 * ADVERSARIAL REVIEW", 2026-08-04): two independent fs.writeFileSync()
 * calls are not one atomic unit, so a crash between them (or mid-write of
 * the second one) could leave settings.json truncated or corrupted, with
 * only a manual `.bak` restore as recovery.
 *
 * GRAPHSMITH_UNINSTALL_TEST_CRASH_BEFORE_RENAME: test-only. If set, throws
 * immediately after the temp file is fully written and fsynced but before
 * the rename that installs it — used by the test suite to prove the real
 * settings.json is left byte-for-byte untouched by an interruption at
 * exactly that point. Never set in production use.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/**
 * Write `content` to `targetPath` atomically: write to a scratch temp file
 * in the same directory, fsync, then a single fs.renameSync() onto the
 * real target. Mirrors atomicWriteFileSync() in scripts/reconcile.js at
 * the repo root (same rationale, same pattern) — this file doesn't need
 * that module's locking/CAS machinery (uninstall is a rare, manual,
 * single-shot operation, not a concurrent hot path), only the atomicity
 * half of it.
 *
 * @param {string} targetPath
 * @param {string} content
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  const tmpPath = path.join(
    dir,
    `.graphsmith-uninstall.${path.basename(targetPath)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  const buf = Buffer.from(content, "utf8");
  const fd = fs.openSync(tmpPath, "wx", 0o644);
  try {
    let off = 0;
    while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (process.env.GRAPHSMITH_UNINSTALL_TEST_CRASH_BEFORE_RENAME) {
      throw new Error("GRAPHSMITH_UNINSTALL_TEST_CRASH_BEFORE_RENAME: simulated crash before rename (test-only)");
    }
    fs.renameSync(tmpPath, targetPath);
  } catch (e) {
    try {
      fs.unlinkSync(tmpPath);
    } catch (_) {
      /* best-effort cleanup; the original error is the one that matters */
    }
    throw e;
  }
}

// Matches ONLY GraphSmith's own enabledPlugins key: "graphsmith@<marketplace>"
// or the skills-directory form "graphsmith@skills-dir". Deliberately anchored
// (^...$) so it can never match a differently-named plugin such as
// "graphsmith-extra@marketplace" or "not-graphsmith@marketplace".
const ENABLED_PLUGIN_KEY_RE = /^graphsmith@[^@]+$/;

// Matches a hook command/args entry that points at one of THIS plugin's own
// hook scripts, inside a path segment that identifies it as the graphsmith
// plugin's own installed copy (plugin-cache or skills-dir layout both put
// the plugin identity directory directly above `hooks/scripts/`).
const HOOK_SCRIPT_PATH_RE =
  /(^|[/\\])graphsmith@[^/\\]+[/\\]hooks[/\\]scripts[/\\](session-start|subagent-start|uninstall-check)\.js$/;

function isOurEnabledPluginKey(key) {
  return ENABLED_PLUGIN_KEY_RE.test(key);
}

function stringReferencesOurHookScript(value) {
  return typeof value === "string" && HOOK_SCRIPT_PATH_RE.test(value);
}

function hookEntryReferencesUs(hookGroupEntry) {
  if (!hookGroupEntry || !Array.isArray(hookGroupEntry.hooks)) return false;
  return hookGroupEntry.hooks.some((h) => {
    if (!h || typeof h !== "object") return false;
    if (stringReferencesOurHookScript(h.command)) return true;
    if (Array.isArray(h.args) && h.args.some(stringReferencesOurHookScript)) return true;
    return false;
  });
}

/**
 * Pure function: takes a settings-shaped object, returns a NEW object with
 * only GraphSmith's own segment removed, plus a summary of what changed.
 * Never mutates the input.
 *
 * @param {object} settings
 * @returns {{settings: object, removed: {enabledPluginKeys: string[], hookEventNames: Record<string, number>}}}
 */
function removeGraphsmithSegment(settings) {
  const input = settings && typeof settings === "object" ? settings : {};
  const output = JSON.parse(JSON.stringify(input));
  const removed = { enabledPluginKeys: [], hookEventNames: {} };

  if (output.enabledPlugins && typeof output.enabledPlugins === "object") {
    for (const key of Object.keys(output.enabledPlugins)) {
      if (isOurEnabledPluginKey(key)) {
        delete output.enabledPlugins[key];
        removed.enabledPluginKeys.push(key);
      }
    }
  }

  if (output.hooks && typeof output.hooks === "object") {
    for (const eventName of Object.keys(output.hooks)) {
      const group = output.hooks[eventName];
      if (!Array.isArray(group)) continue;
      const before = group.length;
      output.hooks[eventName] = group.filter((entry) => !hookEntryReferencesUs(entry));
      const removedCount = before - output.hooks[eventName].length;
      if (removedCount > 0) removed.hookEventNames[eventName] = removedCount;
      if (output.hooks[eventName].length === 0) delete output.hooks[eventName];
    }
  }

  return { settings: output, removed };
}

function parseArgs(argv) {
  const out = { settingsPath: null, apply: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--settings") out.settingsPath = argv[++i];
    else if (argv[i] === "--apply") out.apply = true;
  }
  return out;
}

function main() {
  const { settingsPath, apply } = parseArgs(process.argv.slice(2));
  if (!settingsPath) {
    console.error("Usage: node uninstall-check.js --settings <path> [--apply]");
    process.exitCode = 2;
    return;
  }

  const raw = fs.readFileSync(settingsPath, "utf8");
  const parsed = JSON.parse(raw);
  const { settings: pruned, removed } = removeGraphsmithSegment(parsed);

  const nothingToDo =
    removed.enabledPluginKeys.length === 0 && Object.keys(removed.hookEventNames).length === 0;

  if (nothingToDo) {
    console.log("No GraphSmith segment found — nothing to remove.");
    return;
  }

  console.log("GraphSmith segment found:");
  for (const k of removed.enabledPluginKeys) console.log(`  enabledPlugins["${k}"]`);
  for (const [event, count] of Object.entries(removed.hookEventNames)) {
    console.log(`  hooks.${event}: ${count} entr${count === 1 ? "y" : "ies"} referencing graphsmith`);
  }

  if (!apply) {
    console.log("\nDry run only — pass --apply to write changes.");
    return;
  }

  fs.writeFileSync(settingsPath + ".bak", raw, "utf8");
  atomicWriteFileSync(settingsPath, JSON.stringify(pruned, null, 2) + "\n");
  console.log(`\nApplied. Previous contents saved to ${settingsPath}.bak`);
}

module.exports = { removeGraphsmithSegment, isOurEnabledPluginKey, hookEntryReferencesUs, atomicWriteFileSync };

if (require.main === module) {
  main();
}
