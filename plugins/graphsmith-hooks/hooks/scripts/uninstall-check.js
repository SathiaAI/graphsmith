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
 * makes no changes. With --apply, writes the pruned settings back to the
 * same path (after taking a `.bak` snapshot alongside it).
 */

const fs = require("fs");

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
  fs.writeFileSync(settingsPath, JSON.stringify(pruned, null, 2) + "\n", "utf8");
  console.log(`\nApplied. Previous contents saved to ${settingsPath}.bak`);
}

module.exports = { removeGraphsmithSegment, isOurEnabledPluginKey, hookEntryReferencesUs };

if (require.main === module) {
  main();
}
