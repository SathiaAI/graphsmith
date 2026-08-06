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
 * @param {number} [mode] permission bits to install on the new file (e.g.
 *   the original file's own mode, read via fs.statSync before this call).
 *   Defaults to 0o644 when omitted -- only appropriate when there is no
 *   original file to preserve the permissions of.
 */
function atomicWriteFileSync(targetPath, content, mode) {
  const dir = path.dirname(targetPath);
  const tmpPath = path.join(
    dir,
    `.graphsmith-uninstall.${path.basename(targetPath)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  const buf = Buffer.from(content, "utf8");
  const fd = fs.openSync(tmpPath, "wx", mode !== undefined ? mode : 0o644);
  try {
    let off = 0;
    while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
    fs.fsyncSync(fd);
    // openSync's mode argument is masked by the process umask, so asking
    // for a specific mode (e.g. preserving a locked-down 0600 original)
    // can still land looser than requested. fchmodSync sets the exact bits
    // regardless of umask, closing that gap -- a settings.json with
    // embedded secrets that was 0600 before this run stays 0600 after.
    if (mode !== undefined) fs.fchmodSync(fd, mode);
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

// This script ships as part of exactly one plugin (see plugin.json's own
// "name"). It is never matched against "any plugin named graphsmith" --
// every regex below is additionally scoped to one specific marketplace
// name, resolved by resolveMarketplaceName() below.
const PLUGIN_NAME = "graphsmith";

// Fallback marketplace name (this plugin's own published marketplace, see
// .claude-plugin/marketplace.json) used ONLY when neither an explicit
// --marketplace flag nor ${CLAUDE_PLUGIN_ROOT} (set by Claude Code on a
// real hook invocation) is available to resolve the actual installed
// marketplace. Never widened to "match any marketplace": that would strip
// a same-named GraphSmith install enabled from an unrelated marketplace
// (e.g. an internal fork) -- the exact adversarial scenario this fix
// closes.
const DEFAULT_MARKETPLACE_NAME = "graphsmith-marketplace";

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Resolves which marketplace's GraphSmith install this run should act on.
 * Precedence: explicit --marketplace flag > ${CLAUDE_PLUGIN_ROOT} (a real
 * hook invocation sets this to the plugin's own cache path, shaped
 * `.../cache/<marketplace>/<plugin>/<version>`, per
 * https://code.claude.com/docs/en/plugin-marketplaces) > this plugin's
 * own published default. Never resolves to "unknown" and falls through to
 * matching everything -- that is exactly the over-broad behavior this fix
 * removes.
 *
 * @param {string|null} explicitMarketplace
 * @returns {string}
 */
function resolveMarketplaceName(explicitMarketplace) {
  if (explicitMarketplace) return explicitMarketplace;
  const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT;
  if (pluginRoot) {
    const parts = pluginRoot.split(/[/\\]/).filter(Boolean);
    const cacheIdx = parts.lastIndexOf("cache");
    // cache/<marketplace>/<plugin>/<version> -- CLAUDE_PLUGIN_ROOT is the
    // <version> directory itself, so marketplace is two segments before it.
    if (cacheIdx !== -1 && parts.length >= cacheIdx + 4) {
      return parts[cacheIdx + 1];
    }
  }
  return DEFAULT_MARKETPLACE_NAME;
}

// Matches ONLY GraphSmith's own enabledPlugins key for the resolved
// marketplace: "graphsmith@<that specific marketplace>" (the real
// enabledPlugins key shape, confirmed against
// https://code.claude.com/docs/en/plugin-marketplaces, e.g.
// "code-formatter@company-tools": true). Deliberately anchored (^...$) AND
// scoped to one marketplace name -- not "any graphsmith@*" -- so a
// same-named GraphSmith install enabled from a different marketplace is
// never touched.
function buildEnabledPluginKeyRe(marketplace) {
  return new RegExp(`^${escapeRegExp(PLUGIN_NAME)}@${escapeRegExp(marketplace)}$`);
}

// Matches a hook command/args entry that points at one of THIS plugin's own
// hook scripts, inside the real, documented Claude Code plugin-cache path
// shape: <...>/cache/<marketplace>/<plugin>/<version>/hooks/scripts/<script>.js
// (see https://code.claude.com/docs/en/plugin-marketplaces, "Pre-populate
// plugins for containers": "cache/<marketplace>/<plugin>/<version>/...").
// The version segment is unconstrained ([^/\\]+) since it tracks whatever
// plugin.json currently declares. Scoped to the resolved marketplace name
// for the same reason as buildEnabledPluginKeyRe above.
function buildHookScriptPathRe(marketplace) {
  return new RegExp(
    `(^|[/\\\\])cache[/\\\\]${escapeRegExp(marketplace)}[/\\\\]${escapeRegExp(PLUGIN_NAME)}` +
      `[/\\\\][^/\\\\]+[/\\\\]hooks[/\\\\]scripts[/\\\\](session-start|subagent-start|uninstall-check)\\.js$`
  );
}

function stringReferencesOurHookScript(value, hookScriptPathRe) {
  return typeof value === "string" && hookScriptPathRe.test(value);
}

/**
 * Pure function: takes a settings-shaped object, returns a NEW object with
 * only GraphSmith's own segment (scoped to `marketplace`) removed, plus a
 * summary of what changed. Never mutates the input.
 *
 * Hook removal happens at the INNER hooks[] item level, not by dropping an
 * entire matcher-group entry: a shared entry shaped like
 * `{matcher, hooks: [graphsmithHook, otherPluginHook]}` keeps
 * `otherPluginHook` in place and only the entry as a whole is dropped once
 * every one of its inner hooks belonged to GraphSmith.
 *
 * @param {object} settings
 * @param {string} marketplace the specific marketplace this run should act on
 * @returns {{settings: object, removed: {enabledPluginKeys: string[], hookEventNames: Record<string, number>}}}
 */
function removeGraphsmithSegment(settings, marketplace) {
  const input = settings && typeof settings === "object" ? settings : {};
  const output = JSON.parse(JSON.stringify(input));
  const removed = { enabledPluginKeys: [], hookEventNames: {} };

  const enabledPluginKeyRe = buildEnabledPluginKeyRe(marketplace);
  const hookScriptPathRe = buildHookScriptPathRe(marketplace);

  if (output.enabledPlugins && typeof output.enabledPlugins === "object") {
    for (const key of Object.keys(output.enabledPlugins)) {
      if (enabledPluginKeyRe.test(key)) {
        delete output.enabledPlugins[key];
        removed.enabledPluginKeys.push(key);
      }
    }
  }

  function innerHookIsOurs(h) {
    if (!h || typeof h !== "object") return false;
    if (stringReferencesOurHookScript(h.command, hookScriptPathRe)) return true;
    if (Array.isArray(h.args) && h.args.some((a) => stringReferencesOurHookScript(a, hookScriptPathRe))) return true;
    return false;
  }

  if (output.hooks && typeof output.hooks === "object") {
    for (const eventName of Object.keys(output.hooks)) {
      const group = output.hooks[eventName];
      if (!Array.isArray(group)) continue;
      let removedCount = 0;
      const nextGroup = [];
      for (const entry of group) {
        if (!entry || !Array.isArray(entry.hooks)) {
          nextGroup.push(entry);
          continue;
        }
        const keptInnerHooks = entry.hooks.filter((h) => {
          const isOurs = innerHookIsOurs(h);
          if (isOurs) removedCount++;
          return !isOurs;
        });
        if (keptInnerHooks.length > 0) {
          // Only rebuild the entry (a new object) when something inside it
          // actually changed, so an untouched entry stays byte-identical.
          nextGroup.push(keptInnerHooks.length === entry.hooks.length ? entry : { ...entry, hooks: keptInnerHooks });
        }
        // else: every inner hook in this entry was ours -- drop the whole entry.
      }
      output.hooks[eventName] = nextGroup;
      if (removedCount > 0) removed.hookEventNames[eventName] = removedCount;
      if (output.hooks[eventName].length === 0) delete output.hooks[eventName];
    }
  }

  return { settings: output, removed };
}

function parseArgs(argv) {
  const out = { settingsPath: null, apply: false, marketplace: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--settings") out.settingsPath = argv[++i];
    else if (argv[i] === "--apply") out.apply = true;
    else if (argv[i] === "--marketplace") out.marketplace = argv[++i];
  }
  return out;
}

function main() {
  const { settingsPath, apply, marketplace: explicitMarketplace } = parseArgs(process.argv.slice(2));
  if (!settingsPath) {
    console.error("Usage: node uninstall-check.js --settings <path> [--apply] [--marketplace <name>]");
    process.exitCode = 2;
    return;
  }
  const marketplace = resolveMarketplaceName(explicitMarketplace);

  let raw;
  let parsed;
  let originalMode;
  try {
    raw = fs.readFileSync(settingsPath, "utf8");
    originalMode = fs.statSync(settingsPath).mode & 0o777;
  } catch (err) {
    console.error(`Could not read ${settingsPath}: ${err.code === "ENOENT" ? "file not found" : err.message}`);
    process.exitCode = 2;
    return;
  }
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.error(`${settingsPath} is not valid JSON: ${err.message}`);
    process.exitCode = 2;
    return;
  }
  const { settings: pruned, removed } = removeGraphsmithSegment(parsed, marketplace);

  const nothingToDo =
    removed.enabledPluginKeys.length === 0 && Object.keys(removed.hookEventNames).length === 0;

  if (nothingToDo) {
    console.log(`No GraphSmith segment found for marketplace "${marketplace}" — nothing to remove.`);
    return;
  }

  console.log(`GraphSmith segment found (marketplace "${marketplace}"):`);
  for (const k of removed.enabledPluginKeys) console.log(`  enabledPlugins["${k}"]`);
  for (const [event, count] of Object.entries(removed.hookEventNames)) {
    console.log(`  hooks.${event}: ${count} entr${count === 1 ? "y" : "ies"} referencing graphsmith`);
  }

  if (!apply) {
    console.log("\nDry run only — pass --apply to write changes.");
    return;
  }

  fs.writeFileSync(settingsPath + ".bak", raw, "utf8");
  if (originalMode !== undefined) {
    try {
      fs.chmodSync(settingsPath + ".bak", originalMode);
    } catch (_err) {
      /* best-effort; the .bak is a convenience copy, not the source of truth */
    }
  }
  atomicWriteFileSync(settingsPath, JSON.stringify(pruned, null, 2) + "\n", originalMode);
  console.log(`\nApplied. Previous contents saved to ${settingsPath}.bak`);
}

module.exports = {
  removeGraphsmithSegment,
  buildEnabledPluginKeyRe,
  buildHookScriptPathRe,
  resolveMarketplaceName,
  atomicWriteFileSync,
  DEFAULT_MARKETPLACE_NAME,
};

if (require.main === module) {
  main();
}
