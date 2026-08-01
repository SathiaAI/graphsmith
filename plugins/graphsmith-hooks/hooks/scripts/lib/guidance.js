#!/usr/bin/env node
"use strict";
/* GraphSmith plugin — hooks/scripts/lib/guidance.js
 *
 * Builds the guidance text injected into context by the SessionStart and
 * SubagentStart hooks. Reads ${CLAUDE_PLUGIN_ROOT}/SKILL.md — a real
 * committed copy of the repo root's canonical SKILL.md, deliberately NOT a
 * symlink (a `120000` symlink blob checks out as a literal path-string file
 * on Git for Windows without symlink support). The drift check in
 * tests/plugin-hooks/run-tests.js fails loudly if this copy and the root
 * file ever diverge.
 *
 * Deterministic, zero-dependency CommonJS, Node >= 18. No network calls,
 * no clocks, no randomness — matching this repo's house conventions (see
 * scripts/verify.js, scripts/gate.js at the repo root).
 *
 * additionalContext is capped by the host at roughly 10,000 characters;
 * this module extracts only the frontmatter description and the "never
 * negotiable" discipline block rather than the whole file, and applies its
 * own smaller safety-margin cap on top, so a growing SKILL.md degrades to a
 * clean, explicit truncation notice instead of an oversized or rejected
 * payload.
 */

const fs = require("fs");
const path = require("path");

const MAX_CONTEXT_CHARS = 9000;

function readSkillFile(pluginRoot) {
  const skillPath = path.join(pluginRoot, "SKILL.md");
  try {
    return fs.readFileSync(skillPath, "utf8");
  } catch (_err) {
    return null;
  }
}

function extractFrontmatterDescription(text) {
  const fmMatch = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!fmMatch) return null;
  const descMatch = fmMatch[1].match(/^description:\s*(.+)$/m);
  return descMatch ? descMatch[1].trim() : null;
}

function extractDisciplineBlock(text) {
  // Matches from the "**The discipline ...**" heading line through the
  // numbered list that follows, stopping at the next blank-line boundary.
  const m = text.match(/\*\*The discipline[^\n]*\*\*\n(?:\d+\.[^\n]*\n?)+/);
  return m ? m[0].trim() : null;
}

/**
 * @param {string} pluginRoot   absolute path to the plugin root
 *                              (${CLAUDE_PLUGIN_ROOT} — this repo's root)
 * @param {string} eventLabel   human label, e.g. "SessionStart" or
 *                              "SubagentStart"
 * @returns {{ok: boolean, context: string, truncated: boolean}}
 */
function buildGuidance(pluginRoot, eventLabel) {
  const text = readSkillFile(pluginRoot);
  if (!text) {
    return {
      ok: false,
      truncated: false,
      context:
        "GraphSmith plugin: SKILL.md not found at the plugin root; " +
        "guidance unavailable for " + eventLabel + ". This does not block " +
        "the session — the discipline will not be pre-loaded into context.",
    };
  }

  const description = extractFrontmatterDescription(text);
  const discipline = extractDisciplineBlock(text);

  const parts = [];
  parts.push("# GraphSmith discipline (" + eventLabel + ")");
  if (description) parts.push(description);
  parts.push(
    discipline ||
      "(discipline block not found in SKILL.md — see the file directly for the current rules.)"
  );
  parts.push(
    "Full skill definition: SKILL.md at the project root (also auto-discovered as the `graphsmith` skill)."
  );

  let context = parts.join("\n\n");
  let truncated = false;
  if (context.length > MAX_CONTEXT_CHARS) {
    context = context.slice(0, MAX_CONTEXT_CHARS) + "\n\n[...truncated — see SKILL.md for the full guidance]";
    truncated = true;
  }

  return { ok: true, context, truncated };
}

module.exports = { buildGuidance, MAX_CONTEXT_CHARS };
