"use strict";

const fs = require("fs");
const path = require("path");

/* Resolved relative to THIS FILE's own location inside the installed
 * package (src/skill.js -> ../SKILL.md), never via a relative path that
 * assumes a sibling monorepo checkout. SKILL.md is listed in package.json's
 * "files" allowlist, so it always ships inside the published package
 * directory itself -- this is precisely the createRequire-reach-outside
 * failure mode (ponytail's ponytail-mcp/) that the frozen Lane C design
 * calls out and requires this package to avoid. */
const SKILL_PATH = path.join(__dirname, "..", "SKILL.md");

let cached = null;

/* Cached on first read (deliberately, not per-process-lifetime-mutable) --
 * a long-lived server process should not need to re-stat disk on every
 * tool call for content that only changes when the package itself is
 * reinstalled/upgraded. Exposed as a function (not a top-level constant)
 * so tests can exercise the real file-read path, including failure modes. */
function loadSkillMarkdown() {
  if (cached === null) {
    cached = fs.readFileSync(SKILL_PATH, "utf8");
  }
  return cached;
}

/* Test-only escape hatch: forces the next loadSkillMarkdown() call to
 * re-read from disk. Not used by production code paths. */
function _resetCacheForTests() {
  cached = null;
}

module.exports = { loadSkillMarkdown, SKILL_PATH, _resetCacheForTests };
