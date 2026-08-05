"use strict";

// mcp-server/SKILL.md is a hand-maintained COPY of the root SKILL.md, not a
// symlink and not generated at build time (see mcp-server/package.json's
// "files" list, which ships this copy standalone so `npm install
// graphsmith-mcp-server` works without the rest of the repo present).
//
// Nothing enforces that the two stay in sync. If root SKILL.md is edited
// without updating this copy, the MCP server silently starts serving stale
// guidance with no error anywhere — the exact failure shape already fixed
// once for this same file when it shipped as a raw git symlink (see
// tests/fresh-install.test.js and the Lane B history it references). This
// test closes the other half of that finding: it fails loudly the moment
// the two files diverge by even one byte.
//
// If you're here because this test just failed: you edited one copy of
// SKILL.md and not the other. Make them identical again (usually: copy the
// root SKILL.md over mcp-server/SKILL.md) rather than editing this test.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const LOCAL_SKILL_MD = path.join(__dirname, "..", "SKILL.md");
const ROOT_SKILL_MD = path.join(__dirname, "..", "..", "SKILL.md");

test("mcp-server/SKILL.md is byte-identical to the root SKILL.md", () => {
  assert.ok(fs.existsSync(ROOT_SKILL_MD), `root SKILL.md not found at ${ROOT_SKILL_MD}`);
  assert.ok(fs.existsSync(LOCAL_SKILL_MD), `mcp-server/SKILL.md not found at ${LOCAL_SKILL_MD}`);

  const rootContent = fs.readFileSync(ROOT_SKILL_MD);
  const localContent = fs.readFileSync(LOCAL_SKILL_MD);

  assert.ok(
    rootContent.equals(localContent),
    "mcp-server/SKILL.md has drifted from the root SKILL.md — copy the root " +
      "file over mcp-server/SKILL.md to fix (do not edit this test)."
  );
});
