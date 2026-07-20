#!/usr/bin/env node
/* GraphSmith installer — one command, every agent on the machine.
 * Detects installed AI coding agents and copies this skill into each one's
 * skills directory. Zero dependencies. Safe: never overwrites without --force.
 * Usage: node scripts/install.js [--force] [--project] */
const fs = require("fs");
const path = require("path");
const os = require("os");

const SRC = path.resolve(__dirname, "..");
const FORCE = process.argv.includes("--force");
const PROJECT = process.argv.includes("--project");
const home = os.homedir();

// [detect-dir, skills-dir, label] — user-scoped: install if the agent's config dir exists
const USER_TARGETS = [
  [".claude", ".claude/skills", "Claude Code"],
  [".codex", ".codex/skills", "Codex CLI"],
  [".gemini", ".gemini/skills", "Gemini CLI"],
  [".agents", ".agents/skills", "Universal (~/.agents alias)"],
  [".hermes", ".hermes/skills", "Hermes Agent"],
  [".config/devin", ".config/devin/skills", "Devin (user)"],
];
// project-scoped: install if the agent dir exists in cwd (or --project forces cwd install)
const PROJ_TARGETS = [
  [".cursor", ".cursor/skills", "Cursor"],
  [".windsurf", ".windsurf/skills", "Windsurf / Devin Desktop"],
  [".devin", ".devin/skills", "Devin (project)"],
];

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if ([".git", "node_modules", ".runs"].includes(e.name)) continue;
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    e.isDirectory() ? copyDir(s, d) : fs.copyFileSync(s, d);
  }
}

let installed = 0, skipped = 0;
function tryInstall(base, detect, skillsDir, label) {
  if (!fs.existsSync(path.join(base, detect))) return;
  const dst = path.join(base, skillsDir, "graphsmith");
  if (fs.existsSync(dst) && !FORCE) {
    console.log(`↷ ${label}: already installed (${dst}) — use --force to overwrite`);
    skipped++; return;
  }
  copyDir(SRC, dst);
  console.log(`✓ ${label}: ${dst}`);
  installed++;
}

console.log("GraphSmith installer\n");
for (const [d, s, l] of USER_TARGETS) tryInstall(home, d, s, l);
for (const [d, s, l] of PROJ_TARGETS) tryInstall(process.cwd(), d, s, l);
if (PROJECT && !PROJ_TARGETS.some(([d]) => fs.existsSync(path.join(process.cwd(), d))))
  tryInstall(process.cwd(), ".", ".agents/skills", "This project (.agents/skills)");

if (!installed && !skipped) {
  console.log("No AI coding agents detected. Install one (Claude Code, Codex CLI, Gemini CLI,");
  console.log("Hermes, Cursor, Windsurf/Devin) and re-run, or use --project to install into this repo.");
} else {
  console.log(`\nDone: ${installed} installed, ${skipped} already present.`);
  console.log(`Try it — open your agent and say: "build me an agent that researches leads and drafts emails"`);
  console.log(`(Devin CLI: invoke with /graphsmith)`);
}
