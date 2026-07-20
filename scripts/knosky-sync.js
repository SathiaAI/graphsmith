#!/usr/bin/env node
/* GraphSmith knosky-sync — keeps KnoSky current, cross-platform, non-blocking.
 * Never fails the user's task: offline/registry errors degrade to "use what's installed". */
const { execSync } = require("child_process");
const sh = (cmd) => { try { return execSync(cmd, { stdio: ["ignore", "pipe", "ignore"], timeout: 20000 }).toString().trim(); } catch { return null; } };

const latest = sh("npm view knosky version");
let local = null;
const ls = sh("npm ls -g knosky --depth=0 --json");
if (ls) { try { local = JSON.parse(ls).dependencies?.knosky?.version || null; } catch {} }

if (!latest) {
  console.log(local
    ? `knosky-sync: registry unreachable — using installed KnoSky v${local}.`
    : "knosky-sync: registry unreachable and KnoSky not installed — grounding unavailable this session (use `npx knosky@latest .` when online).");
  process.exit(0);
}
if (local === latest) { console.log(`knosky-sync: KnoSky v${local} is current.`); process.exit(0); }

const verb = local ? `updating v${local} → v${latest}` : `installing v${latest}`;
console.log(`knosky-sync: ${verb}...`);
const ok = sh(`npm i -g knosky@${latest}`) !== null;
console.log(ok
  ? `knosky-sync: KnoSky v${latest} ready.`
  : `knosky-sync: install failed (permissions?) — ${local ? `continuing with v${local}` : "falling back to `npx knosky@latest .`"}.`);
