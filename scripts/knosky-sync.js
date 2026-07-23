#!/usr/bin/env node
/* GraphSmith knosky-sync — prepares KnoSky grounding. Cross-platform, non-blocking.
 * v0.1.1 (post council review, PA-3):
 *   - PINNED version, bumped only with GraphSmith releases — never `latest`.
 *   - NO global install, ever: grounding runs via `npx knosky@<pin>`, so nothing
 *     silently escalates to the agent's global environment.
 *   - No interpolated shell data: every command below is a compile-time constant
 *     (the v0.1.0 injection surface was registry output interpolated into a shell
 *     string; that path no longer exists).
 *   - GRAPHSMITH_OFFLINE=1 skips all network activity — for air-gapped or
 *     regulated environments. Newer upstream versions are REPORTED, not installed.
 * Never fails the user's task: any error degrades to "use what's cached". */
const { execFileSync } = require("child_process");

const PIN = "0.8.0"; // bump together with GraphSmith releases, after review
// PD-10: content-integrity pin. A version label alone can be re-published by a
// compromised registry; the sha512 below is the hash of the exact tarball this
// release was reviewed against. A mismatch means the content behind the label
// changed — refuse and say so. Residual (disclosed): the check queries the same
// registry it distrusts, so it defeats label reassignment, not a registry that
// lies consistently; air-gapped verification belongs to the v0.2.0 regulated
// extension. Bump PIN and EXPECTED_INTEGRITY together, never separately.
const EXPECTED_INTEGRITY = "sha512-YAfZijKUBLJxfSeg0XQJNDT02z+YhjP778Wi3bmBNDpWNVzJtmmUKd5Wt88+OCT6bLhMo1efcOAS9ye+zJ+LuQ==";
const GROUND_CMD = `npx knosky@${PIN} .`;
const win = process.platform === "win32";
// All args are constants; shell:true is required for npm/npx .cmd shims on
// Windows (Node blocks .cmd via execFile without it) and introduces no
// injection surface because nothing here is interpolated from external input.
const opts = { stdio: ["ignore", "pipe", "ignore"], timeout: 30000, shell: win };
const tryRun = (cmd, args) => { try { return execFileSync(cmd, args, opts).toString().trim(); } catch { return null; } };

// PD-9: explicit values only — "0"/"false"/"no" must NOT enable offline mode
// (bare truthiness made GRAPHSMITH_OFFLINE=0 do the opposite of what it says).
const OFFLINE = ["1", "true", "yes"].includes(String(process.env.GRAPHSMITH_OFFLINE || "").toLowerCase());
if (OFFLINE) {
  console.log(`knosky-sync: GRAPHSMITH_OFFLINE set — skipping all network activity.`);
  console.log(`knosky-sync: grounding command (uses npx cache only): ${GROUND_CMD}`);
  process.exit(0);
}

// Verify the content behind the pin BEFORE recommending it for execution.
const integrity = tryRun(win ? "npm.cmd" : "npm", ["view", `knosky@${PIN}`, "dist.integrity"]);
if (integrity !== null && integrity !== EXPECTED_INTEGRITY) {
  console.error(`knosky-sync: INTEGRITY MISMATCH for knosky@${PIN} — the registry is serving different content than this release was reviewed against.`);
  console.error(`  expected ${EXPECTED_INTEGRITY}`);
  console.error(`  got      ${integrity}`);
  console.error(`  Refusing to recommend execution. Do not run knosky until this is resolved (report it: https://github.com/SathiaAI/graphsmith/issues).`);
  process.exit(1);
}
const warmed = tryRun(win ? "npx.cmd" : "npx", ["-y", `knosky@${PIN}`, "--version"]);
if (warmed !== null) {
  console.log(`knosky-sync: KnoSky v${PIN} ready (pinned; content integrity ${integrity !== null ? "verified" : "unverified — registry unreachable, using npx cache"}). Ground with: ${GROUND_CMD}`);
} else {
  console.log(`knosky-sync: registry unreachable — grounding will use whatever npx has cached.`);
  console.log(`knosky-sync: command unchanged: ${GROUND_CMD} (retry when online if it fails).`);
}

const latest = tryRun(win ? "npm.cmd" : "npm", ["view", "knosky", "version"]);
if (latest && /^\d+\.\d+\.\d+$/.test(latest) && latest !== PIN)
  console.log(`knosky-sync: note — knosky v${latest} exists upstream; the pin updates with GraphSmith releases (no auto-install).`);
