"use strict";

/* ADVERSARIAL TEST: "fresh npm install in an empty dir with zero monorepo
 * context, confirm it actually runs."
 *
 * This does the real thing, not a simulation: `npm pack` this package into
 * a real tarball, `npm install` that tarball into a brand-new empty
 * directory that has no path relationship to this repo checkout at all,
 * then spawn the INSTALLED binary from THAT directory and talk real
 * stdio JSON-RPC to it. If this package ever grows a require('../../..')
 * or an assumption about a sibling monorepo checkout (the exact ponytail
 * mcp-server failure mode this design explicitly avoids), this test fails.
 *
 * Slower than the rest of the suite (spawns npm twice) -- given its own
 * generous timeout below.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFileSync, spawn } = require("child_process");

const PACKAGE_DIR = path.join(__dirname, "..");

function sh(cmd, args, opts) {
  // On Windows, npm resolves to npm.cmd, and Node's execFileSync does not
  // auto-resolve .cmd/.bat extensions unless shell: true is set -- without
  // it this fails with ENOENT even though npm is genuinely on PATH.
  const platformOpts = process.platform === "win32" ? { shell: true } : {};
  return execFileSync(cmd, args, Object.assign({ encoding: "utf8" }, opts, platformOpts));
}

test(
  "fresh npm install of the packed tarball into an empty, unrelated directory actually runs",
  { timeout: 120000 },
  async () => {
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-mcp-fresh-install-"));
    const installDir = fs.mkdtempSync(path.join(os.tmpdir(), "graphsmith-mcp-empty-target-"));

    try {
      // 1. Pack the real package exactly as it would be published.
      const packOutput = sh("npm", ["pack", "--json", "--pack-destination", workDir], { cwd: PACKAGE_DIR });
      const [{ filename }] = JSON.parse(packOutput);
      const tarballPath = path.join(workDir, filename);
      assert.ok(fs.existsSync(tarballPath), "npm pack must produce a tarball");

      // 2. Confirm the target directory really is empty before install.
      assert.deepEqual(fs.readdirSync(installDir), []);

      // 3. Install into that empty directory, with NO awareness of this
      // monorepo (a distinct --prefix, no shared node_modules, no
      // relative path back to the repo).
      sh("npm", ["install", tarballPath, "--prefix", installDir, "--no-audit", "--no-fund"], { cwd: installDir });

      const installedBin = path.join(installDir, "node_modules", ".bin", "graphsmith-mcp");
      const installedPkgDir = path.join(installDir, "node_modules", "graphsmith-mcp-server");
      assert.ok(fs.existsSync(installedBin), "the installed package must expose its bin");
      assert.ok(fs.existsSync(path.join(installedPkgDir, "SKILL.md")), "SKILL.md must be bundled inside the installed package");

      // 4. Resolve the real entrypoint to spawn in step 6 below.
      // On Windows, npm's extensionless `.bin/graphsmith-mcp` file is a
      // POSIX shell shim (see cmd-shim), not JavaScript -- spawning it as
      // `node <that file>` below either throws a syntax error on startup
      // or, worse, silently fails with nothing on stdout (stderr is
      // intentionally discarded a few lines down as noise), which just
      // hangs this test until the 15s timeout. Resolve the real JS
      // entrypoint from the installed package's own package.json instead
      // of trusting OS-specific bin-shim mechanics -- this is still a
      // faithful test of "the installed package, in isolation, runs",
      // since that's the exact file any shim ultimately execs.
      const installedPkgJson = JSON.parse(fs.readFileSync(path.join(installedPkgDir, "package.json"), "utf8"));
      const binRelPath = typeof installedPkgJson.bin === "string" ? installedPkgJson.bin : installedPkgJson.bin["graphsmith-mcp"];
      const installedEntrypoint = path.join(installedPkgDir, binRelPath);
      assert.ok(fs.existsSync(installedEntrypoint), "the installed package's bin entrypoint must exist on disk");

      // 5. Confirm no leaked path back into the monorepo checkout anywhere
      // in the installed files (the ponytail createRequire failure mode).
      const installedFiles = fs.readdirSync(installedPkgDir, { recursive: true });
      for (const rel of installedFiles) {
        const full = path.join(installedPkgDir, String(rel));
        if (fs.statSync(full).isFile()) {
          const contents = fs.readFileSync(full, "utf8");
          assert.doesNotMatch(
            contents,
            /\/tmp\/lane-c-work\/repo|graphsmith-mcp-server\/\.\.\/\.\.\//,
            `installed file ${rel} must not reference the monorepo checkout path`
          );
        }
      }

      // 6. Actually run it: spawn the INSTALLED binary from the INSTALLED
      // directory and do a real stdio JSON-RPC round trip.
      const child = spawn(process.execPath, [installedEntrypoint], { cwd: installDir, stdio: ["pipe", "pipe", "pipe"] });
      let stderrBuf = "";
      const response = await new Promise((resolve, reject) => {
        let buf = "";
        const timer = setTimeout(() => reject(new Error(`isolated-install server did not respond in time (stderr: ${stderrBuf.slice(0, 2000)})`)), 15000);
        child.stdout.on("data", (chunk) => {
          buf += chunk.toString("utf8");
          const nl = buf.indexOf("\n");
          if (nl !== -1) {
            clearTimeout(timer);
            resolve(JSON.parse(buf.slice(0, nl)));
          }
        });
        // Keep stderr for the error message above instead of silently
        // discarding it -- a crash on startup used to be indistinguishable
        // from a slow response, both surfacing only as a bare timeout.
        child.stderr.on("data", (chunk) => {
          stderrBuf += chunk.toString("utf8");
        });
        child.on("exit", (code, signal) => {
          reject(new Error(`isolated-install server exited early (code=${code}, signal=${signal}) before responding (stderr: ${stderrBuf.slice(0, 2000)})`));
        });
        child.on("error", reject);
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
      }).finally(() => {
        child.removeAllListeners("exit");
      });
      child.kill();

      assert.equal(response.error, undefined);
      assert.equal(response.result.serverInfo.name, "graphsmith-mcp-server");
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
      fs.rmSync(installDir, { recursive: true, force: true });
    }
  }
);
