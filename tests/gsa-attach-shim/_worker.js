#!/usr/bin/env node
/* Helper child process for tests/gsa-attach-shim/run-tests.js. Stands in for an
 * enterprise's own MCP gateway process embedding the attach-mode shim, following the
 * exact call sequence docs/GSA-ATTACH-MODE-WIRING.md documents: construct, start()
 * (exit non-zero with the refusal on failure), stay up, stop() + exit 0 on
 * SIGTERM/SIGINT. Reports each phase as one JSON line on stdout; never throws uncaught.
 *
 * argv: <projectRoot>
 */
"use strict";

const path = require("path");
const { AttachModeShim } = require(path.join(__dirname, "..", "..", "scripts", "gsa-attach-shim.js"));
const { writeReport } = require(path.join(__dirname, "..", "..", "scripts", "write-report.js"));

const [, , projectRoot] = process.argv;
const shim = new AttachModeShim(projectRoot);

try {
  shim.start();
} catch (error) {
  writeReport(JSON.stringify({ phase: "start", ok: false, code: error.code || "UNKNOWN", message: error.message }) + "\n");
  process.exitCode = 1;
  process.exit(); // nothing scheduled (no keepAlive interval below) -- exits immediately either way; explicit for clarity
}

writeReport(JSON.stringify({ phase: "start", ok: true }) + "\n");

// AttachModeShim.startHeartbeat()'s underlying timer is unref'd (see writer-claim.js) --
// deliberately, so a real embedding gateway's own event loop can idle without this
// shim's heartbeat alone keeping the process alive. This worker stands in for that
// gateway's own request-handling activity, which is the thing that actually keeps a
// real gateway process alive between MCP sessions; a plain ref'd interval reproduces
// that here without pulling in a real MCP server for this test.
const keepAlive = setInterval(() => {}, 1000);

function shutdown() {
  clearInterval(keepAlive);
  let released = false;
  let stopError = null;
  try { released = shim.stop(); } catch (error) { stopError = error; }
  writeReport(JSON.stringify({
    phase: "stop", ok: !stopError, released,
    code: stopError ? (stopError.code || "UNKNOWN") : undefined,
    message: stopError ? stopError.message : undefined,
  }) + "\n");
  process.exit(stopError ? 1 : 0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
