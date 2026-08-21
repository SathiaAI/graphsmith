#!/usr/bin/env node
/* Helper child process for tests/state-store/writer-claim-shared-storage/run-tests.js.
 * Constructs a WriterClaim against a shared state directory (simulating a second host
 * pointed at the same shared/networked volume) and attempts acquire(). Reports the
 * outcome as one JSON line on stdout; never throws uncaught.
 *
 * argv: <stateDir> <hostId> <instanceId>
 */
"use strict";

const path = require("path");
const { WriterClaim } = require(path.join(__dirname, "..", "..", "..", "scripts", "writer-claim.js"));
const { writeReport } = require(path.join(__dirname, "..", "..", "..", "scripts", "write-report.js"));

const [, , stateDir, hostId, instanceId] = process.argv;

try {
  const claim = new WriterClaim(stateDir, { hostId, instanceId });
  claim.acquire();
  writeReport(JSON.stringify({ ok: true, instanceId, hostId }) + "\n");
  process.exitCode = 0;
} catch (error) {
  writeReport(JSON.stringify({ ok: false, instanceId, hostId, code: error.code || "UNKNOWN", message: error.message }) + "\n");
  process.exitCode = 1;
}
