/* write-report.js — hand a machine-readable report to the kernel before this
 * process can exit.
 *
 * THE DEFECT THIS EXISTS TO PREVENT
 *
 * process.stdout.write() and console.log() to a PIPE are asynchronous on POSIX.
 * libuv performs one write(2) and queues whatever it could not hand over, then
 * flushes the remainder on later event-loop turns. process.exit() discards that
 * queue. The caller reads a short — or entirely empty — report alongside exit
 * code 0, which is indistinguishable from this tool genuinely reporting success.
 * For a harness whose output IS the evidence, that is the worst available failure
 * mode: it does not fail loudly, it fabricates a pass.
 *
 * Measured, not theorised. MacBook Air (2015), macOS 12.7.3, node 18.20.8, on
 * `verify.js --selftest` before this was introduced:
 *
 *     redirected to a file : 11886 bytes   (synchronous path — the real report)
 *     captured via spawnSync:  8190 bytes   (pipe — short by 3696, exit code 0)
 *
 * Two properties make it unusually good at hiding, and both are why this helper
 * is applied to every report emit rather than only to large ones:
 *
 *   - It is NOT size-bounded. In CI the report arrived completely empty, meaning
 *     libuv's first try_write moved zero bytes. A small report is not safe.
 *   - It gets HARDER to observe under load. The suite that exposed it passed 17/0
 *     under 8-way CPU contention and failed 3/3 idle, because contention shifts
 *     the reader/writer interleaving in the harness's favour.
 *
 * WHY fs.writeSync AND NOT process.exitCode
 *
 * Setting process.exitCode and returning would also let the queue drain, but it
 * lets the process keep running until the event loop empties — trading a
 * truncated report for a possible hang if any handle is still open. These are
 * batch CLIs whose whole job is to exit with a verdict, so the exit stays
 * explicit and immediate; this helper simply guarantees the bytes are already
 * gone. Exit codes and exit timing are unchanged.
 *
 * tests/report-integrity/ enforces the resulting guarantee, and carries a
 * deliberately-broken positive control so it can prove its own detector is live
 * on the platform it is running on.
 */

"use strict";

const fs = require("fs");

// One shared 4-byte buffer for the EAGAIN backoff. Atomics.wait is the only
// synchronous sleep available, and it is already the idiom used by
// state-store.js's lock backoff.
const IDLE = new Int32Array(new SharedArrayBuffer(4));

/**
 * Write `text` to stdout, looping until every byte has been handed to the
 * kernel. Safe to call immediately before process.exit().
 *
 * @param {string} text the complete report, including any trailing newline
 */
function writeReport(text) {
  const buf = Buffer.from(String(text), "utf8");
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(1, buf, off, buf.length - off);
    } catch (error) {
      const code = error && error.code;
      if (code === "EAGAIN") {
        // A non-blocking pipe is momentarily full. Yield ~1ms rather than
        // spinning hot, then retry — the reader will drain it.
        Atomics.wait(IDLE, 0, 0, 1);
        continue;
      }
      if (code === "EPIPE") {
        // The reader is gone. There is nobody left to tell, and throwing here
        // would turn a closed pipe into a crash.
        return;
      }
      throw error;
    }
  }
}

module.exports = { writeReport };
