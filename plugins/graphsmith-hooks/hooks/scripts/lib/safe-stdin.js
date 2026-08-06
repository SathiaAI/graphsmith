#!/usr/bin/env node
"use strict";
/* GraphSmith plugin — hooks/scripts/lib/safe-stdin.js
 *
 * Defensive stdin reader for command-type Claude Code hooks.
 *
 * Why this exists: Claude Code hook processes are launched by the host and
 * may receive their JSON payload on stdin. A comparable project (ponytail)
 * hit a Windows PowerShell stdin-swallowing class of bug where a spawned
 * hook process could sit waiting on stdin that never delivers an 'end'
 * event — a bare "add a timeout" fix is not sufficient on its own if the
 * still-open stdin handle itself keeps the process alive after the timeout
 * fires. This module hardens against BOTH failure modes:
 *
 *   1. stdin never closes -> race 'end' against a hard timeout, so we never
 *      wait forever for data that isn't coming. The timer is intentionally
 *      left ref'd (Node's default) so it is GUARANTEED to fire even when
 *      nothing else is pending — unref'ing the timer here would be a
 *      textbook footgun: it would let the process exit before the timeout
 *      ever runs, silently defeating the whole point of having one.
 *
 *   2. once we've given up on stdin (timeout fires), the still-open stdin
 *      handle must not itself keep the process alive afterwards — so on
 *      timeout, and ONLY on timeout, we pause() and unref() the stream to
 *      release it. On the normal fast path (stdin actually closes), we
 *      never touch ref state at all, so a real, promptly-delivered payload
 *      is read exactly as a naive implementation would read it — no risk
 *      of exiting before 'end' fires just because we were "being careful".
 *
 * On any timeout, read error, or malformed JSON, this resolves to `null`
 * rather than throwing. Callers MUST treat `null` as "no input available,
 * proceed with defaults" — never as a reason to block.
 *
 * Zero-dependency CommonJS, Node >= 18, matching this repo's house style
 * (see scripts/verify.js, scripts/gate.js at the repo root).
 */

const DEFAULT_TIMEOUT_MS = 2000;

/**
 * @param {number} [timeoutMs]
 * @returns {Promise<object|null>}
 */
function readStdinJSON(timeoutMs) {
  const timeout = typeof timeoutMs === "number" ? timeoutMs : DEFAULT_TIMEOUT_MS;

  return new Promise((resolve) => {
    let settled = false;
    const chunks = [];

    // Guarded so any event firing after we've already settled (including
    // an 'error' from destroy()ing stdin on timeout) is a safe no-op
    // instead of an unhandled exception or a double-resolve.
    function finish(value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    }

    const timer = setTimeout(() => {
      // Only NOW — once we've actually decided to stop waiting — release
      // the stdin handle so a stream that never closes (the ponytail-class
      // PowerShell bug) cannot keep this process alive past this point.
      try {
        process.stdin.pause();
        if (typeof process.stdin.unref === "function") process.stdin.unref();
      } catch (_err) {
        /* best-effort release; falling through to finish() regardless */
      }
      finish(null);
    }, timeout);
    // Deliberately left ref'd: this timer is our only guaranteed way out
    // of a stdin stream that never closes, so it must be allowed to fire.

    try {
      if (process.stdin.isTTY) {
        // Interactive invocation (manual test run, etc.) — no piped
        // payload is coming. Don't wait for one.
        finish(null);
        return;
      }

      process.stdin.on("data", (chunk) => {
        if (settled) return;
        chunks.push(chunk);
      });
      process.stdin.on("end", () => {
        if (settled) return;
        const raw = Buffer.concat(chunks).toString("utf8").trim();
        if (!raw) {
          finish(null);
          return;
        }
        try {
          finish(JSON.parse(raw));
        } catch (_err) {
          finish(null);
        }
      });
      process.stdin.on("error", () => finish(null));
      process.stdin.resume();
    } catch (_err) {
      finish(null);
    }
  });
}

module.exports = { readStdinJSON, DEFAULT_TIMEOUT_MS };
