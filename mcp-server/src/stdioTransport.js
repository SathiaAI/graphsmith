"use strict";

const readline = require("readline");
const { handleMessage } = require("./server.js");
const { ERROR_CODES } = require("./protocol.js");

/* stdio transport. Per the frozen Lane C design: the OS process boundary IS
 * the trust boundary here -- there is exactly one caller type (whatever
 * process spawned this server over stdio), so per-request authentication
 * as SEP-2575 defines it is trivially satisfied and no bearer token is
 * layered on top of stdio itself. This is a narrower claim than "provably
 * only reachable by the intended host" (an OS-level authorization
 * question MCP does not address) -- see the design doc's "Statelessness
 * and auth" section for the full distinction. authenticated stays true for
 * every message on this transport; ctx.connectionState is real (tracks
 * legacy-handshake dialect for this one process's single stdio pipe), it
 * is just never a session ID and never persisted across process restarts.
 *
 * Wire framing: one JSON-RPC message per line (newline-delimited JSON),
 * matching the framing MCP's own stdio transport implementations use.
 */
function runStdioServer(options) {
  const input = (options && options.input) || process.stdin;
  const output = (options && options.output) || process.stdout;

  const connectionState = { legacyInitialized: false };
  const rl = readline.createInterface({ input, terminal: false });

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;

    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (err) {
      const response = {
        jsonrpc: "2.0",
        id: null,
        error: { code: ERROR_CODES.PARSE_ERROR, message: `Parse error: ${err.message}` },
      };
      output.write(JSON.stringify(response) + "\n");
      return;
    }

    const response = handleMessage(msg, { connectionState, authenticated: true });
    if (response !== null) {
      output.write(JSON.stringify(response) + "\n");
    }
  });

  rl.on("close", () => {
    /* Stdin closed (parent process exited or piped EOF) -- exit cleanly.
     * Nothing to flush; there is no session state to persist. */
    process.exit(0);
  });

  return { connectionState, rl };
}

module.exports = { runStdioServer };
