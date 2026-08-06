"use strict";

/* End-to-end integration test: spawns the REAL bin/graphsmith-mcp.js as a
 * child process (exactly how Claude Code or any other stdio host would
 * invoke it) and talks JSON-RPC over its real stdin/stdout, rather than
 * calling handleMessage() directly in-process. */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { spawn } = require("child_process");

const BIN = path.join(__dirname, "..", "bin", "graphsmith-mcp.js");
const { STATELESS_PROTOCOL_VERSION, TOOL_NAME } = require("../src/protocol.js");

function spawnServer() {
  return spawn(process.execPath, [BIN], { stdio: ["pipe", "pipe", "pipe"] });
}

/* Sends one line, waits for exactly one response line. */
function roundTrip(child, msg) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (chunk) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        child.stdout.removeListener("data", onData);
        clearTimeout(timer);
        resolve(JSON.parse(buf.slice(0, nl)));
      }
    };
    const timer = setTimeout(() => {
      child.stdout.removeListener("data", onData);
      reject(new Error("timed out waiting for stdio response"));
    }, 5000);
    child.stdout.on("data", onData);
    child.stdin.write(JSON.stringify(msg) + "\n");
  });
}

test("real subprocess: legacy initialize -> tools/list -> tools/call over real stdio pipes", async () => {
  const child = spawnServer();
  try {
    const init = await roundTrip(child, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.equal(init.error, undefined);
    assert.equal(init.result.serverInfo.name, "graphsmith-mcp-server");

    const list = await roundTrip(child, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    assert.equal(list.result.tools[0].name, TOOL_NAME);

    const call = await roundTrip(child, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: {} },
    });
    assert.equal(call.result.isError, false);
    assert.match(call.result.content[0].text, /GraphSmith/i);
  } finally {
    child.kill();
  }
});

test("real subprocess: stateless-native server/discover works with no prior initialize", async () => {
  const child = spawnServer();
  try {
    const params = {
      _meta: {
        "io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": { name: "integration-test", version: "1.0.0" },
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    };
    const res = await roundTrip(child, { jsonrpc: "2.0", id: 1, method: "server/discover", params });
    assert.equal(res.error, undefined);
    assert.ok(res.result.supportedVersions.includes(STATELESS_PROTOCOL_VERSION));
  } finally {
    child.kill();
  }
});

test("real subprocess: an unexpected-arguments tool call is rejected, not silently ignored", async () => {
  const child = spawnServer();
  try {
    await roundTrip(child, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    const res = await roundTrip(child, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: { sneaky: true } },
    });
    assert.notEqual(res.error, undefined);
  } finally {
    child.kill();
  }
});

test("real subprocess: --help exits without starting a server", async () => {
  const child = spawn(process.execPath, [BIN, "--help"], { stdio: ["ignore", "pipe", "pipe"] });
  const exitCode = await new Promise((resolve) => child.on("exit", resolve));
  assert.equal(exitCode, 0);
});
