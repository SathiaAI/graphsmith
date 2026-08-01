"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { handleMessage } = require("../src/server.js");
const { LEGACY_PROTOCOL_VERSION, STATELESS_PROTOCOL_VERSION, TOOL_NAME } = require("../src/protocol.js");

test("legacy initialize handshake returns a legacy InitializeResult and marks the connection legacy", () => {
  const ctx = { connectionState: { legacyInitialized: false }, authenticated: true };
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, ctx);
  assert.equal(res.error, undefined);
  assert.equal(res.result.protocolVersion, LEGACY_PROTOCOL_VERSION);
  assert.equal(res.result.serverInfo.name, "graphsmith-mcp-server");
  assert.ok(res.result.capabilities.tools);
  assert.equal(ctx.connectionState.legacyInitialized, true);
});

test("notifications/initialized is a notification: returns null (no response sent)", () => {
  const ctx = { connectionState: { legacyInitialized: true }, authenticated: true };
  const res = handleMessage({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }, ctx);
  assert.equal(res, null);
});

test("after legacy initialize, tools/list works WITHOUT any _meta block", () => {
  const ctx = { connectionState: { legacyInitialized: false }, authenticated: true };
  handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, ctx);
  const res = handleMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, ctx);
  assert.equal(res.error, undefined);
  assert.equal(res.result.tools[0].name, TOOL_NAME);
});

test("after legacy initialize, tools/call works WITHOUT any _meta block", () => {
  const ctx = { connectionState: { legacyInitialized: false }, authenticated: true };
  handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, ctx);
  const res = handleMessage(
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: TOOL_NAME, arguments: {} } },
    ctx
  );
  assert.equal(res.error, undefined);
  assert.equal(res.result.isError, false);
});

test("server/discover is ALWAYS required to carry _meta, even on an already-legacy-initialized connection", () => {
  const ctx = { connectionState: { legacyInitialized: false }, authenticated: true };
  handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, ctx);
  const res = handleMessage({ jsonrpc: "2.0", id: 2, method: "server/discover", params: {} }, ctx);
  assert.notEqual(res.error, undefined, "server/discover without _meta must still fail, even post-legacy-handshake");
  assert.equal(res.error.code, -32602);
});

test("server/discover reports both supported protocol versions and points at the single tool", () => {
  const params = {
    _meta: {
      "io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL_VERSION,
      "io.modelcontextprotocol/clientInfo": { name: "c", version: "1" },
      "io.modelcontextprotocol/clientCapabilities": {},
    },
  };
  const ctx = { connectionState: { legacyInitialized: false }, authenticated: true };
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params }, ctx);
  assert.equal(res.error, undefined);
  assert.deepEqual(res.result.supportedVersions.sort(), [LEGACY_PROTOCOL_VERSION, STATELESS_PROTOCOL_VERSION].sort());
  assert.ok(res.result.capabilities.tools[TOOL_NAME]);
  assert.match(res.result.instructions, new RegExp(TOOL_NAME));
});

test("a stateless-native client that never calls legacy initialize must supply _meta on every call, including the first", () => {
  const ctx = { connectionState: { legacyInitialized: false }, authenticated: true };
  const noMeta = handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, ctx);
  assert.notEqual(noMeta.error, undefined);
});
