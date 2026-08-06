"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const { handleMessage } = require("../src/server.js");
const { TOOL_NAME, STATELESS_PROTOCOL_VERSION } = require("../src/protocol.js");
const { loadSkillMarkdown } = require("../src/skill.js");

function legacyCtx() {
  const connectionState = { legacyInitialized: false };
  const ctx = { connectionState, authenticated: true };
  // Perform legacy initialize first so tools/list and tools/call don't need _meta.
  handleMessage({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} }, ctx);
  return ctx;
}

test("tools/list exposes exactly one tool: graphsmith_guidance", () => {
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, legacyCtx());
  assert.equal(res.error, undefined);
  assert.equal(res.result.tools.length, 1);
  assert.equal(res.result.tools[0].name, TOOL_NAME);
});

test("the tool's inputSchema is a closed empty-object schema", () => {
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, legacyCtx());
  const schema = res.result.tools[0].inputSchema;
  assert.deepEqual(schema, { type: "object", properties: {}, additionalProperties: false });
});

test("tools/call with no arguments returns the current SKILL.md content verbatim", () => {
  const res = handleMessage(
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: TOOL_NAME, arguments: {} } },
    legacyCtx()
  );
  assert.equal(res.error, undefined);
  assert.equal(res.result.isError, false);
  assert.equal(res.result.content.length, 1);
  assert.equal(res.result.content[0].type, "text");
  assert.equal(res.result.content[0].text, loadSkillMarkdown());
});

test("tools/call with omitted 'arguments' key also succeeds (defaults to {})", () => {
  const res = handleMessage(
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: TOOL_NAME } },
    legacyCtx()
  );
  assert.equal(res.error, undefined);
});

test("ADVERSARIAL: a client passing unexpected arguments gets a validation error, not silent ignoring", () => {
  const res = handleMessage(
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: { unexpected: "surprise!" } },
    },
    legacyCtx()
  );
  assert.notEqual(res.error, undefined, "expected an error for unexpected arguments, got success");
  assert.equal(res.error.code, -32602); // INVALID_PARAMS
});

test("tools/call for an unknown tool name is INVALID_PARAMS", () => {
  const res = handleMessage(
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "some_other_tool", arguments: {} } },
    legacyCtx()
  );
  assert.notEqual(res.error, undefined);
  assert.equal(res.error.code, -32602);
});

test("returned content matches the package's own bundled SKILL.md file on disk exactly", () => {
  const bundled = fs.readFileSync(path.join(__dirname, "..", "SKILL.md"), "utf8");
  const res = handleMessage(
    { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: TOOL_NAME, arguments: {} } },
    legacyCtx()
  );
  assert.equal(res.result.content[0].text, bundled);
});

test("unknown method returns METHOD_NOT_FOUND", () => {
  const res = handleMessage({ jsonrpc: "2.0", id: 8, method: "resources/subscribe", params: {} }, legacyCtx());
  assert.equal(res.error.code, -32601);
});
