"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { handleMessage } = require("../src/server.js");
const { ERROR_CODES, STATELESS_PROTOCOL_VERSION } = require("../src/protocol.js");

function freshCtx() {
  return { connectionState: { legacyInitialized: false }, authenticated: true };
}

const VALID_META = {
  _meta: {
    "io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0.0" },
    "io.modelcontextprotocol/clientCapabilities": {},
  },
};

test("server/discover with no _meta at all is INVALID_PARAMS", () => {
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params: {} }, freshCtx());
  assert.equal(res.error.code, ERROR_CODES.INVALID_PARAMS);
});

test("tools/call with no _meta on a fresh (non-legacy) connection is INVALID_PARAMS", () => {
  const res = handleMessage(
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "graphsmith_guidance", arguments: {} } },
    freshCtx()
  );
  assert.equal(res.error.code, ERROR_CODES.INVALID_PARAMS);
});

test("tools/list with no _meta on a fresh connection is INVALID_PARAMS", () => {
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, freshCtx());
  assert.equal(res.error.code, ERROR_CODES.INVALID_PARAMS);
});

test("missing clientInfo is INVALID_PARAMS", () => {
  const params = {
    _meta: {
      "io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL_VERSION,
      "io.modelcontextprotocol/clientCapabilities": {},
    },
  };
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params }, freshCtx());
  assert.equal(res.error.code, ERROR_CODES.INVALID_PARAMS);
  assert.match(res.error.message, /clientInfo/);
});

test("missing clientCapabilities is INVALID_PARAMS (even though it may be an empty object)", () => {
  const params = {
    _meta: {
      "io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL_VERSION,
      "io.modelcontextprotocol/clientInfo": { name: "c", version: "1" },
    },
  };
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params }, freshCtx());
  assert.equal(res.error.code, ERROR_CODES.INVALID_PARAMS);
  assert.match(res.error.message, /clientCapabilities/);
});

test("empty clientCapabilities object IS valid (means: supports nothing optional)", () => {
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params: VALID_META }, freshCtx());
  assert.equal(res.error, undefined);
  assert.ok(res.result);
});

test("unsupported protocol version returns UNSUPPORTED_PROTOCOL_VERSION (-32022)", () => {
  const params = {
    _meta: {
      "io.modelcontextprotocol/protocolVersion": "1999-01-01",
      "io.modelcontextprotocol/clientInfo": { name: "c", version: "1" },
      "io.modelcontextprotocol/clientCapabilities": {},
    },
  };
  const res = handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params }, freshCtx());
  assert.equal(res.error.code, -32022);
  assert.equal(res.error.code, ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION);
});

test("valid _meta on tools/call for a fresh connection succeeds", () => {
  const params = Object.assign({ name: "graphsmith_guidance", arguments: {} }, VALID_META);
  const res = handleMessage({ jsonrpc: "2.0", id: 7, method: "tools/call", params }, freshCtx());
  assert.equal(res.error, undefined);
  assert.equal(res.id, 7);
  assert.ok(Array.isArray(res.result.content));
});

test("malformed JSON-RPC envelope (wrong jsonrpc version) is INVALID_REQUEST", () => {
  const res = handleMessage({ jsonrpc: "1.0", id: 1, method: "server/discover", params: VALID_META }, freshCtx());
  assert.equal(res.error.code, ERROR_CODES.INVALID_REQUEST);
});

test("non-object message is INVALID_REQUEST, not a crash", () => {
  const res = handleMessage("not an object", freshCtx());
  assert.equal(res.error.code, ERROR_CODES.INVALID_REQUEST);
});
