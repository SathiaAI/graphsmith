"use strict";

/* ADVERSARIAL TEST (this is the one the Wave 1 kickoff explicitly demands):
 * "Attempt an unauthenticated call against any network transport and
 * confirm it's refused." This test does that against a REAL http.Server
 * instance listening on a real ephemeral TCP port -- not a mock, not a
 * unit test of the auth function in isolation (that's auth.test.js). A
 * genuine HTTP client makes a genuine unauthenticated POST over the loop-
 * back interface and we assert on the real response.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");

const { createHttpServer } = require("../src/httpTransport.js");
const { STATELESS_PROTOCOL_VERSION, TOOL_NAME } = require("../src/protocol.js");

const TEST_TOKEN = "test-only-token-not-a-secret-1234567890";

function startServer(token) {
  const server = createHttpServer({ token });
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

function postJson(port, path_, body, headers) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: path_ || "/",
        method: "POST",
        headers: Object.assign(
          { "content-type": "application/json", "content-length": Buffer.byteLength(data) },
          headers || {}
        ),
      },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          let parsed = null;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch (e) {
            /* some responses (204) legitimately have no body */
          }
          resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed });
        });
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

const validRpcBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: TOOL_NAME,
    arguments: {},
    _meta: {
      "io.modelcontextprotocol/protocolVersion": STATELESS_PROTOCOL_VERSION,
      "io.modelcontextprotocol/clientInfo": { name: "adversarial-test-client", version: "1.0.0" },
      "io.modelcontextprotocol/clientCapabilities": {},
    },
  },
};

test("createHttpServer() REFUSES TO CONSTRUCT without a token (fail closed at startup)", () => {
  assert.throws(() => createHttpServer({}), /token/i);
  assert.throws(() => createHttpServer({ token: "" }), /token/i);
  assert.throws(() => createHttpServer({ token: "short" }), /token/i); // too short to be a real secret
});

test("ADVERSARIAL: an unauthenticated network call is refused with 401, never reaches the tool", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody /* no Authorization header at all */);
    assert.equal(res.statusCode, 401);
    assert.equal(res.headers["www-authenticate"], "Bearer");
    assert.notEqual(res.body.error, undefined);
    assert.equal(res.body.error.code, -32001);
  } finally {
    server.close();
  }
});

test("ADVERSARIAL: a call with the wrong bearer token is refused with 401", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody, { authorization: "Bearer not-the-right-token" });
    assert.equal(res.statusCode, 401);
  } finally {
    server.close();
  }
});

test("ADVERSARIAL: a malformed Authorization header (not 'Bearer ...') is refused with 401", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody, { authorization: TEST_TOKEN }); // missing "Bearer " prefix
    assert.equal(res.statusCode, 401);
  } finally {
    server.close();
  }
});

test("a call WITH the correct bearer token succeeds and returns the guidance", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody, { authorization: `Bearer ${TEST_TOKEN}` });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.error, undefined);
    assert.equal(res.body.result.isError, false);
    assert.ok(res.body.result.content[0].text.length > 0);
  } finally {
    server.close();
  }
});

test("every HTTP request is independently authenticated: a previously-successful request's absence of a session does not help a later unauthenticated one", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const authed = await postJson(port, "/", validRpcBody, { authorization: `Bearer ${TEST_TOKEN}` });
    assert.equal(authed.statusCode, 200);
    // Immediately follow with an unauthenticated call on a fresh connection/request.
    const unauthed = await postJson(port, "/", validRpcBody);
    assert.equal(unauthed.statusCode, 401);
  } finally {
    server.close();
  }
});
