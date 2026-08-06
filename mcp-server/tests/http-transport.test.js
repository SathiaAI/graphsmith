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
const net = require("net");

const { createHttpServer, MAX_BODY_BYTES } = require("../src/httpTransport.js");
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

/* Streamable HTTP transport, 2026-07-28 revision: MCP-Protocol-Version and
 * Mcp-Method are required on every request; Mcp-Name is additionally
 * required for tools/call. These mirror validRpcBody's own method/name/
 * protocol version so a real success path (as opposed to the adversarial
 * auth-rejection tests below, which never get far enough to reach header
 * validation) has valid headers to succeed with. */
const validRpcHeaders = {
  "mcp-protocol-version": STATELESS_PROTOCOL_VERSION,
  "mcp-method": "tools/call",
  "mcp-name": TOOL_NAME,
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
    const res = await postJson(
      port,
      "/",
      validRpcBody,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, validRpcHeaders)
    );
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
    const authed = await postJson(
      port,
      "/",
      validRpcBody,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, validRpcHeaders)
    );
    assert.equal(authed.statusCode, 200);
    // Immediately follow with an unauthenticated call on a fresh connection/request.
    const unauthed = await postJson(port, "/", validRpcBody);
    assert.equal(unauthed.statusCode, 401);
  } finally {
    server.close();
  }
});

/* --- Body-byte-accounting regression tests (round-2 non-Anthropic council
 * review, 2026-08-05): the request-body accumulator used to do
 * `body += chunk`, which implicitly decodes each chunk as UTF-8 and then
 * measures `.length` in UTF-16 code units, not bytes. Two independently
 * confirmed failure modes:
 *   1. Multi-byte UTF-8 payloads could exceed MAX_BODY_BYTES in real bytes
 *      while still passing the (UTF-16-length-based) cap check.
 *   2. A multi-byte UTF-8 character split across two TCP chunks would be
 *      decoded per-chunk and silently corrupt into replacement character(s)
 *      (U+FFFD), with JSON.parse() still succeeding on the corrupted string.
 * Fixed by accumulating raw Buffer chunks, counting real bytes, and
 * decoding once from the fully reassembled buffer. */

function postRaw(port, bodyBuffer, headers) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/",
        method: "POST",
        headers: Object.assign(
          { "content-type": "application/json", "content-length": bodyBuffer.length },
          headers || {}
        ),
      },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => resolve({ statusCode: res.statusCode, body: raw, errored: false }));
      }
    );
    req.on("error", () => resolve({ statusCode: null, body: null, errored: true }));
    req.end(bodyBuffer);
  });
}

test("MAX_BODY_BYTES is enforced against real bytes, not UTF-16 string length (multi-byte UTF-8 payload)", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    // U+4E2D ("中") is 1 UTF-16 code unit but 3 UTF-8 bytes. Repeated enough
    // times, the JS string .length stays well under MAX_BODY_BYTES while
    // the actual UTF-8 byte count is well over it -- the exact gap the
    // old `body.length > MAX_BODY_BYTES` check missed.
    const filler = "中".repeat(400000);
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: { junk: filler }, _meta: validRpcBody.params._meta },
    });
    const buf = Buffer.from(payload, "utf8");
    // Sanity-check the premise of this test before asserting server behavior.
    assert.ok(
      payload.length < MAX_BODY_BYTES,
      "test payload's UTF-16 .length must stay under the cap (that's what the old buggy check saw)"
    );
    assert.ok(buf.length > MAX_BODY_BYTES, "test payload's real UTF-8 byte length must exceed the cap");

    const res = await postRaw(port, buf, { authorization: `Bearer ${TEST_TOKEN}` });
    // The connection is destroyed once real bytesReceived exceeds the cap --
    // there is no complete 200 response for this oversized payload.
    assert.notEqual(res.statusCode, 200);
  } finally {
    server.close();
  }
});

function splitRawHttpPost(port, headBuffer, bodyBuffer, splitAt) {
  // Collect the response as raw Buffer chunks and concat-then-decode once at
  // the end -- decoding incrementally per 'data' event here would reintroduce
  // the exact same chunk-boundary corruption bug this test is checking for,
  // this time in the test harness's own response reading instead of the
  // server's request reading.
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    const chunks = [];
    socket.on("data", (d) => {
      chunks.push(d);
    });
    socket.on("close", () => resolve(Buffer.concat(chunks)));
    socket.on("error", reject);
    socket.on("connect", () => {
      socket.write(headBuffer, () => {
        const first = bodyBuffer.subarray(0, splitAt);
        const second = bodyBuffer.subarray(splitAt);
        socket.write(first, () => {
          // Force these onto separate TCP segments / separate 'data' events
          // server-side, rather than letting Nagle's algorithm or a single
          // fast write coalesce them back into one.
          setTimeout(() => socket.end(second), 20);
        });
      });
    });
    setTimeout(() => {
      if (!socket.destroyed) socket.destroy();
      resolve(Buffer.concat(chunks));
    }, 3000);
  });
}

test("a multi-byte UTF-8 character split across two TCP chunks round-trips intact, not corrupted into U+FFFD", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    // The id itself carries the multi-byte character, since handleMessage
    // echoes `id` back verbatim in the JSON-RPC response -- corruption here
    // is directly observable in the response, not silently absorbed.
    const idWithMultiByteChar = "id-中-tail";
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: idWithMultiByteChar,
      method: "tools/call",
      params: { name: TOOL_NAME, arguments: {}, _meta: validRpcBody.params._meta },
    });
    const bodyBuffer = Buffer.from(payload, "utf8");
    const charByteOffset = bodyBuffer.indexOf(Buffer.from("中", "utf8"));
    assert.ok(charByteOffset > 0, "test payload must actually contain the multi-byte character");
    // Split one byte into the character's 3-byte UTF-8 encoding, so each
    // half genuinely holds a partial, invalid-on-its-own byte sequence.
    const splitAt = charByteOffset + 1;

    const headLines = [
      "POST / HTTP/1.1",
      "Host: 127.0.0.1",
      "Content-Type: application/json",
      `Content-Length: ${bodyBuffer.length}`,
      `Authorization: Bearer ${TEST_TOKEN}`,
      "Connection: close",
      "",
      "",
    ];
    const headBuffer = Buffer.from(headLines.join("\r\n"), "utf8");

    const rawResponse = await splitRawHttpPost(port, headBuffer, bodyBuffer, splitAt);
    const blankLineIdx = rawResponse.indexOf("\r\n\r\n");
    assert.ok(blankLineIdx !== -1, `expected a well-formed HTTP response, got: ${rawResponse.toString("utf8")}`);
    let remainder = rawResponse.subarray(blankLineIdx + 4);
    // The server sends chunked transfer-encoding (no explicit Content-Length
    // on its own responses) -- strip the "<hex-length>\r\n...\r\n0\r\n\r\n"
    // chunk framing (possibly multiple chunks, for a large guidance
    // response) to get at the actual JSON payload. Chunk-size lines are
    // pure ASCII hex digits, safe to decode piecemeal; the chunk DATA stays
    // in Buffer form and is only decoded once, fully reassembled, below --
    // exactly the discipline this test exists to enforce.
    const bodyChunks = [];
    while (true) {
      const lineEnd = remainder.indexOf("\r\n");
      const sizeLine = remainder.subarray(0, lineEnd).toString("ascii");
      assert.ok(/^[0-9a-fA-F]+$/.test(sizeLine), `expected a hex chunk-size line, got: ${sizeLine}`);
      const chunkLen = parseInt(sizeLine, 16);
      if (chunkLen === 0) break;
      bodyChunks.push(remainder.subarray(lineEnd + 2, lineEnd + 2 + chunkLen));
      remainder = remainder.subarray(lineEnd + 2 + chunkLen + 2); // skip trailing \r\n after chunk data
    }
    const responseBody = Buffer.concat(bodyChunks).toString("utf8");
    const parsed = JSON.parse(responseBody);
    // If the chunk-boundary split corrupted the character, this comes back
    // containing U+FFFD (or something else) instead of the original id.
    assert.equal(parsed.id, idWithMultiByteChar);
  } finally {
    server.close();
  }
});

/* --- Mirrored HTTP header validation (Streamable HTTP transport,
 * 2026-07-28 revision, "Request Metadata" / "Server Validation"): every
 * POST must carry MCP-Protocol-Version and Mcp-Method matching the body,
 * plus Mcp-Name for tools/call; a missing or disagreeing header is a 400
 * with a HeaderMismatch (-32020) JSON-RPC error, checked after auth but
 * before dispatch. --- */

test("a request missing the MCP-Protocol-Version header is rejected 400 HeaderMismatch", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody, {
      authorization: `Bearer ${TEST_TOKEN}`,
      "mcp-method": "tools/call",
      "mcp-name": TOOL_NAME,
      // MCP-Protocol-Version deliberately omitted
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, -32020);
  } finally {
    server.close();
  }
});

test("a request missing the Mcp-Method header is rejected 400 HeaderMismatch", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody, {
      authorization: `Bearer ${TEST_TOKEN}`,
      "mcp-protocol-version": STATELESS_PROTOCOL_VERSION,
      "mcp-name": TOOL_NAME,
      // Mcp-Method deliberately omitted
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, -32020);
  } finally {
    server.close();
  }
});

test("a tools/call request missing the Mcp-Name header is rejected 400 HeaderMismatch", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(port, "/", validRpcBody, {
      authorization: `Bearer ${TEST_TOKEN}`,
      "mcp-protocol-version": STATELESS_PROTOCOL_VERSION,
      "mcp-method": "tools/call",
      // Mcp-Name deliberately omitted
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, -32020);
  } finally {
    server.close();
  }
});

test("a Mcp-Method header that disagrees with the body's method is rejected 400 HeaderMismatch", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(
      port,
      "/",
      validRpcBody,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, validRpcHeaders, { "mcp-method": "tools/list" })
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, -32020);
  } finally {
    server.close();
  }
});

test("a Mcp-Name header that disagrees with the body's tool name is rejected 400 HeaderMismatch", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const res = await postJson(
      port,
      "/",
      validRpcBody,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, validRpcHeaders, { "mcp-name": "not_the_real_tool" })
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, -32020);
  } finally {
    server.close();
  }
});

test("tools/list does not require an Mcp-Name header (only tools/call does)", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const body = {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/list",
      params: { _meta: validRpcBody.params._meta },
    };
    const res = await postJson(
      port,
      "/",
      body,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, { "mcp-protocol-version": STATELESS_PROTOCOL_VERSION, "mcp-method": "tools/list" })
    );
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.result.tools[0].name, TOOL_NAME);
  } finally {
    server.close();
  }
});

/* --- Real HTTP status codes reflecting JSON-RPC error vs success. --- */

test("an unknown method returns HTTP 404 (spec: unimplemented method -> 404, not 200)", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const body = { jsonrpc: "2.0", id: 10, method: "resources/subscribe", params: {} };
    const res = await postJson(
      port,
      "/",
      body,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, { "mcp-protocol-version": STATELESS_PROTOCOL_VERSION, "mcp-method": "resources/subscribe" })
    );
    assert.equal(res.statusCode, 404);
    assert.equal(res.body.error.code, -32601);
  } finally {
    server.close();
  }
});

test("an unsupported protocol version returns HTTP 400 with a supported/requested data payload, not 200", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const body = {
      jsonrpc: "2.0",
      id: 11,
      method: "server/discover",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "1999-01-01",
          "io.modelcontextprotocol/clientInfo": { name: "c", version: "1" },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    };
    const res = await postJson(
      port,
      "/",
      body,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, { "mcp-protocol-version": "1999-01-01", "mcp-method": "server/discover" })
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, -32022);
    assert.deepEqual(res.body.error.data.supported.sort(), [STATELESS_PROTOCOL_VERSION, "2025-06-18"].sort());
    assert.equal(res.body.error.data.requested, "1999-01-01");
  } finally {
    server.close();
  }
});

test("a successful tools/call result carries resultType 'complete' and cacheable tools/list carries ttlMs/cacheScope", async () => {
  const server = await startServer(TEST_TOKEN);
  try {
    const { port } = server.address();
    const callRes = await postJson(
      port,
      "/",
      validRpcBody,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, validRpcHeaders)
    );
    assert.equal(callRes.body.result.resultType, "complete");

    const listBody = { jsonrpc: "2.0", id: 12, method: "tools/list", params: { _meta: validRpcBody.params._meta } };
    const listRes = await postJson(
      port,
      "/",
      listBody,
      Object.assign({ authorization: `Bearer ${TEST_TOKEN}` }, { "mcp-protocol-version": STATELESS_PROTOCOL_VERSION, "mcp-method": "tools/list" })
    );
    assert.equal(listRes.body.result.resultType, "complete");
    assert.equal(typeof listRes.body.result.ttlMs, "number");
    assert.equal(listRes.body.result.cacheScope, "public");
  } finally {
    server.close();
  }
});
