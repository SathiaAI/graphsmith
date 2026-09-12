#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/downstream.js's own transport-level behavior
 * (connectStdio/connectHttp/connectAllDownstreams) -- as opposed to
 * tests/gateway/proxy/run-tests.js, which fakes this layer out entirely to isolate
 * dispatch/correlation logic, and tests/gateway/e2e/run-tests.js, which drives the whole
 * gateway process end to end. This suite sits in between: real child processes / a real
 * HTTP server, but talking to downstream.js's exported functions directly rather than
 * through gateway.js. Added for Codex PR #29 review round 3's downstream.js findings
 * (see each test's own header comment for the specific finding it covers).
 */

const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const downstream = require(path.join(ROOT, "scripts", "gateway", "downstream.js"));
const FIXTURE_SERVER = path.join(__dirname, "..", "_fixtures", "fixture-mcp-server.js");

let failures = 0;
const results = [];
function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}
function check(name, cond, reason) {
  record(name, cond ? "PASS" : "FAIL", reason);
}

function freshDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-downstream-${prefix}-`));
}

/** Codex PR #29 review round 3 "store server information without prototype-sensitive
 * keys": a downstream configured with the name "__proto__" must be recorded as a genuine
 * own property of serverInfos, not silently reroute into Object.prototype. Uses the real
 * fixture (not a fake) so this exercises connectAllDownstreams' actual initialize
 * handshake end to end, matching this file's own "real transport" scope. */
async function prototypePollutingServerNameIsStoredSafely() {
  const serverConfig = { name: "__proto__", transport: "stdio", endpoint: `node ${FIXTURE_SERVER} --server-name __proto__` };
  const handles = await downstream.connectAllDownstreams([serverConfig]);
  try {
    check(
      "prototype-polluting-server-name-stored-as-own-property",
      Object.prototype.hasOwnProperty.call(handles.serverInfos, "__proto__") &&
        handles.serverInfos["__proto__"] &&
        handles.serverInfos["__proto__"].name === "__proto__",
      JSON.stringify(handles.serverInfos["__proto__"])
    );
    check(
      "prototype-polluting-server-name-does-not-corrupt-object-prototype",
      Object.getPrototypeOf({}) === Object.prototype,
      String(Object.getPrototypeOf({}))
    );
  } finally {
    for (const conn of handles.connections.values()) conn.close();
  }
}

/** Codex PR #29 review round 3 "require the tools array in every tools/list result": a
 * downstream whose tools/list result omits "tools" entirely (not merely the wrong type)
 * must fail startup rather than silently be treated as an empty tool surface. */
async function malformedToolsListMissingArrayRejected() {
  const dir = freshDir("bad-tools-list");
  const fixturePath = path.join(dir, "bad-tools-list-fixture.js");
  fs.writeFileSync(
    fixturePath,
    `
    "use strict";
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
    rl.on("line", (line) => {
      let msg; try { msg = JSON.parse(line); } catch (e) { return; }
      if (msg.method === "initialize") { send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "bad", version: "1.0" } } }); return; }
      if (msg.method === "tools/list") { send({ jsonrpc: "2.0", id: msg.id, result: {} }); return; } // no "tools" at all
    });
    `
  );
  const serverConfig = { name: "bad", transport: "stdio", endpoint: `node ${fixturePath}` };
  let threw = null;
  try {
    await downstream.connectAllDownstreams([serverConfig]);
  } catch (error) {
    threw = error;
  }
  check(
    "malformed-tools-list-missing-tools-array-rejected",
    Boolean(threw && threw.code === "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"),
    threw && threw.message
  );
}

/** Codex PR #29 review round 3 "require a result or error in HTTP responses": a
 * downstream HTTP response carrying the right jsonrpc/id but neither "result" nor
 * "error" (or, symmetrically, both) must fail closed instead of resolving `undefined` as
 * a false success. */
async function httpResponseRequiresExactlyOneOfResultOrError() {
  const responses = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const next = responses.shift();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(typeof next === "function" ? next(body.id) : next));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const conn = downstream.connectHttp(`http://127.0.0.1:${port}/`);
  try {
    responses.push((id) => ({ jsonrpc: "2.0", id })); // neither result nor error
    let threwNeither = null;
    try { await conn.call("tools/list", {}, 2000); } catch (error) { threwNeither = error; }
    check("http-response-with-neither-result-nor-error-rejected", Boolean(threwNeither && threwNeither.code === "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"), threwNeither && threwNeither.message);

    responses.push((id) => ({ jsonrpc: "2.0", id, result: { ok: true }, error: { code: -32000, message: "also an error" } })); // both
    let threwBoth = null;
    try { await conn.call("tools/list", {}, 2000); } catch (error) { threwBoth = error; }
    check("http-response-with-both-result-and-error-rejected", Boolean(threwBoth && threwBoth.code === "GATEWAY_DOWNSTREAM_MALFORMED_RESPONSE"), threwBoth && threwBoth.message);

    responses.push((id) => ({ jsonrpc: "2.0", id, result: { ok: true } })); // sanity: well-formed still resolves
    const ok = await conn.call("tools/list", {}, 2000);
    check("http-response-with-only-result-still-resolves", ok && ok.ok === true, JSON.stringify(ok));
  } finally {
    conn.close();
    await new Promise((resolve) => server.close(resolve));
  }
}

/** Codex PR #29 review round 3 "bound newline-delimited responses from stdio
 * downstreams": a downstream that writes a large, unterminated line must not be allowed
 * to buffer unboundedly in the gateway -- the connection should force-close once a single
 * unterminated line exceeds the shared MAX_HTTP_RESPONSE_BYTES-sized cap, rather than let
 * memory grow without limit. */
async function unboundedUnterminatedLineForcesClose() {
  const dir = freshDir("unbounded-line");
  const fixturePath = path.join(dir, "unbounded-line-fixture.js");
  fs.writeFileSync(
    fixturePath,
    `
    "use strict";
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
    rl.on("line", (line) => {
      let msg; try { msg = JSON.parse(line); } catch (e) { return; }
      if (msg.method === "initialize") {
        send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "bad", version: "1.0" } } });
        // Immediately after replying, start writing an unterminated line that never
        // stops -- large chunks, no trailing newline.
        const chunk = "x".repeat(1024 * 1024);
        const timer = setInterval(() => process.stdout.write(chunk), 5);
        setTimeout(() => { clearInterval(timer); process.exit(0); }, 5000).unref();
      }
    });
    `
  );
  const conn = downstream.connectStdio(`node ${fixturePath}`);
  try {
    await conn.call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } });
    const closedWithin = await Promise.race([
      conn.whenClosed().then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 4000)),
    ]);
    check("unbounded-unterminated-line-force-closes-connection", closedWithin === true, "connection did not self-close within 4s");
  } finally {
    conn.close();
  }
}

/** CodeRabbit PR #29 review round 4 "track only the bytes after the last newline": a
 * single chunk containing several COMPLETE, well-formed, newline-terminated lines whose
 * combined length exceeds MAX_HTTP_RESPONSE_BYTES must NOT force-close the connection --
 * only a genuinely unterminated line that itself exceeds the cap should. Before the fix,
 * readline's own "data" listener (registered first) consumed and reset the byte counter
 * for each line, and then this listener still added the WHOLE chunk's length on top,
 * misreporting bounded, healthy traffic as a single oversized unterminated line. */
async function completeLinesBatchedInOneChunkDoNotForceClose() {
  const dir = freshDir("batched-lines");
  const fixturePath = path.join(dir, "batched-lines-fixture.js");
  fs.writeFileSync(
    fixturePath,
    `
    "use strict";
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
    rl.on("line", (line) => {
      let msg; try { msg = JSON.parse(line); } catch (e) { return; }
      if (msg.method === "initialize") {
        send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "batch", version: "1.0" } } });
        return;
      }
      if (msg.method === "tools/list") {
        // Write several complete, newline-terminated, oversized-when-combined lines in
        // ONE process.stdout.write() call -- i.e. one "data" event downstream.js's side.
        const big = "x".repeat(4 * 1024 * 1024); // 4MiB per padded line, 3 lines = 12MiB > 10MiB cap
        const lines = [0, 1, 2].map((i) => JSON.stringify({ jsonrpc: "2.0", id: "extra-" + i, unexpected: big }));
        process.stdout.write(lines.join("\\n") + "\\n");
        send({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } });
        return;
      }
    });
    `
  );
  const conn = downstream.connectStdio(`node ${fixturePath}`);
  try {
    await conn.call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } });
    const toolsResult = await conn.call("tools/list", {}, 4000);
    check("complete-lines-batched-in-one-chunk-do-not-force-close", Array.isArray(toolsResult && toolsResult.tools), JSON.stringify(toolsResult));
  } finally {
    conn.close();
  }
}

/** CodeRabbit PR #29 review round 4 "make this regression test deterministic":
 * completeLinesBatchedInOneChunkDoNotForceClose above drives the fix indirectly through
 * a real child process's stdout, relying on a single process.stdout.write() call
 * arriving as one "data" chunk on this side -- but the OS pipe is free to (and on Linux
 * typically does, with its ~64KB default pipe buffer) split that into many smaller
 * chunks regardless, so that test could pass against the OLD buggy logic too without
 * ever actually exercising the multiple-complete-lines-in-one-chunk case it claims to
 * cover. This test instead drives downstream.js's own exported, pure
 * nextResidualLineBytes helper directly with explicit in-memory Buffers -- no child
 * process or OS pipe chunking involved, so it deterministically reproduces (and would
 * fail against) the exact old bug: several complete, individually-under-the-cap lines
 * combined into one chunk whose SUM exceeds MAX_HTTP_RESPONSE_BYTES. */
function residualLineBytesHelperIsDeterministic() {
  const MAX = downstream.MAX_HTTP_RESPONSE_BYTES;

  // Three complete, newline-terminated lines combined into ONE chunk, each individually
  // well under the cap but whose sum exceeds it.
  const perLine = Math.floor(MAX / 3) + 1000;
  const line = "x".repeat(perLine);
  const oneChunk = Buffer.from([line, line, line].join("\n") + "\n", "utf8");
  check("residual-line-bytes-setup-batched-chunk-exceeds-cap-if-misreported", oneChunk.length > MAX, String(oneChunk.length));
  const afterBatchedChunk = downstream.nextResidualLineBytes(0, oneChunk);
  check(
    "residual-line-bytes-batched-complete-lines-in-one-chunk-resets-to-zero-not-the-whole-chunk",
    afterBatchedChunk === 0,
    String(afterBatchedChunk)
  );

  // A genuinely unterminated chunk (no newline at all) extends the residual by its full
  // length, and that residual carries forward correctly across successive chunks.
  const afterFirstPartial = downstream.nextResidualLineBytes(0, Buffer.from("x".repeat(100), "utf8"));
  check("residual-line-bytes-no-newline-chunk-extends-residual", afterFirstPartial === 100, String(afterFirstPartial));
  const afterSecondPartial = downstream.nextResidualLineBytes(afterFirstPartial, Buffer.from("y".repeat(50), "utf8"));
  check("residual-line-bytes-residual-carries-forward-across-chunks", afterSecondPartial === 150, String(afterSecondPartial));

  // A chunk containing a newline followed by trailing unterminated bytes resets to just
  // those trailing bytes, discarding whatever residual had built up before the newline.
  const afterNewlineThenTrailing = downstream.nextResidualLineBytes(999999, Buffer.from("z".repeat(10) + "\n" + "w".repeat(7), "utf8"));
  check(
    "residual-line-bytes-newline-then-trailing-bytes-resets-to-trailing-length",
    afterNewlineThenTrailing === 7,
    String(afterNewlineThenTrailing)
  );
}

/** Codex PR #29 review round 4 "advertise sampling before accepting sampling requests":
 * connectAllDownstreams must declare the MCP `sampling` client capability during
 * initialize when the caller says the agent transport can relay it, and must NOT declare
 * it otherwise -- a conforming downstream only sends sampling/createMessage to a client
 * that has actually negotiated support for it. */
async function samplingCapabilityAdvertisedOnlyWhenSupported() {
  const dir = freshDir("sampling-capability");
  const fixturePath = path.join(dir, "capture-init-fixture.js");
  const capturePath = path.join(dir, "captured-init.json");
  fs.writeFileSync(
    fixturePath,
    `
    "use strict";
    const fs = require("fs");
    const readline = require("readline");
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
    rl.on("line", (line) => {
      let msg; try { msg = JSON.parse(line); } catch (e) { return; }
      if (msg.method === "initialize") {
        fs.writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify(msg.params));
        send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "cap", version: "1.0" } } });
        return;
      }
      if (msg.method === "tools/list") { send({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } }); return; }
    });
    `
  );
  const serverConfig = { name: "cap", transport: "stdio", endpoint: `node ${fixturePath}` };

  const withSampling = await downstream.connectAllDownstreams([serverConfig], { supportsSampling: true });
  const capturedWith = JSON.parse(fs.readFileSync(capturePath, "utf8"));
  for (const conn of withSampling.connections.values()) conn.close();
  check(
    "sampling-capability-advertised-when-supported",
    Boolean(capturedWith.capabilities && capturedWith.capabilities.sampling && typeof capturedWith.capabilities.sampling === "object"),
    JSON.stringify(capturedWith.capabilities)
  );

  const withoutSampling = await downstream.connectAllDownstreams([serverConfig], { supportsSampling: false });
  const capturedWithout = JSON.parse(fs.readFileSync(capturePath, "utf8"));
  for (const conn of withoutSampling.connections.values()) conn.close();
  check(
    "sampling-capability-omitted-when-not-supported",
    Boolean(capturedWithout.capabilities) && !("sampling" in capturedWithout.capabilities),
    JSON.stringify(capturedWithout.capabilities)
  );
}

/** Codex PR #29 review round 4 "preserve the originating server for sampling": with
 * multiple stdio downstreams sharing one `onRequest` callback, connectAllDownstreams must
 * bind each connection's OWN configured server name into its own callback invocation --
 * not have every downstream's unsolicited request reach onRequest indistinguishably. */
async function onRequestReceivesOwnServerName() {
  const dir = freshDir("onrequest-server-name");
  function writeSamplerFixture(name) {
    const fixturePath = path.join(dir, `${name}-fixture.js`);
    fs.writeFileSync(
      fixturePath,
      `
      "use strict";
      const readline = require("readline");
      const rl = readline.createInterface({ input: process.stdin, terminal: false });
      function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
      rl.on("line", (line) => {
        let msg; try { msg = JSON.parse(line); } catch (e) { return; }
        if (typeof msg.method !== "string" && msg.id === "upstream-1") { return; } // reply to our own request, ignored here
        if (msg.method === "initialize") { send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: ${JSON.stringify(name)}, version: "1.0" } } }); return; }
        if (msg.method === "tools/list") {
          send({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } });
          // Immediately after the handshake, fire our own unsolicited request upstream.
          send({ jsonrpc: "2.0", id: "upstream-1", method: "sampling/createMessage", params: {} });
          return;
        }
      });
      `
    );
    return fixturePath;
  }
  const fixtureA = writeSamplerFixture("server-a");
  const fixtureB = writeSamplerFixture("server-b");
  const seenServerNames = [];
  const handles = await downstream.connectAllDownstreams(
    [
      { name: "server-a", transport: "stdio", endpoint: `node ${fixtureA}` },
      { name: "server-b", transport: "stdio", endpoint: `node ${fixtureB}` },
    ],
    {
      supportsSampling: true,
      onRequest: (msg, serverName) => { seenServerNames.push(serverName); return Promise.resolve(null); },
    }
  );
  try {
    await new Promise((resolve) => setTimeout(resolve, 500)); // let both fixtures' unsolicited requests arrive
    check(
      "onrequest-receives-each-connections-own-server-name",
      seenServerNames.includes("server-a") && seenServerNames.includes("server-b") && seenServerNames.length === 2,
      JSON.stringify(seenServerNames)
    );
  } finally {
    for (const conn of handles.connections.values()) conn.close();
  }
}

async function main() {
  await prototypePollutingServerNameIsStoredSafely();
  await malformedToolsListMissingArrayRejected();
  await httpResponseRequiresExactlyOneOfResultOrError();
  await unboundedUnterminatedLineForcesClose();
  await completeLinesBatchedInOneChunkDoNotForceClose();
  residualLineBytesHelperIsDeterministic();
  await samplingCapabilityAdvertisedOnlyWhenSupported();
  await onRequestReceivesOwnServerName();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
