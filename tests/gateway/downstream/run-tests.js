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

async function main() {
  await prototypePollutingServerNameIsStoredSafely();
  await malformedToolsListMissingArrayRejected();
  await httpResponseRequiresExactlyOneOfResultOrError();
  await unboundedUnterminatedLineForcesClose();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
