#!/usr/bin/env node
"use strict";

/* End-to-end integration suite: spawns the REAL gateway CLI (scripts/gateway/gateway.js)
 * as a child process, talking to a REAL, separate downstream fixture process
 * (tests/gateway/_fixtures/fixture-mcp-server.js) over real stdio pipes -- not
 * unit-level fakes. Proves the whole pipeline SG-FR-1 through SG-FR-5/SG-FR-7 actually
 * works end to end, matching the Standalone Gateway TRD's SS8 test plan:
 *   1  single agent, single downstream, one tool call, clean disconnect -> exactly one
 *      bundle written, verifies under gsa-verify.js, matches the session's actual calls.
 *   5  clean shutdown (SIGTERM) with a session in flight -> drains and finalizes before
 *      exit, claim released, process exits 0. SKIPPED ON WIN32: Node cannot deliver a
 *      real SIGTERM for graceful in-process handling on Windows (child.kill('SIGTERM')
 *      unconditionally terminates the process there) -- mirrors this repo's own existing
 *     precedent (tests/state-store/writer-claim, "skip win32-unreproducible renew()
 *     TOCTOU simulation") of naming and skipping a platform-unreproducible case rather
 *     than writing a test that cannot mean what it claims to mean.
 *   6  second gateway instance started against the same state_dir while the first is
 *      running -> FR-1 refusal, named identity in the error.
 *   15 mode configured as attach but the standalone binary is started anyway -> logs
 *      dormant, exits 0, binds no port, holds no claim.
 */

const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const readline = require("readline");

const ROOT = path.resolve(__dirname, "../../..");
const GATEWAY_CLI = path.join(ROOT, "scripts", "gateway", "gateway.js");
const FIXTURE_SERVER = path.join(__dirname, "..", "_fixtures", "fixture-mcp-server.js");
const { writeConfirmedMode } = require("../_fixtures/mode-file.js");
const { walkGatewaySessions } = require(path.join(ROOT, "checks", "register-gateway-sessions.js"));
const chain = require(path.join(ROOT, "scripts", "gateway", "chain.js"));
const { verifyBundle } = require(path.join(ROOT, "scripts", "gsa-verify.js"));

let failures = 0;
const results = [];
function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : status === "SKIP" ? `SKIP ${name}${reason ? " (" + reason + ")" : ""}` : `FAIL ${name}+${reason || "unknown"}`);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}
function check(name, cond, reason) {
  record(name, cond ? "PASS" : "FAIL", reason);
}
function skip(name, reason) {
  record(name, "SKIP", reason);
}

function freshRoot(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-e2e-${prefix}-`));
}

function writeSigningKey(root) {
  const kp = crypto.generateKeyPairSync("ed25519");
  const pem = kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, pem);
  const publicPem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  return { keyPath, publicPem, signer: "graphsmith-standalone-gateway" };
}

function writeGatewayConfig(root, options = {}) {
  const stateDir = path.join(root, "state");
  const { keyPath } = writeSigningKey(root);
  const config = {
    schema_version: "1.0",
    state_dir: stateDir,
    downstream_servers: [{ name: "fixture", transport: "stdio", endpoint: `node ${FIXTURE_SERVER} --server-name fixture` }],
    signing_key_ref: keyPath,
    ...options,
  };
  const configPath = path.join(root, "gateway-config.json");
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  return { configPath, stateDir };
}

/** Spawns the real gateway CLI against `configPath`, cwd=`root` (so it reads
 * <root>/.graphsmith/gateway-mode.json per SS3.8). Returns a small driver object. */
function spawnGateway(root, configPath) {
  const child = spawn(process.execPath, [GATEWAY_CLI, configPath], { cwd: root, stdio: ["pipe", "pipe", "pipe"] });
  const rl = readline.createInterface({ input: child.stdout, terminal: false });
  const lineQueue = [];
  const waiters = [];
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try { msg = JSON.parse(trimmed); } catch (error) { return; }
    if (waiters.length > 0) waiters.shift()(msg);
    else lineQueue.push(msg);
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });

  function nextMessage(timeoutMs = 10000) {
    if (lineQueue.length > 0) return Promise.resolve(lineQueue.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timed out waiting for a gateway response (stderr so far: ${stderr})`)), timeoutMs);
      waiters.push((msg) => { clearTimeout(timer); resolve(msg); });
    });
  }
  function send(msg) {
    child.stdin.write(JSON.stringify(msg) + "\n");
  }
  function exitCode() {
    return new Promise((resolve) => child.on("close", (code) => resolve(code)));
  }
  return { child, send, nextMessage, exitCode, stderr: () => stderr };
}

async function singleSessionEndToEndVerifies() {
  const root = freshRoot("happy");
  writeConfirmedMode(root, "standalone");
  const { configPath, stateDir } = writeGatewayConfig(root);
  const gw = spawnGateway(root, configPath);

  gw.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "test-agent", version: "1.0" } } });
  const initResp = await gw.nextMessage();
  check("e2e-initialize-responds", initResp && initResp.result && initResp.result.serverInfo, JSON.stringify(initResp));

  gw.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const toolsResp = await gw.nextMessage();
  const toolNames = toolsResp && toolsResp.result && toolsResp.result.tools.map((t) => t.name);
  check("e2e-tools-list-includes-fixture-tools", Array.isArray(toolNames) && toolNames.includes("fixture_echo"), JSON.stringify(toolsResp));

  gw.send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "fixture_echo", arguments: { hello: "world" } } });
  const callResp = await gw.nextMessage();
  check("e2e-tool-call-round-trips-through-real-downstream", callResp && callResp.result && /hello/.test(JSON.stringify(callResp.result)), JSON.stringify(callResp));

  gw.child.stdin.end(); // clean agent disconnect -> finalize + persist + graceful exit
  const code = await gw.exitCode();
  check("e2e-clean-disconnect-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);

  const head = chain.readHead(stateDir);
  check("e2e-exactly-one-bundle-written", head && head.seq === 1, JSON.stringify(head));
  const bundleFile = chain.bundlePath(stateDir, head.bundle_id);
  check("e2e-bundle-file-exists", fs.existsSync(bundleFile), bundleFile);
  const bundle = JSON.parse(fs.readFileSync(bundleFile, "utf8"));

  const kp = crypto.createPublicKey(fs.readFileSync(path.join(root, "signing-key.pem"), "utf8"));
  const publicPem = kp.export({ type: "spki", format: "pem" }).toString();
  const verified = verifyBundle(bundle, { trustedKeys: { "graphsmith-standalone-gateway": publicPem } });
  check("e2e-bundle-verifies-under-gsa-verify", verified.status === "PASS", JSON.stringify(verified));

  const traceStr = bundle.contents["execution_trace.jsonl"];
  check("e2e-bundle-matches-the-actual-tool-call-made", /"tool":"fixture:fixture_echo"/.test(traceStr), traceStr);

  const chainResult = walkGatewaySessions({
    chain: chain.readChain(stateDir),
    head: chain.readHead(stateDir),
    computeEntrySha256: chain.computeEntrySha256,
    bundleExists: (id) => fs.existsSync(chain.bundlePath(stateDir, id)),
  });
  check("e2e-chain-verifies", chainResult.status === "verified", JSON.stringify(chainResult));
}

/** Waits for the HTTP agent listener's port announcement on stderr (rather than a
 * fixed sleep -- matches this suite's own established "signal, not sleep" discipline,
 * see cleanSigtermDrainsAndExitsZero's comment). */
function waitForHttpPort(gw, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const poll = () => {
      const match = /agent-facing HTTP listener on port (\d+)/.exec(gw.stderr());
      if (match) {
        resolve(Number(match[1]));
        return;
      }
      if (Date.now() > deadline) {
        reject(new Error(`timed out waiting for the HTTP listener's port announcement (stderr so far: ${gw.stderr()})`));
        return;
      }
      setTimeout(poll, 25);
    };
    poll();
  });
}

/** Posts one JSON-RPC message to the agent-facing HTTP listener. `sessionId`, when
 * given, is echoed on the `Mcp-Session-Id` request header (board decision 2026-09-08:
 * sessions are identified by this explicit header, not by TCP socket identity -- see
 * scripts/gateway/agent-transport.js#runHttpAgentTransport's own header comment).
 * Resolves `{ body, headers }` (not just the parsed body) so callers can read the
 * session ID the server minted/echoed back. */
function httpPost(port, token, body, agent, sessionId) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const headers = { "content-type": "application/json", "content-length": Buffer.byteLength(payload), authorization: `Bearer ${token}` };
    if (sessionId) headers["mcp-session-id"] = sessionId;
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", agent, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve({ body: JSON.parse(Buffer.concat(chunks).toString("utf8")), headers: res.headers });
          } catch (error) {
            reject(new Error(`HTTP response was not valid JSON: ${error.message}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.end(payload);
  });
}

/** Board decision 2026-09-04 (PR #29 review, Decision 1, Option B): a downstream
 * server's own unsolicited "sampling/createMessage" request is forwarded to the agent
 * ONLY when the agent transport is stdio (the only one that can push a request rather
 * than merely reply to one). Proves the fixture's own upstream request round-trips
 * through the real gateway process to a real stdio agent and back. */
async function samplingForwardedToStdioAgent() {
  const root = freshRoot("sampling-stdio");
  writeConfirmedMode(root, "standalone");
  const { configPath, stateDir } = writeGatewayConfig(root);
  const gw = spawnGateway(root, configPath);

  gw.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "test-agent", version: "1.0" } } });
  await gw.nextMessage();

  gw.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fixture_sample", arguments: { prompt: "hello from downstream" } } });

  const pushed = await gw.nextMessage();
  check(
    "e2e-sampling-forwarded-to-stdio-agent",
    pushed && pushed.method === "sampling/createMessage" && pushed.id !== undefined && pushed.id !== null && !("result" in pushed) && !("error" in pushed),
    JSON.stringify(pushed)
  );

  gw.send({ jsonrpc: "2.0", id: pushed && pushed.id, result: { role: "assistant", content: { type: "text", text: "mocked model output" } } });

  const toolResp = await gw.nextMessage();
  check(
    "e2e-sampling-tool-call-resolves-with-forwarded-agent-result",
    toolResp && toolResp.id === 2 && toolResp.result && /mocked model output/.test(JSON.stringify(toolResp.result)),
    JSON.stringify(toolResp)
  );

  gw.child.stdin.end();
  const code = await gw.exitCode();
  check("e2e-sampling-stdio-clean-disconnect-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);

  /* Codex PR #29 review "record downstream-initiated sampling in the session": before
   * that fix, this forwarded exchange never touched session.js at all, so the sealed
   * bundle attested only the outer fixture_sample tool call -- the model invocation
   * itself (and its hashed prompt/result) was silently absent even though the gateway
   * observed and relayed it. Assert it now actually lands in the persisted trace with
   * model_call:true, not just that the tool call round-tripped in-memory.
   *
   * The recorded id is "fixture:sampling/createMessage" (the real downstream server's
   * configured name, not a placeholder) per Codex PR #29 review round 4 "preserve the
   * originating server for sampling" -- writeGatewayConfig's single downstream is named
   * "fixture". */
  const head = chain.readHead(stateDir);
  const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(stateDir, head.bundle_id), "utf8"));
  const traceLines = bundle.contents["execution_trace.jsonl"].trim().split("\n").map((l) => JSON.parse(l));
  const sampleStep = traceLines.find((t) => t.tool === "fixture:sampling/createMessage");
  check(
    "e2e-sampling-recorded-as-model-call-in-sealed-bundle",
    // execution_trace.jsonl records only hashes of input/result (SS5.2), never plaintext
    // -- assert the step exists, is attributed as a real model call, and is not an error.
    sampleStep && sampleStep.model_call === true && sampleStep.is_error === false && typeof sampleStep.result_sha256 === "string" && sampleStep.result_sha256.length > 0,
    traceLines.map((t) => JSON.stringify(t)).join("\n")
  );
}

/** Codex PR #29 review round 3 "validate agent replies to pushed sampling requests":
 * a reply to a gateway-pushed request that is missing "jsonrpc": "2.0" and carries
 * neither "result" nor "error" must be rejected as malformed, not resolved as a
 * successful `undefined` sampling result and forwarded to the downstream as success. */
async function malformedPushedReplyIsRejectedNotSilentlyAccepted() {
  const root = freshRoot("sampling-malformed-reply");
  writeConfirmedMode(root, "standalone");
  const { configPath } = writeGatewayConfig(root);
  const gw = spawnGateway(root, configPath);

  gw.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "test-agent", version: "1.0" } } });
  await gw.nextMessage();

  gw.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fixture_sample", arguments: { prompt: "hello from downstream" } } });

  const pushed = await gw.nextMessage();
  check(
    "e2e-malformed-reply-setup-sampling-request-pushed",
    Boolean(pushed && pushed.method === "sampling/createMessage" && pushed.id !== undefined && pushed.id !== null),
    JSON.stringify(pushed)
  );

  // Malformed reply: right id, no "jsonrpc", and neither "result" nor "error".
  gw.send({ id: pushed && pushed.id });

  const toolResp = await gw.nextMessage();
  check(
    "e2e-malformed-pushed-reply-surfaces-as-tool-call-error-not-fake-success",
    Boolean(toolResp && toolResp.id === 2 && toolResp.error && typeof toolResp.error.message === "string" && !/mocked/.test(JSON.stringify(toolResp))),
    JSON.stringify(toolResp)
  );

  gw.child.stdin.end();
  const code = await gw.exitCode();
  check("e2e-malformed-pushed-reply-clean-disconnect-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);
}

/** CodeRabbit PR #29 review round 4 "a reply with a present but falsy error resolves as
 * a successful undefined result": a pushed-reply of the well-formed SHAPE
 * {"jsonrpc":"2.0","id":..., "error":null} passes the exactly-one-of-result-or-error
 * check (it HAS an "error" key), but branching on msg.error's truthiness afterward
 * treated it as "no error" and resolved undefined as a fake success -- silently turning
 * an agent-signaled failure into a tool call that looks like it succeeded. */
async function pushedReplyWithPresentButFalsyErrorIsRejected() {
  const root = freshRoot("sampling-falsy-error-reply");
  writeConfirmedMode(root, "standalone");
  const { configPath } = writeGatewayConfig(root);
  const gw = spawnGateway(root, configPath);

  gw.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "test-agent", version: "1.0" } } });
  await gw.nextMessage();

  gw.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fixture_sample", arguments: { prompt: "hello from downstream" } } });

  const pushed = await gw.nextMessage();
  check(
    "e2e-falsy-error-reply-setup-sampling-request-pushed",
    Boolean(pushed && pushed.method === "sampling/createMessage" && pushed.id !== undefined && pushed.id !== null),
    JSON.stringify(pushed)
  );

  // Well-formed per the "exactly one of result/error PRESENT" check -- "error" is a real
  // own key -- but its VALUE is falsy (null). Must still be treated as an error reply.
  gw.send({ jsonrpc: "2.0", id: pushed && pushed.id, error: null });

  const toolResp = await gw.nextMessage();
  check(
    "e2e-falsy-error-reply-surfaces-as-tool-call-error-not-fake-success",
    Boolean(toolResp && toolResp.id === 2 && toolResp.error && typeof toolResp.error.message === "string" && !/"sampled"/.test(JSON.stringify(toolResp))),
    JSON.stringify(toolResp)
  );

  gw.child.stdin.end();
  const code = await gw.exitCode();
  check("e2e-falsy-error-reply-clean-disconnect-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);
}

/** Board decision 2026-09-04 (PR #29 review, Decision 1, Option B): when the agent
 * transport is HTTP, a downstream's sampling request must get back a real JSON-RPC
 * error naming why -- never the silent drop this was before the fix, and never a hang. */
async function samplingOverHttpAgentGetsExplicitError() {
  const root = freshRoot("sampling-http");
  writeConfirmedMode(root, "standalone");
  const tokenPath = path.join(root, "agent-token.txt");
  fs.writeFileSync(tokenPath, "a-fake-but-long-enough-bearer-token-value");
  const { configPath } = writeGatewayConfig(root, { agent_listen: { transport: "http", token_ref: tokenPath } });
  const gw = spawnGateway(root, configPath);

  const port = await waitForHttpPort(gw);
  const token = fs.readFileSync(tokenPath, "utf8").trim();

  /* Session identity on the agent-facing HTTP transport is an explicit, server-minted
   * `Mcp-Session-Id` (board decision 2026-09-08) -- NOT TCP socket identity, so this
   * test deliberately does NOT rely on connection/keep-alive reuse to make these two
   * requests share one logical session (that dependency is exactly what the prior
   * design got wrong: it made this test's outcome depend on http.globalAgent's
   * keepAlive default, which differs across Node versions). No `agent` option is
   * passed at all -- each request may or may not reuse a socket; either way, the
   * session ID captured from `initialize`'s response header is what ties them
   * together. */
  const initResp = await httpPost(port, token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "test-agent-http", version: "1.0" } } });
  check("e2e-sampling-http-initialize-responds", initResp.body && initResp.body.result, JSON.stringify(initResp.body));
  const sessionId = initResp.headers["mcp-session-id"];
  check("e2e-sampling-http-initialize-returns-session-id", typeof sessionId === "string" && sessionId.length > 0, JSON.stringify(initResp.headers));

  const callResp = await httpPost(port, token, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fixture_sample", arguments: { prompt: "hi" } } }, undefined, sessionId);
  check(
    "e2e-sampling-over-http-agent-gets-explicit-error-not-silence",
    callResp.body && callResp.body.id === 2 && callResp.body.error && /stdio/i.test(callResp.body.error.message),
    JSON.stringify(callResp.body)
  );

  gw.child.kill();
  await gw.exitCode();
}

/** Board decision 2026-09-04, PR #29 review "send stateless metadata to HTTP
 * downstreams": the fixture used by every other test in this suite is permissive and
 * never exercised the real, stricter contract this repo's OWN in-repo MCP HTTP server
 * enforces (mcp-server/src/server.js's validateMeta: every tools/list and tools/call
 * over HTTP needs a fresh, complete _meta block, since connectionState is per-request
 * and never remembers an earlier `initialize`). Runs the real mcp-server HTTP transport
 * as the gateway's configured downstream and proves the full handshake, tools/list, and
 * tools/call all succeed against it -- not just against the lenient fixture. */
async function httpDownstreamAgainstRealMcpServerSucceeds() {
  const root = freshRoot("http-downstream-real-server");
  writeConfirmedMode(root, "standalone");
  const { createHttpServer } = require(path.join(ROOT, "mcp-server", "src", "httpTransport.js"));
  const downstreamToken = "a-fake-but-long-enough-downstream-bearer-token";
  const downstreamServer = createHttpServer({ token: downstreamToken });
  await new Promise((resolve) => downstreamServer.listen(0, resolve));
  const downstreamPort = downstreamServer.address().port;
  const downstreamTokenPath = path.join(root, "downstream-token.txt");
  fs.writeFileSync(downstreamTokenPath, downstreamToken);

  const { configPath } = writeGatewayConfig(root, {
    downstream_servers: [{ name: "real-mcp", transport: "http", endpoint: `http://127.0.0.1:${downstreamPort}`, token_ref: downstreamTokenPath }],
  });
  const gw = spawnGateway(root, configPath);

  gw.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "test-agent", version: "1.0" } } });
  const initResp = await gw.nextMessage();
  check("e2e-http-downstream-initialize-responds", initResp && initResp.result, JSON.stringify(initResp));

  gw.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const toolsResp = await gw.nextMessage();
  const toolNames = toolsResp && toolsResp.result && Array.isArray(toolsResp.result.tools) && toolsResp.result.tools.map((t) => t.name);
  check(
    "e2e-http-downstream-tools-list-succeeds-against-real-mcp-server",
    Array.isArray(toolNames) && toolNames.includes("graphsmith_guidance"),
    JSON.stringify(toolsResp)
  );

  gw.send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "graphsmith_guidance", arguments: {} } });
  const callResp = await gw.nextMessage();
  check("e2e-http-downstream-tools-call-succeeds-against-real-mcp-server", callResp && callResp.result && !callResp.error, JSON.stringify(callResp));

  gw.child.stdin.end();
  await gw.exitCode();
  await new Promise((resolve) => downstreamServer.close(resolve));
}

/** Board decision 2026-09-04, PR #29 review "reject non-POST requests on the agent HTTP
 * listener": a GET carrying a JSON-RPC body must be refused with 405 before
 * authentication or dispatch, mirroring mcp-server/src/httpTransport.js's own contract
 * for its listener. */
async function agentHttpListenerRejectsNonPostMethod() {
  const root = freshRoot("agent-http-non-post");
  writeConfirmedMode(root, "standalone");
  const tokenPath = path.join(root, "agent-token.txt");
  fs.writeFileSync(tokenPath, "a-fake-but-long-enough-bearer-token-value");
  const { configPath } = writeGatewayConfig(root, { agent_listen: { transport: "http", token_ref: tokenPath } });
  const gw = spawnGateway(root, configPath);
  const port = await waitForHttpPort(gw);

  const status = await new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method: "GET" }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.end();
  });
  check("e2e-agent-http-listener-rejects-get-with-405", status === 405, String(status));

  gw.child.kill();
  await gw.exitCode();
}

/** Board decision 2026-09-04, PR #29 review "reject HTTP listener bind failures through
 * the startup promise": a second gateway configured to bind the SAME already-occupied
 * agent_listen.port must fail its startup promise (not hang or crash uncaught) and exit
 * non-zero with a clear message, mirroring secondInstanceRefused's own writer-claim
 * precedent for a different resource. */
async function agentHttpListenerBindFailureRejectedCleanly() {
  const rootA = freshRoot("agent-http-bind-a");
  writeConfirmedMode(rootA, "standalone");
  const tokenPathA = path.join(rootA, "agent-token.txt");
  fs.writeFileSync(tokenPathA, "a-fake-but-long-enough-bearer-token-value");
  const { configPath: configPathA } = writeGatewayConfig(rootA, { agent_listen: { transport: "http", token_ref: tokenPathA } });
  const gwA = spawnGateway(rootA, configPathA);
  const occupiedPort = await waitForHttpPort(gwA);

  const rootB = freshRoot("agent-http-bind-b");
  writeConfirmedMode(rootB, "standalone");
  const tokenPathB = path.join(rootB, "agent-token.txt");
  fs.writeFileSync(tokenPathB, "a-fake-but-long-enough-bearer-token-value");
  const { configPath: configPathB } = writeGatewayConfig(rootB, { agent_listen: { transport: "http", port: occupiedPort, token_ref: tokenPathB } });
  const gwB = spawnGateway(rootB, configPathB);
  const codeB = await gwB.exitCode();
  check("e2e-agent-http-bind-failure-exits-nonzero-not-hang", codeB !== 0, `exit code ${codeB}`);
  check("e2e-agent-http-bind-failure-names-listener-in-stderr", /agent-facing HTTP listener/i.test(gwB.stderr()), gwB.stderr());

  gwA.child.kill();
  await gwA.exitCode();
}

/** Board decision 2026-09-08 (external panel consult, x-ai/grok-4.5's dissent adopted
 * over the socket-scoped alternative): proves the actual reason that design was chosen
 * over a simpler one -- two DISTINCT logical sessions sharing one physical TCP socket
 * (the connection-pooling-reverse-proxy scenario this repo's own prior comments already
 * flagged as an unenforced assumption) must NOT collide, cross-contaminate, or let one
 * agent call tools before ITS OWN "initialize". A socket-identity design cannot pass
 * this by construction; an explicit `Mcp-Session-Id` design can. Also covers the new
 * transport-level session lifecycle surface directly: missing-header rejection, unknown-
 * session 404, and explicit DELETE termination. */
async function httpAgentSessionsAreIdBasedNotSocketBased() {
  const root = freshRoot("agent-http-session-id");
  writeConfirmedMode(root, "standalone");
  const tokenPath = path.join(root, "agent-token.txt");
  fs.writeFileSync(tokenPath, "a-fake-but-long-enough-bearer-token-value");
  const { configPath } = writeGatewayConfig(root, { agent_listen: { transport: "http", token_ref: tokenPath } });
  const gw = spawnGateway(root, configPath);
  const port = await waitForHttpPort(gw);
  const token = fs.readFileSync(tokenPath, "utf8").trim();

  /* One shared, single-socket keep-alive agent: both logical sessions below are forced
   * onto the SAME underlying TCP connection. Under the prior (superseded) socket-keyed
   * design this would make the second "initialize" silently reuse the first session --
   * exactly the pooling-proxy corruption this change exists to fix. */
  const sharedSocketAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  try {
    const missingHeaderResp = await httpPost(port, token, { jsonrpc: "2.0", id: 0, method: "tools/call", params: { name: "fixture_echo", arguments: {} } }, sharedSocketAgent);
    check(
      "e2e-agent-http-missing-session-header-non-initialize-rejected",
      missingHeaderResp.body && missingHeaderResp.body.error && /mcp-session-id/i.test(missingHeaderResp.body.error.message),
      JSON.stringify(missingHeaderResp.body)
    );

    const initA = await httpPost(port, token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "agent-A", version: "1.0" } } }, sharedSocketAgent);
    const sessionA = initA.headers["mcp-session-id"];
    const initB = await httpPost(port, token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "agent-B", version: "1.0" } } }, sharedSocketAgent);
    const sessionB = initB.headers["mcp-session-id"];
    check("e2e-agent-http-two-sessions-on-one-socket-get-distinct-ids", typeof sessionA === "string" && typeof sessionB === "string" && sessionA !== sessionB, JSON.stringify({ sessionA, sessionB }));

    const callA = await httpPost(port, token, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "fixture_echo", arguments: { prompt: "from A" } } }, sharedSocketAgent, sessionA);
    check("e2e-agent-http-session-a-tools-call-succeeds", callA.body && callA.body.id === 2 && callA.body.result, JSON.stringify(callA.body));

    const unknownResp = await httpPost(port, token, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "fixture_echo", arguments: {} } }, sharedSocketAgent, "http-" + "0".repeat(32));
    check("e2e-agent-http-unknown-session-id-rejected-404", unknownResp.body && unknownResp.body.error && /unknown or expired/i.test(unknownResp.body.error.message), JSON.stringify(unknownResp.body));

    await new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, method: "DELETE", agent: sharedSocketAgent, headers: { authorization: `Bearer ${token}`, "mcp-session-id": sessionA } }, (res) => {
        check("e2e-agent-http-delete-terminates-session-204", res.statusCode === 204, String(res.statusCode));
        res.resume();
        res.on("end", resolve);
      });
      req.on("error", reject);
      req.end();
    });

    const afterDeleteA = await httpPost(port, token, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "fixture_echo", arguments: {} } }, sharedSocketAgent, sessionA);
    check("e2e-agent-http-deleted-session-now-unknown", afterDeleteA.body && afterDeleteA.body.error && /unknown or expired/i.test(afterDeleteA.body.error.message), JSON.stringify(afterDeleteA.body));

    const callB = await httpPost(port, token, { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "fixture_echo", arguments: { prompt: "from B" } } }, sharedSocketAgent, sessionB);
    check("e2e-agent-http-session-b-unaffected-by-session-a-deletion", callB.body && callB.body.id === 5 && callB.body.result, JSON.stringify(callB.body));
  } finally {
    sharedSocketAgent.destroy();
  }

  gw.child.kill();
  await gw.exitCode();
}

async function modeDormantExitsZero() {
  const root = freshRoot("dormant");
  writeConfirmedMode(root, "attach");
  const { configPath, stateDir } = writeGatewayConfig(root);
  const gw = spawnGateway(root, configPath);
  gw.child.stdin.end();
  const code = await gw.exitCode();
  check("e2e-attach-mode-standalone-binary-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);
  check("e2e-attach-mode-mentions-dormant-in-stderr", /dormant/i.test(gw.stderr()), gw.stderr());
  check("e2e-attach-mode-never-created-state-dir", !fs.existsSync(stateDir), "state_dir was created despite dormant mode");
}

async function secondInstanceRefused() {
  const root = freshRoot("second-instance");
  writeConfirmedMode(root, "standalone");
  const { configPath } = writeGatewayConfig(root);

  const first = spawnGateway(root, configPath);
  first.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await first.nextMessage(); // wait until the first instance is fully up (claim held) before racing the second

  const second = spawnGateway(root, configPath);
  const secondCode = await second.exitCode();
  check("e2e-second-instance-refused-nonzero-exit", secondCode !== 0, `exit code ${secondCode}`);
  check("e2e-second-instance-error-names-writer-claim", /single-writer constraint/i.test(second.stderr()) && /writer-claim/i.test(second.stderr()), second.stderr());

  first.child.kill(); // best-effort cleanup; not testing graceful shutdown here (see test 5)
  await first.exitCode();
}

async function cleanSigtermDrainsAndExitsZero() {
  if (process.platform === "win32") {
    skip("e2e-sigterm-clean-drain-and-release", "Windows cannot deliver a real SIGTERM for graceful in-process handling (child.kill('SIGTERM') force-terminates on win32) -- mirrors this repo's existing writer-claim precedent of skipping a platform-unreproducible signal test rather than writing one that cannot mean what it claims.");
    return;
  }
  const root = freshRoot("sigterm");
  writeConfirmedMode(root, "standalone");
  const { configPath, stateDir } = writeGatewayConfig(root);
  const gw = spawnGateway(root, configPath);

  /* Board decision 2026-09-04, PR #29 review "enforce the agent initialization
   * lifecycle": tools/call and tools/list are now both rejected before a connection has
   * completed initialize, so this test (previously skipping it to focus purely on
   * SIGTERM-drain behavior) must complete a real handshake first. Awaited on its own
   * before the two sends below, so it does not disturb their own same-tick ordering
   * guarantee (see the comment on that below). */
  gw.send({ jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const initResp = await gw.nextMessage();
  check("e2e-sigterm-preinitialize-succeeded", initResp && initResp.id === 0 && initResp.result, JSON.stringify(initResp));

  gw.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "fixture_echo", arguments: { delayMs: 200 } } });
  /* Explicit call-start signal, not a fixed sleep: tools/list needs no downstream round-
   * trip (it's answered straight from the cached tool surface), so sending it right
   * behind the slow call and awaiting ITS response proves the slow call's handleMessage()
   * already ran synchronously up to (and including) session.recordCallStart() -- i.e. it
   * is genuinely pending -- before this test signals. Readline dispatches "line" events,
   * and therefore these two handleMessage() invocations, strictly in the order the lines
   * were written, so this ordering holds regardless of scheduler/startup latency (the
   * flakiness a fixed sleep was exposed to: a 50ms sleep can fire before the gateway has
   * even read its first line under CI scheduling pressure). */
  gw.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const readinessResp = await gw.nextMessage();
  check("e2e-sigterm-readiness-signal-received-before-sending-it", readinessResp && readinessResp.id === 2, JSON.stringify(readinessResp));
  gw.child.kill("SIGTERM");
  const callResp = await gw.nextMessage(5000);
  check("e2e-sigterm-in-flight-call-still-completes-during-drain", callResp && callResp.id === 1 && callResp.result, JSON.stringify(callResp));
  const code = await gw.exitCode();
  check("e2e-sigterm-clean-drain-and-release-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);
  const head = chain.readHead(stateDir);
  check("e2e-sigterm-session-still-finalized-and-persisted", head && head.seq === 1, JSON.stringify(head));
}

async function main() {
  await singleSessionEndToEndVerifies();
  await samplingForwardedToStdioAgent();
  await malformedPushedReplyIsRejectedNotSilentlyAccepted();
  await pushedReplyWithPresentButFalsyErrorIsRejected();
  await samplingOverHttpAgentGetsExplicitError();
  await httpDownstreamAgainstRealMcpServerSucceeds();
  await agentHttpListenerRejectsNonPostMethod();
  await agentHttpListenerBindFailureRejectedCleanly();
  await httpAgentSessionsAreIdBasedNotSocketBased();
  await modeDormantExitsZero();
  await secondInstanceRefused();
  await cleanSigtermDrainsAndExitsZero();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIP").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
  process.exit(failures ? 1 : 0);
}

main().catch((error) => {
  console.error("FATAL:", error.stack || error.message);
  process.exit(1);
});
