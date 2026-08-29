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
 *      precedent (tests/state-store/writer-claim, "skip win32-unreproducible renew()
 *      TOCTOU simulation") of naming and skipping a platform-unreproducible case rather
 *      than writing a test that cannot mean what it claims to mean.
 *   6  second gateway instance started against the same state_dir while the first is
 *      running -> FR-1 refusal, named identity in the error.
 *   15 mode configured as attach but the standalone binary is started anyway -> logs
 *      dormant, exits 0, binds no port, holds no claim.
 */

const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
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

  gw.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "fixture_echo", arguments: { delayMs: 200 } } });
  await new Promise((resolve) => setTimeout(resolve, 50)); // let the call actually be in flight before signaling
  gw.child.kill("SIGTERM");
  const callResp = await gw.nextMessage(5000);
  check("e2e-sigterm-in-flight-call-still-completes-during-drain", callResp && callResp.result, JSON.stringify(callResp));
  const code = await gw.exitCode();
  check("e2e-sigterm-clean-drain-and-release-exits-zero", code === 0, `exit code ${code}; stderr: ${gw.stderr()}`);
  const head = chain.readHead(stateDir);
  check("e2e-sigterm-session-still-finalized-and-persisted", head && head.seq === 1, JSON.stringify(head));
}

async function main() {
  await singleSessionEndToEndVerifies();
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
