#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/proxy.js (SS3.3/SS6 dispatch). Uses FAKE
 * downstream connections (plain objects implementing .call()) rather than real child
 * processes -- the transport itself is scripts/gateway/downstream.js's job and is
 * covered by tests/gateway/e2e/run-tests.js against a real fixture process; this suite
 * isolates the dispatch/correlation/routing logic. Covers SS8 test plan items:
 *   2  multiple downstream servers -> tools correctly attributed, a call to server B's
 *      tool is routed to B, not A.
 *   3  multiple concurrent agents -> independent sessions, no cross-contamination.
 *   9  downstream unreachable at startup -> refuse to start (connectAllDownstreams).
 *   10 downstream disconnect with an in-flight call -> recorded as error w/ marker.
 *   14 malformed/hostile downstream response -> fails closed on that call, does not
 *      crash the gateway process.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const { GatewayProxy } = require(path.join(ROOT, "scripts", "gateway", "proxy.js"));
const chain = require(path.join(ROOT, "scripts", "gateway", "chain.js"));

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
async function checkAsync(name, fn) {
  try {
    const cond = await fn();
    check(name, cond);
  } catch (error) {
    check(name, false, error.message);
  }
}

function freshDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-proxy-${prefix}-`));
}
function makeKeys() {
  const kp = crypto.generateKeyPairSync("ed25519");
  return { privateKey: kp.privateKey, signer: "test-key", algo: "ed25519" };
}

/** A fake downstream connection: `impl(method, params) -> result` (may throw/reject). */
function fakeConnection(impl) {
  let closed = false;
  return {
    transport: "fake",
    call: async (method, params) => {
      if (closed) throw Object.assign(new Error("closed"), { code: "GATEWAY_DOWNSTREAM_DISCONNECTED" });
      return impl(method, params);
    },
    close: () => { closed = true; },
    isClosed: () => closed,
    whenClosed: () => new Promise(() => {}), // never resolves unless the test wants it to
  };
}

function makeProxy(dir, connections, mergedTools, toolOwners, extra) {
  return new GatewayProxy({
    connections,
    mergedTools,
    toolOwners,
    serverInfos: {},
    keys: makeKeys(),
    stateDir: dir,
    ...extra,
  });
}

async function multipleDownstreamAttribution() {
  const dir = freshDir("attribution");
  const connA = fakeConnection(async (method, params) => ({ from: "A", method, params }));
  const connB = fakeConnection(async (method, params) => ({ from: "B", method, params }));
  const connections = new Map([["A", connA], ["B", connB]]);
  const mergedTools = [{ name: "toolA", server: "A", schema: {} }, { name: "toolB", server: "B", schema: {} }];
  const toolOwners = new Map([["toolA", "A"], ["toolB", "B"]]);
  const proxy = makeProxy(dir, connections, mergedTools, toolOwners);

  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const respA = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "toolB", arguments: {} } });
  check("call-to-toolB-routed-to-server-B-not-A", respA.result.from === "B", JSON.stringify(respA));
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function unknownToolRejected() {
  const dir = freshDir("unknown-tool");
  const conn = fakeConnection(async () => ({}));
  const proxy = makeProxy(dir, new Map([["A", conn]]), [], new Map());
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "nonexistent", arguments: {} } });
  check("unknown-tool-returns-jsonrpc-error", resp.error && /Unknown tool/.test(resp.error.message), JSON.stringify(resp));
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function concurrentAgentsIndependentSessions() {
  const dir = freshDir("concurrent");
  const conn = fakeConnection(async (method, params) => ({ echoed: params }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);

  proxy.openConnection("agent-1");
  proxy.openConnection("agent-2");
  /* gsa-mcp-shim.js's bundle_id hashes {init, grantedTools, n} -- not call CONTENT --
   * so two sessions need distinct `initialize` clientInfo to produce distinct bundle_ids
   * (an existing, unchanged property of the shim being designed around here, not a bug
   * in this test). */
  await proxy.handleMessage("agent-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: { clientInfo: { name: "agent-one", version: "1" } } });
  await proxy.handleMessage("agent-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: { clientInfo: { name: "agent-two", version: "1" } } });
  await proxy.handleMessage("agent-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { who: "one" } } });
  await proxy.handleMessage("agent-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { who: "two" } } });

  check("two-independent-sessions-open", proxy.openSessionCount() === 2, String(proxy.openSessionCount()));
  const s1 = proxy.sessions.get("agent-1");
  const s2 = proxy.sessions.get("agent-2");
  check("agent-1-session-has-only-its-own-call", s1.calls.length === 1 && s1.calls[0].arguments.who === "one", JSON.stringify(s1.calls));
  check("agent-2-session-has-only-its-own-call", s2.calls.length === 1 && s2.calls[0].arguments.who === "two", JSON.stringify(s2.calls));
  check("no-cross-contamination-between-sessions", s1.calls.every((c) => c.arguments.who !== "two") && s2.calls.every((c) => c.arguments.who !== "one"), "cross-contamination detected");

  await proxy.closeConnection("agent-1", "test cleanup");
  await proxy.closeConnection("agent-2", "test cleanup");
}

async function downstreamDisconnectMarksErrorNotCrash() {
  const dir = freshDir("disconnect");
  let rejectCall;
  const conn = {
    transport: "fake",
    call: () => new Promise((resolve, reject) => { rejectCall = reject; }),
    close: () => {},
    isClosed: () => false,
    whenClosed: () => Promise.resolve(),
  };
  const mergedTools = [{ name: "hangs", server: "srv", schema: {} }];
  const toolOwners = new Map([["hangs", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const callPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "hangs", arguments: {} } });
  // Simulate the downstream dying while the call is in flight.
  rejectCall(Object.assign(new Error("downstream process exited"), { code: "GATEWAY_DOWNSTREAM_DISCONNECTED" }));
  const resp = await callPromise;
  check("in-flight-call-surfaces-as-jsonrpc-error-not-a-crash", resp.error && /downstream process exited/.test(resp.error.message), JSON.stringify(resp));
  const s = proxy.sessions.get("conn-1");
  check("in-flight-call-recorded-with-isError", s.calls.length === 1 && s.calls[0].isError === true, JSON.stringify(s.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function malformedDownstreamResponseFailsClosedPerCall() {
  const dir = freshDir("malformed");
  const conn = fakeConnection(async () => { throw new Error("malformed JSON from downstream"); });
  const goodConn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "bad", server: "bad-srv", schema: {} }, { name: "good", server: "good-srv", schema: {} }];
  const toolOwners = new Map([["bad", "bad-srv"], ["good", "good-srv"]]);
  const proxy = makeProxy(dir, new Map([["bad-srv", conn], ["good-srv", goodConn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const badResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "bad", arguments: {} } });
  check("malformed-response-fails-closed-as-jsonrpc-error", badResp.error !== undefined, JSON.stringify(badResp));
  const goodResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "good", arguments: {} } });
  check("proxy-process-survives-and-serves-next-call", goodResp.result && goodResp.result.ok === true, JSON.stringify(goodResp));
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function connectionCloseWithPendingCallsMarksDisconnected() {
  const dir = freshDir("close-pending");
  const conn = { transport: "fake", call: () => new Promise(() => {}), close: () => {}, isClosed: () => false, whenClosed: () => Promise.resolve() };
  const mergedTools = [{ name: "neverresponds", server: "srv", schema: {} }];
  const toolOwners = new Map([["neverresponds", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "neverresponds", arguments: {} } }); // fire and forget, never resolves
  const entry = await proxy.closeConnection("conn-1", "agent hung up mid-call");
  check("closing-connection-with-pending-call-still-produces-a-chain-entry", entry !== null, "no entry appended");
  const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, entry.bundle_id), "utf8"));
  const trace = bundle.contents["execution_trace.jsonl"];
  check("finalized-bundle-trace-shows-the-pending-call-as-an-error", /"is_error":true/.test(trace), trace);
}

async function stopAcceptingNewSessionsRefusesNewButNotExisting() {
  const dir = freshDir("stop-accepting");
  const conn = fakeConnection(async () => ({ ok: true }));
  const proxy = makeProxy(dir, new Map([["srv", conn]]), [], new Map());
  proxy.openConnection("conn-1");
  proxy.stopAcceptingNewSessions();
  let threw = null;
  try { proxy.openConnection("conn-2"); } catch (error) { threw = error; }
  check("stopAcceptingNewSessions-refuses-new-connection", threw && threw.code === "GATEWAY_NOT_ACCEPTING", threw && threw.code);
  const entry = await proxy.closeConnection("conn-1", "already-open session still finalizes");
  check("already-open-session-still-finalizes-after-stop", entry !== null, "existing session was not finalized");
}

/* Board decision 2026-09-04, PR #29 review "honor MCP tool-level error results": a
 * `tools/call` result carrying `isError: true` on the RESULT itself (not a thrown
 * transport/RPC error) must be recorded as an error in the session, but the JSON-RPC
 * response sent back to the agent stays a normal `result` (MCP tool-level errors are not
 * protocol errors). */
async function toolLevelErrorRecordedButNotProtocolError() {
  const dir = freshDir("tool-level-error");
  const conn = fakeConnection(async () => ({ content: [{ type: "text", text: "boom" }], isError: true }));
  const mergedTools = [{ name: "flaky", server: "srv", schema: {} }];
  const toolOwners = new Map([["flaky", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "flaky", arguments: {} } });
  check("tool-level-isError-still-returns-a-normal-result-not-a-protocol-error", resp.result && resp.result.isError === true && resp.error === undefined, JSON.stringify(resp));
  const s = proxy.sessions.get("conn-1");
  check("tool-level-isError-recorded-as-error-in-session", s.calls.length === 1 && s.calls[0].isError === true, JSON.stringify(s.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Board decision 2026-09-04, PR #29 review "preserve downstream JSON-RPC error
 * envelopes": a downstream's own structured JSON-RPC error (code/data) must reach the
 * agent unchanged, not be flattened into a generic -32000. */
async function preservesDownstreamJsonRpcErrorEnvelope() {
  const dir = freshDir("rpc-error");
  const conn = {
    transport: "fake",
    call: async () => { throw Object.assign(new Error("Invalid arguments"), { code: "GATEWAY_DOWNSTREAM_RPC_ERROR", rpcError: { code: -32602, message: "Invalid arguments", data: { field: "arguments.x" } } }); },
    close: () => {},
    isClosed: () => false,
    whenClosed: () => new Promise(() => {}),
  };
  const mergedTools = [{ name: "picky", server: "srv", schema: {} }];
  const toolOwners = new Map([["picky", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "picky", arguments: {} } });
  check(
    "downstream-rpc-error-code-and-data-preserved-not-flattened-to--32000",
    resp.error && resp.error.code === -32602 && resp.error.data && resp.error.data.field === "arguments.x",
    JSON.stringify(resp)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Board decision 2026-09-04, PR #29 review "enforce the agent initialization
 * lifecycle". */
async function initializationLifecycleEnforced() {
  const dir = freshDir("init-lifecycle");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");

  const preInitList = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  check("tools-list-before-initialize-rejected", preInitList.error !== undefined, JSON.stringify(preInitList));
  const preInitCall = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } });
  check("tools-call-before-initialize-rejected", preInitCall.error !== undefined, JSON.stringify(preInitCall));

  const initResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 3, method: "initialize", params: {} });
  check("first-initialize-succeeds", initResp.result !== undefined, JSON.stringify(initResp));

  const postInitCall = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "echo", arguments: {} } });
  check("tools-call-after-initialize-succeeds", postInitCall.result && postInitCall.result.ok === true, JSON.stringify(postInitCall));

  const repeatInit = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 5, method: "initialize", params: {} });
  check("repeated-initialize-rejected", repeatInit.error !== undefined, JSON.stringify(repeatInit));

  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Board decision 2026-09-04, PR #29 review "emit the required structured log for each
 * call": one structured line per completed call, naming the connection, step, tool,
 * status, and duration -- not only the much-later (or never, on a crash) session-finalize
 * log. */
async function structuredLogEmittedPerCompletedCall() {
  const dir = freshDir("structured-log");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const logLines = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, { log: (line) => logLines.push(line) });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: {} } });
  const callLog = logLines.map((l) => { try { return JSON.parse(l); } catch (error) { return null; } }).find((l) => l && l.event === "gateway_call_completed");
  check(
    "structured-log-line-emitted-for-completed-call",
    callLog && callLog.connection_id === "conn-1" && callLog.tool === "echo" && callLog.status === "ok" && typeof callLog.duration_ms === "number",
    JSON.stringify(logLines)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #29 review "forward the full cached tool descriptor": tools/list previously
 * projected each tool down to {name, description, inputSchema}, discarding whatever else
 * the downstream actually advertised (outputSchema, annotations, title, ...) even though
 * downstream.js already preserves it on the cached descriptor. Only the two
 * gateway-private fields (`server`, and the internal `schema` alias of inputSchema)
 * should ever be stripped. */
async function toolsListForwardsFullDescriptor() {
  const dir = freshDir("full-descriptor");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [
    {
      name: "echo",
      description: "echoes its arguments",
      inputSchema: { type: "object" },
      outputSchema: { type: "object", properties: { echoed: {} } },
      annotations: { title: "Echo", readOnlyHint: true },
      server: "srv", // gateway-private ownership field: must NOT reach the agent
      schema: { type: "object" }, // gateway-private internal alias: must NOT reach the agent
    },
  ];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const listResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
  const tool = listResp.result && listResp.result.tools && listResp.result.tools[0];
  check(
    "tools-list-forwards-outputSchema-and-annotations",
    tool && tool.name === "echo" && tool.description === "echoes its arguments" &&
      JSON.stringify(tool.outputSchema) === JSON.stringify(mergedTools[0].outputSchema) &&
      JSON.stringify(tool.annotations) === JSON.stringify(mergedTools[0].annotations) &&
      JSON.stringify(tool.inputSchema) === JSON.stringify(mergedTools[0].inputSchema),
    JSON.stringify(tool)
  );
  check(
    "tools-list-strips-gateway-private-server-and-schema-fields",
    tool && tool.server === undefined && tool.schema === undefined,
    JSON.stringify(tool)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #29 review "handle JSON-RPC null IDs before recording calls": JSON-RPC 2.0
 * permits an explicit `id: null` on a request (distinct from a notification, which omits
 * "id" entirely). Using it directly as the internal correlation key previously reached
 * session.recordCallStart's Map key, which throws INVALID_ARGUMENT on null -- turning a
 * legal-if-unusual request into an escaped internal error instead of a normal response. */
async function nullJsonRpcIdDoesNotCrash() {
  const dir = freshDir("null-id");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: null, method: "tools/call", params: { name: "echo", arguments: {} } });
  check(
    "null-jsonrpc-id-tools-call-does-not-throw-and-echoes-null-id",
    resp && resp.id === null && resp.result && resp.result.ok === true,
    JSON.stringify(resp)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #29 review round 3 "retain sessions when persistence fails": closeConnection
 * used to discard the fully-sealed bundle the moment chain.appendSession threw, leaving
 * only a summary log line. Two connections given identical initialize params and an
 * identical call count deterministically produce the same bundle_id (gsa-mcp-shim.js
 * hashes only {init, grantedTools, n} -- see chain.js's own "same agent reconnecting ...
 * reproduces it" comment), so the second one's real chain.appendSession call genuinely
 * throws GATEWAY_BUNDLE_ID_COLLISION here rather than a synthetic/forced failure. */
async function persistenceFailureQuarantinesSealedBundle() {
  const dir = freshDir("quarantine");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const sealFailures = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    onSealFailure: (s, error) => sealFailures.push(error),
  });

  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "x", version: "1" } } });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } });
  const entry1 = await proxy.closeConnection("conn-1", "test cleanup");
  check("quarantine-setup-first-append-succeeds", Boolean(entry1 && typeof entry1.bundle_id === "string"), JSON.stringify(entry1));

  proxy.openConnection("conn-2");
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "x", version: "1" } } });
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } });
  const entry2 = await proxy.closeConnection("conn-2", "test cleanup");
  check("persistence-failure-returns-null", entry2 === null, JSON.stringify(entry2));
  check(
    "persistence-failure-invokes-onSealFailure-with-collision-code",
    sealFailures.length === 1 && sealFailures[0].code === "GATEWAY_BUNDLE_ID_COLLISION",
    JSON.stringify(sealFailures.map((e) => e && e.code))
  );

  const quarantinedTo = sealFailures[0] && sealFailures[0].quarantinedTo;
  check("persistence-failure-quarantines-sealed-bundle", typeof quarantinedTo === "string" && fs.existsSync(quarantinedTo), String(quarantinedTo));
  if (typeof quarantinedTo === "string" && fs.existsSync(quarantinedTo)) {
    const quarantined = JSON.parse(fs.readFileSync(quarantinedTo, "utf8"));
    check(
      "quarantined-file-preserves-the-sealed-bundle",
      Boolean(quarantined.sealed && quarantined.sealed.bundle && quarantined.sealed.bundle.manifest),
      JSON.stringify(Object.keys(quarantined))
    );
  }
}

async function main() {
  await multipleDownstreamAttribution();
  await unknownToolRejected();
  await concurrentAgentsIndependentSessions();
  await downstreamDisconnectMarksErrorNotCrash();
  await malformedDownstreamResponseFailsClosedPerCall();
  await connectionCloseWithPendingCallsMarksDisconnected();
  await stopAcceptingNewSessionsRefusesNewButNotExisting();
  await toolLevelErrorRecordedButNotProtocolError();
  await preservesDownstreamJsonRpcErrorEnvelope();
  await initializationLifecycleEnforced();
  await structuredLogEmittedPerCompletedCall();
  await toolsListForwardsFullDescriptor();
  await nullJsonRpcIdDoesNotCrash();
  await persistenceFailureQuarantinesSealedBundle();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
