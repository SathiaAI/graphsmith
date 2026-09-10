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
const recovery = require(path.join(ROOT, "scripts", "gateway", "recovery.js"));

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

/** Like fakeConnection, but also records every call's full argument list -- needed for
 * the Option C tests below to assert on `idempotencyKey` (call()'s 5th argument) and on
 * how many times a logical operation was actually dispatched downstream. */
function fakeConnectionCapturing(impl) {
  let closed = false;
  const calls = [];
  return {
    transport: "fake",
    calls,
    call: async (method, params, timeoutMs, onIdAssigned, idempotencyKey) => {
      calls.push({ method, params, idempotencyKey });
      if (closed) throw Object.assign(new Error("closed"), { code: "GATEWAY_DOWNSTREAM_DISCONNECTED" });
      return impl(method, params);
    },
    close: () => { closed = true; },
    isClosed: () => closed,
    whenClosed: () => new Promise(() => {}),
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

/* Option C (Codex PR #29 Finding 1 + 2, external-panel-reviewed design -- see
 * option-c-hardened-design.md): recovery.js's WAL + idempotency-intent wiring inside
 * proxy.js's real dispatch path. These use fakeConnectionCapturing (not the plain
 * fakeConnection above) specifically to observe how many times a logical operation was
 * actually dispatched downstream and what idempotency key (if any) it carried. */

async function idempotencyKeyPropagatedToRealToolCallOnly() {
  const dir = freshDir("idem-key");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  const expectedKey = recovery.computeIntentKey("conn-1", "echo", { a: 1 });
  check(
    "idempotency-key-propagated-to-downstream-tools-call",
    conn.calls.length === 1 && conn.calls[0].idempotencyKey === expectedKey,
    JSON.stringify(conn.calls)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function inFlightRetryBlockedAsAmbiguousRetry() {
  const dir = freshDir("in-flight-retry");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  // Deliberately not awaited: an async function body runs synchronously up to its first
  // `await` (here, `conn.call(...)`), so by the time control returns to this line the
  // intent has already been durably created as "dispatched" -- no extra tick needed.
  const firstPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: { x: 1 } } });
  const retryResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "slow", arguments: { x: 1 } } });
  check("in-flight-retry-blocked-with-ambiguous-retry-code", retryResp && retryResp.error && retryResp.error.code === -32080, JSON.stringify(retryResp));
  check("in-flight-retry-did-not-redispatch-downstream", conn.calls.length === 1, JSON.stringify(conn.calls));
  resolveCall({ ok: true });
  await firstPromise;
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Frontier-panel decision (Paul, 2026-09-10, cluster E1): completed-intent replay now
 * requires the retry to present the SAME caller-supplied idempotency key
 * (params._meta.idempotencyKey) the original dispatch carried -- argument equality alone
 * is no longer sufficient to trigger a silent replay. */
async function completedCallReplaysCachedResultOnRetryWithMatchingKey() {
  const dir = freshDir("replay");
  const conn = fakeConnectionCapturing(async () => ({ value: 42 }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const params = { name: "echo", arguments: { a: 1 }, _meta: { idempotencyKey: "caller-key-1" } };
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  const retry = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params });
  check("retry-of-completed-call-replays-cached-result-with-matching-key", retry && retry.result && retry.result.value === 42, JSON.stringify(retry));
  check("retry-of-completed-call-did-not-redispatch-downstream-with-matching-key", conn.calls.length === 1, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* E1's actual fix: WITHOUT a caller-supplied idempotency key, a repeated identical call
 * after completion is no longer silently replayed -- it dispatches as a new, independent
 * call (this is precisely the two reviewers' finding: argument equality alone cannot
 * distinguish an intentional second call from a lost-response retry). The intent's
 * generation is bumped and the downstream-facing idempotency key is suffixed so a
 * downstream implementing its own dedup does not mistake this for the earlier call. */
async function retryOfCompletedCallWithoutKeyDispatchesIndependently() {
  const dir = freshDir("no-key-supersede");
  const conn = fakeConnectionCapturing(async () => ({ value: 42 }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const params = { name: "echo", arguments: { a: 1 } }; // no _meta.idempotencyKey
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  const retry = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params });
  check("retry-without-key-redispatched-downstream", conn.calls.length === 2, JSON.stringify(conn.calls));
  check("retry-without-key-still-returns-a-real-result", Boolean(retry && retry.result && retry.result.value === 42), JSON.stringify(retry));
  const intentKey = recovery.computeIntentKey("conn-1", "echo", { a: 1 });
  check(
    "retry-without-key-downstream-call-uses-generation-suffixed-key",
    conn.calls[0].idempotencyKey === intentKey && conn.calls[1].idempotencyKey === `${intentKey}.g2`,
    JSON.stringify(conn.calls)
  );
  const finalIntent = recovery.readIntent(dir, intentKey);
  check("retry-without-key-intent-generation-bumped", Boolean(finalIntent) && finalIntent.generation === 2 && finalIntent.state === "completed", JSON.stringify(finalIntent));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* A retry presenting a DIFFERENT idempotency key than the original dispatch is also not a
 * caller-signaled retry of that specific attempt -- treated the same as no key at all. */
async function retryWithMismatchedKeyDispatchesIndependently() {
  const dir = freshDir("mismatched-key");
  const conn = fakeConnectionCapturing(async () => ({ value: 7 }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { a: 1 }, _meta: { idempotencyKey: "key-A" } } });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { a: 1 }, _meta: { idempotencyKey: "key-B" } } });
  check("retry-with-mismatched-key-redispatched-downstream", conn.calls.length === 2, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function ambiguousOutcomeBlocksRetryUntilOperatorResolves() {
  const dir = freshDir("ambiguous");
  const conn = fakeConnectionCapturing(async () => { throw Object.assign(new Error("boom"), { code: "GATEWAY_DOWNSTREAM_RPC_ERROR" }); });
  const mergedTools = [{ name: "flaky", server: "srv", schema: {} }];
  const toolOwners = new Map([["flaky", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const first = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "flaky", arguments: {} } });
  check("first-attempt-surfaces-the-real-transport-error", Boolean(first && first.error), JSON.stringify(first));
  const retry = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "flaky", arguments: {} } });
  check("ambiguous-retry-blocked-with-downstream-outcome-unknown-code", retry && retry.error && retry.error.code === -32081, JSON.stringify(retry));
  check("ambiguous-retry-did-not-redispatch-downstream", conn.calls.length === 1, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

async function closeConnectionFencesInFlightIntentAsAmbiguous() {
  const dir = freshDir("close-fence");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const inFlight = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: {} } });
  const intentKey = recovery.computeIntentKey("conn-1", "slow", {});
  await proxy.closeConnection("conn-1", "agent hung up mid-call");
  const intent = recovery.readIntent(dir, intentKey);
  check("close-connection-fences-in-flight-intent-as-ambiguous", Boolean(intent) && intent.state === "ambiguous", JSON.stringify(intent));
  resolveCall({ ok: true }); // let the now-orphaned call settle so nothing is left hanging
  await inFlight.catch(() => {});
}

async function walRecordsLifecycleEventsAndIsCleanedUpOnClose() {
  const dir = freshDir("wal-lifecycle");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: {} } });
  const eventsBeforeClose = recovery.readWalEvents(dir, "conn-1").map((e) => e.type);
  check(
    "wal-records-session-start-initialize-call-start-call-result-in-order",
    JSON.stringify(eventsBeforeClose) === JSON.stringify(["SESSION_START", "INITIALIZE", "CALL_START", "CALL_RESULT"]),
    JSON.stringify(eventsBeforeClose)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
  const eventsAfterClose = recovery.readWalEvents(dir, "conn-1");
  check("wal-deleted-after-a-clean-close", eventsAfterClose.length === 0, JSON.stringify(eventsAfterClose));
}

// ---------------------------------------------------------------------------
// PR #33 round-2 fixes.
// ---------------------------------------------------------------------------

/* Codex PR #33 review "append blocked-retry anomalies to the WAL": a blocked duplicate
 * used to be recorded in-memory only (session.recordAnomaly) -- a crash before this
 * connection's own close would silently drop that attestation from a recovered/sealed
 * bundle. Now also durably WAL-logged and given a normal structured completion log. */
async function blockedRetryAnomalyIsDurablyRecorded() {
  const dir = freshDir("blocked-anomaly-wal");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const logLines = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, { log: (line) => logLines.push(line) });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const firstPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: { x: 1 } } });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "slow", arguments: { x: 1 } } });
  const walEvents = recovery.readWalEvents(dir, "conn-1");
  const anomalyEvent = walEvents.find((e) => e.type === "ANOMALY");
  check("blocked-retry-anomaly-appended-to-wal", Boolean(anomalyEvent) && anomalyEvent.kind === "GATEWAY_AMBIGUOUS_RETRY" && anomalyEvent.tool === "slow", JSON.stringify(walEvents));
  const parsedLogs = logLines.map((l) => { try { return JSON.parse(l); } catch (error) { return null; } });
  const blockedLog = parsedLogs.find((l) => l && l.event === "gateway_call_completed" && l.status === "blocked");
  check("blocked-retry-gets-a-structured-completion-log", Boolean(blockedLog) && blockedLog.tool === "slow", JSON.stringify(logLines));
  resolveCall({ ok: true });
  await firstPromise;
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #33 review "emit complete step logs for replayed and blocked calls": a
 * completed-intent replay previously logged only the special-purpose
 * gateway_intent_replayed event, missing the normal step/status/duration shape every
 * other handled call gets. */
async function replayedCallGetsAStructuredCompletionLogToo() {
  const dir = freshDir("replay-structured-log");
  const conn = fakeConnectionCapturing(async () => ({ value: 1 }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const logLines = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, { log: (line) => logLines.push(line) });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const params = { name: "echo", arguments: { a: 1 }, _meta: { idempotencyKey: "structured-log-key" } };
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  logLines.length = 0; // only care about the retry's own logging below
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params });
  const parsedLogs = logLines.map((l) => { try { return JSON.parse(l); } catch (error) { return null; } });
  const replayedLog = parsedLogs.find((l) => l && l.event === "gateway_call_completed" && l.status === "replayed");
  check("replayed-call-gets-a-structured-completion-log", Boolean(replayedLog) && replayedLog.tool === "echo", JSON.stringify(logLines));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Frontier-panel decision (Paul, 2026-09-10, cluster E2): a reconnecting agent gets a
 * brand-new connectionId, so its retry of "the same" logical operation computes a
 * DIFFERENT intentKey than a still-unresolved intent its crashed predecessor connection
 * left behind. A tool with an unresolved (dispatched/ambiguous) intent belonging to a
 * connection startup recovery flagged pendingOperatorReview is quarantined for every
 * connection until an operator resolves it -- regardless of connectionId or arguments. */
async function toolQuarantinedWhileACrashedConnectionIsPendingOperatorReview() {
  const dir = freshDir("quarantine");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "email", server: "srv", schema: {} }];
  const toolOwners = new Map([["email", "srv"]]);
  // Simulate a crash-left "ambiguous" intent belonging to a now-defunct connection, the
  // way gateway.js#recoverCrashedSessions would leave one on disk at startup.
  const staleIntentKey = recovery.computeIntentKey("crashed-conn", "email", { to: "x" });
  recovery.createIntentIfAbsent(dir, staleIntentKey, {
    connection_id: "crashed-conn",
    tool: "email",
    arguments: { to: "x" },
    state: "dispatched",
    dispatched_at: Date.now(),
  });
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    pendingOperatorReviewConnections: ["crashed-conn"],
  });
  proxy.openConnection("conn-2"); // a brand-new (e.g. reconnecting) connection
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const resp = await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "email", arguments: { to: "y" } } });
  check("tool-quarantined-for-different-connection-and-arguments", Boolean(resp && resp.error && resp.error.code === -32082), JSON.stringify(resp));
  check("tool-quarantined-did-not-redispatch-downstream", conn.calls.length === 0, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-2", "test cleanup");
}

/* The quarantine must not over-block: a DIFFERENT tool on the same gateway, and the SAME
 * tool once its owning connection is no longer in pendingOperatorReview (i.e. resolved),
 * must dispatch normally. */
async function toolQuarantineScopedToTheAffectedToolAndConnectionOnly() {
  const dir = freshDir("quarantine-scope");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "email", server: "srv", schema: {} }, { name: "increment", server: "srv", schema: {} }];
  const toolOwners = new Map([["email", "srv"], ["increment", "srv"]]);
  const staleIntentKey = recovery.computeIntentKey("crashed-conn", "email", { to: "x" });
  recovery.createIntentIfAbsent(dir, staleIntentKey, {
    connection_id: "crashed-conn",
    tool: "email",
    arguments: { to: "x" },
    state: "dispatched",
    dispatched_at: Date.now(),
  });
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    pendingOperatorReviewConnections: ["crashed-conn"],
  });
  proxy.openConnection("conn-2");
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const otherTool = await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "increment", arguments: {} } });
  check("unrelated-tool-not-quarantined", Boolean(otherTool && otherTool.result && otherTool.result.ok === true), JSON.stringify(otherTool));
  // Simulate the operator resolving the crashed connection (recovery-abandon deletes the
  // intent; recovery-resolve --confirmed executed/not-executed sets a terminal state --
  // either way this connection no longer belongs in pendingOperatorReviewConnections on
  // the NEXT gateway startup, which is what a fresh GatewayProxy instance below models).
  recovery.deleteIntent(dir, staleIntentKey);
  const proxy2 = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, { pendingOperatorReviewConnections: [] });
  proxy2.openConnection("conn-3");
  await proxy2.handleMessage("conn-3", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const afterResolve = await proxy2.handleMessage("conn-3", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "email", arguments: { to: "y" } } });
  check("tool-dispatches-normally-once-crashed-connection-resolved", Boolean(afterResolve && afterResolve.result && afterResolve.result.ok === true), JSON.stringify(afterResolve));
  await proxy.closeConnection("conn-2", "test cleanup");
  await proxy2.closeConnection("conn-3", "test cleanup");
}

/* Codex PR #33 review "undo the fence when CALL_START persistence fails": the intent is
 * created (dispatched) before this WAL append -- if the append itself fails (e.g. a full
 * disk), the call never actually reaches conn.call(). Without a rollback, the intent
 * stays "dispatched" forever (every retry permanently blocked) and, worse, the exception
 * used to escape handleMessage entirely, breaking its documented "never throws" contract. */
async function callStartWalAppendFailureRollsBackAndStaysRetryable() {
  const dir = freshDir("call-start-wal-failure");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });

  const realAppendWalEvent = recovery.appendWalEvent;
  let failNextCallStart = true;
  recovery.appendWalEvent = (...args) => {
    if (failNextCallStart && args[2] && args[2].type === "CALL_START") {
      failNextCallStart = false;
      throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    }
    return realAppendWalEvent(...args);
  };
  let resp, threw = null;
  try {
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("call-start-wal-failure-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("call-start-wal-failure-returns-a-retryable-jsonrpc-error", Boolean(resp && resp.error && resp.error.code === -32000), JSON.stringify(resp));
  check("call-start-wal-failure-did-not-dispatch-downstream", conn.calls.length === 0, JSON.stringify(conn.calls));
  const intentKey = recovery.computeIntentKey("conn-1", "echo", { a: 1 });
  check("call-start-wal-failure-rolled-back-the-intent", recovery.readIntent(dir, intentKey) === null, "intent still present");

  const retry = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  check("call-start-wal-failure-retry-dispatches-normally-afterward", Boolean(retry && retry.result && retry.result.ok === true), JSON.stringify(retry));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #33 review "guard the post-dispatch intent update": a concurrent removal of
 * this call's intent (an operator's recovery-resolve, or a race with closeConnection)
 * while conn.call() is still in flight used to make the post-dispatch updateIntent throw
 * GATEWAY_RECOVERY_INTENT_NOT_FOUND uncaught -- preventing the JSON-RPC response for a
 * call that DID complete. */
async function postDispatchUpdateSkippedWhenIntentConcurrentlyRemoved() {
  const dir = freshDir("intent-removed-midflight");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  const callPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: { a: 1 } } });
  const intentKey = recovery.computeIntentKey("conn-1", "slow", { a: 1 });
  recovery.deleteIntent(dir, intentKey); // simulate the concurrent removal
  resolveCall({ ok: true });
  let resp, threw = null;
  try {
    resp = await callPromise;
  } catch (error) {
    threw = error;
  }
  check("post-dispatch-update-does-not-throw-when-intent-concurrently-removed", threw === null, threw && threw.message);
  check("post-dispatch-update-still-returns-the-real-result-to-the-agent", Boolean(resp && resp.result && resp.result.ok === true), JSON.stringify(resp));
  await proxy.closeConnection("conn-1", "test cleanup");
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
  await idempotencyKeyPropagatedToRealToolCallOnly();
  await inFlightRetryBlockedAsAmbiguousRetry();
  await completedCallReplaysCachedResultOnRetryWithMatchingKey();
  await retryOfCompletedCallWithoutKeyDispatchesIndependently();
  await retryWithMismatchedKeyDispatchesIndependently();
  await toolQuarantinedWhileACrashedConnectionIsPendingOperatorReview();
  await toolQuarantineScopedToTheAffectedToolAndConnectionOnly();
  await ambiguousOutcomeBlocksRetryUntilOperatorResolves();
  await closeConnectionFencesInFlightIntentAsAmbiguous();
  await walRecordsLifecycleEventsAndIsCleanedUpOnClose();

  await blockedRetryAnomalyIsDurablyRecorded();
  await replayedCallGetsAStructuredCompletionLogToo();
  await callStartWalAppendFailureRollsBackAndStaysRetryable();
  await postDispatchUpdateSkippedWhenIntentConcurrentlyRemoved();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
