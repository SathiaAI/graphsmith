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

/* Codex PR #29 review round 8 "wait for notifications/initialized before admitting
 * tools": GatewayProxy now only admits tools/list and tools/call after this
 * notification has actually been received, not merely after "initialize" completes --
 * every existing test below that exercises tools/list or tools/call must send it too. */
async function sendInitializedNotification(proxy, connectionId) {
  await proxy.handleMessage(connectionId, { jsonrpc: "2.0", method: "notifications/initialized" });
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "agent-1");
  await sendInitializedNotification(proxy, "agent-2");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  const logLines = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, { log: (line) => logLines.push(line) });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "neverresponds", arguments: {} } }); // fire and forget, never resolves
  const entry = await proxy.closeConnection("conn-1", "agent hung up mid-call");
  check("closing-connection-with-pending-call-still-produces-a-chain-entry", entry !== null, "no entry appended");
  const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, entry.bundle_id), "utf8"));
  const trace = bundle.contents["execution_trace.jsonl"];
  check("finalized-bundle-trace-shows-the-pending-call-as-an-error", /"is_error":true/.test(trace), trace);

  /* Codex PR #29 review round 4 "log calls finalized as disconnected": a call finalized
   * via closeConnection's own pending-call cleanup previously got no matching
   * "gateway_call_completed" operational log line at all, unlike every other way a call
   * can complete. */
  const disconnectLog = logLines.map((l) => { try { return JSON.parse(l); } catch (error) { return null; } }).find((l) => l && l.event === "gateway_call_completed" && l.status === "disconnected");
  check(
    "close-connection-with-pending-call-emits-completion-log",
    Boolean(disconnectLog && disconnectLog.connection_id === "conn-1" && disconnectLog.tool === "neverresponds" && typeof disconnectLog.duration_ms === "number"),
    JSON.stringify(logLines)
  );
}

/** Codex PR #29 review round 4 "log calls finalized as disconnected": a downstream
 * disconnect mid-session (handleDownstreamDisconnect, distinct from closeConnection
 * above) marks that server's pending calls disconnected too, and must emit the same
 * structured completion log for each -- otherwise those steps have no run ID, status, or
 * duration anywhere in the operational log despite being fully recorded in the trace. */
async function downstreamDisconnectEmitsCompletionLog() {
  const dir = freshDir("disconnect-log");
  const conn = { transport: "fake", call: () => new Promise(() => {}), close: () => {}, isClosed: () => false, whenClosed: () => new Promise(() => {}) };
  const mergedTools = [{ name: "hangs", server: "srv", schema: {} }];
  const toolOwners = new Map([["hangs", "srv"]]);
  const logLines = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, { log: (line) => logLines.push(line) });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "hangs", arguments: {} } }); // fire and forget, never resolves
  proxy.handleDownstreamDisconnect("srv");
  const s = proxy.sessions.get("conn-1");
  check("downstream-disconnect-marks-pending-call-disconnected", s.calls.length === 1 && s.calls[0].disconnected === true, JSON.stringify(s.calls));
  const disconnectLog = logLines.map((l) => { try { return JSON.parse(l); } catch (error) { return null; } }).find((l) => l && l.event === "gateway_call_completed" && l.status === "disconnected");
  check(
    "downstream-disconnect-emits-completion-log",
    Boolean(disconnectLog && disconnectLog.connection_id === "conn-1" && disconnectLog.tool === "hangs" && disconnectLog.server === "srv" && typeof disconnectLog.duration_ms === "number"),
    JSON.stringify(logLines)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #29 review "bound completed call history retained by each session": a
 * session that never trips MAX_PENDING_CALLS_PER_SESSION (calls issued one at a time,
 * never concurrently) could previously grow session.calls without any bound at all.
 * Drives the session's own recorded-call count up to the cap directly (issuing that many
 * real calls would make this test absurdly slow) rather than through 100000 real round
 * trips, then asserts the NEXT call is refused exactly the way the pending-call cap
 * already refuses admission once its own limit is hit. */
async function completedCallHistoryCapped() {
  const { MAX_COMPLETED_CALLS_PER_SESSION } = require(path.join(ROOT, "scripts", "gateway", "proxy.js"));
  const dir = freshDir("completed-call-cap");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "tool", server: "srv", schema: {} }];
  const toolOwners = new Map([["tool", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const s = proxy.sessions.get("conn-1");
  s.calls.length = MAX_COMPLETED_CALLS_PER_SESSION; // cheap stand-in for MAX_COMPLETED_CALLS_PER_SESSION genuinely-completed calls
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "tool", arguments: {} } });
  check(
    "completed-call-history-cap-refuses-further-admission",
    Boolean(resp.error && resp.error.code === -32000 && /already completed/.test(resp.error.message)),
    JSON.stringify(resp)
  );
  check("completed-call-history-cap-does-not-grow-past-the-cap", s.calls.length === MAX_COMPLETED_CALLS_PER_SESSION, String(s.calls.length));
  await proxy.closeConnection("conn-1", "test cleanup");
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

/* Round-1 fix-plan commit 6: getChainIntegrityFailure defaults to `() => null`
 * (never latched), mirroring isWriterClaimValid's own always-valid default -- every
 * existing test in this file that constructs a bare GatewayProxy (no chain-integrity
 * concern of its own) must stay unaffected by this commit. */
function getChainIntegrityFailureDefaultsToNeverLatchedSoBareProxiesAreUnaffected() {
  const dir = freshDir("chain-integrity-default");
  const proxy = makeProxy(dir, new Map(), [], new Map());
  let threw = null;
  try { proxy.openConnection("conn-1"); } catch (error) { threw = error; }
  check("chain-integrity-default-does-not-block-admission", threw === null, threw && threw.message);
  check("chain-integrity-default-session-actually-opened", proxy.sessions.has("conn-1"), "conn-1 missing from proxy.sessions");
}

/* Round-1 fix-plan commit 6: PRIMARY enforcement point. A latched chain-integrity
 * failure must refuse every NEW admission (mirroring stopAcceptingNewSessions'
 * own new-vs-existing split above) while never force-closing a session already open
 * before the latch fired -- belt-and-braces on top of the append-time check, not a
 * second drain mechanism. */
async function chainIntegrityLatchRefusesNewAdmissionButNotExisting() {
  const dir = freshDir("chain-integrity-latch");
  const conn = fakeConnection(async () => ({ ok: true }));
  let latched = null;
  const proxy = makeProxy(dir, new Map([["srv", conn]]), [], new Map(), { getChainIntegrityFailure: () => latched });
  proxy.openConnection("conn-1");

  latched = { status: "refuse", class: "tampered", reason: "test: genuine structural corruption at seq 2", at: "2026-09-16T00:00:00.000Z" };
  let threw = null;
  try { proxy.openConnection("conn-2"); } catch (error) { threw = error; }
  check("chain-integrity-latch-refuses-new-admission", threw && threw.code === "GATEWAY_CHAIN_INTEGRITY_FAILED", threw && threw.code);
  check(
    "chain-integrity-latch-error-names-the-reason-not-a-generic-message",
    threw && threw.message.includes("test: genuine structural corruption at seq 2") && threw.message.includes("class=tampered"),
    threw && threw.message
  );
  check("chain-integrity-latch-second-connection-never-published", !proxy.sessions.has("conn-2"), "conn-2 leaked into proxy.sessions despite the throw");

  const entry = await proxy.closeConnection("conn-1", "already-open session still finalizes despite the latch");
  check("chain-integrity-latch-does-not-force-close-existing-sessions", entry !== null, "existing session was not finalized");
}

/* Round-1 fix-plan commit 6: the naming rationale itself -- getChainIntegrityFailure
 * must be consulted for its DETAIL OBJECT (reason/class/at), not coerced to a bare
 * boolean, so the thrown error can actually name what happened. */
function chainIntegrityLatchCarriesTheDiagnosticDetailNotJustABoolean() {
  const dir = freshDir("chain-integrity-detail");
  const proxy = makeProxy(dir, new Map(), [], new Map(), {
    getChainIntegrityFailure: () => ({ status: "refuse", class: "sequence-gap", reason: "entry[4] seq=6 expected 5", at: "2026-09-16T01:02:03.000Z" }),
  });
  let threw = null;
  try { proxy.openConnection("conn-1"); } catch (error) { threw = error; }
  check(
    "chain-integrity-detail-message-includes-reason-class-and-timestamp",
    Boolean(threw) && threw.message.includes("entry[4] seq=6 expected 5") && threw.message.includes("class=sequence-gap") && threw.message.includes("2026-09-16T01:02:03.000Z"),
    threw && threw.message
  );
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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

  /* Codex PR #29 review round 8 "wait for notifications/initialized before admitting
   * tools": the "initialize" response alone must NOT be enough to unlock tools/list or
   * tools/call -- a conforming client's own subsequent "notifications/initialized" is
   * required first, matching the same rejection shape as a pre-initialize call. */
  const preNotifCall = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "echo", arguments: {} } });
  check("tools-call-after-initialize-but-before-notifications-initialized-rejected", preNotifCall.error !== undefined, JSON.stringify(preNotifCall));
  const preNotifList = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 7, method: "tools/list", params: {} });
  check("tools-list-after-initialize-but-before-notifications-initialized-rejected", preNotifList.error !== undefined, JSON.stringify(preNotifList));

  await sendInitializedNotification(proxy, "conn-1");

  const postInitCall = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "echo", arguments: {} } });
  check("tools-call-after-notifications-initialized-succeeds", postInitCall.result && postInitCall.result.ok === true, JSON.stringify(postInitCall));

  const repeatInit = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 5, method: "initialize", params: {} });
  check("repeated-initialize-rejected", repeatInit.error !== undefined, JSON.stringify(repeatInit));

  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #29 review round 8 "wait for notifications/initialized before admitting
 * tools": an initialize sent AS A NOTIFICATION (no "id") must not unlock tools either --
 * the client never received the selected protocol/capabilities in that case, so admitting
 * tools afterward would let it invoke a contract it was never shown. */
async function noIdInitializeDoesNotUnlockToolsWithoutNotification() {
  const dir = freshDir("init-notify-noid");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");

  const initResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", method: "initialize", params: {} });
  check("id-less-initialize-notification-produces-no-response", initResp === null, JSON.stringify(initResp));

  const callBeforeNotification = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: {} } });
  check("tools-call-after-id-less-initialize-but-before-notifications-initialized-rejected", callBeforeNotification.error !== undefined, JSON.stringify(callBeforeNotification));

  await sendInitializedNotification(proxy, "conn-1");
  const callAfterNotification = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } });
  check("tools-call-after-notifications-initialized-following-id-less-initialize-succeeds", callAfterNotification.result && callAfterNotification.result.ok === true, JSON.stringify(callAfterNotification));

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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-1");
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

/* Round-1 fix-round follow-up (2026-09-15, "anomaly cap tests and the WAL/disk-growth
 * follow-up ticket", tying back to the still-open 2026-09-14 Cluster H recommendation):
 * MAX_ANOMALIES_PER_SESSION (session.js) bounds session.anomalies -- the in-memory array
 * that becomes the sealed bundle's anomalies -- but proxy.js's blocked-retry path (the
 * "block" branch above) appends an ANOMALY event to the WAL UNCONDITIONALLY, every single
 * time it is hit, regardless of what session.recordAnomaly returned. A blocked-retry
 * attempt never goes through MAX_PENDING_CALLS_PER_SESSION or
 * MAX_COMPLETED_CALLS_PER_SESSION either -- it is rejected before ever being admitted as a
 * pending or completed call -- so nothing in this codebase bounds how many ANOMALY WAL
 * lines one connection can generate. Proves both halves directly against the real
 * dispatch path (not just session.js in isolation): the in-memory/sealed-bundle side
 * plateaus at the cap while the WAL keeps growing past it. This is deliberately NOT
 * treated as closing out the broader disk-growth risk -- see the WAL/disk-growth ticket
 * in KNOWN-LIMITATIONS.md; neither this event-count cap nor WAL rotation alone bounds
 * disk usage when event SIZE varies. */
async function blockedRetryAnomaliesAreUncappedInTheWalDespiteTheSessionCap() {
  const session = require(path.join(ROOT, "scripts", "gateway", "session.js"));
  const { MAX_ANOMALIES_PER_SESSION } = session;
  const dir = freshDir("anomaly-cap-vs-wal");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  // Keeps the original call in flight for the whole test, so every subsequent identical
  // call is blocked as an ambiguous retry rather than dispatched or admitted anywhere.
  const firstPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: { x: 1 } } });
  await new Promise((resolve) => setImmediate(resolve));

  const blockedAttempts = MAX_ANOMALIES_PER_SESSION + 5;
  for (let i = 0; i < blockedAttempts; i++) {
    const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 100 + i, method: "tools/call", params: { name: "slow", arguments: { x: 1 } } });
    if (!(resp && resp.error && resp.error.code === -32080)) {
      check("every-retry-in-this-loop-is-actually-blocked-as-ambiguous", false, `attempt ${i}: ${JSON.stringify(resp)}`);
      break;
    }
  }

  const s = proxy.sessions.get("conn-1");
  check(
    "session-side-anomalies-plateau-at-the-cap-plus-terminal-marker",
    Boolean(s) && s.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1,
    `length=${s && s.anomalies.length}, blockedAttempts=${blockedAttempts}`
  );

  const walAnomalyCount = recovery.readWalEvents(dir, "conn-1").filter((e) => e.type === "ANOMALY").length;
  check(
    "wal-anomaly-count-is-not-bounded-by-the-session-cap-and-matches-every-blocked-attempt",
    walAnomalyCount === blockedAttempts,
    `walAnomalyCount=${walAnomalyCount}, blockedAttempts=${blockedAttempts}, sessionCap=${MAX_ANOMALIES_PER_SESSION}`
  );
  check(
    "wal-anomaly-count-exceeds-what-the-session-cap-would-allow-if-it-applied-to-the-wal-too",
    walAnomalyCount > MAX_ANOMALIES_PER_SESSION + 1,
    `walAnomalyCount=${walAnomalyCount}`
  );

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
  await sendInitializedNotification(proxy, "conn-1");
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
  await sendInitializedNotification(proxy, "conn-2");
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
  await sendInitializedNotification(proxy, "conn-2");
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
  await sendInitializedNotification(proxy2, "conn-3");
  const afterResolve = await proxy2.handleMessage("conn-3", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "email", arguments: { to: "y" } } });
  check("tool-dispatches-normally-once-crashed-connection-resolved", Boolean(afterResolve && afterResolve.result && afterResolve.result.ok === true), JSON.stringify(afterResolve));
  await proxy.closeConnection("conn-2", "test cleanup");
  await proxy2.closeConnection("conn-3", "test cleanup");
}

/* Cluster A (cross-connection replay of a proven-completed call): a reconnecting agent
 * gets a brand-new connectionId, so its retry of "the same" logical operation computes a
 * DIFFERENT intentKey than its own crashed/closed predecessor connection's completed
 * call (intentKey is scoped to connectionId -- see computeIntentKey's own header).
 * Presenting the SAME caller idempotency key the original call carried must still
 * replay that real result rather than re-executing the downstream side effect. */
async function reconnectWithMatchingIdempotencyKeyReplaysCrossConnectionCompletedCall() {
  const dir = freshDir("cross-conn-replay");
  const conn = fakeConnectionCapturing(async () => ({ value: 7 }));
  const mergedTools = [{ name: "charge", server: "srv", schema: {} }];
  const toolOwners = new Map([["charge", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  const params = { name: "charge", arguments: { amount: 5 }, _meta: { idempotencyKey: "customer-key-1" } };

  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  await proxy.closeConnection("conn-1", "conn-1 done");

  // A brand-new connection (e.g. the agent reconnected after a crash) presents the SAME
  // idempotency key for the SAME logical operation.
  proxy.openConnection("conn-2");
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-2");
  const resp = await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  check("cross-connection-replay-returns-the-original-result", Boolean(resp && resp.result && resp.result.value === 7), JSON.stringify(resp));
  check("cross-connection-replay-does-not-redispatch-downstream", conn.calls.length === 1, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-2", "test cleanup");
}

/* The other half of the same fix: WITHOUT a matching (or any) idempotency key, a
 * reconnecting agent's call to the same tool+arguments is a genuinely new, independent
 * dispatch -- never silently collapsed onto an old connection's result just because the
 * arguments happen to match, mirroring the live same-connection rule exactly. */
async function reconnectWithoutMatchingIdempotencyKeyDispatchesIndependently() {
  const dir = freshDir("cross-conn-no-replay");
  let callCount = 0;
  const conn = fakeConnectionCapturing(async () => { callCount += 1; return { value: callCount }; });
  const mergedTools = [{ name: "charge", server: "srv", schema: {} }];
  const toolOwners = new Map([["charge", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  const params = { name: "charge", arguments: { amount: 5 } }; // no _meta.idempotencyKey

  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  await proxy.closeConnection("conn-1", "conn-1 done");

  proxy.openConnection("conn-2");
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-2");
  const resp = await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  check("cross-connection-without-key-dispatches-independently", Boolean(resp && resp.result && resp.result.value === 2), JSON.stringify(resp));
  check("cross-connection-without-key-redispatches-downstream", conn.calls.length === 2, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-2", "test cleanup");
}

/* "Extend the existing quarantine mechanism ... to also cover this retained-completed-
 * intent case": a tool quarantined because some OTHER crashed connection left it with an
 * unresolved outcome must stay blocked even for a reconnecting caller that also happens
 * to present a valid, matching idempotency key for an unrelated, already-completed
 * signature on that same tool -- the retained-signature replay path must never bypass
 * the quarantine gate. */
async function retainedSignatureReplayStillBlockedByQuarantine() {
  const dir = freshDir("cross-conn-quarantine");
  const conn = fakeConnectionCapturing(async () => ({ value: 1 }));
  const mergedTools = [{ name: "email", server: "srv", schema: {} }];
  const toolOwners = new Map([["email", "srv"]]);
  const params = { name: "email", arguments: { to: "a" }, _meta: { idempotencyKey: "email-key-1" } };

  // First, a real completed call on its own connection -- this is what populates the
  // cross-connection retained-signature store the quarantine gate must still override.
  const proxy1 = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy1.openConnection("conn-1");
  await proxy1.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy1, "conn-1");
  await proxy1.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  await proxy1.closeConnection("conn-1", "conn-1 done");

  // Now simulate a DIFFERENT, still-crashed connection leaving this exact tool
  // quarantined (an unresolved intent for the SAME tool, different arguments -- the
  // quarantine check is scoped to the tool, not the arguments; see proxy.js's own doc
  // comment on it).
  const staleIntentKey = recovery.computeIntentKey("crashed-conn", "email", { to: "z" });
  recovery.createIntentIfAbsent(dir, staleIntentKey, {
    connection_id: "crashed-conn",
    tool: "email",
    arguments: { to: "z" },
    state: "dispatched",
    dispatched_at: Date.now(),
  });
  const proxy2 = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    pendingOperatorReviewConnections: ["crashed-conn"],
  });
  proxy2.openConnection("conn-2");
  await proxy2.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy2, "conn-2");
  const resp = await proxy2.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params });
  check("quarantine-blocks-even-a-matching-retained-signature-replay", Boolean(resp && resp.error && resp.error.code === -32082), JSON.stringify(resp));
  check("quarantine-blocks-retained-signature-replay-without-redispatch", conn.calls.length === 1, JSON.stringify(conn.calls)); // only conn-1's original call
  await proxy2.closeConnection("conn-2", "test cleanup");
}

/* Codex PR #33 review "undo the fence when CALL_START persistence fails": the intent is
 * created (dispatched) before this WAL append -- if the append itself fails (e.g. a full
 * disk), the call never actually reaches conn.call(). Without a rollback, the intent
 * stays "dispatched" forever (every retry permanently blocked) and, worse, the exception
 * used to escape handleMessage entirely, breaking its documented "never throws" contract.
 *
 * Round-2 fix pass update: this append failure now also poisons the CONNECTION (see
 * poisonWalOnFailure above), per docs/contracts/wal-append-failure-semantics.md (C1 SS2)
 * -- "the caller should treat the refusal exactly like a second append failure," which
 * for a retry on the SAME connection means every subsequent appendWalEvent attempt is
 * refused too, not just this one intent's own fence. "Stays retryable" therefore now
 * means retryable on a fresh connection (close and reopen, per the poisoned error's own
 * wording), not a bare retry on the same, now-poisoned one -- this test asserts both. */
async function callStartWalAppendFailureRollsBackAndStaysRetryable() {
  const dir = freshDir("call-start-wal-failure");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");

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

  // Round-2 fix pass: a bare retry on the SAME (now-poisoned) connection must be
  // refused, not silently allowed through onto a possibly-torn WAL line.
  const sameConnRetry = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  check(
    "call-start-wal-failure-retry-on-the-same-connection-is-refused-poisoned",
    Boolean(sameConnRetry && sameConnRetry.error && /poisoned/i.test(sameConnRetry.error.message)),
    JSON.stringify(sameConnRetry)
  );
  check("call-start-wal-failure-retry-on-the-same-connection-did-not-dispatch", conn.calls.length === 0, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");

  // A fresh connection (close-and-reopen, exactly as the poisoned error's own wording
  // instructs) gets its own fresh WAL and dispatches normally.
  proxy.openConnection("conn-2");
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-2");
  const freshConnRetry = await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  check("call-start-wal-failure-retry-on-a-fresh-connection-dispatches-normally", Boolean(freshConnRetry && freshConnRetry.result && freshConnRetry.result.ok === true), JSON.stringify(freshConnRetry));
  await proxy.closeConnection("conn-2", "test cleanup");
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
  await sendInitializedNotification(proxy, "conn-1");
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

/* CodeRabbit PR #33 review "guard this WAL append the same way the CALL_START append is
 * guarded": the ANOMALY append on a blocked-retry path (GATEWAY_AMBIGUOUS_RETRY etc.) was
 * unguarded, unlike CALL_START's own established pattern -- a WAL failure here used to
 * escape handleMessage entirely instead of still returning the block response. */
async function anomalyWalAppendFailureDoesNotEscapeHandleMessage() {
  const dir = freshDir("anomaly-wal-failure");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const firstPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: { a: 1 } } });
  await new Promise((resolve) => setImmediate(resolve));

  const realAppendWalEvent = recovery.appendWalEvent;
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type === "ANOMALY") throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    return realAppendWalEvent(...args);
  };
  let resp, threw = null;
  try {
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "slow", arguments: { a: 1 } } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("anomaly-wal-failure-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("anomaly-wal-failure-still-returns-the-block-response", Boolean(resp && resp.error && resp.error.code === -32080), JSON.stringify(resp));
  /* Round-1 fix-round follow-up (2026-09-15): settle, with a test rather than an
   * assumption, whether session.recordAnomaly consumes the MAX_ANOMALIES_PER_SESSION
   * budget BEFORE this path's WAL append (and its outcome) or after -- prior review
   * rounds disagreed on this. proxy.js calls session.recordAnomaly(...) unconditionally,
   * THEN attempts the (here, deliberately failing) WAL append in its own try/catch --
   * so the in-memory/sealed-bundle accounting must already be done by the time the WAL
   * append is even attempted, independent of whether that append succeeds. */
  const sAfterWalFailure = proxy.sessions.get("conn-1");
  check(
    "anomaly-budget-was-consumed-in-memory-before-the-failed-wal-append-was-even-attempted",
    Boolean(sAfterWalFailure) && sAfterWalFailure.anomalies.length === 1 && sAfterWalFailure.anomalies[0].kind === "GATEWAY_AMBIGUOUS_RETRY",
    JSON.stringify(sAfterWalFailure && sAfterWalFailure.anomalies)
  );
  resolveCall({ ok: true });
  await firstPromise;
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* CodeRabbit PR #33 review "add a not_executed branch to the live dispatch guard": an
 * intent an operator confirmed via recovery-resolve --confirmed not-executed used to fall
 * through to the generic "could not establish a durable dispatch intent" AMBIGUOUS_RETRY
 * after two wasted attempts, instead of a response that reflects what actually happened. */
async function notExecutedIntentReturnsDedicatedBlockCode() {
  const dir = freshDir("not-executed-branch");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "email", server: "srv", schema: {} }];
  const toolOwners = new Map([["email", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const intentKey = recovery.computeIntentKey("conn-1", "email", { to: "x" });
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-1", tool: "email", arguments: { to: "x" }, state: "dispatched", dispatched_at: Date.now() });
  recovery.resolveIntentNotExecuted(dir, intentKey);
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "email", arguments: { to: "x" } } });
  check("not-executed-intent-returns-dedicated-code", Boolean(resp && resp.error && resp.error.code === -32084), JSON.stringify(resp));
  check("not-executed-intent-did-not-dispatch-downstream", conn.calls.length === 0, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #33 review "reject duplicate request IDs before creating intents": an agent
 * reusing an in-flight JSON-RPC id for a genuinely different operation used to get a
 * durable "dispatched" intent created BEFORE session.recordCallStart's own duplicate-id
 * check ran (and threw, uncaught) -- orphaning that intent forever for a call that never
 * actually dispatched. */
async function duplicateJsonRpcIdRejectedBeforeIntentCreated() {
  const dir = freshDir("duplicate-id");
  let resolveFirst;
  const conn = fakeConnectionCapturing((method, params) => {
    if (params && params.name === "slow") return new Promise((resolve) => { resolveFirst = resolve; });
    return Promise.resolve({ ok: true });
  });
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }, { name: "other", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"], ["other", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const firstPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: {} } });
  await new Promise((resolve) => setImmediate(resolve));

  let resp, threw = null;
  try {
    // Same id (1) reused for a DIFFERENT tool while the first is still pending.
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "other", arguments: {} } });
  } catch (error) {
    threw = error;
  }
  check("duplicate-id-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("duplicate-id-rejected-with-a-jsonrpc-error", Boolean(resp && resp.error), JSON.stringify(resp));
  check("duplicate-id-did-not-dispatch-the-second-call", conn.calls.length === 1, JSON.stringify(conn.calls));
  const otherIntentKey = recovery.computeIntentKey("conn-1", "other", {});
  check("duplicate-id-did-not-create-an-orphaned-intent", recovery.readIntent(dir, otherIntentKey) === null, "intent unexpectedly present");
  resolveFirst({ ok: true });
  await firstPromise;
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* CodeRabbit/Codex PR #33 review "restore the prior completed intent when CALL_START WAL
 * persistence fails": when a completed intent is superseded by a new, independent dispatch
 * (no matching idempotency key) and THAT dispatch's own CALL_START WAL append then fails,
 * the rollback used to unconditionally delete the intent -- discarding the earlier
 * generation's real cached result. A later request carrying the ORIGINAL idempotency key
 * would then find no record and dispatch again instead of replaying it. */
async function supersedeCallStartWalFailureRestoresPriorCompletedIntent() {
  const dir = freshDir("supersede-wal-failure");
  const conn = fakeConnectionCapturing(async () => ({ value: 1 }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const originalParams = { name: "echo", arguments: { a: 1 }, _meta: { idempotencyKey: "first-attempt" } };
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: originalParams });
  const intentKey = recovery.computeIntentKey("conn-1", "echo", { a: 1 });
  const beforeSupersede = recovery.readIntent(dir, intentKey);
  check("supersede-setup-first-call-completed", Boolean(beforeSupersede) && beforeSupersede.state === "completed" && beforeSupersede.idempotency_key === "first-attempt", JSON.stringify(beforeSupersede));

  const realAppendWalEvent = recovery.appendWalEvent;
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type === "CALL_START") throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    return realAppendWalEvent(...args);
  };
  let resp, threw = null;
  try {
    // No idempotencyKey -> this is treated as a new, independent dispatch that supersedes
    // the completed record above, generation 2 -- whose own CALL_START append then fails.
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("supersede-wal-failure-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("supersede-wal-failure-returns-a-retryable-jsonrpc-error", Boolean(resp && resp.error && resp.error.code === -32000), JSON.stringify(resp));
  check("supersede-wal-failure-did-not-redispatch-downstream", conn.calls.length === 1, JSON.stringify(conn.calls));
  const restored = recovery.readIntent(dir, intentKey);
  check(
    "supersede-wal-failure-restored-the-original-completed-record",
    Boolean(restored) && restored.state === "completed" && restored.idempotency_key === "first-attempt" && restored.generation === 1 && restored.cached_result && restored.cached_result.value === 1,
    JSON.stringify(restored)
  );
  // The original idempotency key must still replay the FIRST call's cached result, not
  // dispatch a third time.
  const replay = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 3, method: "tools/call", params: originalParams });
  check("supersede-wal-failure-original-key-still-replays-not-redispatches", conn.calls.length === 1 && Boolean(replay && replay.result && replay.result.value === 1), JSON.stringify({ calls: conn.calls, replay }));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* CodeRabbit PR #33 review "fail closed when the quarantine scan cannot read an intent":
 * listAllIntents propagating a read failure for ANY intent file on disk (not just the one
 * relevant to this dispatch) used to reject handleMessage with a generic -32603 instead of
 * this quarantine check's own documented -32082, and the tool was not actually blocked. */
async function quarantineScanFailureFailsClosed() {
  const dir = freshDir("quarantine-scan-failure");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "email", server: "srv", schema: {} }];
  const toolOwners = new Map([["email", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    pendingOperatorReviewConnections: ["crashed-conn"],
  });
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");

  const realListAllIntents = recovery.listAllIntents;
  recovery.listAllIntents = () => { throw Object.assign(new Error("simulated corrupt intent"), { code: "GATEWAY_RECOVERY_INTENT_CORRUPT" }); };
  let resp, threw = null;
  try {
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "email", arguments: { to: "x" } } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.listAllIntents = realListAllIntents;
  }
  check("quarantine-scan-failure-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("quarantine-scan-failure-fails-closed-with-quarantine-code", Boolean(resp && resp.error && resp.error.code === -32082), JSON.stringify(resp));
  check("quarantine-scan-failure-did-not-dispatch-downstream", conn.calls.length === 0, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #33 review "block dispatch when a retained signature is unreadable": this catch
 * claimed to fail closed but converted the failure to `null` -- a CACHE MISS that fell
 * straight through to a fresh dispatched intent and a real downstream call. An EIO or a
 * corrupt signature file therefore repeated an already-completed side effect at exactly the
 * moment its deduplication evidence could not be verified. */
async function unreadableRetainedSignatureBlocksInsteadOfDispatching() {
  const dir = freshDir("retained-signature-unreadable");
  const conn = fakeConnectionCapturing(async () => ({ value: 7 }));
  const mergedTools = [{ name: "charge", server: "srv", schema: {} }];
  const toolOwners = new Map([["charge", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");

  const realReadCompletedSignature = recovery.readCompletedSignature;
  recovery.readCompletedSignature = () => {
    throw Object.assign(new Error("EIO: simulated unreadable retained signature"), { code: "GATEWAY_RECOVERY_SIGNATURE_UNREADABLE" });
  };
  let resp, threw = null;
  try {
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "charge", arguments: { amount: 5 }, _meta: { idempotencyKey: "customer-key-1" } } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.readCompletedSignature = realReadCompletedSignature;
  }
  check("unreadable-retained-signature-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("unreadable-retained-signature-fails-closed-with-its-own-code", Boolean(resp && resp.error && resp.error.code === -32083), JSON.stringify(resp));
  check("unreadable-retained-signature-did-not-dispatch-downstream", conn.calls.length === 0, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #33 review "make the post-fence diagnostic non-throwing": on the supersede path
 * the durable intent is already flipped to "dispatched" before this diagnostic is logged.
 * A caller-supplied logger that throws there was caught by the surrounding block's catch
 * and rethrown, aborting before recordCallStart / the CALL_START WAL append / the
 * downstream dispatch -- leaving a false in-flight fence that blocks every future retry of
 * an effect that never occurred. */
async function throwingLoggerOnTheSupersedePathDoesNotStrandTheFence() {
  const dir = freshDir("supersede-logger-throws");
  let callCount = 0;
  const conn = fakeConnectionCapturing(async () => { callCount += 1; return { value: callCount }; });
  const mergedTools = [{ name: "charge", server: "srv", schema: {} }];
  const toolOwners = new Map([["charge", "srv"]]);
  let loggerThrows = 0;
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    log: (payload) => {
      if (typeof payload === "string" && payload.includes("gateway_intent_signature_reused_without_key")) {
        loggerThrows += 1;
        throw new Error("simulated caller-supplied logger failure");
      }
    },
  });
  const args = { amount: 5 };

  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "charge", arguments: args, _meta: { idempotencyKey: "key-1" } } });

  // Same connection, same tool+arguments, NO idempotency key -> the supersede path, which
  // is where the post-fence diagnostic (and the throwing logger) lives.
  const resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "charge", arguments: args } });
  check("supersede-logger-throw-was-actually-exercised", loggerThrows === 1, String(loggerThrows));
  check("supersede-logger-throw-does-not-abort-the-dispatch", Boolean(resp && resp.result && resp.result.value === 2), JSON.stringify(resp));
  check("supersede-logger-throw-still-reaches-downstream", conn.calls.length === 2, JSON.stringify(conn.calls));
  const intentKey = recovery.computeIntentKey("conn-1", "charge", args);
  const intent = recovery.readIntent(dir, intentKey);
  check("supersede-logger-throw-leaves-no-false-in-flight-fence", Boolean(intent) && intent.state === "completed", JSON.stringify(intent));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #33 review "commit initialization only after its WAL event succeeds": a WAL
 * failure on the INITIALIZE append used to be unguarded (escaping handleMessage) AND ran
 * after agentInitialized was already flipped true, so a retry would be rejected as a
 * repeat initialize even though it was never durably recorded. */
async function initializeWalFailureDoesNotEscapeAndRollsBack() {
  const dir = freshDir("initialize-wal-failure");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");

  const realAppendWalEvent = recovery.appendWalEvent;
  let failNext = true;
  recovery.appendWalEvent = (...args) => {
    if (failNext && args[2] && args[2].type === "INITIALIZE") {
      failNext = false;
      throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    }
    return realAppendWalEvent(...args);
  };
  let resp, threw = null;
  try {
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("initialize-wal-failure-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("initialize-wal-failure-returns-a-retryable-jsonrpc-error", Boolean(resp && resp.error && resp.error.code === -32000), JSON.stringify(resp));
  check("initialize-wal-failure-did-not-flip-agentInitialized", proxy.agentInitialized.get("conn-1") === "none", `agentInitialized unexpectedly advanced: ${proxy.agentInitialized.get("conn-1")}`);

  // Round-2 fix pass: this append failure now also poisons the CONNECTION (see
  // poisonWalOnFailure above) -- a bare retry of initialize on the SAME connection must
  // be refused too, not silently allowed through onto a possibly-torn WAL line.
  const sameConnRetry = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  check(
    "initialize-retry-on-the-same-connection-is-refused-poisoned",
    Boolean(sameConnRetry && sameConnRetry.error && /poisoned/i.test(sameConnRetry.error.message)),
    JSON.stringify(sameConnRetry)
  );
  await proxy.closeConnection("conn-1", "test cleanup");

  // A fresh connection (close-and-reopen) gets its own fresh WAL and initializes
  // normally.
  proxy.openConnection("conn-2");
  const freshConnRetry = await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  check("initialize-retry-on-a-fresh-connection-succeeds-normally", Boolean(freshConnRetry && freshConnRetry.result && freshConnRetry.result.protocolVersion), JSON.stringify(freshConnRetry));
  await proxy.closeConnection("conn-2", "test cleanup");
}

/* Codex PR #33 review "roll back session publication when its first WAL write fails": a
 * SESSION_START WAL failure in openConnection used to be unguarded and ran AFTER the
 * session was already published into this.sessions/agentInitialized -- leaving an
 * unreachable "ghost" session counted by openSessionCount() even though the caller (who
 * never gets a usable connectionId back) saw openConnection throw. */
async function openConnectionWalFailureDoesNotPublishGhostSession() {
  const dir = freshDir("open-connection-wal-failure");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);

  const realAppendWalEvent = recovery.appendWalEvent;
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type === "SESSION_START") throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    return realAppendWalEvent(...args);
  };
  let threw = null;
  try {
    proxy.openConnection("conn-1");
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("open-connection-wal-failure-still-throws-to-its-caller", threw !== null, "openConnection did not throw");
  check("open-connection-wal-failure-did-not-publish-a-ghost-session", proxy.openSessionCount() === 0, `openSessionCount()=${proxy.openSessionCount()}`);
  check("open-connection-wal-failure-did-not-set-agentInitialized", proxy.agentInitialized.has("conn-1") === false, "agentInitialized unexpectedly set");

  // A subsequent real openConnection for the SAME connectionId must work normally --
  // proof there is no leftover half-published state blocking it.
  proxy.openConnection("conn-1");
  check("open-connection-retry-succeeds-normally-afterward", proxy.openSessionCount() === 1, `openSessionCount()=${proxy.openSessionCount()}`);
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Part of the same WAL-append-guarding cluster as CALL_START/INITIALIZE/ANOMALY above: the
 * CALL_RESULT append (after a call has ALREADY completed downstream, with no "don't
 * dispatch" option left) must be best-effort and never escape handleMessage -- the agent
 * is still owed its real result even if this durability write fails. */
async function callResultWalFailureDoesNotEscapeHandleMessage() {
  const dir = freshDir("call-result-wal-failure");
  const conn = fakeConnectionCapturing(async () => ({ value: 99 }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");

  const realAppendWalEvent = recovery.appendWalEvent;
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type === "CALL_RESULT") throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    return realAppendWalEvent(...args);
  };
  let resp, threw = null;
  try {
    resp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: {} } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("call-result-wal-failure-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("call-result-wal-failure-still-returns-the-real-result", Boolean(resp && resp.result && resp.result.value === 99), JSON.stringify(resp));
  const intentKey = recovery.computeIntentKey("conn-1", "echo", {});
  const intent = recovery.readIntent(dir, intentKey);
  check("call-result-wal-failure-intent-still-marked-completed", Boolean(intent) && intent.state === "completed", JSON.stringify(intent));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* Codex PR #29 review round 3 "retain sessions when persistence fails": closeConnection
 * used to discard the fully-sealed bundle the moment chain.appendSession threw, leaving
 * only a summary log line. Two connections given identical initialize params, an
 * identical call count, AND (Cluster B: session_id is now folded into bundle_id -- see
 * session.js#createSession/gsa-mcp-shim.js#sealBoundaryBundle) the SAME explicit
 * session_id deterministically produce the same bundle_id, so the second one's real
 * chain.appendSession call genuinely throws GATEWAY_BUNDLE_ID_COLLISION here rather than
 * a synthetic/forced failure. Forcing an identical session_id across two otherwise-
 * independent connections is now the only way to reproduce that collision on purpose
 * (a real, live connection always gets its own random one) -- exactly mirroring what
 * "two connections with identical content" meant before session_id existed. */

// ---------------------------------------------------------------------------
// Round-2 fix pass (2026-09-16): closing commit 5's WAL-poison enforcement gap.
//
// The independent verify pass on commit 5 (b14bf35c) found that gateway.js:142/
// session.js:88 document a connection-wide contract -- once an appendWalEvent call
// fails for a connection, `s.walPoisoned` is set and EVERY later appendWalEvent
// attempt on that same connection must be refused before touching the filesystem
// (docs/contracts/wal-append-failure-semantics.md, C1 SS2-3) -- but that contract was
// only actually enforced on gateway.js's own downstream-initiated sampling-forward
// path. proxy.js's own appendWalEvent call sites (SESSION_START/INITIALIZE/ANOMALY/
// CALL_START/CALL_RESULT/CLOSING) neither checked nor set it, so an agent-initiated
// call could still dispatch onto (and CLOSING would unconditionally append onto) a
// connection's own already-poisoned or already-torn WAL. The four tests below cover:
// (1) proxy.js's own append failures now actually SET s.walPoisoned (not just check
// it); (2) an already-poisoned connection refuses a brand-new CALL_START before
// touching the filesystem, attested as an anomaly; (3) the CLOSING append -- the
// guaranteed-violation path the verify pass named explicitly, since every connection
// eventually closes -- is skipped and attested rather than unconditionally attempted;
// (4) the fail-open CALL_RESULT path still returns the agent's real result when
// skipping its own append due to poisoning, attested the same way.
// ---------------------------------------------------------------------------

/* Closes the other half of the gap: not just gating on s.walPoisoned before an append,
 * but proxy.js's OWN append failures must actually SET it (matching gateway.js#
 * poisonWalOnFailure's identical contract), so a second, otherwise-healthy call on the
 * SAME now-poisoned connection is refused too, without the filesystem ever being
 * touched a second time. */
async function ownAppendFailurePoisonsConnectionForEverySubsequentCallSite() {
  const dir = freshDir("own-failure-poisons");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");

  const realAppendWalEvent = recovery.appendWalEvent;
  let failNextCallStart = true;
  recovery.appendWalEvent = (...args) => {
    if (failNextCallStart && args[2] && args[2].type === "CALL_START") {
      failNextCallStart = false;
      throw Object.assign(new Error("simulated ENOSPC"), { code: "ENOSPC" });
    }
    return realAppendWalEvent(...args);
  };
  let firstResp;
  try {
    firstResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { a: 1 } } });
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("own-failure-first-call-refused-as-not-dispatched", Boolean(firstResp && firstResp.error && firstResp.error.code === -32000), JSON.stringify(firstResp));

  const s = proxy.sessions.get("conn-1");
  check("own-CALL_START-failure-sets-walPoisoned-on-the-session", Boolean(s.walPoisoned) && s.walPoisoned.reason === "simulated ENOSPC", JSON.stringify(s.walPoisoned));

  const attemptedTypes = [];
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type) attemptedTypes.push(args[2].type);
    return realAppendWalEvent(...args);
  };
  let secondResp, threw = null;
  try {
    secondResp = await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { a: 2 } } });
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("own-failure-second-call-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("own-failure-second-call-refused-via-the-poisoned-gate-not-a-fresh-append-attempt", !attemptedTypes.includes("CALL_START"), JSON.stringify(attemptedTypes));
  check("own-failure-second-call-returns-a-poisoned-wal-error", Boolean(secondResp && secondResp.error && /poisoned/i.test(secondResp.error.message)), JSON.stringify(secondResp));
  check("own-failure-connection-never-dispatched-downstream-at-all", conn.calls.length === 0, JSON.stringify(conn.calls));
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* An already-poisoned connection must refuse a brand-new tools/call's CALL_START append
 * before ever touching the filesystem -- treated exactly like a caught append failure
 * (rollback pendingCalls/intent, attest an anomaly, return "not dispatched -- safe to
 * retry"), never silently dispatched onto a possibly-torn WAL line. */
async function poisonedConnectionRefusesNewCallStartAndAttestsSkip() {
  const dir = freshDir("poisoned-call-start");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");

  const s = proxy.sessions.get("conn-1");
  s.walPoisoned = { reason: "simulated earlier ENOSPC", at: Date.now() };

  const realAppendWalEvent = recovery.appendWalEvent;
  const attemptedTypes = [];
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type) attemptedTypes.push(args[2].type);
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
  check("poisoned-call-start-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("poisoned-call-start-returns-a-poisoned-wal-error", Boolean(resp && resp.error && resp.error.code === -32000 && /poisoned/i.test(resp.error.message)), JSON.stringify(resp));
  check("poisoned-call-start-never-attempted-the-CALL_START-append", !attemptedTypes.includes("CALL_START"), JSON.stringify(attemptedTypes));
  check("poisoned-call-start-did-not-dispatch-downstream", conn.calls.length === 0, JSON.stringify(conn.calls));
  const intentKey = recovery.computeIntentKey("conn-1", "echo", { a: 1 });
  check("poisoned-call-start-did-not-leave-an-orphaned-intent", recovery.readIntent(dir, intentKey) === null, "intent unexpectedly present");
  check(
    "poisoned-call-start-skip-is-attested-as-an-anomaly",
    s.anomalies.some((a) => a.kind === "GATEWAY_RECOVERY_WAL_APPEND_SKIPPED_POISONED" && a.tool === "echo"),
    JSON.stringify(s.anomalies)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* The fail-OPEN CALL_RESULT path (the downstream call has already genuinely completed --
 * there is no "don't return the result" option left) must still skip its own append when
 * the connection is poisoned, attest the skip, and still hand back the real result. */
async function poisonedConnectionSkipsCallResultAppendButStillReturnsResult() {
  const dir = freshDir("poisoned-call-result");
  let resolveCall;
  const conn = fakeConnectionCapturing(() => new Promise((resolve) => { resolveCall = resolve; }));
  const mergedTools = [{ name: "slow", server: "srv", schema: {} }];
  const toolOwners = new Map([["slow", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const callPromise = proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: {} } });
  await new Promise((resolve) => setImmediate(resolve));

  // Poison mid-flight (after this call's own CALL_START already durably appended, before
  // its CALL_RESULT does) -- simulating an earlier failed append on this connection
  // (e.g. a concurrent downstream-initiated sampling forward via gateway.js) without
  // needing to force a real filesystem error on this specific append.
  const s = proxy.sessions.get("conn-1");
  s.walPoisoned = { reason: "simulated mid-flight poisoning", at: Date.now() };

  const realAppendWalEvent = recovery.appendWalEvent;
  const attemptedTypes = [];
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type) attemptedTypes.push(args[2].type);
    return realAppendWalEvent(...args);
  };
  resolveCall({ value: 7 });
  let resp, threw = null;
  try {
    resp = await callPromise;
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }
  check("poisoned-call-result-does-not-escape-handleMessage", threw === null, threw && threw.message);
  check("poisoned-call-result-still-returns-the-real-result", Boolean(resp && resp.result && resp.result.value === 7), JSON.stringify(resp));
  check("poisoned-call-result-never-attempted-the-CALL_RESULT-append", !attemptedTypes.includes("CALL_RESULT"), JSON.stringify(attemptedTypes));
  check(
    "poisoned-call-result-skip-is-attested-as-an-anomaly",
    s.anomalies.some((a) => a.kind === "GATEWAY_RECOVERY_WAL_APPEND_SKIPPED_POISONED"),
    JSON.stringify(s.anomalies)
  );
  await proxy.closeConnection("conn-1", "test cleanup");
}

/* The explicitly-required regression: the independent verify pass on commit 5 named
 * closeConnection's CLOSING append as a GUARANTEED violation path, since it ran with no
 * guard at all and every open connection eventually closes. Poisons a connection's WAL,
 * drives it through a real close, and asserts the CLOSING append is never attempted (not
 * attempted-and-caught -- refused before touching the filesystem, per C1 SS2-3) and that
 * the skip is attested in the sealed bundle's own anomaly list, not silently swallowed. */
async function poisonedConnectionSkipsClosingAppendAndAttestsIt() {
  const dir = freshDir("poisoned-closing");
  const conn = fakeConnectionCapturing(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners);
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 0, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: {} } });

  // Poison the connection's WAL exactly the way a real appendWalEvent failure would
  // (poisonWalOnFailure's own {reason, at} shape), simulating an earlier failure on this
  // connection without needing to force a real filesystem error at close time itself.
  const s = proxy.sessions.get("conn-1");
  s.walPoisoned = { reason: "simulated earlier ENOSPC", at: Date.now() };

  const realAppendWalEvent = recovery.appendWalEvent;
  const attemptedTypes = [];
  recovery.appendWalEvent = (...args) => {
    if (args[2] && args[2].type) attemptedTypes.push(args[2].type);
    return realAppendWalEvent(...args);
  };
  let entry, threw = null;
  try {
    entry = await proxy.closeConnection("conn-1", "test cleanup");
  } catch (error) {
    threw = error;
  } finally {
    recovery.appendWalEvent = realAppendWalEvent;
  }

  check("poisoned-closing-does-not-escape-closeConnection", threw === null, threw && threw.message);
  check("poisoned-closing-still-seals-and-appends-the-session", Boolean(entry), "closeConnection returned null");
  check("poisoned-closing-never-attempts-the-CLOSING-append-at-all", !attemptedTypes.includes("CLOSING"), JSON.stringify(attemptedTypes));
  // `s` is the same in-memory session object closeConnection operated on (only removed
  // from proxy.sessions, never replaced) -- session.recordAnomaly's push onto s.anomalies
  // happens before finalizeSession seals it, so this is exactly what the sealed bundle's
  // own decision_record.md "## Anomalies" section (scripts/gsa-mcp-shim.js) attests from.
  check(
    "poisoned-closing-skip-is-attested-as-an-anomaly",
    s.anomalies.some((a) => a.kind === "GATEWAY_RECOVERY_WAL_APPEND_SKIPPED_POISONED" && a.detail === "simulated earlier ENOSPC"),
    JSON.stringify(s.anomalies)
  );
}

async function persistenceFailureQuarantinesSealedBundle() {
  const dir = freshDir("quarantine");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const sealFailures = [];
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    onSealFailure: (s, error) => sealFailures.push(error),
  });
  const forcedSharedSessionId = "forced-shared-session-id-for-collision-test";

  proxy.openConnection("conn-1", { sessionId: forcedSharedSessionId });
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "x", version: "1" } } });
  await sendInitializedNotification(proxy, "conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } });
  const entry1 = await proxy.closeConnection("conn-1", "test cleanup");
  check("quarantine-setup-first-append-succeeds", Boolean(entry1 && typeof entry1.bundle_id === "string"), JSON.stringify(entry1));

  proxy.openConnection("conn-2", { sessionId: forcedSharedSessionId });
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "x", version: "1" } } });
  await sendInitializedNotification(proxy, "conn-2");
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

/* Cluster C: onClaimLost (gateway.js) only calls proxy.stopAcceptingNewSessions() --
 * an already-open session is deliberately left alone to finish and finalize (SS7). This
 * covers the narrower fix: closeConnection must re-check isWriterClaimValid()
 * synchronously immediately before chain.appendSession, and refuse to append (quarantine
 * instead) if the claim is no longer valid at THAT moment -- not just at the moment
 * claim-loss was first detected. */
async function writerClaimRevalidatedImmediatelyBeforeAppend() {
  const dir = freshDir("writer-claim-append");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const sealFailures = [];
  let claimValid = true;
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners, {
    onSealFailure: (s, error) => sealFailures.push(error),
    isWriterClaimValid: () => claimValid,
  });

  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "x", version: "1" } } });
  await sendInitializedNotification(proxy, "conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } });
  // Simulate the claim being lost/stolen by a replacement writer AFTER this session
  // opened (and even after it ran its call) but before it happens to finalize --
  // exactly the window onClaimLost's own "in-flight sessions are left alone" comment
  // describes.
  claimValid = false;
  const entry = await proxy.closeConnection("conn-1", "test cleanup");
  check("append-refused-when-writer-claim-invalid-at-close-time", entry === null, JSON.stringify(entry));
  check(
    "refused-append-invokes-onSealFailure-with-claim-lost-code",
    sealFailures.length === 1 && sealFailures[0].code === "GATEWAY_WRITER_CLAIM_LOST_AT_APPEND",
    JSON.stringify(sealFailures.map((e) => e && e.code))
  );
  const quarantinedTo = sealFailures[0] && sealFailures[0].quarantinedTo;
  check("claim-lost-append-quarantines-sealed-bundle-for-recovery", typeof quarantinedTo === "string" && fs.existsSync(quarantinedTo), String(quarantinedTo));
  check("no-chain-entry-was-actually-written", chain.readHead(dir) === null, JSON.stringify(chain.readHead(dir)));

  // A session opened AFTER the claim is valid again finalizes normally -- this is a
  // per-append check, not a permanent proxy-wide latch.
  claimValid = true;
  proxy.openConnection("conn-2");
  await proxy.handleMessage("conn-2", { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "y", version: "1" } } });
  const entry2 = await proxy.closeConnection("conn-2", "test cleanup");
  check("append-succeeds-once-writer-claim-is-valid-again", Boolean(entry2 && typeof entry2.bundle_id === "string"), JSON.stringify(entry2));
}

/* Default behavior (no isWriterClaimValid passed, e.g. every other test in this suite,
 * and any production caller that hasn't wired a writer-claim at all): appends must not
 * be refused. Mirrors onSessionFinalized/onSealFailure's own default-no-op contract. */
async function writerClaimCheckDefaultsToValidWhenNotProvided() {
  const dir = freshDir("writer-claim-default");
  const conn = fakeConnection(async () => ({ ok: true }));
  const mergedTools = [{ name: "echo", server: "srv", schema: {} }];
  const toolOwners = new Map([["echo", "srv"]]);
  const proxy = makeProxy(dir, new Map([["srv", conn]]), mergedTools, toolOwners); // no isWriterClaimValid
  proxy.openConnection("conn-1");
  await proxy.handleMessage("conn-1", { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await sendInitializedNotification(proxy, "conn-1");
  const entry = await proxy.closeConnection("conn-1", "test cleanup");
  check("append-not-refused-when-no-writer-claim-check-configured", Boolean(entry && typeof entry.bundle_id === "string"), JSON.stringify(entry));
}

async function main() {
  await multipleDownstreamAttribution();
  await unknownToolRejected();
  await concurrentAgentsIndependentSessions();
  await downstreamDisconnectMarksErrorNotCrash();
  await malformedDownstreamResponseFailsClosedPerCall();
  await connectionCloseWithPendingCallsMarksDisconnected();
  await downstreamDisconnectEmitsCompletionLog();
  await completedCallHistoryCapped();
  await stopAcceptingNewSessionsRefusesNewButNotExisting();
  getChainIntegrityFailureDefaultsToNeverLatchedSoBareProxiesAreUnaffected();
  await chainIntegrityLatchRefusesNewAdmissionButNotExisting();
  chainIntegrityLatchCarriesTheDiagnosticDetailNotJustABoolean();
  await toolLevelErrorRecordedButNotProtocolError();
  await preservesDownstreamJsonRpcErrorEnvelope();
  await initializationLifecycleEnforced();
  await noIdInitializeDoesNotUnlockToolsWithoutNotification();
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
  await reconnectWithMatchingIdempotencyKeyReplaysCrossConnectionCompletedCall();
  await reconnectWithoutMatchingIdempotencyKeyDispatchesIndependently();
  await retainedSignatureReplayStillBlockedByQuarantine();
  await ambiguousOutcomeBlocksRetryUntilOperatorResolves();
  await closeConnectionFencesInFlightIntentAsAmbiguous();
  await walRecordsLifecycleEventsAndIsCleanedUpOnClose();

  await blockedRetryAnomalyIsDurablyRecorded();
  await blockedRetryAnomaliesAreUncappedInTheWalDespiteTheSessionCap();
  await replayedCallGetsAStructuredCompletionLogToo();
  await callStartWalAppendFailureRollsBackAndStaysRetryable();
  await postDispatchUpdateSkippedWhenIntentConcurrentlyRemoved();

  // PR #33 review round 5 (post E1/E2) fixes:
  await anomalyWalAppendFailureDoesNotEscapeHandleMessage();
  await notExecutedIntentReturnsDedicatedBlockCode();
  await duplicateJsonRpcIdRejectedBeforeIntentCreated();
  await supersedeCallStartWalFailureRestoresPriorCompletedIntent();
  await quarantineScanFailureFailsClosed();

  // Codex PR #33 review round 2 (2026-09-17):
  await unreadableRetainedSignatureBlocksInsteadOfDispatching();
  await throwingLoggerOnTheSupersedePathDoesNotStrandTheFence();
  await initializeWalFailureDoesNotEscapeAndRollsBack();
  await openConnectionWalFailureDoesNotPublishGhostSession();
  await callResultWalFailureDoesNotEscapeHandleMessage();

  // Round-2 fix pass (2026-09-16): closing commit 5's WAL-poison enforcement gap.
  await ownAppendFailurePoisonsConnectionForEverySubsequentCallSite();
  await poisonedConnectionRefusesNewCallStartAndAttestsSkip();
  await poisonedConnectionSkipsCallResultAppendButStillReturnsResult();
  await poisonedConnectionSkipsClosingAppendAndAttestsIt();

  // From feature/track-1.2-standalone-gateway (merged into PR #33):
  await persistenceFailureQuarantinesSealedBundle();
  await writerClaimRevalidatedImmediatelyBeforeAppend();
  await writerClaimCheckDefaultsToValidWhenNotProvided();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
