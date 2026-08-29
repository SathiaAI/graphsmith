#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/session.js (Standalone Gateway TRD SS3.3/SS3.4/
 * SS3.5). Covers SS8 test plan items: 2 (tool/server attribution), 4 (out-of-order
 * correlation by JSON-RPC id), 10 (downstream disconnect marks pending as error, not
 * silently dropped), 11 (unmatched response is an anomaly, does not crash). */

const crypto = require("crypto");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const session = require(path.join(ROOT, "scripts", "gateway", "session.js"));

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

function makeKeys() {
  const kp = crypto.generateKeyPairSync("ed25519");
  return { privateKey: kp.privateKey, signer: "test-key", algo: "ed25519" };
}

function createSessionRejectsBadConnectionId() {
  let threw = null;
  try { session.createSession(""); } catch (error) { threw = error; }
  check("createSession-rejects-empty-connectionId", threw && threw.code === "INVALID_ARGUMENT", threw && threw.code);
}

function toolServerAttribution() {
  const s = session.createSession("conn-1");
  session.recordToolsList(s, [
    { name: "read", server: "fs", schema: {} },
    { name: "fetch", server: "web", schema: {} },
  ]);
  session.recordCallStart(s, 1, { tool: "read", server: "fs", arguments: { path: "a" }, ts: 1 });
  session.recordCallResult(s, 1, { result: { ok: true }, ts: 2 });
  session.recordCallStart(s, 2, { tool: "fetch", server: "web", arguments: { url: "x" }, ts: 3 });
  session.recordCallResult(s, 2, { result: { status: 200 }, ts: 4 });
  check("call-1-attributed-to-fs", s.calls[0].server === "fs" && s.calls[0].tool === "read", JSON.stringify(s.calls[0]));
  check("call-2-attributed-to-web", s.calls[1].server === "web" && s.calls[1].tool === "fetch", JSON.stringify(s.calls[1]));
}

function outOfOrderCorrelation() {
  const s = session.createSession("conn-2");
  session.recordCallStart(s, "id-A", { tool: "slow", server: "srv", arguments: {}, ts: 10 });
  session.recordCallStart(s, "id-B", { tool: "fast", server: "srv", arguments: {}, ts: 11 });
  // Response for id-B (sent SECOND) arrives FIRST.
  session.recordCallResult(s, "id-B", { result: { which: "B" }, ts: 20 });
  session.recordCallResult(s, "id-A", { result: { which: "A" }, ts: 21 });
  check("out-of-order-both-correlated", s.calls.length === 2, `expected 2 calls, got ${s.calls.length}`);
  const byTool = Object.fromEntries(s.calls.map((c) => [c.tool, c.result]));
  check("out-of-order-B-correlated-correctly", byTool.fast && byTool.fast.which === "B", JSON.stringify(byTool.fast));
  check("out-of-order-A-correlated-correctly", byTool.slow && byTool.slow.which === "A", JSON.stringify(byTool.slow));
  check("no-pending-left-after-both-resolved", s.pendingCalls.size === 0, `pendingCalls.size=${s.pendingCalls.size}`);
}

function unmatchedResponseIsAnomalyNotCrash() {
  const s = session.createSession("conn-3");
  let threw = null;
  let correlated = null;
  try { correlated = session.recordCallResult(s, "never-sent-id", { result: { x: 1 } }); } catch (error) { threw = error; }
  check("unmatched-response-does-not-throw", threw === null, threw && threw.message);
  check("unmatched-response-reports-not-correlated", correlated === false, String(correlated));
  check("unmatched-response-recorded-as-anomaly", s.anomalies.length === 1 && s.anomalies[0].kind === "UNMATCHED_RESPONSE", JSON.stringify(s.anomalies));
  check("unmatched-response-not-in-calls", s.calls.length === 0, `expected 0 calls, got ${s.calls.length}`);
}

function disconnectMarksPendingAsError() {
  const s = session.createSession("conn-4");
  session.recordCallStart(s, 1, { tool: "hangs", server: "srv", arguments: {}, ts: 1 });
  session.markPendingAsDisconnected(s, "downstream server \"srv\" disconnected");
  check("disconnect-moves-pending-into-calls", s.calls.length === 1, `expected 1 call, got ${s.calls.length}`);
  check("disconnect-marks-isError-true", s.calls[0].isError === true, JSON.stringify(s.calls[0]));
  check("disconnect-carries-explicit-marker", s.calls[0].disconnected === true && /disconnected/.test(s.calls[0].disconnect_reason), JSON.stringify(s.calls[0]));
  check("disconnect-clears-pendingCalls", s.pendingCalls.size === 0, `pendingCalls.size=${s.pendingCalls.size}`);
}

function modelCallFlagPreserved() {
  const s = session.createSession("conn-5");
  session.recordCallStart(s, 1, { tool: "sampling/createMessage", server: "sampling", arguments: {}, isModelCall: true, ts: 1 });
  session.recordCallResult(s, 1, { result: {}, ts: 2 });
  check("model-call-flag-preserved-through-correlation", s.calls[0].model_call === true, JSON.stringify(s.calls[0]));
}

function duplicateJsonRpcIdRejected() {
  const s = session.createSession("conn-6");
  session.recordCallStart(s, 1, { tool: "a", server: "srv", arguments: {}, ts: 1 });
  let threw = null;
  try { session.recordCallStart(s, 1, { tool: "b", server: "srv", arguments: {}, ts: 2 }); } catch (error) { threw = error; }
  check("duplicate-jsonrpc-id-rejected", threw && threw.code === "DUPLICATE_JSONRPC_ID", threw && threw.code);
}

function finalizeRefusesWithPendingCalls() {
  const s = session.createSession("conn-7");
  session.recordCallStart(s, 1, { tool: "a", server: "srv", arguments: {}, ts: 1 });
  let threw = null;
  try { session.finalizeSession(s, makeKeys()); } catch (error) { threw = error; }
  check("finalize-refuses-with-pending-calls", threw && threw.code === "SESSION_HAS_PENDING_CALLS", threw && threw.code);
}

function finalizeSealsAndVerifies() {
  const { verifyBundle } = require(path.join(ROOT, "scripts", "gsa-verify.js"));
  const kp = crypto.generateKeyPairSync("ed25519");
  const pem = kp.publicKey.export({ type: "spki", format: "pem" }).toString();
  const keys = { privateKey: kp.privateKey, signer: "gw-key", algo: "ed25519" };

  const s = session.createSession("conn-8", { goal: "test session" });
  session.recordInitialize(s, { clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  session.recordToolsList(s, [{ name: "t", server: "srv", schema: {} }]);
  session.recordCallStart(s, 1, { tool: "t", server: "srv", arguments: { a: 1 }, ts: 1 });
  session.recordCallResult(s, 1, { result: { ok: true }, ts: 2 });

  const sealed = session.finalizeSession(s, keys);
  const verified = verifyBundle(sealed.bundle, { trustedKeys: { "gw-key": pem } });
  check("finalized-bundle-verifies", verified.status === "PASS", JSON.stringify(verified));
  check("finalize-marks-session-finalized", s.finalized === true, String(s.finalized));

  let threw = null;
  try { session.recordToolsList(s, []); } catch (error) { threw = error; }
  check("cannot-record-into-finalized-session", threw && threw.code === "SESSION_FINALIZED", threw && threw.code);

  let threw2 = null;
  try { session.finalizeSession(s, keys); } catch (error) { threw2 = error; }
  check("cannot-finalize-twice", threw2 && threw2.code === "SESSION_FINALIZED", threw2 && threw2.code);
}

function main() {
  createSessionRejectsBadConnectionId();
  toolServerAttribution();
  outOfOrderCorrelation();
  unmatchedResponseIsAnomalyNotCrash();
  disconnectMarksPendingAsError();
  modelCallFlagPreserved();
  duplicateJsonRpcIdRejected();
  finalizeRefusesWithPendingCalls();
  finalizeSealsAndVerifies();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
