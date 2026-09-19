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

/** CodeRabbit/Codex PR #29 review round 8 "record unmatched downstream responses without
 * agent-call correlation" / "keep unmatched downstream IDs out of agent correlation": a
 * downstream response whose id has no matching pending call must be recorded as an
 * anomaly WITHOUT ever touching pendingCalls -- proven directly here by picking a
 * jsonRpcId that collides with a LIVE pending call and asserting that call survives
 * untouched. recordCallResult (the pre-fix call site) would have deleted it. */
function unmatchedResponseAnomalyDoesNotTouchPendingCalls() {
  const s = session.createSession("conn-collision");
  session.recordCallStart(s, 1, { tool: "live-agent-call", server: "srv", arguments: {}, ts: 1 });
  const correlated = session.recordUnmatchedResponseAnomaly(s, 1, "downstream-internal id collided with an agent-facing pending call", 2);
  check("unmatched-anomaly-helper-reports-recorded", correlated === true, String(correlated));
  check(
    "unmatched-anomaly-does-not-delete-the-colliding-live-pending-call",
    s.pendingCalls.has(1) && s.pendingCalls.get(1).tool === "live-agent-call",
    JSON.stringify(Array.from(s.pendingCalls.entries()))
  );
  check("unmatched-anomaly-recorded-once", s.anomalies.length === 1 && s.anomalies[0].kind === "UNMATCHED_RESPONSE" && s.anomalies[0].jsonRpcId === 1, JSON.stringify(s.anomalies));
  check("unmatched-anomaly-does-not-add-a-spurious-completed-call", s.calls.length === 0, JSON.stringify(s.calls));

  // The live call, still genuinely pending, resolves normally afterward -- proving it was
  // never corrupted or removed by the colliding anomaly recorded against the same id.
  session.recordCallResult(s, 1, { result: { ok: true }, ts: 3 });
  check("colliding-live-call-still-resolves-normally-afterward", s.calls.length === 1 && s.calls[0].tool === "live-agent-call" && s.calls[0].isError === false, JSON.stringify(s.calls));
}

/** Codex PR #29 review round 8 "cap unmatched-response anomalies per session": without a
 * bound, a stream of unmatched responses (a faulty/compromised downstream sending ids this
 * gateway never issued) would grow session.anomalies without limit. */
function anomaliesCappedWithTerminalMarker() {
  const { MAX_ANOMALIES_PER_SESSION } = session;
  const s = session.createSession("conn-anomaly-cap");
  for (let i = 0; i < MAX_ANOMALIES_PER_SESSION + 5; i++) {
    session.recordUnmatchedResponseAnomaly(s, `unknown-${i}`, "test anomaly", i);
  }
  check(
    "anomalies-stop-growing-past-the-cap-plus-one-terminal-marker",
    s.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1,
    `expected ${MAX_ANOMALIES_PER_SESSION + 1}, got ${s.anomalies.length}`
  );
  check("anomaly-cap-hit-is-itself-recorded-once", s.anomalies[s.anomalies.length - 1].kind === "ANOMALY_CAP_REACHED", JSON.stringify(s.anomalies[s.anomalies.length - 1]));
  check(
    "anomalies-before-the-cap-are-all-genuine-unmatched-responses",
    s.anomalies.slice(0, MAX_ANOMALIES_PER_SESSION).every((a) => a.kind === "UNMATCHED_RESPONSE"),
    "a non-UNMATCHED_RESPONSE entry appeared before the cap"
  );
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

/** CodeRabbit PR #29 review round 4 "contain disconnect-callback failures during
 * session finalization": onDisconnect is the CALLER's side effect (proxy.js wires it to
 * a JSON.stringify + this.log() call, which console.error can in principle throw for --
 * e.g. an EPIPE on a closed stderr). Before this fix, a throwing onDisconnect would
 * escape markPendingAsDisconnected entirely, aborting the loop for any remaining pending
 * calls on this session and propagating up through closeConnection/
 * handleDownstreamDisconnect -- in gateway.js's shutdown drain this would abort
 * finalizing every OTHER open session too and skip writerClaim.release(), leaking a
 * stale claim. Two pending calls here prove both halves: the call whose callback throws
 * is still correctly recorded (not lost), AND the loop continues to the next one rather
 * than stopping. */
function disconnectCallbackFailureDoesNotAbortLoopOrPropagate() {
  const s = session.createSession("conn-callback-failure");
  session.recordCallStart(s, "first", { tool: "a", server: "srv", arguments: {}, ts: 1 });
  session.recordCallStart(s, "second", { tool: "b", server: "srv", arguments: {}, ts: 2 });
  const seen = [];
  let threw = null;
  try {
    session.markPendingAsDisconnected(s, "downstream disconnected", undefined, undefined, (call) => {
      seen.push(call.tool);
      throw new Error("logger EPIPE (simulated)");
    });
  } catch (error) {
    threw = error;
  }
  check("disconnect-callback-failure-does-not-propagate-out-of-markPendingAsDisconnected", threw === null, threw && threw.message);
  check("disconnect-callback-still-invoked-for-every-pending-call-despite-throwing", seen.length === 2 && seen.includes("a") && seen.includes("b"), JSON.stringify(seen));
  check("disconnect-callback-failure-does-not-lose-the-call-record", s.calls.length === 2, `expected 2 calls, got ${s.calls.length}`);
  check("disconnect-callback-failure-still-clears-pendingCalls", s.pendingCalls.size === 0, `pendingCalls.size=${s.pendingCalls.size}`);
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

/* PR #29 review thread 4000335147, frontier-panel review (4/4 converged) "flag
 * structurally malformed tools/call results distinctly from tool-level errors": the
 * predicate itself lives in proxy.js (isMalformedToolCallResult) -- this module's own
 * job, tested here, is just to store whatever the caller computed (like isError) and
 * carry it through to sealBoundaryBundle's trace line, additive-only. */
function malformedResultFlagStoredAndPropagatedToSealedTrace() {
  const keys = makeKeys();

  const flagged = session.createSession("conn-malformed");
  session.recordCallStart(flagged, 1, { tool: "shapeless", server: "srv", arguments: {}, ts: 1 });
  session.recordCallResult(flagged, 1, { result: {}, malformedResult: true, ts: 2 });
  check("recordCallResult-stores-malformedResult-true", flagged.calls[0].malformedResult === true, JSON.stringify(flagged.calls));

  const clean = session.createSession("conn-clean");
  session.recordCallStart(clean, 1, { tool: "clean", server: "srv", arguments: {}, ts: 1 });
  // malformedResult intentionally omitted from the recordCallResult options, exactly like
  // every non-tools/call caller (e.g. sampling/createMessage) does -- must default to a
  // plain false, never undefined/truthy.
  session.recordCallResult(clean, 1, { result: { content: [] }, ts: 2 });
  check("recordCallResult-defaults-malformedResult-to-false-when-omitted", clean.calls[0].malformedResult === false, JSON.stringify(clean.calls));

  const sealedFlagged = session.finalizeSession(flagged, keys);
  const traceFlagged = sealedFlagged.bundle.contents["execution_trace.jsonl"];
  check("sealed-trace-carries-malformed-result-true-for-flagged-call", traceFlagged.includes("\"malformed_result\":true"), traceFlagged);

  const sealedClean = session.finalizeSession(clean, keys);
  const traceClean = sealedClean.bundle.contents["execution_trace.jsonl"];
  check("sealed-trace-omits-malformed-result-key-for-well-formed-call-byte-parity", !traceClean.includes("malformed_result"), traceClean);
}

function main() {
  createSessionRejectsBadConnectionId();
  toolServerAttribution();
  outOfOrderCorrelation();
  unmatchedResponseIsAnomalyNotCrash();
  unmatchedResponseAnomalyDoesNotTouchPendingCalls();
  anomaliesCappedWithTerminalMarker();
  disconnectMarksPendingAsError();
  disconnectCallbackFailureDoesNotAbortLoopOrPropagate();
  modelCallFlagPreserved();
  malformedResultFlagStoredAndPropagatedToSealedTrace();
  duplicateJsonRpcIdRejected();
  finalizeRefusesWithPendingCalls();
  finalizeSealsAndVerifies();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
