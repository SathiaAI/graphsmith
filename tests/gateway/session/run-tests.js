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

/* Round-1 fix-round follow-up (2026-09-15, "anomaly cap tests and the WAL/disk-growth
 * follow-up ticket"): the existing anomaliesCappedWithTerminalMarker test above only ever
 * drives the cap through recordUnmatchedResponseAnomaly. recordAnomaly is a SEPARATE
 * external entry point (used by proxy.js's blocked-retry path, not by unmatched-response
 * handling) that happens to share the same pushCappedAnomaly implementation -- prove the
 * cap boundary holds for THIS entry point directly rather than assuming the shared
 * implementation makes that redundant. Also settles, with a test rather than an
 * assumption (per Paul's 2026-09-15 instruction -- prior review rounds disagreed on this),
 * that recordAnomaly's return value flips from true to false exactly at the cap boundary:
 * true for every one of the first MAX_ANOMALIES_PER_SESSION calls (including the one that
 * also appends the ANOMALY_CAP_REACHED terminal marker), false for every call after. */
function recordAnomalyRespectsCapWithTerminalMarker() {
  const { MAX_ANOMALIES_PER_SESSION } = session;
  const s = session.createSession("conn-record-anomaly-cap");
  const returns = [];
  for (let i = 0; i < MAX_ANOMALIES_PER_SESSION; i++) {
    returns.push(session.recordAnomaly(s, { kind: "GATEWAY_AMBIGUOUS_RETRY", tool: "t", detail: `attempt ${i}` }));
  }
  check(
    "recordAnomaly-returns-true-for-every-call-up-to-and-including-the-cap",
    returns.every((r) => r === true),
    JSON.stringify(returns.filter((r) => r !== true))
  );
  check(
    "recordAnomaly-cap-plus-terminal-marker-present-at-MAX",
    s.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1 && s.anomalies[s.anomalies.length - 1].kind === "ANOMALY_CAP_REACHED",
    `length=${s.anomalies.length}`
  );
  // Past the cap: every further call is dropped (returns false) and anomalies stops
  // growing entirely -- not even a second terminal marker.
  const post1 = session.recordAnomaly(s, { kind: "GATEWAY_AMBIGUOUS_RETRY", tool: "t", detail: "past cap #1" });
  const post2 = session.recordAnomaly(s, { kind: "GATEWAY_AMBIGUOUS_RETRY", tool: "t", detail: "past cap #2" });
  check("recordAnomaly-returns-false-once-cap-is-reached", post1 === false && post2 === false, JSON.stringify([post1, post2]));
  check(
    "recordAnomaly-past-cap-does-not-grow-anomalies-further",
    s.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1,
    `length=${s.anomalies.length}`
  );
}

/* Frontier-panel decision (Paul, 2026-09-10, cluster E2, see proxy.js's own comment on
 * "a reconnecting agent gets a brand-new connectionId"): a reconnect is, at the
 * session-capture layer, simply a fresh session.createSession call with its own empty
 * anomalies array -- the cap is a PER-SESSION budget, not a per-agent or per-connectionId-
 * string lifetime budget. Prove that a session exhausted to its cap does not poison a
 * later session: the later one starts at zero and can independently record up to its own
 * full budget. */
function reconnectStartsWithAFreshAnomalyBudget() {
  const { MAX_ANOMALIES_PER_SESSION } = session;
  const exhausted = session.createSession("conn-reconnect-before-crash");
  for (let i = 0; i < MAX_ANOMALIES_PER_SESSION + 3; i++) {
    session.recordAnomaly(exhausted, { kind: "GATEWAY_AMBIGUOUS_RETRY", tool: "t", detail: `attempt ${i}` });
  }
  check(
    "pre-reconnect-session-is-fully-exhausted",
    exhausted.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1,
    `length=${exhausted.anomalies.length}`
  );

  // The reconnecting agent's new connection -- a DIFFERENT connectionId, matching
  // proxy.js's own documented behavior that a reconnect never reuses the old one.
  const reconnected = session.createSession("conn-reconnect-after-crash");
  check("reconnected-session-starts-with-zero-anomalies", reconnected.anomalies.length === 0, `length=${reconnected.anomalies.length}`);
  const recorded = session.recordAnomaly(reconnected, { kind: "GATEWAY_AMBIGUOUS_RETRY", tool: "t", detail: "first attempt after reconnect" });
  check("reconnected-session-records-normally-despite-the-old-session-being-exhausted", recorded === true && reconnected.anomalies.length === 1, JSON.stringify(reconnected.anomalies));

  // And the reconnected session has its OWN full budget, unaffected by the old one's cap
  // having been hit -- fill it independently and confirm it caps at the same boundary.
  for (let i = 1; i < MAX_ANOMALIES_PER_SESSION + 3; i++) {
    session.recordAnomaly(reconnected, { kind: "GATEWAY_AMBIGUOUS_RETRY", tool: "t", detail: `attempt ${i}` });
  }
  check(
    "reconnected-session-caps-independently-at-its-own-full-budget",
    reconnected.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1,
    `length=${reconnected.anomalies.length}`
  );
}

/* LIMITATION, confirmed here rather than silently accepted (per Paul's 2026-09-15
 * instruction): MAX_ANOMALIES_PER_SESSION is a plain event-COUNT cap with no notion of
 * severity or evidentiary value -- it drops the (count+1)-th anomaly regardless of
 * whether it is one more low-value duplicate of noise already recorded or the single
 * highest-value entry in the whole session (e.g. the one GATEWAY_AMBIGUOUS_RETRY that
 * proves a duplicate dispatch was actually prevented). A sufficiently large flood of
 * low-value anomalies (e.g. UNMATCHED_RESPONSE from a chatty misbehaving downstream) can
 * therefore silently crowd out and suppress a later high-value one from ever reaching the
 * sealed bundle. This test proves the suppression happens (it is not hypothetical) and
 * exists to keep this limitation visible rather than let it regress into an unexamined
 * assumption; see KNOWN-LIMITATIONS.md ("Anomaly cap is an event count, not a value or
 * byte budget") for the tracked follow-up. */
function cappedAnomaliesCanSuppressAHigherValueLaterEvent() {
  const { MAX_ANOMALIES_PER_SESSION } = session;
  const s = session.createSession("conn-suppression-risk");
  for (let i = 0; i < MAX_ANOMALIES_PER_SESSION; i++) {
    session.recordAnomaly(s, { kind: "UNMATCHED_RESPONSE", detail: `low-value noise #${i}` });
  }
  check("suppression-setup-cap-exactly-reached", s.anomalies.length === MAX_ANOMALIES_PER_SESSION + 1, `length=${s.anomalies.length}`);

  // A genuinely high-value event arrives immediately after: a blocked duplicate dispatch,
  // the exact kind of anomaly Option C's design depends on the sealed bundle attesting.
  const recorded = session.recordAnomaly(s, {
    kind: "GATEWAY_AMBIGUOUS_RETRY",
    tool: "transfer-funds",
    detail: "a prior attempt of this exact operation was still in flight -- dispatch halted",
  });
  check("high-value-anomaly-after-cap-is-silently-dropped-not-recorded", recorded === false, String(recorded));
  check(
    "high-value-anomaly-kind-does-not-appear-anywhere-in-the-sealed-anomalies",
    !s.anomalies.some((a) => a.kind === "GATEWAY_AMBIGUOUS_RETRY"),
    JSON.stringify(s.anomalies.filter((a) => a.kind === "GATEWAY_AMBIGUOUS_RETRY"))
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

/* Cluster B (session-identity distinctness in the audit trail): two sessions that
 * record byte-identical {init, tools, calls, results} must NOT be treated as "the same
 * session" merely because gsa-mcp-shim.js's own bundle_id formula cannot otherwise tell
 * them apart -- see that module's own doc comment on why session_id was folded into the
 * hash. Also asserts createSession mints a session_id automatically when the caller
 * (the live proxy.js#openConnection path) does not supply one. */
function identicalContentDifferentSessionIdsProduceDifferentBundleIds() {
  const keys = makeKeys();
  function sealWithSessionId(sessionId) {
    const s = session.createSession("conn-identical", { sessionId });
    session.recordInitialize(s, { clientInfo: { name: "same-agent", version: "1" } });
    session.recordToolsList(s, [{ name: "t", server: "srv", schema: {} }]);
    session.recordCallStart(s, 1, { tool: "t", server: "srv", arguments: { a: 1 }, ts: 1 });
    session.recordCallResult(s, 1, { result: { ok: true }, ts: 2 });
    return session.finalizeSession(s, keys);
  }
  const sealedA = sealWithSessionId("session-id-A");
  const sealedB = sealWithSessionId("session-id-B");
  check(
    "identical-content-different-session-ids-produce-different-bundle-ids",
    sealedA.bundle.manifest.bundle_id !== sealedB.bundle.manifest.bundle_id,
    JSON.stringify({ a: sealedA.bundle.manifest.bundle_id, b: sealedB.bundle.manifest.bundle_id })
  );
  // Same session_id + identical content must still be deterministic (this is what makes
  // "replay the same session twice" produce the same bundle_id in the first place).
  const sealedA2 = sealWithSessionId("session-id-A");
  check(
    "identical-content-and-session-id-produce-the-same-bundle-id",
    sealedA.bundle.manifest.bundle_id === sealedA2.bundle.manifest.bundle_id,
    JSON.stringify({ a: sealedA.bundle.manifest.bundle_id, a2: sealedA2.bundle.manifest.bundle_id })
  );
}

function sessionIdAutoGeneratedWhenNotProvided() {
  const s1 = session.createSession("conn-auto-1");
  const s2 = session.createSession("conn-auto-2");
  check("session-id-auto-generated-when-omitted", typeof s1.sessionId === "string" && s1.sessionId.length > 0, String(s1.sessionId));
  check("session-id-auto-generated-differs-across-sessions", s1.sessionId !== s2.sessionId, JSON.stringify([s1.sessionId, s2.sessionId]));
}

function main() {
  createSessionRejectsBadConnectionId();
  toolServerAttribution();
  outOfOrderCorrelation();
  unmatchedResponseIsAnomalyNotCrash();
  unmatchedResponseAnomalyDoesNotTouchPendingCalls();
  anomaliesCappedWithTerminalMarker();
  recordAnomalyRespectsCapWithTerminalMarker();
  reconnectStartsWithAFreshAnomalyBudget();
  cappedAnomaliesCanSuppressAHigherValueLaterEvent();
  disconnectMarksPendingAsError();
  disconnectCallbackFailureDoesNotAbortLoopOrPropagate();
  modelCallFlagPreserved();
  duplicateJsonRpcIdRejected();
  finalizeRefusesWithPendingCalls();
  finalizeSealsAndVerifies();
  sessionIdAutoGeneratedWhenNotProvided();
  identicalContentDifferentSessionIdsProduceDifferentBundleIds();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
