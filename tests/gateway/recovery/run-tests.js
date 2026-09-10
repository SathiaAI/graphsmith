#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/recovery.js (Option C: Codex PR #29 Finding 1
 * [session.js -- a completed call lives only in memory until the whole session closes]
 * and Finding 2 [proxy.js -- nothing fences a retried tools/call against a duplicate
 * downstream side effect], external-panel-reviewed design -- see
 * option-c-hardened-design.md in the project record) and of gateway.js's own
 * recoverCrashedSessions/abandonConnection startup-recovery + operator-override paths
 * that replay recovery.js's WAL through session.js's real, unmodified recorder
 * functions.
 *
 * Covers:
 *   - recovery.js's WAL primitives (append/read/list/delete), including the "torn tail
 *     line" tolerance a real crash mid-fsync produces.
 *   - recovery.js's intent-store primitives (create-if-absent, read, update, delete,
 *     list-for-connection, list-all, operator resolution) including canonicalization
 *     (key-order-independent hashing) and the race-safety of createIntentIfAbsent.
 *   - gateway.js#recoverCrashedSessions: the Finding-1 gap (a call completed downstream
 *     but the WAL never recorded CALL_RESULT before a crash) is closed by consulting the
 *     real intent record, NOT by guessing; an unresolved in-flight call is left for an
 *     operator rather than auto-sealed; a repeated recovery attempt on already-sealed
 *     data is a no-op (GATEWAY_BUNDLE_ID_COLLISION), not a crash.
 *   - gateway.js#abandonConnection: the explicit "give up on the fence, seal what we
 *     have" operator override, and that it actually releases the intent fence it gives
 *     up on (by design -- see its own doc comment in gateway.js).
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const recovery = require(path.join(ROOT, "scripts", "gateway", "recovery.js"));
const session = require(path.join(ROOT, "scripts", "gateway", "session.js"));
const chain = require(path.join(ROOT, "scripts", "gateway", "chain.js"));
const { recoverCrashedSessions, abandonConnection, startGateway, runRecoveryResolveCli } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
const { WriterClaim } = require(path.join(ROOT, "scripts", "writer-claim.js"));

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
  return fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-recovery-${prefix}-`));
}
function makeKeys() {
  const kp = crypto.generateKeyPairSync("ed25519");
  return { privateKey: kp.privateKey, signer: "test-key", algo: "ed25519" };
}
function silentLog() {} // most tests don't care about the operational log lines

// ---------------------------------------------------------------------------
// WAL primitives
// ---------------------------------------------------------------------------

function walAppendAndReadRoundTrip() {
  const dir = freshDir("wal-roundtrip");
  recovery.appendWalEvent(dir, "conn-1", { type: "SESSION_START", goal: "g" });
  recovery.appendWalEvent(dir, "conn-1", { type: "INITIALIZE", model: "m" });
  const events = recovery.readWalEvents(dir, "conn-1");
  check("wal-roundtrip-count", events.length === 2, String(events.length));
  check("wal-roundtrip-order-and-content", events[0].type === "SESSION_START" && events[0].goal === "g" && events[1].type === "INITIALIZE" && events[1].model === "m", JSON.stringify(events));
  check("wal-roundtrip-records-recorded_at", typeof events[0].recorded_at === "number", JSON.stringify(events[0]));
}

function walReadOfMissingConnectionReturnsEmpty() {
  const dir = freshDir("wal-missing");
  const events = recovery.readWalEvents(dir, "never-existed");
  check("wal-read-missing-connection-returns-empty-array", Array.isArray(events) && events.length === 0, JSON.stringify(events));
}

function walTornTailLineToleratedRestKept() {
  const dir = freshDir("wal-torn");
  recovery.appendWalEvent(dir, "conn-1", { type: "SESSION_START", goal: null });
  recovery.appendWalEvent(dir, "conn-1", { type: "CALL_START", call_seq: 1, tool: "t", server: "s", arguments: {}, ts: 1 });
  // Simulate a crash mid-fsync of the THIRD line: append a torn (non-JSON) tail
  // directly, bypassing appendWalEvent's own well-formed JSON.stringify.
  fs.appendFileSync(recovery.walPath(dir, "conn-1"), '{"type":"CALL_RESULT","call_se');
  const events = recovery.readWalEvents(dir, "conn-1");
  check("wal-torn-tail-keeps-every-complete-line-before-it", events.length === 2 && events[0].type === "SESSION_START" && events[1].type === "CALL_START", JSON.stringify(events));
}

function walListActiveConnectionsAndDelete() {
  const dir = freshDir("wal-list-delete");
  recovery.appendWalEvent(dir, "conn-a", { type: "SESSION_START" });
  recovery.appendWalEvent(dir, "conn-b", { type: "SESSION_START" });
  const active = recovery.listActiveConnections(dir).sort();
  check("wal-lists-every-active-connection", JSON.stringify(active) === JSON.stringify(["conn-a", "conn-b"]), JSON.stringify(active));
  recovery.deleteWal(dir, "conn-a");
  const afterDelete = recovery.listActiveConnections(dir);
  check("wal-delete-removes-only-that-connection", JSON.stringify(afterDelete) === JSON.stringify(["conn-b"]), JSON.stringify(afterDelete));
  // Deleting an already-gone WAL must be a silent no-op (ENOENT swallowed), not a throw
  // -- recoverCrashedSessions relies on this for the "events.length === 0" early-out path.
  let threw = null;
  try { recovery.deleteWal(dir, "conn-a"); } catch (error) { threw = error; }
  check("wal-delete-of-already-deleted-is-a-no-op", threw === null, threw && threw.message);
}

function walOnEmptyRecoveryDirReturnsNoActiveConnections() {
  const dir = freshDir("wal-empty-root");
  const active = recovery.listActiveConnections(dir);
  check("wal-list-on-a-state-dir-with-no-recovery-dir-yet-returns-empty", Array.isArray(active) && active.length === 0, JSON.stringify(active));
}

// ---------------------------------------------------------------------------
// Intent-store primitives
// ---------------------------------------------------------------------------

function intentKeyStableRegardlessOfArgumentKeyOrder() {
  const k1 = recovery.computeIntentKey("conn-1", "send_email", { to: "a@example.com", subject: "hi" });
  const k2 = recovery.computeIntentKey("conn-1", "send_email", { subject: "hi", to: "a@example.com" });
  check("intent-key-stable-across-argument-key-order", k1 === k2, `${k1} !== ${k2}`);
}

function intentKeyDiffersOnConnectionToolOrArgs() {
  const base = recovery.computeIntentKey("conn-1", "send_email", { to: "a" });
  const diffConn = recovery.computeIntentKey("conn-2", "send_email", { to: "a" });
  const diffTool = recovery.computeIntentKey("conn-1", "send_sms", { to: "a" });
  const diffArgs = recovery.computeIntentKey("conn-1", "send_email", { to: "b" });
  check("intent-key-differs-on-connection", base !== diffConn, base);
  check("intent-key-differs-on-tool", base !== diffTool, base);
  check("intent-key-differs-on-arguments", base !== diffArgs, base);
}

function intentKeyTreatsUndefinedArgsAsNull() {
  const k1 = recovery.computeIntentKey("conn-1", "ping", undefined);
  const k2 = recovery.computeIntentKey("conn-1", "ping", null);
  check("intent-key-treats-undefined-arguments-same-as-null", k1 === k2, `${k1} !== ${k2}`);
}

function createIntentIfAbsentIsRaceSafe() {
  const dir = freshDir("intent-create");
  const key = recovery.computeIntentKey("conn-1", "tool", {});
  const first = recovery.createIntentIfAbsent(dir, key, { connection_id: "conn-1", tool: "tool", arguments: {}, state: "dispatched", dispatched_at: 1 });
  check("create-intent-if-absent-returns-record-first-time", Boolean(first) && first.state === "dispatched", JSON.stringify(first));
  const second = recovery.createIntentIfAbsent(dir, key, { connection_id: "conn-1", tool: "tool", arguments: {}, state: "dispatched", dispatched_at: 2 });
  check("create-intent-if-absent-returns-null-when-already-exists", second === null, JSON.stringify(second));
  // And the ORIGINAL record must be untouched by the second, losing attempt.
  const onDisk = recovery.readIntent(dir, key);
  check("create-intent-if-absent-does-not-let-a-losing-attempt-overwrite", onDisk.dispatched_at === 1, JSON.stringify(onDisk));
}

function readIntentOfMissingKeyReturnsNull() {
  const dir = freshDir("intent-missing");
  const result = recovery.readIntent(dir, "gs_doesnotexist");
  check("read-intent-of-missing-key-returns-null", result === null, JSON.stringify(result));
}

function updateIntentMergesAndRejectsUnknown() {
  const dir = freshDir("intent-update");
  const key = recovery.computeIntentKey("conn-1", "tool", {});
  recovery.createIntentIfAbsent(dir, key, { connection_id: "conn-1", tool: "tool", arguments: {}, state: "dispatched", dispatched_at: 1 });
  const updated = recovery.updateIntent(dir, key, { state: "completed", cached_result: { ok: true } });
  check("update-intent-merges-patch", updated.state === "completed" && updated.cached_result.ok === true && updated.dispatched_at === 1, JSON.stringify(updated));
  let threw = null;
  try { recovery.updateIntent(dir, "gs_doesnotexist", { state: "completed" }); } catch (error) { threw = error; }
  check("update-intent-of-unknown-key-throws-not-found", threw && threw.code === "GATEWAY_RECOVERY_INTENT_NOT_FOUND", threw && threw.code);
}

function deleteIntentIsIdempotent() {
  const dir = freshDir("intent-delete");
  const key = recovery.computeIntentKey("conn-1", "tool", {});
  recovery.createIntentIfAbsent(dir, key, { connection_id: "conn-1", tool: "tool", arguments: {}, state: "dispatched", dispatched_at: 1 });
  recovery.deleteIntent(dir, key);
  check("delete-intent-removes-it", recovery.readIntent(dir, key) === null, "still present");
  let threw = null;
  try { recovery.deleteIntent(dir, key); } catch (error) { threw = error; }
  check("delete-intent-of-already-deleted-is-a-no-op", threw === null, threw && threw.message);
}

function listIntentsForConnectionFiltersCorrectly() {
  const dir = freshDir("intent-list-conn");
  const keyA1 = recovery.computeIntentKey("conn-a", "tool1", {});
  const keyA2 = recovery.computeIntentKey("conn-a", "tool2", {});
  const keyB1 = recovery.computeIntentKey("conn-b", "tool1", {});
  recovery.createIntentIfAbsent(dir, keyA1, { connection_id: "conn-a", tool: "tool1", arguments: {}, state: "dispatched" });
  recovery.createIntentIfAbsent(dir, keyA2, { connection_id: "conn-a", tool: "tool2", arguments: {}, state: "completed" });
  recovery.createIntentIfAbsent(dir, keyB1, { connection_id: "conn-b", tool: "tool1", arguments: {}, state: "dispatched" });
  const forA = recovery.listIntentsForConnection(dir, "conn-a").map((i) => i.tool).sort();
  check("list-intents-for-connection-only-returns-that-connections-intents", JSON.stringify(forA) === JSON.stringify(["tool1", "tool2"]), JSON.stringify(forA));
}

function listAllIntentsSpansEveryConnection() {
  const dir = freshDir("intent-list-all");
  recovery.createIntentIfAbsent(dir, recovery.computeIntentKey("conn-a", "t", {}), { connection_id: "conn-a", tool: "t", arguments: {}, state: "ambiguous", ambiguous_reason: "x" });
  recovery.createIntentIfAbsent(dir, recovery.computeIntentKey("conn-b", "t", {}), { connection_id: "conn-b", tool: "t", arguments: {}, state: "dispatched" });
  const all = recovery.listAllIntents(dir);
  check("list-all-intents-spans-every-connection", all.length === 2, String(all.length));
  check("list-all-intents-preserves-each-records-own-state", all.some((i) => i.connection_id === "conn-a" && i.state === "ambiguous") && all.some((i) => i.connection_id === "conn-b" && i.state === "dispatched"), JSON.stringify(all));
}

function operatorResolutionExecutedAndNotExecuted() {
  const dir = freshDir("intent-resolve");
  const keyExecuted = recovery.computeIntentKey("conn-1", "toolA", {});
  const keyNotExecuted = recovery.computeIntentKey("conn-1", "toolB", {});
  recovery.createIntentIfAbsent(dir, keyExecuted, { connection_id: "conn-1", tool: "toolA", arguments: {}, state: "ambiguous" });
  recovery.createIntentIfAbsent(dir, keyNotExecuted, { connection_id: "conn-1", tool: "toolB", arguments: {}, state: "ambiguous" });

  const resolved = recovery.resolveIntentExecuted(dir, keyExecuted, { charged: true });
  check("resolve-intent-executed-marks-completed-with-cached-result", resolved.state === "completed" && resolved.cached_result.charged === true, JSON.stringify(resolved));

  // PR #33 round-2 fix (Codex "persist a terminal not-executed resolution"): this used
  // to delete the intent immediately. It now persists a terminal `not_executed` state
  // instead, so a crashed connection's still-pending WAL replay can resolve to this real
  // decision on the next restart rather than looping back to operator review forever --
  // see gateway.js#recoverCrashedSessions's own handling of this state. The intent is
  // deleted only once that replay actually consumes it and the connection is sealed.
  const resolvedNotExecuted = recovery.resolveIntentNotExecuted(dir, keyNotExecuted);
  check("resolve-intent-not-executed-persists-a-terminal-state", resolvedNotExecuted.state === "not_executed", JSON.stringify(resolvedNotExecuted));
  check("resolve-intent-not-executed-is-not-immediately-deleted", recovery.readIntent(dir, keyNotExecuted) !== null, "was deleted immediately");
}

// ---------------------------------------------------------------------------
// gateway.js#recoverCrashedSessions -- WAL replay through session.js's real functions
// ---------------------------------------------------------------------------

/** Simulates a live connection up through the WAL events proxy.js itself would have
 * appended for a fully-clean session (SESSION_START/INITIALIZE/CALL_START/CALL_RESULT),
 * WITHOUT ever calling closeConnection -- exactly what a real crash before disconnect
 * leaves behind. */
function seedCleanCallWal(dir, connectionId) {
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [{ name: "echo", server: "srv", schema: {} }] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 1 }, ts: 10 });
  const intentKey = recovery.computeIntentKey(connectionId, "echo", { a: 1 });
  // proxy.js's real dispatch guard always creates the intent record BEFORE the CALL_START
  // WAL event is appended (see proxy.js's own handleMessage) -- mirror that ordering here
  // so these fixtures match what a real crash actually leaves on disk.
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: connectionId, tool: "echo", arguments: { a: 1 }, state: "dispatched", dispatched_at: 9 });
  return intentKey;
}

function recoverAutoSealsASessionThatCrashedAfterCleanDisconnect() {
  const dir = freshDir("recover-clean");
  const keys = makeKeys();
  const connectionId = "conn-clean";
  const intentKey = seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  // No CLOSING event -- the crash happened after the response was recorded but before
  // the agent ever disconnected. Everything needed to seal is already in the WAL.
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-clean-crash-produces-no-pending-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("recover-clean-crash-deletes-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
  const headEntry = chain.readHead(dir);
  check("recover-clean-crash-appends-exactly-one-chain-entry", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
}

function recoverClosesFinding1GapUsingCompletedIntentAsProofOfOutcome() {
  const dir = freshDir("recover-finding1-gap");
  const keys = makeKeys();
  const connectionId = "conn-gap";
  const intentKey = seedCleanCallWal(dir, connectionId);
  // THE Finding-1 gap: proxy.js's real code marks the intent "completed" BEFORE it
  // appends the CALL_RESULT WAL line -- a crash in between leaves exactly this shape.
  recovery.updateIntent(dir, intentKey, { state: "completed", completed_at: 12, cached_result: { proven: "from-intent-not-wal" } });
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-closes-finding1-gap-without-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("recover-closes-finding1-gap-deletes-the-now-redundant-completed-intent", recovery.readIntent(dir, intentKey) === null, "intent still present");
  const headEntry = chain.readHead(dir);
  check("recover-closes-finding1-gap-still-produces-a-sealed-chain-entry", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
}

function recoverLeavesUnprovenInFlightCallForOperatorReview() {
  const dir = freshDir("recover-unproven");
  const keys = makeKeys();
  const connectionId = "conn-unproven";
  seedCleanCallWal(dir, connectionId);
  // The intent is still "dispatched" -- the crash happened with truly no proof either
  // way. This must NOT be auto-sealed by guessing.
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-flags-unproven-in-flight-call-for-operator-review", pendingOperatorReview.includes(connectionId), JSON.stringify(pendingOperatorReview));
  check("recover-does-not-touch-the-wal-of-a-flagged-connection", recovery.readWalEvents(dir, connectionId).length > 0, "WAL was deleted");
  check("recover-does-not-seal-anything-for-a-flagged-connection", chain.readHead(dir) === null, "a chain entry was appended despite no proven outcome");
}

function recoverIsIdempotentAcrossACrashDuringRecoveryItself() {
  const dir = freshDir("recover-repeat");
  const keys = makeKeys();
  const connectionId = "conn-repeat";
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  // First recovery pass succeeds and would normally clean up -- but simulate THIS
  // process itself crashing between chain.appendSession succeeding and deleteWal
  // running, by re-seeding the identical WAL afterward.
  recoverCrashedSessions(dir, keys, silentLog);
  const eventsAfterFirst = recovery.readWalEvents(dir, connectionId); // [] -- already cleaned up
  check("recover-first-pass-cleans-up-normally", eventsAfterFirst.length === 0, JSON.stringify(eventsAfterFirst));
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-second-pass-on-identical-content-is-not-flagged-for-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("recover-second-pass-still-cleans-up-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
  const headEntry = chain.readHead(dir);
  check("recover-second-pass-does-not-append-a-second-chain-entry", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
}

function recoverDeletesEmptyOrFullyTornWalWithoutFlagging() {
  const dir = freshDir("recover-empty-wal");
  const keys = makeKeys();
  const connectionId = "conn-empty";
  // A crash mid-write of the very FIRST line leaves nothing parseable at all.
  fs.mkdirSync(recovery.activeDir(dir), { recursive: true });
  fs.writeFileSync(recovery.walPath(dir, connectionId), '{"type":"SESSION_ST');
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-does-not-flag-a-connection-with-no-parseable-wal-content", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("recover-deletes-the-unusable-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
}

// ---------------------------------------------------------------------------
// PR #33 round-2 fixes: path-safety, bundle-collision content verification,
// per-connection isolation, not_executed replay, and anomaly-WAL replay.
// ---------------------------------------------------------------------------

function pathBearingIdentifiersAreRejected() {
  const dir = freshDir("path-safety");
  let threwWal = null;
  try { recovery.walPath(dir, "../../etc/passwd"); } catch (error) { threwWal = error; }
  check("wal-path-rejects-traversal-connection-id", threwWal && threwWal.code === "GATEWAY_RECOVERY_UNSAFE_ID", threwWal && threwWal.message);
  let threwIntent = null;
  try { recovery.intentPath(dir, "../outside"); } catch (error) { threwIntent = error; }
  check("intent-path-rejects-traversal-intent-key", threwIntent && threwIntent.code === "GATEWAY_RECOVERY_UNSAFE_ID", threwIntent && threwIntent.message);
  // A normal, real-shaped id (gs_<hex>, or a plain connection id) must still work.
  let ok = null;
  try { ok = recovery.walPath(dir, "conn-abc123_.-"); } catch (error) { ok = error; }
  check("wal-path-accepts-a-normal-id", typeof ok === "string", ok && ok.message);
}

function bundleCollisionWithDifferentContentIsFlaggedNotDiscarded() {
  const dir = freshDir("recover-collision");
  const keys = makeKeys();
  // First connection: seals normally, occupying a bundle_id derived only from
  // {init, grantedTools, n: calls.length} -- NOT from the actual call content.
  seedCleanCallWal(dir, "conn-x");
  recovery.appendWalEvent(dir, "conn-x", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(dir, keys, silentLog);
  const firstHead = chain.readHead(dir);

  // Second, DIFFERENT connection: same tool, same init shape, same call COUNT (1) --
  // deliberately different arguments/result, which gsa-mcp-shim.js's bundle_id formula
  // does not account for, so this collides on bundle_id despite being a genuinely
  // different session's content.
  const connectionId = "conn-y";
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [{ name: "echo", server: "srv", schema: {} }] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 999 }, ts: 10 });
  const intentKeyY = recovery.computeIntentKey(connectionId, "echo", { a: 999 });
  recovery.createIntentIfAbsent(dir, intentKeyY, { connection_id: connectionId, tool: "echo", arguments: { a: 999 }, state: "dispatched", dispatched_at: 9 });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: false, different: true }, isError: false, ts: 11 });

  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("bundle-collision-genuine-conflict-flagged-for-operator", pendingOperatorReview.includes(connectionId), JSON.stringify(pendingOperatorReview));
  check("bundle-collision-genuine-conflict-wal-not-discarded", recovery.readWalEvents(dir, connectionId).length > 0, "WAL was deleted despite unverified collision");
  check("bundle-collision-genuine-conflict-intent-not-discarded", recovery.readIntent(dir, intentKeyY) !== null, "intent was deleted despite unverified collision");
  const headAfter = chain.readHead(dir);
  check("bundle-collision-genuine-conflict-no-second-chain-entry-appended", headAfter && headAfter.seq === firstHead.seq, JSON.stringify(headAfter));
}

function unreadableWalForOneConnectionDoesNotBlockAnother() {
  const dir = freshDir("recover-isolation");
  const keys = makeKeys();
  // conn-bad's WAL "file" is actually a directory -- fs.readFileSync fails with EISDIR,
  // a genuine fs-level read error (GATEWAY_RECOVERY_WAL_UNREADABLE), not a content/JSON
  // problem readWalEvents already tolerates.
  fs.mkdirSync(recovery.activeDir(dir), { recursive: true });
  fs.mkdirSync(recovery.walPath(dir, "conn-bad"));
  // conn-good is a normal, cleanly-recoverable connection.
  seedCleanCallWal(dir, "conn-good");
  recovery.appendWalEvent(dir, "conn-good", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("isolation-unreadable-connection-flagged-not-thrown", pendingOperatorReview.includes("conn-bad"), JSON.stringify(pendingOperatorReview));
  check("isolation-good-connection-still-recovered", !pendingOperatorReview.includes("conn-good"), JSON.stringify(pendingOperatorReview));
  const headEntry = chain.readHead(dir);
  check("isolation-good-connections-chain-entry-appended-despite-sibling-failure", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
}

function abandonConnectionQuarantinesAnUnreadableWal() {
  const dir = freshDir("abandon-quarantine");
  const keys = makeKeys();
  const connectionId = "conn-corrupt";
  fs.mkdirSync(recovery.activeDir(dir), { recursive: true });
  fs.mkdirSync(recovery.walPath(dir, connectionId));
  let threw = null;
  try { abandonConnection(dir, keys, connectionId, silentLog); } catch (error) { threw = error; }
  check("abandon-quarantine-does-not-throw", threw === null, threw && threw.message);
  check("abandon-quarantine-removes-the-active-wal", recovery.listActiveConnections(dir).includes(connectionId) === false, "still listed as active");
  const quarantined = fs.existsSync(recovery.quarantineDir(dir)) ? fs.readdirSync(recovery.quarantineDir(dir)) : [];
  check("abandon-quarantine-moves-it-to-the-quarantine-dir", quarantined.some((f) => f.startsWith(connectionId)), JSON.stringify(quarantined));
}

function notExecutedIntentReplaysAsAFailedCallAndIsThenCleanedUp() {
  const dir = freshDir("recover-not-executed");
  const keys = makeKeys();
  const connectionId = "conn-not-executed";
  const intentKey = seedCleanCallWal(dir, connectionId);
  // Simulates the operator having already run
  // "recovery-resolve --confirmed not-executed" on this crashed, still-pending call --
  // no CALL_RESULT exists in the WAL (it never got one), but the intent now records the
  // operator's decision as a persisted terminal state (see recovery.js#resolveIntentNotExecuted).
  recovery.resolveIntentNotExecuted(dir, intentKey);
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("not-executed-replay-does-not-need-further-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("not-executed-replay-cleans-up-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
  check("not-executed-replay-cleans-up-the-intent-once-consumed", recovery.readIntent(dir, intentKey) === null, "intent still present");
  const headEntry = chain.readHead(dir);
  check("not-executed-replay-still-produces-a-sealed-chain-entry", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
}

// ---------------------------------------------------------------------------
// gateway.js#abandonConnection -- explicit operator override
// ---------------------------------------------------------------------------

function abandonConnectionSealsAndReleasesTheFenceForAnUnprovenCall() {
  const dir = freshDir("abandon");
  const keys = makeKeys();
  const connectionId = "conn-abandon";
  const intentKey = seedCleanCallWal(dir, connectionId);
  // Confirm this connection would otherwise be stuck pending operator review.
  const before = recoverCrashedSessions(dir, keys, silentLog);
  check("abandon-precondition-connection-was-pending-operator-review", before.pendingOperatorReview.includes(connectionId), JSON.stringify(before));

  abandonConnection(dir, keys, connectionId, silentLog);
  check("abandon-deletes-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
  check("abandon-releases-the-intent-fence", recovery.readIntent(dir, intentKey) === null, "intent still present");
  const headEntry = chain.readHead(dir);
  check("abandon-still-produces-a-sealed-chain-entry", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
}

function abandonConnectionOnAlreadyCleanConnectionIsANoOp() {
  const dir = freshDir("abandon-noop");
  const keys = makeKeys();
  let threw = null;
  try { abandonConnection(dir, keys, "never-existed", silentLog); } catch (error) { threw = error; }
  check("abandon-of-a-connection-with-no-wal-does-not-throw", threw === null, threw && threw.message);
}

// ---------------------------------------------------------------------------
// PR #33 round-2 fixes that need a real WriterClaim / real startGateway plumbing.
// ---------------------------------------------------------------------------

function writerClaimIsReleasedWhenStartupRecoveryThrows() {
  const root = freshDir("release-on-recovery-failure");
  const stateDir = path.join(root, "state");
  fs.mkdirSync(path.join(root, ".graphsmith", "state"), { recursive: true });
  const { writeConfirmedMode } = require(path.join(ROOT, "tests", "gateway", "_fixtures", "mode-file.js"));
  writeConfirmedMode(root, "standalone");
  const kp = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  const configPath = path.join(root, "gateway-config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    schema_version: "1.0",
    state_dir: stateDir,
    // Never actually reached -- recovery throws before connectAllDownstreams runs.
    downstream_servers: [{ name: "unused", transport: "stdio", endpoint: "node -e process.exit(1)" }],
    signing_key_ref: keyPath,
  }));
  // Make gateway-recovery/active a FILE, not a directory: recovery.listActiveConnections'
  // own fs.readdirSync then fails with ENOTDIR, a genuine non-ENOENT error this function
  // does not (and should not) swallow -- an unlistable recovery directory is a real,
  // whole-pass failure distinct from any single connection's own unreadable state.
  fs.mkdirSync(recovery.recoveryDir(stateDir), { recursive: true });
  fs.writeFileSync(recovery.activeDir(stateDir), "not a directory");

  let rejection = null;
  return startGateway({ configPath, root, log: () => {} }).then(
    () => { rejection = null; },
    (error) => { rejection = error; }
  ).then(() => {
    check("recovery-listActiveConnections-failure-rejects-startGateway", rejection !== null, "startGateway resolved instead of rejecting");
    // The writer-claim file must be gone -- proof that writerClaim.release() actually ran
    // rather than leaking a claim an immediate restart would then be refused for.
    const { WriterClaim: WC } = require(path.join(ROOT, "scripts", "writer-claim.js"));
    const fresh = new WC(stateDir, { hostId: "test-second-instance" });
    let acquireError = null;
    try { fresh.acquire(); fresh.release(); } catch (error) { acquireError = error; }
    check("writer-claim-released-so-a-fresh-instance-can-immediately-acquire-it", acquireError === null, acquireError && acquireError.message);
  });
}

function recoveryResolveRequiresResultFileForExecuted() {
  const dir = freshDir("cli-result-file");
  const root = freshDir("cli-result-file-root");
  const kp = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  const configPath = path.join(root, "gateway-config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    schema_version: "1.0",
    state_dir: dir,
    downstream_servers: [{ name: "unused", transport: "stdio", endpoint: "node -e process.exit(1)" }],
    signing_key_ref: keyPath,
  }));
  const intentKey = recovery.computeIntentKey("conn-cli", "toolX", { x: 1 });
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-cli", tool: "toolX", arguments: { x: 1 }, state: "ambiguous" });

  let threw = null;
  try {
    runRecoveryResolveCli(["--connection", "conn-cli", "--intent", intentKey, "--confirmed", "executed", "--config", configPath], () => {});
  } catch (error) {
    threw = error;
  }
  check("recovery-resolve-executed-without-result-file-is-rejected", threw !== null && threw.code === "GATEWAY_RECOVERY_CLI_USAGE", threw ? threw.message : "did not throw");
  check("recovery-resolve-rejected-attempt-does-not-mutate-the-intent", recovery.readIntent(dir, intentKey).state === "ambiguous", JSON.stringify(recovery.readIntent(dir, intentKey)));

  // Providing --result-file must still work.
  const resultFile = path.join(root, "result.json");
  fs.writeFileSync(resultFile, JSON.stringify({ charged: true }));
  runRecoveryResolveCli(["--connection", "conn-cli", "--intent", intentKey, "--confirmed", "executed", "--result-file", resultFile, "--config", configPath], () => {});
  const resolved = recovery.readIntent(dir, intentKey);
  check("recovery-resolve-executed-with-result-file-succeeds", resolved.state === "completed" && resolved.cached_result.charged === true, JSON.stringify(resolved));

  // The writer-claim taken internally by runRecoveryResolveCli must be released
  // afterward -- a second call against a different intent must not be refused.
  const intentKey2 = recovery.computeIntentKey("conn-cli", "toolY", {});
  recovery.createIntentIfAbsent(dir, intentKey2, { connection_id: "conn-cli", tool: "toolY", arguments: {}, state: "ambiguous" });
  let secondThrew = null;
  try {
    runRecoveryResolveCli(["--connection", "conn-cli", "--intent", intentKey2, "--confirmed", "not-executed", "--config", configPath], () => {});
  } catch (error) {
    secondThrew = error;
  }
  check("recovery-resolve-releases-its-writer-claim-after-each-run", secondThrew === null, secondThrew && secondThrew.message);
}

function recoveryResolveRefusesWhileAnotherWriterHoldsTheClaim() {
  const dir = freshDir("cli-writer-claim");
  const root = freshDir("cli-writer-claim-root");
  const kp = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "signing-key.pem");
  fs.writeFileSync(keyPath, kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  const configPath = path.join(root, "gateway-config.json");
  fs.writeFileSync(configPath, JSON.stringify({
    schema_version: "1.0",
    state_dir: dir,
    downstream_servers: [{ name: "unused", transport: "stdio", endpoint: "node -e process.exit(1)" }],
    signing_key_ref: keyPath,
    host_id: "owning-host",
  }));
  const intentKey = recovery.computeIntentKey("conn-locked", "toolZ", {});
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-locked", tool: "toolZ", arguments: {}, state: "ambiguous" });

  const owner = new WriterClaim(dir, { hostId: "owning-host-2" });
  owner.acquire();
  let threw = null;
  try {
    runRecoveryResolveCli(["--connection", "conn-locked", "--intent", intentKey, "--confirmed", "not-executed", "--config", configPath], () => {});
  } catch (error) {
    threw = error;
  } finally {
    owner.release();
  }
  check("recovery-resolve-refuses-while-another-writer-holds-the-claim", threw !== null && String(threw.code || "").startsWith("WRITER_CLAIM"), threw ? `${threw.code}: ${threw.message}` : "did not throw");
  check("recovery-resolve-refused-attempt-did-not-mutate-the-intent", recovery.readIntent(dir, intentKey).state === "ambiguous", JSON.stringify(recovery.readIntent(dir, intentKey)));
}

function main() {
  walAppendAndReadRoundTrip();
  walReadOfMissingConnectionReturnsEmpty();
  walTornTailLineToleratedRestKept();
  walListActiveConnectionsAndDelete();
  walOnEmptyRecoveryDirReturnsNoActiveConnections();

  intentKeyStableRegardlessOfArgumentKeyOrder();
  intentKeyDiffersOnConnectionToolOrArgs();
  intentKeyTreatsUndefinedArgsAsNull();
  createIntentIfAbsentIsRaceSafe();
  readIntentOfMissingKeyReturnsNull();
  updateIntentMergesAndRejectsUnknown();
  deleteIntentIsIdempotent();
  listIntentsForConnectionFiltersCorrectly();
  listAllIntentsSpansEveryConnection();
  operatorResolutionExecutedAndNotExecuted();

  recoverAutoSealsASessionThatCrashedAfterCleanDisconnect();
  recoverClosesFinding1GapUsingCompletedIntentAsProofOfOutcome();
  recoverLeavesUnprovenInFlightCallForOperatorReview();
  recoverIsIdempotentAcrossACrashDuringRecoveryItself();
  recoverDeletesEmptyOrFullyTornWalWithoutFlagging();

  abandonConnectionSealsAndReleasesTheFenceForAnUnprovenCall();
  abandonConnectionOnAlreadyCleanConnectionIsANoOp();

  pathBearingIdentifiersAreRejected();
  bundleCollisionWithDifferentContentIsFlaggedNotDiscarded();
  unreadableWalForOneConnectionDoesNotBlockAnother();
  abandonConnectionQuarantinesAnUnreadableWal();
  notExecutedIntentReplaysAsAFailedCallAndIsThenCleanedUp();

  recoveryResolveRequiresResultFileForExecuted();
  recoveryResolveRefusesWhileAnotherWriterHoldsTheClaim();

  return writerClaimIsReleasedWhenStartupRecoveryThrows().then(() => {
    const passed = results.filter((r) => r.status === "PASS").length;
    const failed = results.filter((r) => r.status === "FAIL").length;
    console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
    process.exit(failures ? 1 : 0);
  });
}

main().catch((error) => {
  console.error("FATAL:", error);
  process.exit(1);
});
