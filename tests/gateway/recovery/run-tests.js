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
const { recoverCrashedSessions, abandonConnection, startGateway, runRecoveryResolveCli, forwardDownstreamRequestToAgent, buildHealthStatus } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
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

/* Codex PR #33 review "complete WAL writes before treating them as durable": fs.writeSync
 * may write fewer bytes than the caller asked for in a single call. Before this fix, a
 * short write here was fsync'd (and reported durable) exactly as if it had written the
 * whole line -- readWalEvents' own "stop at the first malformed line" tolerance (its own
 * header comment) would then treat that torn interior line as a crash tail and silently
 * discard it AND every real, complete event appended after it. */
function appendWalEventRetriesOnAShortWrite() {
  const dir = freshDir("wal-short-write");
  const originalWriteSync = fs.writeSync;
  let calls = 0;
  fs.writeSync = function (fd, buffer, offset, length, position) {
    calls++;
    if (calls === 1) {
      // Simulate a short write: only the first half of the requested bytes land.
      const partial = Math.max(1, Math.floor(length / 2));
      return originalWriteSync(fd, buffer, offset, partial, position);
    }
    return originalWriteSync.apply(fs, arguments);
  };
  try {
    recovery.appendWalEvent(dir, "conn-1", { type: "SESSION_START", goal: "g" });
  } finally {
    fs.writeSync = originalWriteSync;
  }
  check("wal-short-write-took-more-than-one-writeSync-call", calls > 1, String(calls));
  const events = recovery.readWalEvents(dir, "conn-1");
  check("wal-short-write-still-produces-one-complete-parseable-event", events.length === 1 && events[0].type === "SESSION_START" && events[0].goal === "g", JSON.stringify(events));
  // A second, real event appended afterward must not be lost the way a genuinely torn
  // line would discard it -- confirms the whole first line landed intact on disk, not
  // just that JSON.parse happened to tolerate a truncated tail by coincidence.
  recovery.appendWalEvent(dir, "conn-1", { type: "INITIALIZE", model: "m" });
  const eventsAfter = recovery.readWalEvents(dir, "conn-1");
  check("wal-short-write-does-not-corrupt-subsequent-events", eventsAfter.length === 2 && eventsAfter[1].type === "INITIALIZE", JSON.stringify(eventsAfter));
}

function appendWalEventFailsClosedWhenWriteSyncMakesNoProgress() {
  const dir = freshDir("wal-no-progress-write");
  const originalWriteSync = fs.writeSync;
  fs.writeSync = function () { return 0; };
  let threw = null;
  try {
    recovery.appendWalEvent(dir, "conn-1", { type: "SESSION_START", goal: "g" });
  } catch (error) {
    threw = error;
  } finally {
    fs.writeSync = originalWriteSync;
  }
  check("wal-no-progress-write-throws-rather-than-fsync-nothing", threw && threw.code === "GATEWAY_RECOVERY_SHORT_WRITE", threw && threw.code);
}

/* Codex PR #33 review "restrict permissions on raw recovery records": these files/dirs
 * hold raw goals, tool arguments, and cached results -- data the signed execution trace
 * otherwise only ever stores as hashes. Under a common 022 umask, the previous default
 * modes (0755 dirs, 0644 files) let any other local user on the host read them. POSIX-only
 * (Windows has no equivalent permission bits to assert against). */
function recoveryFilesAndDirsAreOwnerOnlyPermissions() {
  if (process.platform === "win32") {
    record("recovery-permissions-owner-only", "SKIP", "POSIX file mode bits do not apply on win32");
    return;
  }
  const dir = freshDir("permissions");
  recovery.appendWalEvent(dir, "conn-1", { type: "SESSION_START", goal: null });
  const walMode = fs.statSync(recovery.walPath(dir, "conn-1")).mode & 0o777;
  check("recovery-wal-file-is-0600", walMode === 0o600, walMode.toString(8));
  const activeDirMode = fs.statSync(recovery.activeDir(dir)).mode & 0o777;
  check("recovery-active-dir-is-0700", activeDirMode === 0o700, activeDirMode.toString(8));

  const intentKey = recovery.computeIntentKey("conn-1", "toolA", {});
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-1", tool: "toolA", arguments: {}, state: "dispatched", dispatched_at: 1 });
  const intentModeAfterCreate = fs.statSync(recovery.intentPath(dir, intentKey)).mode & 0o777;
  check("recovery-intent-file-is-0600-after-create", intentModeAfterCreate === 0o600, intentModeAfterCreate.toString(8));
  const intentsDirMode = fs.statSync(recovery.intentsDir(dir)).mode & 0o777;
  check("recovery-intents-dir-is-0700", intentsDirMode === 0o700, intentsDirMode.toString(8));

  recovery.updateIntent(dir, intentKey, { state: "ambiguous", ambiguous_at: 2 });
  const intentModeAfterUpdate = fs.statSync(recovery.intentPath(dir, intentKey)).mode & 0o777;
  check("recovery-intent-file-is-0600-after-update", intentModeAfterUpdate === 0o600, intentModeAfterUpdate.toString(8));
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

/* Codex PR #33 review "sort active connections before recovery": readdirSync gives no
 * portable ordering guarantee -- recoverCrashedSessions consumes listActiveConnections'
 * result directly, in order, to decide chain-append sequence/tail-hash assignment, so an
 * unsorted order made replay order (and therefore the resulting chain) platform/fs
 * dependent. Deliberately does NOT sort the expectation itself, unlike
 * walListActiveConnectionsAndDelete above, to actually exercise the function's own
 * ordering guarantee rather than the test's. */
function walListActiveConnectionsReturnsSortedOrder() {
  const dir = freshDir("wal-list-sorted");
  // Appended out of lexical order on purpose.
  recovery.appendWalEvent(dir, "conn-c", { type: "SESSION_START" });
  recovery.appendWalEvent(dir, "conn-a", { type: "SESSION_START" });
  recovery.appendWalEvent(dir, "conn-b", { type: "SESSION_START" });
  const active = recovery.listActiveConnections(dir);
  check("wal-list-active-connections-is-sorted", JSON.stringify(active) === JSON.stringify(["conn-a", "conn-b", "conn-c"]), JSON.stringify(active));
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

/* Codex PR #33 review "fsync the intent directory after rollback deletion": proxy.js's own
 * CALL_START-failure rollback calls deleteIntent to remove a just-created "dispatched"
 * intent it now knows never actually dispatched, then tells the caller a retry is safe --
 * but the unlink's own directory-entry removal was never fsynced, so a crash shortly after
 * could resurrect the stale record on the next mount. */
function deleteIntentFsyncsTheIntentsDirectoryAfterRemoval() {
  const dir = freshDir("intent-delete-fsync");
  const key = recovery.computeIntentKey("conn-1", "tool", {});
  recovery.createIntentIfAbsent(dir, key, { connection_id: "conn-1", tool: "tool", arguments: {}, state: "dispatched", dispatched_at: 1 });
  const originalFsyncSync = fs.fsyncSync;
  let fsyncCount = 0;
  fs.fsyncSync = (fd) => { fsyncCount++; return originalFsyncSync(fd); };
  try {
    recovery.deleteIntent(dir, key);
  } finally {
    fs.fsyncSync = originalFsyncSync;
  }
  check("delete-intent-fsyncs-the-intents-directory", fsyncCount >= 1, `expected at least 1 fsyncSync call, got ${fsyncCount}`);
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

/* Codex PR #33 review "reject resolutions that overwrite terminal intents": both resolve*
 * functions used to patch unconditionally regardless of the intent's current state -- a
 * stale or repeated operator command could silently rewrite an already-`completed`
 * intent's own observed result, or flip a `not_executed` intent the other way, discarding
 * real evidence. Only dispatched/ambiguous may transition; a repeat of the SAME terminal
 * resolution is a no-op; any OTHER terminal state is refused outright. */
function resolveIntentGuardsAgainstOverwritingATerminalState() {
  const dir = freshDir("intent-resolve-terminal-guard");
  const keyCompleted = recovery.computeIntentKey("conn-1", "toolA", {});
  recovery.createIntentIfAbsent(dir, keyCompleted, { connection_id: "conn-1", tool: "toolA", arguments: {}, state: "dispatched", dispatched_at: 1 });
  recovery.resolveIntentExecuted(dir, keyCompleted, { charged: true });

  let threwOnRepeat = null;
  let repeatResult = null;
  try { repeatResult = recovery.resolveIntentExecuted(dir, keyCompleted, { charged: true }); } catch (error) { threwOnRepeat = error; }
  check("resolve-executed-repeat-is-a-no-op-not-a-throw", threwOnRepeat === null, threwOnRepeat && threwOnRepeat.message);
  check("resolve-executed-repeat-does-not-change-the-record", repeatResult && repeatResult.cached_result.charged === true, JSON.stringify(repeatResult));

  let threwOnConflict = null;
  try { recovery.resolveIntentNotExecuted(dir, keyCompleted); } catch (error) { threwOnConflict = error; }
  check("resolve-not-executed-refuses-to-overwrite-a-completed-intent", threwOnConflict && threwOnConflict.code === "GATEWAY_RECOVERY_INTENT_TERMINAL", threwOnConflict && threwOnConflict.code);
  check("resolve-not-executed-refusal-did-not-mutate-the-record", recovery.readIntent(dir, keyCompleted).state === "completed", JSON.stringify(recovery.readIntent(dir, keyCompleted)));

  const keyNotExecuted = recovery.computeIntentKey("conn-1", "toolB", {});
  recovery.createIntentIfAbsent(dir, keyNotExecuted, { connection_id: "conn-1", tool: "toolB", arguments: {}, state: "ambiguous" });
  recovery.resolveIntentNotExecuted(dir, keyNotExecuted);
  let threwOnReverseConflict = null;
  try { recovery.resolveIntentExecuted(dir, keyNotExecuted, { forced: true }); } catch (error) { threwOnReverseConflict = error; }
  check("resolve-executed-refuses-to-overwrite-a-not-executed-intent", threwOnReverseConflict && threwOnReverseConflict.code === "GATEWAY_RECOVERY_INTENT_TERMINAL", threwOnReverseConflict && threwOnReverseConflict.code);
  check("resolve-executed-refusal-did-not-mutate-the-record", recovery.readIntent(dir, keyNotExecuted).state === "not_executed", JSON.stringify(recovery.readIntent(dir, keyNotExecuted)));

  let threwOnRepeatNotExecuted = null;
  try { recovery.resolveIntentNotExecuted(dir, keyNotExecuted); } catch (error) { threwOnRepeatNotExecuted = error; }
  check("resolve-not-executed-repeat-is-a-no-op-not-a-throw", threwOnRepeatNotExecuted === null, threwOnRepeatNotExecuted && threwOnRepeatNotExecuted.message);
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

/* Cluster A (generation-aware crash recovery): the intent file's `generation` is
 * overwritten IN PLACE on every supersede -- by the time recovery runs it always
 * reflects the MOST RECENT generation, not necessarily the one a specific crashed
 * CALL_START event belongs to. Reproduces the exact gap this closes: generation 1
 * completes for real but its own CALL_RESULT WAL write never lands (proxy.js's
 * documented best-effort append -- a real ENOSPC, not a crash), then the SAME
 * connection later dispatches and cleanly completes generation 2 of the identical
 * (tool, arguments), whose CALL_RESULT WAL write DOES land. A subsequent real crash
 * leaves generation 1's own CALL_START forever unresolved in the WAL while the intent
 * file now sits at generation 2. Before this fix, recoverCrashedSessions would have
 * bound generation 2's cached_result (a DIFFERENT call's real outcome) to generation 1's
 * pending call -- a false attestation. */
function recoverDoesNotBindALaterGenerationsResultToAnEarlierCrashedGenerationsCall() {
  const dir = freshDir("recover-generation-mismatch");
  const keys = makeKeys();
  const connectionId = "conn-gen-mismatch";
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [{ name: "echo", server: "srv", schema: {} }] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  // Generation 1: dispatched, completes for real, but its CALL_RESULT WAL line never lands.
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 1 }, ts: 10, generation: 1 });
  const intentKey = recovery.computeIntentKey(connectionId, "echo", { a: 1 });
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: connectionId, tool: "echo", arguments: { a: 1 }, state: "dispatched", dispatched_at: 9, generation: 1 });
  recovery.updateIntent(dir, intentKey, { state: "completed", completed_at: 11, cached_result: { from: "generation-1" }, generation: 1 });
  // Generation 2 (same connection, same tool+arguments, no caller idempotency key --
  // proxy.js's supersede path): dispatched, ALSO completes for real, and this time its
  // CALL_RESULT WAL line DOES land.
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 2, tool: "echo", server: "srv", arguments: { a: 1 }, ts: 20, generation: 2 });
  recovery.updateIntent(dir, intentKey, { state: "dispatched", dispatched_at: 19, generation: 2, cached_result: undefined, completed_at: undefined });
  recovery.updateIntent(dir, intentKey, { state: "completed", completed_at: 21, cached_result: { from: "generation-2" }, generation: 2 });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 2, result: { from: "generation-2" }, isError: false, ts: 21, generation: 2 });

  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check(
    "recover-does-not-auto-seal-a-generation-mismatched-crashed-call",
    pendingOperatorReview.includes(connectionId),
    JSON.stringify(pendingOperatorReview)
  );
  check("recover-leaves-the-wal-in-place-for-a-generation-mismatch", recovery.readWalEvents(dir, connectionId).length > 0, "WAL was deleted despite an unresolved generation-1 call");
  check("recover-does-not-seal-a-chain-entry-for-a-generation-mismatch", chain.readHead(dir) === null, "a chain entry was appended despite generation 1's own outcome being unproven");
}

/* Cluster B (session-identity distinctness in the audit trail): replaying the identical
 * crash-left WAL -- including its own persisted session_id, exactly as proxy.js's real
 * openConnection writes it -- in two completely independent recovery runs must produce
 * the identical bundle_id both times (replay reuses the persisted session_id; it never
 * mints a fresh one -- see session.js#createSession's own doc comment). */
function walReplayedTwiceInIndependentStateDirsProducesIdenticalBundleId() {
  const keys = makeKeys();
  const connectionId = "conn-replay-twice";
  function buildAndRecover() {
    const dir = freshDir("replay-twice");
    recovery.appendWalEvent(dir, connectionId, {
      type: "SESSION_START",
      started_at: 1,
      goal: null,
      session_id: "fixed-session-id-for-replay-determinism-test",
      tools: [{ name: "echo", server: "srv", schema: {} }],
    });
    recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
    recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 1 }, ts: 10, generation: 1 });
    const intentKey = recovery.computeIntentKey(connectionId, "echo", { a: 1 });
    recovery.createIntentIfAbsent(dir, intentKey, { connection_id: connectionId, tool: "echo", arguments: { a: 1 }, state: "dispatched", dispatched_at: 9, generation: 1 });
    recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11, generation: 1 });
    recoverCrashedSessions(dir, keys, silentLog);
    return chain.readHead(dir);
  }
  const headA = buildAndRecover();
  const headB = buildAndRecover();
  check(
    "wal-replayed-twice-in-independent-envs-produces-identical-bundle-id",
    Boolean(headA && headB && typeof headA.bundle_id === "string" && headA.bundle_id === headB.bundle_id),
    JSON.stringify({ headA, headB })
  );
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

/* Codex PR #33 review "verify the chain entry before cleaning a colliding WAL": content
 * verification alone proves the BUNDLE FILE on disk really is this connection's own
 * durable record -- it does not prove chain.appendSession's own chain.jsonl append (step
 * 2 of its own documented write order) ever actually happened. Simulates exactly that
 * partial-append crash (bundle file present and content-verified, chain.jsonl/HEAD.json
 * still reflecting "no chain yet") by sealing normally once, then stripping only the
 * chain.jsonl/HEAD.json side of that append and re-seeding the identical WAL as a second
 * crash-left copy would look. Recovery must complete the missing append, not just discard
 * the WAL believing nothing more was needed. */
function recoverRepairsAPartialAppendMissingItsChainEntry() {
  const dir = freshDir("recover-partial-append");
  const keys = makeKeys();
  const connectionId = "conn-partial";
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(dir, keys, silentLog);
  const firstHead = chain.readHead(dir);
  check("partial-append-fixture-first-pass-sealed", firstHead && firstHead.seq === 1, JSON.stringify(firstHead));

  // Simulate the crash landing between chain.appendSession's own bundle-file write and its
  // chain.jsonl append: the bundle file stays exactly as written; chain.jsonl/HEAD.json are
  // rolled back to "nothing appended yet".
  fs.unlinkSync(chain.chainPath(dir));
  fs.unlinkSync(chain.headPath(dir));
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("partial-append-repair-does-not-need-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("partial-append-repair-completes-the-missing-chain-entry", chain.chainHasEntryForBundle(dir, firstHead.bundle_id), "chain.jsonl still has no entry for the content-verified bundle");
  const headAfter = chain.readHead(dir);
  check("partial-append-repair-head-points-at-the-repaired-entry", headAfter && headAfter.seq === 1 && headAfter.bundle_id === firstHead.bundle_id, JSON.stringify(headAfter));
  check("partial-append-repair-cleans-up-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
}

/* Codex PR #33 review "renew ownership during synchronous recovery": recoverCrashedSessions'
 * own per-connection loop is entirely synchronous fs work that can, with enough or large
 * enough crash-left WALs, run long enough to starve the writer-claim's async heartbeat past
 * its own staleAfterMs -- writer-claim.js's own startHeartbeat() doc comment discloses
 * exactly this gap and prescribes a synchronous renew() call at the boundary of any long
 * synchronous phase the claim is held across. */
function recoverCrashedSessionsRenewsTheWriterClaimPerConnection() {
  const dir = freshDir("recover-renew");
  const keys = makeKeys();
  seedCleanCallWal(dir, "conn-1");
  recovery.appendWalEvent(dir, "conn-1", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  seedCleanCallWal(dir, "conn-2");
  recovery.appendWalEvent(dir, "conn-2", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let renewCalls = 0;
  const fakeWriterClaim = { renew: () => { renewCalls++; } };
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog, fakeWriterClaim);
  check("recover-renews-the-claim-once-per-connection", renewCalls === 2, String(renewCalls));
  check("recover-with-a-fake-claim-still-seals-normally", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
}

function recoverCrashedSessionsWithoutAWriterClaimStillWorks() {
  // Every existing direct caller of recoverCrashedSessions (this whole test file) omits
  // the writerClaim argument -- confirms it stays fully optional/backward-compatible.
  const dir = freshDir("recover-no-claim-arg");
  const keys = makeKeys();
  seedCleanCallWal(dir, "conn-1");
  recovery.appendWalEvent(dir, "conn-1", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  let threw = null;
  try { recoverCrashedSessions(dir, keys, silentLog); } catch (error) { threw = error; }
  check("recover-without-a-writer-claim-argument-does-not-throw", threw === null, threw && threw.message);
}

function recoverCrashedSessionsAbortsImmediatelyIfTheClaimIsLost() {
  const dir = freshDir("recover-renew-lost");
  const keys = makeKeys();
  seedCleanCallWal(dir, "conn-a");
  recovery.appendWalEvent(dir, "conn-a", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  seedCleanCallWal(dir, "conn-b");
  recovery.appendWalEvent(dir, "conn-b", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let renewCalls = 0;
  const fakeWriterClaim = {
    renew: () => {
      renewCalls++;
      const error = new Error("Lost the writer-claim: another writer has taken over.");
      error.code = "WRITER_CLAIM_LOST";
      throw error;
    },
  };
  let threw = null;
  try {
    recoverCrashedSessions(dir, keys, silentLog, fakeWriterClaim);
  } catch (error) {
    threw = error;
  }
  check("recover-aborts-when-the-claim-is-lost-mid-pass", threw && threw.code === "WRITER_CLAIM_LOST", threw && threw.code);
  check("recover-stops-at-the-very-first-renew-failure", renewCalls === 1, String(renewCalls));
  // The claim was lost before EITHER connection's own body ran -- neither WAL may be
  // touched, since this process can no longer prove it is still the sole writer.
  const remaining = recovery.listActiveConnections(dir);
  check("recover-leaves-every-connections-wal-untouched-once-the-claim-is-lost", remaining.length === 2 && remaining.includes("conn-a") && remaining.includes("conn-b"), JSON.stringify(remaining));
  check("recover-appended-no-chain-entry-once-the-claim-is-lost", chain.readHead(dir) === null, JSON.stringify(chain.readHead(dir)));
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

/* Codex PR #33 review "verify collisions in recovery-abandon before cleanup": unlike
 * recoverCrashedSessions' own already-hardened GATEWAY_BUNDLE_ID_COLLISION handling
 * (bundleCollisionWithDifferentContentIsFlaggedNotDiscarded above), abandonConnection used
 * to treat EVERY collision on that error code as the expected repeated-attempt case and
 * fall straight through to deleting the connection's WAL/intents -- discarding a genuinely
 * DIFFERENT session's only remaining, unrecoverable record. */
function abandonConnectionRefusesOnUnverifiedBundleCollision() {
  const dir = freshDir("abandon-collision");
  const keys = makeKeys();
  // First connection: seals normally via recoverCrashedSessions, occupying a bundle_id
  // derived only from {init, grantedTools, n: calls.length} -- not the actual content.
  seedCleanCallWal(dir, "conn-x");
  recovery.appendWalEvent(dir, "conn-x", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(dir, keys, silentLog);
  const firstHead = chain.readHead(dir);

  // Second, DIFFERENT connection an operator now runs recovery-abandon on: same tool,
  // same init shape, same call count (1) -- deliberately different arguments/result, so
  // it collides on bundle_id despite being a genuinely different session's content.
  const connectionId = "conn-y";
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [{ name: "echo", server: "srv", schema: {} }] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 999 }, ts: 10 });
  const intentKeyY = recovery.computeIntentKey(connectionId, "echo", { a: 999 });
  recovery.createIntentIfAbsent(dir, intentKeyY, { connection_id: connectionId, tool: "echo", arguments: { a: 999 }, state: "dispatched", dispatched_at: 9 });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: false, different: true }, isError: false, ts: 11 });

  let threw = null;
  try { abandonConnection(dir, keys, connectionId, silentLog); } catch (error) { threw = error; }
  check("abandon-collision-refuses-rather-than-silently-cleaning-up", threw !== null, "abandonConnection did not throw on an unverified collision");
  check("abandon-collision-wal-not-discarded", recovery.readWalEvents(dir, connectionId).length > 0, "WAL was deleted despite unverified collision");
  check("abandon-collision-intent-not-discarded", recovery.readIntent(dir, intentKeyY) !== null, "intent was deleted despite unverified collision");
  const headAfter = chain.readHead(dir);
  check("abandon-collision-no-second-chain-entry-appended", headAfter && headAfter.seq === firstHead.seq, JSON.stringify(headAfter));
}

/* Same GATEWAY_BUNDLE_ID_COLLISION content-verification path, but for the ordinary case
 * where recovery-abandon really is re-run on the SAME already-sealed connection (matching
 * content) -- must still succeed and clean up normally, not regress into refusing every
 * collision unconditionally. */
function abandonConnectionStillSucceedsOnAGenuineRepeatedAttempt() {
  const dir = freshDir("abandon-collision-repeat");
  const keys = makeKeys();
  const connectionId = "conn-repeat";
  const intentKey = seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  // First abandon: seals it for real.
  abandonConnection(dir, keys, connectionId, silentLog);
  const firstHead = chain.readHead(dir);
  // Re-seed the IDENTICAL WAL/intent (as a crash-left copy of the same connection's state
  // would look on disk) and abandon it again -- same content, same bundle_id, expected.
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  let threw = null;
  try { abandonConnection(dir, keys, connectionId, silentLog); } catch (error) { threw = error; }
  check("abandon-repeated-genuine-attempt-does-not-throw", threw === null, threw && threw.message);
  check("abandon-repeated-genuine-attempt-cleans-up-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");
  const headAfter = chain.readHead(dir);
  check("abandon-repeated-genuine-attempt-no-duplicate-chain-entry", headAfter && headAfter.seq === firstHead.seq, JSON.stringify(headAfter));
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
// PR #33 round-3 fix: forwardDownstreamRequestToAgent's own WAL persistence for
// downstream-initiated sampling/createMessage forwards (Codex "persist sampling calls
// in the recovery WAL"), and that recovery replay preserves the isModelCall flag and
// does not block auto-seal on an unresolved (unfenced) sampling call.
// ---------------------------------------------------------------------------

/** Minimal fake GatewayProxy shape forwardDownstreamRequestToAgent actually reads:
 * .stateDir, .now(), and .sessions (a Map already containing the one live session). */
function fakeProxyWithSession(dir, connectionId, s) {
  return { stateDir: dir, now: () => 1000, sessions: new Map([[connectionId, s]]) };
}

function samplingForwardSuccessIsPersistedToWalWithModelCallFlag() {
  const dir = freshDir("sampling-success");
  const connectionId = "conn-sample";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  const agentPusher = { current: () => Promise.resolve({ content: [{ type: "text", text: "hi" }] }), connectionId };
  const msg = { method: "sampling/createMessage", id: 5, params: { prompt: "hi" } };
  return forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy).then((resp) => {
    check("sampling-forward-returns-the-agents-result", resp.result && resp.result.content[0].text === "hi", JSON.stringify(resp));
    const events = recovery.readWalEvents(dir, connectionId);
    const start = events.find((e) => e.type === "CALL_START");
    const result = events.find((e) => e.type === "CALL_RESULT");
    check("sampling-forward-wal-records-call-start-with-model-call-flag", Boolean(start) && start.isModelCall === true && start.tool === "sampling/createMessage", JSON.stringify(events));
    check("sampling-forward-wal-records-call-result-not-an-error", Boolean(result) && result.isError === false, JSON.stringify(events));
    check("sampling-forward-session-records-it-as-a-model-call", s.calls.length === 1 && s.calls[0].model_call === true && s.calls[0].isError === false, JSON.stringify(s.calls));
  });
}

function samplingForwardErrorIsPersistedAsFailedResult() {
  const dir = freshDir("sampling-error");
  const connectionId = "conn-sample-err";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  const agentPusher = { current: () => Promise.reject(new Error("agent unreachable")), connectionId };
  const msg = { method: "sampling/createMessage", id: 6, params: { prompt: "hi" } };
  return forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy).then((resp) => {
    check("sampling-forward-error-still-returns-a-jsonrpc-error", Boolean(resp.error), JSON.stringify(resp));
    const events = recovery.readWalEvents(dir, connectionId);
    const result = events.find((e) => e.type === "CALL_RESULT");
    check("sampling-forward-error-wal-records-call-result-as-an-error", Boolean(result) && result.isError === true, JSON.stringify(events));
    check("sampling-forward-error-session-records-it-as-an-error", s.calls.length === 1 && s.calls[0].isError === true, JSON.stringify(s.calls));
  });
}

/* Codex PR #33 review "refuse sampling when its CALL_START cannot be saved": this WAL
 * append happens strictly BEFORE agentPusher.current() is ever invoked -- nothing has been
 * sent to the agent yet at the point it fails, so this must refuse to forward (a real,
 * retryable JSON-RPC error) rather than dispatch work a subsequent crash could never
 * replay (no CALL_START in the WAL at all). */
function samplingForwardRefusesWhenCallStartCannotBeSaved() {
  const dir = freshDir("sampling-wal-failure");
  const connectionId = "conn-sample-wal-fail";
  // Force recovery.appendWalEvent's own ensureDir(activeDir(...)) to fail: pre-create
  // "gateway-recovery/active" as a plain FILE so mkdirSync(..., {recursive:true}) throws
  // EEXIST instead of creating the directory appendWalEvent needs.
  fs.mkdirSync(path.join(dir, "gateway-recovery"), { recursive: true });
  fs.writeFileSync(path.join(dir, "gateway-recovery", "active"), "not a directory");

  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  let agentWasCalled = false;
  const agentPusher = { current: () => { agentWasCalled = true; return Promise.resolve({ content: [] }); }, connectionId };
  const msg = { method: "sampling/createMessage", id: 7, params: { prompt: "hi" } };
  return forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy).then((resp) => {
    check("sampling-wal-failure-does-not-forward-to-the-agent", agentWasCalled === false, "agentPusher.current was called despite the WAL append failing");
    check("sampling-wal-failure-returns-a-jsonrpc-error", Boolean(resp.error), JSON.stringify(resp));
    check("sampling-wal-failure-rolls-back-the-pending-call-entry", s.pendingCalls.size === 0, String(s.pendingCalls.size));
  });
}

function recoverPreservesModelCallFlagOnSamplingReplay() {
  const dir = freshDir("recover-sampling-replay");
  const keys = makeKeys();
  const connectionId = "conn-sampling-replay";
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "sampling/createMessage", server: "sampling", arguments: { prompt: "hi" }, isModelCall: true, ts: 10 });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { content: [{ type: "text", text: "hi back" }] }, isError: false, ts: 11 });
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-sampling-replay-no-operator-review-needed", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  const headEntry = chain.readHead(dir);
  check("recover-sampling-replay-produces-a-sealed-chain-entry", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
  const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, headEntry.bundle_id), "utf8"));
  const trace = bundle.contents["execution_trace.jsonl"];
  check("recover-sampling-replay-preserves-model-call-flag-not-hardcoded-false", /"model_call":true/.test(trace), trace);
}

function recoverDoesNotBlockAutoSealOnAnUnresolvedSamplingCall() {
  const dir = freshDir("recover-sampling-unresolved");
  const keys = makeKeys();
  const connectionId = "conn-sampling-crash";
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  // No CALL_RESULT: the gateway crashed while the agent was still computing its model
  // response. There is no intent/fence for a sampling call (unlike a fenced tools/call),
  // so this must NOT be treated the same as an unproven fenced call -- it should auto-seal
  // as a real, disconnected/failed result rather than block on operator review forever.
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "sampling/createMessage", server: "sampling", arguments: { prompt: "hi" }, isModelCall: true, ts: 10 });
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("recover-unresolved-sampling-call-does-not-need-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  const headEntry = chain.readHead(dir);
  check("recover-unresolved-sampling-call-still-auto-seals", headEntry && headEntry.seq === 1, JSON.stringify(headEntry));
  const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, headEntry.bundle_id), "utf8"));
  const trace = bundle.contents["execution_trace.jsonl"];
  check("recover-unresolved-sampling-call-recorded-as-an-error-not-a-guessed-success", /"is_error":true/.test(trace), trace);
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

/* Codex PR #33 review "report each unresolved intent key in recovery output": a bare
 * `in_flight` COUNT cannot distinguish an ordinary live in-progress call from a crashed
 * connection's own unresolved one left in the same "dispatched" state -- an operator needs
 * the actual keys (recovery-resolve/recovery-abandon both require the exact key) to act. */
function healthStatusItemizesDispatchedIntentsAlongsideTheCount() {
  const dir = freshDir("health-dispatched");
  const intentKeyA = recovery.computeIntentKey("conn-a", "toolA", { x: 1 });
  recovery.createIntentIfAbsent(dir, intentKeyA, { connection_id: "conn-a", tool: "toolA", arguments: { x: 1 }, state: "dispatched", dispatched_at: 123 });
  const intentKeyB = recovery.computeIntentKey("conn-b", "toolB", {});
  recovery.createIntentIfAbsent(dir, intentKeyB, { connection_id: "conn-b", tool: "toolB", arguments: {}, state: "ambiguous", ambiguous_at: 456, ambiguous_reason: "test" });

  const ctx = {
    config: { state_dir: dir },
    writerClaim: { status: () => ({}) },
    connections: new Map(),
    proxy: { openSessionCount: () => 0 },
  };
  const status = buildHealthStatus(ctx);
  check("health-in-flight-count-still-reported", status.recovery.in_flight === 1, JSON.stringify(status.recovery));
  check(
    "health-dispatched-list-itemizes-the-actual-intent",
    Array.isArray(status.recovery.dispatched) && status.recovery.dispatched.length === 1 && status.recovery.dispatched[0].intent_key === intentKeyA && status.recovery.dispatched[0].connection_id === "conn-a" && status.recovery.dispatched[0].tool === "toolA",
    JSON.stringify(status.recovery)
  );
  check(
    "health-pending-operator-review-unaffected-by-this-change",
    status.recovery.pending_operator_review.length === 1 && status.recovery.pending_operator_review[0].intent_key === intentKeyB,
    JSON.stringify(status.recovery)
  );
}

/* Codex PR #33 review "include the intent key in the advertised resolution command": the
 * RECOVERY_AMBIGUOUS_INTENT log used to print a literal "<key>" placeholder in its example
 * remediation command regardless of which (or how many) calls were actually unresolved --
 * unusable without first hand-parsing raw recovery files to find the real key. */
function recoverAmbiguousIntentLogNamesTheRealKeyNotAPlaceholder() {
  const dir = freshDir("recover-log-real-key");
  const keys = makeKeys();
  const connectionId = "conn-unresolved";
  // A crashed call with NO intent record at all (never even reached createIntentIfAbsent,
  // or its file was lost) -- recoverCrashedSessions must still flag it for operator review
  // (the existing "needsOperator" fallback) and now names its real, computable key.
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [{ name: "echo", server: "srv", schema: {} }] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 1 }, ts: 10 });
  const expectedIntentKey = recovery.computeIntentKey(connectionId, "echo", { a: 1 });

  const logLines = [];
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, (line) => logLines.push(line));
  check("recover-log-real-key-flags-for-operator-review", pendingOperatorReview.includes(connectionId), JSON.stringify(pendingOperatorReview));
  const ambiguousLog = logLines.find((l) => l.includes("RECOVERY_AMBIGUOUS_INTENT"));
  check("recover-log-real-key-line-exists", Boolean(ambiguousLog), JSON.stringify(logLines));
  check("recover-log-real-key-names-the-actual-computed-key", Boolean(ambiguousLog) && ambiguousLog.includes(expectedIntentKey), ambiguousLog || "no log line");
  check("recover-log-real-key-does-not-print-the-old-placeholder", Boolean(ambiguousLog) && !ambiguousLog.includes("--intent <key>"), ambiguousLog || "no log line");
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
  walListActiveConnectionsReturnsSortedOrder();
  recoveryFilesAndDirsAreOwnerOnlyPermissions();
  walOnEmptyRecoveryDirReturnsNoActiveConnections();
  appendWalEventRetriesOnAShortWrite();
  appendWalEventFailsClosedWhenWriteSyncMakesNoProgress();

  intentKeyStableRegardlessOfArgumentKeyOrder();
  intentKeyDiffersOnConnectionToolOrArgs();
  intentKeyTreatsUndefinedArgsAsNull();
  createIntentIfAbsentIsRaceSafe();
  readIntentOfMissingKeyReturnsNull();
  updateIntentMergesAndRejectsUnknown();
  deleteIntentIsIdempotent();
  deleteIntentFsyncsTheIntentsDirectoryAfterRemoval();
  listIntentsForConnectionFiltersCorrectly();
  listAllIntentsSpansEveryConnection();
  operatorResolutionExecutedAndNotExecuted();
  resolveIntentGuardsAgainstOverwritingATerminalState();

  recoverAutoSealsASessionThatCrashedAfterCleanDisconnect();
  recoverClosesFinding1GapUsingCompletedIntentAsProofOfOutcome();
  recoverLeavesUnprovenInFlightCallForOperatorReview();
  recoverIsIdempotentAcrossACrashDuringRecoveryItself();
  recoverDeletesEmptyOrFullyTornWalWithoutFlagging();
  recoverDoesNotBindALaterGenerationsResultToAnEarlierCrashedGenerationsCall();
  walReplayedTwiceInIndependentStateDirsProducesIdenticalBundleId();

  abandonConnectionSealsAndReleasesTheFenceForAnUnprovenCall();
  abandonConnectionOnAlreadyCleanConnectionIsANoOp();

  pathBearingIdentifiersAreRejected();
  bundleCollisionWithDifferentContentIsFlaggedNotDiscarded();
  recoverRepairsAPartialAppendMissingItsChainEntry();
  recoverCrashedSessionsRenewsTheWriterClaimPerConnection();
  recoverCrashedSessionsWithoutAWriterClaimStillWorks();
  recoverCrashedSessionsAbortsImmediatelyIfTheClaimIsLost();
  unreadableWalForOneConnectionDoesNotBlockAnother();
  abandonConnectionQuarantinesAnUnreadableWal();
  abandonConnectionRefusesOnUnverifiedBundleCollision();
  abandonConnectionStillSucceedsOnAGenuineRepeatedAttempt();
  notExecutedIntentReplaysAsAFailedCallAndIsThenCleanedUp();
  healthStatusItemizesDispatchedIntentsAlongsideTheCount();
  recoverAmbiguousIntentLogNamesTheRealKeyNotAPlaceholder();

  recoveryResolveRequiresResultFileForExecuted();
  recoveryResolveRefusesWhileAnotherWriterHoldsTheClaim();

  return samplingForwardSuccessIsPersistedToWalWithModelCallFlag()
    .then(() => samplingForwardErrorIsPersistedAsFailedResult())
    .then(() => samplingForwardRefusesWhenCallStartCannotBeSaved())
    .then(() => {
      recoverPreservesModelCallFlagOnSamplingReplay();
      recoverDoesNotBlockAutoSealOnAnUnresolvedSamplingCall();
    })
    .then(() => writerClaimIsReleasedWhenStartupRecoveryThrows())
    .then(() => {
      const passed = results.filter((r) => r.status === "PASS").length;
      const failed = results.filter((r) => r.status === "FAIL").length;
      const skipped = results.filter((r) => r.status === "SKIP").length;
      console.log(`SUMMARY passed=${passed} failed=${failed} skipped=${skipped}`);
      process.exit(failures ? 1 : 0);
    });
}

main().catch((error) => {
  console.error("FATAL:", error);
  process.exit(1);
});
