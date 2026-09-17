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
const stateStore = require(path.join(ROOT, "scripts", "state-store.js"));
const { recoverCrashedSessions, abandonConnection, startGateway, runRecoveryResolveCli, forwardDownstreamRequestToAgent, buildHealthStatus, writeStatusFile } = require(path.join(ROOT, "scripts", "gateway", "gateway.js"));
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

// Mirrors gsa-mcp-shim.js's own sha256Hex(JSON.stringify(...)) exactly -- the sealed
// execution_trace.jsonl only ever stores a call's result as this hash (privacy-preserving
// by design; see session.js's own doc comment on why), so a test proving replay recovered
// a SPECIFIC real result must compare against this same hash, not grep for raw text that
// the trace never contains.
function expectedResultSha256(result) {
  return crypto.createHash("sha256").update(Buffer.from(JSON.stringify(result === undefined ? null : result), "utf8")).digest("hex");
}

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
 * (Windows has no equivalent permission bits to assert against).
 *
 * Codex PR #33 review round 2 "preserve group access when creating recovery state": the
 * asserted modes are now the SHARED access model (stateStore.DEFAULT_DIR_MODE 0750 /
 * DEFAULT_FILE_MODE 0640) that startup-permissions.js applies to these exact paths, not
 * the single-user 0700/0600 literals recovery.js used to reset them to on every write --
 * which silently undid that startup pass and locked same-group ops tooling out again. The
 * property under test is unchanged (never the umask-dependent world-readable default);
 * only the group bit the later access model deliberately requires has changed. */
function recoveryFilesAndDirsUseTheSharedAccessModel() {
  if (process.platform === "win32") {
    record("recovery-permissions-shared-access-model", "SKIP", "POSIX file mode bits do not apply on win32");
    return;
  }
  const dir = freshDir("permissions");
  recovery.appendWalEvent(dir, "conn-1", { type: "SESSION_START", goal: null });
  const walMode = fs.statSync(recovery.walPath(dir, "conn-1")).mode & 0o777;
  check("recovery-wal-file-is-0640", walMode === 0o640, walMode.toString(8));
  check("recovery-wal-file-is-never-world-readable", (walMode & 0o007) === 0, walMode.toString(8));
  const activeDirMode = fs.statSync(recovery.activeDir(dir)).mode & 0o777;
  check("recovery-active-dir-is-0750", activeDirMode === 0o750, activeDirMode.toString(8));

  const intentKey = recovery.computeIntentKey("conn-1", "toolA", {});
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-1", tool: "toolA", arguments: {}, state: "dispatched", dispatched_at: 1 });
  const intentModeAfterCreate = fs.statSync(recovery.intentPath(dir, intentKey)).mode & 0o777;
  check("recovery-intent-file-is-0640-after-create", intentModeAfterCreate === 0o640, intentModeAfterCreate.toString(8));
  const intentsDirMode = fs.statSync(recovery.intentsDir(dir)).mode & 0o777;
  check("recovery-intents-dir-is-0750", intentsDirMode === 0o750, intentsDirMode.toString(8));

  recovery.updateIntent(dir, intentKey, { state: "ambiguous", ambiguous_at: 2 });
  const intentModeAfterUpdate = fs.statSync(recovery.intentPath(dir, intentKey)).mode & 0o777;
  check("recovery-intent-file-is-0640-after-update", intentModeAfterUpdate === 0o640, intentModeAfterUpdate.toString(8));

  // The point of the fix: startup-permissions.js's pass and recovery.js's own per-write
  // re-tightening must agree, so a write after startup cannot undo it.
  check(
    "recovery-runtime-modes-match-the-startup-permissions-pass",
    activeDirMode === stateStore.DEFAULT_DIR_MODE && walMode === stateStore.DEFAULT_FILE_MODE,
    `${activeDirMode.toString(8)}/${walMode.toString(8)} vs ${stateStore.DEFAULT_DIR_MODE.toString(8)}/${stateStore.DEFAULT_FILE_MODE.toString(8)}`
  );
}

/* Codex PR #33 review "propagate real directory fsync failures": fsyncDir used to swallow
 * EVERY error, so a genuine EIO while making a new WAL/intent's DIRECTORY ENTRY durable
 * was reported to the caller as success -- the gateway could dispatch believing its fence
 * was durable and restart to find no record of it. deleteIntent is the smallest public
 * call that ends in fsyncDir and nothing else, so it isolates the behavior exactly.
 * Only the directory open (flags "r") is faulted; the record's own unlink is left real. */
function directoryFsyncRealIoFailurePropagates() {
  const dir = freshDir("fsyncdir-eio");
  const intentKey = recovery.computeIntentKey("conn-fsync", "toolA", {});
  recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-fsync", tool: "toolA", arguments: {}, state: "dispatched", dispatched_at: 1 });

  const realOpenSync = fs.openSync;
  let threw = null;
  fs.openSync = function (p, flags, mode) {
    if (flags === "r") throw Object.assign(new Error("EIO: simulated directory fsync failure"), { code: "EIO" });
    return realOpenSync.call(fs, p, flags, mode);
  };
  try {
    recovery.deleteIntent(dir, intentKey);
  } catch (error) {
    threw = error;
  } finally {
    fs.openSync = realOpenSync;
  }
  check("directory-fsync-eio-propagates-instead-of-reporting-success", threw !== null && threw.code === "EIO", threw ? `${threw.code}: ${threw.message}` : "did not throw");
}

/* The other half: the cases this helper was actually written to tolerate must still be
 * tolerated -- a directory that is simply gone (ENOENT, e.g. mid-teardown in a test) and a
 * platform/filesystem that does not support fsync on a directory fd (EINVAL) are NOT real
 * I/O faults and must not turn a durably-completed write into a failure. */
function directoryFsyncUnsupportedAndMissingAreStillTolerated() {
  for (const code of ["ENOENT", "EINVAL", "ENOTSUP", "EPERM"]) {
    const dir = freshDir(`fsyncdir-tolerated-${code.toLowerCase()}`);
    const intentKey = recovery.computeIntentKey("conn-fsync", "toolA", {});
    recovery.createIntentIfAbsent(dir, intentKey, { connection_id: "conn-fsync", tool: "toolA", arguments: {}, state: "dispatched", dispatched_at: 1 });

    const realOpenSync = fs.openSync;
    let threw = null;
    fs.openSync = function (p, flags, mode) {
      if (flags === "r") throw Object.assign(new Error(`${code}: simulated`), { code });
      return realOpenSync.call(fs, p, flags, mode);
    };
    try {
      recovery.deleteIntent(dir, intentKey);
    } catch (error) {
      threw = error;
    } finally {
      fs.openSync = realOpenSync;
    }
    check(`directory-fsync-${code.toLowerCase()}-is-still-tolerated`, threw === null, threw && `${threw.code}: ${threw.message}`);
    check(`directory-fsync-${code.toLowerCase()}-still-completed-the-real-work`, recovery.readIntent(dir, intentKey) === null, "intent was not actually deleted");
  }
}

/* Codex PR #33 review "retain operator-confirmed results for reconnect replay": when an
 * operator resolves a crashed keyed call as EXECUTED, this used to update only the
 * connection-scoped intent. Startup recovery then consumes and deletes that intent, so --
 * unlike proxy.js's live completion path -- nothing ever wrote the connection-INDEPENDENT
 * completed-signature record, and a reconnecting agent presenting the same idempotency key
 * computed a brand-new intentKey, found nothing, and dispatched the already-executed side
 * effect a second time. */
function operatorConfirmedExecutedRetainsTheCrossConnectionSignature() {
  const dir = freshDir("operator-confirmed-signature");
  const intentKey = recovery.computeIntentKey("conn-crashed", "charge", { amount: 5 });
  recovery.createIntentIfAbsent(dir, intentKey, {
    connection_id: "conn-crashed",
    tool: "charge",
    arguments: { amount: 5 },
    state: "dispatched",
    dispatched_at: 1,
    idempotency_key: "customer-key-1",
    generation: 1,
  });
  recovery.resolveIntentExecuted(dir, intentKey, { value: 7 });

  const signatureKey = recovery.computeSignatureKey("charge", { amount: 5 }, "customer-key-1");
  const retained = recovery.readCompletedSignature(dir, signatureKey);
  check("operator-confirmed-executed-writes-the-completed-signature", retained !== null, "no retained signature was written");
  check(
    "operator-confirmed-executed-signature-carries-the-confirmed-result-and-key",
    Boolean(retained) && retained.idempotency_key === "customer-key-1" && retained.cached_result && retained.cached_result.value === 7,
    JSON.stringify(retained)
  );

  // The operator's own primary resolution is unchanged by the secondary write.
  const resolved = recovery.readIntent(dir, intentKey);
  check("operator-confirmed-executed-intent-still-terminal-completed", resolved.state === "completed" && resolved.resolution === "operator_confirmed_executed", JSON.stringify(resolved));
}

/* Same review item, negative half: a call with NO caller idempotency key can never be
 * replayed by proxy.js's own read gate (which requires retained.idempotency_key to match),
 * so resolving it must not leave an unreplayable-by-construction file sitting in the
 * signature store until its retention window expires. */
function operatorConfirmedExecutedWithoutAKeyWritesNoSignature() {
  const dir = freshDir("operator-confirmed-no-key");
  const intentKey = recovery.computeIntentKey("conn-crashed", "charge", { amount: 5 });
  recovery.createIntentIfAbsent(dir, intentKey, {
    connection_id: "conn-crashed",
    tool: "charge",
    arguments: { amount: 5 },
    state: "dispatched",
    dispatched_at: 1,
    idempotency_key: null,
    generation: 1,
  });
  recovery.resolveIntentExecuted(dir, intentKey, { value: 7 });
  const retained = recovery.readCompletedSignature(dir, recovery.computeSignatureKey("charge", { amount: 5 }, null));
  check("operator-confirmed-executed-without-a-key-writes-no-signature", retained === null, JSON.stringify(retained));
}

/* Codex PR #33 review "keep the WAL until corrupt-intent cleanup succeeds":
 * listIntentsForConnection reads every intent file on disk before filtering and throws on
 * any damaged one -- including an unrelated one. Running it AFTER deleteWal meant
 * recovery-abandon could irreversibly destroy this connection's last remaining record and
 * then abort, leaving the corrupt fence with nothing left to quarantine or replay. */
function abandonConnectionKeepsTheWalWhenTheIntentScanFails() {
  const dir = freshDir("abandon-intent-scan-failure");
  const keys = makeKeys();
  const connectionId = "conn-scan-failure";
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  const realListIntentsForConnection = recovery.listIntentsForConnection;
  recovery.listIntentsForConnection = () => {
    throw Object.assign(new Error("Corrupt intent record \"gs_int_unrelated\": Unexpected end of JSON input"), { code: "GATEWAY_RECOVERY_INTENT_CORRUPT" });
  };
  let threw = null;
  try {
    abandonConnection(dir, keys, connectionId, silentLog);
  } catch (error) {
    threw = error;
  } finally {
    recovery.listIntentsForConnection = realListIntentsForConnection;
  }
  check("abandon-intent-scan-failure-surfaces-the-error", threw !== null && threw.code === "GATEWAY_RECOVERY_INTENT_CORRUPT", threw ? `${threw.code}: ${threw.message}` : "did not throw");
  check(
    "abandon-intent-scan-failure-leaves-the-wal-intact",
    recovery.readWalEvents(dir, connectionId).length > 0,
    "the WAL was deleted before the intent scan that failed -- nothing left to quarantine or replay"
  );

  // And the whole command stays re-runnable once the corrupt record is dealt with: the
  // bundle is already sealed, so the retry takes the content-verified collision path.
  let secondThrow = null;
  try {
    abandonConnection(dir, keys, connectionId, silentLog);
  } catch (error) {
    secondThrow = error;
  }
  check("abandon-intent-scan-failure-is-re-runnable-after-the-scan-is-fixed", secondThrow === null, secondThrow && `${secondThrow.code}: ${secondThrow.message}`);
  check("abandon-intent-scan-failure-retry-cleans-up-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present after the successful retry");
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

/* Round-1 fix-plan commit 4 test fixture: seedCleanCallWal's own bundle_id formula
 * (gsa-mcp-shim.js: sha256({init, grantedTools, n: calls.length})) depends only on the
 * CALL COUNT, not on any call's actual arguments -- two connections both built from
 * seedCleanCallWal always collide on bundle_id regardless of their argument values. This
 * variant makes TWO calls (n=2) instead of one, so a session sealed from it lands on a
 * genuinely different bundle_id than seedCleanCallWal's own -- needed to advance the
 * chain's tail to a second, distinct entry so a test can then re-present the FIRST
 * connection's own (now-ancestor, no-longer-tail) chain entry as a bundle-id collision. */
function seedTwoCallWal(dir, connectionId) {
  recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [{ name: "echo", server: "srv", schema: {} }] });
  recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "echo", server: "srv", arguments: { a: 1 }, ts: 10 });
  const intentKey1 = recovery.computeIntentKey(connectionId, "echo", { a: 1 });
  recovery.createIntentIfAbsent(dir, intentKey1, { connection_id: connectionId, tool: "echo", arguments: { a: 1 }, state: "dispatched", dispatched_at: 9 });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 2, tool: "echo", server: "srv", arguments: { a: 2 }, ts: 12 });
  const intentKey2 = recovery.computeIntentKey(connectionId, "echo", { a: 2 });
  recovery.createIntentIfAbsent(dir, intentKey2, { connection_id: connectionId, tool: "echo", arguments: { a: 2 }, state: "dispatched", dispatched_at: 9 });
  return intentKey2;
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

/* Round-1 fix-plan commit 4 regression test ("WAL-survives-failed-cleanup"): reproduces
 * the exact scenario the rewritten verifyAndRepairBundleCollision exists for. The OLD
 * shipped check compared HEAD directly against the colliding bundle's OWN chain entry --
 * which breaks the instant any OTHER session sealed afterward and moved HEAD on, even
 * though the original entry is still a perfectly valid, verified ANCESTOR of the current
 * tail. Sequence: connection A seals (chain tail becomes A's entry); a different
 * connection B then also seals (chain tail advances to B's entry, A's entry is now an
 * ancestor, not the tail); A's own WAL/intent is then re-seeded EXACTLY as it looked
 * before recovery ever cleaned it up (its own real "recovery completed but the WAL
 * unlink never landed" crash signature) and recovery is run a third time. The rewritten
 * check (HEAD equals the chain's own current tail, not equals this bundle's own entry)
 * must allow this cleanup rather than refusing it. */
function bundleCollisionRewriteAllowsAncestorEntryWhenHeadPointsAtANewerTail() {
  const dir = freshDir("collision-ancestor-ok");
  const keys = makeKeys();
  const connA = "conn-ancestor-a";
  seedCleanCallWal(dir, connA);
  recovery.appendWalEvent(dir, connA, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(dir, keys, silentLog);
  const entryA = chain.readHead(dir);
  check("collision-ancestor-fixture-a-sealed", entryA && entryA.seq === 1, JSON.stringify(entryA));

  const connB = "conn-ancestor-b";
  seedTwoCallWal(dir, connB);
  recovery.appendWalEvent(dir, connB, { type: "CALL_RESULT", call_seq: 2, result: { ok: true }, isError: false, ts: 13 });
  recoverCrashedSessions(dir, keys, silentLog);
  const entryB = chain.readHead(dir);
  check(
    "collision-ancestor-fixture-b-sealed-as-new-tail",
    entryB && entryB.seq === 2 && entryB.bundle_id !== entryA.bundle_id,
    JSON.stringify({ entryA, entryB })
  );

  // Re-seed connection A's WAL with IDENTICAL content -- the WAL-survives-a-failed-
  // cleanup scenario: recovery's own post-seal cleanup for A crashed before deleting its
  // WAL/intent, leaving an exact duplicate on disk that a later recovery pass must still
  // be able to clean up even though HEAD has since moved on to B's entry.
  seedCleanCallWal(dir, connA);
  recovery.appendWalEvent(dir, connA, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("collision-ancestor-not-flagged-for-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  check("collision-ancestor-wal-cleaned-up", recovery.readWalEvents(dir, connA).length === 0, "WAL still present after ancestor-collision cleanup");
  const headAfter2 = chain.readHead(dir);
  check(
    "collision-ancestor-head-still-points-at-b-not-duplicated",
    headAfter2 && headAfter2.seq === 2 && headAfter2.bundle_id === entryB.bundle_id,
    JSON.stringify(headAfter2)
  );
  const chainEntriesAfter = chain.readChain(dir);
  check("collision-ancestor-no-third-chain-entry-appended", chainEntriesAfter.length === 2, JSON.stringify(chainEntriesAfter.map((e) => e.seq)));
}

/* Round-1 fix-plan commit 4 regression test (the negative half of the rewrite above):
 * proves the new HEAD-vs-tail check has real teeth, not just permissiveness. Same setup
 * (A seals, then B seals as the new tail) but HEAD.json is then corrupted into a genuine
 * fork -- same seq/bundle_id as A's own real entry, but a bogus entry_sha256 that does
 * not match anything actually in chain.jsonl -- before A's WAL is re-seeded and recovery
 * run again. This is neither "HEAD already equals the tail" nor a genuine single-step-lag
 * ancestor of it, so the shared classifier must refuse (flag for operator review, leave
 * the WAL/intent/chain untouched) rather than silently accept it as another instance of
 * the legitimate ancestor case above. */
function bundleCollisionRewriteRefusesOnAGenuineForkNotJustAnyAncestorMismatch() {
  const dir = freshDir("collision-fork-refuses");
  const keys = makeKeys();
  // Round-1 fix-plan commit 6: this test's own fork below is exactly the genuine
  // structural failure that now latches chain.js's process-local admission gate
  // (getChainIntegrityFailure). Reset before AND after, so this test's fixture never
  // depends on latch state left behind by an earlier test, and never leaks its own
  // latch into whatever runs next in this same process/file.
  chain._resetChainIntegrityFailureForTests();
  const connA = "conn-fork-a";
  seedCleanCallWal(dir, connA);
  recovery.appendWalEvent(dir, connA, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(dir, keys, silentLog);
  const entryA = chain.readHead(dir);

  const connB = "conn-fork-b";
  seedTwoCallWal(dir, connB);
  recovery.appendWalEvent(dir, connB, { type: "CALL_RESULT", call_seq: 2, result: { ok: true }, isError: false, ts: 13 });
  recoverCrashedSessions(dir, keys, silentLog);

  // Corrupt HEAD.json into a genuine fork: same seq/bundle_id as entry A's real position,
  // but a bogus entry_sha256 that matches no real entry in chain.jsonl -- distinct from
  // the legitimate single-step-lag ancestor case the classifier auto-repairs.
  const forkedHead = Object.assign({}, entryA, { entry_sha256: "f".repeat(64) });
  fs.writeFileSync(chain.headPath(dir), JSON.stringify(forkedHead));

  seedCleanCallWal(dir, connA);
  recovery.appendWalEvent(dir, connA, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
  check("collision-fork-flagged-for-operator-review", pendingOperatorReview.includes(connA), JSON.stringify(pendingOperatorReview));
  check("collision-fork-wal-not-discarded", recovery.readWalEvents(dir, connA).length > 0, "WAL deleted despite an unresolved fork");
  const headAfterFork = JSON.parse(fs.readFileSync(chain.headPath(dir), "utf8"));
  check("collision-fork-head-left-untouched-not-silently-fixed", headAfterFork.entry_sha256 === forkedHead.entry_sha256, JSON.stringify(headAfterFork));
  chain._resetChainIntegrityFailureForTests();
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
  // No maybeRenew() on this fake -- createLeaseGuard's own maybeRenew() wrapper treats
  // its absence as a no-op (exactly like an omitted writerClaim), so only this fixture's
  // TWO unconditional renew() call sites per connection (the per-connection renew at the
  // top of the loop, and the pre-append renew immediately before chain.appendSession)
  // are actually counted here.
  const fakeWriterClaim = { renew: () => { renewCalls++; } };
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog, fakeWriterClaim);
  check("recover-renews-the-claim-twice-per-connection", renewCalls === 4, String(renewCalls));
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

/* Round-1 fix-plan item 1 (lease keepalive, generalized): renew()'s own failure can be a
 * raw fs error (e.g. EIO from writer-claim.js's own openSync) that carries no
 * WRITER_CLAIM_LOST code at all -- the required comparison is by reference identity
 * (createLeaseGuard's own isLeaseError), never `error.code === "WRITER_CLAIM_LOST"` string
 * matching, so a raw fs error must be treated exactly the same as a named claim-loss
 * error: fatal to the whole recovery pass, never downgraded to this connection's own
 * per-connection "flag for operator review, continue" handling. This exercises the
 * UNCONDITIONAL renew() immediately before chain.appendSession specifically (not the
 * per-connection renew() at the top of the loop, already covered by
 * recoverCrashedSessionsAbortsImmediatelyIfTheClaimIsLost above). */
function recoverAbortsOnARawFsErrorFromThePreAppendRenewNotJustNamedClaimCodes() {
  const dir = freshDir("recover-raw-fs-error-pre-append");
  const keys = makeKeys();
  seedCleanCallWal(dir, "conn-a");
  recovery.appendWalEvent(dir, "conn-a", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let renewCalls = 0;
  const rawFsError = new Error("EIO: i/o error, open '/state/writer-claim.json'");
  rawFsError.errno = -5;
  rawFsError.code = "EIO"; // deliberately NOT "WRITER_CLAIM_LOST" -- a genuine raw fs error
  const fakeWriterClaim = {
    renew: () => {
      renewCalls++;
      if (renewCalls === 2) throw rawFsError; // 1: top-of-loop renew, 2: pre-append renew
    },
  };
  let threw = null;
  try {
    recoverCrashedSessions(dir, keys, silentLog, fakeWriterClaim);
  } catch (error) {
    threw = error;
  }
  check("pre-append-renew-raw-fs-error-aborts-with-the-exact-detected-error", threw === rawFsError, threw && threw.message);
  check("pre-append-renew-raw-fs-error-never-reaches-chain-append", chain.readHead(dir) === null, JSON.stringify(chain.readHead(dir)));
}

/* Round-1 fix-plan item 1: the per-event maybeRenew() call inside recoverCrashedSessions'
 * own WAL-replay loop must detect a lease taken over by a competing writer mid-replay --
 * not only once per connection at the loop's own top. This also proves the detected loss
 * aborts the WHOLE function, not merely the one connection whose replay happened to be
 * running when it fired: conn-1 (whose replay/seal finishes before the simulated takeover
 * fires) is fully sealed into the chain, but conn-2 (where the takeover is actually
 * detected) is left completely untouched -- recoverCrashedSessions never falls through to
 * its own per-connection "flag for operator review, continue with the next connection"
 * handling for a lease-loss error, unlike every other failure mode that same per-connection
 * try/catch already tolerates. */
function recoverAbortsOnLeaseTakeoverDuringWalReplayNotJustOneConnection() {
  const dir = freshDir("recover-takeover-mid-replay");
  const keys = makeKeys();
  seedCleanCallWal(dir, "conn-1");
  recovery.appendWalEvent(dir, "conn-1", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  seedCleanCallWal(dir, "conn-2");
  recovery.appendWalEvent(dir, "conn-2", { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let callCount = 0;
  const takeoverError = new Error("simulated competing writer took over this state_dir mid-replay");
  const fakeWriterClaim = {
    renew: () => {},
    maybeRenew: () => {
      callCount++;
      // Each connection's WAL replay above has 4 events (SESSION_START, INITIALIZE,
      // CALL_START, CALL_RESULT), so calls 1-4 are conn-1's own replay and call 5 is
      // conn-2's very first event -- strictly after conn-1's own replay/seal/chain-append
      // has already completed in full.
      if (callCount === 5) throw takeoverError;
    },
  };
  let threw = null;
  try {
    recoverCrashedSessions(dir, keys, silentLog, fakeWriterClaim);
  } catch (error) {
    threw = error;
  }
  check("takeover-mid-replay-aborts-with-the-exact-detected-error", threw === takeoverError, threw && threw.message);
  check("takeover-mid-replay-conn-1-was-already-fully-sealed-first", chain.readHead(dir) !== null, JSON.stringify(chain.readHead(dir)));
  check(
    "takeover-mid-replay-conn-2-left-completely-untouched-not-flagged-for-operator-review",
    recovery.readWalEvents(dir, "conn-2").length === 4,
    String(recovery.readWalEvents(dir, "conn-2").length)
  );
}

/* Round-1 fix-plan item 1: a lease loss detected by verifyAndRepairBundleCollision's own
 * leaseGuard.renew() (called immediately before chain.repairMissingChainEntry) must not be
 * relabeled as an ordinary "RECOVERY CHAIN-REPAIR FAILURE" -- it must propagate by
 * reference identity all the way out of recoverCrashedSessions entirely, exactly like every
 * other detected lease loss in this same function. */
function recoverRepairPathLeaseLossIsNotRelabeledAsAnOrdinaryFailure() {
  const dir = freshDir("recover-repair-path-lease-loss");
  const keys = makeKeys();
  const connectionId = "conn-repair-lease";
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(dir, keys, silentLog);
  const firstHead = chain.readHead(dir);
  check("repair-path-lease-loss-fixture-first-pass-sealed", firstHead && firstHead.seq === 1, JSON.stringify(firstHead));

  // Roll chain.jsonl/HEAD.json back to "nothing appended yet" (same partial-append
  // simulation recoverRepairsAPartialAppendMissingItsChainEntry above uses), then replay
  // the identical WAL again so the second pass hits GATEWAY_BUNDLE_ID_COLLISION and
  // attempts the repair path.
  fs.unlinkSync(chain.chainPath(dir));
  fs.unlinkSync(chain.headPath(dir));
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let renewCalls = 0;
  const rawError = new Error("simulated lease loss during the repair-path renew");
  const fakeWriterClaim = {
    renew: () => {
      renewCalls++;
      if (renewCalls === 3) throw rawError; // 1: top-of-loop, 2: pre-append, 3: repair-path
    },
  };
  let threw = null;
  try {
    recoverCrashedSessions(dir, keys, silentLog, fakeWriterClaim);
  } catch (error) {
    threw = error;
  }
  check("repair-path-lease-loss-propagates-by-reference-not-relabeled", threw === rawError, threw && threw.message);
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

/* Round-1 fix-plan item 1: same unconditional pre-append renew() as recoverCrashedSessions'
 * own normal path, applied to abandonConnection's own single-connection chain-append. This
 * function has no per-connection try/catch of its own -- a detected lease loss simply
 * propagates uncaught out to runRecoveryAbandonCli's caller, exactly as fatal as
 * recoverCrashedSessions' own explicit rethrow. */
function abandonConnectionAbortsWhenThePreAppendRenewFails() {
  const dir = freshDir("abandon-pre-append-renew-fails");
  const keys = makeKeys();
  const connectionId = "conn-abandon-renew-fail";
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let renewCalls = 0;
  const rawError = new Error("simulated lease loss immediately before abandonConnection's own chain.appendSession");
  const fakeWriterClaim = {
    renew: () => {
      renewCalls++;
      if (renewCalls === 2) throw rawError; // 1: top-of-function renew, 2: pre-append renew
    },
  };
  let threw = null;
  try {
    abandonConnection(dir, keys, connectionId, silentLog, fakeWriterClaim);
  } catch (error) {
    threw = error;
  }
  check("abandon-pre-append-renew-failure-aborts-with-the-exact-detected-error", threw === rawError, threw && threw.message);
  check("abandon-pre-append-renew-failure-never-reaches-chain-append", chain.readHead(dir) === null, JSON.stringify(chain.readHead(dir)));
  check("abandon-pre-append-renew-failure-leaves-the-wal-in-place", recovery.readWalEvents(dir, connectionId).length > 0, "WAL was deleted despite the aborted renew");
}

/* Round-1 fix-plan item 1: same reference-identity, not-relabeled requirement as
 * recoverCrashedSessions' own repair path, for abandonConnection's own
 * GATEWAY_BUNDLE_ID_COLLISION handling -- the repair-path lease loss must be rethrown
 * unwrapped, not wrapped in fail()'s own GATEWAY_RECOVERY_CHAIN_REPAIR_FAILED. */
function abandonConnectionRepairPathLeaseLossIsNotRelabeledAsChainRepairFailure() {
  const dir = freshDir("abandon-repair-path-lease-loss");
  const keys = makeKeys();
  const connectionId = "conn-abandon-repair-lease";
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  abandonConnection(dir, keys, connectionId, silentLog);
  const firstHead = chain.readHead(dir);
  check("abandon-repair-path-lease-loss-fixture-first-pass-sealed", firstHead && firstHead.seq === 1, JSON.stringify(firstHead));

  fs.unlinkSync(chain.chainPath(dir));
  fs.unlinkSync(chain.headPath(dir));
  seedCleanCallWal(dir, connectionId);
  recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });

  let renewCalls = 0;
  const rawError = new Error("simulated lease loss during abandonConnection's own repair-path renew");
  const fakeWriterClaim = {
    renew: () => {
      renewCalls++;
      if (renewCalls === 3) throw rawError; // 1: top-of-function, 2: pre-append, 3: repair-path
    },
  };
  let threw = null;
  try {
    abandonConnection(dir, keys, connectionId, silentLog, fakeWriterClaim);
  } catch (error) {
    threw = error;
  }
  check("abandon-repair-path-lease-loss-propagates-by-reference-not-wrapped-in-fail", threw === rawError, threw && threw.message);
  check("abandon-repair-path-lease-loss-has-no-gateway-recovery-error-code", !(threw && threw.code === "GATEWAY_RECOVERY_CHAIN_REPAIR_FAILED"), threw && threw.code);
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
    // Per C1 (docs/contracts/wal-append-failure-semantics.md SS2), ANY appendWalEvent
    // failure on this connection poisons it, not only a CALL_RESULT failure -- otherwise
    // a second sampling request on the same connection could still attempt an append onto
    // whatever the first failure may have left behind.
    check("sampling-wal-failure-poisons-the-connection-too", Boolean(s.walPoisoned) && typeof s.walPoisoned.reason === "string", JSON.stringify(s.walPoisoned));
  });
}

// ---------------------------------------------------------------------------
// Item 5 (2026-09-15 fix-round, C1 contract): fail-closed CALL_RESULT WAL handling for
// forwardDownstreamRequestToAgent's success branch, the mirror-image fail-open error
// branch, and connection-wide WAL poisoning on any append failure on this path. See
// docs/contracts/wal-append-failure-semantics.md for the contract these tests verify.
// ---------------------------------------------------------------------------

/** Monkeypatches recovery.appendWalEvent (the SAME module-singleton object gateway.js
 * itself calls through -- both this test file and gateway.js require the identical
 * "./recovery.js"/"scripts/gateway/recovery.js" module instance) so that only the ONE
 * next append whose event.type === failType runs through `injectFault` instead of going
 * straight to the real implementation; every other append (including a later one for the
 * same connection, once the poison check should have refused it) runs unpatched. Always
 * restores the original in `finally`, whether `fn` resolves, rejects, or throws
 * synchronously. `injectFault` receives the REAL appendWalEvent (bound with its original
 * arguments) so it can inject a raw fs-level failure around an append that actually still
 * writes to the real filesystem for real (this is fault injection at the syscall layer,
 * not a fake that skips the disk -- see its callers below). */
function withOneAppendWalEventFaultForType(failType, injectFault, fn) {
  const original = recovery.appendWalEvent;
  let armed = true;
  recovery.appendWalEvent = function (stateDir, connectionId, event) {
    if (!armed || event.type !== failType) return original.apply(recovery, arguments);
    armed = false;
    const args = arguments;
    return injectFault(() => original.apply(recovery, args));
  };
  const restore = () => { recovery.appendWalEvent = original; };
  let result;
  try {
    result = fn();
  } catch (error) {
    restore();
    throw error;
  }
  if (result && typeof result.then === "function") {
    return result.then(
      (value) => { restore(); return value; },
      (error) => { restore(); throw error; }
    );
  }
  restore();
  return result;
}

function samplingCallResultWalFailurePoisonsTheConnectionAndFailsClosed() {
  const dir = freshDir("sampling-result-poison");
  const connectionId = "conn-sample-poison";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  let agentCallCount = 0;
  const agentPusher = {
    current: () => { agentCallCount++; return Promise.resolve({ content: [{ type: "text", text: "hi" }] }); },
    connectionId,
  };
  const msg = { method: "sampling/createMessage", id: 8, params: { prompt: "hi" } };
  return withOneAppendWalEventFaultForType(
    "CALL_RESULT",
    () => { throw new Error("ENOSPC: simulated CALL_RESULT append failure"); },
    () => forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy)
  ).then((resp) => {
    check("sampling-result-wal-failure-returns-a-jsonrpc-error-not-the-real-result", Boolean(resp.error), JSON.stringify(resp));
    check("sampling-result-wal-failure-does-not-claim-safe-to-retry", !/safe to retry/i.test(resp.error.message), resp.error.message);
    check(
      "sampling-result-wal-failure-states-the-honest-risk-not-a-false-safety-claim",
      /did not durably record/i.test(resp.error.message) && /may already have executed/i.test(resp.error.message) && /retrying/i.test(resp.error.message),
      resp.error.message
    );
    check("sampling-result-wal-failure-records-the-call-as-an-error", s.calls.length === 1 && s.calls[0].isError === true, JSON.stringify(s.calls));
    check(
      "sampling-result-wal-failure-does-not-attach-a-fabricated-digest",
      s.calls[0].result && s.calls[0].result.discarded_result_sha256 === undefined,
      JSON.stringify(s.calls[0].result)
    );
    const anomaly = s.anomalies.find((a) => a.kind === "GATEWAY_RECOVERY_WAL_APPEND_FAILED" && a.tool === "sampling/createMessage");
    check("sampling-result-wal-failure-reuses-the-existing-anomaly-kind-not-a-new-one", Boolean(anomaly), JSON.stringify(s.anomalies));
    check("sampling-result-wal-failure-poisons-the-connection", Boolean(s.walPoisoned) && typeof s.walPoisoned.reason === "string", JSON.stringify(s.walPoisoned));
    check("sampling-result-wal-failure-still-called-the-agent-once", agentCallCount === 1, String(agentCallCount));

    // A second, brand-new sampling request on the SAME (now-poisoned) connection must be
    // refused before it ever reaches agentPusher.current or attempts another append --
    // C1 SS3's "no best-effort second append," generalized to the whole connection.
    const msg2 = { method: "sampling/createMessage", id: 9, params: { prompt: "again" } };
    return forwardDownstreamRequestToAgent(msg2, agentPusher, () => {}, proxy).then((resp2) => {
      check("sampling-result-wal-poisoned-refuses-a-second-call-without-touching-the-agent", agentCallCount === 1, String(agentCallCount));
      check("sampling-result-wal-poisoned-second-call-returns-an-error", Boolean(resp2.error), JSON.stringify(resp2));
      check("sampling-result-wal-poisoned-second-call-names-the-poison", /poisoned/i.test(resp2.error.message), resp2.error.message);
      check("sampling-result-wal-poisoned-does-not-grow-pending-calls", s.pendingCalls.size === 0, String(s.pendingCalls.size));
    });
  });
}

/* Mirror-image of the success-branch failure above (C1): the downstream already got a
 * real JSON-RPC error from the agent's own rejection, so a WAL append failure recording
 * THAT error result must stay fail-open (nothing left to withhold) -- but per C1 SS2 it
 * still poisons the connection, and per this item's own requirement it must be attested
 * via session.recordAnomaly, not merely logged. */
function samplingCallResultErrorBranchWalFailureStaysFailOpenButIsAttestedAndPoisons() {
  const dir = freshDir("sampling-error-result-wal-fail");
  const connectionId = "conn-sample-error-wal-fail";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  const agentPusher = { current: () => Promise.reject(new Error("agent unreachable")), connectionId };
  const msg = { method: "sampling/createMessage", id: 10, params: { prompt: "hi" } };
  return withOneAppendWalEventFaultForType(
    "CALL_RESULT",
    () => { throw new Error("EROFS: simulated CALL_RESULT append failure on the error branch"); },
    () => forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy)
  ).then((resp) => {
    check(
      "sampling-error-branch-wal-failure-still-fails-open-and-returns-the-agents-real-error",
      Boolean(resp.error) && resp.error.message === "agent unreachable",
      JSON.stringify(resp)
    );
    check("sampling-error-branch-wal-failure-still-records-the-error-result", s.calls.length === 1 && s.calls[0].isError === true, JSON.stringify(s.calls));
    const anomaly = s.anomalies.find((a) => a.kind === "GATEWAY_RECOVERY_WAL_APPEND_FAILED" && a.tool === "sampling/createMessage");
    check("sampling-error-branch-wal-failure-is-attested-not-just-logged", Boolean(anomaly), JSON.stringify(s.anomalies));
    check("sampling-error-branch-wal-failure-still-poisons-the-connection", Boolean(s.walPoisoned), JSON.stringify(s.walPoisoned));
  });
}

/* Real fault injection at the syscall layer (not a fake that skips the disk), followed by
 * an actual crash-recovery/replay pass over whatever the injected failure genuinely left
 * on disk -- per C1 SS1, a caught append failure does not tell the caller which of the
 * three outcomes actually happened, so these three tests drive each one directly and
 * confirm replay behaves correctly for each. */

/* C1 outcome 3, first half: "the line was written completely, and a later step failed" --
 * writeFullySync AND appendDurableLine's own file-level fsyncSync both genuinely succeed
 * (every byte is written and confirmed durable), and only the subsequent fs.closeSync of
 * that same fd throws. (Note: fsyncDir, recovery.js's OTHER post-write step, is
 * deliberately best-effort/non-throwing by its own design -- see its doc comment -- so it
 * cannot be the source of a propagating append failure; closeSync is the real one here.)
 * The content is genuinely, completely, durably on disk despite the throw. */
function samplingCallResultFailureAfterACompleteWriteIsWalAuthoritativeOnReplay() {
  const dir = freshDir("sampling-result-after-complete-write");
  const connectionId = "conn-sample-after-complete-write";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  const agentPusher = { current: () => Promise.resolve({ content: [{ type: "text", text: "real-result-after-complete-write" }] }), connectionId };
  const msg = { method: "sampling/createMessage", id: 11, params: { prompt: "hi" } };

  return withOneAppendWalEventFaultForType(
    "CALL_RESULT",
    (runRealAppend) => {
      const originalCloseSync = fs.closeSync;
      let closeCalls = 0;
      fs.closeSync = function (fd) {
        closeCalls++;
        // The first closeSync call within this one append is appendDurableLine's own
        // file-fd close, reached only after writeFullySync + fsyncSync[file] both
        // already returned successfully for real.
        if (closeCalls === 1) throw new Error("EIO: simulated close failure after a complete, fsynced write");
        return originalCloseSync.apply(fs, arguments);
      };
      try {
        return runRealAppend();
      } finally {
        fs.closeSync = originalCloseSync;
      }
    },
    () => forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy)
  ).then((resp) => {
    check("sampling-after-complete-write-still-fails-closed-to-the-live-caller", Boolean(resp.error), JSON.stringify(resp));
    check("sampling-after-complete-write-poisons-the-connection", Boolean(s.walPoisoned), JSON.stringify(s.walPoisoned));

    // Confirm the bytes actually made it to disk complete, despite the throw.
    const events = recovery.readWalEvents(dir, connectionId);
    const resultEvent = events.find((e) => e.type === "CALL_RESULT");
    check(
      "sampling-after-complete-write-wal-line-is-genuinely-complete-on-disk",
      Boolean(resultEvent) && resultEvent.isError === false,
      JSON.stringify(events)
    );

    // An actual crash-recovery/replay pass over this exact on-disk state, as if this
    // process had crashed right after the failed append (which the live gateway, above,
    // could not distinguish from total loss -- it told the caller "error" regardless).
    // Per C1, replay is WAL-authoritative: it must recover the REAL successful result the
    // WAL actually holds, not re-derive the live process's own "not durably recorded"
    // error.
    const keys = makeKeys();
    const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
    check("sampling-after-complete-write-replay-needs-no-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
    const headEntry = chain.readHead(dir);
    check("sampling-after-complete-write-replay-auto-seals", Boolean(headEntry) && headEntry.seq === 1, JSON.stringify(headEntry));
    const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, headEntry.bundle_id), "utf8"));
    const trace = bundle.contents["execution_trace.jsonl"];
    const expectedHash = expectedResultSha256({ content: [{ type: "text", text: "real-result-after-complete-write" }] });
    check(
      "sampling-after-complete-write-replay-recovers-the-real-successful-result",
      /"is_error":false/.test(trace) && trace.includes(expectedHash),
      trace
    );
  });
}

/* C1 outcome 3b: "fsyncSync (data) ... can throw after writeFullySync has already returned
 * successfully" -- the FILE-level fsync itself is the one that fails this time, before the
 * directory fsync is ever reached. The complete line is still genuinely present in the
 * file (writeSync already delivered every byte); only durability-confirmation failed. */
function samplingCallResultFailureDuringFsyncIsWalAuthoritativeOnReplay() {
  const dir = freshDir("sampling-result-during-fsync");
  const connectionId = "conn-sample-during-fsync";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  const agentPusher = { current: () => Promise.resolve({ content: [{ type: "text", text: "real-result-during-fsync" }] }), connectionId };
  const msg = { method: "sampling/createMessage", id: 12, params: { prompt: "hi" } };

  return withOneAppendWalEventFaultForType(
    "CALL_RESULT",
    (runRealAppend) => {
      const originalFsyncSync = fs.fsyncSync;
      fs.fsyncSync = function () {
        // The very first fsyncSync call for this append IS the file-level one --
        // fail it immediately, before fsyncDir is ever reached.
        fs.fsyncSync = originalFsyncSync;
        throw new Error("EIO: simulated file-level fsync failure right after a complete write");
      };
      try {
        return runRealAppend();
      } finally {
        fs.fsyncSync = originalFsyncSync;
      }
    },
    () => forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy)
  ).then((resp) => {
    check("sampling-during-fsync-still-fails-closed-to-the-live-caller", Boolean(resp.error), JSON.stringify(resp));
    check("sampling-during-fsync-poisons-the-connection", Boolean(s.walPoisoned), JSON.stringify(s.walPoisoned));

    const events = recovery.readWalEvents(dir, connectionId);
    const resultEvent = events.find((e) => e.type === "CALL_RESULT");
    check(
      "sampling-during-fsync-wal-line-is-genuinely-complete-on-disk",
      Boolean(resultEvent) && resultEvent.isError === false,
      JSON.stringify(events)
    );

    const keys = makeKeys();
    const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
    check("sampling-during-fsync-replay-needs-no-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
    const headEntry = chain.readHead(dir);
    check("sampling-during-fsync-replay-auto-seals", Boolean(headEntry) && headEntry.seq === 1, JSON.stringify(headEntry));
    const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, headEntry.bundle_id), "utf8"));
    const trace = bundle.contents["execution_trace.jsonl"];
    const expectedHash = expectedResultSha256({ content: [{ type: "text", text: "real-result-during-fsync" }] });
    check(
      "sampling-during-fsync-replay-recovers-the-real-successful-result",
      /"is_error":false/.test(trace) && trace.includes(expectedHash),
      trace
    );
  });
}

/* C1 outcome 2: a torn/partial line. fs.writeSync makes SOME progress and then a LATER
 * call in writeFullySync's own loop THROWS outright (not merely returns 0) -- unlike
 * appendWalEventFailsClosedWhenWriteSyncMakesNoProgress above (a "no progress" return,
 * which writeFullySync's own stall handling cleanly truncates back to the pre-append
 * size), a raw throw from mid-loop bypasses that truncate-on-stall path entirely and
 * leaves a genuinely torn, unparseable line physically on disk. */
function samplingCallResultFailureAfterAPartialWriteReplaysTheOrphanedCallStartAsUnresolved() {
  const dir = freshDir("sampling-result-partial-write");
  const connectionId = "conn-sample-partial-write";
  const s = session.createSession(connectionId, { now: () => 1000 });
  session.recordToolsList(s, []);
  const proxy = fakeProxyWithSession(dir, connectionId, s);
  const agentPusher = { current: () => Promise.resolve({ content: [{ type: "text", text: "never-durably-recorded" }] }), connectionId };
  const msg = { method: "sampling/createMessage", id: 13, params: { prompt: "hi" } };

  return withOneAppendWalEventFaultForType(
    "CALL_RESULT",
    (runRealAppend) => {
      const originalWriteSync = fs.writeSync;
      let calls = 0;
      fs.writeSync = function (fd, buffer, offset, length, position) {
        calls++;
        if (calls === 1) {
          // Genuine partial progress: only half the requested bytes actually land.
          const partial = Math.max(1, Math.floor(length / 2));
          return originalWriteSync(fd, buffer, offset, partial, position);
        }
        // The NEXT call throws outright -- writeFullySync's own stall-truncate path
        // never runs, so the partial bytes from call 1 are left behind, torn.
        throw new Error("EIO: simulated mid-write failure leaving a torn line");
      };
      try {
        return runRealAppend();
      } finally {
        fs.writeSync = originalWriteSync;
      }
    },
    () => forwardDownstreamRequestToAgent(msg, agentPusher, () => {}, proxy)
  ).then((resp) => {
    check("sampling-partial-write-still-fails-closed-to-the-live-caller", Boolean(resp.error), JSON.stringify(resp));
    check("sampling-partial-write-poisons-the-connection", Boolean(s.walPoisoned), JSON.stringify(s.walPoisoned));

    // The torn line is not a parseable CALL_RESULT at all -- readWalEvents' own
    // stop-at-first-bad-line contract drops it entirely.
    const events = recovery.readWalEvents(dir, connectionId);
    check("sampling-partial-write-torn-line-produces-no-parseable-call-result", !events.some((e) => e.type === "CALL_RESULT"), JSON.stringify(events));
    check("sampling-partial-write-call-start-before-the-tear-is-still-intact", events.some((e) => e.type === "CALL_START"), JSON.stringify(events));

    // An actual crash-recovery/replay pass: only the CALL_START survives, so this is
    // exactly the existing "orphaned sampling CALL_START" replay path -- recorded as a
    // real, disconnected/unproven error and auto-sealed, never guessed as a success and
    // never left stuck pending operator review (there is no intent fence for a sampling
    // call to review in the first place).
    const keys = makeKeys();
    const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, silentLog);
    check("sampling-partial-write-replay-needs-no-operator-review", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
    const headEntry = chain.readHead(dir);
    check("sampling-partial-write-replay-auto-seals", Boolean(headEntry) && headEntry.seq === 1, JSON.stringify(headEntry));
    const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, headEntry.bundle_id), "utf8"));
    const trace = bundle.contents["execution_trace.jsonl"];
    check(
      "sampling-partial-write-replay-records-an-error-not-a-guessed-success",
      /"is_error":true/.test(trace) && !/never-durably-recorded/.test(trace),
      trace
    );
  });
}

/* Not a fault-injection scenario at all: a genuinely SUCCESSFUL append, with the process
 * (hypothetically) crashing in the gap between that successful append returning and
 * forwardDownstreamRequestToAgent's own session.recordCallResult/logCompletion ever
 * running -- there is no in-memory session left to consult, only the WAL. Per C1, replay
 * must be WAL-authoritative (recover the real result from disk, not need any live state)
 * and CALL_RESULT replay must be idempotent (a second recovery pass over the identical
 * WAL content, e.g. this same recovery pass itself crashing before cleanup, must not
 * throw, must not re-seal, and must not append a second chain entry). */
function samplingCallResultCrashBetweenSuccessfulAppendAndInMemoryMutationReplaysIdempotently() {
  const dir = freshDir("sampling-crash-between-append-and-memory");
  const keys = makeKeys();
  const connectionId = "conn-sampling-crash-gap";
  const seed = () => {
    recovery.appendWalEvent(dir, connectionId, { type: "SESSION_START", started_at: 1, goal: null, tools: [] });
    recovery.appendWalEvent(dir, connectionId, { type: "INITIALIZE", clientInfo: { name: "agent", version: "1" }, serverInfo: { name: "srv", version: "1" } });
    recovery.appendWalEvent(dir, connectionId, { type: "CALL_START", call_seq: 1, tool: "sampling/createMessage", server: "sampling", arguments: { prompt: "hi" }, isModelCall: true, ts: 10 });
    // This append itself succeeds for real -- "crash between a successful append and the
    // in-memory mutation" means the live process got exactly this far and then died
    // before session.recordCallResult/logCompletion ever ran.
    recovery.appendWalEvent(dir, connectionId, { type: "CALL_RESULT", call_seq: 1, result: { content: [{ type: "text", text: "hi back" }] }, isError: false, ts: 11 });
  };
  seed();
  const first = recoverCrashedSessions(dir, keys, silentLog);
  check("sampling-crash-gap-replay-needs-no-operator-review", first.pendingOperatorReview.length === 0, JSON.stringify(first.pendingOperatorReview));
  const headEntry = chain.readHead(dir);
  check("sampling-crash-gap-replay-is-wal-authoritative-and-auto-seals", Boolean(headEntry) && headEntry.seq === 1, JSON.stringify(headEntry));
  const bundle = JSON.parse(fs.readFileSync(chain.bundlePath(dir, headEntry.bundle_id), "utf8"));
  const trace = bundle.contents["execution_trace.jsonl"];
  const expectedHash = expectedResultSha256({ content: [{ type: "text", text: "hi back" }] });
  check("sampling-crash-gap-replay-recovers-the-real-successful-result", /"is_error":false/.test(trace) && trace.includes(expectedHash), trace);
  check("sampling-crash-gap-replay-cleans-up-the-wal", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present");

  // Idempotency: simulate THIS recovery pass itself crashing between sealing and cleanup
  // by re-seeding the identical WAL and running recovery again (same idiom as
  // recoverIsIdempotentAcrossACrashDuringRecoveryItself above) -- must not throw, must not
  // append a second chain entry, and must not need operator review the second time either.
  seed();
  const second = recoverCrashedSessions(dir, keys, silentLog);
  check("sampling-crash-gap-second-replay-pass-is-not-flagged-for-operator-review", second.pendingOperatorReview.length === 0, JSON.stringify(second.pendingOperatorReview));
  check("sampling-crash-gap-second-replay-pass-does-not-append-a-second-chain-entry", chain.readHead(dir).seq === 1, JSON.stringify(chain.readHead(dir)));
  check("sampling-crash-gap-call-result-replay-is-idempotent", recovery.readWalEvents(dir, connectionId).length === 0, "WAL still present after second pass");
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

/* Round-1 fix-plan commit 4, Paul's 2026-09-15 startup-posture decision: a genuine
 * chain-integrity failure found by chain.reconcileHead at startup must hard-fail --
 * refuse to start, write a diagnostic artifact naming the manual-recovery runbook, and
 * release the writer-claim lease -- rather than starting in some degraded/silent state.
 * Builds a real state_dir with two genuinely sealed sessions (via recoverCrashedSessions,
 * the real public API -- not by disabling the safety check), then corrupts HEAD.json into
 * a genuine fork the same way the bundle-collision regression test above does, so
 * startGateway's own reconcileHead call hits exactly the "worse than single-step lag"
 * case this whole commit exists to hard-fail on. */
/* Round-1 fix-plan commit 6: if an earlier connection's own repair path latches a
 * genuine chain-integrity failure partway through this loop, every remaining
 * connection is guaranteed to hit the identical failure -- this function must abort
 * immediately rather than spend more fsyncs parsing/replaying WALs guaranteed to be
 * quarantined anyway. Builds the latch through the real public detector
 * (chain.reconcileHead on a genuinely forked chain), exactly as commit 4's own
 * startup-hard-fail test above does, rather than poking chain.js's private state. */
function recoverCrashedSessionsAbortsImmediatelyWhenAlreadyLatched() {
  const dir = freshDir("recover-already-latched");
  const keys = makeKeys();

  const connA = "conn-already-latched-a";
  seedCleanCallWal(dir, connA);
  recovery.appendWalEvent(dir, connA, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 1 });
  recoverCrashedSessions(dir, keys, silentLog);
  const entryA = chain.readHead(dir);

  // Fork HEAD against the real, already-sealed tail -- the exact "worse than
  // single-step lag" case commit 4's own reconcileHead refuses and latches on.
  const forkedHead = Object.assign({}, entryA, { entry_sha256: "9".repeat(64) });
  fs.writeFileSync(chain.headPath(dir), JSON.stringify(forkedHead));
  chain._resetChainIntegrityFailureForTests();
  try {
    chain.reconcileHead(dir);
  } catch (error) {
    // expected: this is exactly how a real process would come to have this latched.
  }
  check("recover-abort-fixture-is-latched", Boolean(chain.getChainIntegrityFailure()), JSON.stringify(chain.getChainIntegrityFailure()));

  // Two brand-new crashed connections, each with a fully clean, resolvable WAL -- if
  // recoverCrashedSessions did not abort early, both would ordinarily seal without issue.
  const connB = "conn-already-latched-b";
  seedCleanCallWal(dir, connB);
  recovery.appendWalEvent(dir, connB, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 2 });
  const connC = "conn-already-latched-c";
  seedCleanCallWal(dir, connC);
  recovery.appendWalEvent(dir, connC, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 3 });

  const logs = [];
  const { pendingOperatorReview } = recoverCrashedSessions(dir, keys, (l) => logs.push(l));
  check("recover-abort-processes-nothing", pendingOperatorReview.length === 0, JSON.stringify(pendingOperatorReview));
  const stillActive = recovery.listActiveConnections(dir);
  check("recover-abort-leaves-conn-b-wal-in-place", stillActive.includes(connB), JSON.stringify(stillActive));
  check("recover-abort-leaves-conn-c-wal-in-place", stillActive.includes(connC), JSON.stringify(stillActive));
  check("recover-abort-logs-a-recovery-aborted-message", logs.some((l) => /RECOVERY ABORTED/.test(l)), JSON.stringify(logs));
  chain._resetChainIntegrityFailureForTests();
}

/* Round-1 fix-plan commit 6: documented explicitly, in both code comments and the
 * WRITTEN status output, that the periodic status walk never latches (docs/contracts/
 * chain-validity.md SS5/SS6) and that its cadence is not what stops admission on any
 * finding -- see writeStatusFile's own doc comment for the full rationale. */
function writeStatusFileDocumentsTheCadenceLimitationInTheWrittenOutput() {
  const dir = freshDir("status-cadence-note");
  fs.mkdirSync(dir, { recursive: true });
  const ctx = { config: { state_dir: dir }, writerClaim: { status: () => ({}) }, connections: new Map(), proxy: { openSessionCount: () => 0 } };
  writeStatusFile(ctx, silentLog);
  const written = JSON.parse(fs.readFileSync(path.join(dir, "gateway-status.json"), "utf8"));
  check(
    "status-file-documents-the-cadence-mid-chain-limitation",
    typeof written.session_chain_integrity_cadence_note === "string" &&
      /mid-chain/i.test(written.session_chain_integrity_cadence_note) &&
      /HEAD\/tail/i.test(written.session_chain_integrity_cadence_note) &&
      /evidence only/i.test(written.session_chain_integrity_cadence_note),
    JSON.stringify(written.session_chain_integrity_cadence_note)
  );
}

/* Round-1 fix-plan commit 6: a genuine content-level structural finding (a tampered
 * interior entry) that the periodic status walk's own evidence surfaces must NOT, by
 * itself, latch admission -- per docs/contracts/chain-validity.md SS5, this walk is
 * evidence-only and mixing its own hand-rolled classification into the admission-latch
 * path would violate the "one authoritative structural validator" contract. Real
 * on-disk chain/bundle files (not chain.validateChain's in-memory fixtures) so this
 * exercises the exact path buildHealthStatus/writeStatusFile actually runs. */
function writeStatusFileNeverLatchesEvenOnAGenuineTamperedEntryItFinds() {
  const dir = freshDir("status-never-latches-tampered");
  const e1 = { schema_version: "1.0", seq: 1, bundle_id: "gsa-status-tampered-0000001", prev_entry_sha256: null };
  e1.entry_sha256 = chain.computeEntrySha256(e1);
  const e2 = { schema_version: "1.0", seq: 2, bundle_id: "gsa-status-tampered-0000002", prev_entry_sha256: e1.entry_sha256 };
  e2.entry_sha256 = chain.computeEntrySha256(e2);
  const tamperedE2 = Object.assign({}, e2, { entry_sha256: "7".repeat(64) });
  fs.mkdirSync(chain.sessionsDir(dir), { recursive: true });
  fs.writeFileSync(chain.chainPath(dir), JSON.stringify(e1) + "\n" + JSON.stringify(tamperedE2) + "\n");
  fs.writeFileSync(chain.headPath(dir), JSON.stringify({ schema_version: "1.0", seq: 2, bundle_id: tamperedE2.bundle_id, entry_sha256: tamperedE2.entry_sha256 }));
  fs.writeFileSync(chain.bundlePath(dir, e1.bundle_id), "{}");
  fs.writeFileSync(chain.bundlePath(dir, tamperedE2.bundle_id), "{}");

  chain._resetChainIntegrityFailureForTests();
  const ctx = { config: { state_dir: dir }, writerClaim: { status: () => ({}) }, connections: new Map(), proxy: { openSessionCount: () => 0 } };
  const health = buildHealthStatus(ctx);
  check(
    "status-walk-fixture-actually-finds-the-tampered-entry",
    health.session_chain_integrity.status === "failed" && /TAMPERED/.test(health.session_chain_integrity.evidence.join(" ")),
    JSON.stringify(health.session_chain_integrity)
  );
  writeStatusFile(ctx, silentLog);
  check("status-walk-does-not-latch-even-on-a-genuine-finding", chain.getChainIntegrityFailure() === null, JSON.stringify(chain.getChainIntegrityFailure()));
}

function startupHardFailsWritesDiagnosticAndReleasesTheClaimOnAGenuineChainFork() {
  const root = freshDir("startup-chain-fork");
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
    // Never actually reached -- reconcileHead throws before connectAllDownstreams runs.
    downstream_servers: [{ name: "unused", transport: "stdio", endpoint: "node -e process.exit(1)" }],
    signing_key_ref: keyPath,
  }));

  const keys = makeKeys();
  const connA = "conn-startup-fork-a";
  seedCleanCallWal(stateDir, connA);
  recovery.appendWalEvent(stateDir, connA, { type: "CALL_RESULT", call_seq: 1, result: { ok: true }, isError: false, ts: 11 });
  recoverCrashedSessions(stateDir, keys, silentLog);
  const entryA = chain.readHead(stateDir);

  const connB = "conn-startup-fork-b";
  seedTwoCallWal(stateDir, connB);
  recovery.appendWalEvent(stateDir, connB, { type: "CALL_RESULT", call_seq: 2, result: { ok: true }, isError: false, ts: 13 });
  recoverCrashedSessions(stateDir, keys, silentLog);

  const forkedHead = Object.assign({}, entryA, { entry_sha256: "e".repeat(64) });
  fs.writeFileSync(chain.headPath(stateDir), JSON.stringify(forkedHead));

  let rejection = null;
  return startGateway({ configPath, root, log: () => {} }).then(
    () => { rejection = null; },
    (error) => { rejection = error; }
  ).then(() => {
    check(
      "startup-hard-fail-rejects-with-the-structural-failure-code",
      rejection !== null && rejection.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE",
      rejection ? `${rejection.code}: ${rejection.message}` : "startGateway resolved instead of rejecting"
    );

    const diagnosticPath = path.join(stateDir, "gateway-startup-failure.json");
    let diagnostic = null;
    let readError = null;
    try {
      diagnostic = JSON.parse(fs.readFileSync(diagnosticPath, "utf8"));
    } catch (error) {
      readError = error;
    }
    check("startup-hard-fail-writes-a-diagnostic-artifact", diagnostic !== null, readError && readError.message);
    check(
      "startup-hard-fail-diagnostic-names-the-structural-failure-code",
      Boolean(diagnostic) && diagnostic.code === "GATEWAY_CHAIN_STRUCTURAL_FAILURE",
      JSON.stringify(diagnostic)
    );
    check(
      "startup-hard-fail-diagnostic-references-the-manual-recovery-runbook",
      Boolean(diagnostic) && typeof diagnostic.runbook === "string" && diagnostic.runbook.includes("docs/runbooks/gateway-chain-corruption-recovery.md") && String(diagnostic.action_required || "").includes(diagnostic.runbook),
      JSON.stringify(diagnostic)
    );

    // The writer-claim file must be gone -- proof that writerClaim.release() actually ran
    // rather than leaking a claim an immediate restart would then be refused for.
    const { WriterClaim: WC } = require(path.join(ROOT, "scripts", "writer-claim.js"));
    const fresh = new WC(stateDir, { hostId: "test-second-instance-chain-fork" });
    let acquireError = null;
    try { fresh.acquire(); fresh.release(); } catch (error) { acquireError = error; }
    check("startup-hard-fail-releases-the-writer-claim", acquireError === null, acquireError && acquireError.message);
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
  // Round-1 fix-plan commit 6: chain.js's admission latch is process-local module
  // state, not per-test -- start this whole suite from a known-clean slate regardless
  // of require-time or import-order side effects in any dependency.
  chain._resetChainIntegrityFailureForTests();
  walAppendAndReadRoundTrip();
  walReadOfMissingConnectionReturnsEmpty();
  walTornTailLineToleratedRestKept();
  walListActiveConnectionsAndDelete();
  walListActiveConnectionsReturnsSortedOrder();
  recoveryFilesAndDirsUseTheSharedAccessModel();

  // Codex PR #33 review round 2 (2026-09-17):
  directoryFsyncRealIoFailurePropagates();
  directoryFsyncUnsupportedAndMissingAreStillTolerated();
  operatorConfirmedExecutedRetainsTheCrossConnectionSignature();
  operatorConfirmedExecutedWithoutAKeyWritesNoSignature();
  abandonConnectionKeepsTheWalWhenTheIntentScanFails();
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
  bundleCollisionRewriteAllowsAncestorEntryWhenHeadPointsAtANewerTail();
  bundleCollisionRewriteRefusesOnAGenuineForkNotJustAnyAncestorMismatch();
  recoverRepairsAPartialAppendMissingItsChainEntry();
  recoverCrashedSessionsRenewsTheWriterClaimPerConnection();
  recoverCrashedSessionsWithoutAWriterClaimStillWorks();
  recoverCrashedSessionsAbortsImmediatelyIfTheClaimIsLost();
  recoverAbortsOnARawFsErrorFromThePreAppendRenewNotJustNamedClaimCodes();
  recoverAbortsOnLeaseTakeoverDuringWalReplayNotJustOneConnection();
  recoverRepairPathLeaseLossIsNotRelabeledAsAnOrdinaryFailure();
  unreadableWalForOneConnectionDoesNotBlockAnother();
  abandonConnectionQuarantinesAnUnreadableWal();
  abandonConnectionRefusesOnUnverifiedBundleCollision();
  abandonConnectionStillSucceedsOnAGenuineRepeatedAttempt();
  abandonConnectionAbortsWhenThePreAppendRenewFails();
  abandonConnectionRepairPathLeaseLossIsNotRelabeledAsChainRepairFailure();
  notExecutedIntentReplaysAsAFailedCallAndIsThenCleanedUp();
  healthStatusItemizesDispatchedIntentsAlongsideTheCount();
  recoverAmbiguousIntentLogNamesTheRealKeyNotAPlaceholder();

  recoveryResolveRequiresResultFileForExecuted();
  recoveryResolveRefusesWhileAnotherWriterHoldsTheClaim();

  return samplingForwardSuccessIsPersistedToWalWithModelCallFlag()
    .then(() => samplingForwardErrorIsPersistedAsFailedResult())
    .then(() => samplingForwardRefusesWhenCallStartCannotBeSaved())
    .then(() => samplingCallResultWalFailurePoisonsTheConnectionAndFailsClosed())
    .then(() => samplingCallResultErrorBranchWalFailureStaysFailOpenButIsAttestedAndPoisons())
    .then(() => samplingCallResultFailureAfterACompleteWriteIsWalAuthoritativeOnReplay())
    .then(() => samplingCallResultFailureDuringFsyncIsWalAuthoritativeOnReplay())
    .then(() => samplingCallResultFailureAfterAPartialWriteReplaysTheOrphanedCallStartAsUnresolved())
    .then(() => samplingCallResultCrashBetweenSuccessfulAppendAndInMemoryMutationReplaysIdempotently())
    .then(() => {
      recoverPreservesModelCallFlagOnSamplingReplay();
      recoverDoesNotBlockAutoSealOnAnUnresolvedSamplingCall();
    })
    .then(() => writerClaimIsReleasedWhenStartupRecoveryThrows())
    .then(() => {
      recoverCrashedSessionsAbortsImmediatelyWhenAlreadyLatched();
      writeStatusFileDocumentsTheCadenceLimitationInTheWrittenOutput();
      writeStatusFileNeverLatchesEvenOnAGenuineTamperedEntryItFinds();
    })
    .then(() => startupHardFailsWritesDiagnosticAndReleasesTheClaimOnAGenuineChainFork())
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
