#!/usr/bin/env node
/* GraphSmith standalone gateway -- crash-recovery WAL and idempotency-intent store.
 *
 * Fixes two Codex findings on PR #29, deliberately built as a SEPARATE PR after an
 * independent 5-model external architecture panel review (Option C; see
 * option-c-hardened-design.md in the project record) rather than fixed unilaterally by
 * the team that wrote the original gateway code:
 *
 *   Finding 1 (session.js): a completed tools/call lives only in memory until
 *   closeConnection() seals the whole session at once. A crash between "downstream
 *   returned a result" and "the agent disconnects" silently drops that evidence from the
 *   signed chain -- the gateway would have no way to know, on restart, that it ever
 *   observed that call at all.
 *
 *   Finding 2 (proxy.js): nothing ties a retried tools/call to its original attempt, so
 *   a timeout-then-retry on a side-effecting tool (email, payment, ...) can execute the
 *   downstream side effect twice.
 *
 * Both close with a SEPARATE, UNSIGNED local recovery store -- this module -- leaving
 * session.js, gsa-mcp-shim.js#sealBoundaryBundle, and chain.js's write order and
 * collision semantics completely untouched (verified against the actual current code,
 * not assumed): this module never signs anything and is never itself chain-appended.
 * `session.js` has ZERO diff for this change: the WAL replays through session.js's
 * existing, unmodified createSession/recordInitialize/recordToolsList/recordCallStart/
 * recordCallResult/markPendingAsDisconnected -- recovery reconstructs an in-memory
 * session using the exact same recorder functions the live gateway already calls, so
 * there is no second, parallel "session shape" to keep in sync.
 *
 * Layout under the existing `stateDir`:
 *   gateway-recovery/
 *     active/<connectionId>.jsonl   an append-only WAL, one JSON line per session event
 *                                   (SESSION_START/INITIALIZE/TOOLS_LIST/CALL_START/
 *                                   CALL_RESULT/CLOSING), deleted once that connection's
 *                                   session is durably chain-appended.
 *     intents/<intentKey>.json      one file per logical (connection, tool, args)
 *                                   operation -- NOT deleted just because its owning
 *                                   session got sealed; only deleted on a clean
 *                                   `completed` outcome at session-close cleanup, or by
 *                                   an explicit operator `resolveNotExecuted` call. An
 *                                   `ambiguous` intent is the durable fence Finding 2
 *                                   needs and is never auto-expired by this module.
 *
 * Why append-only WAL rather than a rewritten-per-call snapshot (the shape most of the
 * five external panel models proposed): every event is one `appendDurableLine` call --
 * the exact primitive chain.js already uses and this codebase already trusts -- with no
 * per-call O(session-size) rewrite cost, and recovery replay needs no new
 * snapshot/rehydrate shape to keep in sync with session.js: it just calls session.js's
 * real functions with the real recorded arguments, in order.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const stateStore = require("../state-store.js");

const RECOVERY_DIRNAME = "gateway-recovery";
const ACTIVE_DIRNAME = "active";
const INTENTS_DIRNAME = "intents";
const INTENT_SCHEMA_VERSION = 1;

function fail(message, code = "GATEWAY_RECOVERY_ERROR") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function recoveryDir(stateDir) {
  return path.join(stateDir, RECOVERY_DIRNAME);
}
function activeDir(stateDir) {
  return path.join(recoveryDir(stateDir), ACTIVE_DIRNAME);
}
function intentsDir(stateDir) {
  return path.join(recoveryDir(stateDir), INTENTS_DIRNAME);
}
function walPath(stateDir, connectionId) {
  return path.join(activeDir(stateDir), `${connectionId}.jsonl`);
}
function intentPath(stateDir, intentKey) {
  return path.join(intentsDir(stateDir), `${intentKey}.json`);
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

/* Mirrors chain.js's own appendDurableLine, which is not exported from that module --
 * this codebase's own established convention (see config.js's header on why a second,
 * small hand-rolled helper scoped to its own file is preferred over reaching into
 * another module's private internals) is to duplicate a tiny fs primitive like this
 * rather than change chain.js's export surface for an unrelated module's benefit. */
function appendDurableLine(filePath, line) {
  const fd = fs.openSync(filePath, "a");
  try {
    fs.writeSync(fd, `${line}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** Appends one WAL event for `connectionId`. Synchronous end-to-end (open/write/fsync/
 * close), matching chain.js's own durability discipline for chain.jsonl -- safe against
 * interleaving from concurrent async call sites on the SAME connection (two tools/call
 * messages pipelined without the agent awaiting the first) because Node's single-
 * threaded event loop never runs other JS in the middle of a synchronous fs call. */
function appendWalEvent(stateDir, connectionId, event) {
  ensureDir(activeDir(stateDir));
  appendDurableLine(walPath(stateDir, connectionId), JSON.stringify({ ...event, recorded_at: Date.now() }));
}

function deleteWal(stateDir, connectionId) {
  try {
    fs.unlinkSync(walPath(stateDir, connectionId));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

/** Reads and parses every valid line of a connection's WAL, stopping at the first
 * malformed line rather than discarding the whole file -- a crash mid-`fs.writeSync`
 * can only ever torn-write the LAST line still in flight (every earlier line already
 * completed its own open/write/fsync/close cycle), so everything before the first bad
 * line is real, durable, and safe to replay. Returns [] if no WAL exists for this
 * connection (nothing was ever in flight, or it was already cleaned up). */
function readWalEvents(stateDir, connectionId) {
  let raw;
  try {
    raw = fs.readFileSync(walPath(stateDir, connectionId), "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw fail(`Unreadable WAL for connection "${connectionId}": ${error.message}`, "GATEWAY_RECOVERY_WAL_UNREADABLE");
  }
  const events = [];
  for (const line of raw.split("\n")) {
    if (line.length === 0) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch (error) {
      break; // torn tail line from a crash mid-write: stop here, keep everything before it
    }
    events.push(event);
  }
  return events;
}

/** Lists connectionIds with an active (not yet cleaned-up) WAL file -- the startup
 * recovery scan's entry point (gateway.js#startGateway, before connectAllDownstreams). */
function listActiveConnections(stateDir) {
  let entries;
  try {
    entries = fs.readdirSync(activeDir(stateDir));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  return entries.filter((f) => f.endsWith(".jsonl")).map((f) => f.slice(0, -".jsonl".length));
}

/** Stable-key JSON stringify -- {a:1,b:2} and {b:2,a:1} must canonicalize identically so
 * a retry with the same logical arguments in a different key order still hashes to the
 * same intent key. Not a general-purpose canonical-JSON library: sufficient for hashing
 * plain JSON-shaped tool arguments (objects/arrays/primitives), which is all a JSON-RPC
 * `params.arguments` value can ever be. */
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

/** The stable per-operation identity Finding 2 needs: same connection + tool + logical
 * arguments always produces the same key regardless of the agent's own JSON-RPC id (a
 * retry legitimately uses a NEW JSON-RPC id -- that id is a transport correlation
 * concern, never an operation identity, per every reviewing model's own analysis).
 * Deliberately scoped to the live connectionId, not a cross-session/cross-restart
 * identity: an agent resubmitting "the same" call in a brand-new session is a new,
 * intentional request from the gateway's point of view, not a retry of an old one --
 * cross-restart continuity for a call that was already in flight is handled by the WAL
 * replay path instead (the intent file itself is what survives a restart, keyed the
 * same way, so an in-flight call's fence is preserved across a crash even though a NEW
 * connectionId after reconnect would not itself match the old key). */
function computeIntentKey(connectionId, tool, args) {
  const material = `${connectionId} ${tool} ${canonicalJson(args === undefined ? null : args)}`;
  return "gs_" + crypto.createHash("sha256").update(material, "utf8").digest("hex").slice(0, 32);
}

function readIntent(stateDir, intentKey) {
  let raw;
  try {
    raw = fs.readFileSync(intentPath(stateDir, intentKey), "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw fail(`Unreadable intent "${intentKey}": ${error.message}`, "GATEWAY_RECOVERY_INTENT_UNREADABLE");
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw fail(`Corrupt intent record "${intentKey}": ${error.message}`, "GATEWAY_RECOVERY_INTENT_CORRUPT");
  }
}

/** Creates a new intent record IFF one does not already exist. Race-safe across
 * concurrent async call sites (and, in principle, processes) because it relies on
 * atomicCreateExclusive's O_EXCL semantics as the real guarantee -- the caller's own
 * prior readIntent() check is an optimization, not the safety mechanism. Returns the
 * created record, or null if one already existed (the caller must re-read to see its
 * current state and respond consistently, rather than assume what it would have been). */
function createIntentIfAbsent(stateDir, intentKey, data) {
  ensureDir(intentsDir(stateDir));
  const record = { schema_version: INTENT_SCHEMA_VERSION, intent_key: intentKey, ...data };
  try {
    stateStore.atomicCreateExclusive(intentPath(stateDir, intentKey), JSON.stringify(record));
  } catch (error) {
    if (error.code === "EEXIST") return null;
    throw error;
  }
  return record;
}

function updateIntent(stateDir, intentKey, patch) {
  const current = readIntent(stateDir, intentKey);
  if (!current) throw fail(`Cannot update unknown intent "${intentKey}"`, "GATEWAY_RECOVERY_INTENT_NOT_FOUND");
  const updated = { ...current, ...patch };
  stateStore.atomicOverwriteFile(intentPath(stateDir, intentKey), JSON.stringify(updated), intentsDir(stateDir));
  return updated;
}

function deleteIntent(stateDir, intentKey) {
  try {
    fs.unlinkSync(intentPath(stateDir, intentKey));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

/** Lists every intent belonging to `connectionId` -- used to find ambiguous intents
 * blocking a clean auto-seal at startup recovery, and to clean up terminal (`completed`)
 * intents once a session is durably sealed. O(all intents on disk) per call: acceptable
 * because intents are cleaned up promptly on a normal close (only orphaned `ambiguous`
 * ones persist, which should be rare in practice), not indexed by connection -- a real
 * scaling limit, disclosed rather than hidden, not worth a secondary index for v1. */
function listIntentsForConnection(stateDir, connectionId) {
  let entries;
  try {
    entries = fs.readdirSync(intentsDir(stateDir));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const intents = [];
  for (const f of entries) {
    if (!f.endsWith(".json")) continue;
    const record = readIntent(stateDir, f.slice(0, -".json".length));
    if (record && record.connection_id === connectionId) intents.push(record);
  }
  return intents;
}

/** Lists every intent on disk regardless of connection -- used by the health surface
 * (gateway.js#buildHealthStatus) to report ambiguous/dispatched intents an operator still
 * needs to act on, across every connection, not just the one most recently recovered.
 * Same O(all intents on disk) characteristic as listIntentsForConnection above, and for
 * the same disclosed reason. */
function listAllIntents(stateDir) {
  let entries;
  try {
    entries = fs.readdirSync(intentsDir(stateDir));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const intents = [];
  for (const f of entries) {
    if (!f.endsWith(".json")) continue;
    const record = readIntent(stateDir, f.slice(0, -".json".length));
    if (record) intents.push(record);
  }
  return intents;
}

/** Operator resolution for an `ambiguous` intent (never automatic -- see this module's
 * header and KNOWN-LIMITATIONS.md): the operator is answering "did it actually execute?",
 * not "should we allow a retry?" -- those are different questions and conflating them is
 * exactly the mistake this module's stricter (dispatched -> completed | ambiguous, no
 * "failed") state machine is designed to avoid (see option-c-hardened-design.md point 7a). */
function resolveIntentExecuted(stateDir, intentKey, result) {
  return updateIntent(stateDir, intentKey, {
    state: "completed",
    resolved_at: Date.now(),
    resolution: "operator_confirmed_executed",
    cached_result: result,
  });
}

/** Confirmed NOT executed: deletes the intent entirely so a future identical dispatch is
 * treated as brand new, not as "retrying a resolved failure" (there is no such state --
 * the fence is either up or gone). */
function resolveIntentNotExecuted(stateDir, intentKey) {
  deleteIntent(stateDir, intentKey);
}

module.exports = {
  RECOVERY_DIRNAME,
  recoveryDir,
  activeDir,
  intentsDir,
  walPath,
  intentPath,
  appendWalEvent,
  deleteWal,
  readWalEvents,
  listActiveConnections,
  canonicalJson,
  computeIntentKey,
  readIntent,
  createIntentIfAbsent,
  updateIntent,
  deleteIntent,
  listIntentsForConnection,
  listAllIntents,
  resolveIntentExecuted,
  resolveIntentNotExecuted,
};
