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
 * `session.js` is very nearly untouched by this change (its only diff, added late in PR
 * #33 for Codex's "persist cached replays in the session trace" finding, is one OPTIONAL
 * `replayed` marker spread conditionally into an already-recorded call -- exactly the
 * mechanism the pre-existing `disconnected` marker already used, so no ordinary session's
 * sealed shape changes): the WAL replays through session.js's
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
const SIGNATURES_DIRNAME = "completed-signatures";
const INTENT_SCHEMA_VERSION = 1;
/* Cluster A (generation-aware crash recovery / cross-connection replay -- Codex PR #29
 * Finding 2 follow-up): a completed intent is normally keyed by (connectionId, tool,
 * args) alone (see computeIntentKey's own header on why that scoping is deliberate for
 * the LIVE dispatch fence), which means a reconnecting agent -- a brand-new
 * connectionId after its old connection crashed or dropped -- computes a DIFFERENT
 * intentKey than its own crashed predecessor's completed call, and would otherwise
 * re-dispatch a side effect that already durably succeeded. This second, much narrower
 * store retains just enough about the MOST RECENT completed call for a given (tool,
 * args) SIGNATURE (no connectionId) to let that reconnect replay the real result instead
 * of re-executing it -- but ONLY when the caller proves it is deliberately asking for a
 * replay via the same `params._meta.idempotencyKey` mechanism the live fence already
 * uses (see proxy.js's own dispatch-guard doc comment); never a bare argument match,
 * which would silently collapse two deliberately-repeated independent calls into one,
 * exactly the ambiguity the caller-idempotency-key mechanism exists to resolve. Bounded
 * by DEFAULT_RETAINED_SIGNATURE_TTL_MS below rather than kept forever. */
const DEFAULT_RETAINED_SIGNATURE_TTL_MS = 24 * 60 * 60 * 1000; // 24h

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
function quarantineDir(stateDir) {
  return path.join(recoveryDir(stateDir), "quarantine");
}
function signaturesDir(stateDir) {
  return path.join(recoveryDir(stateDir), SIGNATURES_DIRNAME);
}

/* CodeRabbit PR #33 review "reject path-bearing recovery identifiers": connectionId and
 * intentKey normally come from this codebase's own generated IDs (safe), but
 * recovery-resolve/recovery-abandon's CLI flags and this module's exported API both also
 * accept them directly from a caller, unvalidated -- and path.join happily normalizes a
 * "../" segment, so an unvalidated value could address a file outside its recovery
 * directory. Applied at the two path-construction points below, not at every call site
 * individually, so nothing can reach fs.* with an unsafe path regardless of caller. */
const SAFE_ID = /^[A-Za-z0-9._-]+$/;
function assertSafeId(value, what) {
  if (typeof value !== "string" || !SAFE_ID.test(value) || value === "." || value === "..") {
    throw fail(`Unsafe ${what} ${JSON.stringify(value)} -- refusing to build a recovery path from it.`, "GATEWAY_RECOVERY_UNSAFE_ID");
  }
  return value;
}
function walPath(stateDir, connectionId) {
  return path.join(activeDir(stateDir), `${assertSafeId(connectionId, "connectionId")}.jsonl`);
}
function intentPath(stateDir, intentKey) {
  return path.join(intentsDir(stateDir), `${assertSafeId(intentKey, "intentKey")}.json`);
}
function signaturePath(stateDir, signatureKey) {
  return path.join(signaturesDir(stateDir), `${assertSafeId(signatureKey, "signatureKey")}.json`);
}

/* Codex PR #33 review "restrict permissions on raw recovery records": these directories
 * (and, below, the WAL/intent files inside them) hold raw goals, tool arguments, and
 * cached results -- data the signed execution trace otherwise only ever stores as
 * hashes. Under the common `022` umask, mkdirSync's default mode is `0755`, letting any
 * other local user on the host read them. `0700` scopes the whole recovery tree to this
 * process's own owner, matching the "OS process boundary is the trust boundary"
 * convention this codebase already uses elsewhere. An explicit chmod (not just the mode
 * passed to mkdirSync) also re-tightens a directory that was created by an older build
 * of this file before this fix, since `recursive: true` does not revisit dirs that
 * already existed. Best-effort: a chmod that fails (e.g. a filesystem that does not
 * support POSIX modes) must not mask the real error from the write that follows.
 *
 * Codex PR #33 review "preserve group access when creating recovery state": the literal
 * `0700`/`0600` this originally used predate startup-permissions.js's access model, which
 * is explicitly group-readable (stateStore.DEFAULT_DIR_MODE 0750 / DEFAULT_FILE_MODE 0640,
 * "NOT single-user 0700/0600") so same-group ops tooling running under another UID can
 * read recovery state. That startup pass chmods these very directories to 0750 -- and
 * then every subsequent WAL/intent/signature write came back through this helper and
 * reset them to 0700, silently undoing it. Use the shared constants so the two agree; the
 * original intent (never the umask-dependent world-readable 0755/0644 default) is
 * unchanged, only the group bit that the later access model deliberately requires. */
/* Round-N fix (frontier-panel finding #4): mkdirSync(dir, {recursive:true}) can create
 * MULTIPLE new ancestor levels in one call (e.g. both gateway-recovery/ and
 * gateway-recovery/active/ when neither existed yet on a fresh state_dir), but every call
 * site below only ever fsyncs `dir` itself (the leaf) afterward, via its own later
 * fsyncDir(dir) call following the actual WAL/intent/signature write (CodeRabbit PR #33's
 * review just above named exactly that convention for the leaf). A newly created
 * ancestor's own directory entry -- its name appearing in ITS parent -- never gets
 * fsynced by anyone in that case, so a crash shortly after the FIRST-ever recovery write
 * on a fresh state_dir could lose the gateway-recovery/ directory entry itself even
 * though active/ and the file inside it were both durably fsynced, leaving a WAL file
 * that is unreachable (its parent directory's own entry never landed) despite the
 * gateway believing it was fully durable. Detect which ancestors are missing BEFORE
 * creating anything (existsSync walk-up, stopping at the first that already exists),
 * then fsync each of those -- and only those -- newly created ancestors after mkdirSync
 * returns. `dir` itself is intentionally excluded here: every call site already fsyncs it
 * via its own existing post-write fsyncDir(dir) call, unchanged by this fix.
 *
 * Post-review correction (found during PR #33/#29 merge-verification, still describing
 * finding #4): the loop below originally stopped at the TOPMOST missing ancestor without
 * also fsyncing that ancestor's own pre-existing PARENT (`cursor`, once the walk-up loop
 * ends). fsyncDir(X) persists X's own directory CONTENTS -- i.e. that X's children are
 * durably listed inside X -- it says nothing about whether X's own entry is durably
 * listed inside X's parent. So the original code fsynced gateway-recovery/'s listing of
 * active/ (via fsyncDir(gateway-recovery)) but never fsynced state_dir's listing of
 * gateway-recovery/ itself -- exactly the "lost the gateway-recovery/ directory entry
 * itself" scenario this comment already claimed to prevent. Fixed below by also fsyncing
 * `cursor` (the first pre-existing ancestor the walk-up found) whenever anything was
 * actually created under it. */
function ensureDir(dir) {
  const missingAncestors = [];
  let cursor = dir;
  while (cursor && !fs.existsSync(cursor)) {
    missingAncestors.push(cursor);
    const parent = path.dirname(cursor);
    if (parent === cursor) break; // filesystem root -- stop rather than loop forever
    cursor = parent;
  }

  fs.mkdirSync(dir, { recursive: true, mode: stateStore.DEFAULT_DIR_MODE });
  try {
    fs.chmodSync(dir, stateStore.DEFAULT_DIR_MODE);
  } catch (error) {
    /* best effort -- see doc comment above */
  }

  // Fsync every newly created ancestor's directory entry, topmost (closest to the
  // pre-existing root) first. Index 0 is `dir` itself -- excluded, see doc comment above.
  for (let i = missingAncestors.length - 1; i >= 1; i--) {
    fsyncDir(missingAncestors[i]);
  }
  // The topmost missing ancestor's own directory ENTRY lives in `cursor` (the first
  // pre-existing ancestor found by the walk-up above). Nothing else fsyncs cursor's
  // listing, so without this, a crash right after the very first recovery write on a
  // fresh state_dir could still lose the whole newly-created subtree's entry point.
  if (missingAncestors.length > 0) {
    fsyncDir(cursor);
  }
}

/* Same rationale as ensureDir's own doc comment above, for the individual WAL/intent
 * files themselves: `fs.openSync(path, "a")`/atomicCreateExclusive/atomicOverwriteFile
 * all default to `0666 & ~umask` (typically `0644`), which is WORLD-readable under a
 * `022` umask. Called after every write (mirroring fsyncDir's own "not just on first
 * creation" convention above) so a file that predates this fix is re-tightened too.
 * Uses stateStore.DEFAULT_FILE_MODE (0640) rather than a literal 0600 for the same
 * reason ensureDir's own doc comment above gives. */
function restrictFileMode(filePath) {
  try {
    fs.chmodSync(filePath, stateStore.DEFAULT_FILE_MODE);
  } catch (error) {
    /* best effort -- see doc comment above */
  }
}

/* CodeRabbit PR #33 review "fsync the recovery directory after creating WAL files": a
 * file's own fsync (appendDurableLine, atomicCreateExclusive) guarantees its CONTENT is
 * durable, but not that the new directory entry (its name appearing in its parent
 * directory) survives a power loss -- that needs the parent directory's own fd fsynced
 * too. Mirrors state-store.js's atomicOverwriteFile, which already fsyncs its target
 * directory on every write for the same reason; called after every append/create here
 * rather than only on first creation, matching that existing convention.
 *
 * Codex PR #33 review "propagate real directory fsync failures": this used to swallow
 * EVERY error, so a genuine storage fault (EIO, ENOSPC) while making a brand-new WAL or
 * intent's DIRECTORY ENTRY durable was reported to the caller as success. The file's own
 * fsync does not cover its directory entry, so the gateway could dispatch a side effect
 * believing CALL_START and its fence were durable and then restart to find neither. Only
 * the cases this was actually written to tolerate are still ignored: the directory being
 * gone (ENOENT -- mid-teardown in a test, the case the original comment names) and a
 * platform/filesystem that simply does not support fsync on a directory fd. Everything
 * else propagates, before dispatch. */
const DIR_FSYNC_TOLERATED_CODES = new Set([
  "ENOENT",   // the directory is already gone -- nothing left to make durable
  "EINVAL",   // filesystem rejects fsync on a directory fd
  "ENOTSUP",
  "EOPNOTSUPP",
  "ENOSYS",
  "EISDIR",   // platforms (Windows) that refuse to open a directory as a file at all
  "EPERM",
  "EACCES",
]);
function fsyncDir(dir) {
  let fd;
  try {
    fd = fs.openSync(dir, "r");
    fs.fsyncSync(fd);
  } catch (error) {
    if (!DIR_FSYNC_TOLERATED_CODES.has(error.code)) throw error;
    /* tolerated platform/teardown case only -- see doc comment above */
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/* Codex PR #33 review "complete WAL writes before treating them as durable": fs.writeSync
 * is permitted by Node's own docs to write FEWER bytes than requested in one call (short
 * write) -- this previously trusted a single call to have written the whole line before
 * fsyncSync'ing it. A short write here is silently invisible to the caller (appendWalEvent
 * has already returned success to a dispatch decision), but readWalEvents' own "stop at
 * the first malformed line" replay logic (see its header) treats the truncated line as a
 * torn crash-tail and discards it AND every real, complete event appended after it. Loops
 * until every byte of the encoded line has actually been written, on the same fd, before
 * the fsync that is supposed to make it durable. */
function writeFullySync(fd, buffer) {
  /* CodeRabbit PR #33 review "truncate the partial record before throwing
   * GATEWAY_RECOVERY_SHORT_WRITE": a short write that makes SOME progress before
   * stalling (or a later call in this same loop stalling after earlier calls already
   * wrote bytes) leaves an incomplete JSON line appended past the file's prior end --
   * readWalEvents' own "stop at the first malformed line" replay logic (see its header)
   * then discards that truncated line AND every real, complete event appended after it.
   * Capturing the size before any write lets a stall truncate the file back to exactly
   * its pre-append state, so a subsequent successful append starts clean rather than
   * leaving a torn line for replay to trip over. */
  const originalSize = fs.fstatSync(fd).size;
  let offset = 0;
  while (offset < buffer.length) {
    /* Codex PR #33 review "roll back the WAL when a write throws, not only when it
     * returns non-positive progress": fs.writeSync can itself throw (e.g. ENOSPC,
     * EIO) partway through a multi-call write, leaving bytes from a prior successful
     * writeSync call in this same loop already appended past the file's pre-append
     * end. Only checking `written > 0` misses that case entirely, since a throw never
     * reaches that check. Wrap the call itself so a throw also truncates back to
     * originalSize before propagating, matching the short-write branch below. */
    let written;
    try {
      written = fs.writeSync(fd, buffer, offset, buffer.length - offset);
    } catch (writeError) {
      try {
        fs.ftruncateSync(fd, originalSize);
      } catch (truncateError) {
        /* best effort -- see the short-write branch's identical comment below. */
      }
      throw writeError;
    }
    if (!(written > 0)) {
      try {
        fs.ftruncateSync(fd, originalSize);
      } catch (truncateError) {
        /* best effort -- if truncation itself fails, the original SHORT_WRITE error
         * below is still the one that matters; masking it with a truncate failure
         * would hide the more actionable diagnosis. */
      }
      throw fail(`fs.writeSync made no progress (wrote ${written} of ${buffer.length - offset} remaining byte(s)) -- refusing to fsync a possibly-incomplete record.`, "GATEWAY_RECOVERY_SHORT_WRITE");
    }
    offset += written;
  }
}

/* Mirrors chain.js's own appendDurableLine, which is not exported from that module --
 * this codebase's own established convention (see config.js's header on why a second,
 * small hand-rolled helper scoped to its own file is preferred over reaching into
 * another module's private internals) is to duplicate a tiny fs primitive like this
 * rather than change chain.js's export surface for an unrelated module's benefit. */
function appendDurableLine(filePath, line) {
  /* CodeRabbit PR #33 review "create recovery files with mode 0o600 at creation":
   * fs.openSync's default mode (0666 & ~umask) leaves a freshly-created WAL file
   * group/world-readable for the window between creation and restrictFileMode's chmod
   * below under a permissive (022) umask. Passing an explicit mode here closes that
   * window for new files; restrictFileMode is kept unchanged so a file created by an older
   * build still gets tightened on its next append. The mode is stateStore.DEFAULT_FILE_MODE
   * (0640) to match restrictFileMode -- see ensureDir's doc comment for why. */
  const fd = fs.openSync(filePath, "a", stateStore.DEFAULT_FILE_MODE);
  try {
    writeFullySync(fd, Buffer.from(`${line}\n`, "utf8"));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  restrictFileMode(filePath);
}

/** Appends one WAL event for `connectionId`. Synchronous end-to-end (open/write/fsync/
 * close), matching chain.js's own durability discipline for chain.jsonl -- safe against
 * interleaving from concurrent async call sites on the SAME connection (two tools/call
 * messages pipelined without the agent awaiting the first) because Node's single-
 * threaded event loop never runs other JS in the middle of a synchronous fs call. */
function appendWalEvent(stateDir, connectionId, event) {
  ensureDir(activeDir(stateDir));
  appendDurableLine(walPath(stateDir, connectionId), JSON.stringify({ ...event, recorded_at: Date.now() }));
  fsyncDir(activeDir(stateDir));
}

/** Best-effort: moves a connection's WAL out of `active/` into `gateway-recovery/
 * quarantine/` rather than deleting it, for the case where the file could not even be
 * read (permission/I/O error, not a JSON/content problem -- see readWalEvents) and an
 * operator has explicitly decided to give up on recovering it (gateway.js#abandonConnection).
 * A rename does not require read access to the file's own content, only to its directory
 * entry, so this can succeed even when the read that motivated it could not. Returns the
 * quarantined path, or null if there was no WAL file to move. */
function quarantineWal(stateDir, connectionId) {
  ensureDir(quarantineDir(stateDir));
  const from = walPath(stateDir, connectionId);
  const to = path.join(quarantineDir(stateDir), `${connectionId}-${Date.now()}.jsonl`);
  try {
    fs.renameSync(from, to);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  /* Codex PR #33 review "fsync both directories after quarantining a WAL": this rename IS
   * the durable save point recovery-abandon reports success on -- it must both remove the
   * connection from active/ and preserve its evidence under quarantine/. rename(2) only
   * mutates two DIRECTORY ENTRIES, and neither is durable until its own parent directory's
   * fd is fsynced (exactly the reason appendWalEvent/createIntentIfAbsent already fsync
   * theirs). Without this, a power loss right after the command printed "quarantined" can
   * resurrect the active/ entry or lose the quarantine/ one -- and by then abandonConnection
   * has already deleted this connection's intent fences, so the resurrected WAL would
   * re-enter startup recovery stripped of the very guards that were protecting it. Both
   * directories, source and destination, through the same tolerated-codes fsyncDir helper
   * hardened earlier in this PR. */
  fsyncDir(activeDir(stateDir));
  fsyncDir(quarantineDir(stateDir));
  return to;
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
  /* Codex PR #33 review "sort active connections before recovery": readdirSync gives no
   * portable ordering guarantee across platforms/filesystems -- gateway.js#
   * recoverCrashedSessions consumes this array directly, in order, to decide chain-append
   * sequence numbers and tail hashes for each recovered connection. An unsorted, platform-
   * dependent order made re-running recovery on the same crash-left files potentially
   * produce a different resulting chain across restarts/hosts. Sorting here (once, at the
   * source) keeps every consumer's replay/append order deterministic. */
  return entries.filter((f) => f.endsWith(".jsonl")).map((f) => f.slice(0, -".jsonl".length)).sort();
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
  const material = `${connectionId}\0${tool}\0${canonicalJson(args === undefined ? null : args)}`;
  return "gs_" + crypto.createHash("sha256").update(material, "utf8").digest("hex").slice(0, 32);
}

/** The signature identity Cluster A's cross-connection replay needs: (tool, logical
 * arguments) alone, deliberately WITHOUT connectionId (unlike computeIntentKey above) --
 * see this file's own header comment on DEFAULT_RETAINED_SIGNATURE_TTL_MS for why. */
function computeSignatureKey(tool, args, idempotencyKey) {
  /* CodeRabbit PR #33 review "signature key collides across different idempotency
   * keys for the same (tool, args)": two distinct caller-supplied idempotencyKeys
   * calling the same tool with the same logical arguments previously hashed to the
   * exact same signature, so the second caller's genuinely-distinct request would
   * read back the first caller's cached result (or overwrite it) instead of being
   * treated as its own operation. Folding idempotencyKey into the hashed material
   * disambiguates them; omitting it (undefined/null) still hashes deterministically
   * to the same key as before for callers that never supplied one. */
  const material = `${tool}\0${canonicalJson(args === undefined ? null : args)}\0${idempotencyKey === undefined || idempotencyKey === null ? "" : idempotencyKey}`;
  return "gs_sig_" + crypto.createHash("sha256").update(material, "utf8").digest("hex").slice(0, 32);
}

/** Retains (overwriting any prior record for this exact signature) the most recent
 * proven-successful outcome for a (tool, arguments) signature, independent of which
 * connection produced it -- called only from the same completion point that transitions
 * an intent to "completed" (proxy.js's handleMessage). Unconditional overwrite is
 * correct here: only ONE "most recent completed call for this signature" can ever be
 * replayed at a time, and a newer completion is strictly more useful to a future
 * reconnect than an older one. */
function recordCompletedSignature(stateDir, signatureKey, data) {
  ensureDir(signaturesDir(stateDir));
  const record = { schema_version: INTENT_SCHEMA_VERSION, signature_key: signatureKey, ...data };
  stateStore.atomicOverwriteFile(signaturePath(stateDir, signatureKey), JSON.stringify(record), signaturesDir(stateDir));
  fsyncDir(signaturesDir(stateDir));
  restrictFileMode(signaturePath(stateDir, signatureKey));
}

/** Reads a retained completed-call signature, honoring the bounded retention window --
 * an expired record is treated exactly as if it never existed (returns null) and is
 * best-effort deleted so it stops taking up space, rather than kept around forever
 * (this file's own header explains why an unbounded retention would be wrong: a stale
 * "it once succeeded" fact should eventually stop being replayable at all). `ttlMs`
 * defaults to DEFAULT_RETAINED_SIGNATURE_TTL_MS when not given. */
function readCompletedSignature(stateDir, signatureKey, ttlMs) {
  let raw;
  try {
    raw = fs.readFileSync(signaturePath(stateDir, signatureKey), "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw fail(`Unreadable retained completed-call signature "${signatureKey}": ${error.message}`, "GATEWAY_RECOVERY_SIGNATURE_UNREADABLE");
  }
  let record;
  try {
    record = JSON.parse(raw);
  } catch (error) {
    throw fail(`Corrupt retained completed-call signature "${signatureKey}": ${error.message}`, "GATEWAY_RECOVERY_SIGNATURE_CORRUPT");
  }
  const effectiveTtl = typeof ttlMs === "number" ? ttlMs : DEFAULT_RETAINED_SIGNATURE_TTL_MS;
  if (typeof record.completed_at !== "number" || Date.now() - record.completed_at > effectiveTtl) {
    try {
      fs.unlinkSync(signaturePath(stateDir, signatureKey));
    } catch (error) {
      /* best effort -- see this function's own doc comment */
    }
    return null;
  }
  return record;
}

/* Codex PR #33 review "sweep expired completed-signature records" + CodeRabbit PR #33
 * review "sweep expired completed signatures" (the same finding, from both reviewers):
 * readCompletedSignature above enforces DEFAULT_RETAINED_SIGNATURE_TTL_MS only for the
 * one key being looked up, and recordCompletedSignature writes one file per DISTINCT
 * (tool, arguments, idempotency key) signature. Calls with unique arguments are therefore
 * never looked up again, so their records -- which hold the raw arguments and the raw
 * cached result -- are never deleted by anything, and a long-running gateway accumulates
 * them (and their inodes) without bound despite the advertised 24-hour retention. This is
 * the global counterpart to that per-key check: one readdir of signatures/, unlink of
 * every record already past its own TTL.
 *
 * Deliberately BOUNDED and best-effort, because its only caller is startup recovery, on
 * the critical path to accepting traffic:
 *   - `maxEntries` caps how many directory entries one sweep will examine (default
 *     DEFAULT_SIGNATURE_SWEEP_MAX_ENTRIES). A directory bigger than that is simply swept
 *     across successive restarts rather than making one startup arbitrarily long --
 *     progress is monotonic, since a swept file is gone and never reconsidered.
 *   - Expiry is decided by the record's own `completed_at`, the EXACT field
 *     readCompletedSignature already uses, so the two can never disagree about what
 *     "expired" means.
 *   - A record that cannot be read, parsed, or unlinked is SKIPPED, not fatal: this is
 *     space reclamation, never a correctness gate, and an unreadable signature is already
 *     handled (fail-closed) by readCompletedSignature on the dispatch path where it
 *     actually matters. A malformed record with no usable `completed_at` is treated as
 *     expired, matching readCompletedSignature's own identical rule.
 * Returns { scanned, removed } so the caller can log what it reclaimed. */
const DEFAULT_SIGNATURE_SWEEP_MAX_ENTRIES = 5000;

function sweepExpiredSignatures(stateDir, options = {}) {
  const ttlMs = typeof options.ttlMs === "number" ? options.ttlMs : DEFAULT_RETAINED_SIGNATURE_TTL_MS;
  const maxEntries = typeof options.maxEntries === "number" ? options.maxEntries : DEFAULT_SIGNATURE_SWEEP_MAX_ENTRIES;
  const now = typeof options.now === "function" ? options.now() : Date.now();
  const dir = signaturesDir(stateDir);
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (error) {
    if (error.code === "ENOENT") return { scanned: 0, removed: 0 };
    throw error;
  }
  let scanned = 0;
  let removed = 0;
  for (const name of entries) {
    if (scanned >= maxEntries) break;
    if (!name.endsWith(".json")) continue;
    scanned += 1;
    const filePath = path.join(dir, name);
    let expired;
    try {
      const record = JSON.parse(fs.readFileSync(filePath, "utf8"));
      expired = typeof record.completed_at !== "number" || now - record.completed_at > ttlMs;
    } catch (error) {
      continue; // unreadable/corrupt: leave it for an operator, never delete on a guess
    }
    if (!expired) continue;
    try {
      fs.unlinkSync(filePath);
      removed += 1;
    } catch (error) {
      /* best effort -- another process may have removed it, or it may be locked */
    }
  }
  if (removed > 0) fsyncDir(dir);
  return { scanned, removed };
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
  // See fsyncDir's own doc comment: atomicCreateExclusive (state-store.js, shared with
  // callers outside this module) fsyncs the file's own content but not the directory
  // entry that makes this new intent file discoverable after a crash -- done here,
  // locally, rather than changing that shared helper's behavior for every other caller.
  fsyncDir(intentsDir(stateDir));
  // Same "restrict permissions on raw recovery records" rationale as ensureDir/
  // appendDurableLine above -- state-store.js's shared atomicCreateExclusive is not
  // itself changed (other callers outside this module rely on its current mode), so this
  // module re-tightens its own files locally after the fact instead.
  restrictFileMode(intentPath(stateDir, intentKey));
  return record;
}

function updateIntent(stateDir, intentKey, patch) {
  const current = readIntent(stateDir, intentKey);
  if (!current) throw fail(`Cannot update unknown intent "${intentKey}"`, "GATEWAY_RECOVERY_INTENT_NOT_FOUND");
  const updated = { ...current, ...patch };
  stateStore.atomicOverwriteFile(intentPath(stateDir, intentKey), JSON.stringify(updated), intentsDir(stateDir));
  restrictFileMode(intentPath(stateDir, intentKey));
  return updated;
}

function deleteIntent(stateDir, intentKey) {
  try {
    fs.unlinkSync(intentPath(stateDir, intentKey));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  /* Codex PR #33 review "fsync the intent directory after rollback deletion": proxy.js's
   * CALL_START-failure rollback (handleMessage) calls this to remove a just-created
   * "dispatched" intent it now knows never actually dispatched, then tells the caller the
   * retry is safe -- but the unlink's directory-entry removal was never itself fsynced.
   * A crash/power-loss shortly after can leave the OLD directory entry (and therefore the
   * stale "dispatched" record) resurrected on the next mount, permanently blocking every
   * future retry of that same operation until an operator notices and cleans it up by
   * hand. Same fsyncDir convention as createIntentIfAbsent's own directory-entry fsync
   * above, applied here for the deletion side too. */
  fsyncDir(intentsDir(stateDir));
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
/* Codex PR #33 review "reject resolutions that overwrite terminal intents": both resolve*
 * functions used to patch unconditionally regardless of the intent's CURRENT state -- a
 * stale or repeated operator command (e.g. a shell history re-run, or two operators
 * racing to resolve the same intent) could silently rewrite an already-`completed`
 * intent's own observed result, or flip it to `not_executed`, discarding the original
 * evidence recovery already signed into a sealed bundle for another connection's replay.
 * Only a `dispatched`/`ambiguous` intent may transition; a repeat of the SAME terminal
 * resolution is a harmless no-op (returns the existing record unchanged, no write), and
 * any other terminal state is refused outright rather than silently overwritten. */
function resolveIntentExecuted(stateDir, intentKey, result) {
  const current = readIntent(stateDir, intentKey);
  if (!current) throw fail(`Cannot update unknown intent "${intentKey}"`, "GATEWAY_RECOVERY_INTENT_NOT_FOUND");
  if (current.state === "completed") return current; // identical terminal resolution: no-op
  if (current.state !== "dispatched" && current.state !== "ambiguous") {
    throw fail(
      `Cannot mark intent "${intentKey}" executed: it is already resolved as "${current.state}" -- refusing to overwrite a different terminal resolution with a new one.`,
      "GATEWAY_RECOVERY_INTENT_TERMINAL"
    );
  }
  const resolvedAt = Date.now();
  const updated = updateIntent(stateDir, intentKey, {
    state: "completed",
    resolved_at: resolvedAt,
    resolution: "operator_confirmed_executed",
    cached_result: result,
  });
  /* Codex PR #33 review "retain operator-confirmed results for reconnect replay": this
   * used to update only the CONNECTION-SCOPED intent. Startup recovery then consumes that
   * result and deletes the intent -- so, unlike proxy.js's live completion path, nothing
   * ever wrote the connection-INDEPENDENT completed-signature record, and a reconnecting
   * agent presenting the same caller idempotency key computed a brand-new intentKey,
   * found nothing, and dispatched the already-executed side effect a second time. Write
   * the same record the live path writes, from the same proven-executed outcome.
   *
   * Gated on a caller idempotency key actually being present, which is where this
   * deliberately differs from proxy.js's unconditional write: proxy.js's own read gate
   * (`retained.idempotency_key && retained.idempotency_key === callerIdempotencyKey`)
   * can never replay an unkeyed record, so writing one here would only leave a file that
   * is unreplayable by construction until its retention window expires.
   *
   * Best-effort, for the same reason the live path's own write is: the operator's
   * decision is already durable in the intent record above, and this secondary
   * cross-connection cache must not be able to undo or fail it. */
  if (typeof current.idempotency_key === "string" && current.idempotency_key.length > 0) {
    try {
      recordCompletedSignature(stateDir, computeSignatureKey(current.tool, current.arguments, current.idempotency_key), {
        tool: current.tool,
        arguments: current.arguments,
        intent_key: intentKey,
        connection_id: current.connection_id,
        generation: current.generation,
        idempotency_key: current.idempotency_key,
        cached_result: result,
        completed_at: resolvedAt,
      });
    } catch (error) {
      /* best effort -- see doc comment above */
    }
  }
  return updated;
}

/** Confirmed NOT executed. Codex PR #33 review "persist a terminal not-executed
 * resolution": this used to delete the intent immediately, on the reasoning that a
 * future identical dispatch should be treated as brand new. That is correct for a LIVE
 * connection, but recovery-resolve only ever runs while no gateway process holds the
 * writer-claim for this state_dir (gateway.js#runRecoveryResolveCli now acquires it
 * itself) -- so the connection this intent belongs to is always a crashed one, still
 * sitting on a WAL with the same call's CALL_START still pending replay. Deleting the
 * intent outright left recoverCrashedSessions with no record of the operator's decision
 * on the next restart: it would find the same pending call, find no "completed" intent,
 * and re-flag the same connection for operator review forever -- this CLI resolution
 * could never actually finish recovery. Persisting a terminal `not_executed` state
 * instead lets recoverCrashedSessions replay it as a real (failed) call result and then
 * clean up the intent itself once the connection is actually sealed -- see
 * gateway.js#recoverCrashedSessions's own handling of this state. */
function resolveIntentNotExecuted(stateDir, intentKey) {
  const current = readIntent(stateDir, intentKey);
  if (!current) throw fail(`Cannot update unknown intent "${intentKey}"`, "GATEWAY_RECOVERY_INTENT_NOT_FOUND");
  if (current.state === "not_executed") return current; // identical terminal resolution: no-op
  if (current.state !== "dispatched" && current.state !== "ambiguous") {
    throw fail(
      `Cannot mark intent "${intentKey}" not-executed: it is already resolved as "${current.state}" -- refusing to overwrite a different terminal resolution with a new one.`,
      "GATEWAY_RECOVERY_INTENT_TERMINAL"
    );
  }
  return updateIntent(stateDir, intentKey, {
    state: "not_executed",
    resolved_at: Date.now(),
    resolution: "operator_confirmed_not_executed",
  });
}

module.exports = {
  RECOVERY_DIRNAME,
  DEFAULT_RETAINED_SIGNATURE_TTL_MS,
  recoveryDir,
  activeDir,
  intentsDir,
  quarantineDir,
  signaturesDir,
  walPath,
  intentPath,
  signaturePath,
  appendWalEvent,
  deleteWal,
  quarantineWal,
  readWalEvents,
  listActiveConnections,
  canonicalJson,
  computeIntentKey,
  computeSignatureKey,
  recordCompletedSignature,
  readCompletedSignature,
  sweepExpiredSignatures,
  DEFAULT_SIGNATURE_SWEEP_MAX_ENTRIES,
  readIntent,
  createIntentIfAbsent,
  updateIntent,
  deleteIntent,
  listIntentsForConnection,
  listAllIntents,
  resolveIntentExecuted,
  resolveIntentNotExecuted,
};
