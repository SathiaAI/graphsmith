#!/usr/bin/env node
/* GraphSmith standalone gateway -- startup permission-tightening pass.
 *
 * Access model (Paul's decision, 2026-09-15 fix round -- see
 * claude/graphsmith-fix-round-plan-round1-2026-09-15.md, "Access model"): the gateway's
 * state directories are group-readable (0750 dirs / 0640 files), NOT single-user
 * (0700/0600) -- other-uid ops tooling must keep working against them. The one named
 * exception is gateway.js's operator-facing gateway-status.json health file, which stays
 * at its current, operator-readable mode (see that file's own writeStatusFile comment) --
 * it is deliberately never listed below.
 *
 * WHY A SEPARATE STARTUP PASS, not just a creation-mode fix.
 *
 * scripts/state-store.js's atomicCreateExclusive/atomicOverwriteFile now default every
 * NEW file they create to 0640 (see that file's own doc comments), which protects
 * anything written fresh from here on. That alone protects nothing that ALREADY EXISTS
 * on disk from a prior run or an older build, and it does not even cover every future
 * write: several of the files this pass targets (chain.jsonl, the writer-claim's own
 * renew()) are append-only or rewritten-in-place through a raw fs.openSync/writeSync
 * pair, never through either primitive, precisely because they are long-lived records
 * whose IDENTITY (not just their content) must survive across appends -- a
 * creation-mode-only fix would protect the file's very first byte and nothing an
 * operator would actually be worried about leaking. Retrofitting the mode explicitly,
 * once, at startup, covers both gaps: the file that already existed yesterday, and the
 * file whose own write path was never going to call either primitive to begin with.
 *
 * WHAT IS COVERED, and why each one:
 *   - the writer-claim file (writer-claim.js's CLAIM_FILE) -- the single-writer
 *     attestation record for this state directory.
 *   - chain.jsonl / HEAD.json (chain.js) -- the signed session hash-chain and its tail
 *     pointer.
 *   - every sealed session bundle in gateway-sessions/*.json (chain.js's own
 *     `<bundle_id>.json` files) -- raw tool arguments/results the signed chain otherwise
 *     only ever stores as a hash.
 *   - every quarantined sealed bundle in gateway-sessions/quarantine/*.json (proxy.js's
 *     quarantineSealedBundle) -- a full, unsealed copy of the same raw session data,
 *     written by a RAW fs.writeFileSync that never goes through either shared primitive
 *     at all, so it is exactly the "creation-mode-only fix protects nothing" case this
 *     pass exists for.
 *   - every WAL file in gateway-recovery/active/*.jsonl (recovery.js) -- an in-flight
 *     session's raw, unsigned event log.
 *   - every quarantined WAL in gateway-recovery/quarantine/*.jsonl (recovery.js's
 *     quarantineWal) -- the same raw event log, moved rather than deleted when an
 *     operator gives up on recovering it.
 *   - every intent/signature record in gateway-recovery/intents/*.json and
 *     gateway-recovery/completed-signatures/*.json (recovery.js) -- raw tool arguments
 *     and cached results kept for crash-recovery idempotency.
 * Deliberately NOT covered: scripts/state-store.js's own general state files
 * (window.json, run-registry.jsonl, the state.lock, ...) -- a different subsystem, used
 * far outside the gateway, with its own existing convention and out of this item's
 * scope. mode-selection.js's per-deployment secret key already chmods itself to 0600
 * (stricter than 0640) and is left untouched here too, for the same reason.
 *
 * WHY DIRECTORIES ARE INCLUDED TOO (0750): a file's own mode is moot if the directory
 * that contains it is still world/group-executable-and-readable in a way that lets
 * another local user list its contents or open it by name under a permissive umask --
 * mkdirSync's default mode (0755 under a common 022 umask) does exactly that, and
 * `{ recursive: true }` never revisits a directory that already existed before this fix.
 *
 * Best-effort per path, but NOT best-effort on a real fault: a missing file/directory
 * (a fresh deployment that has never had a crash, or never had one recovered/sealed yet)
 * is skipped silently via stateStore.chmodPathOrFail's own ENOENT handling -- that is an
 * entirely ordinary, expected state, not a fault. A genuine EPERM/EIO chmod failure is
 * NOT swallowed: several of these files can hold a bearer credential or a full raw
 * session bundle, so a failed permission-tightening attempt on one of them is an
 * operational error this process should refuse to start past, not a logged nitpick.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const stateStore = require("../state-store.js");
const recovery = require("./recovery.js");
const chain = require("./chain.js");
const writerClaimModule = require("../writer-claim.js");

const FILE_MODE = stateStore.DEFAULT_FILE_MODE; // 0o640
const DIR_MODE = stateStore.DEFAULT_DIR_MODE;   // 0o750

/* proxy.js's quarantineSealedBundle writes into <gateway-sessions>/quarantine/ -- a
 * literal here, not an import from proxy.js, so this module (loaded very early at
 * startup, before proxy.js's own dependency graph is otherwise needed) stays a one-way
 * dependency on chain.js/recovery.js/writer-claim.js rather than adding a reverse edge
 * from a permissions module back into the request-dispatch module. Kept in sync with
 * proxy.js's own literal by the dedicated cross-check test in this module's own suite. */
const SESSION_QUARANTINE_DIRNAME = "quarantine";
function sessionQuarantineDir(stateDir) {
  return path.join(chain.sessionsDir(stateDir), SESSION_QUARANTINE_DIRNAME);
}

/* Lists the full paths of every entry directly inside `dir` whose name ends with
 * `suffix`. Returns [] for a directory that does not exist yet (nothing to protect);
 * any other readdir failure propagates -- an unreadable-but-present sensitive directory
 * is exactly the kind of real fault this pass must not paper over. */
function listMatchingFiles(dir, suffix) {
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  return entries.filter((name) => name.endsWith(suffix)).map((name) => path.join(dir, name));
}

/** Every directory this pass tightens to DIR_MODE (0750), in an order that only matters
 * for readability (parents before children) -- chmod does not require a particular
 * order, and a missing entry anywhere in this list is simply skipped. */
function sensitiveDirectories(stateDir) {
  return [
    stateDir,
    chain.sessionsDir(stateDir),
    sessionQuarantineDir(stateDir),
    recovery.recoveryDir(stateDir),
    recovery.activeDir(stateDir),
    recovery.intentsDir(stateDir),
    recovery.signaturesDir(stateDir),
  ];
}

/** Every individual file this pass tightens to FILE_MODE (0640) -- the fixed,
 * known-by-name files (the claim, chain.jsonl, HEAD.json) plus every CURRENT entry in
 * each of the per-record directories above, discovered fresh each call rather than
 * cached, since this only ever runs once at startup before any of those directories'
 * contents can have changed under it. */
function sensitiveFiles(stateDir) {
  return [
    writerClaimModule.claimPath(stateDir),
    chain.chainPath(stateDir),
    chain.headPath(stateDir),
    ...listMatchingFiles(chain.sessionsDir(stateDir), ".json").filter(
      (file) => path.basename(file) !== chain.HEAD_FILE
    ),
    ...listMatchingFiles(sessionQuarantineDir(stateDir), ".json"),
    ...listMatchingFiles(recovery.activeDir(stateDir), ".jsonl"),
    ...listMatchingFiles(recovery.intentsDir(stateDir), ".json"),
    ...listMatchingFiles(recovery.signaturesDir(stateDir), ".json"),
  ];
}

/** Re-chmods every known-sensitive EXISTING file/directory under `stateDir` to this
 * codebase's group-readable access model. Called once, synchronously, at gateway
 * startup -- see this module's own header for the full rationale and the exact,
 * deliberately-bounded list of what is and is not covered.
 *
 * Returns `{ dirs, files }`, the paths actually changed (a path that did not exist yet
 * is simply absent from both arrays, not an error). Throws on the FIRST real
 * permission fault (stateStore.chmodPathOrFail's own STATE_STORE_CHMOD_FAILED) --
 * callers (gateway.js#startGateway) let that abort startup rather than proceed with a
 * sensitive file left more permissive than this access model requires. */
function tightenStateDirPermissions(stateDir) {
  const changed = { dirs: [], files: [] };

  for (const dir of sensitiveDirectories(stateDir)) {
    if (stateStore.chmodPathOrFail(dir, DIR_MODE)) changed.dirs.push(dir);
  }
  for (const file of sensitiveFiles(stateDir)) {
    if (stateStore.chmodPathOrFail(file, FILE_MODE)) changed.files.push(file);
  }

  return changed;
}

module.exports = {
  FILE_MODE,
  DIR_MODE,
  sessionQuarantineDir,
  sensitiveDirectories,
  sensitiveFiles,
  tightenStateDirPermissions,
};
