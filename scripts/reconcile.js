#!/usr/bin/env node
/* GraphSmith reconciled-mode primitive (scripts/reconcile.js) — Lane A,
 * v0.5.0 Wave 1.
 *
 * Deterministic, zero-LLM, zero-dependency CommonJS, Node >= 18. No network
 * calls, no clock/randomness in any DECISION path (crypto.randomBytes is used
 * only to name a scratch temp file, never read back into a pass/fail branch;
 * Atomics.wait is used only for an opt-in, env-var-gated test stall — see
 * TEST-ONLY HOOK below, same posture as tests/_harness/deadline.js's
 * GRAPHSMITH_DEADLINE_SCALE).
 *
 * WHAT THIS IS
 *
 * schemas/host-adapter.schema.json's `placementMode: "reconciled"` names this
 * file directly: "the generator's rendered output for this adapter MUST be
 * handed to Lane A's reconciler and never written directly... Lane A's
 * reconciler currently assumes the target file supports HTML-comment markers
 * (<!-- -->) for its begin/end delimited block." This module is that
 * reconciler. It places one already-rendered block of text (produced by Lane
 * D from canonical SKILL.md — this file never reads SKILL.md and has no
 * opinion about how the block was rendered) into a single target file,
 * without disturbing anything else the target file may contain.
 *
 * It is a REUSABLE PRIMITIVE, not an AGENTS.md-specific tool: `blockId`
 * scopes each call to one marker-delimited region, so AGENTS.md, a future
 * CLAUDE.md, and .github/copilot-instructions.md (both v0.5.0 launch
 * reconciled targets per .plans/v0.5.0/WAVE-0-CANONICAL-SOURCE.md) all go
 * through this same function, and in principle several distinct blocks
 * (different blockIds) can coexist in one file without colliding.
 *
 * Ported from, and generalized beyond, microsoft/clarity-agent's
 * src/clarity_agent/setup/snippet.py `ensure_agents_md` (verified against
 * that source directly, not its README — see
 * claude/graphsmith-clarity-agent-oss-extraction-2026-07-30.md): a
 * marker-delimited begin/end block, a versioned meta header, and a four-way
 * state machine — file absent -> write; file present with no complete marker
 * pair for this blockId -> append; block present and byte-identical (body +
 * schema version) -> no-op; block present but drifted (hand edit, layout
 * change, or schema bump) -> splice only the marker-bounded region, leaving
 * everything else in the file untouched. clarity-agent keeps its version/mode
 * fields in a separate hidden `<!-- clarity-meta ... -->` comment; this
 * module folds the single field it actually needs (schema_version) into the
 * begin marker's own attributes instead, which removes a second marker line
 * to keep in sync and removes a second place drift could hide.
 *
 * MARKER FORMAT (HTML comments; see host-adapter.schema.json's documented
 * bound — this is known NOT to work for a target that cannot host an HTML
 * comment, e.g. JSON/TOML/YAML; no such target exists among v0.5.0's
 * reconciled adapters, and extending past Markdown requires a schema change
 * first, not a silent guess here):
 *
 *   <!-- graphsmith:begin id="<blockId>" schema_version="<N>" -->
 *   ...renderedBlock, verbatim, exactly one trailing newline...
 *   <!-- graphsmith:end id="<blockId>" -->
 *
 * Both marker lines must appear alone on their own line (anchored at column
 * 0) with this exact literal text and nothing else on the line. That is what
 * keeps a marker-LOOKALIKE string inside a user's own prose ("for example,
 * `<!-- graphsmith:begin id="x" schema_version="1" -->` mid-sentence") from
 * being misparsed as a real marker: an exact, whole-line, anchored match is
 * required, not a substring scan.
 *
 * SCHEMA-VERSION COMPATIBILITY (the "old reconciler vs. newer-spliced file,
 * and the reverse" adversarial case)
 *
 * `schemaVersion` is a property of the CALL (the version of the marker/body
 * contract the caller's renderedBlock conforms to), not of this file's own
 * released version — that is what lets one deployed reconcile.js serve a
 * caller asking for schema_version "1" today and "2" once a future format
 * change ships, and lets a test exercise both directions without needing two
 * copies of this module. Comparison is a plain integer compare of the
 * version already recorded in the file's begin marker against the version
 * the current call is asking for:
 *
 *   - recorded version <= call's version -> compatible; splice/no-op as
 *     normal, and the marker is re-stamped with the call's version.
 *   - recorded version >  call's version -> the file was already written by
 *     a LATER-schema reconciler than the one making this call. Silently
 *     overwriting it would mean guessing at a body format this call does not
 *     understand. Refused, no write, `reason: "future-schema-version"`.
 *
 * SYMLINK POLICY
 *
 * "resolve-once-trust-forever" is named in the Lane A brief as a known bug
 * class on this project. This function does not resolve a symlinked target
 * at all: `fs.lstatSync` on the target path (never `fs.statSync`, which
 * would follow it) is the only inspection performed, and a symlink at that
 * path is refused outright before anything is read or written -- not
 * followed, not written through, not silently replaced. This is a stricter
 * property than "the write cannot escape the tree" (which the atomic
 * temp-file-then-rename below would also give for free, since POSIX rename()
 * never follows a symlink at its destination path): a legitimate symlinked
 * target is left completely alone rather than being silently unlinked and
 * replaced by a plain file.
 *
 * ATOMICITY
 *
 * Every write in this module goes through atomicWriteFileSync(): write the
 * COMPLETE new file content to a scratch temp file in the same directory,
 * fsync it, then a single fs.renameSync() onto the real target path. A
 * process killed before the rename leaves the original target file (or its
 * absence) completely untouched; a same-filesystem rename is a single atomic
 * directory-entry update at the OS level and cannot itself produce a
 * half-written target. There is never a window where the target path holds
 * partial content.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { writeReport } = require("./write-report.js");

// The default schema_version a caller gets if it does not pass one. Bump
// this, and document why, only when the marker/body CONTRACT itself changes
// in a way an old reconciler could not safely splice over (see the
// SCHEMA-VERSION COMPATIBILITY note above). It is NOT this file's package
// version and NOT GraphSmith's release version -- those change for reasons
// unrelated to this one narrow contract.
const DEFAULT_SCHEMA_VERSION = "1";

const BLOCK_ID_RE = /^[a-z][a-z0-9-]*$/; // same shape as host-adapter.schema.json's `id`
const SCHEMA_VERSION_RE = /^[0-9]+$/;

// A line terminator that recognizes "\r\n" and "\n" (bare "\n" and CRLF).
// DOCUMENTED, BOUNDED GAP (contract-10-style honest language, not a silent
// overclaim): a lone "\r" with no following "\n" (classic pre-OS-X Mac line
// endings) will not be recognized as a line boundary by JavaScript regex
// "^"/"$" under the "m" flag, so a marker line terminated only by a bare "\r"
// will not be detected as a marker. Every reconciled-mode adapter target in
// this project is a plain UTF-8 Markdown file GraphSmith itself renders with
// "\n" or accepts as ordinary "\n"/"\r\n" text from a user's editor; a
// lone-"\r" file has not been observed and is not claimed to be handled.
const LINE_END = "(?:\\r\\n|\\n|$)";

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertValidBlockId(blockId) {
  if (typeof blockId !== "string" || !BLOCK_ID_RE.test(blockId)) {
    throw new TypeError(`reconcile: blockId must match ${BLOCK_ID_RE} (got ${JSON.stringify(blockId)})`);
  }
}

function assertValidSchemaVersion(schemaVersion) {
  if (typeof schemaVersion !== "string" || !SCHEMA_VERSION_RE.test(schemaVersion)) {
    throw new TypeError(`reconcile: schemaVersion must be a non-negative integer string (got ${JSON.stringify(schemaVersion)})`);
  }
}

function beginRegex(blockId) {
  return new RegExp(`^<!-- graphsmith:begin id="${escapeRegExp(blockId)}" schema_version="([0-9]+)" -->[ \\t]*${LINE_END}`, "m");
}

function endRegex(blockId) {
  return new RegExp(`^<!-- graphsmith:end id="${escapeRegExp(blockId)}" -->[ \\t]*${LINE_END}`, "m");
}

function beginLine(blockId, schemaVersion) {
  return `<!-- graphsmith:begin id="${blockId}" schema_version="${schemaVersion}" -->\n`;
}

function endLine(blockId) {
  return `<!-- graphsmith:end id="${blockId}" -->\n`;
}

/** Ensure renderedBlock ends with exactly one trailing newline, so a block
 * this module writes and later re-extracts round-trips to the identical
 * string regardless of whether the caller's renderedBlock already had one. */
function normalizeBody(renderedBlock) {
  if (typeof renderedBlock !== "string") {
    throw new TypeError(`reconcile: renderedBlock must be a string (got ${typeof renderedBlock})`);
  }
  return renderedBlock.endsWith("\n") ? renderedBlock : renderedBlock + "\n";
}

function buildBlock(blockId, schemaVersion, body) {
  return beginLine(blockId, schemaVersion) + body + endLine(blockId);
}

/**
 * Find the first COMPLETE begin/end marker pair for `blockId` in `raw`
 * (already BOM-stripped). Returns null when there is no complete pair --
 * that covers "no markers at all", "a lookalike string that doesn't match
 * the exact anchored format", and the malformed "a begin marker with no
 * matching end, or two begins before one end" cases alike. All of those are
 * treated identically and safely: as "append a fresh block", never as
 * "guess how to repair the existing one". Nothing already in the file is
 * ever deleted by that fallback.
 */
function findBlock(raw, blockId) {
  const bre = beginRegex(blockId);
  const beginMatch = bre.exec(raw);
  if (!beginMatch) return null;

  const bodyStart = beginMatch.index + beginMatch[0].length;
  const tail = raw.slice(bodyStart);

  const ere = endRegex(blockId);
  const endMatch = ere.exec(tail);
  if (!endMatch) return null; // begin with no matching end -> not a valid block

  // Reject ambiguity: a second begin for this same id appearing before the
  // end we just found means the file is already malformed for this blockId
  // (e.g. a half-applied hand edit). Fail open to "no valid block" rather
  // than guess which begin the end belongs to.
  const secondBegin = bre.exec(tail.slice(0, endMatch.index));
  if (secondBegin) return null;

  const bodyEnd = bodyStart + endMatch.index;
  const blockEnd = bodyStart + endMatch.index + endMatch[0].length;

  return {
    blockStart: beginMatch.index,
    blockEnd,
    schemaVersion: beginMatch[1],
    body: raw.slice(bodyStart, bodyEnd),
  };
}

// ---------------------------------------------------------------------------
// TEST-ONLY HOOK: an opt-in, env-var-gated synchronous stall inserted between
// "the new complete content is fsynced to a scratch temp file" and "the
// rename that makes it visible at the target path". Exists so a test can
// deterministically kill this process mid-operation and assert the target
// path was never left partially written -- reproducing a real SIGKILL
// without relying on timing luck. Inert unless GRAPHSMITH_RECONCILE_TEST_
// STALL_MS is set to a positive number, exactly the posture
// tests/_harness/deadline.js documents for its own env-var knob: normal runs
// never read this and are unaffected. Atomics.wait is the same synchronous-
// sleep primitive scripts/write-report.js already uses for its EAGAIN
// backoff, not a novel mechanism introduced here.
// ---------------------------------------------------------------------------
function testStallBeforeRenameIfRequested() {
  const raw = process.env.GRAPHSMITH_RECONCILE_TEST_STALL_MS;
  if (!raw) return;
  const ms = Number(raw);
  if (!Number.isFinite(ms) || ms <= 0) return;
  const ia = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(ia, 0, 0, ms);
}

/**
 * Write `content` to `targetPath` atomically: full content to a scratch temp
 * file in the same directory, fsync, then a single rename onto the target.
 * Never opens `targetPath` itself for writing, so a symlink or any other
 * existing object at that path is replaced as a whole name-table entry
 * (POSIX rename semantics), never written through.
 */
function atomicWriteFileSync(targetPath, content) {
  const dir = path.dirname(targetPath);
  const tmpPath = path.join(
    dir,
    `.graphsmith-reconcile.${path.basename(targetPath)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  const buf = Buffer.from(content, "utf8");
  const fd = fs.openSync(tmpPath, "wx", 0o644);
  try {
    let off = 0;
    while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    testStallBeforeRenameIfRequested();
    fs.renameSync(tmpPath, targetPath);
  } catch (e) {
    try {
      fs.unlinkSync(tmpPath);
    } catch (_) {
      /* best-effort cleanup; the rename error is the one that matters */
    }
    throw e;
  }
  return buf.length;
}

function baseResult(status, targetPath, blockId, schemaVersion, extra) {
  return Object.assign(
    {
      status, // "created" | "appended" | "unchanged" | "spliced" | "refused"
      path: targetPath,
      blockId,
      schemaVersion,
    },
    extra || {}
  );
}

/**
 * Place `renderedBlock` into `targetPath` under marker `blockId`, per the
 * four-way state machine documented at the top of this file.
 *
 * @param {string} targetPath absolute or relative path to the surface file
 *   (e.g. "AGENTS.md", ".github/copilot-instructions.md")
 * @param {string} renderedBlock the already-rendered block text (Lane D's
 *   output). This function does not transform it beyond ensuring exactly one
 *   trailing newline.
 * @param {object} options
 * @param {string} options.blockId stable id for this block, e.g. an adapter
 *   id (`^[a-z][a-z0-9-]*$`). Scopes marker matching so multiple distinct
 *   blocks can coexist in one file.
 * @param {string} [options.schemaVersion] non-negative integer string; the
 *   schema version of the marker/body contract this call's renderedBlock
 *   conforms to. Defaults to DEFAULT_SCHEMA_VERSION.
 * @returns {object} a result with at least {status, path, blockId,
 *   schemaVersion}; `status: "refused"` results also carry `reason` and
 *   never write anything.
 */
function reconcile(targetPath, renderedBlock, options) {
  if (typeof targetPath !== "string" || targetPath.length === 0) {
    throw new TypeError("reconcile: targetPath must be a non-empty string");
  }
  const opts = options || {};
  const blockId = opts.blockId;
  assertValidBlockId(blockId);
  const schemaVersion = opts.schemaVersion == null ? DEFAULT_SCHEMA_VERSION : String(opts.schemaVersion);
  assertValidSchemaVersion(schemaVersion);
  const desiredBody = normalizeBody(renderedBlock); // validates renderedBlock is a string too

  let lst = null;
  try {
    lst = fs.lstatSync(targetPath);
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }

  if (lst) {
    if (lst.isSymbolicLink()) {
      return baseResult("refused", targetPath, blockId, schemaVersion, { reason: "symlink-refused" });
    }
    if (!lst.isFile()) {
      return baseResult("refused", targetPath, blockId, schemaVersion, { reason: "target-not-a-file" });
    }
  }

  // ---- STATE: absent -> write ----
  if (!lst) {
    const dir = path.dirname(targetPath);
    fs.mkdirSync(dir, { recursive: true });
    const content = buildBlock(blockId, schemaVersion, desiredBody);
    const bytesWritten = atomicWriteFileSync(targetPath, content);
    return baseResult("created", targetPath, blockId, schemaVersion, { bytesWritten });
  }

  const rawWithBom = fs.readFileSync(targetPath, "utf8");
  const hasBom = rawWithBom.charCodeAt(0) === 0xfeff;
  const bom = hasBom ? "﻿" : "";
  const raw = hasBom ? rawWithBom.slice(1) : rawWithBom;

  const found = findBlock(raw, blockId);

  // ---- STATE: present, no complete marker pair for this blockId -> append ----
  if (!found) {
    const blockText = buildBlock(blockId, schemaVersion, desiredBody);
    // Preserve every existing byte; only decide how much separation to add
    // before the new block. Trim trailing blank lines/whitespace from the
    // existing content's end, then join with exactly one blank line, unless
    // the file was empty.
    const trimmedRaw = raw.replace(/[ \t\r\n]+$/, "");
    const newRaw = trimmedRaw.length === 0 ? blockText : `${trimmedRaw}\n\n${blockText}`;
    const bytesWritten = atomicWriteFileSync(targetPath, bom + newRaw);
    return baseResult("appended", targetPath, blockId, schemaVersion, { bytesWritten });
  }

  const foundVersionNum = Number(found.schemaVersion);
  const callVersionNum = Number(schemaVersion);

  // ---- REFUSAL: file already carries a block from a schema newer than this
  // call understands. Splicing over it would mean guessing at a body format
  // this call was never told about. ----
  if (foundVersionNum > callVersionNum) {
    return baseResult("refused", targetPath, blockId, schemaVersion, {
      reason: "future-schema-version",
      foundSchemaVersion: found.schemaVersion,
    });
  }

  // ---- STATE: present, block current (same version, byte-identical body) -> no-op ----
  if (foundVersionNum === callVersionNum && found.body === desiredBody) {
    return baseResult("unchanged", targetPath, blockId, schemaVersion, { bytesWritten: 0 });
  }

  // ---- STATE: present, block drifted (older version, or same version but
  // different body -- a schema bump or a hand edit inside the markers) ->
  // splice only the marker-bounded region in place. ----
  const blockText = buildBlock(blockId, schemaVersion, desiredBody);
  const newRaw = raw.slice(0, found.blockStart) + blockText + raw.slice(found.blockEnd);
  const bytesWritten = atomicWriteFileSync(targetPath, bom + newRaw);
  return baseResult("spliced", targetPath, blockId, schemaVersion, {
    bytesWritten,
    previousSchemaVersion: found.schemaVersion,
  });
}

// ---------------------------------------------------------------------------
// CLI (secondary surface; the exported `reconcile` function is the primary
// one Lane D's generator calls in-process). Reads the rendered block from a
// file or stdin so this can be exercised/spot-checked without writing a
// throwaway Node script.
// ---------------------------------------------------------------------------

function readAllStdinSync() {
  const chunks = [];
  const buf = Buffer.alloc(65536);
  for (;;) {
    let n;
    try {
      n = fs.readSync(0, buf, 0, buf.length, null);
    } catch (e) {
      if (e.code === "EAGAIN") continue;
      if (e.code === "EOF") break;
      throw e;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buf.slice(0, n)));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--target" && argv[i + 1]) out.target = argv[++i];
    else if (argv[i] === "--block-id" && argv[i + 1]) out.blockId = argv[++i];
    else if (argv[i] === "--schema-version" && argv[i + 1]) out.schemaVersion = argv[++i];
    else if (argv[i] === "--input" && argv[i + 1]) out.input = argv[++i];
  }
  return out;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  try {
    if (!opts.target || !opts.blockId || !opts.input) {
      process.stderr.write(
        "Usage: node scripts/reconcile.js --target <path> --block-id <id> --input <file|-> [--schema-version <n>]\n"
      );
      process.exit(2);
      return;
    }
    const renderedBlock = opts.input === "-" ? readAllStdinSync() : fs.readFileSync(opts.input, "utf8");
    const result = reconcile(opts.target, renderedBlock, {
      blockId: opts.blockId,
      schemaVersion: opts.schemaVersion,
    });
    writeReport(JSON.stringify(result, null, 2) + "\n");
    process.exit(result.status === "refused" ? 1 : 0);
  } catch (e) {
    process.stderr.write(`Error: ${e && e.message ? e.message : String(e)}\n`);
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  DEFAULT_SCHEMA_VERSION,
  reconcile,
  // Exported for white-box testing, same convention as scripts/verify.js
  // exporting its own internal helpers (sha256Hex, verifyFileList, ...).
  findBlock,
  buildBlock,
  normalizeBody,
  atomicWriteFileSync,
};
