#!/usr/bin/env node
/* GraphSmith reconciled-mode primitive (scripts/reconcile.js) — Lane A,
 * v0.5.0 Wave 1. Cherry-picked verbatim from origin/v0.5.0/lane-a-reconciler
 * for Lane D's use (Lane D never writes a reconciled-mode target directly;
 * it always calls this module's reconcile()). See that branch for the full
 * canonical copy and its own independent review; this copy is kept
 * byte-identical to avoid two diverging implementations of the same
 * data-loss-critical primitive prior to both branches merging to main.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DEFAULT_SCHEMA_VERSION = "1";

const BLOCK_ID_RE = /^[a-z][a-z0-9-]*$/;
const SCHEMA_VERSION_RE = /^[0-9]+$/;

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

function normalizeBody(renderedBlock) {
  if (typeof renderedBlock !== "string") {
    throw new TypeError(`reconcile: renderedBlock must be a string (got ${typeof renderedBlock})`);
  }
  return renderedBlock.endsWith("\n") ? renderedBlock : renderedBlock + "\n";
}

function buildBlock(blockId, schemaVersion, body) {
  return beginLine(blockId, schemaVersion) + body + endLine(blockId);
}

function findBlock(raw, blockId) {
  const bre = beginRegex(blockId);
  const beginMatch = bre.exec(raw);
  if (!beginMatch) return null;

  const bodyStart = beginMatch.index + beginMatch[0].length;
  const tail = raw.slice(bodyStart);

  const ere = endRegex(blockId);
  const endMatch = ere.exec(tail);
  if (!endMatch) return null;

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

function testStallBeforeRenameIfRequested() {
  const raw = process.env.GRAPHSMITH_RECONCILE_TEST_STALL_MS;
  if (!raw) return;
  const ms = Number(raw);
  if (!Number.isFinite(ms) || ms <= 0) return;
  const ia = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(ia, 0, 0, ms);
}

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
      status,
      path: targetPath,
      blockId,
      schemaVersion,
    },
    extra || {}
  );
}

function reconcile(targetPath, renderedBlock, options) {
  if (typeof targetPath !== "string" || targetPath.length === 0) {
    throw new TypeError("reconcile: targetPath must be a non-empty string");
  }
  const opts = options || {};
  const blockId = opts.blockId;
  assertValidBlockId(blockId);
  const schemaVersion = opts.schemaVersion == null ? DEFAULT_SCHEMA_VERSION : String(opts.schemaVersion);
  assertValidSchemaVersion(schemaVersion);
  const desiredBody = normalizeBody(renderedBlock);

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

  if (!lst) {
    const dir = path.dirname(targetPath);
    fs.mkdirSync(dir, { recursive: true });
    const content = buildBlock(blockId, schemaVersion, desiredBody);
    const bytesWritten = atomicWriteFileSync(targetPath, content);
    return baseResult("created", targetPath, blockId, schemaVersion, { bytesWritten });
  }

  const rawWithBom = fs.readFileSync(targetPath, "utf8");
  const hasBom = rawWithBom.charCodeAt(0) === 0xfeff;
  const bom = hasBom ? String.fromCharCode(0xfeff) : "";
  const raw = hasBom ? rawWithBom.slice(1) : rawWithBom;

  const found = findBlock(raw, blockId);

  if (!found) {
    const blockText = buildBlock(blockId, schemaVersion, desiredBody);
    const trimmedRaw = raw.replace(/[ \t\r\n]+$/, "");
    const newRaw = trimmedRaw.length === 0 ? blockText : `${trimmedRaw}\n\n${blockText}`;
    const bytesWritten = atomicWriteFileSync(targetPath, bom + newRaw);
    return baseResult("appended", targetPath, blockId, schemaVersion, { bytesWritten });
  }

  const foundVersionNum = Number(found.schemaVersion);
  const callVersionNum = Number(schemaVersion);

  if (foundVersionNum > callVersionNum) {
    return baseResult("refused", targetPath, blockId, schemaVersion, {
      reason: "future-schema-version",
      foundSchemaVersion: found.schemaVersion,
    });
  }

  if (foundVersionNum === callVersionNum && found.body === desiredBody) {
    return baseResult("unchanged", targetPath, blockId, schemaVersion, { bytesWritten: 0 });
  }

  const blockText = buildBlock(blockId, schemaVersion, desiredBody);
  const newRaw = raw.slice(0, found.blockStart) + blockText + raw.slice(found.blockEnd);
  const bytesWritten = atomicWriteFileSync(targetPath, bom + newRaw);
  return baseResult("spliced", targetPath, blockId, schemaVersion, {
    bytesWritten,
    previousSchemaVersion: found.schemaVersion,
  });
}

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
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
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
  findBlock,
  buildBlock,
  normalizeBody,
  atomicWriteFileSync,
};
