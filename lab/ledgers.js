/* GraphSmith Conformance Lab — Harness-Owned Ledger Writers (lab/ledgers.js)
 * Contract 12: append-only process/spawn and file-mutation ledgers. The HARNESS
 * records them, not the agent — "cleaned up before scoring" must not erase evidence.
 * Zero-dep CommonJS, Node >= 18.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const SCHEMA_VERSION = "1.0";

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function verifyLedger(ledgerPath) {
  /* Detect tampering via hash chain (item 5).
   * Each entry carries prev_hash = sha256(previous canonical entry).
   * A broken/truncated/overwritten chain → tampered. */
  if (!fs.existsSync(ledgerPath)) {
    return { ok: true, brokenAt: null };
  }

  try {
    const content = fs.readFileSync(ledgerPath, "utf8");
    const lines = content.split("\n").filter((line) => line.trim().length > 0);

    let prevEntryHash = null;
    for (let i = 0; i < lines.length; i++) {
      let entry;
      try {
        entry = JSON.parse(lines[i]);
      } catch (e) {
        return { ok: false, brokenAt: i, reason: "entry-not-valid-json" };
      }

      /* Calculate canonical hash of this entry (before checking prev_hash). */
      const entryForHash = { ...entry };
      delete entryForHash.prev_hash;
      const currentHash = sha256(JSON.stringify(entryForHash));

      /* If this is not the first entry, verify prev_hash matches previous entry. */
      if (i > 0) {
        if (entry.prev_hash !== prevEntryHash) {
          return {
            ok: false,
            brokenAt: i,
            reason: "prev-hash-mismatch",
            expected: prevEntryHash,
            got: entry.prev_hash,
          };
        }
      }

      prevEntryHash = currentHash;
    }

    return { ok: true, brokenAt: null };
  } catch (e) {
    return { ok: false, brokenAt: -1, reason: "read-error", error: e.message };
  }
}

/* Ledger entry types and formats. */
const ENTRY_TYPES = {
  PROCESS_SPAWN: "process-spawn",
  PROCESS_EXIT: "process-exit",
  FILE_CREATE: "file-create",
  FILE_MODIFY: "file-modify",
  FILE_DELETE: "file-delete",
  FILE_CHMOD: "file-chmod",
  NETWORK_REQUEST: "network-request",
};

class LedgerWriter {
  constructor(ledgerDir, cellId) {
    this.ledgerDir = ledgerDir;
    this.cellId = cellId;

    if (!fs.existsSync(this.ledgerDir)) {
      fs.mkdirSync(this.ledgerDir, { recursive: true });
    }

    this.processLedgerPath = path.join(
      this.ledgerDir,
      `cell-${cellId}-process-ledger.jsonl`
    );
    this.fileMutationLedgerPath = path.join(
      this.ledgerDir,
      `cell-${cellId}-file-mutation-ledger.jsonl`
    );
  }

  /* Append-only process ledger: records spawned processes and exits.
   * Used to detect unauthorized process chains or resource exhaustion. */
  recordProcessSpawn(processInfo) {
    const entry = {
      type: ENTRY_TYPES.PROCESS_SPAWN,
      timestamp: new Date().toISOString(),
      pid: processInfo.pid,
      command: processInfo.command,
      args: processInfo.args || [],
      cwd: processInfo.cwd || null,
      env_keys: processInfo.env ? Object.keys(processInfo.env) : [],
      parentPid: processInfo.parentPid ?? null,
    };

    this._append(this.processLedgerPath, entry);
    return entry;
  }

  recordProcessExit(processInfo) {
    const entry = {
      type: ENTRY_TYPES.PROCESS_EXIT,
      timestamp: new Date().toISOString(),
      pid: processInfo.pid,
      exitCode: processInfo.exitCode ?? null,
      signal: processInfo.signal || null,
      duration: processInfo.duration || null,
    };

    this._append(this.processLedgerPath, entry);
    return entry;
  }

  /* Append-only file mutation ledger: records all file operations.
   * Used to detect unauthorized file modifications. Contract 12:
   * "the harness (not the agent) records append-only process/spawn and
   * file-mutation ledgers per cell; 'cleaned up before scoring' no longer
   * erases evidence". */
  recordFileCreate(filePath, size) {
    const entry = {
      type: ENTRY_TYPES.FILE_CREATE,
      timestamp: new Date().toISOString(),
      path: filePath,
      size: size || null,
    };

    this._append(this.fileMutationLedgerPath, entry);
    return entry;
  }

  recordFileModify(filePath, beforeHash, afterHash) {
    const entry = {
      type: ENTRY_TYPES.FILE_MODIFY,
      timestamp: new Date().toISOString(),
      path: filePath,
      beforeHash,
      afterHash,
    };

    this._append(this.fileMutationLedgerPath, entry);
    return entry;
  }

  recordFileDelete(filePath) {
    const entry = {
      type: ENTRY_TYPES.FILE_DELETE,
      timestamp: new Date().toISOString(),
      path: filePath,
    };

    this._append(this.fileMutationLedgerPath, entry);
    return entry;
  }

  recordFileChmod(filePath, beforeMode, afterMode) {
    const entry = {
      type: ENTRY_TYPES.FILE_CHMOD,
      timestamp: new Date().toISOString(),
      path: filePath,
      beforeMode,
      afterMode,
    };

    this._append(this.fileMutationLedgerPath, entry);
    return entry;
  }

  /* Append a JSON object to a ledger file (one per line, JSONL format).
   * Compute prev_hash for hash chain verification. */
  _append(ledgerPath, entry) {
    /* Read the last entry to compute prev_hash. */
    let prevHash = null;
    if (fs.existsSync(ledgerPath)) {
      try {
        const content = fs.readFileSync(ledgerPath, "utf8");
        const lines = content.split("\n").filter((line) => line.trim().length > 0);
        if (lines.length > 0) {
          const lastEntry = JSON.parse(lines[lines.length - 1]);
          const lastEntryForHash = { ...lastEntry };
          delete lastEntryForHash.prev_hash;
          prevHash = sha256(JSON.stringify(lastEntryForHash));
        }
      } catch (e) {
        /* If we can't read or parse, proceed without prev_hash chain. */
        prevHash = null;
      }
    }

    if (prevHash) {
      entry.prev_hash = prevHash;
    }

    const line = JSON.stringify(entry);
    fs.appendFileSync(ledgerPath, line + "\n");
  }

  /* Read all entries from a ledger. */
  readLedger(ledgerPath) {
    if (!fs.existsSync(ledgerPath)) {
      return [];
    }

    const content = fs.readFileSync(ledgerPath, "utf8");
    return content
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line));
  }

  getProcessLedger() {
    return this.readLedger(this.processLedgerPath);
  }

  getFileMutationLedger() {
    return this.readLedger(this.fileMutationLedgerPath);
  }

  /* Analyze ledger for anomalies. Contract 12: evidence of unauthorized
   * activity is preserved and available to the scorer. */
  analyzeProcessLedger() {
    const entries = this.getProcessLedger();
    const analysis = {
      totalProcesses: entries.filter((e) => e.type === ENTRY_TYPES.PROCESS_SPAWN).length,
      totalExits: entries.filter((e) => e.type === ENTRY_TYPES.PROCESS_EXIT).length,
      failedExits: entries.filter(
        (e) => e.type === ENTRY_TYPES.PROCESS_EXIT && e.exitCode !== 0
      ).length,
      longestDuration: Math.max(
        0,
        ...entries
          .filter((e) => e.type === ENTRY_TYPES.PROCESS_EXIT && e.duration)
          .map((e) => e.duration)
      ),
    };

    return analysis;
  }

  analyzeFileMutationLedger() {
    const entries = this.getFileMutationLedger();
    const analysis = {
      filesCreated: entries.filter((e) => e.type === ENTRY_TYPES.FILE_CREATE).length,
      filesModified: entries.filter((e) => e.type === ENTRY_TYPES.FILE_MODIFY).length,
      filesDeleted: entries.filter((e) => e.type === ENTRY_TYPES.FILE_DELETE).length,
      chmodOperations: entries.filter((e) => e.type === ENTRY_TYPES.FILE_CHMOD).length,
    };

    return analysis;
  }
}

function selftest() {
  const os = require("os");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-ledger-test-"));

  try {
    /* Test 1: LedgerWriter initialization. */
    const writer = new LedgerWriter(tmpDir, "test-cell-1");

    if (!fs.existsSync(tmpDir)) {
      throw new Error("Ledger directory not created");
    }

    /* Test 2: Process spawn recording. */
    writer.recordProcessSpawn({
      pid: 1234,
      command: "node",
      args: ["script.js"],
      cwd: "/tmp",
    });

    const processLedger = writer.getProcessLedger();
    if (processLedger.length !== 1) {
      throw new Error("Process spawn not recorded");
    }
    if (processLedger[0].type !== ENTRY_TYPES.PROCESS_SPAWN) {
      throw new Error("Process spawn entry has wrong type");
    }

    /* Test 3: Process exit recording. */
    writer.recordProcessExit({
      pid: 1234,
      exitCode: 0,
      duration: 1500,
    });

    const processLedger2 = writer.getProcessLedger();
    if (processLedger2.length !== 2) {
      throw new Error("Process exit not recorded");
    }

    /* Test 4: File mutation recording. */
    writer.recordFileCreate("/test/file.js", 1024);
    writer.recordFileModify("/test/file.js", "hash1", "hash2");
    writer.recordFileDelete("/test/file.js");

    const fileLedger = writer.getFileMutationLedger();
    if (fileLedger.length !== 3) {
      throw new Error("File mutations not recorded");
    }

    /* Test 5: Ledger analysis. */
    const processAnalysis = writer.analyzeProcessLedger();
    if (processAnalysis.totalProcesses !== 1) {
      throw new Error("Process analysis incorrect");
    }
    if (processAnalysis.totalExits !== 1) {
      throw new Error("Exit analysis incorrect");
    }

    const fileAnalysis = writer.analyzeFileMutationLedger();
    if (fileAnalysis.filesCreated !== 1) {
      throw new Error("File create analysis incorrect");
    }
    if (fileAnalysis.filesModified !== 1) {
      throw new Error("File modify analysis incorrect");
    }
    if (fileAnalysis.filesDeleted !== 1) {
      throw new Error("File delete analysis incorrect");
    }

    /* Test 6: JSONL format is preserved. */
    const processLedgerContent = fs.readFileSync(writer.processLedgerPath, "utf8");
    const lines = processLedgerContent.split("\n").filter((l) => l.trim().length > 0);
    if (lines.length !== 2) {
      throw new Error("JSONL format not preserved");
    }

    for (const line of lines) {
      const obj = JSON.parse(line);
      if (!obj.type || !obj.timestamp) {
        throw new Error("JSONL entry malformed");
      }
    }

    console.log("✓ lab/ledgers.js --selftest PASSED");
    return 0;
  } catch (e) {
    console.error("✗ lab/ledgers.js --selftest FAILED:", e.message);
    return 1;
  } finally {
    require("child_process").execSync(`rm -rf ${tmpDir}`, { stdio: "ignore" });
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes("--selftest")) {
    process.exit(selftest());
  }
  console.log(JSON.stringify({ entry_types: ENTRY_TYPES }, null, 2));
}

module.exports = { LedgerWriter, verifyLedger, ENTRY_TYPES, SCHEMA_VERSION };
