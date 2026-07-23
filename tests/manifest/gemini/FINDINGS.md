# Tests for `scripts/manifest.js` (Gemini Family)

## Coverage Statement
I implemented and executed a test suite covering all required attacks from the prompt:
1. Tamper detection (byte flip).
2. Extra/missing payload file detection (excluding tree manifest itself).
3. Case-fold collision (Skipped native directory generation test on Windows due to FS case-insensitivity merging the files before the script could read them).
4. Unicode NFC vs NFD path forms.
5. Raw-byte discipline (CRLF vs LF uniqueness).
6. Symlink/junction refusal in the tree.
7. Determinism.
8. Malformed manifest inputs (truncated JSON, wrong schema_version, negative sizes).

I did not test extremely large directory trees, out-of-memory limits, or deeply nested paths.

## Findings

### 1. BLOCKING: Symlinks and junctions are silently ignored instead of refused
- **Result:** `FAIL`
- **Description:** When `generate('tree', ...)` encounters a symlink or junction, it is completely ignored. The `walkDir` function only checks `entry.isDirectory()` and `entry.isFile()`, so symlinks are silently omitted from the manifest without throwing an error. This violates the contract 01 rule: "symlink/junction refusal".
- **Proposed Fix:** Modify `walkDir` in `scripts/manifest.js` to explicitly throw an error if `entry.isSymbolicLink()` is true.

### 2. MAJOR: `verifyTree` does not validate `schema_version`
- **Result:** `FAIL`
- **Description:** `verifyTree` happily accepts and processes manifests with `"schema_version": "99.0"` or even missing `schema_version` fields. It does not throw a clean error for this malformed input.
- **Proposed Fix:** Add a strict check `if (manifest.schema_version !== SCHEMA_VERSION) throw new Error("Unsupported schema_version");` at the top of `verifyTree`.

### 3. MINOR: `verifyTree` does not validate negative sizes or strictly adhere to schema types
- **Result:** `FAIL`
- **Description:** A manifest with negative `bytes` for a file does not trigger a clean error exit for a malformed manifest. Instead, `verifyTree` proceeds to do disk I/O and simply reports a "mismatch" because the negative size doesn't match the actual file size. While this avoids a crash or false pass, it is not cleanly rejecting the malformed input according to the schema rules.
- **Proposed Fix:** Add basic validation iterating over `manifest.files` in `verifyTree` to ensure `bytes >= 0` and correct types before performing file system reads.
