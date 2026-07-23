# Manifest Adversarial Test Findings

This suite attacks `scripts/manifest.js` against `contracts/09-manifest-formats.md`, `contracts/01-promotion-transaction.md` section Topology, and `schemas/tree-manifest.schema.json`. Run it with:

```sh
node tests/manifest/gpt-sol-pro/run-tests.js
```

## Coverage And Results

| Attack | Result |
| --- | --- |
| One-byte payload tamper | PASS: `verifyTree` reports `mismatch`. |
| Extra payload | PASS: closed inventory verification reports `extra`. |
| Missing payload | PASS: closed inventory verification reports `missing`. |
| `tree.manifest.json` metadata exception during verification | PASS: the manifest is not reported as extra. |
| Existing `tree.manifest.json` during generation | FAIL: generated tree inventory includes it unless the caller supplies an optional exclusion. |
| Case-fold collision | PASS: generation refuses the collision. Tested through public `generate` with virtual enumeration so the attack also runs on case-insensitive Windows filesystems. |
| Single NFD path | PASS: output path is NFC canonicalized. |
| NFC/NFD post-normalization collision | PASS: generation refuses the collision. Tested through public `generate` with virtual enumeration because some filesystems normalize names. |
| LF versus CRLF bytes | PASS: hashes differ and equal the expected raw-byte SHA-256 values. |
| Symlink/junction | FAIL when link creation is available: generation silently ignores a directory link instead of refusing the tree. SKIPPED only if the host denies link creation. |
| Determinism | PASS: two tree manifests serialize byte-for-byte identically. Tree manifests have no declared timestamp field. |
| Truncated JSON | PASS: CLI exits 1 with a concise error and no stack trace. |
| Wrong `schema_version` | FAIL: verification returns a false PASS and exits 0. |
| Negative `bytes` | PASS for rejection: hash/size comparison makes verification exit 1. This does not establish general schema validation. |
| Closed-schema additional property | FAIL: verification returns a false PASS and exits 0. |
| Duplicate manifest path | FAIL: later entries overwrite earlier entries in a `Map`, and verification exits 0. |

## Defects

### [BLOCKING] `verifyTree` does not validate the frozen tree-manifest schema

Wrong `schema_version` values and forbidden additional properties are accepted with exit 0. This permits manifests outside the frozen contract to produce a false integrity PASS.

Proposed fix: validate the parsed object against all constraints in `schemas/tree-manifest.schema.json` before filesystem comparison. Since the implementation is zero-dependency, implement explicit checks for the exact top-level keys, `schema_version === "1.0"`, the exact entry keys and types, lowercase 64-hex hashes, non-negative integer sizes, canonical relative paths, and a unique path set. Return a clean verification error on any violation.

### [BLOCKING] Duplicate manifest entries are silently merged

`verifyTree` inserts entries into a `Map` without checking whether the canonical path already exists. Duplicate paths therefore collapse into one expected entry and can pass verification.

Proposed fix: while building `expected`, reject a path already present after NFC canonicalization and case folding. Do not overwrite it.

### [MAJOR] Generation does not automatically exclude exactly `tree.manifest.json`

`generate("tree")` inventories an existing `tree.manifest.json` unless every caller knows to pass `excludeManifest`. The topology contract defines this as the sole metadata exception, not a caller-selected exception.

Proposed fix: for `kind === "tree"`, always exclude canonical root-relative `tree.manifest.json`; reject attempts to use another metadata exception. Keep arbitrary exclusions, if needed for non-tree manifests, separate from this invariant.

### [MAJOR] Symlinks and junctions are not refused

`walkDir` handles only `Dirent.isDirectory()` and `Dirent.isFile()`. A symbolic link or Windows junction is silently omitted, so generation can bless a tree containing a forbidden link while presenting an apparently complete inventory.

Proposed fix: inspect every directory entry with `lstatSync`; throw on symbolic links and reparse-point/junction-like entries before recursing or hashing. Apply the same refusal during verification so links introduced after generation cannot be ignored.

## Honest Coverage Gaps

The suite did not test hostile concurrent mutation during directory walking or hashing, special device/FIFO/socket entries, unreadable files, deep path/long-path limits, or performance on very large trees. It did not invoke an external JSON Schema engine; it tested representative frozen-schema violations through the verifier CLI. Case and Unicode collision enumeration is mocked at the `fs.readdirSync` boundary on all hosts to avoid hollow skips caused by Windows case folding or filesystem Unicode normalization.
