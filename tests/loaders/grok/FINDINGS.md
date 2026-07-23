# FINDINGS — adversarial test of `scripts/loaders.js` (family: grok)

**Lane:** `tests/loaders/grok/` only  
**Target:** `scripts/loaders.js` (Claude Sonnet builder)  
**Contracts:** `01-promotion-transaction.md` (Topology / fail-closed ACTIVE), `04-trust-boundary-matrix.md` B2/B3, `schemas/active-pointer.schema.json`  
**Runner:** `node tests/loaders/grok/run-tests.js` (zero-dep CJS; exit 1 on any FAIL)  
**Fixtures:** OS temp dirs only — never repo `.graphsmith/`

---

## How to run

```bash
node tests/loaders/grok/run-tests.js
```

---

## Verbatim suite output (authoritative run)

```
# grok adversarial loaders suite
# loaders=F:\Users\PaulPoulose\GraphSmith\graphsmith\scripts\loaders.js
# MARKER_SEQUENCES count=11
# APPENDIX_TOKEN_CAP=1500 WORDS_TO_TOKENS=1.3 PROMPT_SIZE_CAP=65536
PASS	FC/missing-ACTIVE	ACTIVE pointer missing or unreadable at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-miss-active-9u86lS\.graphsmith\evolvable\ACTIVE (ENOENT). Run: graphsm
PASS	FC/missing-evolvable-dir	ACTIVE pointer missing or unreadable at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-no-evo-DZ3CYI\.graphsmith\evolvable\ACTIVE (ENOENT). Run: graphsmith p
PASS	FC/corrupt-JSON-ACTIVE	ACTIVE pointer is corrupt JSON at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-corrupt-json-dMf33a\.graphsmith\evolvable\ACTIVE (Expected property name or 
PASS	FC/empty-ACTIVE	ACTIVE pointer is corrupt JSON at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-empty-active-QEw9Ry\.graphsmith\evolvable\ACTIVE (Unexpected end of JSON inp
PASS	FC/ACTIVE-type-null	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-badtype-null-iU7GYD\.graphsmith\evolvable\ACTIVE failed schema validation: not a JSON object
PASS	FC/ACTIVE-type-array	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-badtype-array-eyhB56\.graphsmith\evolvable\ACTIVE failed schema validation: not a JSON objec
PASS	FC/ACTIVE-type-string	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-badtype-string-WybsPW\.graphsmith\evolvable\ACTIVE failed schema validation: not a JSON obje
PASS	FC/ACTIVE-type-number	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-badtype-number-6wy9hg\.graphsmith\evolvable\ACTIVE failed schema validation: not a JSON obje
PASS	FC/ACTIVE-missing-tree_manifest_sha256	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-partial-u0Bhpv\.graphsmith\evolvable\ACTIVE failed schema validation: missing required field
PASS	FC/ACTIVE-unexpected-field	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-extra-field-BbYASJ\.graphsmith\evolvable\ACTIVE failed schema validation: unexpected field "
PASS	FC/ACTIVE-tree-path-traversal-pattern	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-bad-tree-pat-JnLvoe\.graphsmith\evolvable\ACTIVE failed schema validation: tree "v-../../etc
PASS	FC/ACTIVE-bad-txid-pattern	ACTIVE pointer at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-bad-txid-aCYFjP\.graphsmith\evolvable\ACTIVE failed schema validation: txid "NOT-HEX-VALUE!!
PASS	FC/ACTIVE-nonexistent-tree	Active tree "v-eeeeeeeeeeeeeeee" named by ACTIVE does not exist at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-ghost-tree-nx4HDG\.graphsmith\evolvable\v-e
PASS	FC/ACTIVE-tree-is-file-not-dir	Active tree path C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-tree-is-file-GEwuxI\.graphsmith\evolvable\v-aaaaaaaaaaaaaaaa exists but is not a directory. R
PASS	FC/tree.manifest.json-hash-mismatch	tree.manifest.json hash mismatch for active tree "v-12d00acbfef4e9fd": ACTIVE claims 0000000000000000000000000000000000000000000000000000000000000000, on-disk f
PASS	FC/missing-tree.manifest.json	tree.manifest.json missing for active tree "v-77222db1ffada194" at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-no-manifest-h4aHeT\.graphsmith\evolvable\v-
PASS	FC/unknown-schema_version-9.9	ACTIVE pointer schema_version "9.9" is not understood by this loader (expects "1.0"). Run: graphsmith promote --recover
PASS	FC/empty-projectRoot	resolveActive: projectRoot must be a non-empty string, got "". Run: graphsmith promote --recover
PASS	FC/null-projectRoot	resolveActive: projectRoot must be a non-empty string, got null. Run: graphsmith promote --recover
PASS	FC/undefined-projectRoot	resolveActive: projectRoot must be a non-empty string, got undefined. Run: graphsmith promote --recover
PASS	INJ/appendix-marker-_GRAPHSMITH_UNTRUSTED_CONTENT_BEGIN_	Appendix contains a refused marker sequence: "===GRAPHSMITH-UNTRUSTED-CONTENT-BEGIN===".
PASS	INJ/appendix-marker-_GRAPHSMITH_UNTRUSTED_CONTENT_END_	Appendix contains a refused marker sequence: "===GRAPHSMITH-UNTRUSTED-CONTENT-END===".
PASS	INJ/appendix-marker-NUL	Appendix contains a refused marker sequence: "\u0000".
PASS	INJ/appendix-marker-IGNORE_ALL_PREVIOUS_INSTRUCTIONS	Appendix contains a refused marker sequence: "IGNORE ALL PREVIOUS INSTRUCTIONS".
PASS	INJ/appendix-marker-IGNORE_PREVIOUS_INSTRUCTIONS	Appendix contains a refused marker sequence: "IGNORE PREVIOUS INSTRUCTIONS".
PASS	INJ/appendix-marker-DISREGARD_ALL_PRIOR_INSTRUCTIONS	Appendix contains a refused marker sequence: "DISREGARD ALL PRIOR INSTRUCTIONS".
PASS	INJ/appendix-marker-DISREGARD_PREVIOUS_INSTRUCTIONS	Appendix contains a refused marker sequence: "DISREGARD PREVIOUS INSTRUCTIONS".
PASS	INJ/appendix-marker-SYSTEM_PROMPT_	Appendix contains a refused marker sequence: "SYSTEM PROMPT:".
PASS	INJ/appendix-marker-_SYSTEM	Appendix contains a refused marker sequence: "###SYSTEM".
PASS	INJ/appendix-marker-_im_start_	Appendix contains a refused marker sequence: "<|im_start|>".
PASS	INJ/appendix-marker-_im_end_	Appendix contains a refused marker sequence: "<|im_end|>".
PASS	INJ/case-insensitive-directive	Appendix contains a refused marker sequence: "IGNORE ALL PREVIOUS INSTRUCTIONS".
PASS	INJ/split-across-lines-NOT-caught	substring matcher misses markers split by newlines (documented gap if considered attack)
PASS	INJ/forged-DELIM_END	Appendix contains a refused marker sequence: "===GRAPHSMITH-UNTRUSTED-CONTENT-END===".
PASS	INJ/prompt-marker	Prompt "worker" contains a refused marker sequence: "SYSTEM PROMPT:".
PASS	INJ/under-cap-clean-loads	estTokens~=1499
PASS	CAP/words-over-heuristic-quarantined	words=1154 est=1501
PASS	CAP/exactly-at-or-under-loads	words=1153 est=1499
PASS	CAP/CJK-no-space-undercount-BYPASS	DEFECT: 3000 CJK chars = 1 word under heuristic; cap not enforceable for CJK (~2 tok est, real>>1500)
PASS	CAP/monospace-no-space-BYPASS	DEFECT: 50k consecutive letters = 1 word; token cap bypassed via whitespace heuristic
PASS	CAP/newline-separated-words-counted	n=2000
PASS	PATH/refuse-dotdot	fail-closed: Missing prompt "workers/...prompt.md" in active tree "v-48b9eafe98d8be30". Run: graphsmith promote --recover
PASS	PATH/refuse-dotdot-file	fail-closed: loadPrompt: invalid worker name "../secret" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-abs-posix	fail-closed: loadPrompt: invalid worker name "/etc/passwd" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-abs-win	fail-closed: loadPrompt: invalid worker name "C:\\Windows\\win.ini" -- refusing to build a path from it. Run: graphsmith promote --re
PASS	PATH/refuse-drive-rel	fail-closed: loadPrompt: invalid worker name "C:foo" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-nul-byte	fail-closed: loadPrompt: invalid worker name "wo\u0000rker" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-ads	fail-closed: loadPrompt: invalid worker name "file.txt:ads" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-slash	fail-closed: loadPrompt: invalid worker name "a/b" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-backslash	fail-closed: loadPrompt: invalid worker name "a\\b" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-space	fail-closed: loadPrompt: invalid worker name "has space" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-empty	fail-closed: loadPrompt: invalid worker name "" -- refusing to build a path from it. Run: graphsmith promote --recover
PASS	PATH/refuse-unicode-sep	fail-closed: loadPrompt: invalid worker name "a∕b" -- refusing to build a path from it. Run: graphsmith promote --recover
SKIPPED	PATH/symlink-escape-quarantine	no symlink privilege: EPERM
SKIPPED	PATH/rel-symlink-escape	EPERM
PASS	ENC/appendix-invalid-utf8	Appendix in tree "v-ac61e49e5f03188c" is not valid UTF-8 (The encoded data was not valid for encoding utf-8).
PASS	ENC/prompt-invalid-utf8	Prompt "p" is not valid UTF-8 (The encoded data was not valid for encoding utf-8).
PASS	ENC/prompt-utf16-bom-quarantined	invalid-utf8: Prompt "u16" is not valid UTF-8 (The encoded data was not valid for encoding utf-8).
PASS	ENC/appendix-utf16-bom-quarantined	invalid-utf8
PASS	ENC/prompt-NFD-content	Prompt "nfd" is not NFC-normalized Unicode.
PASS	ENC/appendix-NFD-NOT-checked	OBSERVED: loadAppendix does not enforce NFC (only loadPrompt does); asymmetry vs B3; B2 does not list NFC
PASS	ENC/invalid-utf8-no-crash	both loaders returned quarantine objects
PASS	SIZE/prompt-over-64KB-quarantined	Prompt "big" is 65537 bytes, cap is 65536.
PASS	SIZE/prompt-exactly-64KB-allowed	bytes=65536
PASS	PIN/ctx-stable-after-ACTIVE-swap	treeId=v-aaaaaaaaaaaaaaaa
PASS	PIN/fresh-resolve-sees-swapped-tree	v-bbbbbbbbbbbbbbbb
PASS	PIN/second-ctx-loads-B	v-bbbbbbbbbbbbbbbb
PASS	PIN/forged-ctx-treeId-treeDir-desync	OBSERVED: treeId is non-authoritative label; content follows treeDir. Callers must not forge ctx.
PASS	RET/appendix-shape-and-sha256	sha256=c7d6872bc17d... sub=true subOk=true
PASS	RET/prompt-shape-and-sha256	sha256=819b41e2a52d... sub=false subOk=true
PASS	RET/appendix-has-subordination-preamble
PASS	RET/prompt-no-subordination-preamble
PASS	RET/missing-appendix-quarantined	No graphsmith.learned.md in active tree "v-8aea27efcd378bab" at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-ret-no-app-nDdirn\.graphsmith\evolvable\v-8aea27efcd378bab\graphsmith.learned.md.
PASS	RET/missing-prompt-fail-closed	Missing prompt "workers/ghost.prompt.md" in active tree "v-4b3c855b17aad178". Run: graphsmith promote --recover
PASS	RET/loadAppendix-null-ctx	loadAppendix: invalid ctx -- expected the object returned by resolveActive() ({ treeId, treeDir, pointer }), got null. Run: graphsmith promote --recover
PASS	RET/loadPrompt-empty-ctx	loadPrompt: invalid ctx -- expected the object returned by resolveActive() ({ treeId, treeDir, pointer }), got {}. Run: graphsmith promote --recover
PASS	XTRA/ACTIVE-utf8-bom-fail-closed	ACTIVE pointer is corrupt JSON at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-bom-active-afLY6g\.graphsmith\evolva
PASS	XTRA/ACTIVE-trailing-garbage-fail-closed	ACTIVE pointer is corrupt JSON at C:\Users\pjpou\AppData\Local\Temp\gs-loaders-grok-trail-garbage-8P
PASS	XTRA/quarantined-appendix-does-not-block-prompt
PASS	XTRA/valid-worker-name-charset
PASS	XTRA/fullwidth-marker-NOT-caught	DEFECT/LIMIT: fullwidth homoglyphs bypass casefold substring marker list
PASS	XTRA/zwj-in-marker-NOT-caught	LIMIT: ZWSP breaks substring match
# summary PASS=80 FAIL=0 SKIPPED=2 TOTAL=82
```

**Exit code:** `0`. Symlink cases SKIPPED on this Windows host without symlink privilege (EPERM) — not hollow greens.

---

## Attack matrix vs required cases

| # | Attack | Result | Verdict |
|---|--------|--------|---------|
| 1 | Fail-closed ACTIVE (missing, corrupt JSON, empty, wrong types, closed-schema extra field, bad patterns, ghost tree, tree-is-file, manifest hash mismatch, missing manifest, unknown schema_version, bad projectRoot) | All throw `failClosed` + `graphsmith promote --recover`; **no default/fallback tree** | **HOLD** |
| 2 | Injection: every `MARKER_SEQUENCES` entry in appendix; case-folded directive; forged `DELIM_END`; prompt `SYSTEM PROMPT:` | All quarantined `marker-sequence` | **HOLD** for exact/CI substring |
| 2b | Markers **split across lines** (`IGNORE\nALL\nPREVIOUS\nINSTRUCTIONS`) | Contiguous substring absent → **loads successfully** | **LIMIT** (documented) |
| 3 | Cap at/over English whitespace words | 1153 words (~1499 tok) loads; 1154 (~1501) quarantines | **HOLD** for WS English |
| 3b | Cap gaming: 3000 CJK no-space; 50k monoword ASCII | Both **load** (≈2 estimated tokens) | **DEFECT MED** |
| 4 | Worker names: `..`, `../x`, abs paths, `C:`, NUL, ADS, slashes, empty, unicode sep | Refuse/fail-closed; never leaves tree via name | **HOLD** (escape blocked) |
| 4b | Symlink / relative symlink escape | **SKIPPED** (EPERM) — selftest path exists in loaders but not executed here | **UNVERTIFIABLE on this host** |
| 5 | Invalid UTF-8, UTF-16 BOM → quarantine, no crash; NFD prompt → `not-nfc-normalized` | Holds for prompts | **HOLD** for B3 |
| 5b | NFD appendix | **Not checked** by `loadAppendix` | **LIMIT / asymmetry** (B2 omits NFC; OK by letter, asymmetric) |
| 6 | Prompt >64KB quarantine; ==64KB allowed | Holds | **HOLD** |
| 7 | Ctx pin: swap ACTIVE between loads with same ctx | Both appendix+prompt stay on tree A; fresh resolve sees B | **HOLD** |
| 8 | Return `{content, treeId, sha256}`; sha of raw file bytes; subordination on appendix only | Holds | **HOLD** |

---

## Defects (severity + fix)

### D1 — Appendix token cap bypass via non-whitespace scripts / monowords  
**Severity:** MEDIUM (B2 integrity / DoS / context stuffing)  
**Evidence:** `CAP/CJK-no-space-undercount-BYPASS`, `CAP/monospace-no-space-BYPASS`  
**Mechanism:** `estimateTokens` = `ceil(text.split(/\s+/).filter(Boolean).length * 1.3)`. Any text without whitespace is **one “word”**. 3000 Han characters or 50KB of `a` estimate to ~2 tokens and pass the 1,500 cap.  
**Fix (proposal, not applied — out of lane):** Combine heuristic with hard byte/char caps (e.g. max 6–8KB raw or max code points ≈ cap) and/or per-script estimators (CJK ≈1 tok/char). Document if product accepts English-only appendix assumption.

### D2 — Marker refusal is contiguous-substring only (split / homoglyph / ZWSP)  
**Severity:** LOW–MED (injection residual; contract 04 standing rule already admits residual semantic risk)  
**Evidence:** `INJ/split-across-lines-NOT-caught`, `XTRA/fullwidth-marker-NOT-caught`, `XTRA/zwj-in-marker-NOT-caught`  
**Mechanism:** `findMarker` uses `includes` / lowercased `includes`. Newlines, ZWSP (`\u200b`), fullwidth Latin defeat the list while remaining model-readable.  
**Fix:** Normalize (NFKC strip bidi/zw), collapse whitespace before match, optionally match loose regexes for directive phrases; treat NFKC of marker list.

### D3 — `WORKER_NAME_RE` allows `..` as a legal name  
**Severity:** LOW (no FS escape observed)  
**Evidence:** `PATH/refuse-dotdot` → name accepted, path becomes `workers/...prompt.md` (because `workerName + ".prompt.md"` ⇒ `"...prompt.md"`), missing → fail-closed.  
**Not an escape**, but surprising.  
**Fix:** Reject names that are `.` / `..` or start with `.` if only “safe identifiers” are intended (`^(?!\\.*)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*$`).

### D4 — Forged `ctx` can desync `treeId` from `treeDir`  
**Severity:** LOW (trusted caller assumed; not a remote attack)  
**Evidence:** `PIN/forged-ctx-treeId-treeDir-desync`  
**Mechanism:** Loaders trust `ctx.treeDir` for I/O and stamp returned `treeId` from `ctx.treeId` without re-binding. A buggy caller can lie in telemetry.  
**Fix:** Optionally re-derive `treeId` as `path.basename(realpath(treeDir))` or seal ctx from `resolveActive` (frozen object + WeakMap).

### D5 — Symlink escape not executed on this agent host  
**Severity:** n/a (coverage gap, not a product fail)  
**Evidence:** SKIPPED `PATH/symlink-*` EPERM  
**Note:** Implementation presence of `realpathSync` + `isInside` is reviewed statically and matches B3; CI with symlink privilege should un-skip.

### Observed non-defects (asymmetric by contract)

- **Appendix NFC not enforced:** B2 lists token cap / delimiter / subordination / marker — not NFC. B3 lists NFC for prompts. Asymmetry is **contract-consistent**, flagged only for operators.
- **ACTIVE UTF-8 BOM / trailing garbage:** fail-closed (strict JSON.parse) — good.
- **Missing appendix quarantine vs missing prompt refuse:** matches B2 vs B3 wording.

---

## Coverage statement (honest)

| Area | Covered? |
|------|----------|
| resolveActive fail-closed surface | Yes — broad schema/IO matrix |
| loadAppendix marker list (all exported markers) | Yes |
| loadAppendix token heuristic English | Yes |
| loadAppendix token gaming CJK/monoword | Yes (finds D1) |
| loadPrompt path allowlist | Yes |
| loadPrompt realpath symlink escape | **No** on this host (SKIPPED EPERM) |
| Encoding UTF-8 fatal + UTF-16 BOM + NFD prompt | Yes |
| Size 64KB boundary | Yes |
| Single-read ctx pinning across ACTIVE swap | Yes |
| Return sha256 binding to **raw file bytes** (pre-wrap) | Yes |
| Concurrent multi-process races on ACTIVE | **No** (out of unit scope; contract 01 is promote-side) |
| Payload inventory vs `tree.manifest.json` files[] | **No** — loaders.js explicitly defers full tree verify to `manifest.js` |
| NTFS ADS open via validated name | Name with `:` refused; did not attempt CreateFile ADS APIs |
| Windows junction directory escape | **No** (no priv) |

**Overall:** Required attacks 1–8 exercised. Product fail-closed + pin + shape contracts hold. Real break found: **token-cap heuristic is not a cap under no-whitespace content (D1)**. Marker list is brittle to reshape (D2). Suite is runnable, exit-gated, temp-only, zero-dep; did not modify `scripts/loaders.js` or leave lane.

---

## Files in lane

- `tests/loaders/grok/run-tests.js` — suite  
- `tests/loaders/grok/FINDINGS.md` — this document  
