# FINDINGS — Kimi adversarial test of `scripts/capability-policy.js` + `scripts/risk-policy.json`

**Tester lane:** `tests/risk-policy/kimi/`  
**Date:** 2026-07-23  
**Policy under test:** `syntactic-allowlist-v1` / `scripts/risk-policy.json`  
**Harness:** `tests/risk-policy/kimi/run-tests.js` (zero-deps, temp-dir only)

## Executive summary

The fail-closed syntactic allowlist correctly blocks most obvious and obfuscated external-call payloads, and policy-shape / bounds tests pass. However, **the review found issues**:

1. **HIGH:** Variable aliasing of `require`/`fetch` bypasses the scan.
2. **HIGH:** Block-comment / whitespace insertion between a call keyword and its argument list bypasses the regex detection.
3. **MEDIUM:** The `worker-prompt` classification rule never matches normal repo-relative paths because it looks for `/workers/` while `normalizeRelPosix` strips the leading slash, so `workers/gather.prompt.md` is classified as `data` instead of `prompt`.

Because of #1 and #2, a payload that still executes an external effect can return `no_external_calls:true`, making an unsafe typed repair auto-apply-eligible. A zero-finding review is therefore INVALID.

## Test methodology

- Drive `scripts/capability-policy.js` through `require()` from a temporary directory.
- Drive its CLI (`node scripts/capability-policy.js --selftest`) from a temporary directory.
- Verdicts taken from return values / JSON fields (`no_external_calls`, `repairClass`, etc.), never from log text.
- No modifications to `scripts/`.
- Compare policy patterns with `scripts/heal.js` inline `EXTERNAL_CALL_PATTERNS` / `STATIC_UNPROVABLE_PATTERNS` for consistency.
- Determinism verified by repeated scans and by inspecting result shape for clock/random fields.

## Detailed results

### 1. Fail-closed eligibility — bypass attacks

| # | Attack vector | Payload gist | Expected verdict | Result |
|---|---------------|--------------|------------------|--------|
| 1 | `String.fromCharCode` assembly | `String.fromCharCode(...); globalThis[m]('http')` | Not eligible | **Blocked** |
| 2 | Hex escape assembly | `'\x72\x65...'` + computed member | Not eligible | **Blocked** |
| 3 | Unicode escape assembly | `'\u0072...'` + dynamic `require` | Not eligible | **Blocked** |
| 4 | String concat assembly | `globalThis['re'+'quire']('http')` | Not eligible | **Blocked** |
| 5 | Template assembly | `require(\`${mod}\`)` | Not eligible | **Blocked** |
| 6 | Computed member | `cp['exec']('whoami')` | Not eligible | **Blocked** |
| 7 | Dynamic `require` | `require(m).get('x')` | Not eligible | **Blocked** |
| 8 | Dynamic `import` | `import(m).then(...)` | Not eligible | **Blocked** |
| 9 | `globalThis` indirection | `globalThis.fetch('http://x')` | Not eligible | **Blocked** |
| 10 | `Function` constructor | `new Function('return require("http")...')` | Not eligible | **Blocked** |
| 11 | `Reflect.construct` | `Reflect.construct(require('http'), [])` | Not eligible | **Blocked** |
| 12 | Variable indirection (`require` alias) | `const load = require; load('http').get('x')` | Not eligible | **Bypass** |
| 13 | Variable indirection (`fetch` alias) | `const f = fetch; f('http://x')` | Not eligible | **Bypass** |
| 14 | Comment/whitespace trick (`require`) | `require /* external */ ('http').get('x')` | Not eligible | **Bypass** |
| 15 | Comment/whitespace trick (`fetch`) | `fetch /* external */ ('http://x')` | Not eligible | **Bypass** |
| 16 | Combined obfuscation | concat + fromCharCode + globalThis | Not eligible | **Blocked** |
| 17 | Clean prose prompt | plain safe prose | Eligible (`true`) | **Eligible** |
| 18 | Clean tunables JSON | `{"max_retries":3}` | Eligible (`true`) | **Eligible** |

### 2. Manager / path classification

All case-variant manager paths are classified as `repairClass=code, kind=manager, isManager=true`:
- `MANAGER.js`, `Manager.js`, `nested/manager.JS`, `manager.cjs`, `manager.mjs`, `Manager.BOX.js`.

Non-manager and typed targets classify correctly, with one inconsistency:
- `workers/process.js` → `code / executable / not manager`
- `.md`, `.txt`, `.yml`, `.yaml` → `typed / data`
- `tunables.json` → `typed / tunables`
- `scenario.json` / `*.scenario.json` / `/scenarios/*.json` → `typed / scenario`
- `*.config.json`, `workflow.manifest.json`, generic `*.json` → `typed / config`
- `workers/*.prompt.md` → **`typed / data`** (expected `typed / prompt` per the `worker-prompt` rule)
- executable extensions `.ts`, `.tsx`, `.jsx` → `code / executable / not manager`
- unknown extension e.g. `.exe` → fail-closed `code / unknown-executable-surface`

### 3. Policy integrity

- `validatePolicyShape(RAW_POLICY)` passes.
- `external_call_patterns` and `unprovable_constructs` are non-empty and every regex compiles.
- `bounds` include `max_scan_input_bytes` and `max_reported_matches`, both with numeric `value` and non-empty `unit`.

### 4. Oversized input fail-closed

- Input at exactly `max_scan_input_bytes` (2,000,000 bytes) returns `no_external_calls:false` and `unprovable:["input-too-large"]`.
- Input one byte under is clean-eligible (`true`).
- Input one byte over is rejected.

No silent truncation occurs.

### 5. Consistency with `scripts/heal.js`

- Every pattern id in `heal.js` `EXTERNAL_CALL_PATTERNS` and `STATIC_UNPROVABLE_PATTERNS` exists in `risk-policy.json`.
- Regex sources are byte-for-byte equivalent for the existing ids.
- Representative samples that `heal.js` flags are also flagged by the policy.

No divergence in the currently-shared pattern set.

### 6. Determinism

- Repeated scans of the same obfuscated payload produce identical serialized output.
- Repeated classifications of the same case-variant manager path produce identical output.
- Result objects do not contain timestamps, random values, or `Date.now()`.

### 7. CLI smoke

`node scripts/capability-policy.js --selftest` runs successfully from a temporary directory and reports `all_pass:true` for the built-in selftest.

## Defects found

### D1 — Variable indirection bypasses the allowlist

**Severity:** HIGH  
**Test cases:** `attack-variable-indirection-require-alias`, `attack-variable-indirection-fetch-alias`

The policy only looks for call-site syntax (`require(...)`, `fetch(...)`, dynamic `import(...)`, etc.). Assigning the built-in `require` or `fetch` to a local variable defeats every current pattern:

```js
const load = require; load('http').get('x');   // no_external_calls = true (bypass)
const f = fetch;    f('http://x');             // no_external_calls = true (bypass)
```

Because the payload still performs an external effect but the scan returns `no_external_calls:true`, a typed repair containing this code would be classified auto-apply-eligible.

**Fix options:**
- Add an unprovable-construct pattern that flags `require` used as a value rather than a call, e.g. `\brequire\s*[,;)]` or `=\s*require\b`.
- More conservatively, treat any occurrence of the bare token `\brequire\b` as unprovable (may over-flag clean prose that mentions "require" — acceptable for fail-closed, but consider scoping to code-path classification).
- Add a generic "indirect external-call" pattern that flags `fetch`/`require`/`import` assigned to a variable and later invoked through that variable (requires interprocedural reasoning, so conservatively flagging aliases is simpler).

### D2 — Block-comment / whitespace insertion bypasses regex call-site detection

**Severity:** HIGH  
**Test cases:** `attack-comment-whitespace-require`, `attack-comment-whitespace-fetch`

Because the regexes assume the opening parenthesis immediately follows the keyword (allowing only `\s*`), inserting `/* ... */` between the keyword and the argument list evades detection:

```js
require /* external */ ('http').get('x');   // no_external_calls = true (bypass)
fetch /* external */ ('http://x');          // no_external_calls = true (bypass)
```

JS grammar permits comments and arbitrary whitespace/line terminators between a callee and its arguments.

**Fix options:**
- Pre-process the scan blob by stripping block comments `/* ... */` and line comments `// ...` before running the external-call regexes, OR
- Add a lightweight unprovable-construct pattern that detects a call keyword immediately followed by `/*` or `//`, since legitimate code rarely inserts comments between a function name and its argument list.

### D3 — `worker-prompt` classification rule never matches repo-relative paths

**Severity:** MEDIUM  
**Test case:** `typed-prompt`

The `worker-prompt` rule uses `"path_contains": "/workers/"` and `"basename_suffix": ".prompt.md"`. The engine calls `normalizeRelPosix(target)`, which strips leading slashes and produces paths like `workers/gather.prompt.md`. That normalized path does **not** contain `/workers/`, so the rule never matches. The file then falls through to the `.md` / `.txt` / `.yml` / `.yaml` rule and is classified as `data`.

**Observed output:**
```json
{"target":"workers/gather.prompt.md","got":{"repairClass":"typed","isManager":false,"kind":"data"},"want":{"repairClass":"typed","isManager":false,"kind":"prompt"}}
```

**Fix options:**
- Change `"path_contains": "/workers/"` to `"path_contains": "workers/"` in `risk-policy.json`, OR
- Make `applyRule` for `path-contains-and-basename-suffix` match against a slash-qualified path (`/${posix}/`) in addition to the normalized path.

## Recommendations

1. Close D1 and D2 before treating any typed repair as auto-apply-eligible in production.
2. Fix D3 so prompt files under `workers/` get the intended `prompt` kind and are not silently downgraded to `data`.
3. Consider a pre-scan normalizer in `capabilityScan` that removes JS comments and collapses horizontal whitespace, so the regex policy is harder to evade with layout tricks.
4. Keep pattern parity with `heal.js` under version control (a CI check that extracts the two arrays and diffs them against `risk-policy.json`).
5. Add the new adversarial cases in this harness to the module's `--selftest` suite so regressions are caught by the builder's own tests.

## Run status

Run command: `node tests/risk-policy/kimi/run-tests.js`

Summary (verbatim from harness):

```
PASS=43 FAIL=5 SKIPPED=0
EXIT: 1
```

The five failures are exactly D1 (2 tests), D2 (2 tests), and D3 (1 test). All other policy-shape, classification, oversized, consistency, determinism, and CLI tests pass.

## Appendices

- Harness: `tests/risk-policy/kimi/run-tests.js`
- This file: `tests/risk-policy/kimi/FINDINGS.md`
- Policy: `scripts/risk-policy.json`
- Engine: `scripts/capability-policy.js`
- Heal reference: `scripts/heal.js`
