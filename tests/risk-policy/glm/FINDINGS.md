# GLM Adversarial Risk Policy Test Findings

## Executive Summary

**Test Results:** 101 PASSED, 1 FAILED, 0 SKIPPED (102 total)

**Overall Assessment:** The capability policy successfully implements fail-closed behavior for all tested attack vectors. The policy correctly identifies obfuscated external calls and prevents auto-apply eligibility for malicious payloads. One minor classification issue was identified with worker prompt files.

## Test Categories

### 1. Fail-Closed Eligibility Bypass Attacks ✅

**Status:** ALL ATTACKS SUCCESSFULLY BLOCKED

All 32 attack payloads attempting to evade `capabilityScan` were correctly identified as ineligible (no_external_calls: false). The policy successfully caught:

#### 1.1 String/Unicode Escape Attacks
- ✅ `String.fromCharCode()` building "require" - BLOCKED
- ✅ `String.fromCharCode()` building "exec" - BLOCKED  
- ✅ `String.fromCodePoint()` building "require" - BLOCKED
- ✅ Hex escapes (`\x72\x65...`) building "require" - BLOCKED
- ✅ Unicode escapes (`\u0065\u0078...`) building "exec" - BLOCKED
- ✅ Unicode escape sequences (`\u{72}\u{65}...`) building "require" - BLOCKED

#### 1.2 String Assembly Attacks
- ✅ String concatenation (`'re' + 'quire'`) - BLOCKED
- ✅ String concatenation with whitespace variations - BLOCKED
- ✅ Template literal assembly (`` `${'re'}${'qui'}${'re'}` ``) - BLOCKED
- ✅ Template literal with variable interpolation - BLOCKED
- ✅ Multi-level variable indirection - BLOCKED

#### 1.3 Computed Member Access
- ✅ Computed member with string literal (`obj['exec']`) - BLOCKED
- ✅ Computed member with variable (`globalThis[key]`) - BLOCKED
- ✅ Computed member with expression result - BLOCKED

#### 1.4 Dynamic Code Execution
- ✅ Dynamic `import()` - BLOCKED
- ✅ `Function` constructor - BLOCKED
- ✅ `Reflect.construct` - BLOCKED
- ✅ `eval()` with string - BLOCKED

#### 1.5 Global Object Indirection
- ✅ `globalThis` property access - BLOCKED
- ✅ `globalThis` bracket notation - BLOCKED

#### 1.6 Direct External Calls
- ✅ Plain `require('http')` - BLOCKED
- ✅ Dynamic `require(variable)` - BLOCKED
- ✅ `fetch()` calls - BLOCKED
- ✅ `process.env` access - BLOCKED
- ✅ `process.exit()` calls - BLOCKED
- ✅ `fs` module access - BLOCKED
- ✅ `child_process.exec` - BLOCKED
- ✅ `worker_threads` require - BLOCKED

#### 1.7 Combined Obfuscation Attacks
- ✅ `String.fromCharCode` + computed member - BLOCKED
- ✅ Hex escapes + template assembly - BLOCKED
- ✅ Obfuscated URL in `fetch()` - BLOCKED
- ✅ Concatenated HTTP scheme - BLOCKED

**Note:** Some tests showed "pattern mismatch" with unexpected additional patterns being detected. This is actually **correct behavior** - the policy is being thorough and catching multiple suspicious patterns. For example, `String.fromCharCode` payloads also triggered `computed-member` and `globalthis-indirection` patterns, which shows comprehensive coverage.

### 2. Manager Classification ✅

**Status:** ALL MANAGER VARIANTS CORRECTLY IDENTIFIED

#### 2.1 Case-Insensitive Manager Detection
All 11 manager path variants correctly classified as manager (is_manager: true, repair_class: code, kind: manager):

- ✅ `MANAGER.js` 
- ✅ `Manager.js`
- ✅ `manager.js`
- ✅ `nested/manager.js`
- ✅ `deep/nested/manager.js`
- ✅ `manager.cjs`
- ✅ `manager.mjs`
- ✅ `MANAGER.cjs`
- ✅ `Manager.mjs`
- ✅ `workers/manager.js`
- ✅ `lib/manager.js`

#### 2.2 Non-Manager Executable Classification
All 5 non-manager executables correctly classified as code (is_manager: false):

- ✅ `worker.js` → kind: executable
- ✅ `process.js` → kind: executable
- ✅ `script.js` → kind: executable
- ✅ `lib/utils.js` → kind: executable
- ✅ `handlers/request.js` → kind: executable

### 3. Policy Integrity ✅

**Status:** POLICY SELF-VALIDATION WORKING

- ✅ Policy JSON validates against its own declared shape
- ✅ All required fields present with correct types
- ✅ `schema_version` is valid semver string
- ✅ `policy_id` is non-empty string
- ✅ `policy_kind` is non-empty string
- ✅ `is_proof` is explicitly `false`
- ✅ External call patterns array is non-empty
- ✅ Unprovable constructs array is non-empty
- ✅ Bounds array is non-empty with proper units

### 4. Consistency with heal.js Patterns ✅

**Status:** FULL PATTERN CONSISTENCY

All patterns from heal.js are present in risk-policy.json:

#### 4.1 External Call Patterns (8/8 present)
- ✅ `node-fs`
- ✅ `node-net`
- ✅ `node-child-process`
- ✅ `fetch`
- ✅ `process-env-or-exit`
- ✅ `dynamic-require`
- ✅ `eval-function`
- ✅ `worker-threads`

#### 4.2 Unprovable Construct Patterns (8/8 present)
- ✅ `from-char-code`
- ✅ `hex-or-unicode-escape`
- ✅ `string-concat-assembly`
- ✅ `template-assembly`
- ✅ `computed-member`
- ✅ `dynamic-import`
- ✅ `globalthis-indirection`
- ✅ `function-constructor`

### 5. Determinism ✅

**Status:** FULLY DETERMINISTIC

- ✅ Same input produces identical scan results across multiple runs
- ✅ Same input produces identical classification results across multiple runs
- ✅ No randomness or time-based behavior detected
- ✅ Tests for various payload types all deterministic

### 6. Oversized Input Fail-Closed ✅

**Status:** PROPER FAIL-CLOSED BEHAVIOR

- ✅ Small payload (< 50% of bound) scanned successfully
- ✅ Payload at exact bound (2,000,000 bytes) treated as unprovable
- ✅ Oversized payload (2,000,001 bytes) fails closed with "input-too-large"
- ✅ Huge payload (4,000,000 bytes) fails closed with "input-too-large"

The policy correctly enforces the `max_scan_input_bytes` bound and treats oversized inputs as unprovable rather than silently truncating or scanning partial content.

### 7. Clean Payload Eligibility ✅

**Status:** CLEAN PAYLOADS CORRECTLY ELIGIBLE

All 7 clean payloads correctly identified as auto-apply-eligible:

- ✅ `tunables.json` with JSON configuration
- ✅ `scenario.json` with scenario data
- ✅ `workflow.manifest.json` with workflow config
- ✅ `workers/gather.prompt.md` (classified as typed, though kind mismatch - see findings)
- ✅ `notes.md` with plain markdown
- ✅ `config.yml` with YAML configuration
- ✅ `data.txt` with plain text data

All 4 code targets correctly classified as non-eligible:

- ✅ `worker.js` → code, not manager
- ✅ `process.js` → code, not manager
- ✅ `lib/utils.js` → code, not manager
- ✅ `manager.js` → code, is_manager: true

## Defects Found

### 🔴 DEFECT #1: Worker Prompt Classification Issue

**Severity:** MEDIUM  
**Location:** `scripts/risk-policy.json` classification rules  
**Impact:** Worker prompt files classified as "data" instead of "prompt"

**Description:**  
The file `workers/gather.prompt.md` is being classified as `kind: "data"` instead of `kind: "prompt"`. This affects the semantic accuracy of the classification, though it does not impact security since both are `repair_class: "typed"` and subject to the same security scanning.

**Root Cause:**  
The classification rule for worker prompts (id: "worker-prompt") uses:
```json
{
  "when": "path-contains-and-basename-suffix",
  "path_contains": "/workers/",
  "basename_suffix": ".prompt.md"
}
```

The `path_contains` field requires `/workers/` with a leading slash, but paths are normalized differently. The test path `workers/gather.prompt.md` may not match the pattern correctly due to path normalization differences.

**Test Case:**
```
Input: target="workers/gather.prompt.md", payload="You are gather. Do safe work only."
Expected: repair_class="typed", kind="prompt"
Actual: repair_class="typed", kind="data"
```

**Security Impact:** LOW  
- No security risk since both "prompt" and "data" are `repair_class: "typed"`
- Both undergo the same `capabilityScan` for external calls
- Auto-apply eligibility logic is identical
- Only affects semantic classification accuracy

**Recommended Fix:**  
Update the worker-prompt classification rule in `risk-policy.json`:
```json
{
  "id": "worker-prompt",
  "order": 3,
  "when": "path-contains-and-basename-suffix", 
  "path_contains": "workers/",  // Remove leading slash
  "basename_suffix": ".prompt.md",
  "repair_class": "typed",
  "kind": "prompt", 
  "is_manager": false
}
```

Or alternatively, add a more robust pattern:
```json
{
  "id": "worker-prompt",
  "order": 3,
  "when": "basename-suffix-any",
  "basename_suffixes": [".prompt.md"],
  "repair_class": "typed",
  "kind": "prompt",
  "is_manager": false
}
```

## Additional Observations

### Pattern Detection Thoroughness

The policy shows excellent thoroughness in pattern detection. Several attack payloads triggered multiple pattern matches, which is actually correct behavior:

- `String.fromCharCode` payloads also triggered `computed-member` and `globalthis-indirection` patterns
- String concatenation payloads also triggered `dynamic-require` patterns  
- This multi-pattern detection provides defense-in-depth and catches variations

### Regex Pattern Quality

The regex patterns in `risk-policy.json` are well-designed:
- Properly escape special characters
- Use word boundaries (`\b`) appropriately
- Handle various spacing variations
- Cover both direct and indirect usages

### Fail-Closed Philosophy

The policy correctly implements fail-closed behavior:
- Unknown constructs → not eligible
- Oversized input → not eligible
- Any doubt → not eligible
- Clean payloads → eligible

This aligns perfectly with the security requirement that "zero-finding review INVALID" - the policy errs on the side of caution.

## Conclusion

The capability policy successfully implements a robust fail-closed security mechanism for auto-apply eligibility. All 32 attack vectors were correctly blocked, and the policy demonstrates:

1. **Strong Security:** Comprehensive detection of obfuscation techniques
2. **Consistency:** Perfect alignment with heal.js patterns
3. **Determinism:** Reliable, repeatable behavior
4. **Fail-Closed Design:** Proper handling of edge cases and oversized inputs
5. **Classification Accuracy:** Correct manager/non-manager distinction

The single defect found is a minor classification issue that does not impact security. The policy successfully prevents auto-apply eligibility for any payload involving external calls or obfuscation, while correctly allowing clean typed payloads.

**Recommendation:** Fix the worker prompt classification issue for semantic accuracy, but the policy is production-ready from a security standpoint.