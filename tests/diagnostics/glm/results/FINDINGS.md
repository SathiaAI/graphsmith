# GraphSmith Diagnostics Export - GLM Adversarial Test Findings

**Test Date:** 2026-07-23T06:26:21.289Z
**Security Tier:** I4 - 'GraphSmith sends nothing upstream, ever'
**Test Suite:** GLM family adversarial tests

## Executive Summary

- **Total Tests:** 52
- **Passed:** 52
- **Failed:** 0
- **Pass Rate:** 100.0%

## Test Results

### ZERO EGRESS Tests

- **zero-egress-no-network-modules-in-source**: PASS - No network modules found
- **zero-egress-no-socket-apis-in-source**: PASS - No socket APIs found
- **zero-egress-no-child-process-require**: PASS - No child_process require found
- **zero-egress-runtime-no-network-errors**: PASS - Ran successfully without network access
- **zero-egress-runtime-local-write-only**: PASS - Written: true, Exists: true

### REDACTION F16 Tests

- **redaction-f16-all-secrets-redacted**: PASS - All secrets redacted
- **redaction-f16-redacted-marker-present**: PASS - Redaction marker found
- **redaction-f16-api_keys-redacted**: PASS - api_keys properly redacted
- **redaction-f16-bearer_tokens-redacted**: PASS - bearer_tokens properly redacted
- **redaction-f16-passwords-redacted**: PASS - passwords properly redacted
- **redaction-f16-connection_strings-redacted**: PASS - connection_strings properly redacted
- **redaction-f16-pii-redacted**: PASS - pii properly redacted
- **redaction-f16-aws_github-redacted**: PASS - aws_github properly redacted

### RAW-PROMPT/EVIDENCE-MAP EXCLUSION Tests

- **exclusion-raw-prompts-not-in-export**: PASS - No raw prompts leaked
- **exclusion-evidence-real-values-not-in-export**: PASS - No evidence real values leaked
- **exclusion-scope-declares-no-raw-prompts**: PASS - raw_prompts_included: false
- **exclusion-scope-declares-no-evidence-real-values**: PASS - evidence_map_real_values_included: false

### CONSENT GATE Tests

- **consent-gate-no-write-without-yes**: PASS - Written: false, Exists: false
- **consent-gate-preview-available-without-write**: PASS - Preview length: 2394
- **consent-gate-public-tracker-warning-present**: PASS - Public tracker warning check
- **consent-gate-preview-matches-written-file**: PASS - Preview bytes == written bytes
- **consent-gate-preview-shown-before-write**: PASS - Preview index: 3, Written index: 4

### FAIL-CLOSED Tests

- **fail-closed-corrupt-json-window-no-crash**: PASS - Ran without crashing
- **fail-closed-corrupt-json-window-valid-json-output**: PASS - Produced valid JSON
- **fail-closed-corrupt-json-window-no-partial-leak**: PASS - No malformed content leaked
- **fail-closed-corrupt-jsonl-registry-no-crash**: PASS - Ran without crashing
- **fail-closed-corrupt-jsonl-registry-valid-json-output**: PASS - Produced valid JSON
- **fail-closed-corrupt-jsonl-registry-no-partial-leak**: PASS - No malformed content leaked
- **fail-closed-missing-required-files-no-crash**: PASS - Ran without crashing
- **fail-closed-missing-required-files-valid-json-output**: PASS - Produced valid JSON
- **fail-closed-missing-required-files-no-partial-leak**: PASS - No malformed content leaked
- **fail-closed-empty-json-files-no-crash**: PASS - Ran without crashing
- **fail-closed-empty-json-files-valid-json-output**: PASS - Produced valid JSON
- **fail-closed-empty-json-files-no-partial-leak**: PASS - No malformed content leaked
- **fail-closed-malformed-event-records-no-crash**: PASS - Ran without crashing
- **fail-closed-malformed-event-records-valid-json-output**: PASS - Produced valid JSON
- **fail-closed-malformed-event-records-no-partial-leak**: PASS - No malformed content leaked
- **fail-closed-mixed-valid-invalid-records-no-crash**: PASS - Ran without crashing
- **fail-closed-mixed-valid-invalid-records-valid-json-output**: PASS - Produced valid JSON
- **fail-closed-mixed-valid-invalid-records-no-partial-leak**: PASS - No malformed content leaked

### Edge Cases Tests

- **edge-case-empty-project-no-crash**: PASS - Empty project handled
- **edge-case-empty-project-valid-report**: PASS - Basic report structure intact
- **edge-case-long-string-no-crash**: PASS - Long string handled
- **edge-case-long-string-redacted**: PASS - Long string properly redacted

### Integration Tests

- **migrate-integration-redaction-applied**: PASS - Redaction applied via migrate.js
- **cli-selftest-runs**: PASS - Selftest status: pass
- **cli-selftest-has-tests**: PASS - Test count: 19
- **cli-export-no-write-without-yes**: PASS - File exists: false
- **cli-export-preview-in-output**: PASS - Preview shown in CLI output
- **cli-export-write-with-yes**: PASS - File exists: true
- **cli-export-public-tracker-warning**: PASS - Public tracker warning present
- **cli-export-written-message**: PASS - Written confirmation present

## Detailed Findings

No security issues found.

## Security Assessment

### ZERO EGRESS (I4 Requirement)
✅ PASS - No network/upload code detected in source or runtime

### REDACTION F16
✅ PASS - All secrets properly redacted with [REDACTED] marker

### RAW-PROMPT/EVIDENCE-MAP EXCLUSION
✅ PASS - Raw prompts and evidence-map values excluded from export

### CONSENT GATE
✅ PASS - No write without --yes, preview shown first, warning present

### FAIL-CLOSED BEHAVIOR
✅ PASS - Corrupt state handled gracefully, no crashes or partial leaks

## Overall Verdict

## ✅ SECURITY VERIFIED

All I4 security requirements met. GraphSmith diagnostics export is safe for local-only use.

---

**Test Runner:** GLM adversarial tester
**Target:** scripts/diagnostics.js
**Test Root:** F:\Users\PaulPoulose\GraphSmith\graphsmith\tests\diagnostics\glm\temp-projects
**Results Directory:** F:\Users\PaulPoulose\GraphSmith\graphsmith\tests\diagnostics\glm\results
