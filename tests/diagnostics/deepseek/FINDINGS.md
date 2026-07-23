# FINDINGS.md -- deepseek family adversarial test of `scripts/diagnostics.js`

## Suite summary
**run-tests.js** -- 25 attack test cases across all 5 I4 guarantees. **25 PASS, 0 FAIL, 0 SKIPPED.** Verdicts from actual written file bytes + source scan. All state in `os.tmpdir()` subdirectories (pattern `gs-diag-ds-*`).

## Guarantee-by-guarantee results

### G1: ZERO EGRESS -- diagnostics.js contains NO network/upload code

| # | Test | Verdict |
|---|---|---|
| 1 | Source scan: regex for `require('http/https/net/dns/tls/child_process')` and `fetch(` in diagnostics.js source text | PASS -- zero disallowed requires, zero fetch() calls |
| 15 | Built-in selftest via `require()`: selftest internally proves source-self-scan + network-API check | PASS -- selftest status=pass, exitCode=0 |
| 25 | CLI `--selftest`: produces JSON with status=pass, exits 0 | PASS |

### G2: F16 REDACTION -- planted secrets of many shapes, NONE survive into export

| # | Test | Verdict (from written file bytes) |
|---|---|---|
| 2 | **15 secret categories planted simultaneously** across all string fields of events-proposer.jsonl (run_ref, step_ref, evidence_ref, fingerprint, counters) + package.json (name, version). Exported via CLI with --yes --include-detail. Categories: sk-/pk- opaque prefix, github token, AWS key, JWT, MongoDB connection string, email, credit card, password, api_key, Bearer token, client_secret, generic token, PEM private key, private IP | PASS -- zero secrets survive; [REDACTED] markers present throughout |
| 16 | Package.json secrets: `ghp_...` github token in `name`, `api_key=sk-...` in `version` | PASS -- both redacted to [REDACTED] |
| 17 | Nested secrets: `sk-...` in deeply nested counter object string value, `Bearer:` JWT in array element inside counter | PASS -- all nested string values reach [REDACTED] via recursive redactEvidenceRecord |
| 23 | Adversarial value-field placement: AWS key in `evidence_ref`, sk-opaque-prefix in `step_ref`, JWT in rollback `fingerprint` | PASS -- all value-field secrets redacted |
| 24 | KNOWN-LIM: `code` value used as aggregate object KEY in `by_type.*.by_code` -- keys are NOT redacted (redactEvidenceRecord only processes VALUES). However, the same code as a VALUE in detail events IS redacted. Contract 07 guarantees codes are closed enums. | PASS -- documented limitation, detail-event value redaction confirmed |

### G3: RAW-PROMPT / EVIDENCE-MAP EXCLUSION

| # | Test | Verdict |
|---|---|---|
| 3 | Two `.md` raw prompt files planted in `.graphsmith/evolvable/active/` with unique canaries; export with --include-detail --yes | PASS -- canaries + prompt body ("SYSTEM:", "SECRET_INSTRUCTION", "ANOTHER RAW PROMPT") all absent; scope.raw_prompts_included=false |
| 4 | `events-evidence.jsonl` with 3 entries containing `real_value` fields with embedded secrets/API keys | PASS -- `real-run-001`, `real-step-idx-002`, `real-ev-ref-003`, `evidence_map_entry`, `sk-EVIDENCE_SECRET` all absent |
| 12 | Aggregate-only mode: verify zero raw event field names (`seq`, `step_ref`, `run_ref`) reach export bytes | PASS -- aggregate counters only |
| 20 | Scope declarations verification | PASS -- all 4 flags correct: raw_prompts_included=false, learned_rule_bodies_included=false, evidence_map_real_values_included=false, secrets_included=false, redaction_applied=true |

### G4: CONSENT GATE -- preview + warning + consent = write

| # | Test | Verdict |
|---|---|---|
| 5 | CLI without --yes: exit 0, NO file on disk, preview + "Not written" + "--yes" instruction in stdout | PASS |
| 6 | require() API without `confirmWrite`: returns `{written: false, path: null}`, file absent, previewText returned | PASS |
| 7 | CLI with --yes: PREVIEW appears BEFORE "Written:" in stdout ordering; PUBLIC tracker warning present in output; post-write reminder present | PASS |
| 8 | Byte-exact match: `previewText === writtenFileBytes`; preview logged before write notification | PASS |
| 14 | Default outPath resolves to `.graphsmith/diagnostics/diagnostics-report.json` | PASS |

### G5: no-write-without-consent holds against malformed state

| # | Test | Verdict |
|---|---|---|
| 9 | Corrupt window.json (`NOT_VALID_JSON{{{{broken`): tolerated, preview produced, NO file written, report shows state=NO_WINDOW | PASS |
| 10 | Empty `.graphsmith/state/` directory (zero files): tolerated, NO file written, report has zero counts | PASS |
| 11 | No `.graphsmith/` directory at all: tolerated, NO file written, report shows NO_WINDOW | PASS |

### Additional attacks

| # | Test | Verdict |
|---|---|---|
| 13 | CLI with bogus subcommand: exits 2, prints Usage to stderr | PASS |
| 18 | Detail mode safety: event detail fields carry clean aliases/closures (not raw secrets) | PASS |
| 19 | Aggregate counters correctness: run_registry (3+2+1+1), alpha (2+1), rejected (3), rollback (2 recorded, 1 unack), events-by-type (1+2+1+1+1), compiler-stats (5/1/2/0/3/4/1) -- all exact | PASS |
| 21 | Report metadata: schema_version=1.0, report_type, generated_at ISO, platform (node/os), component_versions, verifier_profile.checked=false | PASS |
| 22 | Two exports of same state produce identical redacted output (minus generated_at timestamp) | PASS |

## Secret categories tested (matching migrate.js SECRET_PATTERNS)

| Pattern name | Example planted | Where planted |
|---|---|---|
| opaque-secret-prefix | `sk-A1b2C3d4E5f6G7h8I9j0K1l2` | run_ref, step_ref, counter.nested, package.json |
| opaque-secret-prefix | `pk_myprefixkeyVALUE9876543210` | counter.detail |
| github-token | `ghp_abcdefghijklmnopqrstuvwx12345678` | step_ref, package.json version |
| aws-key | `AKIA1234567890ABCDXY`, `AKIAZZZZZZZZZZZZZZZZ` | evidence_ref, counter string, rollback fingerprint |
| jwt | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature12345` | fingerprint |
| connection-string | `mongodb://admin:hunter2@192.168.1.100:27017/secrets` | run_ref |
| email | `adversary@evil-corp-test.example.com` | step_ref |
| credit-card | `4111-2222-3333-4444` | counter.name |
| password | `password: SuperS3cret!2024Pass` | evidence_ref |
| api-key | `api_key=sk-PLANTEDapikeyABCDEF1234` | fingerprint |
| bearer-token | `Bearer: eyJtokenRidingBearerHeader12345` | counter.note |
| oauth-secret | `client_secret=C1i3ntOAuthS3cr3t98765` | run_ref |
| generic-token | `token=ABCDEFGHIJKLMNOPQRST12345` | step_ref |
| private-key | `-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----` | evidence_ref |
| private-ip | `10.0.0.99` | fingerprint |

## KNOWN LIMITATION found

**Aggregate `by_code` keys not redacted:** `redactEvidenceRecord` recursively redacts all string VALUES in the report object tree, but does not redact object property NAMES (keys). The `code` field from events-proposer is used as an object key in `event_counters.by_type.<type>.by_code`. In normal operation this is safe because contract 07 guarantees `code` values are closed enums. This is not a vulnerability but a theoretical edge case if a non-enum code value resembling a secret were to reach the events-proposer file.

## Honest coverage statement -- what was NOT tested

| Area | Reason |
|---|---|
| Real network capture (packet sniffing) | Not possible in a JS harness; source scan proves zero network code paths exist |
| Disk-full / I/O error during atomic write | OS-level failure injection not available |
| Unicode homoglyph attacks in secret values | Unicode obfuscation could evade ASCII regex patterns; ASCII-only secrets tested |
| Prototype pollution modifying `require` behavior | System-level attack, outside diagnostics.js scope |
| Timing side-channel: export duration vs secret count | Redaction is O(n) regex replace; timing not measured |
| Binary/garbage state files | Only JSON/JSONL/text fixtures tested |
| Extremely large state (100K+ events) | 5 events tested; scale behavior not profiled |
| Symbol-keyed values in report | redactEvidenceRecord iterates Object.keys(), missing Symbol keys; no code path creates Symbols |

## Test suite structure
```
tests/diagnostics/deepseek/
  run-tests.js    # zero-dep CJS test runner (25 cases)
  FINDINGS.md     # this file
```

## Reproduction
```bash
node tests/diagnostics/deepseek/run-tests.js
```

All state created in `os.tmpdir()` subdirectories (pattern `gs-diag-ds-*`). Nothing written to the repo's `.graphsmith/`. No files outside this lane were modified.