# Badge cross-family test — orchestrator adjudication

- **Component:** `scripts/badge.js` (builder: Claude/Sonnet)
- **Tester:** Grok-4.5 (x-ai, non-Anthropic ≠ builder) — `tests/badge/grok/tests.js`, a 646-check adversarial suite (run post-harness-fix; opencode restored)
- **Adjudicator:** orchestrator (direct probe against the live module + JSON-stringified assertion inspection)

## Outcome: badge verified CORRECT. 2 real findings fixed; 9 residual "fails" are tester-assertion bugs.

### Real findings the suite surfaced (both fixed, orch-verified)
1. **validateCiUrl too permissive** — bare `http://` / `https://` (no host) and control-char URLs (null/newline) were emitted as a live `<a xlink:href>`. FIXED (commit hardening): validateCiUrl now rejects empty-authority and any 0x00–0x1F/0x7F char (checked on the RAW url before neutralization); still links well-formed http(s) to ANY host/port (a badge cannot allowlist CI hosts — that is not a defect).
2. **validateCiUrl not exported** — spec listed it as an export; it wasn't. FIXED: now in module.exports.
Result after fix: selftest 103/103; direct probe confirms bare-scheme + null + newline → NOT linked, valid https any-host → linked, hostile schemes (javascript:/data:/vbscript:/file:/…) → blocked, poisoned fields escaped to inert `&lt;…&gt;`, href ampersands `&amp;`-escaped. NO live XSS.

### 9 residual fails — all TESTER-AUTHORED-WRONG assertions (badge behavior is correct)
Proven by JSON-stringifying each assertion and comparing to the live module output:

| tester line | asserts | badge actual | verdict |
|---|---|---|---|
| 326 | `xmlEscape('<script>') === '<script>'` (expects NO escaping) | `&lt;script&gt;` (correct) | tester-bug: expecting an un-escaped result would be the vulnerability |
| 329 | `xmlEscape('a&b') === 'a&b'` (expects raw &) | `a&amp;b` (correct) | tester-bug: unescaped & is invalid XML |
| 331 | `!safeOut.includes('<') && ... && safeOut.includes('<')` | `&lt;x onerror=&quot;y&quot;&gt;` | tester-bug: self-contradictory (`!includes('<') && includes('<')` can never be true) |
| 299/300 | `!svg.includes('onerror=')` | onerror appears only inside escaped-inert `&lt;…&gt;` text | tester-bug: substring match flags inert escaped text; no live handler exists |
| 426 | `validateCiUrl('https://evil.example/') === false` | `true` | tester-bug (over-strict): a valid https URL to any host is legitimately linkable |
| (loop) | `https://evil.example/` "not linkable" / "no `<a>`" | linked (valid https) | tester-bug (over-strict): same as 426 |
| 471 | `sAmp.includes('&b=2')` (expects raw &) | href has `&amp;b=2` (correct) | tester-bug: expects an unescaped ampersand in the href |
| 487 | `svg.includes('<script>') \|\| svg.includes('<script')` (expects RAW `<script` present) | escaped to `&lt;script` (correct) | tester-bug: inverted — correct escaping removes the raw tag it checks for |

### Basis for TEST-PASSED
`badge.js` accepted on: (a) its own selftest 103/103 (extended with all hardening cases — the CI regression guard); (b) orchestrator exhaustive direct verification of every guarantee; (c) Grok cross-family adversarial pass — 637 valid checks + the 2 real findings it surfaced (now fixed). The 9 residual fails are documented tester-assertion bugs, not badge defects (the suite is retained as raw cross-family evidence; the badge's own `--selftest` is the regression guard, not this suite).

Note: the tester's own narrated report was lost (its opencode process was killed mid-run by an orchestrator `oc-flush --force` — a self-inflicted slip, logged; the suite file had already been written, so results were recovered by orchestrator re-run).
