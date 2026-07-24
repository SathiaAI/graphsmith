# Lane D (air-gapped verification) — adversarial adjudication

**Target:** `checks/register-airgap.js` · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0
**Testers (≥2 non-Anthropic, security-tier):** Codex/GPT (OpenAI) · DeepSeek (via OpenRouter) — builder family ≠ tester families. Orchestrator (claude-opus) re-ran every suite; verdicts below are from executed runs, not transcripts.

## Tester #1 — Codex (OpenAI), `tests/register/airgap/codex/run-tests.js`
Authored + (orchestrator-)executed a 28-test suite. **Found 9 real defects** (a valid, non-zero-finding review):
1–2. **Algorithm confusion (HIGH)** — declared `ecdsa`/`rsa-pss` accepted an RSA/EC key+sig because `crypto.verify` auto-detects from the key. **Fixed:** declared algo must now match `keyObj.asymmetricKeyType`.
3. **Prototype-polluted `files` map faked matches-disk (MEDIUM).** **Fixed:** own-property (`hasOwnProperty`) lookup.
4–5. **Extra / inherited signature fields accepted (MEDIUM).** **Fixed:** strict own-key allowlist (`strictSigShape`).
6–9. **Crashes** on BigInt / circular / hostile getter / proxy `ownKeys` (MEDIUM). **Fixed:** outer try/catch → fail closed.
Post-fix: **28/28 PASS.**

## Tester #2 — DeepSeek (via OpenRouter), `tests/register/airgap/deepseek/run-tests.js`
Independently authored + (orchestrator-)executed a 19-test suite against the fixed module: **18/19 PASS.**

The one "FAIL" — `inherited signature fields rejected` — is **adjudicated NOT a defect** (two-sided validation gate: verify the finding against the code):
- The test builds a signature with all 6 **own** fields (via `Object.assign`) plus an **inherited** `inherited:"field"` on its prototype, and expects `failed`.
- Per JSON Schema semantics, `additionalProperties:false` constrains an instance's **own** properties; an inherited property is not an instance property, is invisible to `JSON.stringify`, and is never read by the module (`Object.keys` / explicit field access are own-only).
- The signature still cryptographically verifies over the correct manifest hash by a trusted key, so **`verified` is the correct verdict**. Rejecting it would false-negative genuinely valid signatures.
- The real inherited-object attack (`Object.create(realSig)`, making the required fields non-own) IS defended — Codex's equivalent test passes (own-property required).

## Verdict
**Lane D TEST-PASSED.** Two non-Anthropic families; tester #1 produced 9 genuine findings (all fixed, re-verified 28/28); tester #2 confirmed the fixes with 18/19, its lone miss adjudicated as an over-strict test expectation, not a vulnerability. Module is a pure decision path (no network/clock/random), fail-closed.
