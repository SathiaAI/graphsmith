# v0.4.0 Lane R2 — side-effect receipt reconciliation — adversarial adjudication

**Target:** `checks/v040-receipts.js` (extends the E profile) · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0 · **Testers (≥2 non-Anthropic):** DeepSeek + Mistral-Large (OpenRouter code-gen). Builder ≠ testers. Orchestrator re-ran both.

**Process note:** the first R2 dispatch used a prompt that had inherited R1's *capability* attack list (my error) — those suites tested the wrong module and were discarded. Re-dispatched with a receipts-specific prompt.

## Real defect found + fixed
- **Forged-success protection (the key attack) — verified holds.** Both families confirmed a `success` receipt with no valid `external_id` cannot reconcile. During hardening I confirmed and kept the rule: `success` reconciles ONLY with a present, non-empty **string** `external_id`; anything else routes to `UNKNOWN_EFFECT`. (One intermediate over-fix — failing on a non-string `external_id` — was reverted; see below.)

## The invalid-`external_id` design decision (adjudicated)
The two families **disagree, and are each internally inconsistent**, on the *non-passing outcome* for a `success` receipt whose `external_id` is present but not a valid string:
- DeepSeek `1.3` (null) → expects `unavailable`; `1.4` (number `123`) → `unavailable`; `6.5` (BigInt) → **`failed`**.
- Mistral `null` → expects `unavailable`; non-string `123` → **`failed`**.

**Decision (stood on):** an invalid `external_id` *value* (absent / null / number / BigInt / empty) is **not valid external evidence**, so the effect is `UNKNOWN` → **`unavailable` (reconciliation-required)** — never `failed`. Rationale: the effect *may have succeeded*; we simply cannot confirm it, so "reconciliation-required" is honest and "failed" would be a false claim that it failed. Only a structurally malformed *receipt* (bad `schema_version`, missing `action`/`adapter_id`, `status` not in enum) is `failed`. This rule is consistent across all value types.

Under this rule, DeepSeek `6.5` (BigInt→failed) and Mistral non-string (123→failed) are **adjudicated** as preference-differences, not defects. **The security-critical property is unaffected:** a forged, evidence-less "success" **never reaches `verified`** — both families confirm it (they land on `unavailable`/`failed`, never `verified`).

## Verdict
**Lane R2 TEST-PASSED.** DeepSeek 22/23, Mistral 20/21; both remaining are the adjudicated `unavailable`-vs-`failed` preference for an invalid `external_id`. Properties under executed attack: a forged evidence-less success cannot upgrade an effect (never `verified`); no receipt / `unknown` → reconciliation-required (fail-closed); a failed effect → `failed`; a structurally malformed receipt → `failed`; identity/`ts` is not a decision input (C1); malformed ctx never throws (C2). Honest boundary in copy: run-once/replay-verified of recorded effects, **not** end-to-end single-delivery — the literal banned bigram is absent from the code. Pure decision path.
