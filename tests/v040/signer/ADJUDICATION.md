# v0.4.0 Lane R3 — signer trust lifecycle + attestation recall — adversarial adjudication

**Target:** `checks/v040-signer.js` · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0 · **Testers (≥2 non-Anthropic):** Mistral-Large + Qwen (OpenRouter code-gen). DeepSeek's dispatch hit an upstream **429 rate-limit** and was substituted by Qwen. Builder ≠ testers. Orchestrator re-ran both.

## Real defects found + fixed
1. **Corrupt registry entry silently skipped (MEDIUM) — Mistral.** A signer entry with a non-string `signer_id` was skipped, and the queried signer then reported `unavailable` instead of the registry being refused. **Fixed:** a structurally malformed entry (bad `signer_id`/`status`) fails closed — the registry is corrupt trust config (C2). Config-shape validation, not identity-routing (no C1 conflict). Mistral → **19/19**.
2. **Duplicate `signer_id` (MEDIUM) — Qwen.** Two entries claiming the same `signer_id` (different keys) is ambiguous trust config; the later entry silently won. **Fixed:** duplicate `signer_id` fails closed (mirrors Lane B's duplicate-obligation_id).

## Adjudicated NOT defects (two-sided validation gate)
Qwen's four remaining `malformed-registry-*` cases each keep a **valid `k1` active** entry and add corruption the verdict must be invariant to:
- **`hostile-getter` / `bigint` on `added_at`.** `added_at` is a C1 **evidence** field — the check deliberately never reads it as a decision input, so a throwing getter or a BigInt there is inert. Reading it would make an evidence field gate the verdict (a C1 violation). Correctly verifies.
- **`proto-pollution`** — an inert `__proto__:{pollute:…}` on an otherwise-valid entry; all read fields are own and valid. Same class as the register/GSA proto-pollution adjudications.
- **`proxy`** — `new Proxy(validSignersArray, {})`, a transparent proxy that `Array.isArray` sees through and that returns the valid entry. Behaves identically to the valid array. Same class as the Lane C retention proxy adjudication.

The security-critical properties are unaffected by all four (the queried signer is genuinely valid; the corruption is inert or on an unread evidence field).

## Verdict
**Lane R3 TEST-PASSED.** Two non-Anthropic families; two real fail-closed fixes (corrupt entry, duplicate id) re-verified. Properties under executed attack: a **revoked** signer and a **recalled** bundle (exact `bundle_id`+`manifest_sha256`) fail closed; an **unknown** signer is `unavailable` (never a silent pass); a **rotation chain** verifies only if it resolves to a live successor (cycle / dangling / rotated-into-revoked fail closed); a corrupt/duplicate registry fails closed; the verdict is invariant to the `added_at`/`recalled_at` evidence fields (C1); malformed input never throws (C2). Pure decision path.
