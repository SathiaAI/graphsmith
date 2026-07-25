# v0.4.0 Lane R1 — per-skill capability conformance — adversarial adjudication

**Target:** `checks/v040-caps.js` (D1 enforced-only capability attestation) · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0 · **Testers (≥2 non-Anthropic):** DeepSeek + Mistral-Large (OpenRouter code-gen). Builder ≠ testers. Orchestrator re-ran both suites.

## Real defects found + fixed
1. **Path-prefix confusion (HIGH).** Filesystem containment used `startsWith`, so `/inputs-evil` passed a grant of `/inputs`. **Fixed** (pre-emptively, flagged in the tester prompt): canonical paths only — reject any `.`/`..` segment; containment is exact-match or strictly under `grant + "/"`. DeepSeek's `/inputs/.` case confirmed the canonical-segment rule.
2. **Wrong-typed `attested` coerced (MEDIUM).** A present-but-non-boolean `attested[cls]` was silently treated as "not claimed" instead of failing closed. **Fixed** (Mistral): a malformed attestation now fails closed (C2). `attested` is a capability *claim* (decision-relevant), so validating it does not implicate C1.
3. **`reason` not exposed (LOW/API).** Both suites read a top-level `result.reason`; the output only carried it inside `evidence`. **Fixed:** `reason` surfaced top-level (harmless superset of the report contract).

## The C1 conflict (resolved in favour of the binding rule)
The two families **disagreed** on `skill_id`, and the disagreement is the finding:
- **Mistral `malformed-bigint`** set `grant.skill_id = 123n` and expected `failed` — i.e. wanted the verdict to depend on `skill_id`.
- **DeepSeek `C1 skill_id null / 123`** expected the verdict to be **invariant** to `skill_id` — i.e. identity must NOT be a decision input.

I briefly added `skill_id` structural validation to satisfy Mistral; DeepSeek's C1 test immediately failed, correctly flagging that **gating the verdict on `skill_id` (identity) violates C1** ("identity is evidence, never a decision input"). **Reverted.** Per the binding C1 discipline, DeepSeek is right: the capability verdict is invariant to `skill_id`. Mistral's `malformed-bigint` is therefore an **adjudicated C1-violating expectation**, not a defect.

## Other adjudicated NOT a defect
- **DeepSeek `allowlist network`** builds the network grant as `{allowed:[…]}`, but the schema key for network is `destinations`. Its data lands in the wrong key, so nothing is actually requested/granted via `destinations` and the bundle correctly verifies. Test-construction error, not a fail-open.

## Verdict
**Lane R1 TEST-PASSED.** Two non-Anthropic families; real fixes (path confusion, attested coercion, reason API) re-verified; DeepSeek 29/30, Mistral 29/30 with two adjudicated (one test-bug, one C1-violating expectation). The **D1 honesty line holds under executed attack**: a class is attested satisfied only if enforced AND `requested ⊆ granted`; escalation halts; an unenforced-but-attested boundary is refused; the verdict is invariant to identity (C1); malformed capability claims fail closed (C2). Pure decision path.
