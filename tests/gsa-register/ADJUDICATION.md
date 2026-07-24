# Wave 2 — regulated-mode activation guard (register→GSA integration) — adversarial adjudication

**Target:** `scripts/gsa-register.js` — the PB-8 fail-closed heart: regulated mode activates ONLY when every activation precondition holds against a complete, valid register (composing the four TEST-PASSED lanes).
**Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0 · **Testers (≥2 non-Anthropic):** DeepSeek + Mistral-Large (OpenRouter code-gen), each given a valid-register scaffold to break. Builder ≠ testers. Orchestrator re-ran both suites **and ran an independent pollution probe**.

## Real defect found + fixed
- **Hostile input threw instead of failing closed (MEDIUM).** A `inputs` object with a throwing getter (`get obligations(){ throw }`) propagated the exception out of `activateRegulatedMode` instead of denying. **Fixed:** `evaluateRegister` now catches any hostile-input exception and returns all preconditions false → the guard denies (fail-closed), reason contains no "throw". DeepSeek `hostile-getters` → PASS after fix.

## Adjudicated NOT defects (two-sided validation gate + orchestrator probe)
Both families' single remaining failure is **proto-pollution "unexpected activation"**, adjudicated as a false-positive:
- DeepSeek sets `inputs.__proto__ = { activated: true }`; Mistral sets `inputs.__proto__.polluted = true` (global `Object.prototype.polluted`). Both then activate a **valid** register (a clone of the good scaffold) and expect `activated:false`.
- But a valid register **should** activate, and the guard never reads `inputs.activated` / `.polluted` — the pollution is inert. Denying here would reject valid registers.
- **The real attack — can pollution flip a precondition on an *invalid* register? — is defended.** Orchestrator probe: with `Object.prototype` polluted on all five precondition names + `status` + `regulated_mode_may_activate` + `activated`, an empty/invalid register still returns `activated:false` with all 5 preconditions unmet. The guard and lanes use own-property reads throughout (hardened in the lane adjudications), so inherited/polluted properties cannot satisfy a precondition.

## Verdict
**Wave-2 regulated-mode activation guard TEST-PASSED.** DeepSeek 20/21, Mistral 22/23 (each 1 adjudicated proto-pollution false-positive, independently disproven by the pollution probe). The fail-closed heart holds under executed attack: regulated mode activates only on a complete, valid register; it denies on obligations over-claim, manual-only-marked-covered, a single/conflicted approver, a broken retention chain, a corrupt release signature, a relaxed (`fail_closed:false`) policy, an empty/unknown precondition set, a missing lane, and hostile/malformed input. No path activates without all preconditions genuinely met. Identity/timestamps are evidence, never decision inputs (C1).
