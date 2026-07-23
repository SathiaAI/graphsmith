# Lane B (obligations→controls reconciler — the make-or-break) — adversarial adjudication

**Target:** `checks/register-obligations.js` · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0
**Testers (≥2 non-Anthropic, security-tier):** DeepSeek + Qwen (both via OpenRouter code-gen — each AUTHORED a runnable suite; orchestrator re-ran both). Codex/GPT was blocked by OpenAI's cyber-filter on this lane, so both testers came via the code-gen route. Builder family ≠ tester families.

## Findings (from executed suites, both families)
1. **Crash instead of fail-closed (MEDIUM) — REAL, fixed.** The reconciler threw on hostile getters, proxy `ownKeys`, BigInt, and wrong-typed input instead of returning a status. **Fixed:** outer try/catch → fail closed (matches Lane D's hardening). Qwen 8→10 after this fix.
2. **Invalid `coverage` value silently coerced (HIGH) — REAL, fixed.** An obligation with a non-enum `coverage` (BigInt, number) was coerced to `null` and processed as manual-only instead of being refused. Both families flagged it. **Fixed:** a present-but-invalid `coverage` is now a HIGH violation → `status: failed`, never coerced (fail-closed corruption discipline). Qwen → **12/12**, DeepSeek → **14/15**.

## Adjudicated NOT a defect (two-sided validation gate)
- **DeepSeek `proto pollution` (DeepSeek 15th test).** It builds a **valid manual-only obligation** — own `controls:[]`, `coverage:"manual-only"`, a stated `human_judgment:"test"` — with an inert `__proto__:{polluted:true}`, and asserts it must NOT verify. But a manual-only obligation with a stated human judgment is a **legitimately resolved** state (that is the honest-coverage design: manual-only obligations are declared, not hidden), so `verified` is correct. The `__proto__` is inert — none of the reconciler's field reads (`controls`, `coverage`, `evidence_artifact`, `evidence_vs_judgment`) resolve to the polluted prototype for this input. Real-world registers are `JSON.parse`d (which does not mutate prototypes); in-process `Object.prototype` pollution requires code execution (attacker class A1/A6, out of scope). The test asserts incorrect behavior; not a defect.

## Verdict
**Lane B TEST-PASSED.** Two non-Anthropic families, genuine findings (crash-class + invalid-coverage coercion, both fixed and re-verified), one adjudicated false-positive. The core make-or-break properties hold under executed attack: manual-only can never be marked covered; declared coverage is never trusted (recomputed from evidence); regulated mode activates only on a complete, clean register; corruption fails closed. Pure decision path (no network/clock/random).
