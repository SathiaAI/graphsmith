# Lane C (evidence retention) — adversarial adjudication

**Target:** `checks/register-retention.js` · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0
**Testers (≥2 non-Anthropic):** Mistral-Large + Qwen (via OpenRouter code-gen). DeepSeek's authored suite was a broken harness (`0/0/6` — tests defined but never invoked) and was discarded rather than repaired, to preserve tester independence. Builder ≠ testers. Orchestrator re-ran both suites. (Qwen's suite has a broken *summary counter* — reports `0/0` — but its per-test `PASS/FAIL` lines are emitted by a discriminating runner, so the 19-PASS/2-FAIL split is valid evidence.)

## Real defect found + fixed
- **Sequence rule too strict — rejected valid rotated/large-counter logs (MEDIUM).** Mistral's `large-seq-number` drove a single genesis entry with `seq = MAX_SAFE_INTEGER`; my walk required `seq === position+1` (contiguous **from 1**), rejecting it. The starting counter value is not security-relevant — tamper-evidence comes from the hash chain + contiguous increments + anchored-head. **Fixed:** `seq` must increment by exactly 1 (gap/reorder still caught), but the first entry's `seq` may be any integer ≥ 1. Mistral → **31/31**; selftest's gap case still fails correctly.

## Adjudicated NOT defects (two-sided validation gate)
Both of Qwen's "failures" wrap a **genuinely valid** 3-entry chain (contiguous seq, hashes chain a→b→c, `anchored_head` matches) and expect `failed`:
- **`proto-pollution`** — entry[0] carries `__proto__:{pollute:"polluted"}` (sets an **inert prototype**, not an own key). All required fields are own; `Object.keys` and `hasOwnProperty` reads never touch the prototype. A valid entry with an unusual prototype correctly verifies; expecting failure would false-negative valid data.
- **`proxy`** — entry[2] is `new Proxy(validEntry, {})`, a **transparent** proxy with an empty handler that faithfully returns the target's values. It behaves identically to the valid entry, so it correctly verifies. (A proxy with *malicious* traps — e.g. TOCTOU — is a different case; this one has none.)

## Coverage confirmed (Qwen, all correctly caught)
gap-in-seq · forge-prev-packet-sha256 · remove-entry · wrong-anchored-head · non-hex expected head · root-with-non-null-prev · invalid-entry-shape · non-hex packet/prev/anchored hashes · missing-fields · hostile-getter (fail-closed, no throw) · BigInt · circular-reference · wrong-types.

## Verdict
**Lane C TEST-PASSED.** Two non-Anthropic families; Mistral found a genuine over-strictness (fixed, re-verified 31/31), Qwen confirmed every real tamper is caught (19/21, both misses adjudicated as valid-chain false-positives). Append-only hash-chain integrity holds under executed attack: a mutated/removed/reordered entry breaks the walk, the latest `anchored_head` binds to the adoption-log head, corruption fails closed, malformed input never throws. Pure decision path; A6 limit stated.
