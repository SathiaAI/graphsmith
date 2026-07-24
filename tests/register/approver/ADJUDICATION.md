# Lane A (approver identity) — adversarial adjudication

**Target:** `checks/register-approver.js` · **Builder:** claude-opus (Anthropic) · **Platform:** win32, Node v24.18.0
**Testers (≥2 non-Anthropic):** DeepSeek + Mistral-Large (via OpenRouter code-gen; Qwen's authored suite was itself broken — `packet_sha256` scope bug + `const` counters — and was discarded rather than repaired, to preserve tester independence). Codex not used on this lane. Builder ≠ testers. Orchestrator re-ran both suites.

## Real defect found + fixed
- **N-of-M Sybil — one key mints multiple approvers (CRITICAL fail-open).** DeepSeek's suite drove two attestations signed by the **same trusted key** under **different `approver_id`s** and reached the N=2 threshold. The reconciler counted distinct `approver_id` strings, so one key holder forged multiple "authorities." **Fixed:** the threshold now counts **distinct signer keys** (`signature.signer`) — a key is the authority, not a claimed identity. DeepSeek → **10/10**; Mistral independently confirms (`n-of-m-sybil-same-key-different-approver` PASS).

## Defensive hardening (kept)
- **SoD required + malformed `proposer_id` → fail closed.** Considering Mistral's malformed-proposer angle, I added: when `proposer_ne_approver` is required but `proposer_id` is not a valid non-empty string, separation-of-duties cannot be enforced, so the check refuses rather than silently skipping. Closes a real fail-open in the SoD-*on* path.

## Adjudicated NOT defects (two-sided validation gate)
Mistral's 2 remaining "failures" both use `createPolicy(1)` = **`proposer_ne_approver: false`** (SoD OFF), where `proposer_id` is unused:
- **`crash-bigint`** — a valid single-key approval with `proposer_id = BigInt(12345)` and SoD off. `proposer_id` is not consulted, so the valid approval correctly verifies. Expecting failure over an unused field is over-strict (would false-negative valid approvals).
- **`crash-proto-pollution`** — a valid approval with `Object.prototype.polluted="yes"` (a key the module never reads; all lookups are own-property via `hasOwnProperty`). The pollution is inert; verifying the valid approval is correct.

## Verdict
**Lane A TEST-PASSED.** Two non-Anthropic families; DeepSeek found a genuine Sybil fail-open (fixed, re-verified 10/10), Mistral confirmed the fixes hold (18/20, both misses adjudicated as SoD-off false-positives). Properties under executed attack: only ≥N distinct-KEY valid non-proposer signatures over the anchored head verify; SoD + N-of-M fail closed; algorithm-confusion + strict shape rejected; pure decision path; identity is evidence, never the count.
