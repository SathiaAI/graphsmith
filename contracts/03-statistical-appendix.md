# Contract 03 — Normative Statistical Appendix (Gate 2) — v2
Status: DRAFT v2 (post-panel-pass-1: GPT-9/10/11/12, Gemini-6, DeepSeek-4). gate.js implements THIS document; divergence is a Gate-2 bug.

## Scope narrowing (GPT-9 — claims narrower than implementation)
v0.2.0 freezes **one endpoint type: binary scenario pass/fail**. Continuous-score endpoints are NOT machine-decidable in v0.2.0 (they surface descriptively only); freezing a continuous estimand + interval procedure is a v0.2.x item. This is recorded in the property matrix.

## Design
Unit = scenario; paired: candidate and baseline on identical (scenario, seed, evaluator-hash, model-version) tuples. Order: (1) hard invariants → (2) critical slices → (3) primary endpoint; short-circuit; never averaged across tiers.

## Tier 1 — Hard invariants: any violation in any run → REJECTED (per-shape list frozen in the corpus; semantics inherited from chaos properties [KnoSky: SKILL.md:87-94]).
## Tier 2 — Critical slices: predeclared subsets; any regression (`pass_rate_cand < pass_rate_base` on the slice) → REJECTED; ties pass.

## Tier 3 — Primary endpoint (binary, exactly one)
- **Estimand:** P(candidate passes, baseline fails) − P(candidate fails, baseline passes) on the frozen corpus distribution (unconditional discordance advantage). Reported with its exact-conditional decision rule:
- **Decision rule:** one-sided exact sign test on discordant pairs at **α = 0.05**: promote only if `P(X ≥ x | n_d, ½) ≤ 0.05` (X~Binomial). Concordant pairs are uninformative for the test and reported descriptively. The unconditional estimate `(wins − losses)/n` is published alongside with an exact Clopper-Pearson-style one-sided bound on the discordant split — both shown; the sign test is THE gate.
- **Power precheck (GPT-12, corrected P3-4):** before any candidate run, compute the maximum attainable discordant wins given baseline's corpus results, and **derive the passing threshold from the reserved slot's ACTUAL alpha** (with α = 0.05/3, all-wins needs n_d ≥ 6: 2⁻⁵ = 0.03125 > 0.0167 fails, 2⁻⁶ = 0.015625 passes — never hard-code a count). If no attainable outcome could satisfy the slot's rule, the cycle is declared **INCONCLUSIVE_UNDERPOWERED** up front: no promotion, no reservation consumed by the precheck itself, candidate NOT placed in the rejected buffer. Gate-2 tests include the n_d = 5 vs n_d = 6 boundary. Underpowered ≠ defective.

## Multiplicity / alpha ledger (GPT-10)
- Candidates batch-generated (≤3/cycle) before any scoring. Selection on the selection split only; **selection rule (DeepSeek-4): the candidate with the largest discordant-win advantage on the selection split; tie → lexicographically smallest candidate-semantic fingerprint** (contract 02 definition). Exactly one candidate reaches confirmation; α spent once there.
- **Durable alpha ledger with REAL alpha spending (P2-GPT-6):** per corpus-state, three confirmation slots are preallocated at **α = 0.05/3 ≈ 0.0167 each (Bonferroni)** — family-wise error ≤ 0.05 across everything ever confirmed against one corpus state. Before ANY confirmation data is accessed, a `RESERVED{corpus_state, split_hash, fingerprint, family, alpha_slot}` record is fsync'd to `.graphsmith/state/alpha-ledger.jsonl` (via state-store); **a reservation consumes its slot even if the process crashes** — completion records close it, lease-controlled recovery classifies orphans, and no result is ever read without a prior reservation. Further cycles require corpus growth (new scenarios re-seed the splits). A failed candidate's **family** (same edit-target set per the contract 02 fingerprint's target component) cannot re-enter confirmation against the same corpus state — near-duplicate retry is refused, not just exact-duplicate (GPT-10). The Tier-3 decision rule reads: promote only if exact-test p ≤ the slot's allocated α.
- Split: deterministic seeded partition, 60% selection / 40% confirmation; rotation by cycle counter; the confirmation membership used in a recorded attempt is sealed in the ledger. Proposer never sees per-scenario results or split membership (access audit, boundary B6/B14).

## Missing / crashed runs (v3 — closed attribution taxonomy: P2-GPT-7)
Each side is classified INDEPENDENTLY first, by **recorded cause code** (closed enum, recorded by the evaluation harness), with side-specific codes (P3-5): `workflow_fault` (that side's workflow crashed/HALTed/breached its declared budget — cause codes from contract 07's budget/halt/tripwire families) · `infra_fault` (evaluator error, host failure, evaluation-copy setup failure, provider outage) · `ok`. Process location alone never decides — an infra cause code inside either copy is still `infra_fault`.
| candidate \ baseline | ok | infra_fault | workflow_fault (baseline) |
|---|---|---|---|
| **ok** | scored pair | retry baseline once → else EXCLUDED | retry baseline once → else EXCLUDED — **never a free candidate win** |
| **infra_fault** | retry candidate once → else EXCLUDED | retry both once → else EXCLUDED | retry both once → else EXCLUDED |
| **workflow_fault (candidate)** | candidate LOSS | **candidate LOSS** (precedence: candidate-attributable failure is a loss regardless of baseline state) | **candidate LOSS** (same precedence) |
A baseline `workflow_fault` on a scenario the baseline previously passed is anomalous → also logged for human review (possible corpus/evaluator drift). Excluded pairs > 20% of the corpus → cycle INCONCLUSIVE (not a rejection; not buffered).

## Determinism & pinning
Per-scenario pinned seeds in the corpus file; evaluator (scenario.js + corpus) hash-pinned at cycle start, changes ship in separate PRs and re-baseline; model provider+ID+version recorded per run — mid-cycle model change invalidates the cycle. **Replay is honestly stochastic where providers are** (GPT-25): what is deterministic is the decision function over the recorded evidence bundle (contract 08). Noise floor: same-vs-same discordance published per release; deltas inside it are reported "flat."

## Reporting
Held-out table: n, n_d, wins, exact p, unconditional estimate + bound, exclusions, noise floor, verdict ∈ {promote, reject, inconclusive_underpowered, inconclusive_missingness}. Never "proven."
