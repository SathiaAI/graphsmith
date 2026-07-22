# Contract 03 — Normative Statistical Appendix (Gate 2)
Status: DRAFT. Required by plan §4 Gate 2 (OpenAI F10/MISSING). gate.js implements THIS document; divergence is a Gate-2 bug.

## Design
- **Unit of analysis:** the scenario. **Design:** paired — candidate and baseline run the identical (scenario, seed, evaluator, model-version) tuple.
- **Order of evaluation (short-circuit):** (1) hard invariants → (2) critical slices → (3) primary endpoint. Failure at any tier stops evaluation; tiers are never averaged against each other.

## Tier 1 — Hard invariants (never averaged)
Any single violation in any scenario run → candidate REJECTED. The hard-invariant list is part of the frozen corpus definition (per-shape: e.g., "no duplicate recorded external effect," "halt fired on staged intent-without-completion" — semantics inherited from the v0.1.1 chaos properties [KnoSky: SKILL.md:87-94]).

## Tier 2 — Critical slices
Predeclared scenario subsets (per shape and per posture). Rule: no slice may regress: `pass_rate(candidate, slice) ≥ pass_rate(baseline, slice)` exactly (n is small; no tolerance). A tie is acceptable; a regression rejects.

## Tier 3 — Primary endpoint (exactly one, predeclared)
- **Estimand:** the per-scenario paired difference in the declared score (default score: binary scenario pass). Effect measure for binary: discordant-pair advantage.
- **Decision rule:** one-sided test that candidate > baseline at **α = 0.05**; equivalently the one-sided 95% lower confidence bound on the paired improvement must exceed 0.
  - Binary scores: exact binomial (sign) test on discordant pairs — reject H0 only if `P(X ≥ x | n_d, 0.5) ≤ 0.05` where `n_d` = discordant pairs, `x` = candidate-wins. (At n_d < 5 no result can pass — this is intentional: small evidence cannot promote.)
  - Continuous scores (declared per corpus): one-sided Wilcoxon signed-rank at α = 0.05 plus a bootstrap (B = 2,000, seeded) percentile lower bound > 0. Both must agree; disagreement → no promotion.
- **Multiplicity / alpha spending:** candidates are generated in ONE batch (max 3/cycle, plan §4) BEFORE any scoring. Selection happens on the selection split only; exactly ONE selected candidate reaches the confirmation split; α is spent once, on that confirmation. No re-testing of a failed candidate on the same corpus state (fingerprint-buffered).
- **Selection/confirmation split:** deterministic partition of the corpus (seeded hash of scenario IDs), rotated by cycle counter so membership shifts every cycle; the proposer NEVER sees per-scenario results or held-out membership (access audit — contract 04).

## Missing / crashed runs
Any scenario whose paired run is incomplete (crash, timeout, budget breach) counts as: candidate LOSS if either side is missing. No imputation, no exclusion. (Conservative by construction; stated in evidence output.)

## Determinism & pinning
- Seeds: per-scenario pinned seeds recorded in the corpus file; runs re-executable byte-comparable where the model permits.
- Evaluator: scenario.js + corpus hash-pinned in the manifest at cycle start; evaluator changes ship in separate PRs and re-baseline (plan §3.5); evaluator frozen at RC.
- Model: provider + model ID + version string recorded per run; a mid-cycle model change invalidates the cycle.
- Noise floor: each release publishes same-vs-same (baseline vs baseline) discordance as the run-to-run noise estimate; deltas inside the noise floor are reported as "flat" (design law: publish where results are flat, plan §1).

## Reporting (release notes, plan §13.8)
Held-out table: n scenarios, n_d discordant, x wins, p-value, lower bound, noise floor, verdict. Never the word "proven."
