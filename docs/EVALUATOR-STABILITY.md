# Evaluator-Stability Memo — Frozen Gate-2 Behavioral Evaluator

Shadow-only, Loop-3 (plan §3.5 / §12 / §14). This memo measures the stability
of the FROZEN Gate-2 behavioral evaluator over the held-out scenario corpus,
and reports its noise floor. It is an input to the v0.3 go/no-go decision.
It makes no evolution or fleet effectiveness claim.

Reference timestamp (injected, not a wall clock): `1970-01-01T00:00:00.000Z`

## Frozen evaluator
- Version: `1.0.0`
- Source: `scripts/gate.js`
- Source SHA-256 (freeze pin): `b3d481b2a2b00affacf1375fc48959d9bdf8719b61b57a24df65e70b91aeb5d3`

## Held-out corpus
- Corpus hash: `09f9ab16bfca86b5e507a9f60d1296bf2861015f4ee4a5ad15351fa5260d5748`
- Scenario count: 12
- Scenarios: `fanout-budget-fail`, `fanout-crash-resume`, `fanout-halt-uncertain`, `fanout-normal`, `manager-budget-fail`, `manager-crash-resume`, `manager-halt-uncertain`, `manager-normal`, `pipeline-budget-fail`, `pipeline-crash-resume`, `pipeline-halt-uncertain`, `pipeline-normal`

## Seed policy
- Pinned seeds (the randomness source): 64
- Split: 60% selection / 40% confirmation, rotated by cycle counter (contract 03)
- Confirmation-split size across seeds: 1–8 (the split membership rotates across seeds)

## Noise floor (endpoint spread under no change)
- Endpoint: unconditional discordance advantage (wins − losses)/n
- Construction: same-vs-same (identical candidate and baseline) over the held-out corpus
- Noise floor (max − min across seeds): **0**
- Endpoint across seeds — min 0, max 0, mean 0, stddev 0

The frozen decision function reports zero same-vs-same discordance on every
seed: the endpoint is flat across the seed-driven split rotation. Any measured
delta at or below this noise floor is reported as flat.

## Reproducibility
- Decision function deterministic for a fixed (bundle, seed): yes
- Same-input same-verdict rate across the seed set: 100%
- Modal verdict: `inconclusive_underpowered`

## Flat-is-flat (a null change reports no significant delta)
- Holds: yes
- a null (no-op) change produces no significant delta: never promoted; endpoint stays within the noise floor
- Any promotion on a null change: no
- Maximum endpoint on a null change: 0

## Falsification / sensitivity (synthetic)
- SYNTHETIC probes (not real replay) that show the frozen evaluator responds to real signal, i.e. it is not always-flat
- Injected regression detected: yes
- Injected improvement promoted: yes (endpoint min 0.48)

This confirms the flat null result above is not an artifact of an inert
evaluator: the same frozen decision function detects an injected regression
and promotes an injected improvement.

## Scope
Shadow-only (permanent I4): this harness observes and reports; it never adopts, promotes, writes ACTIVE / the adoption log, or sends anything upstream. No evolution or fleet effectiveness claim is made from this memo. This memo is an input to the v0.3 go/no-go decision, and nothing more.

## Machine form
<!-- lint-allow: honest-language (machine data block) -->
```json
{
  "schema_version": "1.0",
  "memo_kind": "evaluator-stability",
  "posture": "shadow-only",
  "ref_timestamp": "1970-01-01T00:00:00.000Z",
  "frozen_evaluator": {
    "version": "1.0.0",
    "source_file": "scripts/gate.js",
    "source_sha256": "b3d481b2a2b00affacf1375fc48959d9bdf8719b61b57a24df65e70b91aeb5d3"
  },
  "corpus": {
    "hash": "09f9ab16bfca86b5e507a9f60d1296bf2861015f4ee4a5ad15351fa5260d5748",
    "scenario_count": 12,
    "scenario_ids": [
      "fanout-budget-fail",
      "fanout-crash-resume",
      "fanout-halt-uncertain",
      "fanout-normal",
      "manager-budget-fail",
      "manager-crash-resume",
      "manager-halt-uncertain",
      "manager-normal",
      "pipeline-budget-fail",
      "pipeline-crash-resume",
      "pipeline-halt-uncertain",
      "pipeline-normal"
    ]
  },
  "seed_policy": {
    "pinned_seed_count": 64,
    "split": "60% selection / 40% confirmation, rotated by cycle counter (contract 03)",
    "confirmation_size_range": [
      1,
      8
    ]
  },
  "noise_floor": {
    "endpoint": "unconditional discordance advantage (wins − losses)/n",
    "construction": "same-vs-same (identical candidate and baseline) over the held-out corpus",
    "value": 0,
    "endpoint_stats": {
      "min": 0,
      "max": 0,
      "mean": 0,
      "stddev": 0
    }
  },
  "reproducibility": {
    "decision_function_deterministic_same_seed": true,
    "same_input_same_verdict_rate": 1,
    "modal_verdict": "inconclusive_underpowered",
    "verdict_distribution": {
      "inconclusive_underpowered": 64
    }
  },
  "flat_is_flat": {
    "holds": true,
    "detail": "a null (no-op) change produces no significant delta: never promoted; endpoint stays within the noise floor",
    "any_promote": false,
    "endpoint_max": 0
  },
  "falsification": {
    "note": "SYNTHETIC probes (not real replay) that show the frozen evaluator responds to real signal, i.e. it is not always-flat",
    "injected_regression_detected": true,
    "regression_verdict_distribution": {
      "tier2_reject": 64
    },
    "injected_improvement_promoted": true,
    "improvement_verdict_distribution": {
      "promote": 64
    },
    "improvement_endpoint_min": 0.48
  },
  "scope_note": "Shadow-only (permanent I4): this harness observes and reports; it never adopts, promotes, writes ACTIVE / the adoption log, or sends anything upstream. No evolution or fleet effectiveness claim is made from this memo. This memo is an input to the v0.3 go/no-go decision, and nothing more."
}
```
<!-- /lint-allow -->
