# Gate Adversarial Test Findings: gpt-sol-pro

## Result

`node tests/gate/gpt-sol-pro/run-tests.js` exited `0` with all 28 tests passing.

```text
PASS bonferroni-all-wins-n-d-4: verdict=inconclusive_underpowered; n_d=4; p=null
PASS bonferroni-all-wins-n-d-5: verdict=inconclusive_underpowered; n_d=5; p=null
PASS bonferroni-all-wins-n-d-6: verdict=promote; n_d=6; p=0.015625
PASS bonferroni-all-wins-n-d-7: verdict=promote; n_d=7; p=0.0078125
PASS underpowered-does-not-reserve-or-buffer: no alpha reservation and no rejected-buffer write
PASS tier1-hard-invariant-short-circuit: hard violation vetoed an otherwise promotable endpoint
PASS tier2-critical-slice-short-circuit: critical-slice regression vetoed the overall win
PASS alpha-ledger-three-slots-then-refuse-fourth: slots 1-3 reserved; fourth refused with ALPHA_EXHAUSTED
PASS alpha-ledger-family-cannot-reenter: same edit-target family refused after failed completion
PASS alpha-crashed-reservation-remains-consumed: new store instance allocated slot 2 after uncompleted slot 1
PASS gate2-uses-edit-target-family-not-profile: family identity is derived from candidate edit targets
PASS candidate-workflow-fault-is-loss: candidate workflow faults counted as candidate losses
PASS baseline-infra-retry-result-is-scored: baseline infra fault retried once and successful retry was scored
PASS baseline-workflow-fault-never-free-win: baseline workflow faults produced no candidate wins
PASS excluded-over-20-percent-is-inconclusive: verdict=inconclusive_missingness; excluded=3/10
PASS selection-batch-max-and-fingerprint-tiebreak-api: maximum advantage selected; tie resolved lexicographically
PASS proposer-api-does-not-leak-heldout-membership-or-results: Gate-1 response contains no split membership or per-scenario fields
PASS gate1-out-of-fence-write: contract write rejected with G1_OUT_OF_FENCE
PASS gate1-rejected-buffer-duplicate: duplicate rejected with G1_REJECTED_BUFFER_DUP
PASS gate1-injection-in-human-promoted-prose: human-promoted prose rejected with G1_INJECTION
PASS gate1-appendix-cap: 1501-token appendix rejected
PASS gate1-literal-path-is-automatic-reject: literal path rejected before trusted alias translation
PASS decision-byte-determinism: byte-identical output (415 bytes)
PASS decision-path-has-no-clock-random-or-network: no Math.random, Date.now, fetch, or network module in gate.js
PASS evidence-bundle-hash-is-validated: tampered evidence hash refused fail-closed
PASS gate-persistence-has-no-direct-state-writes: state paths are unnamed and no direct filesystem mutation primitive is used
PASS state-store-writes-stay-under-temp-state-boundary: all 2 mutation artifacts remained in .graphsmith/state/
PASS scenario-runner-is-not-decision-engine: promotion decision remains in gate.js; scenario.js only produces evidence
SUMMARY total=28 pass=28 fail=0 skipped=0
```

## Defects

### HIGH: Gate 2 trusts a forged evidence hash

Attack: Replace a valid bundle's `bundle_sha256` with 64 zeroes while retaining promotable result data.

Result: Gate 2 processed the bundle and promoted it. `decideGate2` reports the supplied hash but never recomputes or compares it (`scripts/gate.js:341-369`). This violates the B6 bundle-hash validation boundary and permits modified evidence to drive promotion.

Fix: Canonically recompute the bundle hash with `bundle_sha256` omitted, compare it using a constant-time equality check, validate the evaluator/corpus pins, and fail closed before reading any outcomes or reserving alpha.

### HIGH: Gate 1 accepts proposer-emitted literal paths

Attack: Submit a clean document candidate with `file: "docs/change.md"`.

Result: Gate 1 passed it because the fence treats canonical paths as valid (`scripts/gate.js:99-105`, `scripts/gate.js:190-195`). Contract 08 requires proposer-emitted literal paths to be automatically rejected; only opaque aliases may cross the proposer boundary.

Fix: Preserve provenance through trusted alias translation, or expose a pre-gate translator that rejects any proposer value outside the alias grammar before resolving an alias to a canonical path. Gate 1 must be able to distinguish trusted translated paths from proposer literals.

### HIGH: Required batch selection rule is not implemented

Attack: Present candidates with advantages `3`, `3`, and `2`, where the tied leaders have fingerprints `z` and `a`.

Result: There is no batch selector API. `gate2Behavioral` accepts one candidate, and the code labelled "Selection rule" only totals that candidate's selection pairs (`scripts/gate.js:398-410`). It cannot choose the maximum advantage or apply the lexicographically smallest fingerprint tie-break.

Fix: Add a deterministic selection function over the complete batch generated before scoring. Compute each candidate's `wins - losses` on selection only, sort by descending advantage then ascending semantic fingerprint, and pass exactly one selected candidate to confirmation. Do not expose confirmation membership or per-scenario results to the proposer.

### HIGH: Gate 2 uses execution profile as alpha family identity

Attack: Inspect the reservation created by Gate 2 for independently targeted candidates using the same execution profile.

Result: Gate 2 passes `family: profile || "standard"` (`scripts/gate.js:447-456`). All standard-profile candidates therefore collide as one family, while the required same-edit-target family is not represented. This can exhaust/refuse valid confirmations and cannot enforce the intended near-duplicate rule accurately.

Fix: Supply the candidate semantic fingerprint's target component to Gate 2 as an authenticated field and reserve with that value. Keep `profile` separate from family identity.

### HIGH: Recorded retry outcomes are ignored

Attack: Provide six baseline `infra_fault` initial outcomes with six recorded successful baseline retries that produce candidate wins.

Result: Gate 2 ignored all retries, excluded all six pairs, and returned `inconclusive_missingness` (`scripts/gate.js:285-300`). There is no retry evidence schema or resolver path. The implementation therefore cannot apply the normative retry-once matrix; depending on initial causes, valid evidence is discarded.

Fix: Freeze retry-attempt fields in the evidence schema, require at most one retry for the applicable side or sides, validate the retry cause codes, and resolve each pair from the final permitted attempt. Preserve candidate `workflow_fault` precedence as an immediate loss.

## Passing Attacks

- Bonferroni all-win boundary is correct for `n_d=4,5,6,7`; only `n_d>=6` promotes at `0.05/3`.
- `n_d=5` returns `inconclusive_underpowered` before alpha reservation and without rejected-buffer mutation.
- Tier 1 and Tier 2 short-circuit an otherwise promotable primary endpoint.
- State-store enforces three alpha slots, family exclusion, and consumption of an uncompleted reservation across a new store instance.
- Candidate `workflow_fault` is a loss; baseline faults are not treated as free candidate wins.
- Exclusion above 20% returns `inconclusive_missingness`.
- Gate 1 rejects out-of-fence writes, rejected-buffer duplicates, injection-shaped human prose, and oversized appendices.
- Repeated pure decisions are byte-identical, and `gate.js` contains no clock, random, fetch, or network primitive.
- Gate code performs no direct state-file mutation; exercised state-store writes remained under a temporary `.graphsmith/state/` directory.

## Coverage

The runner directly exercises all eight required attack groups with synthetic evidence and temporary state roots. It also adds a B6 tampered-hash attack. No network, model provider, git operation, production corpus replay, process-level kill, or mutation of repository state was used. Crash reservation persistence is simulated by abandoning a reservation and constructing a new state-store instance against the same temporary root; state-store's journal durability itself is not fault-injected here. Selection confidentiality coverage checks the exported Gate-1 response surface and source/API shape, but cannot audit an absent evolve/proposer integration path. Retry coverage uses an adversarial recorded retry field because no retry evidence schema exists; that absence is the defect under test.
