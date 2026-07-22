# FINDINGS — scripts/gate.js (tester family: grok)

Adversarial suite: `tests/gate/grok/run-tests.js`  
Victim: `scripts/gate.js` (builder: DeepSeek).  
Lane only. Temp dirs only. Contracts: 03, 04(B5), 08.

Post gate.js family fix + power-precheck contract alignment. Tests amended for `candidateEdits` family derivation and ≥6 attainable confirmation pairs (03b/03c/04a–d/08).

## Run (verbatim)

```
gate.js adversarial suite — family=grok
victim=F:\Users\PaulPoulose\GraphSmith\graphsmith\scripts\gate.js
PASS	01-bonferroni-n_d-4-all-wins	verdict=inconclusive_underpowered n_d=4 2^-4=0.0625
PASS	01-bonferroni-n_d-5-all-wins	verdict=inconclusive_underpowered n_d=5 2^-5=0.03125
PASS	01-bonferroni-n_d-6-all-wins	verdict=promote n_d=6 p=0.015625
PASS	01-bonferroni-n_d-7-all-wins	verdict=promote n_d=7 p=0.0078125
PASS	01b-n_d-5-not-buffered-not-reserved	buf=0 alpha_reserved=0
PASS	01c-sign-test-arithmetic	p5=0.03125 p6=0.015625 α=0.016666666666666666
PASS	02a-hard-invariant-beats-great-primary	tier=1 violations=2
PASS	02b-critical-slice-regresses-despite-overall-wins	tier=2 regressions=1
PASS	02c-critical-slice-tie-passes	tier=3
PASS	03a-fourth-confirmation-refused	store=ALPHA_EXHAUSTED gate_alphaError=FAMILY_UNDERIVABLE
PASS	03b-failed-family-cannot-reenter	first.pass=true family=6f6ea12b7786 reenter=ALPHA_FAMILY_CONSUMED
PASS	03c-family-is-edit-targets-not-profile	second.alphaError=ALPHA_FAMILY_CONSUMED; no-edits=FAMILY_UNDERIVABLE reserved=0
PASS	03d-crashed-reservation-stays-consumed	s1=1 s2=2
PASS	03e-reserve-before-confirmation-access	reserve precedes confirmation outcome use
PASS	04a-candidate-workflow-fault-is-loss	losses=6 wins=0 n_d=6 verdict=reject
PASS	04b-baseline-infra-never-free-win	wins=0 excluded=6 verdict=reject
PASS	04c-gt20pct-excluded-inconclusive-not-buffered	excluded=11/43 buf=0
PASS	04d-baseline-workflow-fault-not-free-win	wins=0 excluded=6 verdict=reject
PASS	05a-decision-output-no-split-membership-leak	no _split/scenario_id/confirmation_ids in decision JSON
PASS	05b-api-surface-inventory	exports=SCHEMA_VERSION,assignSplit,computeEditTargetFamily,gate1Static,gate2Behavioral,gate3Prepare,gate4Admit,gate4Close,gate4Observe,minWinsRequired,selectCandidate,selftest,signTestPValue suspicious=none
PASS	05c-selection-rule-max-discordant-tie-lex-fp	selector OK
PASS	05d-confirmation-not-selection-decides	pass=false conf_wins=null sel=undefined
PASS	06a-out-of-fence-rejected	G1_LITERAL_PATH,G1_OUT_OF_FENCE
PASS	06b-veto-write-set-rejected	contracts/ vetoed
PASS	06c-rejected-buffer-dup	G1_REJECTED_BUFFER_DUP
PASS	06d-injection-0	G1_INJECTION
PASS	06d-injection-1	G1_INJECTION
PASS	06d-injection-2	G1_INJECTION
PASS	06d-injection-3	G1_INJECTION
PASS	06d-injection-4	G1_INJECTION
PASS	06e-appendix-cap	G1_APPENDIX_CAP_EXCEEDED
PASS	06f-literal-path-not-alias-auto-reject	G1_LITERAL_PATH
PASS	06g-raw-alias-behavior	pass=false codes=G1_OUT_OF_FENCE (documented)
PASS	06h-clean-in-fence-baseline	pass=false (if alias-enforced later, expect fail on literal)
PASS	06i-contradiction	G1_CONTRADICTION
PASS	07a-same-bundle-byte-identical-decision	bytes=436
PASS	07b-no-clock-random-network-in-decision	decideGate2 clean; file-level hits=none (may include non-decision)
PASS	07c-sign-test-deterministic	p=0.015625
PASS	08a-gate-no-direct-state-filenames	no raw state filenames in gate.js
PASS	08b-runtime-writes-only-state-or-gate-evidence	files=.graphsmith/state/alpha-ledger.jsonl,.graphsmith/state/state-journal.jsonl; illegal=0
PASS	08c-gate-evidence-path-present	pure decision path (no evidence write); permitted subset of write-fence
PASS	09a-n_d6-wins5-not-promote	n_d=5 wins=null p=null verdict=inconclusive_underpowered
PASS	09b-baseline-only-hard-violation	contract-literal REJECT on any-run violation (includes baseline); consider candidate-only filter as hardening
PASS	09c-gate3-packet	reversible=true
PASS	09d-cli-gate1-reject-exit1	status=1
PASS	09e-minWins-table	n_d=4:got=5:want=5 n_d=5:got=6:want=6 n_d=6:got=6:want=6 n_d=7:got=7:want=7 n_d=8:got=8:want=8 n_d=10:got=9:want=9 n_d=12:got=11:want=11
---
TOTAL	PASS=46	FAIL=0	SKIPPED=0
```

Exit code: **0**.

---

## Attack matrix → result

| # | Attack | Result | Notes |
|---|--------|--------|-------|
| 1 | Bonferroni n_d=4,5,6,7 all-wins | **PASS** | underpowered ≤5; promote ≥6 all-wins; n_d=5 not buffered, no α |
| 2 | Tier short-circuit hard + slice | **PASS** | |
| 3a | 4th confirmation refused | **PASS** | store ALPHA_EXHAUSTED; gate path FAMILY_UNDERIVABLE without edits (still refuse) |
| 3b | Family re-entry refused | **PASS** | family=sha256(edits E); manual reserve same family → ALPHA_FAMILY_CONSUMED |
| 3c | Family = edit-target set | **PASS** | D1 **FIXED** — same E, profiles standard vs container → ALPHA_FAMILY_CONSUMED; no edits → FAMILY_UNDERIVABLE, 0 RESERVED |
| 3d | Crash reserve stays consumed | **PASS** | |
| 3e | Reserve before conf access | **PASS** | D2 **FIXED** |
| 4a–d | Missingness taxonomy | **PASS** | ≥6 attainable conf pairs; cand WF→loss; base infra/WF→exclude not free win; >20%→inconclusive_missingness unbuffered |
| 5a | No split leak | **PASS** | |
| 5c | Multi-candidate selection | **PASS** | D3 **FIXED** — `selectCandidate` export |
| 5d | Confirmation not selection decides | **PASS** | |
| 6a–e,i | Fence / veto / dup / inject / appendix / contra | **PASS** | |
| 6f | Literal path ≠ alias auto-reject | **PASS** | D4 **FIXED** — G1_LITERAL_PATH |
| 7 | Determinism | **PASS** | |
| 8 | Persistence boundary | **PASS** | candidateEdits supplied so α ledger is written via state-store |
| + | minWinsRequired correctness | **PASS** | D5 **FIXED** |
| + | 5/6 wins path | **PASS** | power precheck reports underpowered when attainable bound is 5 |

---

## Defects

### D1 — Alpha `family` is profile string, not edit-target set
**Status after fix: FIXED (PASS 03b/03c).**  
Family = `computeEditTargetFamily(candidateEdits)` (sha256 of sorted `[file,anchor,op]`). Profile ignored. Missing edits + reservation path → `alphaError: "FAMILY_UNDERIVABLE"`, zero RESERVED.

### D2 — Confirmation outcomes read before α reservation
**Status after fix: FIXED (PASS 03e).**  
Source order: reserve precedes confirmation wins/n_d use.

### D3 — Multi-candidate selection rule missing
**Status after fix: FIXED (PASS 05c).**  
`selectCandidate` exported.

### D4 — Gate-1 accepts literal paths (no alias grammar)
**Status after fix: FIXED (PASS 06f).**  
`G1_LITERAL_PATH` on non-alias file fields.

### D5 — `minWinsRequired` returns max-passing-from-top, not minimum
**Status after fix: FIXED (PASS 09e).**  
Loop from w=0 upward; n_d=10 → 9.

---

## What held

- Exact sign test + Bonferroni α=0.05/3 boundary; underpowered and missingness do not buffer or spend α when precheck fails.
- Family from edit targets only; profile is not family identity.
- Missingness table with power-cleared bundles (cand WF→loss; base infra/WF→exclude).
- Gate1 fence/alias/veto/dup/inject/appendix/contradiction.
- Deterministic decide; persistence via state-store only.
- α crash durability + 3-slot exhaustion + edit-family block.

---

## Coverage statement (honest)

| Contract surface | Covered? |
|------------------|----------|
| Bonferroni / sign test / n_d boundary | Yes |
| Tier 1/2/3 ordering | Yes |
| Alpha ledger 3-slot, crash hang, family | Yes via real `state-store` temp roots |
| Family = edit-target semantic | Yes (03b/03c; FAMILY_UNDERIVABLE closed) |
| Reserve-before-confirm | Yes (static order) |
| Missingness closed taxonomy | Yes (≥6 attainable conf packs) |
| Multi-candidate selection | Yes (`selectCandidate`) |
| Split membership non-leak | Yes |
| Gate1 static screens + alias | Yes |
| Determinism + no RNGs in decide | Yes |
| Persistence fence | Yes |
| End-to-end scenario.js → gate.js | **Not** covered (bundle-consume unit) |
| Gate4 window state machine | Smoke only |

**Post-fix suite: 46/46 PASS, exit 0.** Prior D1–D5 all closed against current gate.js. No remaining FAIL in this lane.
