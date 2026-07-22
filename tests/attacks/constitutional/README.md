# Constitutional attack corpus

Executable adversarial battery against GraphSmith’s gating / verify / promote guarantees.

## Scope

Contained tests only:

- Temp directories for all project state (never the repo’s real `.graphsmith/`).
- Attacks the already-shipped scripts: `gate.js`, `verify.js`, `promote.js`, `loaders.js`, `state-store.js`, `manifest.js`.
- Zero-dep CJS. No git. No packages. No network.

## What is covered

| Attack | Target boundary | Expected (guarantee holds) |
|---|---|---|
| Out-of-fence write in candidate | B5 / Gate 1 | `G1_OUT_OF_FENCE`, `pass=false` |
| Injection markers in payloads | B5 / Gate 1 | `G1_INJECTION` |
| Loader evasions (newline-split, fullwidth, ZWSP, delim forge) | B2 | appendix quarantined (`marker-sequence`) |
| Appendix over token cap | B2 / Gate 1 | `G1_APPENDIX_CAP` / loaders `token-cap-exceeded` |
| Tampered evidence-bundle hash | B6 / Gate 2 | tier 0 reject, `hashValid=false` |
| Tampered tree / constitutional file into verify | B8 / B15 | not false-verified; freeze or trusted-core HALT |
| Broken adoption-log chain into promote | B15 | HALT (`code=HALT` or exit 3) |
| Rejected-buffer fingerprint duplicate | B5 / Gate 1 | `G1_REJECTED_BUFFER_DUP` |

A **caught** attack is a **PASS**. An attack that succeeds against a must-hold guarantee is a **FAIL** (and a BLOCKING finding in the attacked component).

## What is NOT covered

- Privileged local attacker who rewrites sentinel + both manifests (A6, out of scope).
- Model-level jailbreak resistance (§17).
- Multi-process true concurrency races (see `../toctou/`).
- Network / dependency supply-chain beyond static posture (`../module-escape/`).

## Verdict rule

Every refuse/hold claim is read from **return objects, exit codes, or on-disk state** — never from log strings.

## Run

```bash
node tests/attacks/constitutional/run-tests.js
```

Exit `0` if all guarantees held. Exit `1` if any attack succeeded.
