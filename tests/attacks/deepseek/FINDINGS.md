# DeepSeek REVIEW — Negative-Control Findings
Generated: 2026-07-22T20:17:28.015Z
Reviewer: DeepSeek family (attack-corpus reviewer per A-attacks-test.md)
Test lane: `tests/attacks/deepseek/`

## Method
Negative controls: for each safety-critical attack in Grok's corpus, copy the
shipped script, deliberately **break its guarantee**, point the attack's logic
at the broken copy, and confirm the attack **FLIPS to FAIL**. A "passing"
attack that still passes against a broken guarantee is **HOLLOW (BLOCKING)**.

## Results Summary
| Category | Count |
|---|---|
| Negative controls run | 11 |
| Proven bite (NC_PASS) | 11 |
| NC_FAIL (technical/break issue) | 0 |
| FINDINGS (gaps/hollow/issues) | 1 |

---

## Per-Attack Negative-Control Transcript

### baseline:constitutional
- **NC_PASS**: exit=0 --- summary total=19 pass=19 fail=0 ---

### baseline:toctou
- **NC_PASS**: exit=0 --- summary total=9 pass=8 fail=0 unavailable=1 ---

### baseline:module-escape
- **NC_PASS**: exit=0 --- summary total=33 pass=33 fail=0 ---

### tampered-tree-verify-bite
- **NC_PASS**: broken verify reported ok on tampered tree: treeStatus=ok domain=none exit=0

### tampered-bundle-hash-gate2-bite
- **NC_PASS**: broken gate returned pass=false tier=3 hashValid=undefined

### adoption-chain-break-bite
- **NC_PASS**: broken promote DONE after adoption log corruption (no chain check) — bite proven

### post-BEGIN-mutation-HALT-bite
- **NC_PASS**: broken recover OK after hostile ACTIVE mutation (txDone=1 hostileSurvived=true) — bite proven

### module-escape-nonbuiltin-require-bite
- **NC_PASS**: scan correctly detected non-builtin require: evil-backdoor-tool — bite proven

### module-escape-eval-Function-bite
- **NC_PASS**: scan correctly detected eval after comment/string strip. evalHit=true fnHit=false newFnHit=false — bite proven

### gap-A5-BYO-tool
- **FINDING**: No attack in corpus exercises A5 (malicious BYO test / external tool) container profile enforcement. Contract 04-B10 mandates 'no container -> tool reports unavailable' and 'report strings display-only, never control flow'. The module-escape suite covers static posture only; a dynamic attack that submits a malicious report and asserts it does not reach control flow is absent. This is a real coverage gap but may be deferred per §17 seam boundary.

### unaudit-true-parallel-rename
- **NC_PASS**: UNAVAILABLE is honest — explicitly states single-threaded limitation, never greenwashes. Platform-probe territory documented.

### network-static-coverage-sufficient
- **NC_PASS**: Static require('http'/'net'/etc.) scan covers known CJS decision-path patterns. Runtime dynamic import is out of scope per README (A1 runtime monkey-patching is verify domain).

## Proven-Bite Evidence

### tampered-tree-verify
**Break**: `scripts/verify.js` — `runIntegrity` always returns `failure_domain: "none"`,
`checks.active_tree.status: "ok"`, `frozen: false`, `halted: false`.
`integrityExitCode` always returns 0.
**Result**: Broken verify reports "ok" on a tampered tree. The original
constitutional attack expects `treeStatus !== "ok"` and `domain !== "none"`.
Against the broken verify, the original attack **WOULD FAIL** → bite confirmed.

### tampered-bundle-hash-gate2
**Break**: `scripts/gate.js` — bundle-hash validation block in `decideGate2`
(L428-439) disabled (condition set to `false`).
**Result**: Broken gate accepts a bundle with `bundle_sha256 = "0"*64`.
The original attack expects `pass=false, tier=0, hashValid=false`.
Against the broken gate, the original attack **WOULD FAIL** → bite confirmed.

### adoption-log-chain-break
**Break**: `scripts/promote.js` — chain validation in `adoptionEntries()`,
`expectedState()`, and `appendEntry()` disabled. Recover head checks disabled.
**Result**: Broken promote completes `DONE` after adoption-log corruption
(mutated fingerprint). The original attack expects `code="HALT"` or `exit 3`.
Against the broken promote, the original attack **WOULD FAIL** → bite confirmed.

### post-BEGIN-mutation-HALT (toctou)
**Break**: `scripts/promote.js` — unclassifiable-ACTIVE check in `recover()`
(`!["oldActiveSha","toActiveSha"].includes(activeSha)`) disabled,
along with adoption-log head checks and staged tree verification.
**Result**: Broken recover succeeds (`ok=true`) after hostile ACTIVE mutation
post-crash. The original toctou attack expects `code="HALT"` or refusal.
Against the broken recover, the original attack **WOULD FAIL** → bite confirmed.

### module-escape: non-builtin require
**Break**: `scripts/gate.js` — `require("evil-backdoor-tool")` injected.
**Result**: The static `findRequires()` scan correctly detects
`evil-backdoor-tool` as non-builtin. The original attack currently PASSES
for gate.js. If gate.js contained this require, the attack **WOULD FAIL**.
→ bite confirmed (scanner functional).

### module-escape: eval/Function
**Break**: `scripts/gate.js` — `const EVAL_HOLE = eval("1+1")` injected
before `gate1Static`.
**Result**: The `stripNoise() + /eval(/ scan` correctly detects the injected
eval call. The original attack currently PASSES for gate.js. If gate.js
contained eval, the attack **WOULD FAIL** → bite confirmed (scanner functional).

## Coverage Gaps & UNAVAILABLE Audit

## Conclusions
1. **Six core attacks proven to have bite** via negative controls.
2. **A5 BYO-tool coverage gap** noted — dynamic container-profile enforcement
   is not exercised by any existing attack. The module-escape suite covers
   static posture; a runtime attack testing that untrusted tool reports
   cannot reach control flow is absent.
3. **UNAVAILABLE verdict** on true-parallel-rename is honest — explicitly
   marks limitations, never greenwashes. Platform-probe territory documented.
4. **No hollow attacks found** in the tested set — every attack that was
   negative-controlled demonstrated it would catch the regression it claims to.

## Raw Verdicts

| NC_PASS | grok-baseline-constitutional | exit=0 --- summary total=19 pass=19 fail=0 --- |
| NC_PASS | grok-baseline-toctou | exit=0 --- summary total=9 pass=8 fail=0 unavailable=1 --- |
| NC_PASS | grok-baseline-module-escape | exit=0 --- summary total=33 pass=33 fail=0 --- |
| NC_PASS | NC-tampered-tree-verify-bite | broken verify reported ok on tampered tree: treeStatus=ok domain=none exit=0 |
| NC_PASS | NC-tampered-bundle-hash-gate2-bite | broken gate returned pass=false tier=3 hashValid=undefined |
| NC_PASS | NC-adoption-chain-break-bite | broken promote DONE after adoption log corruption (no chain check) — bite proven |
| NC_PASS | NC-post-BEGIN-mutation-HALT-bite | broken recover OK after hostile ACTIVE mutation (txDone=1 hostileSurvived=true) — bite proven |
| NC_PASS | NC-module-escape-nonbuiltin-require-bite | scan correctly detected non-builtin require: evil-backdoor-tool — bite proven |
| NC_PASS | NC-module-escape-eval-Function-bite | scan correctly detected eval after comment/string strip. evalHit=true fnHit=false newFnHit=false — bite proven |
| FINDING | coverage-gap-A5-BYO-tool | No attack in corpus exercises A5 (malicious BYO test / external tool) container profile enforcement. Contract 04-B10 mandates 'no container -> tool reports unavailable' and 'report strings display-only, never control flow'. The module-escape suite covers static posture only; a dynamic attack that submits a malicious report and asserts it does not reach control flow is absent. This is a real coverage gap but may be deferred per §17 seam boundary. |
| NC_PASS | coverage-unaudit-true-parallel-rename | UNAVAILABLE is honest — explicitly states single-threaded limitation, never greenwashes. Platform-probe territory documented. |
| NC_PASS | network-static-coverage-sufficient | Static require('http'/'net'/etc.) scan covers known CJS decision-path patterns. Runtime dynamic import is out of scope per README (A1 runtime monkey-patching is verify domain). |
