# GPT sol-pro attack-corpus review

Verdict: **BLOCKING**. Six required negative controls bite, but two attacks remain green after their stated guarantee is deliberately broken.

The reviewer ran only against OS temp directories. Each dynamic control copied `scripts/` and `schemas/` into a fresh temp sandbox, mutated the copied script, pointed the attack oracle at that copy, and deleted the sandbox. No repository `.graphsmith/` state was used.

## Blocking findings

### 1. `post-BEGIN-ACTIVE-mutation-HALT` accepts non-HALT errors

Status: **HOLLOW for the stated HALT-with-evidence guarantee**.

The copied `promote.js` was changed so an unclassifiable post-BEGIN ACTIVE identity throws `CORRUPT_STATE` without evidence instead of calling `recoveryHalt(..., "HALT", evidence)`. The attack still passed. Its oracle explicitly accepts `CORRUPT_STATE`, then more broadly accepts any recovery error with a truthy code (`tests/attacks/toctou/run-tests.js:203-220`).

This can prove that some failures are not silent success, but it cannot prove the README's stronger requirement that post-BEGIN mutation produces `HALT` with evidence (`tests/attacks/toctou/README.md:11-15`). Rename the guarantee or tighten the oracle to require `code === "HALT"`, evidence containing expected/observed identity, no `TX_DONE`, and no hostile ACTIVE installation.

Negative control:

```text
HOLLOW	post-BEGIN-ACTIVE-mutation-HALT	broken guarantee still passed: mutant downgrades required HALT-with-evidence to CORRUPT_STATE; corpus oracle accepts it
```

### 2. `child_process-posture-gate.js` does not observe child creation

Status: **HOLLOW**.

The copied `gate.js` was changed to call `spawn(...)` on every in-memory `gate2Behavioral` decision. The attack still passed because it only checks that the call returns an object with a boolean `pass` field (`tests/attacks/module-escape/run-tests.js:206-229`). The captured `before = process.listenerCount("spawn")` value is unused and would not measure child processes in any event (`tests/attacks/module-escape/run-tests.js:221`).

Instrument the copied `child_process` dependency before loading Gate, run Gate in a child with a marker-producing spawn shim, or statically delimit the allowed spawn call to `produceBundle`. A boolean Gate 2 result is not evidence that no process launched.

Negative control:

```text
HOLLOW	module-escape/child_process-posture-gate.js	broken guarantee still passed: mutant spawns on the in-memory decision path; oracle only checks for a boolean result
```

## Proven bites

| Attack | Deliberate break in temp copy | Result |
|---|---|---|
| `tampered-tree-verify` | Forced `verifyActiveTree` to report `status: "ok"` regardless of `verifyTree` | Flipped to FAIL |
| `tampered-bundle-hash-gate2` | Disabled the claimed-vs-recomputed bundle hash branch | Flipped to FAIL |
| `adoption-log-chain-break-HALT` | Disabled adoption entry schema, sequence, linkage, and digest rejection | Flipped to FAIL |
| `no-nonbuiltin-require-gate.js` | Added `require("evil-pkg")` | Flipped to FAIL |
| `no-eval-Function-gate.js` | Added direct `eval("1")` | Flipped to FAIL |
| `no-network-api-gate.js` | Added `require("net")` | Flipped to FAIL |

These controls establish sensitivity to the selected regression, not complete soundness of each coarse regex scanner.

## Coverage gaps

Contract 05 names six attacker classes. A1 has direct tamper/race coverage, and A6 is explicitly out of scope. The following in-scope capabilities have no corresponding attack in the reviewed corpus:

| Attacker class | Missing attack coverage |
|---|---|
| A2 compromised dependency | Pinned tooling content-hash mismatch refusal; CI actions pinned by commit SHA |
| A3 hostile contributor | Trusted-workflow secret isolation; trusted-context attestations; evaluator/corpus PR separation |
| A4 artifact injection | Typed-event source authentication and invalidation on safety-relevant evidence gaps; current tests primarily cover marker strings and loader normalization |
| A5 malicious BYO test/tool | Required container refusal/`unavailable`; network denied; source read-only; scrubbed environment; report strings unable to affect control flow |

These are corpus gaps. This review does not infer that the underlying implementation is vulnerable without implementation-specific attacks.

## UNAVAILABLE review

`true-parallel-rename-race` does not probe concurrency. It creates two source files and one target path, then immediately reports `UNAVAILABLE` (`tests/attacks/toctou/run-tests.js:590-608`). The claim that the property is "inherently unprovable" in this harness is not honest: zero-dependency Node can spawn two child writers, synchronize them through IPC or barrier files, release them together, and assess process exit codes plus final ACTIVE/journal state.

Exact rename scheduling will vary by filesystem, so the result may legitimately be platform-specific or inconclusive after bounded attempts. That is different from declaring the entire property unavailable without attempting a multi-process probe.

## Log-string oracle review

No attack PASS was found whose sole oracle is a human-readable log string. PASS branches use API result fields, error codes, process exits, static scans, marker files, handle counts, or on-disk state. `gate-selftest-exit0` parses stdout JSON, but only after requiring process exit 0 and also accepts exit 0 without a meaningful JSON status (`tests/attacks/module-escape/run-tests.js:445-460`). That is a weak selftest mirror, not a log-string-only oracle.

## Negative-control transcript

Command:

```text
node tests/attacks/gpt-sol-pro/run-tests.js
```

Verbatim output (exit 1, expected because hollow attacks are blocking):

```text
=== gpt-sol-pro attack-corpus negative controls ===
BITES	tampered-tree-verify	shipped=PASS mutant=FAIL mutant reports active tree ok regardless of verifyTree result
BITES	tampered-bundle-hash-gate2	shipped=PASS mutant=FAIL mutant skips bundle hash rejection
BITES	adoption-log-chain-break-HALT	shipped=PASS mutant=FAIL mutant disables adoption entry chain/digest verification
HOLLOW	post-BEGIN-ACTIVE-mutation-HALT	broken guarantee still passed: mutant downgrades required HALT-with-evidence to CORRUPT_STATE; corpus oracle accepts it
BITES	module-escape/no-nonbuiltin-require-gate.js	shipped=PASS mutant=FAIL mutant adds non-builtin require
BITES	module-escape/no-eval-Function-gate.js	shipped=PASS mutant=FAIL mutant adds direct eval
BITES	module-escape/no-network-api-gate.js	shipped=PASS mutant=FAIL mutant adds net API import
HOLLOW	module-escape/child_process-posture-gate.js	broken guarantee still passed: mutant spawns on the in-memory decision path; oracle only checks for a boolean result
GAP	A2-compromised-dependency	no attack exercises pinned tool content-hash refusal or commit-SHA-pinned CI actions
GAP	A3-hostile-contributor	no attack exercises trusted-workflow secret isolation, trusted attestations, or evaluator/corpus PR separation
GAP	A4-artifact-injection	marker strings are covered, but typed-event source authentication and safety-relevant gap invalidation are not attacked
GAP	A5-malicious-BYO-tool	no attack proves container-required refusal/unavailable, network denial, source read-only mounting, or environment scrubbing
DODGED	toctou/true-parallel-rename-race	UNAVAILABLE is not justified: a zero-dependency multi-process harness can synchronize child writers with IPC/barriers and inspect exit codes plus final disk state; platform variance warrants per-platform results, not 'inherently unprovable'
LOG-ORACLE	none-found	reviewed PASS branches use return fields, error codes, process exits, static scan results, marker files, or disk state; stdout JSON in gate selftest is secondary to exit=0
--- summary bites=6 hollow=2 real_holes=0 gaps=5 ---
```
