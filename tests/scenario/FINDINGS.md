# FINDINGS — adversarial test of `scripts/scenario.js` + `scenarios/` corpus

Tester: Claude Sonnet (different model family than the builder, Qwen). Task: `.plans/tasks/A-scenario-test.md`.
Lane: `tests/scenario/` only. `scripts/scenario.js`, `scenarios/`, and everything else in the repo was read-only for this review — every defect below is reproduced through the public CLI / temp-dir fixtures, never by editing the code under test. No `git` was run. No packages were installed. All generated fixture projects live under `os.tmpdir()` and are removed after each test.

Run with: `node tests/scenario/run-tests.js`. Exit code is 1 (7 of 21 cases FAIL) — see verbatim output below.

## How to read this

`run-tests.js` is a real regression suite, not a report generator: every defect below is encoded as a test case that currently **FAILs** and will turn green the day the defect is fixed. That is intentional — a passing suite for a component with real, reproducible bugs would be a false signal.

## Verbatim test output

```
=== tests/scenario/run-tests.js (tester family: Claude Sonnet; builder family: Qwen) ===
REPO_ROOT=F:\Users\PaulPoulose\GraphSmith\graphsmith
SCENARIO_JS=F:\Users\PaulPoulose\GraphSmith\graphsmith\scripts\scenario.js
REAL_CORPUS_DIR=F:\Users\PaulPoulose\GraphSmith\graphsmith\scenarios

FAIL	0a. CLI: the documented invocation 'node scenario.js replay --paired ...' (as shown in scenario.js's own header comment + usage banner) actually runs	DEFECT REPRODUCED: documented CLI form exits 1 with usage banner instead of running. parseArgs() only sets args.replay when the token itself starts with '--' (k.startsWith("--")); the doc comment and usage banner both show bare 'replay'/'record' as the subcommand, which never sets args.replay/args.record. Workaround that DOES work (undocumented): '--replay --paired ...' / '--record --auto ...'.
FAIL	0b. CLI: the documented invocation 'node scenario.js record --auto <dir>' actually runs	DEFECT REPRODUCED (same root cause as 0a): documented 'record --auto' form exits 1 with usage banner.
PASS	1a. determinism: same seed twice -> byte-identical bundle_sha256 (real corpus)	bundle_sha256=c9825518b550f0802c998329772b90104cee02efea6149d9e63feea6d4ad7e05
PASS	1b. determinism: flipped seed -> bundle differs but stays schema-valid	hashes differ (c9825518 vs d555133f) and flipped-seed bundle is schema-valid
PASS	2. bundle schema: full real corpus run has every contract-03 field + closed-enum cause codes	all fields present, 12 pairs, all cause codes closed-enum
PASS	3a. separation of concerns: no verdict/promote/accept/reject decision logic in scenario.js source	only disclaiming comments mention promotion; no executable decision logic found
PASS	3b. separation of concerns: emitted evidence bundle carries no verdict-like key (recursive scan)	no verdict-like keys in emitted bundle (pass/cause_code are per-scenario evidence, not a promotion decision)
PASS	4a. state-based verdict: declared halt scenario where worker never actually halts must FAIL (not scored as halt-pass)	correctly scored FAIL: cause_code=workflow_fault (halt-on-intent-without-completion invariant caught the mismatch)
FAIL	4b. state-based verdict: declared budget-exceeded scenario where budget is never actually breached must FAIL	DEFECT REPRODUCED: budget-exceeded scenario that never breached its budget was scored PASS (cause_code=ok). classifyOutcome() ignores scenario.expected.outcome on its complete-path branch.
PASS	5a. corpus coverage: 12 files = 3 shapes x 4 failure_modes, each combination present exactly once	12/12 combinations present, no duplicates
PASS	5b. corpus integrity: every scenario file is self-contained (no API keys, no network refs, no env/secret refs)	no secret/network/env references found in any of 12 scenario files
FAIL	5c. corpus coverage: actually RUN all 12 real scenarios and confirm each self-consistently passes its own design	scenarios failing their own design: fanout-crash-resume, manager-crash-resume, pipeline-crash-resume
PASS	5d. built-in --selftest flag runs and exits 0	selftest exited 0
PASS	6a. corpus integrity: every scenario has a pinned non-negative integer seed	all 12 scenarios carry a pinned integer seed
PASS	6b. corpus integrity: two full-corpus runs with same cycleSeed give stable bundle_sha256 (already covered by 1a, re-verified with a different seed)	stable hash across two full-corpus runs
SKIPPED	6c. corpus integrity: attempt to construct a secretly-nondeterministic scenario (uses time/random in a decision)	cannot express nondeterministic worker logic through schema-legal fixtures without modifying scenario.js's generator (out of lane) — see coverage statement
PASS	7a. cause-code correctness: unconditional worker failure -> workflow_fault on both sides	both sides correctly classified workflow_fault on unconditional worker crash
FAIL	7b. cause-code correctness: evaluation-copy setup failure (pipeline references an undefined worker) should classify as infra_fault	DEFECT REPRODUCED: missing-worker setup failure was classified 'workflow_fault' instead of infra_fault
PASS	7c. cause-code correctness: every real-corpus pair (both sides) uses only ok/workflow_fault/infra_fault	all cause codes closed-enum across full corpus
FAIL	8. crash-injection: a fresh crash_after_step scenario must actually terminate the manager after that step (root cause of 5c)	DEFECT REPRODUCED (isolated, not corpus-specific): crash_after_step never actually crashed the manager
FAIL	X1. paired replay: --candidate and --baseline are honored as distinct code trees, not just labels	DEFECT: changing --candidate treeId did not change a single pair result

=== SUMMARY: 13 PASS, 7 FAIL, 1 SKIPPED (of 21) ===
```

(The run above trims a few long `detail` strings for readability; `node tests/scenario/run-tests.js` reproduces the full text.)

## Defects found

### D1 — BLOCKING — the documented CLI invocation does not work at all
`scripts/scenario.js`'s own header comment and usage banner document:
```
node scenario.js record --auto <project-dir>
node scenario.js replay --paired --candidate <treeId> --baseline <treeId> [--corpus <dir>] [--seed <n>]
```
`parseArgs()` only sets `args.<key>` for tokens that themselves start with `--` (`if (k.startsWith("--"))`). The subcommand tokens `replay` and `record` are bare (no `--`), so they land in `args._` and never set `args.replay` / `args.record`. The dispatcher (`if (args.replay && args.paired)` / `if (args.record && args.auto)`) is therefore never reached via the documented form — every documented invocation falls through to the usage banner and exits 1. The only way to actually invoke it is the undocumented double-dash form `--replay --paired ...` / `--record --auto ...`.
- Nothing else in the repo currently calls `scenario.js` (`grep -rn "scenario.js"` across non-test files matches only `scripts/scenario.js` itself and `.plans/ownership-map.json`), so this has never been exercised end-to-end.
- Only `--selftest` works, because it calls `replayPaired()` directly as a JS function and never goes through the broken arg path — which is why the shipped selftest looked green.
- **Fix:** either accept the bare positional subcommand (`argv[0] === "replay"` / `"record"`) in addition to / instead of requiring `--replay`/`--record`, or fix the header comment + usage banner to show the form that actually works. Either is a one-line change; whichever is chosen, add a CLI-invocation regression test so this can't regress silently again.
- Reproduced by: `0a`, `0b`.

### D2 — BLOCKING — crash injection is dead code; all 3 crash-resume corpus scenarios fail
In `generateManager()`'s emitted template:
```js
carry = await executeStep(stepDef, carry);
if (CRASH_AFTER && stepDef.step === CRASH_AFTER && !readCheckpoint(path.join(runDir, stepDef.step + ".json"), stepDef.step).done) {
  process.exit(1);
}
```
`executeStep()` only returns (allowing control to reach this line) after it has already called `saveCheckpoint()` on success. So `readCheckpoint(...).done` is always `true` at the point this line runs, `!true` is always `false`, and the crash never fires — the manager just runs to completion. This is not a corpus-specific fluke: `run-tests.js` case `8` reproduces it on a fresh, minimal, isolated 2-step scenario, so it is a property of the generator itself.
- Effect on the shipped corpus: `pipeline-crash-resume`, `fanout-crash-resume`, and `manager-crash-resume` — the entire `crash-resume` failure-mode family, 3 of the 12 scenarios (25% of the corpus) — deterministically FAIL when run through the real CLI (`cause_code: "workflow_fault"`, violation `"crash-expected: run completed but crash was expected after <step>"`). This is `scripts/scenario.js`'s own internal self-consistency guard (`if (scenario.fixture.crash_after_step && result.code === 0) return {pass:false, ...}`) correctly catching the anomaly — it is a loud failure, not a silently wrong pass — but it means the corpus's entire crash/resume-from-checkpoint story, which SKILL.md calls out as one of the core chaos-harness properties this whole project exists to verify (kill test / double-run test), currently cannot be exercised at all.
- **Fix:** the intent is almost certainly "crash immediately after this step's checkpoint is saved" — i.e. the condition should trigger when the checkpoint IS done (e.g. move the check to right after `saveCheckpoint` inside `executeStep`, or simply drop the `!`). As written it can never fire.
- Reproduced by: `5c` (corpus-level symptom), `8` (isolated root cause).

### D3 — MAJOR — `replay --paired` never actually reads a candidate or baseline tree; both sides always run identical code
`replayPaired()` materializes the fixture with `materializeFixture(scenario, candDir)` and `materializeFixture(scenario, baseDir)` — both calls take the **same** `scenario.fixture`, and neither `candidateId` nor `baselineId` is ever read anywhere inside `materializeFixture`, `generateWorker`, or `generateManager`. The `--candidate`/`--baseline` CLI values are used only as opaque string labels copied into `bundle.model_versions`. Test `X1` proves it: changing `--candidate` from `tree-AAA` to `tree-ZZZ-totally-different` against the same corpus/seed produces byte-identical `pairs[]` results — only the label differs.
- Contract 03 ("paired: candidate and baseline on identical (scenario, seed, evaluator-hash, model-version) **tuples**") and contract 08 ("Gate 2 = scenario.js produces → gate.js decides") both presuppose that candidate and baseline are two different code trees under actual comparison. As implemented, `cand` and `base` will always be concordant (same pass/fail) for every scenario, forever — there is no mechanism by which a real regression in a candidate's workflow could ever surface as a discordant pair. Contract 03's Tier-3 sign test is defined entirely over discordant pairs; with zero attainable discordant pairs the promotion mechanism this whole pipeline exists to support can never fire through this path.
- This may be intentional scaffolding for the current build phase (a `treeId → actual project directory` resolution step that hasn't been wired up yet) rather than a one-line bug, so I'm not certain a small patch fixes it — flagging at MAJOR rather than co-equal BLOCKING with D1/D2, but it is the most consequential architectural gap found and should be triaged by whoever owns contract 08/gate.js integration.
- **Fix suggestion:** `--candidate`/`--baseline` should resolve to actual tree directories (e.g. via the state-store's tree registry referenced in contract 11: `register(runId, treeId)`), and `materializeFixture`/execution should run each side against its own tree's actual `pipeline.json`/`workers/` where the scenario fixture provides only the input/topology, not the implementation under test — or, if scenario.js is deliberately corpus-fixture-only for this phase, contract 08 should say so explicitly so gate.js's caller doesn't assume real tree comparison happens here.
- Reproduced by: `X1`.

### D4 — MAJOR — `expected.outcome` is not cross-checked for the `budget-exceeded` case; a broken budget enforcer is scored PASS
`classifyOutcome()`'s first branch:
```js
if (result.code === 0 && combined.includes("__done__"))
  return { pass: true, cause_code: "ok" };
```
fires unconditionally whenever the manager exits 0 and logs `__done__`, **without checking `scenario.expected.outcome` at all**. For the `halt` outcome this is caught by a dedicated invariant (`halt-on-intent-without-completion`, verified by test `4a`), and for `crash-recovered` it's caught by the explicit `crash_after_step && result.code === 0` guard (see D2). But there is no analogous guard for `budget-exceeded`: if a workflow's budget enforcement is silently broken (or absent) so a `budget-fail`-designed scenario just runs to completion instead of halting on budget overrun, `scenario.js` reports `pass: true, cause_code: "ok"` — a false pass. Test `4b` reproduces this directly: a scenario declaring `expected.outcome: "budget-exceeded"` with a generous `budget_ms` and fast `ok` workers (i.e. the budget is never actually breached) is scored PASS.
- This matters because "candidate breaks safety property X but the harness doesn't notice" is exactly the failure class contract 03 and SKILL.md:89 exist to prevent (state-based verdicts, not assumed/label-based ones).
- **Fix:** add an explicit check analogous to the `crash_after_step` guard: if `scenario.fixture.budget_ms` is set and the outcome came back `complete` (not `"BUDGET EXCEEDED"` in output) while `scenario.expected.outcome === "budget-exceeded"`, that's a violation, not a pass.
- Reproduced by: `4b`.

### D5 — MINOR/MAJOR (judgment call) — `infra_fault` is effectively unreachable; setup failures get misclassified as `workflow_fault`
`classifyOutcome()` only returns `infra_fault` when `result.code === 0` but none of `__done__`/`UNRESOLVED SIDE EFFECT`/`BUDGET EXCEEDED` appear in the output — a narrow, hard-to-reach corner. A genuine "evaluation-copy setup failure" (contract 03's own example category), such as a scenario whose `pipeline` references a worker name that's absent from `workers{}` (so `materializeFixture` never writes that file and the generated manager's `require()` throws), instead surfaces as an uncaught exception → `process.exit(1)` → `result.code !== 0` → classified `workflow_fault`. Test `7b` reproduces this directly.
- Why it matters: contract 03's missingness table gives `infra_fault` retry-once semantics that `workflow_fault` does not get, and explicitly says "candidate-attributable failure is a loss regardless of baseline state." Misclassifying a setup/evaluator problem as a workflow fault means a candidate could be scored a LOSS for something that was never its own workflow's fault, with no retry.
- Severity is judgment-call MAJOR rather than BLOCKING because it requires a genuinely broken/misconfigured scenario to trigger (the 12 shipped scenarios are all well-formed and don't hit this path — confirmed by `7c`, which shows only `ok`/`workflow_fault` codes appear across the real corpus today).
- **Fix suggestion:** wrap `require("./workers/" + stepDef.worker)` (and ideally the whole run-manager invocation) so setup-time failures (missing module, syntax error in a worker, directory materialization failure) are distinguishable from a worker's own runtime `throw`, and have `scenario.js` map the former to `infra_fault`.
- Reproduced by: `7b`.

### D6 — Informational, not scored as a defect — `expected.outcome`/cause-code semantics for HALT vs contract 03's literal wording
Contract 03 §Missing/crashed runs defines `workflow_fault` as "that side's workflow crashed/HALTed/breached its declared budget," which read literally would classify even an *expected, correct* safety halt as `workflow_fault`. `scenario.js` instead records `cause_code: "ok"` when a halt matches `scenario.expected.outcome === "halt"` (only genuinely *unexpected* halts/crashes/budget-breaches get `workflow_fault`). I believe the implementation's reading is the more defensible one — an intentional safety halt is correct behavior, not a "fault" — but the contract prose is ambiguous enough that this is worth a one-line clarification from whoever owns contract 03/08 rather than something I should silently resolve either way. Not counted as a FAIL in the suite; flagged here for visibility only.

## Checks performed (mapped to the task's required list)

1. **Determinism** — `1a`/`1b`: same seed → byte-identical `bundle_sha256` across two full real-corpus runs; different seed → different hash, still schema-valid. PASS.
2. **Bundle schema** — `2`: every contract-03 field present on a full 12-scenario real-corpus bundle; all cause codes closed-enum. PASS.
3. **Separation of concerns** — `3a` (source grep) / `3b` (recursive key scan of an emitted bundle for verdict-like keys). PASS — scenario.js does not decide promotion anywhere.
4. **State-based verdicts** — `4a`: a scenario that claims `halt` but whose worker never produces an unresolved intent is correctly scored FAIL (the `halt-on-intent-without-completion` invariant genuinely reads on-disk state, not a string). `4b`: the *analogous* protection for `budget-exceeded` does not exist — DEFECT D4.
5. **Corpus coverage** — `5a`: 12 files = 3 shapes × 4 failure modes, all present, no duplicates. `5b`: no secrets/URLs/env refs in any scenario file. `5c`: actually ran all 12 real scenarios — 3 of them fail (DEFECT D2). `5d`: the shipped `--selftest` still passes (it bypasses the broken CLI arg path — see D1).
6. **Corpus integrity** — `6a`: every scenario has a pinned non-negative integer seed. `6b`: two full-corpus runs with the same cycleSeed give a stable hash. `6c`: attempted to construct a secretly-nondeterministic scenario; **could not** — see coverage statement below.
7. **Cause-code correctness** — `7a`: unconditional worker failure → `workflow_fault` on both sides, correct. `7b`: a setup/evaluation-copy failure (missing worker module) should be `infra_fault` per contract 03 but comes back `workflow_fault` — DEFECT D5. `7c`: across the full real corpus, only closed-enum codes appear.
8. Added: isolated root-cause reproduction of D2 (crash injection dead code) on a fresh minimal scenario, decoupled from the shipped corpus.
9. Added (X1): candidate/baseline tree differentiation — DEFECT D3.
0. Added (0a/0b): documented CLI invocation itself — DEFECT D1, found while wiring up every other check (every check in this suite had to use the undocumented `--replay`/`--record` form to run at all).

## Honest coverage statement — what was NOT tested

- **Nondeterminism detection (`6c`) is SKIPPED, not exercised.** The task asks to "construct a scenario that is secretly nondeterministic (uses time/random in a decision)" and confirm the harness would catch it. The schema-legal worker `behavior` vocabulary (`ok`, `delay`, `fail`, `intent-no-complete`, `budget-exceed`) maps to fixed generator templates in `scenario.js`, none of which contain `Math.random()` or a decision-affecting `Date.now()` outside the (intentional) budget-check wall-clock comparison. Without modifying `scripts/scenario.js` (out of my lane), there is no way to get a `Math.random()`-driven decision into a generated worker at all, so I could not actually build the adversarial input this check calls for. I consider this a coverage gap in the corpus/generator's expressive range rather than something I can claim to have "tested and found clean."
- **Real wall-clock timing flakiness under load was not stress-tested.** The `budget-fail` scenarios rely on genuine `setTimeout`/`Date.now()` timing (200ms budget vs. 500ms worker delay — a 2.5x margin). I did not run these under artificial CPU/IO load to look for flaky flips; the margin is generous enough that I don't expect flakiness under normal conditions, but this is an assumption, not a verified property.
- **`fan-out` and `manager+workers` shape-specific branch logic in `materializeFixture`** (the `fan_out_groups` expansion and `manager_decisions` routing) was exercised only through the 8 real corpus scenarios that use those shapes, not through additional hand-built adversarial fixtures (e.g. a `manager_decisions` table with no matching entry, or an empty `fan_out_groups` array). Time-boxed out given the severity of D1-D5 already found.
- **`gate.js` was not touched or tested.** I read contract 08 for the "scenario.js produces, gate.js decides" boundary but the checklist and my lane are scoped to `scripts/scenario.js` + `scenarios/` only; I did not verify gate.js actually consumes these bundles correctly (that's a different component's test surface).
- **Windows-specific path/lock edge cases were not adversarially probed beyond what the suite naturally exercises.** All testing was done on this Windows machine via Git Bash / node's own cross-platform `path`/`fs` APIs; I did not specifically try to break the lock-file (`fs.openSync(..., "wx")`) or `fsync` logic with Windows-specific races (e.g. antivirus file-lock contention). The lock/lease code was read but not adversarially exercised.
- **The `--corpus` flag pointed only at directories I fully controlled** (the real `scenarios/` dir, or single-scenario temp dirs). I did not test malformed corpus directories (e.g. a `.json` file that isn't valid JSON at all, or a directory with zero scenario files) — `loadCorpus`'s `fail()` calls for these look correct by inspection (`JSON.parse` will throw, `validateScenario` checks required fields) but were not exercised end-to-end in this suite.
- **I did not attempt to fix D1-D5.** Per the task's lane rules, `scripts/scenario.js` and `scenarios/` are read-only to me; all findings above are proposed fixes for whoever owns that lane (Qwen, per `.plans/ownership-map.json`).

## Summary

7 real defects found (2 BLOCKING, 2 MAJOR, 1 MAJOR/MINOR judgment call, 1 informational-only), all encoded as reproducible, currently-failing regression tests in `run-tests.js`. The most severe are D1 (the documented CLI invocation is completely non-functional — only an undocumented flag form works) and D2 (crash injection is dead code, so the entire crash-resume scenario family — 25% of the corpus — fails outright when actually run). D3 (candidate/baseline are never actually differentiated) is the most consequential for the project's stated purpose if it isn't already known/expected scaffolding for this build phase.
