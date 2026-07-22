# graphlint R5/R6 test findings — sonnet lane

Tester: Claude Sonnet (not the DeepSeek V4-pro builder). Driven entirely via `node scripts/graphlint.js <path>`
on temp-dir fixtures created by `run-tests.js`; `scripts/graphlint.js` was not modified or imported as a module.
Live-verified against the actual repo, 2026-07-22 (per CLAUDE.md: docs lie, live systems don't).

Run: `node tests/graphlint/sonnet/run-tests.js` -- 15 passed, 1 failed, 0 skipped. Exit code 1.
Verbatim output is reproduced in full at the bottom of this file.

## THE KEY QUESTION -- R5 scope: position

R5 should be evolvable-scoped. The current implementation is over-firing on the repo's own
constitutional scripts, and that is a real defect, not a defensible "surface everything" design.

### Citations

1. `.plans/tasks/B-graphlint.md:11` (the builder's own task spec):
   "flag eval(, new Function(, Function( used as a constructor, child_process exec/execSync/spawn*
   introduced in a decision/evolvable file, and require( / dynamic import( of a NON-builtin,
   NOT-already-present module"

   The child_process clause is explicitly scoped to "a decision/evolvable file" -- that phrase does
   not appear on the eval/new-Function clause because those are unconditionally dangerous everywhere;
   it appears specifically on child_process because process-spawning is the one primitive that
   legitimate constitutional/orchestration code needs.

2. `.plans/graphsmith-v0.2.0-final-build-plan.md:104` (the master plan, describing the whole static-screen
   design, not just this one task):
   "A static screen bans new require/import statements, eval, new Function, and raw exec in
   machine-evaluated candidates AND in scaffold adapters (graphlint rule -- Gemini F6)."

   Both named contexts -- "machine-evaluated candidates" (code run through the isolated
   evaluation/replay pipeline) and "scaffold adapters" (the adapters/*.js files a scaffolded workflow
   generates) -- are evolvable/generated code, never GraphSmith's own hash-pinned maintainer tooling
   in scripts/.

3. Architectural self-consistency: R5's own stated rationale, printed in the finding message itself, is
   "generated/evolvable code must never gain new execution surface." The six constitutional files R5
   currently flags (chaos.js, scenario.js, watchdog.js, gate.js, scaffold.js,
   ci-check-pr-separation.js) are not generated/evolvable code -- they ARE the supervisor that
   enforces that boundary for everything else. scenario.js spawning replay to run an evaluation,
   watchdog.js killing a hung child, gate.js spawning scenario for a gate check, and scaffold.js
   spawning parallel workers are the mechanism by which GraphSmith safely runs evolvable code at arm's
   length. Banning that in the supervisor itself would make the architecture in section 132/190 impossible
   to implement, which is strong evidence this was never the intent.

R6, by contrast, is already correctly scoped: it only inspects files physically under an adapters/
directory (scripts/graphlint.js:306-329), matching contract 06's declared surface. R5 has no equivalent
directory/role scoping at all -- it applies its regexes to every file under the scanned root unconditionally.
That asymmetry, plus the two citations above, is why I read this as a real gap rather than an intentional
"surface every spawn for human review" design: if "surface everything" were the intent, R6 would not have
been scoped either, and the child_process clause in the builder's own task spec would not carry the
"introduced in a decision/evolvable file" qualifier.

### What was tested

`run-tests.js` encodes the assertion "R5 must not HIGH-flag child_process in the six constitutional
files" as a real test (R5-scope [DEFECT]). It FAILS against the current build -- that failure is the
defect, reported below, not a bug in the test.

## Defects (for the builder -- DeepSeek, currently budget-blocked; keeping this list short and precise)

### D1 -- R5 child_process check has no evolvable/constitutional scoping (HIGH priority, blocks clean dogfood)
- Where: scripts/graphlint.js:268-270 (EXEC_SPAWN_RE + CHILD_PROCESS_REF gate inside the
  per-line R5 loop) -- fires on every file under the scanned root with no path/role check.
- Symptom: `node scripts/graphlint.js scripts/` reports 17 `R5: child_process exec/spawn call`
  HIGH findings (not 16 -- see note below) across 6 constitutional files, 100% of which are legitimate
  orchestration, 0% of which are a real defect in those files.
  - chaos.js: 6 (lines 33, 131, 144, 146, 158, 183)
  - ci-check-pr-separation.js: 2 (lines 291, 299)
  - gate.js: 1 (line 358)
  - scaffold.js: 4 (lines 1715, 1743, 1748, 1753)
  - scenario.js: 2 (lines 319, 338)
  - watchdog.js: 2 (lines 98, 294)
- Note on the task brief's count: the task file (B-graphlint-test.md:11) says "16 R5 HIGH" -- the
  live count as of this run is 17 (verified via CLI, not assumed from the doc). Flagging the drift per
  CLAUDE.md's live-source-over-doc rule; not itself a defect, just a correction for whoever reads both.
- Fix recommendation: scope the EXEC_SPAWN_RE/CHILD_PROCESS_REF check (and, per plan section 104, ideally
  the rest of R5 too -- EVAL_RE, NEW_FUNCTION_RE, FUNCTION_CTOR_RE, REQUIRE_IMPORT_RE,
  DYNAMIC_IMPORT_RE) to evolvable targets only, using the same directory-role convention R6 already
  uses for adapters/ (scripts/graphlint.js:306) -- e.g. only fire R5 under adapters/, workers/, or
  a scaffolded-project/candidate root passed to the linter, and skip GraphSmith's own scripts/ tree
  when scanning the constitutional repo itself. A minimal alternative that fixes the observed dogfood
  noise without touching eval/new-Function/new-require: gate EXEC_SPAWN_RE on the same "is this file
  under an evolvable root" check R6 already has, defaulting to "not evolvable" for files that aren't
  under adapters/ or workers/.
- Severity of the defect itself: the six flagged findings are false positives relative to R5's stated
  scope (not false positives in the sense of "graphlint mis-detected a call" -- the calls are real; they're
  simply out of R5's intended jurisdiction). Until fixed, every dogfood run of graphlint on GraphSmith's
  own scripts/ will show 17 HIGH findings a human has to manually re-triage as "known non-issue," which
  erodes the signal value of HIGH.

### D2 -- R4 false positive: cross-function variable-name collision (LOW priority, pre-existing, advisory-only)
- Where: scripts/scenario.js:640 and :644, inside selftest().
- Symptom: R4 ("routing on a clock/random-derived variable") fires on
  `if (!pair.scenario_id || pair.seed == null || !pair.cand || !pair.base)` (line 640) and
  `if (!["ok","workflow_fault","infra_fault"].includes(pair.base.cause_code))` (line 644).
- Root cause: scripts/graphlint.js:212-216's same-file taint tracker records a local variable
  named `base`, declared at scenario.js:514 inside an entirely different function (makeTempDir)
  via Date.now() + Math.random() (used to build a unique temp-dir name -- legitimate, unrelated to
  control flow). The taint tracker has no function-scope boundary, so `base` stays "tainted" for the
  rest of the file. Separately, the tainted-variable regex \b(var)\b matches the property access
  `pair.base` (an unrelated field from a JSON replay bundle) because "." is a non-word character, so
  \bbase\b matches the "base" inside "pair.base" too.
- Impact: REVIEW-only (advisory, non-blocking) and pre-existing in R4 (not introduced by this R5/R6
  build), so it does not block this task's PASS/FAIL gate on its own merits -- flagging it because the
  dogfood step asked for a TP/FP classification of every finding, and this is a genuine FP.
- Fix recommendation (optional, low priority): either scope taintedVars per function (track
  brace-depth or reset on function/=> boundaries) or require a non-word, non-"." character on both
  sides of the match (i.e. don't let \bvar\b match inside obj.var) -- the second is the smaller diff
  and would also harden R4 generally, not just this instance.

## Required checks -- results

1. R5 recall (eval, new Function, Function()-ctor, child_process exec/spawn, static dynamic import,
   computed dynamic import, new-require) -- all 7 PASS. Bare-view discipline holds: comment-only and
   string-only occurrences of every one of these tokens produce zero R5 findings (2 dedicated precision
   tests, both PASS).
2. R5 precision -- clean builtin-only file: 0 R5 findings (PASS). graphlint's own source
   (scripts/graphlint.js, which contains all six R5 regex literals as literal source text, plus the
   word eval/exec/spawn/require/import throughout its comments and corpus-adjacent strings)
   does NOT self-trip -- 0 R5 findings scanning graphlint.js directly (PASS).
3. R6 recall/precision -- undeclared adapter with an external effect (axios.post) -> R6 HIGH at
   line 1 (PASS). Same adapter with a matching adapters/notify.capability.json -> 0 R6 findings (PASS).
4. Regression -- `node scripts/graphlint.js --selftest`: exit 0, 0 FAIL-marker lines, "0 failure(s)" in the
   summary (PASS). All 11 R1-R4 recall probes and 8 precision-clean files in tests/lint-corpus/
   (including the pre-existing R5/R6 corpus the builder added: e9a-e9g) still green.
5. Dogfood -- `node scripts/graphlint.js scripts/`: 19 total findings (17x R5 HIGH child_process,
   2x R4 REVIEW). Classification: 17 R5 HIGH -> false-positive relative to R5's intended scope (D1);
   2 R4 REVIEW -> false-positive, cross-function taint collision (D2); 0 true-positives. Every
   dogfood finding fell into one of these two buckets -- none required a "real code problem, fix the
   target file" response.

## Full verbatim output of `node tests/graphlint/sonnet/run-tests.js`

```
[PASS] R5-recall-eval: eval(code) flagged HIGH at the call site
[PASS] R5-recall-new-Function: new Function(...) flagged HIGH at the call site
[PASS] R5-recall-Function-ctor: Function("...") string-arg constructor flagged REVIEW
[PASS] R5-recall-exec-spawn: child_process execSync() call flagged HIGH
[PASS] R5-recall-new-require: require() of a non-builtin module seen in only 1 file flagged REVIEW
[PASS] R5-recall-dynamic-import: import("static-spec") flagged HIGH
[PASS] R5-recall-dynamic-import-computed: import(variable) flagged HIGH
[PASS] R5-precision-comment-bait: eval/new-Function/exec/require/import tokens in comments do NOT fire
[PASS] R5-precision-string-bait: eval/new-Function/exec/require/import tokens in string literals do NOT fire
[PASS] R5-precision-clean: builtin-only requires produce zero R5 findings
[PASS] R5-precision-self: graphlint.js's own R5 regex literals (eval, new Function, exec, spawn, require, import as bare source text) do not self-trip
[PASS] R6-recall: an adapter with an external effect and NO capability.json is flagged HIGH
[PASS] R6-precision: an adapter with a matching *.capability.json declared is clean
[PASS] regression-selftest: node scripts/graphlint.js --selftest is 100% green (R1-R4 corpus, no regression from R5/R6)
[FAIL] R5-scope [DEFECT]: R5 must not HIGH-flag legitimate child_process use in hash-pinned constitutional scripts/ files -- R5 fires 17x HIGH on constitutional scripts' legitimate child_process orchestration (scenario spawns replay, watchdog kills processes, gate spawns scenario, scaffold spawns workers, chaos/ci-check-pr-separation spawn subprocesses for testing/CI). Per .plans/tasks/B-graphlint.md:11 ("child_process exec/execSync/spawn* introduced in a DECISION/EVOLVABLE FILE") and .plans/graphsmith-v0.2.0-final-build-plan.md:104 ("bans ... raw exec in MACHINE-EVALUATED CANDIDATES AND IN SCAFFOLD ADAPTERS"), R5's child_process check is scoped to evolvable/candidate code -- not the constitutional orchestration layer itself. Offending: chaos.js:33, chaos.js:131, chaos.js:144, chaos.js:146, chaos.js:158, chaos.js:183, ci-check-pr-separation.js:291, ci-check-pr-separation.js:299, gate.js:358, scaffold.js:1715, scaffold.js:1743, scaffold.js:1748, scaffold.js:1753, scenario.js:319, scenario.js:338, watchdog.js:98, watchdog.js:294
dogfood classification (informational):
  [HIGH] chaos.js:33 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] chaos.js:131 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] chaos.js:144 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] chaos.js:146 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] chaos.js:158 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] chaos.js:183 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] ci-check-pr-separation.js:291 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] ci-check-pr-separation.js:299 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] gate.js:358 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] scaffold.js:1715 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] scaffold.js:1743 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] scaffold.js:1748 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] scaffold.js:1753 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] scenario.js:319 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] scenario.js:338 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] watchdog.js:98 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [HIGH] watchdog.js:294 R5: child_process exec/spawn call -- shell execution surface => scope-question -> resolved FALSE-POSITIVE (R5 out-of-scope on constitutional file; see R5-scope [DEFECT] above)
  [REVIEW] scenario.js:640 R4: routing on a clock/random-derived variable => FALSE-POSITIVE (cross-function taint-variable name collision; see FINDINGS.md D2)
  [REVIEW] scenario.js:644 R4: routing on a clock/random-derived variable => FALSE-POSITIVE (cross-function taint-variable name collision; see FINDINGS.md D2)
[PASS] dogfood-classify: every finding from `graphlint scripts/` is classified TP/FP/scope-question

15 passed, 1 failed, 0 skipped.
```

Exit code: 1 (one FAIL -- the R5-scope defect, D1, is a real, reproducible over-firing bug against the
documented intent, not a test-harness bug).
