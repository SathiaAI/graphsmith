# Assurance Adversarial Findings: gpt-sol-pro

## Verdict

FAIL: 14 checks passed and 3 checks failed. The failures are reproducible from temp-only fixtures with verdicts derived from process exits and files written by the probes.

## Findings

### C1: Container-profile tools are spawned directly on the host

- Severity: CRITICAL
- Check: `B10.available-container-delegated`
- Evidence: a controlled available-container handle exposed `runUntrustedCode()`, but `ext-tool-runner` never called it. The malicious probe ran through a direct host process, created `host-process-ran.txt`, and returned runner status `pass`.
- Root cause: `openProfile()` discards the profile's execution method at `scripts/ext-tool-runner.js:157-169`; `runTool()` then invokes `spawnSync(cmd, args, ...)` directly at `scripts/ext-tool-runner.js:362-372`. The container implementation's enforcement exists behind `runUntrustedCode()` at `scripts/evalenv.js:679-695`, so that enforcement is bypassed.
- Impact: when a container runtime is available, a BYO/untrusted tool can run as an ordinary host child with host networking and writable host paths. Merely using the disposable copy as `cwd` is not B10 containment.
- Fix: preserve the profile execution API and require untrusted tools to execute only through `runUntrustedCode()`. Require an explicit pinned image or return `unavailable`; never fall back to host `spawnSync`. Add a real-runtime integration test that verifies network denial, read-only source behavior, and absence of host writes.

### H1: A nonzero tool exit can self-report a passing result

- Severity: HIGH
- Check: `tool.nonzero-exit-cannot-pass`
- Evidence: a tool emitted a schema-valid report with status `pass`, then exited `7`. The runner recorded `exit_code: 7` but status `pass`, and the CLI exited `0`.
- Root cause: `normalizeReport()` accepts the report enum before considering the exit at `scripts/ext-tool-runner.js:238-247`; registry aggregation and CLI exit then trust that status at `scripts/ext-tool-runner.js:407-408` and `scripts/ext-tool-runner.js:656-657`.
- Impact: a broken or malicious tool can forge a passing battery despite the documented nonzero-exit contract. `assure` can consequently emit a passing packet for a failed external tool.
- Fix: make a nonzero or missing process exit authoritative. A report may refine nonzero into `fail` versus `error`, but it must never become `pass` or `skip`. Add CLI regressions for report-pass/exit-nonzero and report-fail/exit-zero combinations.

### H2: `redteam --project` does not test the supplied workflow

- Severity: HIGH
- Check: `redteam.project-architecture-detected`
- Evidence: the temp workflow first wrote `control-state.json` proving an injected `next_step` reached `__admin__`. `redteam --project <fixture>` still returned a passing report with no check linked to that project or state.
- Root cause: the CLI accepts and passes `project` at `scripts/redteam.js:671-681`, but `runRedteam()` does not consume `options.project` at `scripts/redteam.js:444-473`. Its architecture checks are hard-coded simulations, not checks of the supplied workflow.
- Impact: `assure` can mark `X_adversarially_tested.eligible` from synthetic cases even when the target workflow demonstrably routes attacker data into control flow.
- Fix: either inspect the target using deterministic project-linked checks or report the target assessment as `unavailable`. Executable project probes must use the repaired B10 container path. Do not set project capability eligibility when only generic self-cases ran.

## Attack Results

| Attack | Result | Evidence basis |
|---|---|---|
| Untrusted/BYO tool with no runtime | PASS | `unavailable`, `executed:false`, no filesystem/effect marker |
| BYO executable through redteam with no runtime | PASS | redteam preserved unavailable state; marker absent |
| Available-container execution delegation | FAIL | profile method not called; host marker created |
| Injection-shaped and oversized report fields | PASS | fields remained opaque and bounded; marker absent; CLI failed |
| Report says pass while process exits 7 | FAIL | runner status pass; CLI exit 0 |
| Vulnerable project supplied to redteam | FAIL | on-disk injected route present; no project-linked failure |
| Declarative BYO architecture case | PASS | actual route came from admitted state, not attacker strings |
| Redteam scope boundary | PASS | architecture-only limitation and floor language emitted |
| Passing test fixture twice | PASS | identical report hash and per-check evidence |
| Failing test fixture | PASS | exit 1 with structured failed IDs |
| Smoke effect repeat | PASS | one temp-only effect record after two runs |
| Assure minimal packet | PASS | battery, platform, tool versions, and Phase-E stub disclosure present |
| Assure BYO containment | PASS | unavailable state propagated; marker absent |
| Honest-scope output scan | PASS | no forbidden List-A claim appeared in captured CLI output |
| Harness no-escape | PASS | repository hash snapshot identical before and after execution |

## Coverage Limits

- No reachable Docker/Podman runtime was used. The available-container control-flow defect was proven with a deterministic profile test double and an on-disk host marker; actual runtime network denial and read-only mounts still require a real-container integration run after the delegation fix.
- No public network endpoint was contacted. The refused malicious tool contained an HTTP attempt, and absence of execution was established from state and marker files.
- Scenario regression internals were not repeated because this suite isolates `test.js` with `--no-scenario`; deterministic unit/smoke good and bad outcomes were exercised directly.
- Repository no-escape detects content creation, deletion, and modification outside `.git`, `node_modules`, and `.runs`; temp fixtures were deleted after every run.

## Reproduction

```sh
node tests/assurance/gpt-sol-pro/run-tests.js
```

Expected current exit: `1`, because all three defects are asserted as regression failures.
