# TOCTOU race harness

Time-of-check / time-of-use attacks against promote + verify, contained in temp fixtures.

## Scope

- Temp project roots only (never repo `.graphsmith/`).
- Interleaves promote/recover calls with **direct filesystem mutation** from a simulated second writer.
- Zero-dep CJS. No real multi-host network. No packages.

## Guarantee under test

1. **promote HALTs** (error `code === "HALT"` / CLI exit 3) with evidence when ACTIVE or adoption-log head mutates after `TX_BEGIN` — never silently overwrites.
2. **Staged tree mutation** after `STAGE_DONE` is detected (`verifyTree` fails; recover refuses to install the poisoned tree as success).
3. **verify never reports verified** (`failure_domain === "none"` / exit 0) on a mid-flight-mutated ACTIVE tree.
4. **Stale CAS** (`expected_active_sha`) refuses with `STALE_PROPOSAL`.
5. **Lock** — second process cannot complete promote while the state lock is held.

## What is NOT covered / UNAVAILABLE

| Case | Why |
|---|---|
| True multi-process rename-vs-rename under open handles | Inherently flaky / unprovable in a single-threaded interleaved harness. Marked **UNAVAILABLE**, never green. Platform probe lives in `verify --platform-probe`. |
| Cross-host NFS cache races | Out of scope for local zero-dep scripts. |
| Privileged A6 rewriting lock + journal + both manifests mid-flight | Out of scope (contract 05). |

## Verdict rule

State assessments come from **on-disk ACTIVE / journal / adoption log / verify report fields / `error.code` / process exit code**. Log strings are never the oracle.

## Run

```bash
node tests/attacks/toctou/run-tests.js
```

Exit `0` if all testable guarantees held (UNAVAILABLE does not fail). Exit `1` if any silent-success race.
