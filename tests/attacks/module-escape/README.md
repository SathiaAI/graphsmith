# Module-escape suite

Independent adversarial checks that decision-path constitutional scripts honor the zero-dep / no-eval / no-network / no-clock-in-decision posture.

## Scope

Scripts under test (read-only inspection + in-process API calls):

- `scripts/gate.js`
- `scripts/verify.js`
- `scripts/promote.js`
- `scripts/state-store.js`
- `scripts/loaders.js`
- `scripts/manifest.js`

Temp dirs only for any fixture state. Never mutates the repo’s real `.graphsmith/`. No packages installed. No intentional outbound network.

## Checks

| Check | Claim |
|---|---|
| Non-builtin `require` | Decision scripts only `require` Node builtins or relative paths |
| `eval` / `Function` | Absent from decision script bodies (comment/string-stripped scan) |
| `child_process` | Absent except gate’s optional corpus spawn; in-memory Gate 2 never needs it |
| Network APIs | No `net`/`http`/`https`/`fetch`/etc. requires or calls |
| Clock/random in decisions | `gate1Static` / `decideGate2` / `verifyTree` / loader core free of `Date.now`/`Math.random` driving branches |
| Payload smuggle | `eval`/`Function` strings in candidates rejected by Gate 1; `require('net')` treated as data (not executed) |
| Dual-run | Same Gate 2 bundle → identical decision object |
| `NODE_PATH` smuggle | Hostile package on `NODE_PATH` is not executed by gate1 |
| Gate `--selftest` | Independent mirror that the shipped selftest still exits 0 |

## What is NOT covered

- Runtime monkey-patching of `Module.require` by a privileged same-process attacker after load (A1 detection is dual-manifest / verify domain, not this suite).
- Full JS parser soundness (comment stripper is conservative).
- promote/state-store using `Date.now` for **lease/lock metadata** and window wall-clock (explicitly non-decision for Gate 1–3 outcomes; documented allowed).
- Model-level execution of worker code inside user workflows.

## Verdict rule

Escape/refusal claims use **static parse results, API return objects, marker files on disk, and process exit codes** — never stderr log strings as the oracle.

## Run

```bash
node tests/attacks/module-escape/run-tests.js
```

Exit `0` if posture holds. Exit `1` if a real hole is found (BLOCKING — do not paper over).
