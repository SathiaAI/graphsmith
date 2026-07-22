# FINDINGS — adversarial tests of `scripts/state-store.js` (family: grok)

Lane: `tests/state-store/grok/`. All state under OS temp dirs. Executor: `node tests/state-store/grok/run-tests.js`.

## Suite results (last run)

| Case | Result |
|---|---|
| lock.steal-expired-refuse-fresh-token-mismatch | PASS |
| lock.pid-alive-stale-steal-fresh-refuse-env-gate | PASS |
| lock.renew-owner-token-mismatch | PASS |
| crash.journal-roll-forward-monotonic-no-tear | PASS |
| alpha.reserve-crash-consumes-fourth-refused | PASS |
| registry.register-sweep-live-trees-journaled | PASS |
| window.slots-N-plus-1-terminal-close-abandoned-flag | PASS |
| window.soft-flag-hard-rolling-back | PASS |
| concurrency.two-process-register-deregister | PASS |
| schema.written-valid-unknown-keys-rejected-on-read | **FAIL** (product defect) |

## Attacks and evidence

### 1. Lock: steal expired / refuse fresh / owner-token mismatch
**Result: PASS.** Stale lock (dead pid or expired mtime) is unlink-then-acquire stolen with a new `owner_token`. Held lock refuses second acquire (`LOCKED`). Release with a forged token refuses (`LOCK_OWNER_MISMATCH`). Fake on-disk lock + wrong-token release also refused.

### 2. Pid-reuse + `GRAPHSMITH_TEST_MODE` gate
**Result: PASS.** Lock with **this process’s live pid** and stale mtime is stolen. Same pid + fresh mtime is refused. With `GRAPHSMITH_TEST_MODE` unset, constructor ignores both `options.leaseMs`/`heartbeatMs` and `GRAPHSMITH_LEASE_MS`/`GRAPHSMITH_HEARTBEAT_MS` (forces 30000/5000). A 50ms-old lock is **not** stolen under forced `LEASE_MS=1` without test mode.

### 3. Crash recovery (journal intent → effect → crash before DONE)
**Result: PASS.** `_testing.crashNextMutationAfter(1)` mid multi-file `register` leaves open `MUTATION_INTENT`. Fresh store rolls forward remaining effects; registry + window slot consistent; `state_rev` monotonic. Child process exit after simulated crash recovers alpha RESERVED. Poisoning an effect file to a third hash HALTs with `AMBIGUOUS_RECOVERY`.

### 4. Alpha ledger
**Result: PASS.** Reserve then crash before complete → slot remains consumed after recover. Three slots fill; 4th → `ALPHA_EXHAUSTED`. Same family second reserve → `ALPHA_FAMILY_CONSUMED`.

### 5. Run registry / sweep / live-lease trees / journaled sweep
**Result: PASS.** Register/deregister work. Expired leases sweep to `EXPIRED` registry records and leave `list()` empty. Live runs expose `tree_id` for GC queries. Sweep appends journal `MUTATION_INTENT` whose decoded effect payload includes the swept `run_id` + `EXPIRED`.

### 6. Window slots / dispositions / abandoned → FLAG → CLOSED_FLAGGED
**Result: PASS.** Claim N slots; N+1st register gets `slot: null`. Close with active slots → `WINDOW_ACTIVE`. Terminal dispositions required; pass close → `CLOSED_PASS`. Lease-expiry abandon sets `flag`, disposition `abandoned`, close with `flagged` → `CLOSED_FLAGGED`. Soft wobble FLAGS and close forces `CLOSED_FLAGGED`. Hard fail drives `ROLLING_BACK`.

### 7. Concurrency (two hammer processes)
**Result: PASS.** Two children each perform 30 register/deregister pairs under contention (retry on `LOCKED`/`LOCK_CONTENTION`). Final registry: 60 REGISTERED + 60 DEREGISTERED, 0 live runs, every JSONL line parses, journal revs monotonic. Single-writer lock honored (contention observed via busy retries, no corrupt JSON, no lost deregisters).

### 8. Schema
**Result: FAIL (defect).** All records the store **writes** validate against `schemas/state-store.schema.json` (window, registry, anchors, alpha, rejected, rollback, journal, lock) via a zero-dep draft-2020-12 subset validator (`additionalProperties: false`, `oneOf`, enums, patterns).

**DEFECT — unknown keys not rejected on read**

| Field | Value |
|---|---|
| Severity | **HIGH** (contract/schema promise broken; hostile same-user mutator / hand-edit can inject opaque fields that would circularly plangps through CAS paths; schema `additionalProperties: false` is dead on the read path) |
| Location | `scripts/state-store.js` `parseWindow`, `parseJsonLines` (no schema gate); all `_*` readers accept any JSON shape beyond thin checks |
| Evidence | Inject `unexpected_hostile_key` into `window.json`; `window.get()` returns successfully instead of `CORRUPT_STATE` / schema reject |
| Contract | Task requirement + `schemas/state-store.schema.json` closed records; contract 01 detect-and-HALT posture for hostile mutation warrants reject-or-HALT, not silent accept |
| Proposed fix | After JSON.parse of every state record (window blob, each JSONL line, lock, journal), validate against the published schema (or a frozen allow-list of keys per `record_type`). Reject unknown keys with `CORRUPT_STATE`. Optionally strict-mode strip is **not** sufficient — unknown keys must fail closed. Share one validator helper with CI selftest. |

## Secondary notes (not suite failures)

- Lock file name is `state.lock` (implementation); contract 01 prose says `promotion.lock`. Naming divergence for promote integration — out of scope for this module’s internal tests unless dual paths appear.
- Acquire path throws `LOCKED` rather than blocking/retrying long; callers must retry. Concurrency remains correct under cooperative retry; no silent dropped writes observed.
- Sweep journals via generic `MUTATION_INTENT`/`MUTATION_DONE` payloads (not a distinct `SWEEP` record type). Contract 01’s “swept with a journal record” is satisfied by effect bas64 content; a typed `SWEEP{run_ids:[…]}` journal record would be clearer for auditors (cosmetic / MEDIUM docs gap, not a FAIL).

## Honest coverage — what was NOT tested

- Hostile mutator races in **every** interval of a multi-effect commit while the lock holder is live (kill other writers mid-rename); only single-process simulated crash + post-crash poison.
- Platform rename-replace under open handles (Windows MoveFileEx matrix); directory fsync failures.
- Wall-clock window cap auto-close (`max_window_wall_time`) full endurance path (code path exists; we did not fake `created_at` far in the past in this suite).
- GC tree deletion itself (lives in promotion/GC, not state-store list API).
- Torn partial last JSONL line recovery beyond unit logic (`parseJsonLines` early break) with multi-MB files.
- Full ajv draft-2020-12 fidelity (unevaluatedProperties, dynamic refs); validator is a minimal subset matching this schema.
- `proc_start_hint` used only as opaque string — true OS process-start identity bind not verifiable from here.
- Network / non-local filesystems; concurrent access across machines.
- Interaction with `promote.js` / ACTIVE pointer / adoption-log (different modules).
- Performance under thousands of registry lines / journal growth / compaction.
- Read-only observers without lock (there is no lock-free reader API; every call takes the writer lock).
