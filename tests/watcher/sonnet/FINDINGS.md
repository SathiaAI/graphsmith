# Watcher (Advisory LLM Watcher) — adversarial test FINDINGS

- **Tester:** Claude Sonnet (adversarial, cross-family vs GLM-4.7 builder)
- **Target:** `scripts/watcher.js`
- **Suite:** `tests/watcher/sonnet/run-tests.js`
- **Result:** PASS=34 FAIL=0 SKIPPED=0 (exit 0), Windows win32, Node v24.18.0

## Verdict: all four required safety properties HELD

- **OFF by default** — strict `enabled === true` gate rejects every truthy-coercion attempt
  (`"true"`, `1`, `"yes"`, `{}`, `[]`); disabled path returns before touching `projectRoot`/fs at
  all (proven with a pathological path that would throw if touched); CLI zero-args and
  `--enabled false` both fail closed with disk untouched.
- **Structured-input-only** — `raw_prompt`/`evidence_map`/`event_id`/`evidence_ref` structurally
  cannot reach the model-call batch (checked at the actual batch object via a spy adapter, not just
  final JSON); the sibling `events-evidence.jsonl` is never read; malformed JSONL fails loud.
- **Flag-only / no authority** — `createFlag` is a true 8-key allowlist; an adversarial battery of
  `action`/`command`/`trigger`/`execute`/`halt`/`promote`/`adopt`/`authority` keys, a `label`-override
  attempt, and a `__proto__` pollution attempt all failed to escape it; zero disk side effects, no
  `state.lock`, no cross-run contamination under concurrency.
- **Batched, no real network** — batch capped (default 100, custom sizes respected), exactly one
  `batchAnalyze` call per `watch()` invocation, none when zero events exist; no
  `http`/`https`/`net`/`dns`/`fetch` reference anywhere; a non-stub adapter throws a config error
  rather than attempting a call.

## Defects reported

**D1 — MEDIUM (defense-in-depth).** `watcher.js` only checks `code` is a string, `counters` is an
object, and `run_ref`/`step_ref`/`fingerprint` are strings — it never re-enforces
`event-compiler.js`'s closed `TYPE_CODES` enum, numeric coercion for `counters` values, or
`EVIDENCE_CHARSET` bounds on identifier fields. Confirmed live: an injection-shaped string placed in
`code`, in a `counters` value, in `run_ref`/`step_ref`/`fingerprint`, or in any state-dir jsonl
record's `.state` key (not just `window.json`) reaches the model-call batch verbatim. Per
`contracts/04-trust-boundary-matrix.md`, `events-proposer.jsonl` sits at the UNTRUSTED B4 boundary
and is safe only by convention (no signature/provenance ties it to having gone through
`event-compiler.js`'s `compile()`); watcher provides zero defense-in-depth if that boundary is ever
bypassed. Capped at MEDIUM (not CRITICAL) because the watcher's *output* stays flag-only /
no-authority regardless — indirect-injection-into-an-advisory-summary, not a path to system control.
Fix: import/mirror `TYPE_CODES`, numeric-coerce `counters`, and bound the identifier fields the same
way `event-compiler.js` already does.

**D2 — LOW.** When events exceed `maxBatchSize`, the excess is silently dropped for that call (not
queued/retried), and `events_processed` reports only the capped count with no `events_dropped` stat.
Not a safety defect (advisory-only, off-by-default), but a data-fidelity gap worth a stats field.

## Note (not a defect)

`node scripts/watcher.js --project-root <dir>` with no `--enabled` flag hits a CLI arg-count guard
and exits 2 with usage rather than running with the implicit `enabled=false` default — an ergonomics
rough edge, but it fails closed (never prints `enabled:true`), so it doesn't affect any safety
property.

## Verbatim suite output

```
# sonnet adversarial watcher (Advisory LLM Watcher) suite
# target=F:\Users\PaulPoulose\GraphSmith\graphsmith\scripts\watcher.js
# platform=win32 node=v24.18.0
PASS	OFF/bare-default-nothing-happens
PASS	OFF/poisoned-disk-and-malicious-adapter-inert	adapter never invoked; corrupt window.json ignored
PASS	OFF/strict-boolean-true-required	rejected truthy non-true values: "true",1,"yes",{},[],"TRUE"
PASS	OFF/garbage-project-root-no-throw	disabled path never touches projectRoot/fs
PASS	OFF/cli-zero-args-exit-2	exit=2
PASS	OFF/cli-no-enabled-flag-never-silently-enabled	exit=2
PASS	OFF/cli-explicit-false-inert	exit=0
PASS	STRUCT/raw_prompt-evidence_map-never-in-batch	confirmed at model-call boundary, not just final output
PASS	STRUCT/no-evidence-linkage-fields-in-batch
PASS	STRUCT/batch-event-keys-exact-allowlist	code,counters,delta_ms,fingerprint,lossy,run_ref,seq,step_ref,type
PASS	STRUCT/FINDING-code-field-not-enum-closed	DEFECT D1
PASS	STRUCT/FINDING-counters-values-not-numeric-closed	DEFECT D1 (same root cause)
PASS	STRUCT/FINDING-run_ref-step_ref-fingerprint-unbounded	DEFECT D1 (same root cause)
PASS	STRUCT/FINDING-state-field-unclosed-any-jsonl-file	DEFECT D1 (same root cause)
PASS	STRUCT/type-field-properly-closed-fails-loud	out-of-enum type rejected via thrown validation error
PASS	STRUCT/events-evidence-file-never-read
PASS	STRUCT/corrupt-jsonl-line-fails-loud
PASS	AUTH/malicious-adapter-authority-keys-stripped	category,context,label,message,record_type,schema_version,severity,timestamp_ms
PASS	AUTH/label-cannot-be-overridden-by-model	advisory, unverified
PASS	AUTH/no-prototype-pollution-via-flag-context
PASS	AUTH/adversarial-flag-battery-no-authority-leak	flags=4
PASS	AUTH/no-disk-side-effects	files=2
PASS	AUTH/no-lock-file-created
PASS	AUTH/no-cross-run-contamination-under-concurrency
PASS	BATCH/default-cap-100-single-call	events_processed=100
PASS	BATCH/FINDING-overflow-silently-dropped-not-queued	sent=10 dropped=110 of 120 (single call)
PASS	BATCH/custom-max-batch-size-respected
PASS	BATCH/exactly-one-model-call-per-watch-invocation
PASS	BATCH/no-events-no-model-call
PASS	NET/no-network-primitive-in-source	grepped for http(s)/net/dns require, fetch, XHR, .connect()
PASS	NET/non-stub-adapter-throws-config-error-not-network-attempt
PASS	NET/zero-config-default-adapter-safe
PASS	NET/cli-selftest-bounded-time-and-passes	elapsed=48ms tests=6
PASS	NET/selftest-subchecks-all-pass	6 sub-tests
# summary	PASS=34	FAIL=0	SKIPPED=0	total=34
```
