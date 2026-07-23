# Event Compiler Adversarial Test Findings

This suite attacks `scripts/event-compiler.js` against `contracts/07-lesson-event-schema.md` and `schemas/lesson-event.schema.json`. It drives `compileToFiles()` with temporary fixtures and makes verdicts from the emitted `events-proposer.jsonl` and `events-evidence.jsonl` bytes.

Run it with:

```sh
node tests/event-compiler/gpt-sol-pro/run-tests.js
```

## Verdict

**BLOCKING.** The constitutional injection barrier does not hold for all authenticated inputs. A producer-controlled string in an effective adoption record's `seq` reaches `events-proposer.jsonl` verbatim as `ord`.

The final run produced `7 PASS, 13 FAIL, 0 SKIPPED` and exited nonzero.

## Coverage And Results

| Attack | Result |
| --- | --- |
| Injection-shaped run-log step, embedded `run_id`, evidence path, invalid code, hostile counter key, bidi/Unicode text, and 16 KiB string | PASS: 689 emitted proposer bytes were recursively diffed against all seven values. No producer value appeared; all fields satisfied the explicit alias/enum/number allowlist. |
| Alias collisions using producer values `r01`, `s01`, and `p01` | PASS: coincident literals occurred only in `run_ref`, `step_ref`, and `evidence_ref` alias slots; no second producer-derived field appeared. |
| Injection-shaped string in authenticated adoption `seq` | **FAIL / BLOCKING:** the exact producer string appeared in emitted proposer bytes as `ord`. |
| Authorized adoption schema conformance | **FAIL:** emitted record has `run_ref:null`, violating the required `^r[0-9]{2,6}$` field. |
| Evidence-map real values versus proposer bytes | PASS: all five emitted real values were absent from proposer bytes. |
| Static and dynamic proposer-prompt isolation | **FAIL:** no script outside `event-compiler.js` consumes `events-proposer.jsonl`/`proposerView`; therefore there is no actual proposer prompt-builder path on which to prove the required dynamic isolation. No script was found importing the evidence map into a proposer path, but absence of the required consumer is not a valid dynamic proof. |
| Run-log `adoption`, `rollback`, and `human_correction` source authentication | PASS: all three were rejected, counted, and the emitted proposer file was empty. |
| Unanchored run-log `run_halt` | **FAIL:** harvest was invalid and proposer bytes were empty, but `stats.rejected` remained `0` instead of counting the rejection. |
| Broken per-line hash chain with a second valid run | **FAIL / BLOCKING:** `harvest_valid:false`, but 689 proposer bytes from the valid run were still emitted. |
| Missing anchor with a second valid run | **FAIL / BLOCKING:** `harvest_valid:false`, but 689 proposer bytes from the valid run were still emitted. |
| Truncated anchored chain with a second valid run | **FAIL / BLOCKING:** `harvest_valid:false`, but 689 proposer bytes from the valid run were still emitted. |
| Selective deletion of `run_halt` with a second valid run | **FAIL / BLOCKING:** the cycle was marked invalid but still emitted 689 proposer bytes. |
| Selective deletion of `budget_breach` with a second valid run | **FAIL / BLOCKING:** the cycle was marked invalid but still emitted 689 proposer bytes. |
| Selective deletion of `tripwire` with a second valid run | **FAIL / BLOCKING:** the cycle was marked invalid but still emitted 689 proposer bytes. |
| Selective deletion of authenticated rollback state | **FAIL / BLOCKING:** deleting the only rollback-bearing `window.json` changed a rollback harvest into `harvest_valid:true` with no detection. |
| Same-input determinism | PASS: 1,176 proposer-plus-evidence bytes were identical across two emissions. |
| Timestamp independence | PASS: reversing hostile source timestamps changed neither proposer bytes/order nor evidence bytes/order. |
| Published schema closure and ordinary run-log output conformance | PASS: event, stats, evidence, and per-type counter schemas declare `additionalProperties:false`; two ordinary emitted events passed explicit zero-dependency type, bound, pattern, key, code, and counter checks. |
| Malformed non-safety record | **FAIL:** invalid code, string timestamp, and string counter were silently replaced with defaults and emitted; `quarantined` stayed `0`. |
| Escaping `evidence_path` | **FAIL:** `../outside/secret.txt` appeared in emitted evidence-map bytes and `dropped_refs` was not incremented. |

## Defects

### [BLOCKING] Authenticated adoption `seq` is a direct proposer-string injection

`extractAdoptionEvents()` assigns `ord: entry.seq || 0` without requiring a bounded integer (`scripts/event-compiler.js:313`). The proposer serializer then copies `ev.ord` directly (`scripts/event-compiler.js:525`). The emitted bytes contained the exact attack string `ADOPTION_SEQ__ignore_previous_instructions`.

Proposed fix: schema-validate every adoption-log entry before extraction. Accept `seq` only when it is a bounded safe integer; quarantine malformed non-safety entries by reference and increment `quarantined`. Prefer a compiler-assigned ordinal rather than copying a source ordinal into the proposer view.

### [BLOCKING] `harvest_invalid` does not suppress already collected proposals

Integrity failures set `harvestValid = false`, but the compiler continues sorting and serializing authenticated events (`scripts/event-compiler.js:497-533`). A broken chain, missing anchor, truncation, or selective safety-record deletion in one run therefore allows records from another run to reach `events-proposer.jsonl`. Each attack emitted 689 bytes despite `harvest_valid:false`.

Proposed fix: make invalidity a cycle-wide fail-closed gate before alias assignment/serialization. When `harvestValid` is false, emit an empty proposer view and no evidence mappings, retaining only closed numeric stats for operator diagnosis. Add mixed good-plus-bad fixtures so a test cannot pass merely because the only run was discarded.

### [BLOCKING] Rollback deletion has no authenticated presence/integrity proof

Rollback extraction reads the current optional `window.json` (`scripts/event-compiler.js:170-178`, `329-363`). If that file is deleted, `readWindow()` returns `null` and the compiler treats the absence as a valid no-rollback state. There is no anchored append-only record proving that a rollback was expected, so selective deletion is indistinguishable from no rollback.

Proposed fix: harvest rollback from an authenticated append-only state-store ledger with a trusted head/count anchor, or add equivalent integrity metadata outside the deletable record. Missing/truncated state relative to that anchor must set `harvest_invalid` and suppress all proposals.

### [MAJOR] Authorized adoption records violate the published proposer schema

State-derived adoption and rollback events set `runRef: null` (`scripts/event-compiler.js:311`, `347`), and serialization emits that null as required `run_ref` (`scripts/event-compiler.js:523`). The schema requires an opaque run alias matching `^r[0-9]{2,6}$`.

Proposed fix: assign compiler-owned run aliases to every event source, including state sources, before serialization. Validate every completed proposer record against the frozen schema and fail loudly before writing bytes.

### [MAJOR] Malformed non-safety records are best-effort normalized, not quarantined

Unknown codes become the first enum member, invalid counter values become zero, and invalid `delta_ms` becomes zero (`scripts/event-compiler.js:257-273`). The `quarantined` counter is initialized but never incremented (`scripts/event-compiler.js:386`, `598`). This destroys evidence provenance and can turn attacker-selected malformed data into apparently valid lessons.

Proposed fix: validate the complete source event before normalization. For a malformed non-safety event, emit no proposer event, retain only a safe opaque quarantine reference, and increment `quarantined`. A malformed safety event must invalidate the whole harvest.

### [MAJOR] Evidence paths are charset-checked but not containment-checked

`evidence_path` is slash-normalized and checked only against a permissive character regex (`scripts/event-compiler.js:565-577`). `../outside/secret.txt` therefore survives into `events-evidence.jsonl`; no `realpath` or project-root containment check occurs.

Proposed fix: resolve the target against the allowed project/run evidence root, canonicalize with `realpath`, require containment using path-segment-aware comparison, and emit only the canonical repo-relative path. Drop and count absolute paths, `..` escapes, missing targets, and symlink/junction escapes.

### [MAJOR] Required proposer prompt-builder integration is absent

A static scan found no script outside `event-compiler.js` consuming `events-proposer.jsonl` or `proposerView`. Consequently the contract claim that the proposer prompt builder imports only the proposer view cannot be dynamically exercised, and there is no end-to-end guarantee that a future caller will not pass `evidenceMap` alongside it.

Proposed fix: add one explicit proposer-context builder whose interface accepts only serialized proposer-view bytes plus closed aggregate counts. Add an integration test that traps model-call arguments and proves no `events-evidence.jsonl` bytes or evidence-map real values enter context.

### [MINOR] Unanchored run events are not counted as source-auth rejections

An unanchored `run_halt` correctly makes the harvest invalid and emits no proposer bytes, but it is discarded before source authentication and leaves `stats.rejected` at zero (`scripts/event-compiler.js:430-437`, `482-499`). This violates the required rejected-and-counted audit behavior.

Proposed fix: increment a closed rejection counter for records discarded because their run lacks a valid trusted anchor, while still marking the cycle invalid. If distinct causes are needed, add schema-closed numeric counters rather than producer strings.

## Honest Coverage Gaps

The suite did not allocate enough events to cross the six-digit alias limit, simulate concurrent mutation during reads, test symlink/junction escapes in evidence paths, or invoke a third-party JSON Schema validator. It did not test scenario-result and Gate-3 packet happy paths because the compiler has no extraction path for those sources. The explicit validator covers every emitted event field, closed top-level keys, safe integers, aliases, hashes, closed codes, and closed counter keys; it is not a general JSON Schema implementation.
