# FINDINGS — event-compiler adversarial review (grok)

**Target:** `scripts/event-compiler.js`  
**Lane:** `tests/event-compiler/grok/` ONLY  
**Runner:** `node tests/event-compiler/grok/run-tests.js`  
**Contract:** `contracts/07-lesson-event-schema.md`  
**Verdicts:** from emitted bytes (`compile` / `events-proposer.jsonl` / stats), never log claims.

## Summary

| Result | Count |
|--------|------:|
| PASS   | 51 |
| FAIL   | 0 |
| SKIPPED| 0 |
| TOTAL  | 51 |

**Exit code: 0**

Compiler defects D1–D7 are closed (orchestrator-verified). No reopen of `scripts/` from this lane.

## A2 scope amendment (test-only)

**Prior false FAIL:** `A2.static-no-evidence-in-model-paths` flagged `scripts/migrate.js` solely because it references `events-evidence`.

**Verdict:** Not a code leak. `migrate.js` is F16 redaction infra — it legitimately reads/writes `events-evidence.jsonl` off the model path. It does **not** feed evidence map real values into a proposer/mining LLM context.

**Real constitutional property asserted now:**
1. Proposer-view bytes (memory + `events-proposer.jsonl`) contain no evidence-map `real_value`s.
2. Static scan covers **model-context path** files only (`evolve.js` and any proposer/prompt/mine builder that could assemble LLM input) — requires those paths import proposer view only, never evidence map / `events-evidence`.
3. Explicit exclude set: `event-compiler.js` (writer), `migrate.js` (F16 redaction).

## migrate.js model-path leak?

**No.** No loud reopen. `migrate.js` is not on the proposer-prompt path.

## Reproduce

```bash
node tests/event-compiler/grok/run-tests.js
```

Temp dirs only; no git; zero-dep CJS. Lane did not modify `scripts/`.
