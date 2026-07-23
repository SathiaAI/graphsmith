# Contract 08 — gate.js Public API
Status: DRAFT. Deterministic, zero-LLM, constitutional (I2). No network. No clocks/randomness in any decision path (SKILL.md rule 4). Implements contract 03 exactly.

## Module API (`scripts/gate.js`, CommonJS like all v0.1.1 scripts [KnoSky: scripts/scaffold.js:8-9])
```js
// Gate 1 — static screen. candidate: {id, kind: "doc"|"knob"|"code", edits: TypedEdit[], fingerprint}
gate1Static(candidate, ctx) -> { pass: bool, findings: Finding[], evidence: EvidenceRef }
// checks: fence write-set, typed schema, contradiction screen (advisory composes), injection screen
// (human-promoted prose only), appendix caps, fingerprint-vs-rejected-buffer, sentinel pass.

// Gate 2 — behavioral. Runs the paired seeded replay per contract 03 in the I3 profile for candidate.kind.
gate2Behavioral(candidateId, { corpusPath, profile, cycleSeed }) ->
  { pass: bool, tier: 1|2|3, hard: {violations: []}, slices: SliceResult[],
    primary: { n, n_d, wins, p, lowerBound, noiseFloor }, evidence: EvidenceRef }

// Gate 3 — adoption packet (pure function; APPLYING it is promote.js, contract 01).
gate3Prepare(candidateId) -> { diff, plainEnglish, evidence, inverse: TypedEdit[], reversible: bool,
                               autoRollbackEligible: bool /* doc|knob + compatible schemas only */ }

// Gate 4 — window ops (state machine per contract 02; rollback delegates to promote.js).
gate4Admit(txid, opts) / gate4Observe(runResult) / gate4Close() -> WindowState
```
`TypedEdit`: `{ file, anchor, op: "replace|insert|delete|set-knob", payload, schema_ref }` — bounded edits, never rewrites (plan §1 design law). All types carry `schema_version`.
**Alias translation (P2-Gemini-3):** the proposer emits TypedEdits addressed by ALIAS (`file: "p02"`, per contract 07's opaque view). A trusted pre-gate translation layer in evolve.js maps aliases → canonical paths via the cycle's evidence map BEFORE gate1Static validates; a proposer-emitted literal path (anything not matching the alias grammar) is an AUTOMATIC Gate-1 reject — a real path in proposer output is by construction hallucinated or leaked.

## CLI
```
node scripts/gate.js 1 --candidate <path>          exit 0 pass / 1 reject / 2 error
node scripts/gate.js 2 --candidate <id> --profile standard|container
node scripts/gate.js 3 --candidate <id> --prepare  (writes the adoption packet for human review)
node scripts/gate.js 4 --status|--observe <runId>
```
Exit codes: 0 pass · 1 fail/reject (with findings) · 2 internal error (fail-closed) · 3 HALT (trusted-core defect detected mid-gate). Machine-readable JSON on stdout with `schema_version`; human explanation on stderr.

## Decision engine vs replay runner (v2 — GPT-25)
gate.js is the **pure decision engine**: it consumes a recorded, hashed **evidence bundle** (scenario outcomes, invariant results, slice tables) and decides. The **replay runner** is scenario.js: it executes workflows in the I3 profile and MAY be stochastic where model providers are (contract 03 acknowledges this); it produces the bundle and its hash. Gate 2 = scenario.js produces → gate.js decides.

## Determinism guarantees (mutation-tested)
- Same evidence bundle (same hash) → byte-identical decision output. Replay stochasticity is a property of the runner and is disclosed, never averaged away (contract 03 pinning applies).
- Persistence split: gate.js writes ONLY `.graphsmith/gate-evidence/`; window state belongs to window-store.js; rejected buffer/alpha ledger writes go through the state API (contract 11 lanes) — the write fence is enforceable because ownership is exclusive.
- No LLM call exists in gate.js or anything it requires (lint-enforced: the R5 static screen applies to the constitutional set too). scenario.js invokes workflows that call models — inside workers only, per SKILL.md rule 1.
