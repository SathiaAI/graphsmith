# GraphSmith v0.2.0 — Stage 0 Frozen Contracts
Status: DRAFT — awaiting non-Anthropic panel review, then Paul's Stage 0 gate.
Once frozen, these contracts are the ONLY sync points between build workers (coordination rule 3, `references/multi-agent-coordination.md`).

| # | Contract | Governs |
|---|---|---|
| 01 | promotion-transaction.md | The single change path for all evolvable surface (I2) |
| 02 | gate4-state-machine.md | Serialized observation window + auto-rollback semantics |
| 03 | statistical-appendix.md | Normative Gate-2 statistics (confidence, multiplicity, seeds) |
| 04 | trust-boundary-matrix.md | Every boundary × artifact × trusted root × failure outcome × race control |
| 05 | threat-model.md | Named attacker classes; explicit out-of-scope statement |
| 06 | adapter-capability-schema.md | Adapter effect/idempotency declarations → kill-safety messages (I5) |
| 07 | lesson-event-schema.md | Typed events; the ONLY form harvested artifacts may take (no raw prose to proposer) |
| 08 | gate-js-api.md | gate.js public API — deterministic, zero-LLM |
| 09 | manifest-formats.md | Release + project manifests (I1 dual trust domains); adoption log format |
| 10 | honest-language.md | Banned-strings lists: honest-language + publication hygiene (lint-checkable) |
| 11 | interface-stubs.md | Per-component signatures, file ownership lanes, builder/tester assignment |
| 12 | conformance-lab-battery.md | §16 fixture repos, task battery, artifact scorers, agent matrix |

## Freeze & change control
- Contracts freeze at Paul's Stage 0 gate approval. Each file then carries `Frozen: v1.0 (date)` in its header.
- Post-freeze changes: orchestrator writes a change proposal (what/why/affected components), Paul approves, version bumps (v1.1, …), ledger row records it. Workers building against a superseded version are re-dispatched, never patched silently.
- Builders receive ONLY their component's stub (contract 11) plus the specific contracts it references — never the whole plan (minimal handoffs, SKILL.md rule 5).
- Every claim herein about existing v0.1.1 code carries a KnoSky citation (real `path:line`) or the marker **[inferring]**.

## Constitutional set (I2 — hash-pinned, unreachable by any evolution path)
`scripts/gate.js` · `scripts/verify.js` (sentinel) · `scripts/promote.js` · `scripts/event-compiler.js` · `scripts/scenario.js` · `scripts/evalenv.js` · risk policy + tunables BOUNDS (not values) · scaffolded `manager.js` + intent guards + supervisor · loaders (appendix/prompt) · CI workflow entries · this contracts/ directory itself.
