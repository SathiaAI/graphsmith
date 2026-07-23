# Contract 07 — Typed Lesson-Event Schema (v2 — opaque IDs + authenticated sources)
Status: DRAFT v2 (post-panel-pass-1: GPT-13/14/15, Gemini-3). The ONLY representation in which harvested artifacts reach the proposer.

## Two outputs, hard-split (GPT-13 — the core v2 change)
1. **Proposer view** (`events-proposer.jsonl`): what the mining/proposal LLM sees. Contains ONLY: closed enums, numbers, and **opaque compiler-assigned aliases** (`step_ref: "s01"`, `run_ref: "r03"`, `path_ref: "p02"`). NO raw step names, run IDs, paths, or any producer-controlled string ever appears here — instruction-shaped identifiers (`step: "ignore_previous_instructions"`) cannot reach model context, because no producer-chosen string survives into this view.
2. **Human evidence map** (`events-evidence.jsonl`): alias → real (run_id, step, path:line), charset-checked (`^[A-Za-z0-9._:/-]{1,256}$` — applied to run_id too, Gemini-3), for human review of proposals. Never placed in model context by any GraphSmith code path (lint-checked: the proposer prompt builder imports only the proposer view).

## Event record (published JSON Schema ships as `schemas/lesson-event.schema.json` — GPT-15; `additionalProperties: false`; canonical JSON serialization; all ints bounded, all numbers finite)
```json
{ "schema_version": "1.0", "seq": "int (required, total order)", "event_id": "sha256(run_ref+seq)[:16]",
  "run_ref": "^r[0-9]{2,6}$", "step_ref": "^s[0-9]{2,6}$",
  "ord": "int — compiler-assigned ordinal within run", "delta_ms": "int — offset from run start (P2-GPT-9: NO source timestamp string in the proposer view; real ISO ts lives only in the evidence map)",
  "type": "run_halt | budget_breach | tripwire | retry_exhausted | step_failure | corrupt_checkpoint | lock_contention | scenario_fail | human_correction | adoption | rollback",
  "code": "closed per-type enum (e.g. halt.unresolved_side_effect, budget.max_wall_time)",
  "counters": "closed per-type object schema — no free keys (GPT-15)",
  "lossy": "bool (source value replaced by code)", "evidence_ref": "^p[0-9]{2,6}$ (alias)",
  "fingerprint": "sha256(normalize(type+code+step_ref))  // EVENT fingerprint — distinct from the candidate-semantic fingerprint (contract 02)" }
```
Companion records (also schema'd): `compiler_stats` (counts incl. `skipped`, `quarantined`, `dropped_refs`) and the evidence-map entry.

## Source authentication (GPT-14)
| Event type | Sole authorized producer (trusted root) |
|---|---|
| adoption, rollback | `.graphsmith/state/adoption-log.jsonl` + window store ONLY (contract 01/02 artifacts) — never run logs |
| human_correction | Gate-3 packet decisions recorded by promote.js — never run logs |
| run_halt, budget_breach, tripwire, retry_exhausted, step_failure, corrupt_checkpoint, lock_contention | manager-written run records. Phase B managers write a per-run hash chain (each log line carries prev-hash); **the chain head + expected terminal status are anchored in `.graphsmith/state/run-anchors.jsonl` (state-store, outside the run directory) at run registration/deregistration — the compiler verifies against the ANCHOR, not the checkpoint (P2-GPT-8: checkpoints are untrusted)**. Missing anchor, absent terminal record, or truncated chain → that run's harvest is invalid. Honest scope: a same-user attacker who rewrites BOTH the run logs and the state ledger is class A1 — detected at best, not prevented (contract 05); this defense targets injected content, partial tamper, and accidental corruption |
| scenario_fail | scenario.js result files (hash-pinned evaluator) |
A record of a type arriving from a non-authorized source is REJECTED + counted. **Safety-relevant integrity failures invalidate the harvest cycle** (not merely a counter): any broken/missing chain segment, or any skipped record of types {run_halt, budget_breach, tripwire, rollback}, marks the cycle `harvest_invalid` — no proposals from partial adverse evidence (selective-deletion defense, GPT-14/16).

## Compiler rules (event-compiler.js — constitutional)
1. Inputs read as DATA; nothing evaluated/executed; nothing passed to an LLM raw.
2. Determinism: same inputs → byte-identical outputs (stable sort by **(run_ref, ord, seq)** — compiler-assigned fields only; source timestamps never influence proposer-view ordering — P3-7; no clocks/randomness).
3. `evidence_ref` targets canonicalized (realpath, repo-relative); escapes dropped + counted.
4. Malformed non-safety records: quarantined by reference + counted — never best-effort parsed.
5. Proposer isolation (B5/B6): the proposer consumes `events-proposer.jsonl` + aggregate counts ONLY.
6. Sanitizer (defense-in-depth): rejects any proposer-view record with non-schema keys, out-of-range values, or — belt-and-suspenders on a supposedly alias-only view — anything matching the shared marker/delimiter refusal list (single source of truth with the appendix loader). Rejection is loud.
