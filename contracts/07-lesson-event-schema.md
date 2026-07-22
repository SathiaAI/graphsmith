# Contract 07 — Typed Lesson-Event Schema (harvest boundary B4)
Status: DRAFT. The ONLY representation in which harvested run artifacts may reach the proposer (plan §3.2/§3.4). Raw prose never crosses; embedded instructions are structurally inert.

## Event record (JSONL, `.graphsmith/events.jsonl`; schema_version on every line)
```json
{
  "schema_version": "1.0",
  "event_id": "sha256(run_id + seq)[:16]",
  "run_id": "string (from run log)",
  "step": "string (^[A-Za-z0-9._-]+$ — same charset the manager enforces [KnoSky: scripts/scaffold.js:44-45])",
  "ts": "ISO8601 copied from the run log line, never wall-clock at compile time",
  "type": "run_halt | budget_breach | tripwire | retry_exhausted | step_failure | corrupt_checkpoint | lock_contention | scenario_fail | human_correction | adoption | rollback",
  "code": "string from the CLOSED per-type code enum (e.g. halt.unresolved_side_effect, budget.max_wall_time, tripwire.undeclared_destination)",
  "counters": { "attempt": "int", "duration_ms": "int", "...type-specific numeric fields": "number" },
  "evidence_ref": { "path": "repo-relative canonical path", "line": "int|null" },
  "fingerprint": "sha256(normalize(type + code + step))"
}
```

## Compiler rules (event-compiler.js — constitutional)
1. Input: checkpoints, structured log lines (the one-line-per-step JSON logs [KnoSky: scripts/scaffold.js:35-36]), halt state files, intents/effects logs. Input is read as DATA; no field of any input is ever evaluated, executed, or passed to an LLM raw.
2. Every string field in the OUTPUT is either (a) drawn from a closed enum, (b) charset-restricted to `[A-Za-z0-9._:/-]` with a hard length cap (256), or (c) a number. There is NO free-text field. A source value that doesn't fit is replaced by its code + `"lossy": true` — never truncated prose.
3. Malformed/unparseable source records: skipped, counted in `compiler_stats.skipped`, quarantined by path reference — never "best-effort parsed."
4. `evidence_ref` paths are canonicalized (realpath, repo-relative); refs escaping the project root are dropped + counted.
5. Determinism: same inputs → byte-identical output (stable sort by (run_id, ts, seq); no clocks/randomness — SKILL.md rule 4).
6. The proposer consumes events + aggregate counts ONLY. It never receives checkpoints, logs, prompts, or scenario contents (proposer isolation, plan §3.2), and never per-scenario Gate-2 results (contract 03).

## Sanitizer (defense-in-depth on the compiler output before the proposer)
Rejects any record whose fields contain delimiter/marker sequences (the appendix-loader refusal list, shared single source of truth), overlong values, or non-schema keys. Rejection is loud (counted + evidenced), never silent repair.

## Fingerprints
`normalize` = lowercase, collapse repeated separators, strip digits-only suffixes (so `step-003` families dedupe). Used by: rejected buffer (cap 100), Gate-4 thrash guard (contract 02), dedup screen (Gate 1).
