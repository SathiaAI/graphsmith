# Graduation ladder — when to upgrade, and when NOT to

The scaffold's JSON-file checkpoints are the correct choice for its tier. Upgrade a rung only when you hit that rung's trigger — never speculatively. Read only the rung you need.

| Rung | Persistence / engine | Right for | Upgrade trigger |
|---|---|---|---|
| 1 | JSON file per step (scaffold default) | Single machine, one run at a time, ≤ low thousands of steps | Concurrent runs corrupting state, or you need to query run history |
| 2 | SQLite (one table: run_id, step, output, status, ts) | Single machine, concurrent runs, queryable history | Multiple machines/containers need shared state |
| 3 | Framework checkpointer (e.g., LangGraph + Postgres saver) | Distributed workers, cyclic/branching graphs, human-in-the-loop interrupts | Runs span hours–weeks, survive deploys, or money moves on retries |
| 4 | Durable execution engine (Temporal, Inngest, Restate, DBOS) | Long-running, exactly-once semantics, replay/audit requirements | — (top rung) |

Rules of thumb:
- Each rung adds real operational cost. Rung 4 for a 5-step script is as wrong as rung 1 for a payments workflow.
- Moving up a rung must NOT change the discipline: deterministic manager, save-per-step, re-run-safe workers, capped retries. The rung changes WHERE state lives, not the rules.
- When you move to rung 3–4, replay safety gets strict: no wall-clock or randomness anywhere in workflow code (not just routing), and idempotency keys derive from workflow_id + step_id.
- Migration path is incremental: the scaffold's checkpoint read/write is isolated in `executeStep` — swap that function's storage, keep everything else.
