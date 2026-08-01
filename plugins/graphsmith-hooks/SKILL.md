---
name: graphsmith
description: Build and fix reliable multi-agent AI workflows for any skill level, from first-time builders to senior engineers. ALWAYS use this skill when the user asks to "build an agent", "automate" a task or workflow, wants "AI to do X for me", describes a multi-step job, mentions agents, bots, pipelines, swarms, or orchestration, or has an automation that "keeps breaking", "forgets where it left off", "loops forever", "duplicates work", or "makes stuff up". Also use to review, harden, or migrate an agent loop to a multi-agent architecture, or when multiple agents or sessions must build in parallel without conflicts ("agents keep overwriting each other", "coordinate parallel agents"). Trigger even if the user never says "agent". Includes an executable scaffolder, architecture linter, crash-recovery test harness, and multi-agent coordination rules, plus KnoSky grounding (auto-updated) so answers about existing code carry citations instead of guesses.
---

# GraphSmith

Turn a goal into a reliable multi-agent workflow. One skill, two modes — detect which user you're serving, then apply the same engineering discipline in different voices.

**The discipline (never negotiable, in either mode):**
1. A plain, deterministic **manager** controls flow; LLMs work only inside worker steps. Control returns to the manager after every step.
2. **Save after every step** — a crashed run resumes, never restarts.
3. **Every step is safe to re-run** — assume it WILL be retried.
4. **No clocks or randomness in routing** — same inputs, same path.
5. **Minimal handoffs** — workers get only what they need.
6. **Grounded claims** — anything said about existing code cites KnoSky.
7. **One log line per step** — run ID, step, status, duration.

---

## Mode detection (do this first, silently)

Score the context. Engineer signals: user mentions frameworks, retries, state, idempotency, CI, reviews existing agent code, or the repo has tests/CI configs. Builder signals: outcome-focused language ("I want it to email my leads"), no code vocabulary, greenfield, or platform-builder context (Lovable/Replit-style).

- **Builder mode** → plain English only. Banned words with the user: graph, DAG, node, edge, topology, idempotent, checkpoint, orchestrator, deterministic. Use: blueprint, worker, handoff, save point, manager, "safe to re-run."
- **Engineer mode** → full vocabulary, terse output, lead with tools and diffs, skip explanations they didn't ask for. Never talk down.

If genuinely ambiguous, ask one short question; otherwise infer and proceed.

---

## Phase 0 — Ground (KnoSky)

If the task involves an existing repo or docs folder:

1. Run `node scripts/knosky-sync.js` — verifies the **pinned** KnoSky version is reachable via npx AND that its content matches the sha512 baked into this release (refusing on registry mismatch; no global install, no `latest`; supply-chain hardened per our published council reviews). Non-blocking: offline or registry failures never stop the task. Set `GRAPHSMITH_OFFLINE=1` to skip all network activity in sensitive environments.
2. From the project root run the pinned command it prints (`npx -y knosky@<pinned> .`) — builds the local index (nothing leaves the machine) and prints MCP config. Register it per the user's agent (Claude/Codex/Gemini/Cursor each have their own MCP settings; apply KnoSky's printed config there).
3. **Cite or flag.** Every claim about existing code carries a KnoSky citation (real path). If you can't cite, say "inferring." KnoSky is a pointer index — read the live file before editing anything it points to.

Skip Phase 0 only for fully greenfield work.

## Phase 1 — Blueprint (mandatory gate before code)

One screen, four parts, user approves before any code:

1. **Workers** — one job each, one line each.
2. **Handoffs** — who passes what to whom. Only needed fields.
3. **Save points** — "crash at step 3 restarts at step 3, not step 1."
4. **Stop rules** — end condition + hard retry/loop caps. Nothing runs forever.

Shape selection (internal; name them only in engineer mode):

| Shape | Use when |
|---|---|
| Pipeline A→B→C | Ordered dependent steps |
| Fan-out A→[B,C,D]→E | Independent parallel subtasks |
| Manager+workers | A step's outcome decides the next step |

Default to the fewest workers that work. Add workers in response to observed failure, never speculation. Engineer mode: the blueprint may be a 6-line spec comment; the gate still applies.

## Phase 2 — Build

**Greenfield (both modes):** run the scaffolder —

```bash
node scripts/scaffold.js <project-name>
```

It generates a runnable, zero-dependency Node project: `manager.js` (deterministic routing, per-step JSON checkpoints keyed by run ID — fsync-durable, with corrupt checkpoints backed up and re-run instead of bricking the run — resume on restart, capped retries, collision-proof default run IDs, structured logs), `workers/` (stub workers with an **fsync'd** write-ahead intent guard — intent → effect → completion, durable across power loss, a LOUD HALT on intent-without-completion instead of a silent re-send, and a ready-made `idempotencyKey` (`runId:step`) to hand to external APIs; they run with no API keys so it works immediately), and a README. The manager validates step names at start and takes a per-run lock — the same claim-with-a-lease rule the coordination layer preaches, with a lease + heartbeat (not pid-liveness alone): a second manager on the same run refuses while the first is alive and its lease is fresh, and a lock whose holder has died or whose lease has expired (a heartbeat renews it, so a recycled pid can't fake liveness) is stolen automatically — so a crashed run self-recovers within ~30s with no manual file deletion. Then replace stub workers with the user's real logic — LLM calls live ONLY inside workers, wired to whatever model the user has. Do not restructure what the scaffold enforces; extend it.

**Existing agent code (mostly engineer mode):** run the linter —

```bash
node scripts/graphlint.js <path>
```

It builds a project model (import graph, cross-file LLM reachability) and scans JS/TS/Python for the discipline violations: unbounded LLM loops — including condition-variable loops and loops whose LLM lives in an imported worker — missing persistence, clock/randomness near control flow, and external writes without a KEYED guard. `node scripts/graphlint.js --selftest` runs its shipped regression corpus (every adversarial-review probe is a case). Findings are heuristic — verify each against the live file (with KnoSky citations) before proposing the smallest fix. Fix violations in severity order; don't rebuild what passes.

**Scale honestly.** The scaffold's JSON-file checkpoints are correct for single-machine jobs up to roughly thousands of steps. Beyond that, consult `references/graduation.md` for the upgrade ladder (SQLite → framework checkpointer → durable execution engine) and the thresholds for each rung. Never ship the toy tier to a workload that outgrew it — and never ship Temporal to a 5-step script.

## Phase 3 — Verify (executable, not self-graded)

```bash
node scripts/chaos.js <project-dir>
```

The harness (works on any project following the scaffold's checkpoint conventions):
- **Kill test** — starts a run, kills the process mid-execution (and asserts the kill landed mid-flight, never a hollow green), restarts, asserts it resumed from the last save point.
- **Double-run test** — asserts no step's *recorded* side effects executed twice across the crash/resume cycle, and that intent→effect→completion ordering held. A safety-halt counts as a pass ONLY when the on-disk intent/effect state earns it — a halt string without the halt state, or after a duplicate, FAILS (the verdict comes from state, never from a string).
- **Power-loss probe** — stages the on-disk state a lost flush leaves (intent recorded, completion gone) and proves the restart HALTS instead of re-sending. SIGKILL alone can never exercise this class; staged state can.
- **Lock probes** (three) — a concurrent manager on the same run must refuse; a dead holder's stale lock must be stolen; and a live-but-recycled pid must be judged by its lease, not its pid alone (expired lease → stolen, fresh heartbeat → refused). Every green prints the fault model: process crash + staged power loss + same-run concurrency + pid-reuse/lease-expiry; NOT disk corruption beyond torn writes, and never your business logic.
- **Halt path** — if the crash landed inside a side-effect window, the restart halting loudly with UNRESOLVED SIDE EFFECT is a PASS of the safety property (the workflow refused to guess about external state); resolve per the printed instructions and re-run.

A full pass (or a safety-halt pass) is required before handover. Be precise in handover language: the harness tests crash recovery and once-and-replay-verified *recorded* effects; single-delivery to an external system additionally requires an idempotency key that system honors (`runId + ":" + step` — see `references/graduation.md`, rungs 3–4). If the project doesn't follow scaffold conventions (e.g., pre-existing code), state that the harness doesn't apply and verify the equivalent properties manually, showing your evidence.

Also confirm: blueprint was approved; stop rules fire; existing-code claims are cited; the manager reads top-to-bottom without you.

**Handover:** what it does (≤3 sentences), how to run, how to resume after a failure, where logs live. Engineer mode: add the graduation ladder position and what triggers the next rung.

---

## Scaling to multiple agents

The phases above govern one workflow. The moment TWO OR MORE agents (or agent sessions) build in parallel against the same repo or plan, also apply `references/multi-agent-coordination.md`. Its six rules in one line each: one writer per lane; claim tasks with a lease before working; frozen contracts are the only sync points; the author never certifies its own work (prefer a different model family for review); risk-tier every change and halt at a human gate for anything irreversible or touching money, identity, or private data — when unsure, take the higher tier; and "should work" is not a status — every claim carries a resolvable reference or run evidence. For a solo builder with two sessions, rules 1, 2, and 6 plus a plain tasks file are enough; adopt the rest in response to observed failures.

## Anti-patterns (refuse politely, offer the fix)

- One mega-agent doing everything → split at the observed failure point.
- Agents chatting freely → fixed handoffs through the manager.
- Retry-the-whole-thing recovery → save points exist; never redo finished work.
- Passing full history everywhere → minimal handoffs.
- Speculative workers ("we might need a QA agent") → complexity follows observed failures.
- Self-written happy-path tests as "verification" → run the chaos harness.

## Diagnosing a broken automation

Map the symptom to the rule, in order: forgets progress → no save points (rule 2); unpredictable paths → LLM doing routing (rule 1); infinite loops → no stop rules; duplicate emails/charges → not re-run safe (rule 3); makes stuff up about the codebase → ungrounded (run Phase 0); confused and expensive → everything-everywhere handoffs (rule 5); "works on my machine, dies in prod" → wrong graduation rung. Name the rule (plain English in builder mode), run the linter for evidence, show the smallest fix.
