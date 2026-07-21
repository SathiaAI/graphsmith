# Multi-agent coordination — when more than one agent builds at once

The core skill keeps ONE workflow reliable. This reference keeps MULTIPLE agents from tripping over each other when they build in parallel. Apply it whenever two or more agents (or agent sessions) work the same repo or plan. Read only what the situation needs.

## The six coordination rules

**1. One writer per lane.** Divide the work into lanes — module boundaries where each lane owns its files. One agent per lane at a time. Two tasks that would edit the same files are sequenced or split, never run concurrently. A merge conflict is a planning failure to fix in the plan, not something to power through.

**2. Claim before work, with a lease.** Work comes from a shared, machine-readable task list. An agent claims a task by writing its ID and a lease expiry in one atomic commit — the claim commit IS the lock. Progress renews the lease; an expired lease means the agent is presumed dead and any agent may reset the task to unclaimed (and log the reset). Minimal shape:

```yaml
- id: TASK-14
  outcome: "User can reset password via emailed link"
  lane: backend-auth
  wave: 3
  depends_on: [TASK-09, TASK-11]
  contracts: [API-04]        # must be frozen before this task is ready
  status: unclaimed          # unclaimed|claimed|in-progress|blocked|in-review|merged
  claimed_by: null
  lease_expires: null
  evidence: []               # PR/test-run links, filled at completion
```

**3. Frozen contracts are the sync points.** Interfaces between lanes (APIs, schemas, tokens) live as files with a lifecycle: draft → frozen → deprecated. Building against a draft is forbidden; changing a frozen contract is a planner-level act that re-plans every dependent task. Waves follow from this: a task is *ready* only when its dependencies are merged and its contracts frozen — everything ready in the same wave is parallel-safe by construction.

**4. No self-certification.** The agent that built a thing never reviews, certifies, or merges it. Where possible, the checking agent runs on a **different model family** than the author — a fresh context of the same model shares the same blind spots. A zero-finding "looks good" is an invalid review; reviews attest item-by-item (correctness, tests, contracts honored) or file specific findings.

**5. Risk-tiered autonomy with a human gate.** Classify every change: **C1** (irreversible, or touches money, identity, private data, destructive migrations, infrastructure) → halts for human approval with evidence attached. **C2** (user-visible, reversible) → auto-proceeds with rollback armed, human notified after. **C3** (copy, docs, tests, safe refactors) → fully automatic, batched into a digest. Two hard rules: the tier is re-derived from the actual diff (a mislabeled task can never lower it), and **ambiguity promotes** — when unsure, take the higher tier. An unnecessary approval costs minutes; a wrong auto-deploy costs trust.

**6. Cite or verify — "should work" is not a status.** Any claim about the system ("this endpoint exists," "tests pass," "FR-06 is covered") carries a resolvable reference (an ID, a path, a CI-run link, a KnoSky citation) or is verified by executing the thing claimed. Before calling an endpoint or importing a package, an agent locates it first — via the index, the contracts, or the lockfile; if it doesn't exist, creating it is an explicit reviewable act, never a silent side effect. Done requires run evidence.

## Discovery: how agents find truth from a cold start

Keep one small manifest listing every planning document with ID, path, version, and status (draft / approved / superseded). Agents build only from approved documents, locate them by ID through the manifest — never by guessing paths — and register anything new they create in the same change. Pair the manifest with a KnoSky index over the repo (`npx knosky@0.6.3 .` — pinned and integrity-checked via `scripts/knosky-sync.js`), and give every agent the same cold-start ritual: read the manifest, load the index, read the operating rules, then search for prior art before writing anything new. A document that contradicts the code is a defect — fix one or the other.

## Escalation triggers — the agent stops and asks a human

- Two failed attempts at the same task, or blocked past the lease period
- Acceptance criteria turn out ambiguous or contradictory mid-build
- Any high-severity security finding
- Shared main broken for more than an hour
- Task cost/token budget exceeded
- Anything the agent itself flags as irreversible

## Graduation note

These rules scale down: a solo builder with two parallel agent sessions needs rules 1, 2, and 6 and a plain tasks file. The full apparatus — independent adversarial QA, staged deploy gates, per-agent scorecards that widen or narrow autonomy based on measured performance — belongs to teams running many agents against production systems, and should be adopted the same way everything else in this skill is: in response to observed failures, not in advance of them.
