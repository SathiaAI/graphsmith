# The 11-Document Build System

**An agent-first framework for briefing, building, testing and shipping software.**

> **How this fits the skill:** the core skill ships the *minimum* — the seven build rules and the six multi-agent coordination rules (`multi-agent-coordination.md`). This document is the *full system* those rules were distilled from: a complete operating model for teams running many agents against production software. Adopt it when your project has real users, real money, real data, or several agents shipping in parallel. You do not need it for a weekend build — and that's by design.

## Why agents need a proper brief — and a proper pipeline

AI coding tools can write code quickly. They still need you to define what correct means. These documents reduce ambiguity. They do not guarantee good code, remove the need for testing or replace technical judgment. They give the agent stable constraints so it makes fewer inconsistent decisions.

A brief alone is no longer enough. When agents also plan, build, test and deploy — often several agents in parallel — the documents must be discoverable by machine, explicit about dependency and sequencing, and clear about which decisions still belong to a human. This system extends the original six briefing documents with a discovery layer (00), an independent QA plan (07), a release and operations plan (08), an agent operating protocol (09) and an evaluation layer (10) that scores the agents themselves — because a pipeline you cannot measure is a pipeline you cannot safely hand autonomy to.

> **LIVING DOCUMENTS** — Start lean, test uncertain assumptions and update the documents when the product changes. Treat the latest approved version in the registry as the source of truth. A document that contradicts the code is a defect: fix one or the other.

## The eleven-document system

| # | Document | Purpose |
|---|---|---|
| 00 | Repo Map & Document Registry | Where every artefact lives; how agents find and trust documents (manifest + knosky index) |
| 01 | PRD | Problem, users, scope, requirements, success criteria and criticality |
| 02 | Technical Design | Architecture, stack, module boundaries, contracts, constraints and trade-offs |
| 03 | App Flow | Screens, journeys, states, actions and redirects |
| 04 | UI/UX Brief | Visual system, interaction rules and accessibility |
| 05 | Backend Design | Data model, access rules, API contracts, storage and events |
| 06 | Engineering Plan | Task graph with lanes and dependencies, built for parallel agents |
| 07 | QA & Adversarial Test Plan | Full test taxonomy, adversarial charter, synthetic data, quality gates |
| 08 | Release, Deploy & Operations | Environments, pipeline, progressive delivery, rollback, observability, runbook |
| 09 | Agent Operating Protocol | Roles, pipeline state machine, risk tiers, HITL gates, escalation and audit |
| 10 | Evals & Model Performance | Scorecards for every stage and agent, hallucination controls, eval-gated tuning |
| — | References | Sources behind every practice in this guide |

## Seven rules

1. Define the smallest useful version. Every possible feature creates scope creep.
2. Separate facts, decisions and open questions. Do not present assumptions as requirements.
3. Version these documents with the code. When one changes, check what else is affected.
4. Machine-readable first. Every document carries front matter and stable IDs. Agents locate documents through the registry and the knosky index — never by guessing paths or duplicating content.
5. Autonomy is tiered. Routine changes ship automatically. Critical changes stop at a human gate with evidence attached. When unsure, promote the tier.
6. No self-certification, no shared blind spots. The agent that built a thing never reviews, certifies or merges it, and every checking role — code review, architecture review, adversarial QA — runs on a different model family than the author. Cross-model review is a requirement, not an optimization target; a zero-finding rubber stamp is an invalid review.
7. Measure the machine, not just the product. Every stage's output is scored, every claim must be grounded in a resolvable reference or a run result, and changes to models or prompts are eval-gated exactly like changes to code.

> **FAST PATH** — A weekend prototype may combine everything into one lean file. A production app handling payments, personal data or several roles needs the full set. The manifest (00) and the risk tiers (09) are the last things to drop: they are what keep parallel agents and automatic deploys safe.

---

## DOCUMENT 00 — Repo Map & Document Registry

Make every document and identifier findable by any agent, from a cold start, without tribal knowledge.

Agents fail in predictable ways when discovery is informal: they guess paths, read stale copies, or rewrite documents that already exist. Document 00 fixes the entry point. It has three parts: a canonical layout, a manifest, and a knosky index over the whole repository.

### Include this
- Canonical layout: where documents, contracts, plans and generated indexes live.
- The manifest: one JSON registry listing every document with ID, path, version, status and owner.
- Front matter: metadata block at the top of every document.
- The ID scheme: stable identifiers that make traceability possible across documents, tasks, tests and deploys.
- knosky indexing: how the index is generated, refreshed and queried by agents.
- Cold-start procedure: the fixed reading order for any agent joining the project.

### Canonical layout

```
docs/
  manifest.json            # the registry — single source of truth for document state
  00-repo-map.md … 09-agent-protocol.md
  contracts/               # machine-readable interface contracts (frozen = sync points)
    openapi.yaml           # API-xx
    events/                # EVT-xx event schemas (JSON Schema)
    tokens.json            # design tokens exported from 04
  plan/
    tasks.yaml             # TASK-xx graph — machine-readable mirror of Document 06
  evals/
    models.yaml            # which model + prompt version runs each role (Document 10)
    golden/                # golden task set for eval-gated tuning (Document 10)
city-data.json             # generated knosky index (committed; regenerated in CI)
city.html                  # generated knosky city view for humans
```

### Front matter (top of every document)

```yaml
---
id: DOC-01
title: Product Requirements Document
version: 1.3.0
status: approved          # draft | in-review | approved | superseded
owner: planner            # role, not a person — see Document 09
depends_on: []
feeds: [DOC-02, DOC-03, DOC-06]
last_verified_commit: 8f3ac21
---
```

### Manifest entry

```json
{
  "documents": [
    {
      "id": "DOC-01",
      "path": "docs/01-prd.md",
      "version": "1.3.0",
      "status": "approved",
      "owner": "planner",
      "depends_on": []
    }
  ],
  "id_registry": {
    "FR":   "docs/01-prd.md",
    "DEC":  "docs/02-technical-design.md",
    "SCR":  "docs/03-app-flow.md",
    "API":  "docs/05-backend-design.md",
    "EVT":  "docs/contracts/events/",
    "TASK": "docs/plan/tasks.yaml",
    "TEST": "docs/07-qa-plan.md",
    "RUN":  "docs/08-release-operations.md",
    "EVAL": "docs/10-evals.md"
  }
}
```

### The ID scheme

| Prefix | Names | Defined in |
|---|---|---|
| FR-xx | Functional requirement | 01 PRD |
| DEC-xx | Architecture decision | 02 Technical Design |
| SCR-xx | Screen | 03 App Flow |
| API-xx / EVT-xx | API contract / event schema | 05 + contracts/ |
| TASK-xx | Task | 06 + plan/tasks.yaml |
| TEST-xx | Test charter or suite | 07 QA Plan |
| RUN-xx | Runbook entry | 08 Operations |
| EVAL-xx | Eval metric or golden task | 10 Evals |

Reference by ID everywhere. The traceability chain FR → TASK → TEST → PR → deploy must resolve in both directions; Document 09 audits it.

### knosky indexing and discovery

[knosky](https://github.com/SathiaAI/knosky) turns the repository into a queryable index: pointers plus light projections (title, headings, a short excerpt, tags) linking to live files. It is a map and a router, not a copy of the content — agents use it to find where something lives, then read the live file.

- Generate or refresh the index from the repo root: `npx knosky@0.6.3 .` — pinned; keep in step with the version in `scripts/knosky-sync.js`, which also verifies the tarball's content hash (produces `city-data.json` and the `city.html` view).
- Exclusions follow `.gitignore` plus a `.kcignore` for anything extra; `.git`, `node_modules`, `secrets/`, `keys/` and `.env*` are skipped automatically. Use `--share-safe` (strips absolute paths, runs secret detection and fails closed) before an index leaves the machine; redaction flags mask project-specific terms.
- Agents query through the knosky MCP server: `kc_search` (find by query), `kc_get_node` (file detail), `kc_list_categories` (browse structure), `kc_related` (connected files), `kc_get_provenance` (change history).
- Refresh triggers: any merge to main re-indexes in CI; any document change re-indexes locally before the PR.
- Trade-off, made deliberately: `city-data.json` is a generated file, and committing it adds noise to diffs. Commit it anyway — a cold-starting agent then has discovery without running Node first. If diff noise becomes a problem, move it to a CI artifact and accept the slower cold start.

### Cold-start procedure (any agent, any time)

1. Read `docs/manifest.json`. Reject any document whose status is not `approved` as a basis for building.
2. Load the knosky index (MCP tools if available, else read `city-data.json` directly).
3. Read Document 09 (operating protocol) and the documents your task depends on — located by ID through the manifest, never by guessing paths.
4. Before writing anything, `kc_search` for prior art: an existing document, contract or module that already covers it.

> **REGISTRY RULE** — A document that is not in the manifest and the index does not exist for the pipeline. Agents must not act on unregistered documents, and must register anything new they create in the same change.

> **QUALITY CHECK** — Cold-start test: a fresh agent with repo access only must locate the approved PRD and the current engineering plan in at most two queries. If it cannot, fix the manifest or the index before adding features.

---

## DOCUMENT 01 — Product Requirements Document

Define what you are building, who it is for and what the first version must achieve.

A PRD ties the build to a user problem instead of a pile of features. It should guide decisions without pretending the product will never change. In an automated pipeline the PRD carries one extra duty: every requirement declares how critical it is, because that criticality decides later whether its changes deploy automatically or wait for a human (Document 09).

### Include this
- Product summary: user, problem and intended outcome in one sentence.
- Target user, problem context and current alternative.
- Goals and non-goals for this release.
- Observable functional requirements, split into must-have and later, each with a stable FR-xx ID and a criticality tier.
- User stories with testable acceptance criteria, and dependencies stated explicitly so parallel work can be planned from them.
- Success signals tied to product outcomes.
- Analytics assessment: for every requirement, decide whether its usage and outcome need measurement; if yes, name the events and tie them to a success signal — if no, record the "no" so it was a decision, not an omission. A success signal no event feeds is a wish, not a signal.
- Assumptions, dependencies, risks and open questions — labelled as such.

### Copy/paste template

```
PRODUCT SUMMARY
[User + problem + outcome]

TARGET USER & CURRENT ALTERNATIVE
[Who, when the problem occurs, what they use now]

V1 GOALS / NON-GOALS
Goals:
Non-goals:

REQUIREMENTS
FR-01 — [Required behaviour]
Criticality: C1 | C2 | C3        (definitions in Document 09)
Depends on: [FR-xx or "none"]
Acceptance criteria:
- Given [context], when [action], then [observable result]
- Failure / empty / loading behaviour:

SUCCESS SIGNALS
[Metric, baseline if known, target, window]
[Instrumented by: which analytics events feed each metric]

ASSUMPTIONS / RISKS / OPEN QUESTIONS
[Label each item clearly]
```

> **QUALITY CHECK** — Could a developer — or an agent with no back-channel to you — test every must-have requirement without asking what you meant? If not, tighten the acceptance criteria.

---

## DOCUMENT 02 — Technical Design Document (TDD)

Explain how the system will work and why the major technical choices were made.

Do not make it a shopping list of tools. Record architecture, constraints, trade-offs and consequences. For parallel agent work, this document also draws the module map: the boundaries that let several agents build at once without touching the same files.

### Include this
- System context and architecture: client, server, database, external services and trust boundaries.
- Module boundary map: each module's purpose, owner lane, public contract and forbidden dependencies.
- Frontend, backend, data, hosting and deployment choices.
- APIs: purpose, data exchanged, failure behaviour, limits and cost assumptions — with the contract itself stored under `docs/contracts/` (see 05).
- Security and privacy: secrets, encryption, logging, retention and threats.
- Performance, reliability, observability and environment requirements.
- Major decisions as DEC-xx records: alternatives, reasons and triggers for reconsideration.

### Module boundary map

| Module | Purpose | Lane owner | Public contract | Must not import |
|---|---|---|---|---|
| [name] | [one line] | [lane] | [API-xx / exported interface] | [modules] |

One writer per module at a time. If a task needs to cross a boundary, it changes the contract first — through the planner, not by reaching into another module's files.

### Decision template

```
DECISION: DEC-xx [Short title]
Status: Proposed / Accepted / Replaced
Context: [Requirement or constraint]
Options considered: [A / B / C]
Choice:
Reason:
Consequences: [Costs, risks and limits]
Revisit when: [Specific trigger]
```

### Baseline technical brief

| Area | Decision | Reason / constraint |
|---|---|---|
| Frontend | [Framework + version policy] | [Fit with app and team] |
| Backend | [Runtime + API style] | [Load, skills, deployment] |
| Data | [Database + region] | [Model, residency, scale] |
| Identity | [Provider + session model] | [Roles, MFA, recovery] |
| Delivery | [Hosting + CI/CD] | [Preview, rollback, monitoring] |

> **SECURITY RULE** — Never paste live secrets, private keys or production credentials into a document, an agent chat or an index. List environment-variable names only. Agents read secrets from the environment or the CI secret store — never from documents, and never write them back.

---

## DOCUMENT 03 — App Flow & State Map

Map what users see, what they can do and what happens after every important action.

A route list is not enough. Each screen needs a purpose, permitted users, entry conditions, actions, states and exits — and a stable SCR-xx ID so tasks and tests can point at it.

### Include this
- Screen inventory with SCR-xx ID, route, purpose and allowed roles.
- Primary journeys: signup, first-value action, payment and recovery.
- Desktop and mobile navigation rules.
- Success, loading, empty, validation, error and offline states.
- Redirects, back behaviour, destructive confirmation and session expiry.
- Permission failures: what the user sees and where they go.

### Screen template

```
SCREEN: SCR-xx [Name]    ROUTE: [/path]
Purpose:
Allowed roles:
Entry conditions:
Data required:
Primary / secondary actions:
Success outcome / next screen:
Loading / empty states:
Validation / system errors:
Mobile behaviour:
Analytics events:
```

### Journey template

```
JOURNEY: [User goal]
1. Entry point
2. User action
3. System response
4. Decision or branch
5. Completion state
Recovery path:
Permission edge case:
Testable success condition:
```

> **QUALITY CHECK** — Trace a new user and a returning user from entry to completion. Repeat with no data, invalid input and a failed request. The adversarial QA agent (07) will run exactly these traces against the build — write them so that is possible.

---

## DOCUMENT 04 — UI/UX Design Brief

Define a consistent visual system and how the interface behaves across devices and states.

"Make it look like Linear" can communicate direction, but it is not a design system. Extract the qualities you want and define reusable rules. Export the tokens as data so agents apply them mechanically instead of re-deciding them per screen.

### Include this
- Design principles and tone: calm, dense, playful, editorial or something else.
- Colour tokens by role: surface, text, primary, warning, danger and focus.
- Typography, spacing, radii, borders, elevation and icon style.
- Rules for buttons, fields, cards, tables, modals and feedback.
- Responsive breakpoints and navigation changes.
- Accessibility: contrast, keyboard access, focus, labels and reduced motion.
- Annotated references showing what to copy and what to avoid.
- Token export: the same tokens mirrored to `docs/contracts/tokens.json` so implementing agents consume them programmatically. The prose brief explains intent; the token file is the contract.

### Copy/paste template

```
DESIGN DIRECTION
Three adjectives:
Should feel like:
Must not feel like:

TOKENS  (mirror to docs/contracts/tokens.json)
Colour roles:
Heading / body / mono fonts:
Spacing scale:
Radius / border / shadow:

COMPONENT RULES
Buttons:
Inputs and validation:
Cards / tables:
Modals / destructive actions:
Loading / empty / error:

RESPONSIVE & ACCESSIBLE
Mobile navigation:
Keyboard and focus:
Contrast target:
Reduced motion:
Touch target:
```

> **COPY PRINCIPLES, NOT PRODUCTS** — Do not clone another product's complete interface or brand assets. Use references to identify principles suited to your product.

---

## DOCUMENT 05 — Backend Design & Data Model

Define how data is structured, accessed, validated, retained and changed.

A database schema covers tables, fields, types, constraints and relationships. Authentication, authorisation, APIs, storage and events belong alongside it, but they are separate concerns. In this system the API and event contracts do double duty: once frozen, they are the synchronisation points that let frontend, backend and QA agents work in parallel against the same interface.

### Include this
- Tables, keys, data types, constraints and cardinality.
- Access matrix: which role can create, read, update and delete each resource.
- Signup, verification, login, recovery, session expiry and account deletion.
- Server- or database-side authorisation, not hidden UI controls alone.
- API contracts as files: every endpoint in `docs/contracts/openapi.yaml` with an API-xx ID; every event as a JSON Schema under `docs/contracts/events/` with an EVT-xx ID. Validation, error codes and idempotency where needed.
- Contract lifecycle: `draft → frozen → deprecated`. Building against a draft contract is forbidden; changing a frozen contract is a planner-level change that re-plans every task depending on it (06).
- Migration policy: schema changes are written expand → migrate → contract, so code and schema never have to deploy in the same irreversible step. Destructive steps (drops, contractions) are always a separate, C1-tiered change (09). Execution rules live in 08.
- Indexes based on real query patterns.
- Files, events, webhooks, audit logs, backups, retention and deletion.
- Sensitive-data classification and third-party boundaries.

### Table template

| Field | Type / rule | Purpose |
|---|---|---|
| id | UUID, primary key | Stable identifier |
| user_id | UUID, FK, indexed | Owner; define delete behaviour |
| [field] | [type, null, constraint] | [business meaning] |
| created_at | Timestamp with time zone | Creation time |
| updated_at | Timestamp with time zone | Last server-side change |

### Access matrix

| Resource / action | Owner | Admin |
|---|---|---|
| [resource] — read | Own rows only | Allowed: reason |
| [resource] — update | Allowed fields | Allowed: audited |
| [resource] — delete | Deletion rule | Retention applies |

> **SECURITY CHECK** — Can User A read or change User B's record by modifying an ID? Test cross-user access for every resource. The adversarial QA plan (07) automates this exact check against every API-xx.

---

## DOCUMENT 06 — Engineering Implementation Plan

Turn the design into small, testable tasks in dependency order — expressed as a graph, so any number of agents can build in parallel without stepping on each other.

A useful plan is not "build the frontend, then the backend". Each task states its outcome, dependencies, lane, contracts, acceptance criteria, test evidence and risk tier. The plan exists twice: this document for reasoning, and `docs/plan/tasks.yaml` as the machine-readable mirror agents actually claim work from. If they disagree, the YAML is wrong — fix it from the document.

### The task graph
- Tasks form a directed acyclic graph via `depends_on`. A task is *ready* when every dependency is merged and green, and every contract it lists is `frozen`.
- Tasks group into waves: wave N+1 contains only tasks whose dependencies sit in waves ≤ N. Everything inside a wave is parallelisable by construction.
- Every task belongs to exactly one lane — a module from the boundary map in 02. One agent per lane at a time; two tasks that would edit the same files must be sequenced or split, never run concurrently.
- Mark the critical path — the longest dependency chain. Assign it first; parallelism elsewhere is worthless if the critical path idles.

### Machine-readable mirror — `docs/plan/tasks.yaml`

```yaml
- id: TASK-14
  outcome: "User can reset password via emailed link"
  requirement: FR-06
  lane: backend-auth
  criticality: C1              # inherited from FR, promoted if diff demands (09)
  wave: 3
  depends_on: [TASK-09, TASK-11]
  contracts: [API-04]          # must be frozen before this task is ready
  status: unclaimed            # unclaimed | claimed | in-progress | blocked |
                               # in-review | merged | verified
  claimed_by: null             # agent id
  lease_expires: null          # UTC timestamp
  evidence: []                 # PR links, test-run links, filled at completion
```

### Claiming and leases
- An agent claims a task by setting `claimed_by` and a lease (default: 4 hours) in one atomic commit. The claim commit is the lock.
- Progress (a commit or status update) renews the lease. An expired lease means the agent is presumed dead: any agent may reset the task to `unclaimed` and note the reset in the audit log (09).
- Blocked tasks state what they are blocked on — a task ID, a frozen-contract request, or an open question routed to a human. Blocked without a reason is a protocol violation.

### Git protocol for parallel agents
- One branch (or worktree) per agent per task, named `task/TASK-14-short-slug`, cut from green main. Worktrees let several agents share one clone without collisions.
- Branches live short — target under a day of work; if a task is bigger, the task is too big. Rebase on main before review.
- Integration is serialised through a merge queue: CI must be green on the merged result before the merge lands. The queue, not the agents, decides landing order.
- Merge conflicts are a planning failure, not something to power through: the resolving agent stops, and the planner re-partitions the lanes or sequences the tasks.
- Incomplete features land behind feature flags so trunk stays releasable at all times.

### Recommended sequence
1. Foundation: repository, environments, CI, secrets, manifest + knosky index (00) and basic observability.
2. Contracts: freeze the first API/event/token contracts for the slice ahead (02, 04, 05).
3. Thin end-to-end slice: prove one small journey across UI, API and database — one lane, no parallelism yet.
4. Identity and access: authentication, authorisation and tenant boundaries.
5. Core features in waves: parallel lanes against frozen contracts, with tests and failure states.
6. External integrations with sandbox testing and recovery.
7. UI completion: responsive behaviour, accessibility and full state coverage.
8. Hardening: adversarial QA findings (07), threat review, rate limits, backups, logging and recovery.
9. Release: production config, migrations, monitoring, rollback and smoke tests (08).

> **WHY A THIN SLICE** — After the foundation, one small end-to-end journey exposes integration problems earlier than building every screen before connecting real data. It also validates the pipeline itself: the first slice should travel every stage of Document 09's state machine, including a deliberately triggered rollback.

### Task template

```
TASK-xx / OUTCOME
User or system outcome:
Requirement: FR-xx
Lane / wave:
Criticality: C1 | C2 | C3
Depends on / blocks:
Contracts required (must be frozen):
Areas affected:
Implementation notes:
Acceptance criteria:
Tests required:
Security / privacy checks:
Observability (required — a story without it is not done):
  Logs [what, level, never PII]:
  Metrics [name, type, labels]:
  Traces [spans added or extended]:
  Alerts [condition, threshold, routes to]:
  Dashboard [which one, what changes]:
Analytics assessment (required — a "no" is recorded, not implied):
  Metrics worth tracking [yes/no + why]:
  Events [name, properties, fires when]:
  Feeds success signal [from 01]:
Synthetic data [fixtures / generator changes needed]:
Architecture review [auto-yes if boundaries, contracts, data model,
  new dependency, or C1 — see 09]:
Rollback or recovery:
Done evidence:
Open questions:
```

> **QUALITY CHECK** — Pick any wave and ask: if five agents claimed these tasks simultaneously, would any two touch the same file, wait on the same unfrozen contract, or deadlock on each other? If yes, the graph is not ready.

---

## DOCUMENT 07 — QA & Adversarial Test Plan

Define how the build is verified by someone whose job is to break it, not to finish it.

The agent that wrote the code is the wrong agent to certify it. This document gives an independent QA role its charter: what to test, how hard, with what data, and what "good enough to ship" means. It exists so quality gates are decided before the work, not negotiated after it.

### Include this
- The test taxonomy (below): eight suites, who writes each, and which gate each feeds. Unit, integration, contract, end-to-end, regression, adversarial, smoke and performance/accessibility are all mandatory — none is a nice-to-have, and regression accumulates forever.
- Independence rule: the adversarial QA agent works from the documents only — PRD acceptance criteria, app flow, contracts and access matrix. It must not read the implementation rationale first, so its assumptions cannot be contaminated by the implementer's — and it runs on a different model family than the implementer (09).
- Traceability: every must-have FR-xx maps to at least one TEST-xx. A requirement without a test is unverified; a test without a requirement is a question to raise.
- Escaped-defect accounting: every defect found downstream is attributed backwards — which review approved it, which suite missed it, which requirement under-specified it. This attribution is the raw data for Document 10's scorecards.
- The adversarial charter (below).
- Quality gates: the objective bar for entering the merge queue and for promotion to staging.
- Regression policy: every bug becomes a failing test before it becomes a fix. The suite is append-only unless the requirement itself was removed.
- Flake policy: a flaky test is quarantined the day it flakes, fixed within a set window, and never silently skipped — a quarantined test cannot gate a C1 change.
- Synthetic test data (below): a hard requirement with its own section. No story is done without its fixtures, and production data never enters lower environments.
- Non-functional checks: performance budgets, accessibility checks against the 04 brief, and error-handling behaviour under dependency failure.

### Test taxonomy — all mandatory

| Suite | Verifies | Written by | Runs at |
|---|---|---|---|
| Unit | Functions and components in isolation | Implementer, with the change | Every push; merge gate |
| Integration | Modules against real collaborators (DB, queue, cache) | Implementer, with the change | Merge gate |
| Contract | Both sides of every frozen API-xx / EVT-xx | Implementer + QA adversary | Merge gate; every contract change |
| End-to-end | Whole journeys from 03, through real UI and API | QA adversary | Staging gate |
| Regression | Everything that ever shipped still works: all prior behaviour plus every fixed bug, append-only | Accumulated by all; owned by QA adversary | Targeted subset at merge gate; full suite before staging promotion and nightly |
| Adversarial | The charter below | QA adversary | Staging gate; full sweep before any C1 |
| Smoke | The system is alive on its critical paths | QA adversary + release manager | After every deploy, staging and production |
| Performance / accessibility | Budgets from 02, rules from 04 | QA adversary | Staging gate on touched areas; full run nightly |

### Adversarial charter

The QA agent's standing instruction is to falsify, not confirm. For every release candidate:
- Attack authorisation: for every API-xx and resource in the 05 access matrix, attempt cross-user and cross-tenant access by ID manipulation, direct API calls that bypass the UI, and role escalation.
- Attack inputs: boundary values, empty and enormous payloads, wrong types, malformed encodings, injection attempts against every parser.
- Attack sequencing: replay requests, double-submit payments, interrupt multi-step journeys midway, expire sessions mid-flow, race two clients on the same resource to test idempotency and locking.
- Attack dependencies: fail or slow each external service and verify the 03 error states actually appear.
- Attack assumptions: read the PRD's assumption list and design one test per assumption that would expose it being false.

### Synthetic test data — a requirement, not a preference
- Every story ships with synthetic fixtures covering the states it introduces or changes — success, empty, boundary, invalid and failure, the same states Document 03 enumerates. A story without its data is not done.
- Generators and fixtures are versioned in the repo (`tests/data/`), deterministic under a seed, and produce prod-shaped data: realistic cardinalities, distributions, sizes and referential integrity, including the awkward cases — unicode names, zero-item accounts, maximum-length fields, timezone and daylight-saving edges.
- Volume tiers: small fixtures for unit and integration suites; generated prod-scale sets for performance tests and migration rehearsal.
- Production data never enters lower environments — not masked, not sampled, not once. If a bug only reproduces on production data, extend the generators until it reproduces synthetically; the extended generator is the regression artifact.

### Quality gates

```
GATE: merge queue entry
- Unit + integration tests green; coverage not lower than before
- Contract tests pass against frozen API-xx versions
- Targeted regression subset green for the affected areas
- Static analysis, lint, type checks, secret scan, reference linting clean
- New/changed behaviour has tests (traceability check FR → TEST)
- Independent cross-model review verdict attached; architecture review
  verdict attached when structurally triggered (09)

GATE: staging promotion
- Full regression suite green — everything that ever shipped still works
- Full e2e suite green, including the adversarial suite for affected areas
- Access-matrix (cross-user) checks pass for every touched resource
- Synthetic fixtures exist for every state the change introduces or alters
- Observability proof: the change's logs and metrics appear in staging, and
  its alerts fire when their conditions are forced
- Analytics proof: required events arrive in the analytics pipeline with
  correct properties
- Performance within budget; accessibility checks pass on touched screens
- QA agent files a signed verdict: pass, or findings with severity
```

> **QUALITY CHECK** — Could the QA agent, given only Documents 01–05, decide unambiguously whether the build passed? If it would need to ask the implementer what was intended, the documents — not the tests — are the defect.

---

## DOCUMENT 08 — Release, Deploy & Operations

Define how a green build reaches users, how you watch it, and how you take it back.

Automation makes deploys cheap; this document makes them boring. It fixes the environment chain, the promotion rules, the rollout style and the operational duties that continue after the deploy — so every agent (and every human approver) knows exactly what "ship it" executes.

### Include this
- Environment chain and parity rules.
- Build-once, promote-many: the artifact that passed QA is the artifact that deploys, identified by digest, with provenance recorded at build time.
- Progressive delivery: flags, canary steps, health checks and automatic rollback triggers.
- Migration execution rules (authored per 05's expand → migrate → contract policy).
- Observability: what every feature must emit, and the SLOs that define healthy.
- UAT: what humans check in staging, for which tiers, with what evidence in front of them.
- Runbook entries (RUN-xx): rollback, incident response, kill switch.
- Deploy audit record: what was deployed, by which agent, under which approval, with links to evidence.

### Environment chain

| Environment | Purpose | Data | Deploy trigger |
|---|---|---|---|
| dev | Per-agent workspace / preview | Synthetic | Every branch push |
| ci | Ephemeral test runs | Seeded fixtures | Merge queue |
| staging | Prod-parity, UAT, adversarial QA | Synthetic, prod-shaped | Auto on merge to main |
| production | Users | Real | Risk gate (09): auto C2/C3, human-approved C1 |

Configuration differs by environment variables only. If staging and production differ structurally, staging approvals are theatre.

### Release flow
1. Merge queue lands the change on main; CI builds the artifact once, tags it with commit + digest, records provenance.
2. Auto-deploy to staging; smoke tests and the 07 staging gate run.
3. Risk gate (09) evaluates the change's tier: C3 proceeds, C2 proceeds with canary, C1 waits for human approval with the evidence bundle.
4. Progressive rollout: deploy to a canary slice first; watch error rate, latency and saturation against SLOs for a defined bake time; then complete the rollout.
5. Auto-rollback: any tripped health threshold during bake reverts to the previous artifact without asking — roll back first, diagnose second.
6. Post-deploy: smoke tests in production, deploy record appended to the audit log, observability dashboards checked by the release agent.

### Migrations at deploy time
- Expand first (new columns/tables, backwards-compatible), deploy code, migrate data, and only contract (drop/rename) in a later, separate C1 change after verification.
- Every migration ships with its reverse — or an explicit, human-approved statement that it is irreversible and a roll-forward plan instead.
- Never run a destructive migration and the code that depends on it in the same deploy.

### Operations
- SLOs per primary journey (03), e.g. availability and p95 latency; alerts fire on burn rate, not single blips.
- Severity ladder: Sev1 (users blocked / money or data at risk) pages the human immediately and freezes agent deploys; Sev2 alerts the human and lets agents attempt known runbook remediations; Sev3 becomes a task in the plan.
- Kill switch: one command/flag halts all agent-initiated merges and deploys. Test it monthly; an untested kill switch does not exist.
- Backups restore-tested on a schedule; retention and deletion per 05's data classification.

```
RUNBOOK ENTRY: RUN-xx [Scenario]
Trigger / detection:
Severity default:
Automated remediation allowed: yes / no
Steps:
Rollback / recovery:
Escalate to human when:
Verification after action:
```

> **QUALITY CHECK** — Rehearse the failure before you need it: trigger a bad deploy in staging and confirm the auto-rollback fires, the audit record is written, and the human notification arrives. A rollback that has never run is a hope, not a control.

---

## DOCUMENT 09 — Agent Operating Protocol & Automation Policy

Define who does what, in what order, with how much autonomy — and exactly where a human must be in the loop.

The other ten documents describe the product, the pipeline and the measurements. This one governs the actors. It is the first document any agent reads after the manifest, and the one a human audits when asking "why did the system do that?"

### Agent roles

| Role | Owns | May write to | Never does |
|---|---|---|---|
| Planner | Documents 00–06; task graph; contract freezes | docs/, plan/ | Implementation code |
| Implementer (×N) | Claimed tasks in one lane | Its lane's code + tests | Other lanes; frozen contracts; deploy config |
| Reviewer | Code review against docs | Review comments | Reviewing code it authored; merging anything |
| Architecture reviewer | Structural conformance to 02 (boundaries, contracts, DEC-xx) | Review verdicts; DEC revision proposals | Implementation code; merging anything |
| QA adversary | Document 07 suites and verdicts | tests/, QA reports | Production fixes |
| Release manager | Document 08 execution | Deploy config, releases | Feature code |
| Human operator | Approvals, escalations, policy | Anything | — |

One agent may hold multiple roles on small projects, except the separations below, which are load-bearing: the author never reviews its own change, the implementer never certifies its own QA, and nobody merges their own work.

### Review independence
- The author never reviews, approves or merges its own change. The merge queue enforces this mechanically: author, reviewer and QA-certifier identities in the audit log must all differ, and no agent can land its own PR.
- Cross-model review is mandatory. The reviewer, the architecture reviewer and the QA adversary run on different model families than the implementer whose work they check — a fresh context of the same model is not independence, it is the same blind spots with less information. The model registry (10) encodes the family assignments, and CI rejects any configuration in which a checking role shares a family with the role it checks. Reviewers see only the documents, the diff and the evidence — never the author's reasoning transcript.
- Review is adversarial and evidence-based, not narrative-based. The reviewer's job is to find what is wrong, not to confirm what is right: it verifies the CI run, checks the diff against contracts and acceptance criteria, and either files specific findings or attests item-by-item to a named checklist (correctness, tests, authorisation, contracts honoured, docs updated). "Looks good" with zero findings and no attestation is an invalid review: the merge queue rejects it.
- Reviews are themselves scored (Document 10). A reviewer whose approvals keep preceding escaped defects, or who approves everything with no findings, is a failing component and gets tuned or replaced like one.
- Disputes that survive two author–reviewer rounds escalate to the planner or the human. The author never edits the review verdict.
- C1 changes take the two-key-plus rule: independent review, independent QA verdict, human approval — three different actors by construction.

### Architecture review

Code review checks the change; architecture review checks the system the changes are accumulating into. It is a separate verdict, from a separate role, on a separate model family, working from Document 02 — because architectural erosion is invisible in any single diff.

- Mandatory triggers: any change to module boundaries, frozen contracts, the data model, authn/authz structure, or infrastructure; any new external dependency or service; any cross-lane change; everything C1. No structural change merges on code review alone.
- Standing sweep: on a fixed cadence (weekly by default) the architecture reviewer walks recently merged changes as a whole, looking for the drift no single diff revealed — creeping coupling, duplicated concepts, boundary leaks, patterns that contradict accepted DEC-xx decisions.
- The verdict answers three questions: does this conform to the boundary map and the accepted decisions; does it introduce coupling or duplication that will tax every later change; is a DEC-xx being silently eroded that should instead be formally revisited?
- Findings are blocking (violates an accepted decision — fix the change, or revise the DEC through its own review) or advisory (debt, logged as tasks alongside the drift report). Advisory-only streaks are themselves an eval smell (10).
- Recurring violations in one lane are feedback to the planner: the boundary map, not the agents, may be what needs to change.

### Grounding rules (anti-hallucination)
- Cite or verify. Any claim about the system — "FR-06 is covered", "this endpoint exists", "tests pass" — must carry a resolvable reference (an ID, a path, a CI run link) or be verified by executing the thing claimed. Unsupported claims are protocol violations, logged per agent and counted in Document 10.
- Look up before inventing. Before calling an endpoint, importing a package or reading a config key, the agent must locate it — via `kc_search`, the frozen contracts, or the lockfile. If it does not exist, creating it is an explicit, reviewable act, never a silent side effect of other work.
- Dependency reality check. Every import must exist in the lockfile; every new dependency must exist in the public registry, pass an advisory check and clear the project allowlist. Hallucinated package names are a documented supply-chain attack vector ("slopsquatting"), so CI fails on any dependency that appears without a flagged, reviewed addition.
- Reference linting. CI resolves every DOC/FR/API/TASK/TEST ID and file path cited in documents, PRs and evidence bundles against the manifest and the repo. Broken references fail the merge gate the same way broken tests do.
- "Should work" is not a status. Done requires run evidence — a passing CI link, a reproduced output, a screenshot of the state — per the task's done-evidence field.

### Pipeline state machine

```
INTAKE → SPEC → PLAN → BUILD ∥ → REVIEW → MERGE QUEUE → ADVERSARIAL QA
   → STAGING/UAT → RISK GATE → DEPLOY → OBSERVE → LEARN → (back to INTAKE)
                       │
                       ├─ C3: proceed automatically
                       ├─ C2: proceed with canary + auto-rollback armed
                       └─ C1: halt for human approval (evidence bundle attached)
```

| Stage | Entry criteria | Evidence produced | On failure, route to |
|---|---|---|---|
| SPEC | Request understood; docs 01–05 updated, approved, indexed | Doc diffs, manifest bump | INTAKE (clarify with human) |
| PLAN | Task graph valid: acyclic, laned, contracts identified | tasks.yaml, wave map | SPEC |
| BUILD | Task ready: deps merged, contracts frozen, lease held | Branch, commits, local tests | PLAN (re-partition) |
| REVIEW | PR opened with done evidence | Code review verdict; architecture verdict when triggered | BUILD (same task) |
| MERGE QUEUE | Review passed; 07 merge gate green | Green merged main | BUILD |
| ADVERSARIAL QA | Staging deploy healthy | QA verdict + findings | PLAN (findings become tasks) |
| STAGING/UAT | QA verdict: pass | UAT sign-off (C1 only) | PLAN |
| RISK GATE | Tier confirmed by diff re-check | Approval record | — (halts, never bypasses) |
| DEPLOY | Gate passed | Deploy + provenance record | Auto-rollback, then PLAN |
| OBSERVE | Deploy complete | SLO dashboards, alerts | Incident runbook (08) |
| LEARN | Bake time elapsed | Doc updates, drift report, eval scorecards, reindex | SPEC |

### Risk tiers

| Tier | Meaning | Examples | Deploy policy |
|---|---|---|---|
| C1 | Critical: irreversible, or touches money, identity, private data, or the platform itself | Payments and billing; authn/authz; PII handling; destructive or contracting migrations; infra, IAM and secrets; public API breaking changes; legal/compliance surface | Human approval required before production. UAT sign-off in staging. Canary rollout mandatory |
| C2 | Elevated: user-visible behaviour with blast radius, but reversible | New features on existing surfaces; major dependency upgrades; performance-sensitive paths; changed defaults | Auto-deploy with canary + armed auto-rollback; human notified with evidence after completion |
| C3 | Routine: low blast radius, trivially reversible | Copy and styling; docs; tests; non-breaking internal refactors; dependency patch bumps; config within pre-approved bounds | Fully automatic; batched in the daily digest to the human |

Classification rules:
- The planner assigns a tier to every task, inheriting from the PRD requirement's criticality and raising it for the areas touched.
- The risk gate re-derives the tier from the actual diff — files under payment, auth, migration or infra paths force C1 regardless of the label. A mislabelled task can lower nothing; the max of (declared, derived) wins.
- Ambiguity promotes: when unsure between tiers, take the higher one. An unnecessary approval costs minutes; a wrong auto-deploy costs trust.
- Earned autonomy: reclassification of a change class (for example, C2 → C3 for copy changes behind flags) is itself a C1 policy change — proposed by the system with its track record as evidence, approved by the human, recorded as a DEC-xx. Autonomy narrows the same way: sustained eval degradation (Document 10) moves a change class back to the stricter tier without waiting for an incident.

### HITL mechanics
- Implement approvals as deployment protection rules on the production environment (for GitHub: environment "required reviewers", so the pipeline halts until a designated human approves the pending job). The gate is enforced by the platform, not by agent goodwill.
- Every approval request carries an evidence bundle: plain-language summary of the change and why, diff stats and links, tier and its derivation, test + QA verdicts, canary plan, rollback plan, and the exact command the approval releases.
- The human may approve, reject with a reason (routed back to PLAN as context), or take over manually. Silence is never consent: no timeout-approves, and C1 requests older than the SLA page the operator rather than expire.
- Non-deploy HITL points: contract changes that break a frozen interface, spending above budget caps, adding a new third-party data processor, deleting user data, and any action the agent itself flags as irreversible.

### Escalation triggers (agent must stop and ask)
- Two failed attempts at the same task, or blocked longer than the lease period.
- Any security finding at high severity or above.
- Acceptance criteria that turn out to be ambiguous or contradictory mid-build.
- CI red on main for longer than one working hour.
- Cost/token budget for the task exceeded.
- Any prod Sev1/Sev2 (freezes agent deploys automatically per 08).

### Guardrails and audit
- Protected main: no direct pushes, no force-push, merges only through the queue. Agents hold least-privilege credentials per role; only the release manager's identity can deploy.
- WIP limits: at most one claimed task per agent; lanes cap concurrent agents (02's boundary map is the license to parallelism).
- Budgets: per-task token/cost ceilings; the planner sees burn rates and re-plans rather than letting an agent grind. Cost is optimized where work is routine — smaller models for mechanical C3 tasks, batching, caching — and never at quality gates: code review, architecture review, adversarial QA and anything C1 always run the strongest configured models. Buy quality where it is critical; find savings where it is not.
- Audit log, append-only: every claim, merge, verdict, gate decision, approval and rollback, with actor, timestamp and document references. knosky's `kc_get_provenance` supplements this with per-file history, so "why is this here?" is always answerable.
- Drift control: a nightly job samples reality against the documents — routes vs 03, schema vs 05, task statuses vs the repo, manifest hashes vs files — and files divergences as tasks. Drift is fixed by changing whichever side is wrong, per the Living Documents rule. The same nightly job feeds Document 10's grounding audit by sampling agent claims against live code.

> **QUALITY CHECK** — Replay yesterday from the audit log alone: could a human reconstruct what shipped, why, at which tier, on whose approval, and with what evidence? If not, the autonomy is not yet accountable — tighten the log before widening the gates.

---

## DOCUMENT 10 — Evals & Model Performance

Measure the agents the way you measure the product — so that when quality slips, you can see where, prove why, and fix the right component.

In an automated pipeline the agents are production infrastructure. You would not run production code without monitoring; do not run production agents without evals. This document defines two layers: run-time evals that score each artifact as it is produced, and longitudinal evals that track every role and model configuration over time. Nearly all of it is computed from evidence the pipeline already emits — the audit log, CI history and QA verdicts — so evals are queries over existing records, not a parallel bureaucracy.

### Include this
- Outcome metrics: the DORA four keys — deployment frequency, lead time for changes, change failure rate, failed-deployment recovery time — as the delivery north star.
- Stage rubrics: what "good" means for each stage's output (spec, plan, code, review, QA verdict, deploy), scored automatically wherever possible.
- Per-role scorecards with thresholds and smells (below).
- Grounding and hallucination measurements, computed in CI and nightly.
- The golden task set and the eval-gated tuning loop.
- The model registry: which model, version and prompt runs each role — degradation you cannot attribute is degradation you cannot fix. The registry also carries the family-diversity constraint: CI rejects any configuration in which a checking role (reviewer, architecture reviewer, QA adversary) shares a model family with the role it checks. Cost per role is tracked here too, and optimized only in routine paths — never by weakening the models at the gates.
- Autonomy coupling: how eval trends widen or narrow the risk gates in Document 09.
- The weekly scorecard for the human operator.

### Per-role scorecards

| Role | Primary metrics | Smells that open a tuning task |
|---|---|---|
| Planner | Re-plan rate; % of parallel tasks that conflicted; wave-size estimate accuracy; ambiguity escalations per requirement | Tasks bouncing back from BUILD; graph deadlocks; lane conflicts |
| Implementer | First-pass CI pass rate; review findings per PR; rework ratio (attempts per task); escaped defects traced to its merges | Rising retries; diffs far larger than task scope; unsupported-claim count |
| Reviewer | Defect escape rate (bugs later found in code it approved); findings per review; attestation completeness | Zero-finding approval streaks; approvals faster than the diff could plausibly be read |
| Architecture reviewer | Boundary violations caught vs found later by the sweep; DEC revisions proposed vs silent erosion discovered downstream | Advisory-only streaks; sweeps that never find anything |
| QA adversary | Defects escaped to staging/production in areas it certified; severity mix of findings; false-alarm rate | Suites that never fail; findings clustered only in easy categories |
| Release manager | Change failure rate; rollback time when triggered; deploy-record completeness | Manual overrides; skipped bake times |
| The documents themselves | Clarification requests per FR; drift findings per week; cold-start test pass rate | The same requirement re-litigated across multiple tasks |

Every metric is sliceable by model + prompt version. A scorecard that cannot say "this regression started when the implementer moved to model X, prompt 1.5" is decoration.

### Hallucination and grounding evals

Enforcement lives in Document 09's grounding rules; measurement lives here.

- Reference-resolution rate: share of cited IDs, paths and links in agent output that actually resolve. Target is ~100%; failures gate merges and are logged per agent.
- Dependency violations: imports outside the lockfile/allowlist caught by CI, counted per agent and per model version.
- Unsupported-claim rate: cite-or-verify violations per agent per week.
- Sampled fact-audit: nightly, piggybacking the drift job, an auditor takes N random claims from the day's artifacts — "this endpoint validates X", "this test covers FR-06" — and verifies them against live code through the knosky index. A contradiction is a hallucination incident, logged with the responsible model + prompt version.
- Trend rule: hallucination incidents trend to zero or the affected role's autonomy narrows. There is no acceptable steady-state hallucination rate in a pipeline that deploys.

### Golden task set and eval-gated tuning
- Maintain 10–30 golden tasks with objectively checkable outcomes: a small feature against a fixture repo, a bug with a known root cause, a migration, and at least one adversarial fixture where the correct behaviour is to stop and escalate — the requirement is ambiguous, the "obvious" fix is wrong, or the needed package does not exist.
- Models, prompts and role instructions are versioned config in the repo (`docs/evals/models.yaml`). Changing any of them is a change like any other: branch, PR, golden-set run attached as evidence, independent review. A golden-set regression blocks the change exactly as a failing test blocks code.
- Tier the tuning: prompt and model changes are C2 by default; any change that widens autonomy — loosening a gate, promoting a change class toward auto-deploy — is C1 and carries the eval history as its evidence bundle.
- Tune like an experiment: hypothesis first, one variable at a time, before/after on both the golden set and a rolling window of live metrics; keep or revert. Record the outcome as a DEC-xx so the same dead end is not explored twice.

### The weekly scorecard

One page to the human, generated from the audit log: the four keys, per-role deltas, hallucination incidents, gate outcomes (approvals, rejections, rollbacks), budget burn, and the top proposed tuning task with its evidence. Five minutes of steering a week is the review cadence that autonomy is rented against.

```yaml
# docs/evals/models.yaml
roles:
  implementer:
    model: [family + pinned version]
    prompt: prompts/implementer@1.4.0
    thresholds:
      first_pass_ci: ">= 0.70"
      rework_ratio: "<= 1.5"
      unsupported_claims_weekly: "== 0"
  reviewer:
    model: [different family than implementer]   # required — CI enforces family diversity
    prompt: prompts/reviewer@1.2.1
    thresholds:
      defect_escape_rate: "<= 0.05"
      zero_finding_streak: "<= 5"
golden_set: docs/evals/golden/
report:
  cadence: weekly
  to: human operator
```

> **QUALITY CHECK** — Pick your worst week and interrogate the evals: can you name which role degraded, on which model and prompt version, starting when, and which tuning task was opened in response? If the answer is a shrug, you have dashboards, not evals — and autonomy should shrink until this check passes.

---

## Definition of done — system-wide

- Acceptance criteria pass and failure states work.
- Relevant unit, integration and end-to-end tests pass, including the adversarial suite for the areas touched.
- Authorisation and validation are enforced server-side.
- Logs help debugging without leaking sensitive data.
- Affected documents are updated, the manifest version bumped, and the knosky index refreshed.
- Traceability holds: the FR → TASK → TEST → PR → deploy chain resolves in both directions.
- Independence holds: review and QA verdicts came from different-family models that did not author the change, and every reference cited in the evidence resolves.
- Observability shipped with the change: its logs, metrics, traces and alerts exist and were seen firing in staging.
- Analytics assessed; where required, events verified end-to-end with correct properties.
- Synthetic fixtures cover the change's states, and the full regression suite runs green with them absorbed.
- The change can be deployed and rolled back safely; its risk tier and deploy evidence are in the audit log.

---

## References

Primary and established sources behind the practices used in this guide.

**Document discovery & indexing** — knosky: repo/document indexing, city views, MCP tools for agent discovery — https://github.com/SathiaAI/knosky

**Parallel agent development** — Claude Code docs, running agents in parallel — https://code.claude.com/docs/en/agents · Power user tips (parallel sessions, git worktrees) — https://support.claude.com/en/articles/14554000-claude-code-power-user-tips

**Product requirements** — Atlassian on PRDs — https://www.atlassian.com/agile/product-management/requirements

**Technical design** — Microsoft Learn, functional and technical design documents — https://learn.microsoft.com/en-us/dynamics365/guidance/patterns/create-functional-technical-design-document

**Architecture decisions & diagrams** — Azure Well-Architected: ADRs — https://learn.microsoft.com/en-us/azure/well-architected/architect-role/architecture-decision-record · Design diagrams — https://learn.microsoft.com/en-us/azure/well-architected/architect-role/design-diagrams

**Interface contracts** — OpenAPI — https://spec.openapis.org/oas/latest.html · JSON Schema — https://json-schema.org/

**Accessible interfaces** — WCAG 2.2 — https://www.w3.org/TR/WCAG22/

**Application security & adversarial testing** — OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/ · Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/ · Authorization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

**Database design** — Microsoft, relational design basics — https://support.microsoft.com/en-us/office/database-design-basics-eb2159cf-1e30-401a-8084-bd4f9c9ca1f5

**CI/CD** — DORA capabilities — https://dora.dev/capabilities/continuous-integration/ · https://dora.dev/capabilities/continuous-delivery/ · https://dora.dev/capabilities/trunk-based-development/ · https://dora.dev/capabilities/deployment-automation/ · Martin Fowler, feature toggles — https://martinfowler.com/articles/feature-toggles.html

**Progressive delivery & release engineering** — Google SRE Workbook, canarying — https://sre.google/workbook/canarying-releases/ · SRE Book: release engineering — https://sre.google/sre-book/release-engineering/ · launch checklist — https://sre.google/sre-book/launch-checklist/ · SLOs — https://sre.google/sre-book/service-level-objectives/

**Observability** — Google SRE Book, monitoring distributed systems (four golden signals) — https://sre.google/sre-book/monitoring-distributed-systems/

**HITL deployment gates** — GitHub environments & deployment protection rules — https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment · https://docs.github.com/actions/managing-workflow-runs/reviewing-deployments

**Build provenance & supply chain** — SLSA — https://slsa.dev/spec/v1.0/levels

**Versioning & change communication** — Conventional Commits — https://www.conventionalcommits.org/ · SemVer — https://semver.org/

**Evaluating agents & model output** — Anthropic, creating strong empirical evaluations — https://docs.claude.com/en/docs/test-and-evaluate/develop-tests · DORA four keys — https://dora.dev/guides/dora-metrics-four-keys/

**LLM failure modes & hallucination** — OWASP GenAI Top 10, LLM09:2025 Misinformation — https://genai.owasp.org/llmrisk/llm092025-misinformation/ · https://genai.owasp.org/llm-top-10/ · Spracklen et al., package hallucinations ("slopsquatting") — https://arxiv.org/abs/2406.10279

**Code review** — Google Engineering Practices, the standard of code review — https://google.github.io/eng-practices/review/reviewer/standard.html

**Iterative delivery** — Agile Manifesto — https://agilemanifesto.org/

> **NOTE** — These templates are starting points, not a substitute for product discovery, security review, legal advice or experienced engineering judgment. Increase the depth for products handling money, health, identity or regulated activity — and keep the human gate wide until the pipeline has earned narrower ones.
