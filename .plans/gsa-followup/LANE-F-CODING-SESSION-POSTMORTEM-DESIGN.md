# GraphSmith `postmortem` (Lane F) — Coding-Session Post-Mortem Design Doc

**Status:** design draft, adversarially reviewed (2026-08-01) — **not yet approved to build.** An earlier version of this document read as more decided than a pending-approval draft should (see "Adversarial review" below); this version is explicitly reframed as a proposal. Part of the GSA follow-up track — see `CANONICAL-SOURCE.md` in this same folder for scope, sequencing, and the open items Paul needs to confirm before this is built.

**Scope:** a GraphSmith capability that replays raw Claude Code / Codex coding-agent session logs (the JSONL files those CLIs write to `~/.claude/projects` and `~/.codex/sessions`) as a plain-English post-mortem — Paul's own framing: "see what your agent did in this session in plain english." This is explicitly **not** Lane E's `graphsmith audit replay` (which consumes GraphSmith's own GSA `execution_trace` artifact) — this consumes an upstream coding CLI's own session logs, mindwalk's literal domain. Both are legitimate, cover different session types, and ship under different CLI verbs so neither collides with the other's scope.

**Method:** read mindwalk's actual source (`internal/adapter/adapter.go`, `internal/model/model.go`, `internal/judge/cli.go` in full, both schema files, README, `internal/adapter/claudecode/adapter.go`, `internal/adapter/codex/adapter.go`). Cross-checked against GraphSmith's own `package.json`, `scripts/verify.js`/`scripts/gate.js`/`scripts/capability-policy.js` headers, `scripts/knosky-sync.js`, `scripts/graphsmith-cli.js`, `scripts/install.js`, `scripts/badge.js`, and `schemas/`.

**Adversarial review:** an independent reviewer (fresh context) found 1 HIGH, 3 MEDIUM issues. All are addressed in this version, marked inline as `[Fixed per adversarial review]`. The HIGH finding was about this document's own framing (see immediately below), not about the technical design underneath, which the reviewer confirmed was accurate on nearly every specific factual claim checked.

**`[Fixed per adversarial review — HIGH]`** The first draft proceeded through a full concrete design (firm ADAPT decision, complete schema, CLI verb name, line-count sizing estimates) without framing itself as a draft awaiting Paul's authorization — despite this project's own prior doc (`claude/graphsmith-post-mortem-track-scoping-2026-08-01.md`) explicitly stating no kickoff/design doc had been written for this track yet and that nothing should start without Paul's go-ahead. The doc also self-saved to the project's knowledge base without that framing. Both are corrected here: this doc is a **proposal**, and its status line above says so plainly.

---

## Part 1 — mindwalk background: confirmed and corrected

**Confirmed as accurate** (independently re-verified by the adversarial reviewer against mindwalk's real source, not just re-asserted): `Source` interface (`Harness() string; SessionDir() string; ListSessions() ([]model.SessionMeta, error); Summarize(path string) (model.SessionMeta, error); Parse(path string) (*model.Trace, error)`); two adapters (`claudecode`, `codex`, at `internal/adapter/claudecode/adapter.go` and `internal/adapter/codex/adapter.go`); `actionFor()` classifies into `search|read|edit|verify|exec|other` with conservative fallback ("conservative by design" appears twice in code comments); `targetsFor()` with `weak`/`outside` flags; `InjectedUserMessage()`'s shape-based (not tag-whitelist) filtering; marks vocabulary (`compaction | user-message | subagent`); `schema/trace.schema.json`'s top-level shape; `report.schema.json`'s 4 fixed dimensions (`exploration, scope, wandering, verification`) with `minItems: 4, maxItems: 4`, and its mechanical `max(finding severity)` verdict rollup forced to `insufficient-data` on `unavailable` observability; `verifyCommand()`'s exact ten-substring pattern list (`go test, go vet, npm test, npm run build, pnpm test, pnpm build, pytest, make test, cargo test, swift test` — confirmed no `jest`/`vitest`/`mvn test`/`dotnet test`/`tox`/`rspec`); `AgentGraphSource` as a second, optional interface layered on the core four methods; `SessionKey()`'s warning that Codex resume rollouts can share a session id across files; distribution (GoReleaser static binary, not npm); license (MIT, standard notice-preservation).

**The "untrusted-input isolation" claim about mindwalk's sealed judge is directly sourced, not an inference presented as fact** — confirmed via the adversarial review, which found `internal/judge/cli.go` states outright: *"The trace under evaluation is untrusted input (a prompt injection in the evaluated session must not reach tools), so the judge runs sealed"* and *"strip every tool a prompt injection in the evaluated trace could reach for."*

**`[Fixed per adversarial review — MEDIUM]` The judge subprocess flag lists in the first draft were incomplete**, which mattered because Part 3c's Option A proposes reusing them. Corrected, full lists: the `claude` invocation is `-p --no-session-persistence --tools "" --strict-mcp-config --setting-sources "" --output-format json [--model ...] <prompt>` (the first draft omitted `-p` and `--output-format json`). The `codex` invocation (`codexExecArgs`) is `exec --ephemeral --ignore-user-config --ignore-rules` plus disable flags for shell/browser/computer-use/apps/plugins/hooks/multi-agent/memories/image-gen, **plus** `-c include_apply_patch_tool=false`, `-c tools.view_image=false`, `-c web_search="disabled"`, `--skip-git-repo-check`, `-C <workdir>`, and `--sandbox read-only` — the first draft's summary omitted the three `-c` flags and `--skip-git-repo-check`, which are part of what actually makes the subprocess sealed. An implementer building Option A later should re-read `internal/judge/cli.go` directly rather than trust any flag inventory in this doc, including this corrected one.

**Other corrections from the real source:** `Stats.Observability` is schema-required (`{reads, errors}`, each `exact|estimated|unavailable`). The `Event` schema has no `verifyPassed`/`verifyFailed` boolean — `verify` is a command-shape classification only, never a parsed pass/fail result.

---

## Part 2 — ADOPT / ADAPT / REJECT

**Decision: ADAPT.** Reimplement the trace-normalization design natively in GraphSmith's zero-dependency CommonJS/Node stack; do not vendor or shell out to the Go binary; do not port the 3D visualization or the sealed-subprocess LLM judge in a first build.

**Why not ADOPT:** GraphSmith ships one npm package, zero runtime dependencies, Node ≥18, CommonJS, source-only distribution. mindwalk is a separate Go binary via GoReleaser, not on npm — depending on it means either requiring a separate Go-binary install or vendoring Go source into a pipeline GraphSmith doesn't have. `scripts/knosky-sync.js`, GraphSmith's one external-tool precedent (pinned version, sha512-verified npx, offline escape hatch, fail-open), doesn't fit mindwalk either — nothing to pin/verify via npx since it isn't on npm.

**Why not REJECT:** Paul has stated the need directly, confirming this should eventually cover raw Claude Code/Codex sessions. `grep -rn "audit replay"` across the live repo returns zero hits — independently corroborated by two other project docs that ran the same check. The underlying idea matches GraphSmith's own discipline (`gate.js`'s determinism, evidence-citation), and `scripts/install.js` already walks `~/.claude` and `~/.codex` as install targets.

**Why ADAPT, trace layer vs. judge layer decided separately:** the trace-normalization layer (`Parse`, `actionFor`, `targetsFor`, `InjectedUserMessage`, marks, `Stats`/`Observability`) is pure JSONL-in/typed-IR-out data transformation with no Go dependency — cheap to port, and matches `verify.js`'s own "Deterministic, zero-LLM... NO clocks/randomness in any DECISION path" ethos exactly, since mindwalk's trace layer is already zero-LLM.

The judge layer is left as a genuinely open decision (Part 3c), not resolved here — GraphSmith runs inside a live agent session with a model already attached, so there's no *structural* need for a second subprocess purely to supply a model, but mindwalk's sealed subprocess exists for prompt-injection containment (confirmed above), a different and still-relevant reason.

---

## Part 3 — concrete build

### 3a. `session-trace` JSON Schema (draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://graphsmith.dev/schemas/session-trace.schema.json",
  "title": "GraphSmith Coding-Session Trace",
  "description": "A raw Claude Code or Codex coding-agent session log, normalized into an ordered stream of file-touch events. Adapter-produced, deterministic. A read-only observational record -- makes no claim about whether the session's work was correct, safe, or complete, and no claim about test outcomes beyond 'a command shaped like a verify command ran, and whether the tool call itself errored.' Distinct from GraphSmith's own GSA execution_trace (Lane E's domain) -- this describes an upstream coding CLI's own session, not a GraphSmith-orchestrated run.",
  "type": "object",
  "required": ["schema_version", "session", "events", "marks", "stats"],
  "additionalProperties": false,
  "properties": {
    "schema_version": { "type": "string", "const": "1.0" },
    "session": {
      "type": "object",
      "required": ["harness", "eventCount", "sourcePath"],
      "additionalProperties": false,
      "properties": {
        "harness": { "type": "string", "enum": ["claude-code", "codex"] },
        "id": { "type": "string", "description": "Harness-reported session id, display-only. NOT a safe routing or cache key -- Codex resume rollouts can reuse an id across multiple session files." },
        "model": { "type": "string" },
        "title": { "type": "string" },
        "cwd": { "type": "string" },
        "gitBranch": { "type": "string" },
        "startedAt": { "type": "string", "format": "date-time" },
        "endedAt": { "type": "string", "format": "date-time" },
        "eventCount": { "type": "integer", "minimum": 0 },
        "sourcePath": { "type": "string", "description": "Absolute path to the session JSONL file this trace was parsed from." },
        "sourceLines": { "type": "integer", "minimum": 0, "description": "Total JSONL lines read, including unparseable/skipped ones." }
      }
    },
    "events": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["seq", "tool", "action", "targets", "resultBytes", "isError", "summary"],
        "additionalProperties": false,
        "properties": {
          "seq": { "type": "integer", "minimum": 0 },
          "ts": { "type": "string", "format": "date-time" },
          "tool": { "type": "string" },
          "action": { "enum": ["search", "read", "edit", "exec", "verify", "other"] },
          "targets": { "type": "array", "items": { "$ref": "#/$defs/target" } },
          "outside": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["scope", "path"],
              "additionalProperties": false,
              "properties": {
                "scope": { "enum": ["home", "tmp", "other"] },
                "path": { "type": "string" }
              }
            }
          },
          "resultBytes": { "type": "integer", "minimum": 0 },
          "isError": { "type": "boolean" },
          "summary": { "type": "string", "description": "One-line, mechanically generated description of the call -- never free prose." }
        }
      }
    },
    "marks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["seq", "type"],
        "additionalProperties": false,
        "properties": {
          "seq": { "type": "integer", "minimum": 0 },
          "type": { "enum": ["compaction", "user-message", "subagent"] },
          "note": { "type": "string" }
        }
      }
    },
    "stats": {
      "type": "object",
      "required": [
        "filesInRepo", "touched", "edited", "eventsBeforeFirstEdit",
        "errorRate", "actions", "errors", "maxEditsPerFile", "churnFiles",
        "userTurns", "compactions", "subagents", "resultBytes",
        "editsAfterLastVerify", "observability"
      ],
      "additionalProperties": false,
      "properties": {
        "filesInRepo": { "type": "integer", "minimum": 0, "description": "Set only when the repo is available to count against at parse time; observability.repoSize flags whether this is trustworthy." },
        "touched": {
          "type": "integer",
          "minimum": 0,
          "description": "Distinct files appearing as any target across all events. [Fixed per adversarial review -- MEDIUM: mindwalk's own schema has no equivalent of this field -- mindwalk tracks 'edited' only. Disclosed here explicitly as a genuinely new field, not silently added as if it were a port; kept because 'files touched vs. files actually edited' is useful signal for a report and cheap to compute from data the trace already has."
        },
        "edited": { "type": "integer", "minimum": 0 },
        "eventsBeforeFirstEdit": { "type": "integer", "minimum": 0 },
        "errorRate": { "type": "number", "minimum": 0 },
        "actions": { "$ref": "#/$defs/actionCounts" },
        "errors": { "$ref": "#/$defs/actionCounts" },
        "maxEditsPerFile": { "type": "integer", "minimum": 0 },
        "churnFiles": { "type": "integer", "minimum": 0, "description": "Files edited in three or more events." },
        "userTurns": { "type": "integer", "minimum": 0 },
        "compactions": { "type": "integer", "minimum": 0 },
        "subagents": { "type": "integer", "minimum": 0 },
        "resultBytes": { "type": "integer", "minimum": 0 },
        "editsAfterLastVerify": { "type": "integer", "minimum": 0, "description": "Edit events after the last verify-classified event. NOTE: 'verify' means a command shaped like a test/build runner ran -- not that it passed." },
        "observability": {
          "type": "object",
          "required": ["reads", "errors", "repoSize", "verifyOutcome"],
          "additionalProperties": false,
          "properties": {
            "reads": { "enum": ["exact", "estimated", "unavailable"] },
            "errors": { "enum": ["exact", "estimated", "unavailable"] },
            "repoSize": { "enum": ["exact", "unavailable"] },
            "verifyOutcome": { "const": "unavailable", "description": "Always 'unavailable' in v1: 'verify' actions are a command-shape classification only. Explicitly out of scope for the first build." }
          }
        }
      }
    }
  },
  "$defs": {
    "actionCounts": {
      "type": "object",
      "required": ["search", "read", "edit", "exec", "verify", "other"],
      "additionalProperties": false,
      "properties": {
        "search": { "type": "integer", "minimum": 0 },
        "read": { "type": "integer", "minimum": 0 },
        "edit": { "type": "integer", "minimum": 0 },
        "exec": { "type": "integer", "minimum": 0 },
        "verify": { "type": "integer", "minimum": 0 },
        "other": { "type": "integer", "minimum": 0 }
      }
    },
    "target": {
      "type": "object",
      "required": ["path", "touch"],
      "additionalProperties": false,
      "properties": {
        "path": { "type": "string" },
        "touch": { "enum": ["hit", "read", "edit"] },
        "lines": {
          "type": "array",
          "items": {
            "type": "array",
            "prefixItems": [{ "type": "integer", "minimum": 1 }, { "type": "integer", "minimum": 1 }],
            "minItems": 2, "maxItems": 2
          }
        },
        "weak": { "type": "boolean", "description": "true when the path was inferred from free-text rather than a structured tool argument." }
      }
    }
  }
}
```

**Deltas from mindwalk's `trace.schema.json`, now fully disclosed:** `observability.repoSize`/`verifyOutcome` added (mindwalk always runs against a live local repo; this port must handle a log examined with no checkout). `fovea`/`parafovea` dropped (mindwalk's 3D-layout-derived distance metric — no visual surface here). `target.fileId` dropped (existed only to key into mindwalk's citymap). `stats.touched` added, with no mindwalk equivalent (new field, see inline note above). **`[Fixed per adversarial review — MEDIUM]`**: `regressionRate` (present in mindwalk's real `stats.required` and its `Stats` struct) is **dropped**, not carried over — the first draft's delta list omitted this. Dropped because it depends on a cross-session regression signal (comparing this session's edits against a prior baseline) that has no defined source in a single-session parse; flagged here as a real, disclosed omission rather than silently missing.

### 3b. Adapter design — mapping real session-log formats to `session-trace`

Both adapters are pure functions: JSONL in, one `session-trace` object out. No shared mutable state, no network, no clock in any classification decision.

**Borrowed from mindwalk, and how directly:** the action taxonomy (as-is); direct tool-name→action mappings (as-is: `Read→read`; `Write/Edit/MultiEdit/NotebookEdit/apply_patch→edit`; `Grep/Glob/LS/view_image→search`); the shell-command classification *discipline* — default to `exec` unless positively provable, segment-by-segment across pipelines, refuse on unrecognized program or `>` redirect (reimplemented faithfully; the *exact pattern list* is adapt-not-adopt, extended for GraphSmith's less Go/JS-narrow audience, externalized into a data file mirroring `scripts/risk-policy.json`'s separation from `capability-policy.js`); `targetsFor`'s path-extraction and `weak`/`outside` flags (reimplemented in JS regex, both flags kept as-is); `InjectedUserMessage()` (borrowed near-verbatim, shape-based not tag-whitelist); marks vocabulary and `Observability` (as-is — the single most valuable idea to carry over); `SessionKey`'s warning (as a design constraint: never key caching off a harness-reported session id).

**Claude Code adapter:** correlates `tool_use`/`tool_result` content items across separate lines by id via an in-order pending map, with anything still pending at EOF still emitted (a session ending mid-tool-call shouldn't silently drop the last action). `Task`/`Agent` calls → `subagent` marks. `isSidechain: true` lines (subagent transcripts) skipped in v1, parsing only the root file — matching mindwalk's own `ListSessions` behavior.

**Codex adapter:** a more heterogeneous vocabulary — `session_meta`, `turn_context`, `response_item` (decoded into message/tool-call/tool-output), `event_msg` (`context_compacted`→compaction; `patch_apply_end`→resolves `apply_patch` outcome), and a legacy bare `message` type. `spawn_agent`→`subagent` mark. Both adapters' `isError`-equivalent field handling needs verification against a real Codex session log at implementation time, not assumed from the Go source alone — flagged as an implementation-time fixture question.

### 3c. Narrative output — CLI Markdown, not a viewer, and why

**Recommendation: a single Markdown report to stdout (or `--out report.md`), no viewer.** Distribution fit (no Three.js/UI stack in a zero-dependency npm package), Paul's own framing that the visualization isn't the interesting part, and ethos fit (matches `scripts/verify.js`/`scripts/badge.js`'s "deterministic function → structured report" shape).

Illustrative shape (mechanical, zero-LLM, no interpretive claims):

```
# Session post-mortem — claude-code, 2026-08-01T14:02Z–15:41Z

Source: ~/.claude/projects/graphsmith/a1b2c3.jsonl (812 lines, 3 unparseable — skipped, not dropped silently)
Repo: /home/paul/graphsmith (branch: v0.5.0-lane-a) — observability: repoSize exact

## What happened (mechanical, zero-LLM)

118 tool calls: 41 search, 33 read, 22 edit, 15 exec, 6 verify, 1 other
14 files touched, 9 edited (2 edited 3+ times — churn: scripts/gate.js, tests/gate/fixtures.js)
89 events before the first edit
Error rate: 6.8% (8 of 118 calls returned an error)
3 edits after the last verify-shaped command — the session did not re-verify after its last 3 edits
1 touch outside the repo: ~/.bashrc (scope: home, weak: true)

## Timeline marks
› user turn (seq 0): "add a Codex adapter for the session-trace parser..."
○ subagent launched (seq 34): Task
◇ context compaction (seq 71)

Note: "verify" means a command shaped like a test/build runner ran, not that it passed.
```

**Open design question, deliberately not resolved here:** whether to add an interpretive layer (mindwalk's four-dimension judge-style prose) on top of the mechanical report. **Option A** — mirror mindwalk's sealed subprocess (using `knosky-sync.js`'s pin/verify/offline-escape pattern as the "shell out safely" template — see Part 1's corrected flag list, and re-read `internal/judge/cli.go` directly rather than trusting any flag inventory in this doc when implementing), feeding only the normalized trace, never the raw log, with mechanical severity rollup. **Option B** — let the current live agent narrate in-context from the normalized trace, no subprocess; cheaper, and the normalized JSON shrinks the injection surface versus raw JSONL but doesn't eliminate it, and deviates from GraphSmith's demonstrated preference for mechanical/sealed enforcement over in-context discipline. **Recommendation for the first build: neither — ship the mechanical report only.** If an interpretive layer is wanted later, Option A is the safer default on isolation grounds — but that's Paul's call to make explicitly.

### 3d. Explicit scope cuts for v1

No 3D visualization/viewer. No interpretive/LLM judge layer (an open, explicit later decision). No agent-lens/subagent-graph correlation (`AgentGraphSource`) — real lost value, recommended as a fast-follow. No verify-outcome (pass/fail) parsing — stated structurally via `observability.verifyOutcome: unavailable`. No repo-coverage visual metrics (`fovea`/`parafovea`). No cross-session `regressionRate` (dropped per §3a). No caching layer. Claude Code and Codex only, matching Paul's explicit scoping — not Gemini CLI/Cursor, even though `scripts/install.js` already targets those directories, since their session-log formats aren't verified. Windows path handling gets explicit fixture tests, given this project's documented Windows CI flake history. New CLI verb: `graphsmith postmortem <session.jsonl> [--harness claude-code|codex] [--out report.md]`, deliberately distinct from `graphsmith audit replay` (Lane E) so the two designs don't collide on a name.

---

## Part 4 — sizing

**Sized with more hedging than the first draft's specific claim.** The first draft compared the Markdown renderer to `scripts/badge.js`'s size ("~150-250 lines"); the adversarial reviewer confirmed `scripts/badge.js` is actually 655 lines — 2.6-4.3× that estimate — which undermines the one concrete calibration point the sizing argument offered. The categorical argument (no reconciliation-into-user-files complexity like Lane A's hardest problem, no host-detection breadth like Lane D's) still holds, but the "closest to Lane B, roughly one Wave-1 lane" conclusion should be read as a rough lower bound, not a confident estimate — this build plausibly runs larger once fixture-test coverage (the doc's own "largest real cost" line item) and a full second adapter are actually built out.

Rough basis, hedged accordingly: one schema file (~150 lines); one classification/parsing module (mindwalk's shared Go logic is ~700 dense lines — a JS port with the pattern list externalized is comparably sized once tested, not smaller); one Claude Code adapter (~250-350 lines, per the real file's size); one Markdown renderer (likely closer to `badge.js`'s actual 655 lines than the first draft's estimate, given comparable report-structure complexity); one CLI verb; and — the largest real cost, matching every other GraphSmith lane's pattern — test fixtures covering injected messages, pending-at-EOF calls, sidechain lines, outside-repo touches, and malformed lines. The Codex adapter is additive (schema/classifier/renderer shared), realistically 30-40% on top of a Claude-Code-only build, not another full lane. The interpretive judge layer, if built later, is roughly Lane-C-sized on its own — the hard design work (which subprocess flags actually seal it) is already verified real in Part 1's corrected flag lists, not needing independent research, but the isolation/injection-surface tradeoff itself is a real open decision, not a rubber-stamp port.

---

**File paths referenced during research:** `internal/adapter/adapter.go`, `internal/model/model.go`, `internal/judge/cli.go`, `schema/trace.schema.json`, `schema/report.schema.json`, `internal/adapter/claudecode/adapter.go`, `internal/adapter/codex/adapter.go` (mindwalk, `raw.githubusercontent.com/cosmtrek/mindwalk/master/...`); `package.json`, `scripts/verify.js`, `scripts/gate.js`, `scripts/capability-policy.js`, `scripts/knosky-sync.js`, `scripts/graphsmith-cli.js`, `scripts/install.js`, `scripts/badge.js`, `schemas/host-adapter.schema.json`, `schemas/scenario.schema.json`, `schemas/attestation-bundle.schema.json`, `README.md` (GraphSmith, `SathiaAI/graphsmith`).
