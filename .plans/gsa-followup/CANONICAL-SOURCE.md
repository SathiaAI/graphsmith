# GSA Follow-up Track — Canonical Source (Lanes E & F)

**Status:** design frozen, adversarially reviewed, **not yet approved to build.** Paul's explicit go-ahead is required before any Wave 1 work on this track starts — see "What this doc does not do" below.

**Where this came from:** a deep-dive of `cosmtrek/mindwalk` (MIT), requested by Paul as a detour before v0.5.0 Wave 1 kicked off. The 3D-visualization half of mindwalk had no clear GraphSmith fit; Paul redirected the investigation toward its post-mortem/replay idea instead: *"see what your agent did in this session in plain english and the agent lenses, timeline marks, user turn, the inspector to see the history."* Full mindwalk extraction: `claude/graphsmith-mindwalk-extraction-2026-08-01.md` (project doc).

## The two-domain split, and why it's two lanes, not one

Paul was asked which session domain this should cover — GraphSmith's own workflow-graph runs (GSA attestation bundles) or raw Claude Code/Codex coding sessions (mindwalk's literal domain) — and answered **"both, eventually."** These are genuinely different data sources with no shared schema, so this track has two lanes:

- **Lane E — `graphsmith audit replay`**: narrates an already-produced GSA attestation bundle (`manifest`/`contents`, the output of `gsa-produce.js`). Touches GraphSmith's own attestation data model.
- **Lane F — `graphsmith postmortem`**: narrates a raw Claude Code/Codex session log file (the JSONL the CLI itself writes to `~/.claude/projects` / `~/.codex/sessions`). This is mindwalk's actual domain — an unrelated log format GraphSmith has never touched before.

Both are scoped, designed, and adversarially reviewed as of 2026-08-01. Neither is built yet.

## Sequencing decision (Paul, 2026-07-31/08-01)

When asked how to sequence this relative to v0.5.0, Paul chose **"New GSA follow-up track (recommended)"** — not folded into v0.5.0 Wave 1, and not just logged for later. v0.5.0 Wave 1 (Lanes A–D) is explicitly UX/distribution work that "is not security-tier work... nothing here makes an attestation claim" (`.plans/v0.5.0/CLAUDE-CODE-KICKOFF.md`). Lane E in particular *does* touch attestation territory (it renders GSA bundle contents, even though it re-derives no trust claim itself — see its design doc §7). Mixing it into v0.5.0's Wave 1 would either force Wave 1's whole build-discipline section to be rewritten to a heavier bar it doesn't otherwise need, or let Lane E slip through on a bar that's genuinely too light for what it touches. Keeping this as its own track avoids both.

**A note on a later instruction and how it's reconciled here:** Paul's most recent message asked to "Add the GSA Audit capability in the next Wave 1 as well as coding skills." Read literally against `.plans/v0.5.0/CLAUDE-CODE-KICKOFF.md`, that could mean either (a) fold Lanes E/F into v0.5.0's own Wave 1 (Lanes A–D), or (b) give this new track its own Wave 1, consistent with the "new track" decision from the prior turn. This doc takes reading (b) — Lanes E/F get **this track's own Wave 1**, kept structurally separate from v0.5.0's, because (a) would contradict the "new GSA follow-up track" decision Paul made explicitly one turn earlier and would mismatch Lane E's heavier review bar against Wave 1's stated "not security-tier" discipline. This is a judgment call, not a certainty — **flagged explicitly for Paul to confirm or correct**, not silently assumed.

## What this doc does not do

This doc, and the two lane design docs it points to, are the Wave 0 output for this track — the same shape v0.5.0 used (`WAVE-0-CANONICAL-SOURCE.md`, `WAVE-0-LANE-C-MCP-DESIGN.md`) before any Wave 1 building started. Per this project's standing discipline (and the explicit hard-stop pattern v0.3.0/v0.4.0/v0.5.0 all used), **building does not start on this track until Paul explicitly approves it**, separately from approving these designs as frozen.

## Documents in this track

- `LANE-E-AUDIT-REPLAY-DESIGN.md` — full design for `graphsmith audit replay`, including a first-draft JSON Schema, CLI surface, evidence-anchoring rules, and an explicit security-tier judgment (heavier than Wave 1, lighter than full GSA security-tier).
- `LANE-F-CODING-SESSION-POSTMORTEM-DESIGN.md` — full design for `graphsmith postmortem`, including the ADOPT/ADAPT/REJECT resolution (ADAPT), a first-draft JSON Schema, adapter design, and an explicitly unresolved judge-layer question left for Paul.

Both were adversarially reviewed by an independent agent (fresh context, no access to the builder's reasoning) before this canonical doc was written; real findings from both reviews are folded into each design doc directly (see each doc's "Adversarial review" section) rather than listed separately here.

## Build discipline for this track (once approved)

Same core discipline as v0.5.0 (one writer per lane, builder ≠ reviewer, no self-graded tests) — see `.plans/v0.5.0/CLAUDE-CODE-KICKOFF.md`'s build-discipline section for the shared baseline — **plus, for Lane E specifically, the heavier bar its own design doc §7 specifies**: at least one non-Anthropic-family adversarial pass targeted at (a) secret/PII leak-through from raw trace excerpting, and (b) fuzzed/forged verification-input handling. Lane F does not carry this extra bar — it has no attestation surface — but does carry its own explicit open question (the judge-layer sealed-subprocess decision) that must be resolved before that specific sub-piece is built, even if the rest of Lane F proceeds.

## Open items for Paul (do not proceed past these on independent judgment)

1. **Confirm the Wave-1 placement reading above** (this track's own Wave 1, not v0.5.0's) — or correct it.
2. **Confirm the "coding skills" interpretation.** This doc and Lane F's design treat "coding skills" as meaning the raw Claude Code/Codex session post-mortem capability (mindwalk's literal domain), matching the "both, eventually" answer from the prior turn. This has been the working interpretation through the design phase but had not been explicitly re-confirmed with Paul until this doc.
3. **The CLI copy-vs-implementation gap.** GraphSmith's own README/launch copy already promises a `plan → sign → apply → verify → replay` lifecycle; only `verify` is actually implemented in `scripts/graphsmith-cli.js`. Lane E's `audit replay` would be the first real implementation of the `replay` half of that promise. Two options, not yet decided: (a) fix the copy now to stop overclaiming ahead of Lane E existing, or (b) leave the copy as a known gap and let Lane E's eventual build resolve it directly. No default has been chosen.
4. **Go-ahead to build.** These designs are frozen and reviewed; nothing has been built. Wave 1 work on this track (Lanes E and F) starts only after Paul says so.
