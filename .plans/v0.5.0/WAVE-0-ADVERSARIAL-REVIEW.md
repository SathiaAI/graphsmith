# v0.5.0 Wave 0 — adversarial review record

**Date:** 2026-07-31. **Why this exists:** Wave 0's three deliverables (schema, canonical-source decision, Lane C design) were originally written and committed without independent review — a gap in the build discipline `CLAUDE-CODE-KICKOFF.md` itself specifies for Wave 1 ("builder ≠ reviewer, every lane... do not let the builder propose the adversarial tests for its own code") but that wasn't applied to Wave 0 itself before PR #12 was opened. Paul asked whether Wave 0 had gone through adversarial review; it had not. This document records the review that was then run, its findings, and what was fixed as a result.

## Method

Two independent reviewers, each with fresh context (no exposure to the reasoning behind the original documents, only the frozen artifacts themselves), each explicitly instructed to find real flaws rather than confirm the work looked fine:

1. **Schema reviewer** — given `host-adapter.schema.json` verbatim plus the four launch adapters' real-world targets, instructed to check the schema against Cursor's actual `.mdc` frontmatter requirements and Copilot's actual `copilot-instructions.md` format via web search, not training-data assumptions.
2. **Lane C design reviewer** — given `WAVE-0-LANE-C-MCP-DESIGN.md` verbatim, instructed to fetch the actual SEP-2575 spec text and verify the design doc's summary of it independently before checking the design against it, rather than trusting the design doc's own framing of the spec.

Separately, the live-repo claims in `WAVE-0-CANONICAL-SOURCE.md` (AGENTS.md, `.claude-plugin/`, `.cursor/`, `.github/copilot-instructions.md` all absent from `main`; `SKILL.md` structure) were re-verified fresh against the repository via the GitHub connection, independent of the original checks. All re-verified claims held — no changes to that document.

## Findings and resolutions

### Schema (`host-adapter.schema.json`)

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | `generatedFileHeader` placement relative to YAML frontmatter was unspecified. Cursor's `.mdc` parser silently fails to load any file with content preceding the frontmatter block (no error, no log) — a builder placing the header above `---` produces a rule that quietly never activates. | HIGH | Field description now states placement is format-dependent and mandates the header go immediately after the closing `---`, never before it, with the specific Cursor failure mode named explicitly. |
| 2 | `frontmatterFields[].source` said "copy/adapt" with no defined behavior when a value exceeds `maxLength` — four builders could each resolve overflow differently (truncate, fail, override). | MEDIUM-HIGH | `maxLength` enforcement is now explicitly a build-time validation error, not silent truncation; an oversized `source`-derived value must be replaced with `static` instead. |
| 3 | `source` was an unconstrained string, so a typo (`"desc"` vs `"description"`) would pass schema validation and fail silently at generation time. Separately, reconciled-mode target files' comment/marker syntax was an unstated assumption (HTML comments), true only because both current reconciled targets happen to be Markdown. | MEDIUM / LOW-MEDIUM | `source` is now a closed enum (`name`, `description`, `static`) matching canonical `SKILL.md`'s actual current frontmatter fields. `placementMode`'s description now states the HTML-comment-marker assumption explicitly and flags it as needing a schema extension before any non-Markdown reconciled target is added. |
| 4 | Nothing forbade the semantically broken combination `placementMode: reconciled` + `outputFormat: markdown-frontmatter` (a reconciler can't own both a mid-file block and the document's absolute top). | LOW | Added an `if`/`then` constraint disallowing the combination; none of the four launch adapters need it. |
| 5 | `additionalProperties: false` at the top level means any future per-adapter field forces a synchronized version bump across all four lanes rather than additive extension. | LOW (accepted) | No schema change — this is a deliberate YAGNI tradeoff, not a defect, and no launch adapter needs a field the schema is missing today. Left as a known coordination cost for future adapters. |

**Non-issues the reviewer checked and found fine:** Copilot's `markdown-plain` mapping (confirmed `.github/copilot-instructions.md` has no frontmatter requirement); `bodyTransform: verbatim` as a single-value enum (correctly scoped YAGNI, not speculative machinery); Cursor's `description`/`globs`/`alwaysApply` fields are all expressible via the existing `frontmatterFields` mechanism.

### Lane C design (`WAVE-0-LANE-C-MCP-DESIGN.md`)

SEP-2575 claims in the original design were independently re-verified against the fetched primary spec text and confirmed accurate in every case checked (mandatory `server/discover`, its return shape, the explicit backward-compatibility dual-support pattern, the security-implications language on per-request auth, the existence of mandatory per-request `_meta` fields). The gaps found were in what the design did with an accurately-understood spec, not in spec misrepresentation.

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | The legacy `initialize` fallback's load-bearing status was left as an open check for the Wave 1 builder, framed as roughly a 50/50 unknown. Ecosystem evidence (only beta/pre-release Tier-1 SDKs speak the new stateless protocol as of the spec's 2026-07-28 finalization) makes it a near-certainty that stock clients still speak the legacy protocol only three days later. | HIGH | Resolved now, not deferred: legacy `initialize` is declared REQUIRED and load-bearing for Wave 1 launch. The remaining Wave 1 action is confirmation, not a decision with two live branches. |
| 2 | The deferred check was worded ambiguously between checking Lane C's own dependency version (irrelevant — fully within Lane C's control) and the actual Claude Code host binary's protocol behavior (the thing that actually matters, and is externally versioned). | MEDIUM-HIGH | Design now specifies the correct check: spawn the actual Claude Code binary, observe its first stdio message, record the finding in `BUILD-LEDGER.md`. Explicitly states that checking `package.json` does not satisfy this. |
| 3 | The design specified `server/discover`'s behavior in detail but said nothing about how the actual tool-call path (`graphsmith_guidance`) validates the per-request `_meta` fields SEP-2575 makes mandatory on every RPC, not just discovery. | MEDIUM | Added explicit requirement: the tool handler must validate `_meta` fields per call and return the spec's specified error codes (`INVALID_PARAMS`, `UNSUPPORTED_PROTOCOL_VERSION`/-32022) for missing/malformed/unsupported requests. |
| 4 | `graphsmith_guidance`'s "no arguments required" didn't specify whether unexpected arguments are rejected or silently ignored. | LOW | Design now specifies the exact input schema (`additionalProperties: false`) so unexpected arguments produce a validation error. |
| 5 | The stdio "process boundary is the trust boundary" claim is a reasonable inference but isn't something SEP-2575 itself validates, and the original design didn't distinguish "authenticated per spec" from "authorized to spawn" (an assumption MCP doesn't address at all). | LOW | Design now states this distinction explicitly and flags it for re-examination if a second local caller or additional capability is ever considered. |

**Non-issues the reviewer checked and found fine:** `server/discover`'s response shape and mandatory status; package publishability requirements; the explicit non-goals section (hosted deployment, attestation-shim overlap) as honestly-flagged-open rather than silently assumed.

### Canonical source (`WAVE-0-CANONICAL-SOURCE.md`)

Re-verified independently against the live repo: `AGENTS.md`, `.claude-plugin/`, `.cursor/`, and `.github/copilot-instructions.md` all confirmed still absent from `main`; `SKILL.md` content re-fetched and matches the structure described. No changes required.

## Overall verdict

Both reviewers independently concluded the original Wave 0 artifacts were **not safe to build four Wave 1 lanes against as-is** — a real result, not a formality. All HIGH and MEDIUM-HIGH findings have been resolved in this commit. The LOW-severity `additionalProperties: false` coordination-tax item is accepted as a deliberate tradeoff, not fixed, and is recorded here so it isn't rediscovered as a surprise later.
