# v0.5.0 Wave 0 — Canonical source decision (as executed against the live repo)

**Correction to the original Wave 0 prompt:** that prompt proposed creating a new `.graphsmith/skill.md` as the canonical source. Reading the actual repo before writing anything (per this build's own "don't assume" discipline) found that a canonical source **already exists**: root `SKILL.md` (11.6KB, `name`/`description` frontmatter, already the file `npx skills add` and agentskills.io consume, per `graphsmith-branding-and-plugin-status.md`). Creating a second "canonical" file alongside it would recreate the exact dual-source-of-truth conflict Decision 2 (AGENTS.md ownership) was written to resolve, just one level up. **Corrected decision: root `SKILL.md` is the canonical source. No new file is created.**

## What this means for Lane A and Lane D

- **Lane D (generator)** reads `SKILL.md`'s frontmatter (`name`, `description`) and body, and renders per-adapter output per `schemas/host-adapter.schema.json`. It never writes to `SKILL.md` itself — `SKILL.md` is a read-only input to Lane D, full stop.
- **Lane A (reconciler)** never treats `SKILL.md` as a target. Its job is placing Lane D's *rendered output* into `reconciled`-mode surfaces (starting with `AGENTS.md`, confirmed **does not yet exist** on `main` — first install on this repo is a clean create, not a merge, though the reconciler must still be built for the merge case since every downstream user's repo will have this exact situation happen for real).
- `.cursor/rules/graphsmith.mdc` and `.github/copilot-instructions.md` (Copilot's single-file surface) are the other two launch adapters. Per the resolved host-scope decision, Copilot's surface is `reconciled`-mode (single file, could pre-exist with unrelated content in a real user's repo) — `.cursor/rules/` is a directory that tolerates a dedicated GraphSmith file alongside others, so its adapter is `standalone`-mode.
- **`.claude-plugin/` does not yet exist on `main` either** — confirms the plugin-marketplace scaffold referenced in `graphsmith-branding-and-plugin-status.md` ("scaffold READY, DEFERRED to after v0.4.0") was prepared but never merged. Lane B (Claude Code plugin + hooks) is net-new work on this branch, not a resume of prior work — there is nothing to conflict with.

## Current `SKILL.md` structure (read directly, 2026-07-31)

Frontmatter: `name: graphsmith`, `description:` (a long, trigger-phrase-dense paragraph — this is the field every adapter's `frontmatterFields.source` will most commonly map from, subject to each host's own `maxLength`).

Body sections, in order: title + one-line pitch; "The discipline" (7 numbered non-negotiables); "Mode detection" (builder vs. engineer voice — **note this is GraphSmith's own audience-detection mechanism, unrelated to and not to be confused with ponytail's lite/full/ultra intensity modes** — no analogous concept needs porting here); "Phase 0 — Ground (KnoSky)"; "Phase 1 — Blueprint"; "Phase 2 — Build"; "Phase 3 — Verify"; "Scaling to multiple agents"; "Anti-patterns"; "Diagnosing a broken automation".

This confirms `bodyTransform: verbatim` in the frozen schema is correct — there is no mode-conditional content in the body for a transform to filter; the "modes" that do exist (builder/engineer) are voice instructions for whatever LLM reads the file, not a build-time content variant the generator would need to branch on.
