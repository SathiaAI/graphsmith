# Contract 11 — Interface Stubs, Ownership Lanes, Rotation (v2 — lane conflicts resolved)
Status: DRAFT v2 (post-panel-pass-1: Gemini-4, GPT-23/24). **One owner per physical file for the whole release.** A lane lists every file the owner may touch; the orchestrator gate rejects out-of-lane diffs. Task specs are self-contained (verbatim contract/plan excerpts embedded by the orchestrator — workers never fetch the plan).

Conventions: Node ≥ 18, CommonJS, zero runtime deps [KnoSky: scripts/scaffold.js:2-9]; no clocks/randomness in decision paths; `schema_version` everywhere; JSON stdout / prose stderr; exit codes 0/1/2(/3); `--selftest` where feasible [KnoSky: SKILL.md:77].

**Rotation rule (tightened per GPT-23):** a family that authored ANY revision of a file never tests that file, in any phase. Security tier = 2 independent tester families (both non-Anthropic when the builder is Anthropic; else ≥1 non-Anthropic + any second independent family).

## File-owner registry (whole release — resolves A1/C4, A2/E1, scaffold pile-ups)
| File(s) | Sole owner (family) | Testers (never authors of the file) | Tier |
|---|---|---|---|
| `scripts/gate.js` (Gates 1–4 decision engine, all phases) | DeepSeek | GPT-sol-pro + Grok | SECURITY |
| `scripts/state-store.js` (single writer for ALL `.graphsmith/state/`: window store, universal run registry, run anchors, alpha ledger, rejected buffer, rollback families — P2-GPT-2/14) | GPT-sol (codex) | DeepSeek + Gemini | SECURITY |
| `scripts/promote.js` (contract 01) | GPT-sol (codex) | Grok + DeepSeek | SECURITY |
| `scripts/verify.js` (sentinel, Phase A core + Phase E `--profiles`) | Claude Sonnet | Gemini + DeepSeek (A), Gemini + Grok (E) | SECURITY |
| `scripts/manifest.js` | Qwen | GPT-sol-pro + Gemini | SECURITY |
| `scripts/loaders.js` (appendix + prompt loaders, B2/B3 — NEW lane, GPT-24) | Claude Sonnet | DeepSeek + Grok | SECURITY |
| `scripts/scenario.js` + `scenarios/` | Qwen | Claude Sonnet | routine |
| `scripts/event-compiler.js` + `schemas/lesson-event.schema.json` | DeepSeek | Gemini + Grok | SECURITY |
| `scripts/evolve.js` + migration API (`scripts/migrate.js`, F16 redaction test) | DeepSeek | GPT-sol-pro + Gemini | SECURITY |
| `scripts/heal.js` | Grok-build | GPT-sol-pro + DeepSeek | SECURITY |
| `scripts/evalenv.js` | Claude Sonnet | DeepSeek + Gemini | SECURITY |
| `scripts/scaffold.js` (ALL template changes B1–B3 integrate here under ONE owner) | Claude Sonnet | GPT-sol-pro + Qwen (behavioral), DeepSeek (security review of manager/supervisor templates) | SECURITY |
| `scripts/watchdog.js` (separate process, §7) | Qwen | GPT-sol-pro + Grok | SECURITY |
| `scripts/graphlint.js` (R5/R6 additions; existing R1–R4 [KnoSky: scripts/graphlint.js:182-210]) + `tests/lint-corpus/` | DeepSeek | Claude Sonnet + Gemini | routine |
| `scripts/risk-policy.json` + capability policy (syntactic allowlist, plan §3.3 — NEW lane) | Claude Sonnet | DeepSeek + GPT-sol-pro | SECURITY |
| `scripts/test.js`, `scripts/redteam.js`, `scripts/assure.js` (minimal packet, §17) + external-tool runner | Grok | Gemini + DeepSeek | SECURITY (seam) |
| `scripts/watch.js` | Claude Haiku | Qwen | routine |
| `scripts/diagnostics.js` | Claude Sonnet | GPT-sol-pro + DeepSeek | SECURITY (I4) |
| `scripts/watcher.js` (advisory, off-default) | Qwen | Claude Sonnet | routine |
| `scripts/docs-lint.js` (contract 10 lists A+B — NEW lane) | Claude Haiku | DeepSeek + Gemini | SECURITY (CI enforcement) |
| `scripts/badge.js` + property-matrix generator (`scripts/property-matrix.js` — NEW lane) | Claude Haiku | Gemini + GPT-sol-pro | routine |
| `.github/workflows/*` (extends existing [KnoSky: .github/workflows/ci.yml]) + `action/` + `ci-templates/` | Claude Sonnet | DeepSeek + GPT-sol-pro | SECURITY |
| `GRAPHSMITH-PROTOCOL.md`, `SPEC-CHANGES.md`, RELEASING.md, docs | Claude Sonnet | GPT-sol-pro | routine |
| `lab/` (contract 12: fixtures, tasks, agents, score.js, ledgers) | Claude Haiku | Qwen + DeepSeek (scorer integrity) | SECURITY (scorer) |
| `tests/attacks/{constitutional,toctou,module-escape}/` | Grok | Gemini + DeepSeek | SECURITY |

Phase mapping unchanged (plan §11): A = gate/verify/manifest/promote/state-store/loaders/scenario/CI/attacks/lab-skeleton · B = scaffold+watchdog+capabilities+heal+graphlint · C = evalenv+event-compiler+evolve+gate3/4 wiring+test/redteam · D = watch/diagnostics/watcher · E = profiles/action/protocol/badge/matrix/shadow/assure-minimal · F = docs/demos.

## Ownership completeness (P2-GPT-14)
- **Test trees:** `tests/<component>/` is OWNED BY THE TESTER family of that component (authors barred from writing their component's tests — that IS the rotation); with two tester families, each owns a named subdirectory. `schemas/*.schema.json` belongs to the lane that owns the emitting script. Generated artifacts (manifests, matrices) are owned by their generator's lane; fixtures under `lab/` by the lab lane.
- **Mechanical check:** before Phase A dispatch, the orchestrator generates `.plans/ownership-map.json` enumerating every planned path → exactly one owner; zero or multiple owners fails Stage 0 mechanically. The map is regenerated and re-checked at every phase boundary.

## Constitutional set (superset — GPT-24; mechanically re-derived in Phase A from the enforcement dependency graph, then frozen in the release manifest)
gate.js · verify.js · promote.js · window-store.js · manifest.js · loaders.js · event-compiler.js · scenario.js · evalenv.js · watchdog.js · graphlint.js · docs-lint.js · risk-policy.json · scaffolded manager/supervisor/intent-guard templates · CI workflow entries · schemas/ · tunables BOUNDS · this contracts/ directory.

## Component stubs (signatures; unchanged items carried from v1)
- `promote.js`: `promote(packet) → {txid, state}` · `rollback(txid_or_inverse)` · `recover()` — contract 01 exactly.
- `window-store.js`: `admit(tx)` · `register(runId, treeId)` · `deregister(runId, result)` · `status()` — contract 02 CAS ops.
- `gate.js`: contract 08 (decision engine only; all persistence via window-store/state APIs).
- `verify.js`: `--integrity --selftest --profiles --trust-model --platform-probe` (probe added per contract 01).
- `loaders.js`: `loadAppendix(ctx)` / `loadPrompt(worker)` — resolve via `.graphsmith/evolvable/ACTIVE`, enforce B2/B3, return `{content, treeId, hash}`.
- `manifest.js`: `generate(kind)` · `verifyTree(manifest, root)` — contract 09 canonicalization.
- `event-compiler.js`: `compile(runDirs) → {proposerView, evidenceMap, stats}` — contract 07.
- `evalenv.js`: `create(profile) → {dir, destroy()}` — module-isolation checks, secret-scrub, budgets.
- `heal.js`: `--diagnose` · `--stage` · `rollback <id>` (byte-exact) — typed-vs-code split (plan §3.3).
- `evolve.js`: `cycle()` — harvest→mine→≤3 bounded edits→Gates 1–4, staged-only.
- `test.js`/`redteam.js`/`assure.js`: §17 — deterministic pass/fail + per-check evidence; container-required for untrusted tools (B10); assure-minimal packet in v0.2.0, full format v0.2.x.
- `watchdog.js`: spawned by manager; kills on blocked-event-loop budget breach; chaos-grade resume proof.
