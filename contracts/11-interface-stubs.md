# Contract 11 — Per-Component Interface Stubs, Ownership Lanes, Rotation
Status: DRAFT. One writer per lane (coordination rule 1): a component's builder owns EXACTLY the files listed; touching another lane's files fails the orchestrator gate. Builder/tester families per blueprint §6; security tier = 2 non-Anthropic tester families + Paul's gate.

Conventions binding every component: Node ≥ 18, CommonJS, zero runtime dependencies (v0.1.1 house style [KnoSky: scripts/scaffold.js:2-9]); no clocks/randomness in decision paths; `schema_version` on every artifact; JSON to stdout / prose to stderr; exit codes 0/1/2(/3 where contract 08 applies); every script has `--selftest` where feasible (pattern: [KnoSky: SKILL.md:77]).

## Phase A
| Component | Lane (owns) | Public surface | Tier | Builder → Tester(s) |
|---|---|---|---|---|
| A1 gate.js | `scripts/gate.js`, `tests/gate/` | contract 08 | SECURITY | DeepSeek → GPT-sol-pro + Grok |
| A2 sentinel | `scripts/verify.js`, `tests/verify/` | `verify --integrity --selftest --profiles --trust-model`; failure domains (plan §5); dual manifests (contract 09) | SECURITY | Claude Sonnet → Gemini + DeepSeek |
| A3 promote.js | `scripts/promote.js`, `tests/promote/` | `promote(packet)`, `rollback(txid)`, `recover()`; contract 01 exactly | SECURITY | GPT-sol (codex) → Grok + DeepSeek |
| A4 manifest.js | `scripts/manifest.js`, `tests/manifest/` | `generate(kind)`, `verifyTree(manifestPath)`, canonicalization per contract 09 | SECURITY | Qwen → GPT-sol-pro + Gemini |
| A5 scenario.js + seed corpus | `scripts/scenario.js`, `scenarios/` (12 smoke-tier, per shape) | `record --auto`, `replay --paired --seed`, corpus schema w/ pinned seeds | routine | Qwen → Claude Sonnet |
| A6 CI (3-OS) | `.github/workflows/ci.yml` (extend existing [KnoSky: .github/workflows/ci.yml]) | matrix: windows/macos/ubuntu; jobs: selftests, attack suites, docs lint (contract 10) | SECURITY | Claude Sonnet → DeepSeek + GPT-sol-pro |
| A7 attack suites | `tests/attacks/{constitutional,toctou,module-escape}/` | runnable batteries; each case = fixture + expected containment | SECURITY | Grok → Gemini + DeepSeek |
| A8 lab harness spec impl | `lab/` (fixtures, battery, scorers — contract 12) | `node lab/run.js --agent <adapter> --task <T#>` | routine | Claude Haiku → Qwen |

## Phase B
| B1 supervisor | scaffold template additions in `scripts/scaffold.js` (manager budget block) + `scripts/watchdog.js` | full §7 budget set; breach → HALT + evidence; `--acknowledge-budget`; separate watchdog process (blocked-event-loop kill) | SECURITY | Qwen → GPT-sol-pro + Grok |
| B2 adapter capabilities | scaffold template `adapters/*.capability.json` + manager kill-message derivation | contract 06 | SECURITY | Claude Sonnet → DeepSeek + Gemini |
| B3 prompt separation + workflow.manifest + tunables | scaffold templates: `workers/*.prompt.md`, `workflow.manifest.json`, `tunables.json` | contract 09 workflow-manifest section; loader per B3 boundary | routine | Claude Haiku → Qwen |
| B4 heal.js (staged-only) | `scripts/heal.js`, `tests/heal/` | `heal --diagnose`, `heal --stage`, `heal rollback <id>` (byte-exact); typed-vs-code split (plan §3.3); diagnosis via event compiler only | SECURITY | Grok-build → GPT-sol-pro + DeepSeek |
| B5 graphlint R5/R6 | `scripts/graphlint.js` (extend — existing rules R1–R4 [KnoSky: scripts/graphlint.js:182-210]), `tests/lint-corpus/` additions | R5: eval/new Function/raw exec/new require-import in machine-evaluated candidates + scaffold adapters; R6: adapter capability declaration present + destination allowlist match | routine | DeepSeek → Claude Sonnet |

## Phase C
| C1 evalenv (I3) | `scripts/evalenv.js`, `tests/evalenv/` | `create(profile)` → disposable copy (full copy, no shared git metadata, module-isolation: NODE_PATH hygiene + resolution check + symlink audit), `destroy()`, transactional clean + age-GC | SECURITY | Claude Sonnet → DeepSeek + Gemini |
| C2 event-compiler + sanitizer | `scripts/event-compiler.js`, `tests/events/` | contract 07 | SECURITY | DeepSeek → Gemini + Grok |
| C3 evolve.js | `scripts/evolve.js`, `tests/evolve/` | harvest→mine→≤3 bounded edits→Gates 1–4; staged-only; rejected buffer; `.graphsmith/` state + migration API (F16) | SECURITY | DeepSeek → GPT-sol-pro + Gemini |
| C4 Gate 3+4 wiring | `scripts/gate.js` gate3/gate4 sections + window state | contracts 02, 08 | SECURITY | GPT-sol (codex) → DeepSeek + Grok |
| C5 assurance cmds | `scripts/test.js` (wraps scenario+chaos [KnoSky: scripts/chaos.js:1-20]), `redteam.js` | §17: deterministic pass/fail + per-check evidence; BYO attack cases; external-tool seam (exit-code + JSON contract) | SECURITY (seam) | Grok → Gemini + DeepSeek |

## Phase D
| D1 watch | `scripts/watch.js` | local tail of checkpoints/logs/budgets/tripwires; kill w/ capability message (contract 06) | routine | Claude Haiku → Qwen |
| D2 diagnostics export | `scripts/diagnostics.js` | preview + redaction, aggregate counters default, zero upload code (static-checked) | SECURITY (I4) | Claude Sonnet → GPT-sol-pro + DeepSeek |
| D3 advisory watcher | `scripts/watcher.js` | OFF by default; structured logs only; flag-only; batched | routine | Qwen → Claude Sonnet |

## Phase E
| E1 verify --profiles | `scripts/verify.js` extension | R/E/B/T/G + Q/X per-check evidence, verifier version, platform | SECURITY | Claude Sonnet → Gemini + Grok |
| E2 CI action + GitLab template | `action/` + `ci-templates/` | wraps verify; pinned-SHA usage documented | SECURITY | GPT-sol (codex) → Claude Sonnet + DeepSeek |
| E3 PROTOCOL.md + SPEC-CHANGES.md | `GRAPHSMITH-PROTOCOL.md`, `SPEC-CHANGES.md` | draft banner; schemas from contracts 06/07/09; profile definitions with checks + limits | routine (Paul reads pre-merge anyway) | Claude Sonnet → GPT-sol-pro |
| E4 badge | `scripts/badge.js` | evidence-carrying render (profile string + verifier + platform + date + CI link); stale → downgrade; unprovable → "unavailable" | routine | Claude Haiku → Gemini |
| E5 Loop 3 shadow CI | `.github/workflows/shadow-eval.yml` | held-out deltas on SKILL/references PRs; trusted workflow; no lesson intake | SECURITY | DeepSeek → GPT-sol-pro + Gemini |

Phase F components are docs/demos over the above (routine; honest-language lint gates them). Rotation invariant holds in every row above: no family in both columns; security rows have 2 tester families, both non-Anthropic except where the builder is non-Anthropic (then Anthropic may be ONE of the two).
