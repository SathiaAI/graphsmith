# clarity-agent + ponytail — extraction synthesis for GraphSmith's embed/discovery capability

**Prepared:** 2026-07-30, for Paul + engineering. **Audience:** build-ready — this ends in a concrete plan an engineer or a Claude Code session can pick up.
**Repos reviewed:** `microsoft/clarity-agent` (MIT; 6-agent source-level deep dive done 2026-07-29 night, re-verified fresh tonight — no changes, all load-bearing claims hold) and `DietrichGebert/ponytail` (MIT; 3-agent source-level deep dive done tonight, first-time research). All claims below are cited to file:line from direct source reads, not README text, in both cases.
**Source docs (GraphSmith Claude project):**
- `graphsmith-clarity-agent-extraction-synthesis-2026-07-30.md` + its 6 subsystem docs (staleness engine, mailbox/thinker, decision tracking, MCP server, LLM/evals/license, `graphsmith-clarity-agent-oss-extraction-2026-07-30.md` — the embed-mechanism deep dive, most relevant here)
- `graphsmith-ponytail-embed-mechanism-2026-07-30.md`, `graphsmith-ponytail-hooks-enforcement-2026-07-30.md`, `graphsmith-ponytail-benchmarks-mcp-license-2026-07-30.md`
- `graphsmith-capability-enforcement-withdrawn-2026-07-29.md` — GraphSmith's own recent, hard-won lesson, which this synthesis leans on directly

---

## Executive summary

Both repos are worth extracting from, but not for the reason "seamless discovery" implies. Neither repo has solved automatic discovery of a skill in a cold, fresh repo — both require a human to already know about the tool and run a per-host install command first. What both repos *do* have, in different proportions, is good **installation plumbing** (how you go from "I decided to use this" to "it's active in my agent, in every host I use, without me hand-editing 8 files") and — in ponytail's case — a genuinely well-built **Claude Code plugin + lifecycle-hook** mechanism that is real, not aspirational. If your mental model going in was "these repos solved the discovery problem, let's copy it," that model is wrong. If the model is "these repos have good *installation* patterns we're missing, and one clean *fan-out* pattern for many-host distribution," that's correct and is what the plan below builds.

There's a second, sharper finding underneath the first: **both repos' core "process compliance" mechanism — clarity-agent's staleness gate, ponytail's decision ladder — is, at the code level, 100% prompt injection with zero enforcement.** Neither blocks a tool call, parses a diff, or fails a build if ignored. This lands with extra weight here because GraphSmith's own team just spent five rounds of adversarial review discovering, the hard way, that a "green" claim over an unenforced boundary is worse than an honest "not enforced" one (`graphsmith-capability-enforcement-withdrawn-2026-07-29.md`). Both repos independently confirm that lesson from the outside. The actionable version: whatever GraphSmith builds from this research must not claim to "enforce" the ponytail-style ladder or the clarity-agent-style gate — it should market itself, honestly, as good context-delivery plumbing.

---

## What's real vs. theater, side by side

| | microsoft/clarity-agent | DietrichGebert/ponytail |
|---|---|---|
| Age / maturity | Established, actively maintained (commits through 2026-07-29, re-verified tonight) | ~7 weeks old, viral (~90k stars), single-maintainer-dominated (~52% of commits), **quiet for the last 15 days** |
| Core compliance mechanism | Markdown process guides read into an MCP tool response; a real SHA-256 staleness *detector* (`packet_status.py`) that only ever produces a recommendation string | Markdown ruleset injected via Claude Code lifecycle hooks (`SessionStart`/`SubagentStart`/`UserPromptSubmit`) into system context every turn |
| Real tool-call enforcement anywhere? | **No.** Verified again tonight: grep'ed `src/` for hook/gate/deny/block/pretooluse patterns — nothing. | **No.** No `PreToolUse` registration for Claude Code exists at all. |
| AGENTS.md handling | **Real, idempotent, marker-delimited reconciler** (`snippet.py`/`ensure_agents_md`) | **None.** Pure manual copy-paste per the README |
| Multi-host fan-out | N/A (single MCP-server distribution channel) | Partially generated (1 of 8+ surfaces), rest hand-copied + CI-diff-checked — already missed a real drift bug once (#260/#262) |
| Claude Code plugin + hooks | Not applicable — distributes as MCP server via `.vscode/mcp.json` | **Real, zero-repo-footprint plugin** (`.claude-plugin/`) with three genuinely firing lifecycle hooks, self-cleaning uninstall |
| MCP server | 9 tools, zero auth anywhere | 1 prompt + 1 tool, ~80 LOC, deliberately `"private": true` |
| npm/package publishing | N/A — Python package | Real OIDC-signed provenance publish pipeline (GitHub Actions trusted publishing) |
| Benchmark/claims rigor | N/A | Genuinely reproducible A/B harness but raw run data not committed, single-model (Haiku only), headline number revised down multiple times |
| License | MIT | MIT |

---

## Ranked extraction list

1. **AGENTS.md idempotent reconciler — ADOPT ADAPTED from clarity-agent (`snippet.py`).** Marker-delimited begin/end block, versioned meta header, four-way state machine (absent→write; present-no-markers→append; present-current→no-op; present-drifted→splice-in-place) that never clobbers user content outside the block. Build once, use for every single-file surface.
2. **Claude Code plugin + lifecycle hooks — ADOPT AS-IS the shape, from ponytail.** `.claude-plugin/marketplace.json` + `plugin.json` + hooks registering `SessionStart` and `SubagentStart` (ship from day one, unlike ponytail's late #252 fix). Writes nothing into the target repo.
3. **MCP-server-as-carrier-of-instructions — ADOPT ADAPTED, converges in both repos.** Real, independently-publishable package; token/transport-level auth for non-stdio transports (clarity-agent has zero); keep the tool-response-carries-markdown pattern.
4. **Full canonical→all-surfaces generator — ADOPT ADAPTED, one step past ponytail.** Extend `build-openclaw-skills.js`'s pattern to every surface, not just one with the rest hand-copied.
5. **Two-tier install (thin/PATH-delegating vs. heavy clone+venv) — ADOPT ADAPTED from clarity-agent.**
6. **OIDC-signed npm provenance publishing — ADOPT AS-IS from ponytail** — already GraphSmith's v0.4.0 R5 scope; use ponytail's workflow as a reference.
7. **CI drift-checkers as belt-and-suspenders — ADOPT ADAPTED, backstop only, not primary mechanism.**
8. **Published, dated, issue-linked benchmark/postmortem practice — ADOPT ADAPTED as a credibility artifact.**
9. **The decision-ladder / staleness-gate mechanisms — REJECT for enforcement claims, ADOPT ADAPTED as content/UX only, if at all.**

---

## What neither repo solves

Neither repo solves cold-start discovery — an agent in a repo that's never heard of GraphSmith, with no prior install step, does not find and adopt it in either codebase. Ponytail's own README says as much about its own design. "Trivially easy to install once you've decided to use it" and "an agent discovers and adopts it with zero human action" are two different problems; nothing in either repo advances the second.

---

## Recommendation: roadmap placement

**New track — "v0.5.0: Distribution & Discovery" — not folded into v0.4.0.** v0.4.0 is scoped as enterprise/security hardening; nothing in this extraction list is security-critical. Matches the already-planned "plugin-marketplace scaffold DEFERRED to after v0.4.0."

Two small pull-forwards into v0.4.0: use ponytail's publish workflow as a reference for R5 (SBOM/provenance); add "auto-discovered"/"seamlessly discovered" to the honest-language lint's banned-phrase watch-list now.

---

## Addendum (2026-07-30, later same day) — decisions resolved, plan updated

### Decision 1 — Version slot: v0.5.0, parallel with v0.4.0

v0.4.1 is already spoken for (v0.4.0's own overflow valve). v0.5.0's four lanes are new files, no schema/verifier contention, no security-tier review needed — can start now, on its own branch, independent of v0.4.0's timeline.

### Decision 2 — AGENTS.md ownership: Option 2 (separate canonical source is master; AGENTS.md is just another rendered/reconciled surface)

Two options considered. Option 1 (AGENTS.md itself as master copy): simplest mental model, matches ponytail's SKILL.md-as-source pattern, but AGENTS.md's plain prose likely can't carry every host's metadata needs, and the "master copy" gets entangled with exactly the reconciler's marker boundaries. Option 2 (a separate canonical file is master; AGENTS.md is a generated+reconciled target like every other surface): cleanly separates render-then-place into two composable steps reused across every surface, scales past what prose can hold, costs one more file most users won't open directly. **Recommendation: Option 2** — it resolves the conflict instead of pushing it into the reconciler's edge cases. (Executed against the live repo in Wave 0: the canonical file turned out to already exist as root `SKILL.md` rather than needing a new file — see `WAVE-0-CANONICAL-SOURCE.md`.)

### Decision 3 — Host-surface launch scope: four surfaces, generator-first sequencing

**Recommendation:** launch with AGENTS.md-generic (free) + Claude Code (Lane B) + Cursor + GitHub Copilot. Not the bare floor of 3, not ponytail's full ~8. Step by step: (1) Wave 0 locks the canonical-source decision and the adapter schema; (2) build Lane A + Lane D together first, since every adapter depends on both; (3) ship adapters in priority order — AGENTS.md-generic (zero marginal work) → Claude Code plugin+hooks → Cursor → Copilot; (4) each adapter after the first two is an independently shippable PR; (5) Wave 2 RC gate closes with whatever's done, doesn't hold for a 5th adapter; (6) Windsurf/Cline/Qoder/etc. ship later as point releases once there's a concrete user signal.

### Decision 4 — Stateless MCP: build Lane C stateless-native per SEP-2575, legacy `initialize` as fallback

MCP went stateless in its 2026-07-28 revision ([SEP-2575](https://modelcontextprotocol.io/seps/2575-stateless-mcp), Final). The old mandatory `initialize`/`initialized` handshake (creating server-remembered session state) is removed; every request is now self-contained via HTTP headers + `_meta` fields; a new `server/discover` RPC (mandatory) replaces the handshake's capability-negotiation half; `resources/subscribe`/`unsubscribe` are replaced by a new opt-in `subscriptions/listen`; resumable SSE and `ping` are removed outright. This directly fixes the exact security gap found in clarity-agent's MCP server: the spec's own Security Implications section states "without a session handshake, every request must be independently authenticated and authorized" — building Lane C stateless-native forces per-request auth by construction. It also reframes what "seamless" can mean for Lane C: a stateless server has no reason to be pinned to one machine, so a future hosted/serverless deployment (one URL, nothing to install) becomes a legitimate option — not in scope for Wave 1, but a real opportunity to record. The spec itself anticipates day-2 client-readiness risk and describes the fix: dual-support both the legacy handshake and the new stateless RPCs, with clients probing `server/discover` first and falling back on 400/404. **Recommendation: build Lane C stateless-native per the new spec, legacy `initialize` kept as a compatibility fallback** until Claude Code's actual installed MCP client/SDK version is confirmed (Wave 0 action item). This also nudges — but does not decide — the open question of whether Lane C should share one deployment with the planned v0.3.0 MCP attestation shim; presented as a tradeoff for Paul/the shim owner to confirm before Wave 1's Lane C builder commits to either shape.

---

## Sources

`microsoft/clarity-agent` (MIT) — https://github.com/microsoft/clarity-agent, re-verified 2026-07-30. `DietrichGebert/ponytail` (MIT) — https://github.com/DietrichGebert/ponytail, researched 2026-07-30, HEAD `16f2980`. Full per-subsystem citations in the companion docs in the GraphSmith Claude project.

**Stateless MCP (Decision 4):** [SEP-2575: Make MCP Stateless](https://modelcontextprotocol.io/seps/2575-stateless-mcp) (Final, Standards Track), fetched and read in full 2026-07-30. Secondary/practitioner coverage of the 2026-07-28 release: [MCP Blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/), [4sysops](https://4sysops.com/archives/2026-07-28-model-context-protocol-mcp-stateless-multi-round-trip-routable-headers-authorization-hardening/), [Microsoft Community Hub](https://techcommunity.microsoft.com/blog/appsonazureblog/mcp-just-went-stateless-%E2%80%94-what-the-2026-spec-changes-about-scaling-on-app-servic/4530222), [XenoSpectrum](https://xenospectrum.com/en/mcp-2026-stateless-release/), [Stacktree](https://stacktr.ee/blog/mcp-2026-spec-changes), [Vindler Blog](https://vindler.solutions/blog/mcp-2026-07-28-stateless-spec).
