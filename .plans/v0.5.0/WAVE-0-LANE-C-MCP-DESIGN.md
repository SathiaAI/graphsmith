# v0.5.0 Wave 0 — Lane C (MCP server) design, stateless-native

Per the resolved Decision 4. Design only — no code in this commit; Lane C's builder subagent implements this in Wave 1.

## Tool surface

One tool: `graphsmith_guidance`. Read-only. No arguments required. Returns the current `SKILL.md` body (the same canonical content Lane D renders from) as its result, mirroring the pattern found in both research repos (clarity-agent's `run_clarity`, ponytail's `ponytail_instructions`) — a tool call returns markdown instructions inline, so there is no separate registration step for "which guidance applies now." Kept to one tool deliberately: clarity-agent's 9-tool surface was found to be more than this use case needs, and every additional tool is more surface to keep in sync and more surface to secure.

## `server/discover` (mandatory per SEP-2575)

Returns `supportedVersions` (the 2026-07-28 spec version, plus whatever legacy version the `initialize` fallback below speaks), `capabilities` (advertises the single `graphsmith_guidance` tool, nothing else), `serverInfo` (name/version from `package.json`), and `instructions` (a short string pointing a client at `graphsmith_guidance` — the spec explicitly supports this field for exactly this purpose).

## Statelessness and auth

No session ID anywhere in the implementation. Every call to `graphsmith_guidance` is independently authenticated — for the stdio transport (the only one in scope for Wave 1; see Non-goals below) this means the process boundary itself is the trust boundary, same as any local stdio MCP server; no additional token is needed for stdio specifically, but the code must not silently assume a network transport will ever be safe to add without one. If a network transport is added in a later release, per-request bearer-token auth is a hard prerequisite, not a follow-up — this is the exact gap found in `clarity-agent`'s MCP server (zero auth on `sse`/`streamable-http`) and it does not get repeated here.

## Legacy `initialize` fallback

Implemented per SEP-2575's own documented dual-support pattern: the server accepts the legacy `initialize`/`notifications/initialized` handshake for clients that send it, and separately exposes `server/discover` and the stateless per-request path for clients that probe for it first. **Before Wave 1 closes this lane, the builder subagent must check which MCP SDK/protocol version the Claude Code build actually installed at build time speaks**, and record that finding here or in `BUILD-LEDGER.md` — if it already speaks 2026-07-28, the legacy path can be deprioritized (built, but not load-bearing for launch); if it doesn't yet, the legacy path is required for Lane B's own plugin to be able to reach this server at all.

## Package shape

Independently publishable — `npm install` in an empty directory must work with no assumption of a monorepo checkout (the specific failure mode found in ponytail's `ponytail-mcp/`, which is `"private": true` and reaches outside its own package directory via `createRequire`, and therefore cannot ship standalone). GraphSmith's version reads `SKILL.md` via a path resolved relative to the *installed package's own* copy of it (the package's `files` allowlist must include `SKILL.md`), not via a relative path assuming a sibling checkout.

## Non-goals for Wave 1 (flagged, not decided)

- **Hosted/serverless deployment.** Because a stateless server has no reason to be pinned to one machine, a horizontally-scaled or serverless hosted deployment — letting any MCP-capable host reach GraphSmith's guidance via one URL, nothing installed locally — is a legitimate future option opened up specifically by the spec going stateless. Recording it here as a noted opportunity. Not in scope for Wave 1, which targets "runs correctly as a local stdio process" only.
- **Attestation-shim overlap.** Whether this tool and the already-planned v0.3.0 MCP attestation shim (`graphsmith-v0.3.0-mcp-attestation-shim-design.md`) should share one stateless deployment as two separate tools — using header-based method/tool routing for gateway-level dispatch if that ends up useful — is a real, live design question. **Presenting the tradeoff, not deciding it:** sharing one deployment means one auth story and one publish pipeline to maintain instead of two, but couples two conceptually different concerns (context-delivery plumbing vs. a trust/attestation primitive) into one release cadence and one blast radius if either has a bug. Recommend Paul confirm with whoever owns the attestation-shim design before Wave 1's Lane C builder commits to either shape.
