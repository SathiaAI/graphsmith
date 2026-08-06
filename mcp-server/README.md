# graphsmith-mcp-server

A stateless-native [MCP](https://modelcontextprotocol.io) server that hands agent hosts
GraphSmith's canonical guidance back as a single read-only tool call.

Built against the MCP stateless protocol revision (SEP-2575, "Make MCP Stateless",
2026-07-28) with the legacy `initialize`/`notifications/initialized` handshake kept as a
load-bearing compatibility fallback for hosts that don't speak the stateless dialect yet.
See `.plans/v0.5.0/WAVE-0-LANE-C-MCP-DESIGN.md` in the
[graphsmith](https://github.com/SathiaAI/graphsmith) repo for the full design this package
implements.

This package is independently publishable: `npm install graphsmith-mcp-server` works in a
completely empty directory with no monorepo checkout required. It ships its own bundled
copy of `SKILL.md`, resolved relative to its own installed package directory.

## Install

```
npm install -g graphsmith-mcp-server
```

## Usage

### stdio (default -- how a coding agent host like Claude Code spawns this)

```
graphsmith-mcp
```

No authentication token is needed for stdio: the OS process boundary is the trust
boundary (there is exactly one caller -- whatever process spawned this over stdio).

### HTTP (opt-in network transport)

```
GRAPHSMITH_MCP_TOKEN=$(openssl rand -hex 32) graphsmith-mcp --http --port 8642
```

The HTTP transport refuses to start at all without a bearer token of at least 16
characters, and every request must carry a matching `Authorization: Bearer <token>`
header or it is refused with `401` -- before the request body is even parsed. There is
no "network mode without auth" code path.

Every request must also carry the MCP spec's mirrored request-metadata headers
(`MCP-Protocol-Version`, `Mcp-Method`, and -- for `tools/call` -- `Mcp-Name`), each
matching the corresponding value in the JSON-RPC body. A missing or disagreeing header
is refused with `400` and a `HeaderMismatch` (`-32020`) JSON-RPC error.

## Tool surface

One tool, `graphsmith_guidance`: read-only, takes no arguments (its input schema is
`{type: "object", properties: {}, additionalProperties: false}` -- unexpected arguments
are a validation error, not silently ignored). Returns the current `SKILL.md` body as
markdown.

## Protocol methods

- `initialize` / `notifications/initialized` -- legacy handshake (load-bearing fallback)
- `server/discover` -- mandatory stateless-native discovery RPC
- `tools/list`, `tools/call` -- standard MCP tool RPCs

Every stateless-native RPC (i.e. every call not part of the legacy handshake, and
`server/discover` in all cases) requires a per-request `_meta` block:
`io.modelcontextprotocol/protocolVersion`, `io.modelcontextprotocol/clientInfo`, and
`io.modelcontextprotocol/clientCapabilities`. There is no session, so nothing is ever
inferred from a prior request.

## Development

```
npm test
```

Zero runtime dependencies (matches the parent `graphsmith` monorepo's convention).
