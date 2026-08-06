"use strict";

/* Protocol constants shared by every transport.
 *
 * STATELESS_PROTOCOL_VERSION is the MCP spec version this server is built
 * natively against (SEP-2575, "Make MCP Stateless", Final, 2026-07-28).
 * LEGACY_PROTOCOL_VERSION is the pre-SEP-2575 handshake-based version this
 * server also speaks as a load-bearing compatibility fallback (per
 * .plans/v0.5.0/WAVE-0-LANE-C-MCP-DESIGN.md's "RESOLVED, not deferred"
 * decision -- stock MCP client/SDK builds as of the stateless spec's
 * finalization still default to this legacy dialect).
 */
const STATELESS_PROTOCOL_VERSION = "2026-07-28";
const LEGACY_PROTOCOL_VERSION = "2025-06-18";

const TOOL_NAME = "graphsmith_guidance";

/* This tool's input schema is deliberately a *closed* object schema --
 * additionalProperties:false -- so a client that passes unexpected
 * arguments gets a validation error rather than having them silently
 * ignored, per the frozen Lane C design ("its input schema is
 * {type: 'object', properties: {}, additionalProperties: false}"). */
const TOOL_INPUT_SCHEMA = Object.freeze({
  type: "object",
  properties: {},
  additionalProperties: false,
});

/* JSON-RPC 2.0 standard error codes, plus MCP/SEP-2575-specific codes in the
 * reserved server-error range (-32000 to -32099). */
const ERROR_CODES = Object.freeze({
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  UNSUPPORTED_PROTOCOL_VERSION: -32022,
  UNAUTHENTICATED: -32001,
  // Streamable HTTP transport, "Request Metadata" / "Server Validation":
  // a mirrored HTTP header (MCP-Protocol-Version, Mcp-Method, Mcp-Name) is
  // missing or disagrees with the JSON-RPC body. HTTP status MUST be 400.
  HEADER_MISMATCH: -32020,
});

const META_PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo";
const META_CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities";

module.exports = {
  STATELESS_PROTOCOL_VERSION,
  LEGACY_PROTOCOL_VERSION,
  TOOL_NAME,
  TOOL_INPUT_SCHEMA,
  ERROR_CODES,
  META_PROTOCOL_VERSION_KEY,
  META_CLIENT_INFO_KEY,
  META_CLIENT_CAPABILITIES_KEY,
};
