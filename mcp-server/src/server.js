"use strict";

const pkg = require("../package.json");
const { loadSkillMarkdown } = require("./skill.js");
const {
  STATELESS_PROTOCOL_VERSION,
  LEGACY_PROTOCOL_VERSION,
  TOOL_NAME,
  TOOL_INPUT_SCHEMA,
  ERROR_CODES,
  META_PROTOCOL_VERSION_KEY,
  META_CLIENT_INFO_KEY,
  META_CLIENT_CAPABILITIES_KEY,
} = require("./protocol.js");

const SERVER_INFO = Object.freeze({ name: pkg.name, version: pkg.version });
const GUIDANCE_INSTRUCTIONS =
  `Call the "${TOOL_NAME}" tool (no arguments) to retrieve GraphSmith's current guidance (SKILL.md).`;

function okResponse(id, result) {
  return { jsonrpc: "2.0", id: id === undefined ? null : id, result };
}

function errorResponse(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: "2.0", id: id === undefined ? null : id, error };
}

function toolDescriptor() {
  return {
    name: TOOL_NAME,
    description:
      "Returns GraphSmith's canonical guidance (the current SKILL.md body) as markdown. " +
      "Read-only. Takes no arguments.",
    inputSchema: TOOL_INPUT_SCHEMA,
  };
}

/* Validates the SEP-2575 per-request _meta block. Returns null if valid,
 * or { code, message } describing the first problem found. Every stateless
 * RPC (server/discover, tools/list, tools/call -- NOT the legacy
 * initialize/notifications/initialized pair, which predate _meta entirely)
 * must pass through this on every single call; there is no session to
 * lean on to skip re-validating it. */
function validateMeta(params) {
  const meta = params && typeof params === "object" ? params._meta : undefined;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    return {
      code: ERROR_CODES.INVALID_PARAMS,
      message: `_meta is required on every request under the stateless MCP protocol (missing or malformed).`,
    };
  }

  const protocolVersion = meta[META_PROTOCOL_VERSION_KEY];
  if (typeof protocolVersion !== "string" || protocolVersion.length === 0) {
    return {
      code: ERROR_CODES.INVALID_PARAMS,
      message: `_meta["${META_PROTOCOL_VERSION_KEY}"] is required and must be a non-empty string.`,
    };
  }

  const clientInfo = meta[META_CLIENT_INFO_KEY];
  if (
    !clientInfo ||
    typeof clientInfo !== "object" ||
    Array.isArray(clientInfo) ||
    typeof clientInfo.name !== "string" ||
    typeof clientInfo.version !== "string"
  ) {
    return {
      code: ERROR_CODES.INVALID_PARAMS,
      message: `_meta["${META_CLIENT_INFO_KEY}"] is required and must be {name: string, version: string}.`,
    };
  }

  const clientCapabilities = meta[META_CLIENT_CAPABILITIES_KEY];
  /* Required per spec even when the client supports nothing optional --
   * in that case it MUST still send an empty object. undefined/missing is
   * invalid; {} is valid. Servers must not infer capabilities from a prior
   * request, because under the stateless protocol there is no prior
   * request to infer from. */
  if (
    clientCapabilities === undefined ||
    clientCapabilities === null ||
    typeof clientCapabilities !== "object" ||
    Array.isArray(clientCapabilities)
  ) {
    return {
      code: ERROR_CODES.INVALID_PARAMS,
      message: `_meta["${META_CLIENT_CAPABILITIES_KEY}"] is required (send {} if the client supports nothing optional).`,
    };
  }

  if (protocolVersion !== STATELESS_PROTOCOL_VERSION) {
    return {
      code: ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION,
      message: `Unsupported protocol version "${protocolVersion}". This server speaks "${STATELESS_PROTOCOL_VERSION}" (stateless) and "${LEGACY_PROTOCOL_VERSION}" (legacy initialize handshake).`,
    };
  }

  return null;
}

function handleDiscover(id) {
  return okResponse(id, {
    supportedVersions: [STATELESS_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
    capabilities: {
      tools: { [TOOL_NAME]: {} },
    },
    serverInfo: SERVER_INFO,
    instructions: GUIDANCE_INSTRUCTIONS,
  });
}

function handleToolsList(id) {
  return okResponse(id, { tools: [toolDescriptor()] });
}

function handleToolsCall(id, params) {
  const name = params && params.name;
  if (name !== TOOL_NAME) {
    return errorResponse(
      id,
      ERROR_CODES.INVALID_PARAMS,
      `Unknown tool "${String(name)}". This server exposes exactly one tool: "${TOOL_NAME}".`
    );
  }

  const args = params && Object.prototype.hasOwnProperty.call(params, "arguments") ? params.arguments : {};
  const argKeys = args && typeof args === "object" && !Array.isArray(args) ? Object.keys(args) : null;

  /* additionalProperties:false enforced here explicitly (not just declared
   * in the schema): unexpected arguments are a validation error, not
   * silently ignored input, per the frozen design. */
  if (argKeys === null || argKeys.length > 0) {
    return errorResponse(
      id,
      ERROR_CODES.INVALID_PARAMS,
      `"${TOOL_NAME}" takes no arguments (inputSchema: {type: "object", properties: {}, additionalProperties: false}).`
    );
  }

  let text;
  try {
    text = loadSkillMarkdown();
  } catch (err) {
    return errorResponse(
      id,
      ERROR_CODES.INTERNAL_ERROR,
      `Failed to load GraphSmith guidance: ${err && err.message ? err.message : String(err)}`
    );
  }

  return okResponse(id, {
    content: [{ type: "text", text }],
    isError: false,
  });
}

function handleLegacyInitialize(id, connectionState) {
  connectionState.legacyInitialized = true;
  return okResponse(id, {
    protocolVersion: LEGACY_PROTOCOL_VERSION,
    capabilities: { tools: {} },
    serverInfo: SERVER_INFO,
    instructions: GUIDANCE_INSTRUCTIONS,
  });
}

/* Top-level per-message dispatcher. Transport-agnostic: stdioTransport.js
 * and httpTransport.js both funnel every parsed JSON-RPC message through
 * this single function, so the protocol/auth/meta-validation logic exists
 * in exactly one place regardless of which transport is in use.
 *
 * ctx = {
 *   connectionState: { legacyInitialized: boolean },  // per-connection, in-memory only, never persisted -- NOT a session ID, just protocol-dialect bookkeeping for this one already-open pipe/request
 *   authenticated: boolean,                            // transport-level auth verdict, already decided BEFORE this function is called
 * }
 *
 * Returns a JSON-RPC response object to send back, or null for messages
 * that must not receive a response (JSON-RPC notifications, e.g.
 * "notifications/initialized").
 */
function handleMessage(msg, ctx) {
  if (!ctx || !ctx.authenticated) {
    return errorResponse(
      msg && typeof msg === "object" ? msg.id : null,
      ERROR_CODES.UNAUTHENTICATED,
      "Authentication required: every request on a non-stdio transport must carry a valid bearer token."
    );
  }

  if (!msg || typeof msg !== "object" || Array.isArray(msg) || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return errorResponse(
      msg && typeof msg === "object" && !Array.isArray(msg) ? msg.id : null,
      ERROR_CODES.INVALID_REQUEST,
      "Malformed JSON-RPC 2.0 request envelope."
    );
  }

  const { method, params, id } = msg;
  const connectionState = ctx.connectionState || { legacyInitialized: false };

  /* --- Legacy handshake path (pre-SEP-2575, no _meta at all) --- */
  if (method === "initialize") {
    return handleLegacyInitialize(id, connectionState);
  }
  if (method === "notifications/initialized") {
    /* JSON-RPC notification: no "id", no response. */
    return null;
  }

  /* --- Stateless-native + post-legacy-handshake path --- */
  switch (method) {
    case "server/discover": {
      /* Always required to carry _meta, per spec, regardless of whether
       * this connection already did a legacy handshake -- it is the
       * stateless-native discovery probe and must itself be
       * self-authenticating/self-describing. */
      const metaError = validateMeta(params);
      if (metaError) return errorResponse(id, metaError.code, metaError.message);
      return handleDiscover(id);
    }
    case "tools/list": {
      if (!connectionState.legacyInitialized) {
        const metaError = validateMeta(params);
        if (metaError) return errorResponse(id, metaError.code, metaError.message);
      }
      return handleToolsList(id);
    }
    case "tools/call": {
      if (!connectionState.legacyInitialized) {
        const metaError = validateMeta(params);
        if (metaError) return errorResponse(id, metaError.code, metaError.message);
      }
      return handleToolsCall(id, params);
    }
    default:
      return errorResponse(id, ERROR_CODES.METHOD_NOT_FOUND, `Unknown method: "${method}".`);
  }
}

module.exports = {
  handleMessage,
  validateMeta,
  toolDescriptor,
  SERVER_INFO,
  GUIDANCE_INSTRUCTIONS,
};
