#!/usr/bin/env node
/* GraphSmith standalone gateway -- configuration loader (Standalone Gateway TRD SS4).
 *
 * Hand-rolls the validation this schema needs, mirroring scripts/state-store.js's own
 * schemaErrors() (which does the same for a bigger schema) rather than reusing
 * scripts/schema-validate.js -- that validator's SUPPORTED_KEYWORDS set is deliberately
 * scoped to exactly what schemas/host-adapter.schema.json uses (no minLength/minItems),
 * and gateway-config.schema.json needs both. Hand-rolling a second small, purpose-built
 * validator matches this codebase's own stated preference (schema-validate.js's header:
 * "a general-purpose JSON Schema validator ... would throw loudly rather than under-
 * validate") over silently extending a validator scoped to a different schema's needs.
 *
 * Zero-dependency, Node >= 18.
 */
"use strict";

const fs = require("fs");
const CONFIG_SCHEMA = require("../../schemas/gateway-config.schema.json");

function fail(message, code = "GATEWAY_CONFIG_INVALID") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateDownstreamServer(entry, index, errors) {
  const loc = `downstream_servers[${index}]`;
  if (!isPlainObject(entry)) {
    errors.push(`${loc} must be an object`);
    return;
  }
  for (const key of ["name", "transport", "endpoint"]) {
    if (!Object.prototype.hasOwnProperty.call(entry, key)) errors.push(`${loc}.${key} is required`);
  }
  for (const key of Object.keys(entry)) {
    if (!["name", "transport", "endpoint"].includes(key)) errors.push(`${loc}.${key} is not allowed`);
  }
  if (Object.prototype.hasOwnProperty.call(entry, "name") && (typeof entry.name !== "string" || entry.name.length === 0)) {
    errors.push(`${loc}.name must be a non-empty string`);
  }
  if (Object.prototype.hasOwnProperty.call(entry, "transport") && !["stdio", "http"].includes(entry.transport)) {
    errors.push(`${loc}.transport must be "stdio" or "http"`);
  }
  if (Object.prototype.hasOwnProperty.call(entry, "endpoint") && (typeof entry.endpoint !== "string" || entry.endpoint.length === 0)) {
    errors.push(`${loc}.endpoint must be a non-empty string`);
  }
}

function validateAgentListen(value, errors) {
  const loc = "agent_listen";
  if (!isPlainObject(value)) {
    errors.push(`${loc} must be an object`);
    return;
  }
  if (!Object.prototype.hasOwnProperty.call(value, "transport")) errors.push(`${loc}.transport is required`);
  for (const key of Object.keys(value)) {
    if (!["transport", "port", "token_ref"].includes(key)) errors.push(`${loc}.${key} is not allowed`);
  }
  if (Object.prototype.hasOwnProperty.call(value, "transport") && !["stdio", "http"].includes(value.transport)) {
    errors.push(`${loc}.transport must be "stdio" or "http"`);
  }
  if (Object.prototype.hasOwnProperty.call(value, "port") && (!Number.isInteger(value.port) || value.port < 1)) {
    errors.push(`${loc}.port must be an integer >= 1`);
  }
  if (value.transport === "http" && (typeof value.token_ref !== "string" || value.token_ref.length === 0)) {
    errors.push(`${loc}.token_ref is required (and must be a non-empty string) when transport is "http"`);
  }
  if (Object.prototype.hasOwnProperty.call(value, "token_ref") && (typeof value.token_ref !== "string" || value.token_ref.length === 0)) {
    errors.push(`${loc}.token_ref must be a non-empty string`);
  }
}

const TOP_LEVEL_KEYS = [
  "schema_version", "state_dir", "host_id", "downstream_servers", "signing_key_ref",
  "session_boundary", "persistence", "remote_anchor_ref", "agent_listen",
];

/** Validates `config` against schemas/gateway-config.schema.json's shape, returning an
 * array of human-readable error strings (empty = valid). */
function validateConfigShape(config) {
  const errors = [];
  if (!isPlainObject(config)) return ["config must be a JSON object"];

  for (const key of Object.keys(config)) {
    if (!TOP_LEVEL_KEYS.includes(key)) errors.push(`${key} is not allowed`);
  }
  for (const key of ["schema_version", "state_dir", "downstream_servers", "signing_key_ref"]) {
    if (!Object.prototype.hasOwnProperty.call(config, key)) errors.push(`${key} is required`);
  }
  if (Object.prototype.hasOwnProperty.call(config, "schema_version") && config.schema_version !== "1.0") {
    errors.push(`schema_version must equal "1.0", got ${JSON.stringify(config.schema_version)}`);
  }
  if (Object.prototype.hasOwnProperty.call(config, "state_dir") && (typeof config.state_dir !== "string" || config.state_dir.length === 0)) {
    errors.push("state_dir must be a non-empty string");
  }
  if (Object.prototype.hasOwnProperty.call(config, "host_id") && (typeof config.host_id !== "string" || config.host_id.length === 0)) {
    errors.push("host_id must be a non-empty string");
  }
  if (Object.prototype.hasOwnProperty.call(config, "downstream_servers")) {
    if (!Array.isArray(config.downstream_servers) || config.downstream_servers.length === 0) {
      errors.push("downstream_servers must be a non-empty array");
    } else {
      config.downstream_servers.forEach((entry, index) => validateDownstreamServer(entry, index, errors));
      const names = config.downstream_servers.filter(isPlainObject).map((entry) => entry.name).filter((n) => typeof n === "string");
      const seen = new Set();
      for (const name of names) {
        if (seen.has(name)) errors.push(`downstream_servers contains a duplicate name "${name}" -- names must be unique so tools can be attributed unambiguously`);
        seen.add(name);
      }
    }
  }
  if (Object.prototype.hasOwnProperty.call(config, "signing_key_ref") && (typeof config.signing_key_ref !== "string" || config.signing_key_ref.length === 0)) {
    errors.push("signing_key_ref must be a non-empty string");
  }
  if (Object.prototype.hasOwnProperty.call(config, "session_boundary") && !["connection", "time_window"].includes(config.session_boundary)) {
    errors.push('session_boundary must be "connection" or "time_window"');
  }
  if (Object.prototype.hasOwnProperty.call(config, "persistence") && config.persistence !== "p2_hash_chained_log") {
    errors.push('persistence must be "p2_hash_chained_log"');
  }
  if (Object.prototype.hasOwnProperty.call(config, "remote_anchor_ref") && (typeof config.remote_anchor_ref !== "string" || config.remote_anchor_ref.length === 0)) {
    errors.push("remote_anchor_ref must be a non-empty string");
  }
  if (Object.prototype.hasOwnProperty.call(config, "agent_listen")) {
    validateAgentListen(config.agent_listen, errors);
  }
  return errors;
}

/** Resolves signing_key_ref / token_ref conventions: if the named string is an existing
 * file path, read it; otherwise treat it as an environment variable name. Never accepts
 * raw key material as the ref itself (SS4's own stated secrets discipline). */
function resolveSecretRef(ref, label) {
  if (typeof ref !== "string" || ref.length === 0) throw fail(`${label} must be a non-empty string`, "INVALID_ARGUMENT");
  if (fs.existsSync(ref) && fs.statSync(ref).isFile()) {
    return fs.readFileSync(ref, "utf8").trim();
  }
  const value = process.env[ref];
  if (typeof value !== "string" || value.length === 0) {
    throw fail(`${label} ("${ref}") does not name an existing file, and no environment variable "${ref}" is set.`, "GATEWAY_SECRET_REF_UNRESOLVED");
  }
  return value;
}

/** Loads and validates a gateway config file. Throws GATEWAY_CONFIG_INVALID naming every
 * violation (fail-closed, never a partial/best-guess config) on any schema violation. */
function loadConfig(configPath) {
  let raw;
  try {
    raw = fs.readFileSync(configPath, "utf8");
  } catch (error) {
    throw fail(`Gateway config not readable at ${configPath}: ${error.message}`, "GATEWAY_CONFIG_UNREADABLE");
  }
  let config;
  try {
    config = JSON.parse(raw);
  } catch (error) {
    throw fail(`Gateway config at ${configPath} is not valid JSON: ${error.message}`, "GATEWAY_CONFIG_MALFORMED");
  }
  const errors = validateConfigShape(config);
  if (errors.length > 0) {
    throw fail(`Gateway config at ${configPath} is invalid:\n  - ${errors.join("\n  - ")}`, "GATEWAY_CONFIG_INVALID");
  }
  return config;
}

module.exports = {
  CONFIG_SCHEMA,
  validateConfigShape,
  loadConfig,
  resolveSecretRef,
};
