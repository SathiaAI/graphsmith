#!/usr/bin/env node
"use strict";

/* Regression suite for scripts/gateway/config.js against schemas/gateway-config.schema.json
 * (Standalone Gateway TRD SS4). */

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../../..");
const gatewayConfig = require(path.join(ROOT, "scripts", "gateway", "config.js"));

let failures = 0;
const results = [];
function record(name, status, reason) {
  console.log(status === "PASS" ? `PASS ${name}` : `FAIL ${name}+${reason || "unknown"}`);
  results.push({ name, status, reason: reason || "" });
  if (status === "FAIL") failures++;
}
function check(name, cond, reason) {
  record(name, cond ? "PASS" : "FAIL", reason);
}

function freshFile(prefix, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `gs-gateway-config-${prefix}-`));
  const target = path.join(dir, "gateway-config.json");
  fs.writeFileSync(target, typeof content === "string" ? content : JSON.stringify(content));
  return target;
}

const VALID = {
  schema_version: "1.0",
  state_dir: "/tmp/some-state-dir",
  downstream_servers: [{ name: "fs", transport: "stdio", endpoint: "node fixture.js" }],
  signing_key_ref: "GRAPHSMITH_SIGNING_KEY",
};

function validConfigLoads() {
  const p = freshFile("valid", VALID);
  let threw = null;
  let loaded = null;
  try { loaded = gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("valid-config-loads-without-throwing", threw === null, threw && threw.message);
  check("valid-config-round-trips-state-dir", loaded && loaded.state_dir === VALID.state_dir, "state_dir mismatch");
}

function missingRequiredField() {
  const bad = { ...VALID };
  delete bad.signing_key_ref;
  const p = freshFile("missing-required", bad);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("missing-signing-key-ref-rejected", threw && threw.code === "GATEWAY_CONFIG_INVALID" && /signing_key_ref is required/.test(threw.message), threw && threw.message);
}

function additionalPropertyRejected() {
  const bad = { ...VALID, mode: "standalone" }; // exactly the Rev-2 mistake the TRD's own header warns against
  const p = freshFile("extra-prop", bad);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("mode-field-rejected-as-additional-property", threw && threw.code === "GATEWAY_CONFIG_INVALID" && /mode is not allowed/.test(threw.message), threw && threw.message);
}

function badDownstreamTransportRejected() {
  const bad = { ...VALID, downstream_servers: [{ name: "x", transport: "carrier-pigeon", endpoint: "y" }] };
  const p = freshFile("bad-transport", bad);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("bad-downstream-transport-rejected", threw && /transport must be "stdio" or "http"/.test(threw.message), threw && threw.message);
}

function emptyDownstreamServersRejected() {
  const bad = { ...VALID, downstream_servers: [] };
  const p = freshFile("empty-downstream", bad);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("empty-downstream-servers-rejected", threw && /non-empty array/.test(threw.message), threw && threw.message);
}

function duplicateDownstreamNameRejected() {
  const bad = { ...VALID, downstream_servers: [{ name: "x", transport: "stdio", endpoint: "a" }, { name: "x", transport: "stdio", endpoint: "b" }] };
  const p = freshFile("dup-name", bad);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("duplicate-downstream-name-rejected", threw && /duplicate name/.test(threw.message), threw && threw.message);
}

function malformedJsonRejected() {
  const p = freshFile("malformed", "{not json");
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("malformed-json-rejected", threw && threw.code === "GATEWAY_CONFIG_MALFORMED", threw && threw.code);
}

function unreadableFileRejected() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-gateway-config-unreadable-"));
  let threw = null;
  try { gatewayConfig.loadConfig(path.join(dir, "does-not-exist.json")); } catch (error) { threw = error; }
  check("unreadable-file-rejected", threw && threw.code === "GATEWAY_CONFIG_UNREADABLE", threw && threw.code);
}

function agentListenHttpRequiresTokenRef() {
  const bad = { ...VALID, agent_listen: { transport: "http" } };
  const p = freshFile("agent-listen-no-token", bad);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("agent-listen-http-requires-token-ref", threw && /token_ref is required/.test(threw.message), threw && threw.message);
}

function agentListenStdioValid() {
  const good = { ...VALID, agent_listen: { transport: "stdio" } };
  const p = freshFile("agent-listen-stdio", good);
  let threw = null;
  try { gatewayConfig.loadConfig(p); } catch (error) { threw = error; }
  check("agent-listen-stdio-accepted", threw === null, threw && threw.message);
}

function resolveSecretRefFromEnv() {
  process.env.GS_TEST_GATEWAY_SECRET = "super-secret-value";
  try {
    const value = gatewayConfig.resolveSecretRef("GS_TEST_GATEWAY_SECRET", "signing_key_ref");
    check("resolve-secret-ref-from-env", value === "super-secret-value", value);
  } finally {
    delete process.env.GS_TEST_GATEWAY_SECRET;
  }
}

function resolveSecretRefFromFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gs-gateway-secret-file-"));
  const p = path.join(dir, "key.pem");
  fs.writeFileSync(p, "file-secret-value\n");
  const value = gatewayConfig.resolveSecretRef(p, "signing_key_ref");
  check("resolve-secret-ref-from-file-trims-newline", value === "file-secret-value", JSON.stringify(value));
}

function resolveSecretRefUnresolved() {
  let threw = null;
  try { gatewayConfig.resolveSecretRef("GS_TEST_DOES_NOT_EXIST_ANYWHERE", "signing_key_ref"); } catch (error) { threw = error; }
  check("resolve-secret-ref-unresolved-throws", threw && threw.code === "GATEWAY_SECRET_REF_UNRESOLVED", threw && threw.code);
}

function main() {
  validConfigLoads();
  missingRequiredField();
  additionalPropertyRejected();
  badDownstreamTransportRejected();
  emptyDownstreamServersRejected();
  duplicateDownstreamNameRejected();
  malformedJsonRejected();
  unreadableFileRejected();
  agentListenHttpRequiresTokenRef();
  agentListenStdioValid();
  resolveSecretRefFromEnv();
  resolveSecretRefFromFile();
  resolveSecretRefUnresolved();

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  console.log(`SUMMARY passed=${passed} failed=${failed} skipped=0`);
  process.exit(failures ? 1 : 0);
}

main();
