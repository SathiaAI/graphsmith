#!/usr/bin/env node
/* Minimal stdio JSON-RPC test fixture standing in for "a real downstream MCP server"
 * (Standalone Gateway TRD SS8's test plan needs one that is NOT the gateway's own code,
 * to prove the proxy/correlation logic against an independent implementation). Exposes
 * two tools: "echo" (returns { echoed: arguments }) and "boom" (always returns an
 * error), plus supports a deliberate response DELAY via arguments.delayMs, used by
 * out-of-order-correlation tests. Speaks the same newline-delimited JSON-RPC framing
 * mcp-server/src/stdioTransport.js and scripts/gateway/downstream.js both use.
 *
 * Usage: node fixture-mcp-server.js [--server-name NAME]
 */
"use strict";

const readline = require("readline");

const nameIndex = process.argv.indexOf("--server-name");
const serverName = nameIndex !== -1 ? process.argv[nameIndex + 1] : "fixture";

const rl = readline.createInterface({ input: process.stdin, terminal: false });

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function ok(id, result) {
  send({ jsonrpc: "2.0", id, result });
}
function err(id, message) {
  send({ jsonrpc: "2.0", id, error: { code: -32000, message } });
}

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch (error) {
    return;
  }
  const { id, method, params } = msg;
  if (method === "initialize") {
    ok(id, { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: serverName, version: "1.0.0-fixture" } });
    return;
  }
  if (method === "tools/list") {
    ok(id, {
      tools: [
        { name: `${serverName}_echo`, description: "echoes its arguments", inputSchema: { type: "object" } },
        { name: `${serverName}_boom`, description: "always errors", inputSchema: { type: "object" } },
      ],
    });
    return;
  }
  if (method === "tools/call") {
    const toolName = params && params.name;
    const args = (params && params.arguments) || {};
    const respond = () => {
      if (toolName === `${serverName}_boom`) {
        err(id, "boom: this tool always fails");
      } else {
        ok(id, { content: [{ type: "text", text: JSON.stringify({ echoed: args }) }], isError: false });
      }
    };
    if (typeof args.delayMs === "number" && args.delayMs > 0) {
      setTimeout(respond, args.delayMs);
    } else {
      respond();
    }
    return;
  }
  err(id, `Unknown method: ${method}`);
});
