#!/usr/bin/env node
/* Minimal stdio JSON-RPC test fixture standing in for "a real downstream MCP server"
 * (Standalone Gateway TRD SS8's test plan needs one that is NOT the gateway's own code,
 * to prove the proxy/correlation logic against an independent implementation). Exposes
 * three tools: "echo" (returns { echoed: arguments }), "boom" (always returns an
 * error), and "sample" (sends its OWN unsolicited "sampling/createMessage" request back
 * up this same stdio connection and resolves the tool call with whatever the agent's
 * model returns -- the fixture-side half of the board-decision 2026-09-04 "forward
 * downstream sampling requests upstream" fix, tests/gateway/e2e's own suite drives the
 * gateway-side half). Also supports a deliberate response DELAY via arguments.delayMs on
 * "echo"/"boom", used by out-of-order-correlation tests. Speaks the same
 * newline-delimited JSON-RPC framing mcp-server/src/stdioTransport.js and
 * scripts/gateway/downstream.js both use.
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

// Requests THIS fixture itself sent upstream (sampling/createMessage), awaiting a reply
// -- distinct from `id`s the caller assigns to requests it sends TO this fixture.
const pendingUpstream = new Map();
let nextUpstreamId = 1;

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

  // A reply to this fixture's own upstream sampling/createMessage request, not a new
  // request directed at this fixture (no "method" -- a real request always has one).
  if (typeof method !== "string" && id !== undefined && id !== null && pendingUpstream.has(id)) {
    const { onReply } = pendingUpstream.get(id);
    pendingUpstream.delete(id);
    onReply(msg);
    return;
  }

  if (method === "initialize") {
    ok(id, { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: serverName, version: "1.0.0-fixture" } });
    return;
  }
  if (method === "tools/list") {
    ok(id, {
      tools: [
        { name: `${serverName}_echo`, description: "echoes its arguments", inputSchema: { type: "object" } },
        { name: `${serverName}_boom`, description: "always errors", inputSchema: { type: "object" } },
        { name: `${serverName}_sample`, description: "asks the connected agent's model to do inference, via an unsolicited sampling/createMessage this fixture sends upstream", inputSchema: { type: "object" } },
      ],
    });
    return;
  }
  if (method === "tools/call") {
    const toolName = params && params.name;
    const args = (params && params.arguments) || {};
    if (toolName === `${serverName}_sample`) {
      const upstreamId = "fixture-sample-" + nextUpstreamId++;
      pendingUpstream.set(upstreamId, {
        onReply: (reply) => {
          if (reply.error) err(id, `sampling forward failed: ${reply.error.message}`);
          else ok(id, { content: [{ type: "text", text: JSON.stringify({ sampled: reply.result }) }], isError: false });
        },
      });
      send({ jsonrpc: "2.0", id: upstreamId, method: "sampling/createMessage", params: { prompt: args.prompt || "say hi" } });
      return;
    }
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
