#!/usr/bin/env node
"use strict";

const { runStdioServer } = require("../src/stdioTransport.js");
const { createHttpServer } = require("../src/httpTransport.js");

function parseArgs(argv) {
  const args = {
    transport: "stdio",
    port: 8642,
    host: "127.0.0.1",
    token: process.env.GRAPHSMITH_MCP_TOKEN || null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--http") args.transport = "http";
    else if (a === "--stdio") args.transport = "stdio";
    else if (a === "--port") args.port = Number(argv[++i]);
    else if (a === "--host") args.host = argv[++i];
    else if (a === "--token") args.token = argv[++i];
    else if (a === "--help" || a === "-h") args.help = true;
  }
  return args;
}

function printHelp() {
  process.stdout.write(
    [
      "graphsmith-mcp -- stateless-native MCP server exposing the graphsmith_guidance tool",
      "",
      "Usage:",
      "  graphsmith-mcp                 Run the stdio transport (default, no auth token needed)",
      "  graphsmith-mcp --http          Run the HTTP transport (bearer token REQUIRED)",
      "",
      "Options:",
      "  --port <n>      HTTP port (default 8642, --http only)",
      "  --host <addr>   HTTP bind address (default 127.0.0.1, --http only)",
      "  --token <tok>   Bearer token (--http only). Defaults to $GRAPHSMITH_MCP_TOKEN.",
      "  --help, -h      Show this help",
      "",
      "The HTTP transport refuses to start without a token of >=16 characters.",
      "",
    ].join("\n")
  );
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  if (args.transport === "http") {
    let server;
    try {
      server = createHttpServer({ token: args.token });
    } catch (err) {
      process.stderr.write(`graphsmith-mcp: ${err.message}\n`);
      process.exitCode = 1;
      return;
    }
    server.listen(args.port, args.host, () => {
      process.stderr.write(
        `graphsmith-mcp: HTTP transport listening on http://${args.host}:${args.port} (bearer auth required)\n`
      );
    });
    return;
  }

  runStdioServer();
}

main();
