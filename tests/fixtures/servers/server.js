"use strict";

// Minimal Node.js MCP fixture: only enough to answer server/discover over
// newline-delimited JSON-RPC on stdio. Exists solely to run the real Node
// runtime under the hardened seccomp profile in transport/seccomp.json --
// that profile was built by tracing the Python fixture only, and defaults
// on for every stdio launch including npx-launched Node servers, so this is
// the regression proof that Node actually starts under it.
const readline = require("readline");

function discoverResult() {
  return {
    resultType: "complete",
    protocolVersions: ["2026-07-28"],
    capabilities: { tools: {}, extensions: {} },
    serverInfo: { name: "ap-fixture-node", version: "0.1.0" },
  };
}

function handle(message) {
  if (message.method === "server/discover") {
    return { jsonrpc: "2.0", id: message.id, result: discoverResult() };
  }
  return {
    jsonrpc: "2.0",
    id: message.id,
    error: { code: -32601, message: "Method not found" },
  };
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (line.trim()) {
    process.stdout.write(JSON.stringify(handle(JSON.parse(line))) + "\n");
  }
});
