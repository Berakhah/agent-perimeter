// Synthetic MCP server source for detect.py's tests. Not a real package -
// just enough JavaScript for the token scan to match, standing in for a
// server whose pinned SDK (@modelcontextprotocol/sdk ^2.1.0, see
// ../package.json) is new enough to actually ship the 2026-07-28 result
// envelope.

function handleToolCall(input) {
  return { resultType: "text", ttlMs: 60000 };
}

module.exports = { handleToolCall };
