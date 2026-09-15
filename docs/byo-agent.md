# Bring your own agent

Claim A — that an injection path exists on your server — is proven by the scan
itself, deterministically, with no agent involved.

Claim B — that *your* agent acts on it — is a property of your agent, not of
the server, so measuring it requires your agent. This is the procedure.

## 1. Start the instrumented server

    agent-perimeter instrument --target <your-server> --port 8931

This proxies your server and injects a benign marker
(`AGENT-PERIMETER-INJECTED-INSTRUCTION`) into content returned by source tools.
The marker instructs nothing; it is a tracer, not a payload.

## 2. Point your agent at it

Configure your agent to use `http://localhost:8931` instead of your server, and
run whatever task it normally performs against that data source.

## 3. Export the transcript

Export as JSON with this shape:

    {
      "tool_calls": [
        {"name": "fetch_page", "result": "...text the agent received..."},
        {"name": "run_command", "arguments": {"command": "..."}}
      ]
    }

## 4. Feed it back

    agent-perimeter scan --target <your-server> --agent-transcript transcript.json

If your agent called a privileged tool after seeing the marker, you get a
finding naming the tool and the call sequence. If it did not, you get nothing —
which is the correct result, and is not the same as your agent being immune.
A single negative run is one observation, not a guarantee.

## Snapshots

`--snapshot <path>` writes a `ToolSnapshot` — the portable record drift
compares against — as JSON:

    {
      "version": 1,
      "target": "https://mcp.example.test",
      "taken_at": "2026-09-15T00:00:00Z",
      "scan_id": "base-1",
      "tools": [
        {
          "name": "read_file",
          "description": "Read a file.",
          "input_schema": {"...": "..."},
          "annotations": {"...": "..."},
          "description_hash": "...",
          "schema_hash": "...",
          "annotations_hash": "..."
        }
      ]
    }

`taken_at` is ISO-8601 UTC. Each entry in `tools[]` carries the tool's
`name`, `description`, `input_schema` and `annotations` verbatim, plus a
SHA-256 hash of each (`description_hash`, `schema_hash`, `annotations_hash`)
— the values `drift.description_drift` and the `drift` command actually
compare, so a byte-identical listing always hashes identically regardless of
whether it came from a file or the database.

`agent-perimeter drift scan:<id> scan:<id> --database-url <url>` reads the
same `tool`/`drift_event` rows the API's `GET /api/scans/{id}/drift` route
reads — a scan-id operand is not a separate code path, it resolves to a
`ToolSnapshot` built from those rows and is compared exactly like a file.

Target identity for matching a baseline to a current scan is the exact
`target` string in the snapshot (what you passed to `--target`), never
`--image` — two scans of the same stdio target through different container
images still compare, and two scans of different targets never silently
compare against each other's baseline.
