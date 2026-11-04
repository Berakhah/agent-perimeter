# Bring your own agent

Claim A — that an injection path exists on your server — is proven by the scan
itself, deterministically, with no agent involved.

Claim B — that *your* agent acts on it — is a property of your agent, not of
the server, so measuring it requires your agent. This is the procedure.

## 1. Start the instrumented server

    agent-perimeter instrument --target <your-server> --scope-file scope.json --port 8931 --transcript-out transcript.json

This requires a scope file for the target, binds to loopback only, and proxies
your server. It injects a per-run canary token (`AP-CANARY-<nonce>`) into the
results of source tools. The canary instructs nothing; it is a tracer, not a
payload.

## 2. Point your agent at it

Configure your agent to use `http://localhost:8931` instead of your server, and
run whatever task it normally performs against that data source.

## 3. Stop the proxy

The proxy writes the transcript when you stop it (Ctrl+C). You do not export
anything from your agent.

## 4. Feed it back

    agent-perimeter scan --target <your-server> --agent-transcript transcript.json

If your agent repeated the canary in a later tool call, you get a finding
naming the tool and the call sequence. A canary repeated to a privileged tool
(a name containing `run`, `exec`, `write`, `delete`, `send`, `post` or
`upload`) is CRITICAL; repeated to any other tool it is MEDIUM. Legacy marker
transcripts, which can only show correlation, are INFO. If the agent did not
repeat the canary, you get nothing, which is the correct result and is not the
same as your agent being immune.

### Limits

One negative run is one observation, not a guarantee. The canary goes into
every successful source-tool result, and pagination is followed when computing
which tools are sources. v1 does not support streaming/SSE responses. Scope is
self-attested.

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
