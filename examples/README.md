# Examples

Copy-paste workflows. Each one is also run by this repo's own CI
([`examples.yml`](../.github/workflows/examples.yml)) on every change to this folder, against
the action in the same commit, so a broken example fails a check here before it reaches you.

| File | What it does |
|---|---|
| [`scan-reference-server.yml`](scan-reference-server.yml) | Builds the MCP project's public reference server (`@modelcontextprotocol/server-everything@2.1.0`) into an image, scans it as a stdio target in the scanner's locked-down container, uploads SARIF to code scanning, keeps the HTML report, and gates on tool drift from a committed baseline. |

## Using it

1. Copy the file to `.github/workflows/mcp-scan.yml` in your repo.
2. Push. The first run writes `.agent-perimeter/baseline.json` and passes. Commit that file.
3. Findings appear under **Security → Code scanning**. Each one has a CWE, a taxonomy
   reference and the command that reproduces it.

Scan only servers you own or are authorised to test. Passive mode (the default) launches the
server and lists its tools, resources and prompts; it never calls a tool. Active probes refuse
to run without a [scope file](../README.md#before-you-scan-anything-the-scope-file-requirement).

## What to expect on the reference server

Measured by this repo's `examples` workflow on 9 Nov 2026 against `server-everything@2.1.0`:

```text
Revision claimed:  unknown
Features observed: param_headers
No findings for the checks that ran. 9 checks skipped (2 feature_absent, 1 model_unavailable,
1 no_baseline, 5 not_authorised).
```

- **No findings** is for the checks that ran in passive mode. It is not a clean bill of health.
- The 5 `not_authorised` skips are the active probes, which need a scope file.
- `model_unavailable` is the optional model judge, which is off by default.
- `no_baseline` is the drift check on the first run. It runs from the second run, once the
  baseline is committed.
- "Revision claimed: unknown" means the server didn't advertise a protocol revision the scanner
  recognises. The 2026-07-28 revision's features (`server_discover`, `result_type`) weren't
  observed.

Your own server will differ. The step summary of each run lists any findings, with their rule
ids.
