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

The reference server is a test fixture for MCP clients, so findings on it are expected and
don't say anything about servers built with it. The first CI run of this example records them
in the workflow summary.
