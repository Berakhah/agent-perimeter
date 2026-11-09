# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The CLI, the Python
package and the GitHub Action share one version; `@v1` follows the newest `v1.x.y`.

## [Unreleased]

## [1.2.0] - 2026-11-09

First release on PyPI: `uv tool install agent-perimeter`. No change to `action.yml`'s inputs or
outputs; `uses: Berakhah/agent-perimeter@v1` picks it up.

### Added

- **`instrument`: bring-your-own-agent injection proof.** A loopback-only, scope-gated proxy
  sits between your agent and a server, plants a per-run nonce canary in tool results, and
  records a redacting transcript. A finding is rated by whether your agent repeated the canary
  into a sink and what that sink can reach at call time. It refuses cross-origin, foreign-Host
  and non-JSON requests. See `docs/byo-agent.md`.
- Scan notes on the live-scan screen and in SARIF, including why a tool listing was incomplete.
- `examples/scan-reference-server.yml`: a copy-paste workflow that scans the MCP reference
  server (`@modelcontextprotocol/server-everything@2.1.0`) as a stdio target and uploads SARIF
  to code scanning. `.github/workflows/examples.yml` runs it against every change.
- `.github/workflows/demo-gif.yml` records `docs/demo/scan.gif` from `docs/demo/scan.tape` on
  a runner with Docker.
- PyPI metadata (description, classifiers, project URLs) and a PyPI-specific description with
  absolute links.

### Fixed

- **Tool listings fail closed.** `tools/list` follows `nextCursor` with a page cap. A failed or
  malformed first page, a repeated cursor or a page with no `tools` key is an incomplete
  listing: the scan says so, exits `2` on a gate run, and never writes or compares a drift
  baseline from it. A server that returns zero tools is a complete, empty listing. The
  server-supplied cursor is never echoed into notes.
- The Action reports `drift: unknown`, not `false`, when a gate run was refused before any
  comparison.
- Injection ratings: only sinks backed by an observed capability rate CRITICAL; a verbatim copy
  of a tool result is LOW data pass-through; description-only sinks are named as such.
- Instrument redaction: secrets glued to the canary, URL-encoded or nested several rounds deep,
  and values under secret-sounding keys are redacted before anything is written.
- Reports now carry the installed package version. SARIF `tool.driver.version` and the scan
  record's `tool_version` were hardcoded to `0.1.0`; they read `agent_perimeter.__version__`,
  which comes from the package metadata, and a test fails if a literal comes back.
- The eval never scores a fixture whose listing stopped early, and the degraded-mode floor test
  can now fail.

### Changed

- Security reports go through GitHub private vulnerability reporting; the personal email
  address is gone and a test guards against a published one. The acknowledgement target is 5
  business days.
- Every third-party GitHub Action is pinned to a commit SHA.
- The source distribution contains the package, README, licence and NOTICE only (163 KB, down
  from 2.8 MB); tests, fixtures, the web UI and census data stay in the git repo.
- Dependencies: patched known vulnerabilities in the Python and web lockfiles (including Mako
  1.4.3).
- CI no longer uploads the deliberately flawed fixtures' SARIF to this repo's code scanning.

### Removed

- Private project briefs, from the public repo.

## [1.1.0] - 2026-09-26

### Removed

- **Census Tier 3 (the live-discover stratum).** Review found it sent live, unauthenticated
  `server/discover` probes to sampled third-party hosts with no scope file, which conflicts with
  the rule that no active probe runs without one. It was deleted rather than redesigned: a
  random sample of servers you don't own has no single party who could authorise it. The
  census is passive-only (Tier 1 and Tier 2); see `docs/census/CHANGELOG.md`.

### Changed

- Web UI redesign: surface and elevation tokens, severity chips, type scale, motion states, a
  `StatTileGrid`, and a drift `Sparkline` that never draws a flat line from a single scan.

Verified before tagging: 794 tests passed (95% coverage), ruff and `mypy --strict` clean, 97
Playwright tests including axe and keyboard-only, `docker compose up` clean, 14 sandbox tests
against a live Docker daemon.

## [1.0.0] - 2026-09-16

First tagged release, as a GitHub Action: `uses: Berakhah/agent-perimeter@v1`.

[Unreleased]: https://github.com/Berakhah/agent-perimeter/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Berakhah/agent-perimeter/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Berakhah/agent-perimeter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Berakhah/agent-perimeter/releases/tag/v1.0.0
