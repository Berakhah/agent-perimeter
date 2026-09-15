# Agent Perimeter — GitHub Action wrapper

**Date:** 16 September 2026
**Status:** design approved in brainstorming; awaiting implementation plan
**Scope:** the `agent-perimeter/scan@v1` follow-on that the drift spec
(`2026-09-15-drift-detection-design.md` §10) listed as out of scope pending
a publishing decision. That decision is taken here.
**Consumes:** the existing `agent-perimeter scan` CLI unchanged — no change
to `agent_perimeter/cli.py`, `scan_runner`, checks, or the API.

---

## 1. Why

Drift detection is the subscription story, and its natural home is a CI
job that runs on every push or on a cron: rescan the server, diff against
an approved baseline, fail the build when a tool changed. Today a user has
to hand-write that job — install the package from git, remember the flag
combination, wire SARIF upload, handle the first run. A composite action
turns the README's three-line drift recipe into `uses:
Berakhah/agent-perimeter@v1` and makes the exit-3 contract a thing a
branch-protection rule can see.

## 2. Decisions taken (brainstorming, 16 Sep 2026)

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | Primary job | **Drift gate + SARIF.** Scan, upload SARIF to code scanning, exit 3 when tool descriptions/schemas/annotations drift from a committed baseline. | SARIF only (drops the drift story). Drift only (drops the findings). |
| D2 | Targets in v1 | **HTTP and stdio.** Forces a composite action running on the runner host so the containerised stdio launcher (hard rule 4) can talk to the runner's Docker daemon. | HTTP only via a Docker-container action — cannot launch sibling containers without mounting the socket. |
| D3 | Delivery | **Install from this repo at the action's own ref.** `action.yml` lives at the repo root; the composite installs `agent_perimeter` from `${{ github.action_path }}`. Version = git tag. Zero publishing infrastructure; ~30–60 s install per run. | PyPI release (new recurring surface; 0.1.0 never released). GHCR image (release workflow plus socket/nested-Docker handling for stdio). |
| D4 | Baseline location | **Committed file in the consumer's repo**, default `.agent-perimeter/baseline.json`. Approving a change is a commit reviewed in a PR. First run with no baseline writes one and exits 0; the action never commits. | Actions cache/artifact roll-forward — "approved" degrades to "whatever ran last", and cache eviction silently resets the gate. |
| D5 | Internals | **Python entry point, YAML is glue.** `agent_perimeter/action.py` (run as `python -m agent_perimeter.action`) does input parsing, first-run detection, command assembly, output/summary writing. Every branch is a pytest. | All logic in bash inside `action.yml` — untestable, and exactly the branching that rots. |
| D6 | How the scan runs | **Subprocess: `agent-perimeter scan …`.** The action prints the assembled, shell-quoted argv and runs it. The log a user sees is the CLI's own log; the printed line is a reproduction command a sceptic can paste. | In-process call into `cli.scan` (a monolithic Typer command; would need a refactor of `cli.py` this feature does not otherwise touch). |
| D7 | SARIF upload | **Inside the action, `upload-sarif` input default `true`**, via `github/codeql-action/upload-sarif` pinned. Needs `security-events: write`; the README states it first. Repos without code scanning set it `false` and consume the `sarif-file` output. | Output-only (every consumer re-wires the same step). Silent `continue-on-error` on the upload (a green job with nothing uploaded). |
| D8 | Versioning | **`v1.0.0` tag plus a floating `v1` major tag** moved by a `release.yml` on release publish. `branding` in `action.yml` so a Marketplace listing is one click later; the listing itself is not part of this feature. | Marketplace publication now (needs a public README pass and a decision about support expectations that has not been made). |

Routine calls made without asking: input names are kebab-case and mirror
the CLI flags one-to-one where a flag exists; `mode` defaults to `passive`;
the action does not run `actions/checkout` itself (the consumer's workflow
already checked out the repo the baseline lives in); no `--repo`,
`--config`, `--env-file`, `--agent-transcript` pass-through in v1 (secrets
scanning of the consumer's own repo and injection claim B are separate
workflows; adding them later is additive).

## 3. Hard-rule check

| Rule | Effect on this design |
|---|---|
| 1 No active probe without scope | `mode: active` is accepted only alongside `scope-file`; the action passes the path through and **never synthesises or templates a scope file**. The CLI's own fail-closed refusal (exit 2) is the gate; the action adds nothing in front of it. Boundary test in §7. |
| 2 Public-registry scanning is passive | Unchanged. The action scans the one `target` the consumer names. |
| 3 Never validate a secret | Unchanged. The action writes only what the CLI already writes (SARIF, snapshot, HTML). It never prints input values other than `target`, `mode`, `image`, `only` and file paths; `env` values are passed to the subprocess and not echoed in the reproduction line (each `--env KEY=VALUE` is rendered as `--env KEY=***`). |
| 4 stdio in a locked container | Unchanged; the CLI launches the same way. The self-test workflow proves the launcher works on `ubuntu-latest`. |
| 5 Analysed content never reaches a tool-capable context | The action reads the SARIF it produced to count results and read `properties`; it never re-emits tool descriptions into the job summary. Summary shows counts, ids, titles, severities only. |
| 6 CWE + taxonomy per finding | Unchanged; SARIF already carries them. |
| 7 No weaponisation | Unchanged. |
| 8 No named third-party server in public output | Not applicable — the consumer scans their own target; nothing is published. |
| R1 no hardcoded model names / determinism | The action calls no model. `requires_model` surface unchanged. |
| $0 recurring | Nothing hosted. The self-test workflow runs on the free GitHub runner minutes this repo already uses. |

## 4. Surface — `action.yml` (repo root)

```yaml
name: Agent Perimeter
description: Scan an MCP server, upload SARIF, and fail the job when its tools drift from a committed baseline.
branding: { icon: shield, color: yellow }
```

### Inputs

| Input | Required | Default | Maps to |
|---|---|---|---|
| `target` | yes | — | `--target` |
| `mode` | no | `passive` | `--mode` |
| `scope-file` | no | — | `--scope-file` (required by the CLI when `mode: active`) |
| `image` | no | CLI default (`python:3.12-slim`) | `--image` |
| `env` | no | — | one `--env KEY=VALUE` per non-blank line |
| `only` | no | — | `--only` |
| `baseline` | no | `.agent-perimeter/baseline.json` | `--baseline` (gate run) / `--snapshot` (first run) |
| `snapshot` | no | `.agent-perimeter/current.json` | `--snapshot` (gate run) |
| `fail-on-drift` | no | `true` | `--fail-on-drift` (gate run only) |
| `sarif` | no | `agent-perimeter.sarif` | `--sarif` |
| `html` | no | — | `--html` |
| `upload-sarif` | no | `true` | guards the `upload-sarif` step |

### Outputs

| Output | Value |
|---|---|
| `sarif-file` | path passed as `sarif` — written only when the file exists after the run, absent otherwise so the upload step's guard skips cleanly |
| `snapshot-file` | path the snapshot was written to (`baseline` on a first run, `snapshot` otherwise) |
| `baseline-created` | `true` on a first run, else `false` |
| `drift` | `none` on a first run; else `true` iff the SARIF contains a `drift.description_drift` result, `false` otherwise. Derived from the SARIF, not the exit code, so it is meaningful with `fail-on-drift: false`. |
| `finding-count` | `len(runs[0].results)` in the SARIF |

### Steps (`runs.using: composite`)

1. `astral-sh/setup-uv@<pinned>` then `uv pip install --system "${{ github.action_path }}"`.
2. `python -m agent_perimeter.action` with every input exported as `INPUT_<NAME>` (GitHub's own convention; composite actions do not set these automatically, so the step's `env:` block does it explicitly).
3. `github/codeql-action/upload-sarif@<pinned>` with `sarif_file: ${{ steps.scan.outputs.sarif-file }}`.

Step 2 has `id: scan`. Step 3's condition is
`if: always() && inputs.upload-sarif == 'true' && steps.scan.outputs.sarif-file != ''`
— a drift failure (exit 3) must still upload the SARIF that shows the drift
finding, and `sarif-file` is only written to `GITHUB_OUTPUT` when the file
exists on disk, so a scan that failed before writing SARIF skips the upload
rather than failing it.

### Exit semantics (unchanged from the CLI)

| Code | Meaning |
|---|---|
| 0 | Scan ran; no drift (or first run) |
| 2 | Usage error, scope refusal, missing artifact — nothing to act on |
| 3 | Drift gate tripped |

## 5. Runtime flow — `agent_perimeter/action.py`

```
inputs  = read_inputs(os.environ)            # INPUT_* → dataclass; target required
first   = not Path(inputs.baseline).is_file()
argv    = build_argv(inputs, first_run=first)
print(reproduction_line(argv))               # env values masked
rc      = subprocess.run(argv).returncode    # stdout/stderr inherited
sarif   = read_sarif(inputs.sarif)           # exit 2 if rc == 0 and file missing
write_outputs(github_output_path, ...)
write_summary(github_step_summary_path, ...)
sys.exit(rc)
```

- Before running, the parent directories of `baseline`, `snapshot`, `sarif`
  and `html` are created (`mkdir -p`); the CLI writes with `write_text` and
  does not create them, and the defaults live under `.agent-perimeter/`.
- `build_argv` — first run: `--snapshot <baseline>`, no `--baseline`, no
  `--fail-on-drift`. Gate run: `--baseline <baseline> --snapshot <snapshot>`
  and `--fail-on-drift` iff the input is `true`. Always `--sarif <sarif>`.
  Optional flags only when the input is non-empty.
- `reproduction_line` — `shlex.join(argv)` with every `--env KEY=VALUE`
  value replaced by `***`. Printed before the run under the heading
  `Reproduction:` so it is the first thing in the step log.
- `read_sarif` — returns `None` when the file is absent. Absent with `rc == 0`
  is an error (exit 2: "Scan exited 0 but wrote no SARIF at <path>. Check
  the `sarif` input."). Absent with `rc != 0` is expected (the CLI failed
  before writing); outputs are still written with `finding-count=0`,
  `drift=false`.
- `write_summary` — one markdown table: target, mode, revision claimed
  (from `runs[0].tool.driver.properties` if present, else `unknown`),
  finding count by severity, drift verdict. On a first run a callout:
  *"Baseline written to `<path>`. Commit it to arm the drift gate."* On
  drift: *"Drift gate tripped: N tool(s) changed. Review the diff with
  `agent-perimeter drift <baseline> <snapshot>`; commit the new snapshot as
  the baseline to approve."*
- Exits with the subprocess return code, so the job fails on 2 and 3.

The module has no dependency on `typer` internals; it depends on the
`agent-perimeter` console script being on `PATH`, which step 1 guarantees.

## 6. Error handling (copy rules: state what happened and what to do)

| Condition | Behaviour |
|---|---|
| `target` empty | exit 2: "Set the `target` input to a URL or a stdio command." |
| `mode: active` without `scope-file` | passed through; the CLI refuses (exit 2) with its own message. The action does not pre-empt it, so the refusal path and its message are the CLI's single source of truth. |
| `fail-on-drift`/`upload-sarif` not `true`/`false` | exit 2 naming the input and the accepted values. |
| `baseline` exists but is unreadable/invalid | passed through; the CLI's `--baseline` reader exits 2 with its own message. |
| rc 0 and no SARIF on disk | exit 2 (see §5). Never a green job with nothing uploaded. |
| `GITHUB_OUTPUT` / `GITHUB_STEP_SUMMARY` unset | outputs and summary go to stdout with a `::notice::` line saying so — lets the module run locally for debugging without pretending to be GitHub. |
| upload step lacks `security-events: write` | GitHub's own error fails the upload step; the README's minimal workflow includes the `permissions:` block. |

## 7. Testing

**Unit — `tests/action/test_action.py`** (`subprocess.run` monkeypatched to
record argv and return a chosen rc; `GITHUB_OUTPUT`/`GITHUB_STEP_SUMMARY`
point at tmp files; a small SARIF written by the fake "CLI" where needed):

- first run assembles `--snapshot <baseline>`, no `--baseline`, no
  `--fail-on-drift`; outputs `baseline-created=true`, `drift=none`,
  `snapshot-file=<baseline>`; exit 0
- gate run assembles `--baseline … --snapshot … --fail-on-drift`; rc 3 with
  a drift result in the SARIF → `drift=true`, exit 3
- gate run rc 0, no drift result → `drift=false`, exit 0
- `fail-on-drift: false` omits the flag; SARIF with a drift result →
  `drift=true`, exit 0 (soft gate)
- `env` multiline → repeated `--env`; blank lines ignored; reproduction line
  masks values
- **boundary:** `mode: active` with `scope-file` passes `--scope-file <path>`
  through unchanged; `mode: active` without one passes no `--scope-file`
  and the action writes no file anywhere (asserted by listing the tmp
  workspace before/after)
- `target` empty → exit 2, nothing executed
- rc 0 and no SARIF → exit 2
- `finding-count` and the per-severity summary read from the SARIF
- printed reproduction line equals `shlex.join` of the argv actually
  executed (modulo masking)
- unset `GITHUB_OUTPUT` → outputs printed to stdout with the notice

**Contract — `tests/action/test_action_yml.py`:** parses `action.yml`;
every input has a non-empty description and a matching `INPUT_*` consumer
in `action.py`; every output `action.py` writes is declared and vice versa;
the two `uses:` refs are pinned to full versions (`@vX.Y.Z` or a 40-char
SHA), never a floating major; `branding` present; README's "Use as a GitHub
Action" section names every input (same style as `tests/docs/`).

**Self-test — `.github/workflows/action-selftest.yml`** on `ubuntu-latest`,
`uses: ./`, stdio targets throughout (the fixture fleet is stdio-only, and
this is also the proof the containerised launcher works on a GitHub
runner). Steps: build `tests/fixtures/servers` into a local image; (1) run
with `AP_FIXTURE_FLAW=none` and no baseline → assert `baseline-created ==
'true'`, file exists; (2) rerun identical → assert `drift == 'false'`, step
succeeded; (3) run with `AP_FIXTURE_FLAW=drift_description`,
`continue-on-error: true` → assert `steps.x.outcome == 'failure'` and
`drift == 'true'`; (4) assert the SARIF from (3) contains a
`drift.description_drift` result and that the upload step ran. `upload-sarif`
is left `true` in (1)–(3) so the pinned upload step is exercised (CI already
has `security-events: write`). The workflow runs on push to `main` and on
pull requests, like `ci.yml`.

**Release — `.github/workflows/release.yml`:** on `release: published`, move
the `v1` tag to the release's commit (`git tag -f v1 && git push -f origin
v1`) when the release tag matches `v1.*`. `tests/action/test_action_yml.py`
also asserts this workflow exists, triggers on `release: published`, and is
gated on the `v1.` prefix.

Coverage floor 75% applies; `action.py` is small and fully branch-covered
by the unit tests above.

## 8. Documents this feature must touch

- `README.md` — new section "Use as a GitHub Action" after "Drift
  detection": minimal workflow (`permissions: security-events: write`,
  `uses: Berakhah/agent-perimeter@v1`, `with: { target: … }`), the
  first-run/commit-the-baseline sequence, the input table, the exit-code
  table, and the `fail-on-drift: false` soft-gate pattern.
- `docs/superpowers/specs/2026-09-15-drift-detection-design.md` §10 — the
  GitHub Action bullet gets a pointer to this spec.
- `docs/open-decisions.md` — one dated entry recording D3 (install from
  ref; PyPI/GHCR not adopted) and D8 (no Marketplace listing yet).
- `docs/security.md` — no change; the action introduces no new data flow
  beyond what the CLI already has. Stated here so nobody re-checks.

## 9. Out of scope (recorded so nobody re-decides it by accident)

- Marketplace listing (D8) — metadata is in place; the listing is a
  human-partner decision about support expectations.
- PyPI / GHCR publication (D3).
- Pass-through of `--repo`, `--config`, `--env-file`,
  `--agent-transcript`. Additive later.
- Auto-committing the baseline or opening a PR with a new snapshot on
  drift — the point of D4 is that approval is a human commit.
- A reusable workflow (`workflow_call`) as an alternative to the composite
  action. The composite is enough for one step in a consumer's job.
- Running the web UI or API from the action. It is CLI-only by design
  (decision 2 in `docs/open-decisions.md`: CLI + local UI, nothing hosted).
