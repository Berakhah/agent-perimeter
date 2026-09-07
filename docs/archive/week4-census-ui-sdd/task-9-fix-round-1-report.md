# Task 9 — fix round 1 report

Commit: `a17378d` (branch `week4-census-ui`)

## Finding 1 (Critical) — malformed scope_file crashed with a bare 500

`_build_scope` (`agent_perimeter/api/scans.py`) wraps the `ScopeFile(...)`
construction in `try/except pydantic.ValidationError`. The first error is
translated into the same `AuthorizationRequired` the structural-absence
checks above it already raise, so both paths land in `app.py`'s one
exception handler (422, not 500).

`error.errors()[0]["loc"]` names the field directly for a `field_validator`
error (blank `target`/`authorising_party`/`attestation`). `ScopeFile`'s one
`model_validator(mode="after")` (expiry vs. `authorised_on`) reports
`loc=()` instead — pydantic's own behaviour for whole-model checks — so that
case falls back to `"expires_on"`, the only whole-model check `ScopeFile`
has today (commented in code: name it explicitly if a second one is added).

New tests in `tests/api/test_scans.py`:
- `test_a_whitespace_only_scope_field_is_refused_with_a_422_not_a_500`
- `test_expires_on_before_authorised_on_is_refused_with_a_422_not_a_500`

Both assert 422 with `error: "authorization_required"` and a `missing_field`,
same shape as the brief's own refusal tests.

## Finding 2 (Important) — passive-mode requests wrongly refused

`create_scan` only calls `_build_scope`/builds a real `ScopeFile` when
`scan_request.mode is ScanMode.ACTIVE` — previously it ran unconditionally,
so a passive request carrying an incomplete `scope_file` got refused with an
"Active checks need..." message that made no sense for a passive scan. Now
`scope` stays `None` for passive mode regardless of what `scope_file`
contains, matching the CLI (`--scope-file` unused in passive mode).

New test: `test_passive_mode_with_an_incomplete_scope_file_is_accepted`
(202, not 422).

## Finding 3 (Important) — `_persist`'s DB write path had zero coverage

Added `test_persist_writes_scan_and_finding_rows_to_the_database`: runs a
passive scan through the API, then opens a second connection to the same
sqlite file `create_app(database_url=...)` was given and asserts a `scan`
row exists with the right `target_ref`/`mode`, and the `finding` row count
matches the API's own `findings_count`.

This test caught a real, previously-silent bug: `Scan`/`Tool`/
`CapabilityEdge`/`FindingRow` are related only by raw FK columns (no ORM
`relationship()`), so SQLAlchemy's flush has no dependency graph to order
same-flush inserts by. A scan with no tools discovered (the common case in
these tests — nothing triggers the tool loop's own `session.flush()`) could
flush the `finding` insert before the `scan` insert and fail the FK
constraint. Sqlite doesn't enforce FKs by default, so this was invisible in
every existing test — it only surfaced because a different test module
(`tests/db/test_schema.py`) globally enables `PRAGMA foreign_keys=ON` for
every sqlite connection in the test process, and the new full-suite run hit
it. Postgres always enforces FKs, so this was a live bug, not a test
artifact. Fixed with one explicit `session.flush()` right after
`session.add(scan_row)`, guaranteeing the parent row lands before any child
row regardless of whether tools/edges exist.

## Verification

```
uv run pytest tests/api/ tests/model/test_scope.py tests/test_cli.py -q
  35 passed

uv run pytest tests/ -q
  618 passed, 12 warnings, coverage 93.87% (floor 75%)

uv run mypy --strict agent_perimeter
  Success: no issues found in 98 source files

uv run ruff check agent_perimeter/api/scans.py tests/api/test_scans.py
  All checks passed!

uv run ruff format --check agent_perimeter/api/scans.py tests/api/test_scans.py
  2 files already formatted
```

## Scope

Only `agent_perimeter/api/scans.py` and `tests/api/test_scans.py` touched.
No auth/access-control work done (out of scope per the dispatch). No Minor
items from the original review acted on beyond what these fixes required.
