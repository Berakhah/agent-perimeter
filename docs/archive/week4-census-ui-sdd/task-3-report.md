# Task 3 report: Artifact fetch and safe extraction

## What I implemented

`agent_perimeter/census/artifacts.py` — downloads a published PyPI sdist or
npm tarball (attacker-controlled input), extracts it into a temp directory
with traversal/symlink/bomb rejection, and never executes anything in it.

Public interface, matching the brief exactly:
`ArchiveRejected`, `ArtifactResult(status, detail, root, version)`,
`safe_extract(archive, dest) -> list[Path]`,
`fetch_artifact(client, coords) -> ArtifactResult`,
`MAX_ARCHIVE_BYTES`, `MAX_UNCOMPRESSED_BYTES`, `MAX_MEMBERS`, `MAX_FILE_BYTES`,
`PYPI_JSON`, `NPM_JSON`.

Also added `hypothesis` as a dev dependency (`pyproject.toml`/`uv.lock`) — it
wasn't in the project's dev group yet and the brief's property test needs it.

## How each of the 7 controller instructions was applied

1. **`tf.extractall(path=dest, filter="data")` in a `try` block** —
   `agent_perimeter/census/artifacts.py:138-149` (`_extract_tar`). This is the
   primary defense for tar archives instead of a hand-rolled walk.

2. **Catch specific stdlib exceptions, re-raise as `ArchiveRejected`** —
   `artifacts.py:140-149`: `tarfile.AbsoluteLinkError` and
   `tarfile.LinkOutsideDestinationError` → `"symlink member: {name}"`;
   `tarfile.SpecialFileError` → `"special file member: {name}"`;
   `tarfile.OutsideDestinationError` → `"member resolves outside
   destination: {name}"`; a general `tarfile.FilterError` catch-all →
   `"rejected by extraction filter: {exc}"`. Since I construct the
   `ArchiveRejected` message myself rather than reusing the stdlib message
   text verbatim, the brief's `match="outside"` / `match="symlink"` regexes
   pass unchanged — no test regex needed adjusting. **One real deviation is
   documented under Concerns below.**

3. **Zip path keeps manual member-by-member checks** —
   `artifacts.py:153-179` (`_is_zip_symlink` + `_extract_zip`): rejects zip
   entries whose Unix mode bits (`external_attr`) mark them as a symlink, and
   runs every entry's name through the same `_resolve_member`/`_member_target`
   pre-check tar uses. Tested by
   `test_zip_traversal_members_are_rejected` and
   `test_zip_symlink_members_are_rejected` (new, not in the brief's shown
   test file, added because point 3 introduces a second code path that needs
   its own coverage).

4. **`MAX_FILE_BYTES` per-member cap, actually enforced** — `artifacts.py:33`
   (32 MiB, equal to `MAX_ARCHIVE_BYTES`, well under `MAX_UNCOMPRESSED_BYTES`).
   Enforced per-member before extraction in both `_extract_tar:129-132` (using
   `TarInfo.size` from `tf.getmembers()`) and `_extract_zip:172-173` (using
   `ZipInfo.file_size`). Proven by
   `test_a_single_oversized_member_is_rejected_even_under_the_total_cap`,
   which `monkeypatch`es `MAX_FILE_BYTES` down to 4 bytes and confirms a
   10-byte single member is rejected even though the archive's total size is
   nowhere near `MAX_UNCOMPRESSED_BYTES`.

5. **`MAX_MEMBERS` cap, checked before extracting** — `artifacts.py:34`,
   `121-122` (tar) and `161-162` (zip), both checked against
   `tf.getmembers()` / `zf.infolist()` before any extraction happens.

6. **Kept `_resolve_member` as a small internal helper** — `artifacts.py:59-90`
   — used by three callers: the property test (unchanged import path), the
   tar pre-check (`_member_target`, called from `_extract_tar`), and the zip
   path (`_member_target`, called from `_extract_zip`). This is the "OR" option
   point 6 offered rather than rewriting the property test to drive
   `safe_extract` end-to-end. The property (`resolved is None or dest in
   resolved.parents`) is unchanged from the brief and still holds — verified
   both by the test suite and by an out-of-band 5000-example hypothesis run
   (see Testing below).

7. **`test_the_module_never_executes_an_artifact` extended** —
   `tests/census/test_artifacts.py` (same test function, brief's forbidden-
   substring list kept, plus `assert 'filter="data"' in src` appended) so the
   "we rely on the stdlib filter, not a hand-rolled walk" claim is grep-
   verifiable, not just asserted in prose.

## TDD evidence

RED: ran `uv run pytest tests/census/test_artifacts.py` against the brief's
test file before `artifacts.py` existed →
`ModuleNotFoundError: No module named 'agent_perimeter.census.artifacts'`.

GREEN (final): `uv run pytest tests/census/test_artifacts.py -q --no-cov` →
`22 passed`. Full suite: `uv run pytest -q` → `512 passed, 9 warnings`
(warnings are pre-existing, unrelated to this task — sqlite ResourceWarning
in `test_cli.py`, a legacy-SSE warning). Coverage: 94.04% (floor is 75%).
`uv run ruff check .` → all checks passed. `uv run mypy --strict
agent_perimeter` → no issues in 85 source files.

Two real RED failures surfaced and were fixed mid-implementation, not just
the initial module-not-found RED (see Self-review/Concerns — both were
genuine bugs the property test caught, not test-authoring mistakes):

- Hypothesis found `name='0:'` escaping the destination on this Windows host
  (`(dest / "0:").resolve()` discards `dest` and lands on a different drive).
- Hypothesis then found `name='.'` (resolves to `dest` itself, not a
  descendant of it — technically satisfies "does not escape" but violated the
  test's literal `dest in resolved.parents` assertion), which on inspection
  generalizes to `'..'` also violating the property in the *original brief's*
  hand-rolled `_resolve_member` (unrelated to my filter="data" changes — the
  brief's own two-line implementation had this gap too).

## Files changed

- `agent_perimeter/census/artifacts.py` (new, 349 lines)
- `tests/census/test_artifacts.py` (new, 22 tests)
- `pyproject.toml` / `uv.lock` (added `hypothesis` to the dev dependency group)

## Self-review

- **Completeness**: all 7 points applied (see above); brief's original
  interfaces (`ArchiveRejected`, `ArtifactResult`, `safe_extract`,
  `fetch_artifact`, the three original constants, `PYPI_JSON`/`NPM_JSON`)
  intact and unchanged in shape.
- **Quality**: follows `fetch.py`'s house style — `dataclass(slots=True)`,
  `USER_AGENT` built from `__version__`, defensive `isinstance()` narrowing
  instead of trusting JSON shape, `FetchStatus`/`Ecosystem` reused from
  `model/census.py` without modification, never raises out of
  `fetch_artifact` (verified by test, see below).
- **Discipline**: no scope creep. `fetch_artifact` doesn't retry (unlike
  `fetch.py`'s `paginate`, which does) — the brief didn't ask for retry logic
  here and a single unfetchable package is cheap to skip in a census of
  thousands; I judged adding retry/backoff to be out of scope rather than a
  gap, since nothing in the brief or task instructions asked for it.
- **Testing**: all extraction tests build real tar/zip archives in-process
  (no mocking of `tarfile`/`zipfile`); `fetch_artifact` tests use
  `httpx.MockTransport` serving real JSON bodies and real (small) tar bytes,
  matching `test_fetch.py`'s existing pattern — no mocking of the module
  under test itself. Test output is clean (no warnings from the new file).
- **Security-critical verification**: I explicitly confirmed that
  `test_symlink_members_are_rejected` exercises the real
  `tarfile.extractall(filter="data")` path and not just the `_resolve_member`
  pre-check, by calling `_member_target` directly on the symlink member's own
  name (`"link"`) and confirming it passes without raising — meaning the
  `ArchiveRejected` the test observes can only come from the `except
  (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError)` clause
  around the real `extractall` call. I also stress-tested the escape property
  with 5000 hypothesis examples directly (outside pytest) after fixing the
  two gaps found above, to raise confidence beyond the default ~100-example
  run.

## Concerns / deviations worth flagging

1. **`filter="data"` alone does not reject a leading-slash member name** — it
   strips the leading `/` and treats the rest as relative, so `"/etc/passwd"`
   safely lands at `dest/etc/passwd` instead of raising. I verified this
   empirically (not just by reading the PEP) before deciding it needed a
   supplementary guard: the brief's `test_traversal_members_are_rejected` test
   parametrizes exactly this case and expects `ArchiveRejected`. I kept
   `_resolve_member` as a pre-check specifically to preserve this test's
   original expectation (all three parametrized names, unchanged, still raise
   with `match="outside"`) rather than weakening the test. This is a
   deliberate, documented (`artifacts.py:64-68`) supplement to `filter="data"`
   for one narrow gap — not a return to hand-rolling the traversal walk;
   `filter="data"` still does the actual extraction and remains the deep
   guard against symlink/hardlink/special-file member content.
2. **Two path-escape edge cases (Windows drive-letter names, and `"."`/`".."`)
   were bugs in the brief's own hand-rolled `_resolve_member`**, found by
   running its property test for real rather than assuming it would pass.
   Both are now fixed in `_resolve_member` itself
   (`artifacts.py:59-90`) and documented inline. I did not alter the property
   test's assertion — I made the implementation satisfy it as originally
   written, which I believe is the more conservative fix (reject rather than
   loosen the check).
3. **`fetch_artifact` has no retry/backoff** for the metadata or download
   request (unlike `fetch.py`'s `paginate`). Flagging in case a later task
   expects one; nothing in the brief's Step 2 prose or the controller's task
   description asked for it, and adding it felt like scope creep for this
   task.
4. **Ownership of the extracted `root` directory on success is documented but
   not enforced** — `fetch_artifact` returns `ArtifactResult.root` pointing at
   a real temp directory it does not clean up on the `OK` path (comment at
   `artifacts.py:343-345`). Task 4 (or whatever orchestrates calls across a
   census of thousands of packages) needs to delete it after reading. This
   matches the brief's own prose ("downloaded ... extracted, read, and
   deleted") read as: the archive file is deleted here, the extracted
   directory is deleted by whoever reads it — but I want this called out
   explicitly since it's a caller contract, not an enforced one.

---

## Fix report: reviewer findings on commit 4d84099

Commit fixing all four items: `5586e99`.

### 1. Critical — uncaught exceptions on corrupted/truncated archives

**Confirmed the reproduction before fixing anything.** Built a well-formed
tar.gz and truncated it to half its length, then ran
`tarfile.is_tarfile(truncated)` directly — it raised a bare `EOFError`
("Compressed file ended before the end-of-stream marker was reached"),
*not* a `tarfile.TarError`. Separately, built a well-formed zip and flipped
10 bytes right after the local file header (inside the DEFLATE stream, away
from the EOCD/central directory) — reading it raised `zlib.error: Error -3
while decompressing data: invalid block type`; flipping bytes elsewhere in
the stream instead produced `zipfile.BadZipFile: Bad CRC-32`. None of these
four exception types (`EOFError`, `zlib.error`, `zipfile.BadZipFile`,
`tarfile.TarError` for other corruption modes) were caught anywhere in the
call chain — `_extract_tar`/`_extract_zip` only caught the five PEP-706
`FilterError` subclasses, `safe_extract`'s dispatcher called
`tarfile.is_tarfile()`/`zipfile.is_zipfile()` completely unguarded, and
`_fetch_into`'s outer handler only caught `OSError` (none of these four are
`OSError` subclasses).

**Fix** (`agent_perimeter/census/artifacts.py:49-53` for the constant,
`123-134` for the wrap): added
`_CORRUPT_ARCHIVE_ERRORS = (tarfile.TarError, zipfile.BadZipFile, EOFError,
zlib.error, struct.error)` and wrapped `safe_extract`'s entire dispatcher
body (the `is_tarfile`/`is_zipfile` sniff *and* the calls into
`_extract_tar`/`_extract_zip`) in one `try`/`except _CORRUPT_ARCHIVE_ERRORS`,
re-raising as `ArchiveRejected`. I put the guard at this one call site
rather than duplicating it inside `_extract_tar` and `_extract_zip`
separately — `safe_extract` is the only caller of both, and Python
exceptions propagate through the nested calls into the same `try` block, so
one guard here covers the format sniff and both extraction paths with a
smaller diff than three separate guards would need. `_extract_tar`'s
existing specific `except` clauses for the PEP-706 filter subclasses
(`AbsoluteLinkError`, `OutsideDestinationError`, etc.) still fire first and
keep their specific messages, since they sit in an inner `try` closer to the
raise site and `ArchiveRejected` itself isn't one of the caught types, so
the outer wrap never intercepts them.

Added tests at both layers, per the request to cover this "through the full
`fetch_artifact()` path, not just `safe_extract()`":
- `test_a_truncated_tar_gz_is_rejected_not_raised` /
  `test_a_corrupted_zip_is_rejected_not_raised` — direct `safe_extract()`
  calls, `pytest.raises(ArchiveRejected, match="corrupt")`.
- `test_fetch_artifact_reports_failure_for_a_truncated_tar_gz` /
  `test_fetch_artifact_reports_failure_for_a_corrupted_zip` — full
  `fetch_artifact()` via `httpx.MockTransport` serving the corrupted bytes
  as the download response, asserting `result.status.is_failure` and
  `result.root is None` rather than an exception propagating.

### 2. Important — zip bomb guard bypassable via declared-vs-actual size mismatch

**I verified this claim empirically before implementing the suggested fix,
and it does not reproduce as described on this project's Python floor
(3.12+, running 3.13.14 here) — I'm reporting the finding in full rather
than silently deciding it didn't apply.** I built a zip with a real 300,000
byte member, then binary-patched both the local-file-header and
central-directory uncompressed-size fields down to a lying `10`, leaving the
real compressed DEFLATE data untouched. Reading it back through
`zf.open(info).read()` (the same API `zf.extract()` uses internally, and
the same one my streaming rewrite uses) never returned more than the
truncated bytes — CPython's `zipfile.ZipExtFile._read1` contains `data =
data[:self._left]`, where `self._left` starts at the *declared* size and is
decremented every read. So on the current stdlib, a member that understates
its declared size cannot leak excess decompressed bytes through `.read()`;
it instead produces a `Bad CRC-32` `zipfile.BadZipFile` the moment `_left`
hits zero (now caught by fix #1 above). I ran this through the real
`safe_extract()` end-to-end before writing the permanent test and confirmed
it: `ArchiveRejected: corrupt or truncated archive: Bad CRC-32 for file
'big.bin'`, with the leftover on-disk file at **0 bytes** — nothing large
ever got written.

Given that, the *original* pre-check (`if info.file_size > MAX_FILE_BYTES:
raise ... ; total += info.file_size`) was not actually exploitable via this
specific vector on this stdlib version. That said, I implemented the
requested fix anyway rather than leaving the pre-check as-is, because:
trusting attacker-controlled declared metadata as the sole size guard is
the wrong general pattern for this module regardless of whether the current
CPython version happens to also protect it internally (a stdlib
implementation detail, not a documented contract this code should lean on);
it costs nothing (no measurable slowdown, no added dependency); and it
matches `_download`'s existing established pattern in this same file
(bound by bytes actually received, not by the `Content-Length` header).

**Fix** (`agent_perimeter/census/artifacts.py:177-215`): `_extract_zip` now
opens each member via `zf.open(info)` and streams it in
`_STREAM_CHUNK_BYTES` (64 KiB) chunks to the target file, counting actual
bytes written and checking `MAX_FILE_BYTES`/`MAX_UNCOMPRESSED_BYTES` against
that running total instead of the declared `info.file_size`, mirroring
`_download`'s existing pattern exactly. Added
`test_a_zip_entry_with_understated_declared_size_is_rejected_not_written`,
which builds the lying-size fixture above, asserts `ArchiveRejected`, and
walks the output directory afterward asserting no leftover file exceeds 10
bytes (the declared lie) — proving nothing large landed on disk regardless
of which layer (my counter or the stdlib's own CRC check) catches it first.

### 3. Important — hypothesis-found bugs had no pinned regression test

Added `@example("0:")`, `@example(".")`, `@example("..")` to
`test_no_member_name_ever_escapes_the_destination`
(`tests/census/test_artifacts.py`), each with an inline comment naming the
specific escape it pins (Windows drive-letter join discarding `dest`; `"."`
resolving to `dest` itself; `".."` resolving to `dest`'s parent). These now
run deterministically on every test run rather than depending on
hypothesis's random search or a committed `.hypothesis/examples` database
(none was committed, and I did not add one — `@example` doesn't need it).

### 4. Not blocking — `ArtifactResult.root` cleanup ownership

No change made; already flagged as concern #4 in the original report above.
Repeating plainly for the record since the coordinator asked it be carried
into Task 6's dispatch: `fetch_artifact()`'s `OK` path returns a real temp
directory (`ArtifactResult.root`) that this module never deletes. Task 6's
plan pseudocode (per the reviewer's check) has no cleanup call either, so
end-to-end this is currently unowned and could leak significant temp disk
space at "census of thousands" scale. This is Task 6's problem to solve.

### Minor notes

- `hypothesis` (added as a dev dependency for the brief's own RED test) is
  MPL-2.0, outside this project's "Apache/MIT/BSD only" policy. Flagging
  explicitly per policy; not scope creep on my part since the brief's own
  shown RED test requires it, and it's dev-only (never ships in the
  distributed package).
- Added `test_member_count_at_exactly_the_cap_is_accepted`, exercising the
  `MAX_MEMBERS` boundary itself (monkeypatched down to 3 for speed) rather
  than only the `>` side.

### Verification run

```
uv run pytest tests/census/test_artifacts.py -q --no-cov   → 28 passed
uv run pytest -q                                            → 518 passed, 9 warnings, 94.06% coverage
uv run ruff check .                                         → All checks passed!
uv run mypy --strict agent_perimeter                        → Success: no issues found in 85 source files
```

The 9 warnings are the same pre-existing, unrelated ones noted in the
original report (sqlite `ResourceWarning` in `test_cli.py`, a legacy-SSE
warning) — nothing from this file. Test count rose from 512 to 518 (6 new
tests: 2 corruption tests at the `safe_extract` layer, 2 at the
`fetch_artifact` layer, 1 zip-bomb-bypass test, 1 `MAX_MEMBERS` boundary
test); the `@example` pins added no new test count since they extend an
existing hypothesis test's example set rather than adding new test
functions.
