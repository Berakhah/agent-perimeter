### Task 3: Artifact fetch and safe extraction

**Files:**
- Create: `agent_perimeter/census/artifacts.py`
- Test: `tests/census/test_artifacts.py`

**Interfaces:**
- Produces: `ArchiveRejected`; `ArtifactResult(status, detail, root, version)`; `safe_extract(archive, dest) -> list[Path]`; `fetch_artifact(client, coords) -> ArtifactResult`; `MAX_ARCHIVE_BYTES`, `MAX_UNCOMPRESSED_BYTES`, `MAX_MEMBERS`.
- Consumes: `PackageCoords`, `FetchStatus`.

An sdist or npm tarball is attacker-controlled input from an untrusted party. It is downloaded to a temporary directory, size-capped, extracted with traversal and symlink rejection, read, and deleted. **It is never executed** — no `setup.py`, no `npm install`, no import.

- [ ] **Step 1: RED — the extraction guards**

Create `tests/census/test_artifacts.py`:

```python
import io
import tarfile
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from agent_perimeter.census.artifacts import MAX_MEMBERS, ArchiveRejected, safe_extract


def _tar_with(tmp_path: Path, name: str, *, symlink_to: str | None = None) -> Path:
    path = tmp_path / "archive.tar.gz"
    with tarfile.open(path, mode="w:gz") as tf:
        info = tarfile.TarInfo(name)
        if symlink_to:
            info.type = tarfile.SYMTYPE
            info.linkname = symlink_to
            tf.addfile(info)
        else:
            data = b"x"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


@pytest.mark.parametrize("name", ["../escape.py", "/etc/passwd", "a/../../escape.py"])
def test_traversal_members_are_rejected(tmp_path: Path, name: str) -> None:
    archive = _tar_with(tmp_path, name)
    with pytest.raises(ArchiveRejected, match="outside"):
        safe_extract(archive, tmp_path / "out")


def test_symlink_members_are_rejected(tmp_path: Path) -> None:
    archive = _tar_with(tmp_path, "link", symlink_to="/etc/passwd")
    with pytest.raises(ArchiveRejected, match="symlink"):
        safe_extract(archive, tmp_path / "out")


def test_member_count_is_capped() -> None:
    assert MAX_MEMBERS <= 20_000


@given(st.text(min_size=1, max_size=40))
def test_no_member_name_ever_escapes_the_destination(name: str) -> None:
    """Property: whatever the member is called, nothing lands outside dest."""
    from agent_perimeter.census.artifacts import _resolve_member

    dest = Path("/tmp/ap-extract").resolve()
    resolved = _resolve_member(dest, name)
    assert resolved is None or dest in resolved.parents


def test_the_module_never_executes_an_artifact() -> None:
    src = Path("agent_perimeter/census/artifacts.py").read_text()
    for forbidden in ("subprocess", "os.system", "exec(", "eval(", "importlib"):
        assert forbidden not in src
```

Run: `uv run pytest tests/census/test_artifacts.py`
Expected: `ModuleNotFoundError`

- [ ] **Step 2: GREEN — download and extract**

Create `agent_perimeter/census/artifacts.py`:

```python
"""Download and read published package artifacts. Never execute one."""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from agent_perimeter.model.census import FetchStatus

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 20_000

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
NPM_JSON = "https://registry.npmjs.org/{name}"


class ArchiveRejected(Exception):
    """The archive did something an honest archive does not do."""


@dataclass(slots=True)
class ArtifactResult:
    status: FetchStatus
    detail: str
    root: Path | None
    version: str | None


def _resolve_member(dest: Path, name: str) -> Path | None:
    """Where this member would land, or None if the name is unusable."""
    if not name or name.startswith("/") or "\x00" in name:
        return None
    return (dest / name).resolve()


def safe_extract(archive: Path, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest.resolve()
    written: list[Path] = []
    total = 0

    with _open_archive(archive) as bundle:
        members = _members(bundle)
        if len(members) > MAX_MEMBERS:
            raise ArchiveRejected(f"{len(members)} members exceeds {MAX_MEMBERS}")
        for member in members:
            name, size, is_link = _describe(member)
            if is_link:
                raise ArchiveRejected(f"symlink member: {name}")
            target = _resolve_member(resolved_dest, name)
            if target is None or resolved_dest not in target.parents:
                raise ArchiveRejected(f"member resolves outside destination: {name}")
            total += size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ArchiveRejected("uncompressed size cap exceeded")
            _write(bundle, member, target)
            written.append(target)
    return written
```

`fetch_artifact` resolves coordinates through `PYPI_JSON` / `NPM_JSON`, picks the sdist (PyPI) or `dist.tarball` (npm), streams it with a byte cap, and returns `TOO_LARGE`, `NOT_FOUND`, `THROTTLED` or `OK` — never raising into the run loop, because one unfetchable package must not end a census of thousands.

- [ ] **Step 3: REFACTOR — one honest note**

Add above `safe_extract`:

```python
# ponytail: extraction into a temp dir with caps and traversal rejection, not a
# sandboxed container. Justified because nothing here is executed and every file is
# opened read-only; upgrade to the Week 1 container launcher if that ever changes.
```

- [ ] **Step 4: Commit**

```bash
uv run pytest tests/census/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/artifacts.py tests/census/test_artifacts.py
git commit -m "feat: artifact fetch with traversal, symlink and bomb guards"
```

---

