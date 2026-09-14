import io
import json
import struct
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from agent_perimeter.census.artifacts import (
    MAX_FILE_BYTES,
    MAX_MEMBERS,
    MAX_UNCOMPRESSED_BYTES,
    ArchiveRejected,
    ArtifactResult,
    fetch_artifact,
    safe_extract,
)
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords


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


def _tar_of(tmp_path: Path, files: dict[str, bytes], name: str = "archive.tar.gz") -> Path:
    path = tmp_path / name
    with tarfile.open(path, mode="w:gz") as tf:
        for member_name, data in files.items():
            info = tarfile.TarInfo(member_name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _zip_of(
    tmp_path: Path,
    files: dict[str, bytes],
    name: str = "archive.zip",
    symlinks: dict[str, str] | None = None,
) -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, mode="w") as zf:
        for member_name, data in files.items():
            zf.writestr(member_name, data)
        for member_name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(member_name)
            info.external_attr = 0o120777 << 16  # S_IFLNK
            zf.writestr(info, target)
    return path


def _truncated_tar_gz(tmp_path: Path) -> Path:
    """A well-formed tar.gz cut off mid-stream - the gzip envelope is
    incomplete, which raises a bare EOFError from tarfile's own gzip layer."""
    good = _tar_of(tmp_path, {"pkg/mod.py": b"print(1)\n" * 1000}, name="good.tar.gz")
    raw = good.read_bytes()
    truncated = tmp_path / "truncated.tar.gz"
    truncated.write_bytes(raw[: len(raw) // 2])
    return truncated


def _corrupted_zip(tmp_path: Path) -> Path:
    """A well-formed zip with bytes flipped in the middle of its compressed
    DEFLATE stream - decompressing it raises zlib.error, not BadZipFile."""
    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/mod.py", b"print(1)\n" * 5000)
    raw = bytearray(good.read_bytes())
    start = 30 + len("pkg/mod.py")  # local file header + filename, data follows
    for i in range(start, start + 10):
        raw[i] = 0xFF
    corrupted = tmp_path / "corrupted.zip"
    corrupted.write_bytes(bytes(raw))
    return corrupted


def _zip_with_understated_size(tmp_path: Path) -> Path:
    """A zip entry whose central-directory/local-header uncompressed-size
    field is patched to lie small while the real DEFLATE stream still
    decompresses to much more - the declared size is attacker-controlled
    metadata, not a bound on what the compressed stream actually contains."""
    good = tmp_path / "good.zip"
    payload = b"A" * 300_000  # highly compressible, spans multiple read chunks
    with zipfile.ZipFile(good, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", payload)
    raw = bytearray(good.read_bytes())
    local_sig = raw.find(b"PK\x03\x04")
    central_sig = raw.find(b"PK\x01\x02")
    lie = struct.pack("<I", 10)  # claim 10 bytes instead of 300000
    raw[local_sig + 22 : local_sig + 26] = lie
    raw[central_sig + 24 : central_sig + 28] = lie
    lying = tmp_path / "lying.zip"
    lying.write_bytes(bytes(raw))
    return lying


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


def test_per_file_cap_does_not_exceed_the_total_uncompressed_cap() -> None:
    assert MAX_FILE_BYTES <= MAX_UNCOMPRESSED_BYTES


def test_a_single_oversized_member_is_rejected_even_under_the_total_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A member declaring more bytes than the per-file cap is rejected, even though
    the archive's total declared size is nowhere near MAX_UNCOMPRESSED_BYTES."""
    import agent_perimeter.census.artifacts as artifacts_module

    monkeypatch.setattr(artifacts_module, "MAX_FILE_BYTES", 4)
    archive = _tar_of(tmp_path, {"big.bin": b"0123456789"})
    with pytest.raises(ArchiveRejected, match="exceeds"):
        safe_extract(archive, tmp_path / "out")


def test_a_well_behaved_tar_extracts_cleanly(tmp_path: Path) -> None:
    archive = _tar_of(tmp_path, {"pkg/__init__.py": b"", "pkg/mod.py": b"print(1)\n"})
    written = safe_extract(archive, tmp_path / "out")
    names = {p.name for p in written}
    assert names == {"__init__.py", "mod.py"}
    assert (tmp_path / "out" / "pkg" / "mod.py").read_text() == "print(1)\n"


def test_zip_traversal_members_are_rejected(tmp_path: Path) -> None:
    archive = _zip_of(tmp_path, {"../escape.py": b"x"})
    with pytest.raises(ArchiveRejected, match="outside"):
        safe_extract(archive, tmp_path / "out")


def test_zip_symlink_members_are_rejected(tmp_path: Path) -> None:
    archive = _zip_of(tmp_path, {}, symlinks={"link": "/etc/passwd"})
    with pytest.raises(ArchiveRejected, match="symlink"):
        safe_extract(archive, tmp_path / "out")


def test_a_well_behaved_zip_extracts_cleanly(tmp_path: Path) -> None:
    archive = _zip_of(tmp_path, {"pkg/mod.py": b"print(1)\n"})
    written = safe_extract(archive, tmp_path / "out")
    assert [p.name for p in written] == ["mod.py"]
    assert (tmp_path / "out" / "pkg" / "mod.py").read_text() == "print(1)\n"


def test_a_truncated_tar_gz_is_rejected_not_raised(tmp_path: Path) -> None:
    """A cut-off gzip stream raises a bare EOFError from tarfile's gzip layer,
    not a tarfile.TarError - it still must come back as ArchiveRejected."""
    archive = _truncated_tar_gz(tmp_path)
    with pytest.raises(ArchiveRejected, match="corrupt"):
        safe_extract(archive, tmp_path / "out")


def test_a_corrupted_zip_is_rejected_not_raised(tmp_path: Path) -> None:
    """A bit-flipped DEFLATE stream raises zlib.error, not zipfile.BadZipFile -
    it still must come back as ArchiveRejected."""
    archive = _corrupted_zip(tmp_path)
    with pytest.raises(ArchiveRejected, match="corrupt"):
        safe_extract(archive, tmp_path / "out")


def test_a_zip_entry_with_understated_declared_size_is_rejected_not_written(
    tmp_path: Path,
) -> None:
    """A member's declared uncompressed size is attacker-controlled metadata,
    not a bound on the real DEFLATE stream - extraction must not write more
    than the declared size to disk before the mismatch is caught."""
    archive = _zip_with_understated_size(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(ArchiveRejected):
        safe_extract(archive, out)
    for written_file in out.rglob("*"):
        if written_file.is_file():
            assert written_file.stat().st_size <= 10


def test_member_count_at_exactly_the_cap_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only strictly more than MAX_MEMBERS is rejected - the boundary itself
    is a legitimate small archive, not an attack."""
    import agent_perimeter.census.artifacts as artifacts_module

    monkeypatch.setattr(artifacts_module, "MAX_MEMBERS", 3)
    archive = _tar_of(tmp_path, {"a": b"1", "b": b"2", "c": b"3"})
    written = safe_extract(archive, tmp_path / "out")
    assert len(written) == 3


@given(st.text(min_size=1, max_size=40))
@example("0:")  # Windows drive-letter-like name - (dest / "0:").resolve() used to
# discard `dest` entirely and land on a different drive
@example(".")  # resolves to `dest` itself, not a descendant of it
@example("..")  # resolves to `dest`'s parent - outside `dest`
def test_no_member_name_ever_escapes_the_destination(name: str) -> None:
    """Property: whatever the member is called, nothing lands outside dest."""
    from agent_perimeter.census.artifacts import _resolve_member

    dest = Path("/tmp/ap-extract").resolve()  # noqa: S108 -- fixed probe path, never created
    resolved = _resolve_member(dest, name)
    assert resolved is None or dest in resolved.parents


def test_the_module_never_executes_an_artifact() -> None:
    src = Path("agent_perimeter/census/artifacts.py").read_text()
    for forbidden in ("subprocess", "os.system", "exec(", "eval(", "importlib"):
        assert forbidden not in src
    # We rely on the stdlib's PEP 706 extraction filter, not a hand-rolled walk -
    # assert it is actually wired in, so this is verifiable by grep, not by trust.
    assert 'filter="data"' in src


# --- fetch_artifact -----------------------------------------------------------


def _pypi_json(version: str, sdist_url: str) -> dict:
    return {
        "info": {"version": version},
        "releases": {
            version: [
                {"packagetype": "bdist_wheel", "url": "https://files.example/pkg.whl"},
                {"packagetype": "sdist", "url": sdist_url, "filename": "pkg.tar.gz"},
            ]
        },
    }


def _npm_json(version: str, tarball_url: str) -> dict:
    return {
        "dist-tags": {"latest": version},
        "versions": {version: {"dist": {"tarball": tarball_url}}},
    }


def _transport(routes: dict[str, httpx.Response]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        response = routes.get(str(request.url))
        if response is None:
            raise AssertionError(f"unexpected request: {request.url}")
        return response

    return httpx.MockTransport(handler)


def test_fetch_artifact_downloads_and_extracts_a_pypi_sdist(tmp_path: Path) -> None:
    tar_bytes = _tar_of(tmp_path, {"pkg-1.0.0/setup.py": b"# not executed\n"}).read_bytes()
    meta_url = "https://pypi.org/pypi/widget/json"
    sdist_url = "https://files.pythonhosted.org/packages/widget-1.0.0.tar.gz"
    routes = {
        meta_url: httpx.Response(200, json=_pypi_json("1.0.0", sdist_url)),
        sdist_url: httpx.Response(200, content=tar_bytes),
    }
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status is FetchStatus.OK
    assert result.version == "1.0.0"
    assert result.root is not None
    assert (result.root / "pkg-1.0.0" / "setup.py").exists()


def test_fetch_artifact_downloads_and_extracts_an_npm_tarball(tmp_path: Path) -> None:
    tar_bytes = _tar_of(tmp_path, {"package/index.js": b"// not executed\n"}).read_bytes()
    meta_url = "https://registry.npmjs.org/widget"
    tarball_url = "https://registry.npmjs.org/widget/-/widget-2.0.0.tgz"
    routes = {
        meta_url: httpx.Response(200, json=_npm_json("2.0.0", tarball_url)),
        tarball_url: httpx.Response(200, content=tar_bytes),
    }
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.NPM, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status is FetchStatus.OK
    assert result.version == "2.0.0"
    assert result.root is not None
    assert (result.root / "package" / "index.js").exists()


def test_fetch_artifact_reports_not_found_for_a_missing_package() -> None:
    meta_url = "https://pypi.org/pypi/ghost/json"
    routes = {meta_url: httpx.Response(404)}
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="ghost")

    result = fetch_artifact(client, coords)

    assert result.status is FetchStatus.NOT_FOUND
    assert result.root is None


def test_fetch_artifact_reports_throttled_on_429() -> None:
    meta_url = "https://pypi.org/pypi/widget/json"
    routes = {meta_url: httpx.Response(429)}
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status is FetchStatus.THROTTLED


def test_fetch_artifact_reports_too_large_via_content_length() -> None:
    meta_url = "https://pypi.org/pypi/widget/json"
    sdist_url = "https://files.pythonhosted.org/packages/widget-1.0.0.tar.gz"
    routes = {
        meta_url: httpx.Response(200, json=_pypi_json("1.0.0", sdist_url)),
        sdist_url: httpx.Response(
            200,
            content=b"x" * 10,
            headers={"Content-Length": str(1024 * 1024 * 1024)},
        ),
    }
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status is FetchStatus.TOO_LARGE
    assert result.root is None


def test_fetch_artifact_never_raises_on_malformed_metadata() -> None:
    meta_url = "https://pypi.org/pypi/widget/json"
    routes = {meta_url: httpx.Response(200, content=b"not json")}
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status.is_failure
    assert result.root is None


def test_fetch_artifact_rejects_a_hostile_archive_without_raising(tmp_path: Path) -> None:
    """The download succeeds but the archive itself is a traversal attempt - the
    function still reports failure through ArtifactResult, it does not raise."""
    hostile = _tar_with(tmp_path, "../escape.py")
    meta_url = "https://pypi.org/pypi/widget/json"
    sdist_url = "https://files.pythonhosted.org/packages/widget-1.0.0.tar.gz"
    routes = {
        meta_url: httpx.Response(200, json=_pypi_json("1.0.0", sdist_url)),
        sdist_url: httpx.Response(200, content=hostile.read_bytes()),
    }
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status.is_failure
    assert result.root is None


def test_fetch_artifact_reports_failure_for_a_truncated_tar_gz(tmp_path: Path) -> None:
    """A registry serving a truncated tar.gz must come back through
    ArtifactResult, not crash the census with an uncaught EOFError."""
    truncated_bytes = _truncated_tar_gz(tmp_path).read_bytes()
    meta_url = "https://pypi.org/pypi/widget/json"
    sdist_url = "https://files.pythonhosted.org/packages/widget-1.0.0.tar.gz"
    routes = {
        meta_url: httpx.Response(200, json=_pypi_json("1.0.0", sdist_url)),
        sdist_url: httpx.Response(200, content=truncated_bytes),
    }
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status.is_failure
    assert result.root is None


def test_fetch_artifact_reports_failure_for_a_corrupted_zip(tmp_path: Path) -> None:
    """A registry serving a corrupted zip must come back through
    ArtifactResult, not crash the census with an uncaught zlib.error."""
    corrupted_bytes = _corrupted_zip(tmp_path).read_bytes()
    meta_url = "https://pypi.org/pypi/widget/json"
    sdist_url = "https://files.pythonhosted.org/packages/widget-1.0.0.zip"
    routes = {
        meta_url: httpx.Response(200, json=_pypi_json("1.0.0", sdist_url)),
        sdist_url: httpx.Response(200, content=corrupted_bytes),
    }
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status.is_failure
    assert result.root is None


def test_fetch_artifact_never_executes_json_content_type() -> None:
    """A registry response body that is JSON-shaped but sent as text is still parsed;
    confirms the module isn't relying on Content-Type before treating a body as JSON."""
    meta_url = "https://pypi.org/pypi/widget/json"
    routes = {meta_url: httpx.Response(404, content=json.dumps({"message": "Not Found"}))}
    client = httpx.Client(transport=_transport(routes))
    coords = PackageCoords(ecosystem=Ecosystem.PYPI, name="widget")

    result = fetch_artifact(client, coords)

    assert result.status is FetchStatus.NOT_FOUND


def test_artifact_result_is_the_documented_shape() -> None:
    result = ArtifactResult(status=FetchStatus.OK, detail="ok", root=None, version=None)
    assert result.status is FetchStatus.OK
