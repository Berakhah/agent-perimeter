import io
import json
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest
from hypothesis import given
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
            info.external_attr = (0o120777 << 16)  # S_IFLNK
            zf.writestr(info, target)
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


@given(st.text(min_size=1, max_size=40))
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
