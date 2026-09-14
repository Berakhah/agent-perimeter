import io
import json
import shutil
import tarfile
from pathlib import Path

import httpx
import pytest

from agent_perimeter._contracts import Derivation
from agent_perimeter.census import detect
from agent_perimeter.census.artifacts import fetch_artifact
from agent_perimeter.census.detect import (
    ARTIFACT_CONFIDENCE,
    detect_features,
    detect_sdk_pin,
)
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords
from agent_perimeter.model.feature import Feature
from agent_perimeter.transport.revision import LIVE_PROBE_CONFIDENCE

FIXTURES = Path("tests/fixtures/artifacts")


def test_artifact_confidence_is_strictly_below_a_live_probe() -> None:
    """An artifact says what a package could do, not what a deployment does."""
    assert ARTIFACT_CONFIDENCE < LIVE_PROBE_CONFIDENCE


def test_a_modern_sdk_pin_is_read_from_pyproject() -> None:
    assert detect_sdk_pin(FIXTURES / "py_new") == "2.1.0"


def test_an_old_sdk_pin_bounds_the_feature_set_regardless_of_source() -> None:
    """Source mentioning server/discover cannot raise a package pinned below it."""
    fp = detect_features(FIXTURES / "py_old")
    assert Feature.SERVER_DISCOVER not in fp.features
    assert "sdk pin" in (fp.claim.caveat or "")


def test_every_artifact_derived_claim_is_marked_as_such() -> None:
    fp = detect_features(FIXTURES / "py_new")
    assert fp.claim.derivation is Derivation.ARTIFACT
    assert fp.claim.confidence == ARTIFACT_CONFIDENCE


def test_unresolvable_coordinates_yield_unknown_not_absent() -> None:
    """No SDK pin and no parseable source is UNKNOWN, never 'does not support'."""
    fp = detect_features(FIXTURES / "empty")
    assert fp.is_unknown
    assert fp.features == frozenset()
    assert fp.claim.caveat


def test_the_features_type_matches_the_live_path() -> None:
    """Same type as transport.revision.Fingerprint.features, so they compare directly."""
    fp = detect_features(FIXTURES / "py_new")
    assert isinstance(fp.features, frozenset)


def test_detection_never_imports_the_artifact() -> None:
    src = Path("agent_perimeter/census/detect.py").read_text()
    for forbidden in ("importlib", "exec(", "eval(", "subprocess", "__import__"):
        assert forbidden not in src


# --- Beyond the brief's 7: exercise both branches of the disagreement rule and
# the JS token-scan path, so py_new/js_new are not fixtures nothing runs against.


def test_a_modern_sdk_pin_does_not_drop_the_features_it_supports() -> None:
    """The mirror of the py_old case: source evidence that the pin *does* clear
    is kept, not just dropped evidence being the only thing under test."""
    fp = detect_features(FIXTURES / "py_new")
    assert Feature.SERVER_DISCOVER in fp.features
    assert Feature.RESULT_TYPE in fp.features
    assert "sdk pin" not in (fp.claim.caveat or "")


def test_a_javascript_artifact_is_detected_via_token_scan() -> None:
    """Detection is by ast parse for Python and a token scan for JavaScript -
    this exercises the JS half, which none of the brief's 7 tests touch."""
    fp = detect_features(FIXTURES / "js_new")
    assert fp.sdk_version == "2.1.0"
    assert Feature.RESULT_TYPE in fp.features
    assert Feature.CACHEABLE_RESULT in fp.features


def test_a_v2_split_package_pin_is_recognised_not_just_the_v1_monolith() -> None:
    """@modelcontextprotocol/sdk (v1) never shipped a 2.x release - it is
    frozen at 1.30.0. v2 split the SDK into @modelcontextprotocol/server et
    al, which is what a real server artifact pins. A package.json naming
    only the new package must still be read as a valid, above-floor pin."""
    assert detect_sdk_pin(FIXTURES / "js_v2_split") == "2.1.0"
    fp = detect_features(FIXTURES / "js_v2_split")
    assert fp.sdk_version == "2.1.0"
    assert Feature.RESULT_TYPE in fp.features
    assert Feature.CACHEABLE_RESULT in fp.features
    assert "sdk pin" not in (fp.claim.caveat or "")


# --- Task 8: real npm/PyPI artifacts keep manifests one directory down, not
# at the extraction root; the first full census run misclassified 94% of
# artifacts "unknown" because of this.


def test_npm_pin_is_found_under_the_package_directory(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "^1.12.0"}}), encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "1.12.0"


def test_pypi_pin_is_found_in_a_versioned_sdist_directory(tmp_path: Path) -> None:
    d = tmp_path / "mcp_server_x-2026.8.18"
    d.mkdir()
    (d / "pyproject.toml").write_text(
        '[project]\ndependencies = ["mcp>=1.2.0"]\n', encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "1.2.0"


def test_pypi_pin_is_read_from_sdist_pkg_info(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text(
        "Name: x\nRequires-Dist: httpx\nRequires-Dist: mcp>=2.1\n", encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "2.1"


def test_pypi_pin_is_read_from_wheel_metadata(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0.dist-info"
    d.mkdir()
    (d / "METADATA").write_text(
        'Name: x\nRequires-Dist: mcp>=2.0.0; python_version >= "3.10"\n', encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "2.0.0"


def test_environment_marker_version_is_not_mistaken_for_the_pin(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text('Requires-Dist: mcp; python_version >= "3.10"\n', encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) is None


def test_manifest_search_is_one_level_deep_only(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}), encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) is None


def test_ecosystem_is_detected_under_the_package_directory(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "package.json").write_text("{}", encoding="utf-8")
    assert detect._ecosystem_of(tmp_path) is Ecosystem.NPM


# --- Final review: the pin is the lowest lower bound, never a cap. `packaging`
# normalises specifier sets so `>=1.9.0,<2.0.0` serialises as `<2.0.0,>=1.9.0`,
# and setuptools writes Requires-Dist that way; the first version-looking
# token is then the cap, which is how run #2 recorded a "3.x" Python SDK pin
# that has never been released.


@pytest.mark.parametrize(
    ("requirement", "expected"),
    [
        ("mcp<2.0.0,>=1.9.0", "1.9.0"),
        ("mcp (>=1.2.0,<2.0.0)", "1.2.0"),
        ('mcp[cli]>=1.2; python_version >= "3.10"', "1.2"),
        ("mcp<3", None),
        ("mcp~=1.4", "1.4"),
        ("mcp==2.0.1", "2.0.1"),
        ("MCP >= 1.0", "1.0"),
        ("mcp>=1.9.0,>=1.2.0", "1.2.0"),
        ("httpx>=1.0", None),
        ("mcp >= not-a-version", None),
    ],
)
def test_python_requirement_pin_is_the_lowest_lower_bound(
    requirement: str, expected: str | None
) -> None:
    assert detect._pin_from_requirement(requirement, detect._PY_SDK_NAMES) == expected


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        (">=1.0.0 <2.0.0", "1.0.0"),
        ("^1.12.0", "1.12.0"),
        ("~2.0.0", "2.0.0"),
        ("1.30.0", "1.30.0"),
        ("<2.0.0", None),
        ("<=2.0.0", None),
        (">=2.1.0 <3.0.0 || >=1.0.0 <2.0.0", "1.0.0"),
    ],
)
def test_npm_range_pin_is_the_lowest_lower_bound(
    tmp_path: Path, spec: str, expected: str | None
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": spec}}), encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == expected


def test_a_normalised_pkg_info_requires_dist_records_the_floor_not_the_cap(
    tmp_path: Path,
) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text("Name: x\nRequires-Dist: mcp<2.0.0,>=1.9.0\n", encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) == "1.9.0"


# --- Final review: the two-signals rule is literal. A handler string in
# source without an SDK pin cannot be "supports" - the report says a pin at
# or above the floor AND the handler string are both required.


def test_source_signal_without_any_sdk_pin_is_unknown_not_supports(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text('HANDLERS = {"server/discover": None}\n', encoding="utf-8")
    fp = detect_features(tmp_path)
    assert fp.sdk_version is None
    assert Feature.SERVER_DISCOVER not in fp.features
    assert fp.is_unknown
    assert "server_discover" in (fp.claim.caveat or "")
    assert "pins no SDK" in (fp.claim.caveat or "")


def test_an_unpinned_artifact_is_unknown_even_with_a_floorless_signal(tmp_path: Path) -> None:
    """Re-review residual 1: an unpinned artifact is unknown, full stop. Keeping
    the floorless PARAM_HEADERS made is_unknown False and the report bucketed
    the row as does_not_support, contradicting its own "unknown" definition."""
    (tmp_path / "server.py").write_text(
        'SCHEMA = {"x-mcp-header": True, "server/discover": 1}\n', encoding="utf-8"
    )
    fp = detect_features(tmp_path)
    assert fp.features == frozenset()
    assert fp.is_unknown
    caveat = fp.claim.caveat or ""
    assert "pins no SDK" in caveat
    assert "server_discover" in caveat and "param_headers" in caveat


def test_a_wildcard_equality_pin_parses_to_its_prefix(tmp_path: Path) -> None:
    """Re-review residual 2: `mcp==2.0.*` has specifier version `2.0.*`,
    which Version() rejects; the pin is the prefix, not None."""
    assert detect._pin_from_requirement("mcp==2.0.*", detect._PY_SDK_NAMES) == "2.0"
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text("Requires-Dist: mcp==2.0.*\n", encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) == "2.0"


def test_requirements_txt_inline_comments_are_stripped(tmp_path: Path) -> None:
    """Re-review residual 3: pip strips `\\s+#.*$` from a requirements line;
    `Requirement()` alone does not, and would reject the line."""
    (tmp_path / "requirements.txt").write_text(
        "httpx  # http client\nmcp>=1.0  # why this floor\n", encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "1.0"


# --- Final review: fetch -> detect end to end, through the real manifest
# layouts (npm `package/`, PyPI `<name>-<version>/`). Run #1 misclassified
# 94% of artifacts because no test crossed this seam.


def _tar_bytes(tmp_path: Path, files: dict[str, bytes]) -> bytes:
    path = tmp_path / "archive.tar.gz"
    with tarfile.open(path, mode="w:gz") as tf:
        for member_name, data in files.items():
            info = tarfile.TarInfo(member_name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path.read_bytes()


def _routed_client(routes: dict[str, httpx.Response]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        response = routes.get(str(request.url))
        if response is None:
            raise AssertionError(f"unexpected request: {request.url}")
        return response

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetched_npm_tarball_yields_the_pin_under_package_dir(tmp_path: Path) -> None:
    manifest = json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "^1.12.0"}}).encode()
    tar = _tar_bytes(tmp_path, {"package/package.json": manifest, "package/index.js": b"//\n"})
    meta_url = "https://registry.npmjs.org/widget"
    tarball_url = "https://registry.npmjs.org/widget/-/widget-2.0.0.tgz"
    client = _routed_client(
        {
            meta_url: httpx.Response(
                200,
                json={
                    "dist-tags": {"latest": "2.0.0"},
                    "versions": {"2.0.0": {"dist": {"tarball": tarball_url}}},
                },
            ),
            tarball_url: httpx.Response(200, content=tar),
        }
    )
    result = fetch_artifact(client, PackageCoords(ecosystem=Ecosystem.NPM, name="widget"))
    assert result.status is FetchStatus.OK
    assert result.root is not None
    try:
        assert detect_features(result.root).sdk_version == "1.12.0"
    finally:
        shutil.rmtree(result.root, ignore_errors=True)


def test_fetched_pypi_sdist_yields_the_lower_bound_from_pkg_info(tmp_path: Path) -> None:
    pkg_info = b"Name: x\nVersion: 1.0\nRequires-Dist: mcp<2.0.0,>=1.9.0\n"
    tar = _tar_bytes(tmp_path, {"x-1.0/PKG-INFO": pkg_info, "x-1.0/x.py": b"# not run\n"})
    meta_url = "https://pypi.org/pypi/x/json"
    sdist_url = "https://files.pythonhosted.org/packages/x-1.0.tar.gz"
    client = _routed_client(
        {
            meta_url: httpx.Response(
                200,
                json={
                    "info": {"version": "1.0"},
                    "releases": {
                        "1.0": [{"packagetype": "sdist", "url": sdist_url, "filename": "x.tar.gz"}]
                    },
                },
            ),
            sdist_url: httpx.Response(200, content=tar),
        }
    )
    result = fetch_artifact(client, PackageCoords(ecosystem=Ecosystem.PYPI, name="x"))
    assert result.status is FetchStatus.OK
    assert result.root is not None
    try:
        assert detect_features(result.root).sdk_version == "1.9.0"
    finally:
        shutil.rmtree(result.root, ignore_errors=True)
