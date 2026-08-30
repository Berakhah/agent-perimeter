# tests/report/test_sarif.py
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding
from agent_perimeter.report.sarif import partial_fingerprint, to_sarif
from agent_perimeter.transport.revision import Fingerprint

SCHEMA = json.loads((Path(__file__).parents[1] / "fixtures" / "sarif-2.1.0.json").read_text())
TARGET = "https://mcp.example.test/rpc"

FINGERPRINT = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset({Feature.SERVER_DISCOVER}),
    claim=Claim(
        value="2026-07-28",
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=datetime(2026, 9, 1, tzinfo=UTC),
    ),
)


def _finding(check_id: str = "revision.cache_scope") -> Finding:
    return Finding(
        check_id=check_id,
        severity=Severity.MEDIUM,
        title="Tool listing is marked publicly cacheable",
        cwe="CWE-524",
        taxonomy_refs=("owasp-llm:LLM02",),
        evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt='"cacheScope": "public"'),
        reproduction=f"agent-perimeter scan --target {TARGET} --only {check_id}",
        claim=Claim(
            value="public",
            method=Method.DETERMINISTIC,
            derivation=Derivation.SCHEMA,
            observed_at=datetime(2026, 9, 1, tzinfo=UTC),
        ),
    )


def _config_finding() -> Finding:
    """A finding that already carries a genuine FindingLocation — the
    secrets/* shape, anchored to a real file and line, no invention needed."""
    from agent_perimeter.model.finding import FindingLocation

    return Finding(
        check_id="secrets.config_scan",
        severity=Severity.CRITICAL,
        title="Credential-shaped value at .mcp.json:env.API_KEY",
        cwe="CWE-798",
        taxonomy_refs=("owasp-mcp:MCP01",),
        evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt="fingerprint: abcd1234abcd1234"),
        reproduction=f"agent-perimeter scan --target {TARGET} --only secrets.config_scan",
        claim=Claim(
            value="abcd1234abcd1234",
            method=Method.DETERMINISTIC,
            derivation=Derivation.ARTIFACT,
            observed_at=datetime(2026, 9, 1, tzinfo=UTC),
        ),
        location=FindingLocation(uri=".mcp.json", line=12),
    )


def _sarif(*findings: Finding, workspace: Path) -> dict[str, object]:
    return to_sarif(
        list(findings),
        target=TARGET,
        tool_version="0.1.0",
        fingerprint=FINGERPRINT,
        workspace=workspace,
    )


def test_output_validates_against_the_2_1_0_schema(tmp_path: Path) -> None:
    jsonschema.validate(_sarif(_finding(), workspace=tmp_path), SCHEMA)


def test_empty_findings_still_validates(tmp_path: Path) -> None:
    jsonschema.validate(_sarif(workspace=tmp_path), SCHEMA)


def test_result_carries_both_a_physical_and_a_logical_location(tmp_path: Path) -> None:
    result = _sarif(_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    location = result["locations"][0]
    assert "physicalLocation" in location
    assert "logicalLocations" in location
    physical = location["physicalLocation"]
    assert physical["artifactLocation"]["uri"]
    region = physical["region"]
    assert {"startLine", "startColumn", "endLine", "endColumn"} <= region.keys()
    assert location["logicalLocations"][0]["fullyQualifiedName"].startswith(TARGET)


def test_config_derived_finding_is_anchored_to_its_real_file(tmp_path: Path) -> None:
    result = _sarif(_config_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == ".mcp.json"
    assert physical["region"]["startLine"] == 12


def test_runtime_finding_is_anchored_to_a_scan_profile_that_exists_on_disk(tmp_path: Path) -> None:
    result = _sarif(_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert (tmp_path / uri).exists()
    assert uri.endswith(".mcp-profile.json")
    assert uri.startswith(".agent-perimeter/")


def test_partial_fingerprint_is_stable_across_runs() -> None:
    assert partial_fingerprint(_finding(), TARGET) == partial_fingerprint(_finding(), TARGET)


def test_partial_fingerprint_differs_between_checks() -> None:
    a = partial_fingerprint(_finding("revision.cache_scope"), TARGET)
    b = partial_fingerprint(_finding("static.cleartext_target"), TARGET)
    assert a != b


def test_severity_maps_to_sarif_level(tmp_path: Path) -> None:
    result = _sarif(_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    assert result["level"] == "warning"


def test_security_severity_property_is_numeric_and_ranks_critical_above_high(
    tmp_path: Path,
) -> None:
    medium = _sarif(_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    critical_finding = _finding().model_copy(update={"severity": Severity.CRITICAL})
    critical = _sarif(critical_finding, workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    assert isinstance(medium["properties"]["security-severity"], float)
    assert 0.0 <= medium["properties"]["security-severity"] <= 10.0
    assert critical["properties"]["security-severity"] > medium["properties"]["security-severity"]


def test_primary_location_line_hash_present_alongside_agent_perimeter_fingerprint(
    tmp_path: Path,
) -> None:
    result = _sarif(_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    fingerprints = result["partialFingerprints"]
    assert "primaryLocationLineHash" in fingerprints
    assert "agentPerimeter/v1" in fingerprints


def test_schema_uri_matches_the_document_validated_in_ci() -> None:
    from agent_perimeter.report.sarif import SCHEMA_URI

    assert SCHEMA_URI == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
        "sarif-2.1/schema/sarif-schema-2.1.0.json"
    )


def test_rule_carries_cwe_taxonomy_and_a_help_uri(tmp_path: Path) -> None:
    rules = _sarif(_finding(), workspace=tmp_path)["runs"][0]["tool"]["driver"]["rules"]  # type: ignore[index]
    rule = rules[0]
    assert rule["properties"]["cwe"] == "CWE-524"
    assert "owasp-llm:LLM02" in rule["properties"]["taxonomy_refs"]
    assert rule["helpUri"].startswith("https://")


def test_reproduction_reaches_the_result_message(tmp_path: Path) -> None:
    result = _sarif(_finding(), workspace=tmp_path)["runs"][0]["results"][0]  # type: ignore[index]
    assert "agent-perimeter scan" in result["message"]["text"]


def test_matches_the_committed_golden_file(tmp_path: Path) -> None:
    golden = Path(__file__).parent / "golden" / "basic_scan.sarif.json"
    rendered = _sarif(_finding(), workspace=tmp_path)
    if not golden.exists():
        golden.write_text(json.dumps(rendered, indent=2, sort_keys=True))
        pytest.skip("golden file created; re-run to compare")
    # The scan-profile path is workspace-relative and differs per test run's
    # tmp_path, so it is normalised out before comparing to the golden file.
    golden_doc = json.loads(golden.read_text())
    _normalise_profile_uri(golden_doc)
    _normalise_profile_uri(rendered)
    assert golden_doc == json.loads(json.dumps(rendered, sort_keys=True))


def _normalise_profile_uri(document: dict[str, object]) -> None:
    for result in document["runs"][0]["results"]:  # type: ignore[index]
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        if location["uri"].endswith(".mcp-profile.json"):
            location["uri"] = "<scan-profile>"
            # primaryLocationLineHash is derived from that same workspace-
            # relative uri (see primary_location_line_hash), so it is just as
            # tmp_path-dependent and must be normalised alongside it.
            result["partialFingerprints"]["primaryLocationLineHash"] = "<scan-profile-line-hash>"


# --- Config-derived locations come from a real OS path, not an idealised one --
#
# `_config_finding()` above hand-builds `FindingLocation(uri=".mcp.json")`,
# which nothing actually produces: `secrets/config_scan._locate()` sets the
# uri from the operator's own `--config` argument, i.e. an absolute OS path
# with backslashes on Windows. SARIF 2.1.0 section 3.4.3 wants a valid URI
# reference, and GitHub cannot map an absolute host path back to a file in the
# scanned repo. These two tests drive the real check so the emitter is fed the
# location it will actually see in production.

_SARIF_TEST_HMAC_KEY = b"test-key-0123456789abcdef01234567"
_SARIF_FAKE_KEY = "sk-test-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"


def _real_config_finding(config_path: Path) -> Finding:
    from agent_perimeter.checks.context import ScanContext
    from agent_perimeter.checks.secrets.config_scan import ConfigScanCheck

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        '{\n  "env": {\n    "API_KEY": "' + _SARIF_FAKE_KEY + '"\n  }\n}\n', encoding="utf-8"
    )

    class _NullTransport:
        def request(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            return {}

        def close(self) -> None: ...

    context = ScanContext(
        target=TARGET,
        transport=_NullTransport(),
        fingerprint=FINGERPRINT,
        raw={
            "_config": {"env": {"API_KEY": _SARIF_FAKE_KEY}},
            "_config_path": {"path": str(config_path)},
        },
    )
    findings = ConfigScanCheck(hmac_key=_SARIF_TEST_HMAC_KEY).run(context)
    assert len(findings) == 1
    assert findings[0].location is not None, "the check must anchor to the real file"
    return findings[0]


def test_config_inside_the_workspace_gets_a_workspace_relative_posix_uri(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "repo"
    finding = _real_config_finding(workspace / "conf" / ".mcp.json")
    result = _sarif(finding, workspace=workspace)["runs"][0]["results"][0]  # type: ignore[index]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "conf/.mcp.json"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_config_outside_the_workspace_falls_back_to_the_scan_profile_anchor(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    finding = _real_config_finding(tmp_path / "elsewhere" / ".mcp.json")
    result = _sarif(finding, workspace=workspace)["runs"][0]["results"][0]  # type: ignore[index]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith(".agent-perimeter/")
    assert (workspace / uri).exists(), "the anchor must be a file that really exists"


def test_no_emitted_uri_is_an_absolute_os_path(tmp_path: Path) -> None:
    """SARIF 2.1.0 section 3.4.3: a URI reference, never a host path."""
    workspace = tmp_path / "repo"
    workspace.mkdir()
    document = _sarif(
        _finding(),
        _real_config_finding(workspace / ".mcp.json"),
        _real_config_finding(tmp_path / "outside" / ".mcp.json"),
        workspace=workspace,
    )
    jsonschema.validate(document, SCHEMA)
    for result in document["runs"][0]["results"]:  # type: ignore[index]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri, uri
        assert not Path(uri).is_absolute(), uri
