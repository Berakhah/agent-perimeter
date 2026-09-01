# agent_perimeter/report/sarif.py
"""SARIF 2.1.0 emission for runtime findings.

Revision 2026-08-29 section 1.1: GitHub code scanning requires physicalLocation
(artifactLocation.uri + a four-field region) and does not document
logicalLocations as a supported property at all. Every result here carries
both. Config-derived findings (Finding.location, set by secrets/* checks that
trace to a real file) anchor to that real file and line, normalised to a
workspace-relative POSIX path by `_workspace_relative`. Runtime findings, and
config findings whose file lies outside the workspace (which `--config`
routinely does), anchor to a scan-profile artifact this emitter writes into
the workspace: one JSON line per finding, so the SARIF's location is a real
file containing the exact bytes the finding is about, the way container and
DAST scanners do it. logicalLocations are still emitted alongside for
consumers that use them.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.taxonomy import TAXONOMY
from agent_perimeter.model.finding import Finding
from agent_perimeter.transport.revision import Fingerprint

# Confirmed live 29 August 2026 (revision verification log, section 0) — the
# document actually validated against in CI (Step 1's curl fetch), not a
# different schema-store mirror.
SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub reads this numeric property for its own severity ranking; `level`
# alone collapses CRITICAL and HIGH into one "error" bucket.
SEVERITY_TO_SECURITY_SEVERITY: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.5,
}


def partial_fingerprint(finding: Finding, target: str) -> str:
    """Stable across scans, so a re-scan does not look like a wall of new alerts."""
    material = f"{finding.check_id}|{target}|{finding.claim.value}"
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def primary_location_line_hash(uri: str, line: int) -> str:
    """The only partialFingerprints component GitHub actually reads."""
    return hashlib.sha256(f"{uri}:{line}".encode()).hexdigest()[:16]


def _slugify(target: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", target).strip("-").lower()
    return slug or "target"


def scan_profile_path(target: str, workspace: Path) -> Path:
    return workspace / ".agent-perimeter" / f"{_slugify(target)}.mcp-profile.json"


def _write_scan_profile(findings: list[Finding], *, target: str, workspace: Path) -> Path:
    """One JSON line per finding that has no anchorable location of its own —
    the exact bytes each one cites, so the physicalLocation this emitter
    anchors it to is a real file this tool produced, not an invented one."""
    path = scan_profile_path(target, workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(
            {"check_id": f.check_id, "title": f.title, "evidence": f.evidence.excerpt},
            sort_keys=True,
        )
        for f in findings
    ]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path


def _workspace_relative(uri: str, workspace: Path) -> str | None:
    """A valid, workspace-relative URI reference, or None if `uri` is not one.

    SARIF 2.1.0 section 3.4.3 requires artifactLocation.uri to be a URI
    reference — an absolute OS path (Windows backslashes included) is not
    one, and GitHub cannot map it back to a file in the scanned repo. A
    FindingLocation carries whatever path the operator supplied: `--config`
    is routinely an absolute path, and just as routinely points outside the
    repo being scanned. None means "not anchorable here" and the caller
    falls back to the scan-profile artifact, exactly like a finding with no
    location at all.
    """
    path = Path(uri)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _help_uri(finding: Finding) -> str:
    for ref in finding.taxonomy_refs:
        entry = TAXONOMY.get(ref)
        if entry is not None:
            return entry.url
    return f"https://cwe.mitre.org/data/definitions/{finding.cwe.removeprefix('CWE-')}.html"


def _rules(findings: list[Finding]) -> list[dict[str, object]]:
    rules: dict[str, dict[str, object]] = {}
    for finding in findings:
        if finding.check_id in rules:
            continue
        rules[finding.check_id] = {
            "id": finding.check_id,
            "name": finding.check_id.replace(".", "_"),
            "shortDescription": {"text": finding.title},
            "helpUri": _help_uri(finding),
            "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[finding.severity]},
            "properties": {
                "cwe": finding.cwe,
                "taxonomy_refs": list(finding.taxonomy_refs),
                "tags": ["security", finding.cwe, *finding.taxonomy_refs],
                # GitHub documents security-severity on the rule (reportingDescriptor),
                # not the result — every shipping SARIF producer (CodeQL, Semgrep,
                # Trivy, Grype) puts it here, as a string. Without it GitHub falls
                # back to `level`, collapsing CRITICAL and HIGH into one bucket.
                "security-severity": str(SEVERITY_TO_SECURITY_SEVERITY[finding.severity]),
            },
        }
    return list(rules.values())


def _physical_location(uri: str, line: int) -> dict[str, object]:
    return {
        "artifactLocation": {"uri": uri},
        "region": {"startLine": line, "startColumn": 1, "endLine": line, "endColumn": 1},
    }


def _result(finding: Finding, target: str, *, uri: str, line: int) -> dict[str, object]:
    return {
        "ruleId": finding.check_id,
        "level": SEVERITY_TO_LEVEL[finding.severity],
        "message": {
            "text": (
                f"{finding.title}\n\n"
                f"Evidence:\n{finding.evidence.excerpt}\n\n"
                f"Reproduce:\n{finding.reproduction}"
            )
        },
        "locations": [
            {
                "physicalLocation": _physical_location(uri, line),
                "logicalLocations": [
                    {
                        "name": finding.check_id,
                        "fullyQualifiedName": f"{target}/{finding.check_id}",
                        "kind": "resource",
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": primary_location_line_hash(uri, line),
            "agentPerimeter/v1": partial_fingerprint(finding, target),
        },
        "properties": {
            "cwe": finding.cwe,
            "taxonomy_refs": list(finding.taxonomy_refs),
            "derivation": finding.claim.derivation.value if finding.claim.derivation else None,
            "method": finding.claim.method.value,
            "confidence": finding.confidence,
            "redacted": finding.evidence.redacted,
            # Must be a string, matching the rule-level property above —
            # GitHub's code-scanning ingestion rejects a numeric value here
            # ("parsing restricted subset of SARIF data has failed").
            "security-severity": str(SEVERITY_TO_SECURITY_SEVERITY[finding.severity]),
        },
    }


def _results(findings: list[Finding], target: str, *, workspace: Path) -> list[dict[str, object]]:
    """Every artifactLocation.uri is normalised here, not in the checks that
    produce a FindingLocation — one layer, so every future producer inherits
    it. A location that cannot be expressed relative to the workspace is
    anchored to the scan-profile artifact instead, exactly like a finding
    that never had a location."""
    anchors = [
        (
            finding,
            _workspace_relative(finding.location.uri, workspace) if finding.location else None,
        )
        for finding in findings
    ]
    profile_path = _write_scan_profile(
        [finding for finding, uri in anchors if uri is None], target=target, workspace=workspace
    )
    # scan_profile_path() always nests under workspace, so this is always a
    # valid relative subpath.
    profile_uri = profile_path.relative_to(workspace).as_posix()

    results: list[dict[str, object]] = []
    profile_line = 0
    for finding, relative_uri in anchors:
        if relative_uri is not None and finding.location is not None:
            uri, line = relative_uri, finding.location.line
        else:
            profile_line += 1
            uri, line = profile_uri, profile_line
        results.append(_result(finding, target, uri=uri, line=line))
    return results


def to_sarif(
    findings: list[Finding],
    *,
    target: str,
    tool_version: str,
    fingerprint: Fingerprint,
    workspace: Path = Path("."),
) -> dict[str, object]:
    claimed = fingerprint.revision_claimed
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-perimeter",
                        "version": tool_version,
                        "informationUri": "https://github.com/USER/agent-perimeter",
                        "rules": _rules(findings),
                    }
                },
                "results": _results(findings, target, workspace=workspace),
                "properties": {
                    "target": target,
                    "revision_claimed": claimed.value if claimed else None,
                    "features_observed": sorted(f.value for f in fingerprint.features),
                },
            }
        ],
    }
