from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.all_checks import ALL_CHECKS, CheckOutcome, run_checks
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.taxonomy import has_approved_citation, resolve, resolve_cwe
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.model.finding import Finding
from agent_perimeter.transport.revision import Fingerprint


def test_every_check_has_a_unique_id() -> None:
    ids = [c.id for c in ALL_CHECKS]
    assert len(ids) == len(set(ids))


def test_twenty_five_checks_are_registered() -> None:
    assert len(ALL_CHECKS) == 25


def test_every_check_cites_a_resolvable_taxonomy_entry() -> None:
    for check in ALL_CHECKS:
        assert check.taxonomy_refs, f"{check.id} cites nothing"
        for ref in check.taxonomy_refs:
            resolve(ref)


def test_every_check_cites_at_least_one_approved_scheme() -> None:
    """DoD 2: mcp-spec and rfc alone do not satisfy the citation gate."""
    for check in ALL_CHECKS:
        assert has_approved_citation(check.taxonomy_refs), (
            f"{check.id} cites only {check.taxonomy_refs}, no approved scheme"
        )


def test_every_check_declares_a_well_formed_cwe() -> None:
    for check in ALL_CHECKS:
        assert check.cwe.startswith("CWE-"), check.id


def test_every_check_s_cwe_is_registered() -> None:
    for check in ALL_CHECKS:
        resolve_cwe(check.cwe)


def test_exactly_one_check_requires_a_model() -> None:
    model_checks = [c.id for c in ALL_CHECKS if c.requires_model]
    assert model_checks == ["descriptions.llm_judge"]


def test_only_expected_checks_require_authorisation() -> None:
    auth_checks = sorted(c.id for c in ALL_CHECKS if c.requires_auth)
    assert auth_checks == ["revision.header_body_mismatch"]


class _RaisingCheck:
    id: str = "test.raises"
    cwe: str = "CWE-664"
    taxonomy_refs: tuple[str, ...] = ("mcp-spec:2026-07-28-changelog",)
    severity: Severity = Severity.INFO
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = frozenset()

    def run(self, context: ScanContext) -> list[Finding]:
        raise RecursionError("simulated schema-depth blowup")


def _minimal_context() -> ScanContext:
    class _NullTransport:
        def request(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            return {}

        def close(self) -> None: ...

    return ScanContext(
        target="https://mcp.example.test",
        transport=_NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset({Feature.CACHEABLE_RESULT}),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
    )


def test_a_raising_check_does_not_abort_the_others() -> None:
    from agent_perimeter.checks.revision import cache_scope

    findings, errored = run_checks([_RaisingCheck(), cache_scope.CHECK], _minimal_context())
    assert findings == []  # cache_scope legitimately finds nothing here, but it *ran*
    assert len(errored) == 1
    assert errored[0].check_id == "test.raises"
    assert isinstance(errored[0], CheckOutcome)
