import hashlib
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, SecretFingerprint, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.secrets import config_scan, env_scan
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint

# Synthetic, structurally valid, never issued. gitleaks-safe: not a real prefix.
FAKE_KEY = "sk-test-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"


class NullTransport:
    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(raw: dict[str, dict[str, object]]) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test/rpc",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-21 brief): Feature.STATELESS_META does not exist —
            # a version-implies-feature proxy this design deliberately avoids
            # (see agent_perimeter/model/feature.py). No feature is needed for
            # these tests, so the fixture asserts none.
            features=frozenset(),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw=raw,
    )


def test_fingerprint_records_hash_not_value() -> None:
    fp = SecretFingerprint.of(FAKE_KEY, location=".mcp.json:env.API_KEY")
    assert fp.sha256 == hashlib.sha256(FAKE_KEY.encode()).hexdigest()
    assert fp.last4 == FAKE_KEY[-4:]
    assert fp.entropy > 3.0


def test_fingerprint_object_does_not_retain_the_value() -> None:
    # Revision 2.7: the class uses __slots__, so `fp.__dict__` raises
    # AttributeError and the old version of this test never actually ran.
    # Introspect the slots directly instead.
    fp = SecretFingerprint.of(FAKE_KEY, location="x")
    assert not hasattr(fp, "__dict__")
    rendered = repr(fp) + "".join(str(getattr(fp, slot)) for slot in fp.__slots__)
    assert FAKE_KEY not in rendered
    assert FAKE_KEY[8:] not in rendered


def test_config_secret_is_reported_without_the_value() -> None:
    context = _context({"_config": {"env": {"API_KEY": FAKE_KEY}}})
    findings = config_scan.CHECK.run(context)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-798"
    assert findings[0].severity is Severity.CRITICAL
    assert FAKE_KEY not in findings[0].evidence.excerpt
    assert findings[0].evidence.redacted is True
    # Revision 5.5: only the HMAC'd, truncated form leaves the process.
    assert fp_sha256_not_exposed_raw(findings[0].evidence.excerpt)


def test_low_entropy_placeholder_is_not_reported() -> None:
    context = _context({"_config": {"env": {"API_KEY": "changeme"}}})
    assert config_scan.CHECK.run(context) == []


def test_placeholder_shaped_values_are_not_reported() -> None:
    # revision 5.5: entropy >= 3.0 and length >= 16 alone fires on file
    # paths, URLs, UUIDs and placeholders — the dominant content of public
    # .mcp.json files.
    for placeholder in (
        "your-api-key-here-replace-me",
        "00000000-0000-0000-0000-000000000000",
        "/home/user/.config/app/data",
        "https://example.test/callback",
    ):
        context = _context({"_config": {"env": {"API_KEY": placeholder}}})
        assert config_scan.CHECK.run(context) == [], placeholder


def test_a_known_prefix_is_reported_even_at_borderline_entropy() -> None:
    # SECRET_PATTERNS (declared in this task's interfaces from the start,
    # never implemented until now) raises precision far more than entropy.
    for value in ("sk-live-aaaaaaaaaaaaaaaaaaaaaaaa", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "AKIAAAAAAAAAAAAAAAAA", "xoxb-NOTAREAL-FIXTURETOKEN-000"):
        context = _context({"_config": {"env": {"TOKEN": value}}})
        assert len(config_scan.CHECK.run(context)) == 1, value


def test_env_secret_is_reported() -> None:
    context = _context({"_env": {"MCP_TOKEN": FAKE_KEY}})
    assert len(env_scan.CHECK.run(context)) == 1


def test_no_config_present_yields_nothing() -> None:
    assert config_scan.CHECK.run(_context({})) == []
    assert env_scan.CHECK.run(_context({})) == []


def fp_sha256_not_exposed_raw(excerpt: str) -> bool:
    """The raw hex digest of FAKE_KEY must never appear verbatim in output —
    only the HMAC'd, 16-char-truncated export form."""
    return hashlib.sha256(FAKE_KEY.encode()).hexdigest() not in excerpt
