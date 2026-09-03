from datetime import date

import pytest

from agent_perimeter.model.scope import (
    AuthorizationRequired,
    ScopeFile,
    require_scope,
)

TODAY = date(2026, 9, 1)
TARGET = "https://mcp.example.test"


def _scope(**overrides: object) -> ScopeFile:
    base: dict[str, object] = {
        "target": TARGET,
        "authorising_party": "Example Ltd, Head of Security",
        "authorised_on": date(2026, 8, 30),
        "attestation": "I authorise active security probing of the named target.",
        "expires_on": date(2026, 9, 30),
    }
    base.update(overrides)
    return ScopeFile(**base)  # type: ignore[arg-type]


def test_missing_scope_refuses() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(None, check_id="active.ssrf", target=TARGET, today=TODAY)
    assert "active.ssrf" in str(exc.value)
    assert "scope file" in str(exc.value)


def test_expired_scope_refuses_and_names_the_field() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(expires_on=date(2026, 8, 31)),
            check_id="active.ssrf",
            target=TARGET,
            today=TODAY,
        )
    assert "expires_on" in str(exc.value)


def test_target_mismatch_refuses() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(), check_id="active.ssrf", target="https://other.example.test", today=TODAY
        )
    assert "target" in str(exc.value)


def test_valid_scope_permits() -> None:
    require_scope(_scope(), check_id="active.ssrf", target=TARGET, today=TODAY)


def test_blank_attestation_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="attestation"):
        _scope(attestation="   ")


def test_not_yet_authorised_scope_refuses_and_names_the_field() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(authorised_on=date(2026, 9, 2)),
            check_id="active.ssrf",
            target=TARGET,
            today=TODAY,
        )
    assert "authorised_on" in str(exc.value)


def test_scope_authorised_today_permits() -> None:
    require_scope(_scope(authorised_on=TODAY), check_id="active.ssrf", target=TARGET, today=TODAY)


def test_inverted_date_range_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="expires_on"):
        _scope(authorised_on=date(2026, 9, 10), expires_on=date(2026, 9, 1))


def test_missing_field_is_set_on_every_raise_path() -> None:
    """An unstructured error is the kind of thing that quietly becomes
    structured-ish later -- assert `missing_field` is set, and set to the
    right name, on all four of require_scope's raise sites."""
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(None, check_id="active.ssrf", target=TARGET, today=TODAY)
    assert exc.value.missing_field == "scope_file"

    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(), check_id="active.ssrf", target="https://other.example.test", today=TODAY
        )
    assert exc.value.missing_field == "target"

    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(authorised_on=date(2026, 9, 2)),
            check_id="active.ssrf",
            target=TARGET,
            today=TODAY,
        )
    assert exc.value.missing_field == "authorised_on"

    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(expires_on=date(2026, 8, 31)),
            check_id="active.ssrf",
            target=TARGET,
            today=TODAY,
        )
    assert exc.value.missing_field == "expires_on"
