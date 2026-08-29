# tests/test_contracts.py
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_perimeter._contracts import Claim, Derivation, Method


def test_derived_claim_confidence_cannot_exceed_parents() -> None:
    parent = Claim(
        value=1,
        method=Method.MODEL,
        confidence=0.4,
        observed_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError, match="confidence"):
        Claim(
            value=2,
            method=Method.DERIVED,
            confidence=0.9,
            observed_at=datetime.now(UTC),
            parents=[parent],
        )


def test_caveat_propagates_from_parent() -> None:
    parent = Claim(
        value=1,
        method=Method.DETERMINISTIC,
        observed_at=datetime.now(UTC),
        caveat="sample size 51",
    )
    child = Claim(
        value=2,
        method=Method.DERIVED,
        observed_at=datetime.now(UTC),
        parents=[parent],
    )
    assert child.inherited_caveats() == ["sample size 51"]


def test_deterministic_claim_records_its_derivation() -> None:
    claim = Claim(
        value="net_out",
        method=Method.DETERMINISTIC,
        derivation=Derivation.SCHEMA,
        observed_at=datetime.now(UTC),
    )
    assert claim.derivation is Derivation.SCHEMA
