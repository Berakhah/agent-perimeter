"""Shared fixtures for census tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parents[1] / "fixtures" / "registry"


@pytest.fixture
def registry_pages() -> list[dict]:
    """Two real (trimmed) registry response envelopes that page into each other."""
    return [
        json.loads((FIXTURES / "page1.json").read_text(encoding="utf-8")),
        json.loads((FIXTURES / "page2.json").read_text(encoding="utf-8")),
    ]
