import shutil
from pathlib import Path

import pytest

from tests.docker_build import build_image

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")


def test_a_failed_build_names_dockers_own_error(tmp_path: Path) -> None:
    # A base image that cannot exist. Docker's stderr is the only place that
    # says so; the raw CalledProcessError CI showed on 2026-09-15 did not.
    (tmp_path / "Dockerfile").write_text("FROM agent-perimeter-no-such-base:0\n")

    with pytest.raises(RuntimeError, match=r"agent-perimeter-no-such-base"):
        build_image("agent-perimeter-build-helper:test", tmp_path)
