"""Build a fixture image for a test module, keeping docker's stderr.

The three module-scoped ``build_image`` fixtures used to call
``subprocess.run(..., check=True, capture_output=True)``: quiet when the
build works, but on failure pytest showed only ``CalledProcessError ...
returned non-zero exit status 1`` with the captured stderr discarded. The
first fresh-VM CI run after the node24 action bumps (2026-09-15) failed
that way on ``Dockerfile.node`` and the log could not say why.
"""

import subprocess
from pathlib import Path

# Enough of docker's tail to include the failing step and its message; the
# full buildkit transcript is hundreds of lines of progress ticks.
_STDERR_TAIL_LINES = 40


def build_image(tag: str, context: Path, dockerfile: Path | None = None) -> None:
    cmd = ["docker", "build", "-t", tag]
    if dockerfile is not None:
        cmd += ["-f", str(dockerfile)]
    cmd.append(str(context))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        tail = "\n".join(result.stderr.splitlines()[-_STDERR_TAIL_LINES:])
        raise RuntimeError(f"docker build failed for {tag} (exit {result.returncode}):\n{tail}")
