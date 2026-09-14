import ast
import re
from pathlib import Path

import pytest

FORBIDDEN_PREFIXES = (
    "agent_perimeter.transport",
    "agent_perimeter.checks.active",
    "agent_perimeter.checks.injection",
    "agent_perimeter.discover",
)


def _imports(path: Path) -> set[str]:
    """Every `agent_perimeter.*`-shaped name this file's imports touch.

    `ast.ImportFrom.module` alone misses `from agent_perimeter import
    transport`: that records only "agent_perimeter" (the package), never
    "agent_perimeter.transport" (the submodule bound to the name `transport`)
    - the exact idiom `agent_perimeter/census/run.py` itself already uses for
    its own siblings (`from agent_perimeter.census import artifacts, detect,
    fetch, sample`). A chain that reaches a forbidden module only through
    this import style would resolve to a bare "agent_perimeter", which the
    transitive walk already treats as harmless, and the real submodule would
    never surface at all. So each imported alias is additionally checked
    against the filesystem: if `module.alias` resolves to a real file under
    `agent_perimeter`, it is recorded too, alongside `module` itself - a
    plain symbol import (`from agent_perimeter import __version__`) resolves
    to no file and is correctly left alone.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            for alias in node.names:
                candidate = f"{node.module}.{alias.name}"
                if _module_file(candidate) is not None:
                    names.add(candidate)
    return names


def _module_file(module_name: str) -> Path | None:
    """Best-effort source file for an `agent_perimeter.*` dotted module name.

    Returns None for anything not under `agent_perimeter` (third-party and
    stdlib modules are out of scope - see the module docstring on the
    transitive test below) and for a name that resolves to no file on disk
    (e.g. an attribute pulled off a module, not a submodule itself).
    """
    if not (module_name == "agent_perimeter" or module_name.startswith("agent_perimeter.")):
        return None
    rel = Path(*module_name.split("."))
    as_module = rel.with_suffix(".py")
    if as_module.is_file():
        return as_module
    as_package = rel / "__init__.py"
    if as_package.is_file():
        return as_package
    return None


def _reachable_forbidden_modules(census_dir: Path) -> list[str]:
    """Walk the whole `agent_perimeter.*` import graph reachable from
    `census_dir` - direct or transitive - and return one entry per forbidden
    module reached. Empty means the passive-only guarantee holds.

    Parameterized on `census_dir` (rather than hardcoding
    "agent_perimeter/census" inline) so a regression test can point it at a
    synthetic tree instead of the real repo, the same way the real test
    points it at the real one.

    This is a *transitive* check, not a one-hop scan of each census file's
    own direct imports. A one-hop version catches a forbidden import written
    directly in census code, but misses a chain that leaves the census
    package through another agent_perimeter module - e.g.
    agent_perimeter.census.run importing agent_perimeter.report.foo, where
    foo itself (not anything under agent_perimeter/census) imports
    agent_perimeter.transport.bar. The one-hop version never looks at what
    foo imports, so that chain would sail through claiming "can never reach"
    while doing exactly that. This stops expanding only at a forbidden
    module (already an offence, no need to go further) or a module outside
    agent_perimeter entirely (third-party libraries are not this project's
    graph to police).
    """
    offences: list[str] = []
    seen: set[str] = set()
    worklist: list[tuple[str, Path]] = []

    for path in census_dir.rglob("*.py"):
        for name in _imports(path):
            if name.startswith(FORBIDDEN_PREFIXES):
                offences.append(f"{path}: {name}")
            elif name.startswith("agent_perimeter") and name not in seen:
                seen.add(name)
                worklist.append((name, path))

    while worklist:
        module_name, origin = worklist.pop()
        module_file = _module_file(module_name)
        if module_file is None:
            continue
        for name in _imports(module_file):
            if name.startswith(FORBIDDEN_PREFIXES):
                offences.append(f"{module_file}: {name} (reached from {origin} via {module_name})")
            elif name.startswith("agent_perimeter") and name not in seen:
                seen.add(name)
                worklist.append((name, module_file))

    return offences


def test_census_can_never_reach_a_transport_or_an_active_check() -> None:
    """The census must be structurally incapable of touching a third-party server.

    See `_reachable_forbidden_modules` for why this has to be transitive, not
    a one-hop scan of each census file's own direct imports.
    """
    offences = _reachable_forbidden_modules(Path("agent_perimeter/census"))
    assert offences == [], f"census reached a live-traffic module: {offences}"


def test_from_agent_perimeter_import_subpackage_is_caught_transitively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: `from agent_perimeter import transport` binds the name
    `transport` to the submodule, but `_imports()` used to record only the
    package name "agent_perimeter" for it - never "agent_perimeter.transport"
    - so a chain reaching a forbidden module *only* through this import style
    (already used by `run.py` itself, for its own siblings - see
    `from agent_perimeter.census import artifacts, detect, fetch, sample`)
    was invisible to the transitive walk even after it was made transitive.

    Reproduces the exact chain a reviewer found uncaught: a census file
    imports a sibling agent_perimeter module by name
    (`from agent_perimeter import other_module`), and that sibling reaches a
    forbidden module the same way (`from agent_perimeter import transport`).
    Built as a synthetic tree under `tmp_path` (not the real repo) so this
    never touches the actual `agent_perimeter` package on disk.
    """
    root = tmp_path / "agent_perimeter"
    census_dir = root / "census"
    census_dir.mkdir(parents=True)
    transport_pkg = root / "transport"
    transport_pkg.mkdir()
    (transport_pkg / "__init__.py").write_text(
        "def do_live_request():\n    ...\n", encoding="utf-8"
    )
    (root / "other_module.py").write_text(
        "from agent_perimeter import transport\n\n\n"
        "def do_live_request():\n    return transport.do_live_request()\n",
        encoding="utf-8",
    )
    (census_dir / "run.py").write_text(
        "from agent_perimeter import other_module\n\n\n"
        "def run():\n    return other_module.do_live_request()\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    offences = _reachable_forbidden_modules(Path("agent_perimeter/census"))
    assert any("agent_perimeter.transport" in offence for offence in offences), offences


TIER3 = Path("agent_perimeter/census/tier3.py")
_METHOD_RE = re.compile(r"^[a-z]+/[a-zA-Z]+$")


def test_every_module_but_tier3_talks_only_to_the_allowed_hosts() -> None:
    """Tiers 1-2 are artifact-only: the host list is closed and literal.

    `github.com` is allowed alongside the three hosts tiers 1-2 actually send
    requests to (tier-2 selection is a seeded draw and contacts nothing): it
    never appears as a request target in this package, only as the contact
    URL baked into every `USER_AGENT` constant (fetch.py, artifacts.py) per
    the registry-collection convention of
    identifying the tool with a contact URL. A regex over raw source can't
    tell "host embedded in a header value" from "host requested," so it has
    to be told this one is the former.
    """
    allowed = {
        "registry.modelcontextprotocol.io",
        "pypi.org",
        "registry.npmjs.org",
        "github.com",
    }
    src = "\n".join(
        p.read_text(encoding="utf-8")
        for p in Path("agent_perimeter/census").rglob("*.py")
        if p != TIER3
    )
    hosts = set(re.findall(r"https://([a-z0-9.\-]+)/", src))
    assert hosts <= allowed, f"unexpected host in census: {hosts - allowed}"


def test_tier3_sends_exactly_one_method_and_owns_no_host() -> None:
    """Tier 3's targets come from the frame, so it is constrained by shape, not by host.

    This is the guarantee that makes a live `server/discover` passive discovery
    rather than an active probe. It must be impossible to widen by accident.
    """
    src = TIER3.read_text(encoding="utf-8")

    methods = {
        node.value
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _METHOD_RE.fullmatch(node.value)
    }
    assert methods == {"server/discover"}, f"tier3 may send only server/discover, found {methods}"

    hosts = set(re.findall(r"https://([a-z0-9.\-]+)/", src))
    assert hosts == set(), f"tier3 must take every target from the frame, found {hosts}"
