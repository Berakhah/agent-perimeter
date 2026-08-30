import ast
from collections.abc import Iterable
from pathlib import Path

CHECKS_DIR = Path(__file__).parents[1].parent / "agent_perimeter" / "checks"

# Constructing a jsonschema RefResolver/Registry with remote fetching enabled
# is the concrete way this would happen. Grepping for the shape rather than
# just the string "RefResolver" catches the common ways it gets wired in.
FORBIDDEN_CALLS = {"RefResolver", "Registry", "resolve_from_url", "requests.get", "httpx.get"}


def test_no_check_module_constructs_a_remote_fetching_schema_resolver() -> None:
    offenders = _offenders_in(CHECKS_DIR.rglob("*.py"))
    assert not offenders, "\n".join(offenders)


def test_dotted_module_attr_call_is_recognised_as_forbidden(tmp_path: Path) -> None:
    """requests.get(...) / httpx.get(...) must be caught even though the bare
    attribute name alone ("get") is never itself forbidden — adding a bare
    "get" entry to FORBIDDEN_CALLS would flood false positives on every
    dict.get()/os.environ.get() call already in the codebase. This is a
    regression test for a real gap: the original _call_name only ever
    returned the bare attribute name, so "requests.get" and "httpx.get" in
    FORBIDDEN_CALLS could never match anything.
    """
    offender_file = tmp_path / "evil_check.py"
    offender_file.write_text(
        "import requests\n\ndef fetch(url: str) -> object:\n    return requests.get(url)\n",
        encoding="utf-8",
    )
    offenders = _offenders_in([offender_file])
    assert len(offenders) == 1
    assert "requests.get" in offenders[0]


def _offenders_in(paths: Iterable[Path]) -> list[str]:
    offenders: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                matched = _call_names(node) & FORBIDDEN_CALLS
                if matched:
                    offenders.append(f"{path}:{node.lineno} calls {sorted(matched)[0]}")
    return offenders


def _call_names(node: ast.Call) -> set[str]:
    """Every name-form a call could be matched against: the bare
    function/attribute name, and — for `module.attr(...)` where `module` is
    a plain name — the dotted "module.attr" form too. Matching on the union
    keeps the existing bare-name matches (`.RefResolver(...)` off any
    module) working while also closing the gap where `requests.get(...)`
    could never match the dotted "requests.get" entry in FORBIDDEN_CALLS.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return {func.id}
    if isinstance(func, ast.Attribute):
        names = {func.attr}
        if isinstance(func.value, ast.Name):
            names.add(f"{func.value.id}.{func.attr}")
        return names
    return set()
