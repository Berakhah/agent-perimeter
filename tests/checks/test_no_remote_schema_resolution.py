import ast
from pathlib import Path

CHECKS_DIR = Path(__file__).parents[1].parent / "agent_perimeter" / "checks"

# Constructing a jsonschema RefResolver/Registry with remote fetching enabled
# is the concrete way this would happen. Grepping for the shape rather than
# just the string "RefResolver" catches the common ways it gets wired in.
FORBIDDEN_CALLS = {"RefResolver", "Registry", "resolve_from_url", "requests.get", "httpx.get"}


def test_no_check_module_constructs_a_remote_fetching_schema_resolver() -> None:
    offenders: list[str] = []
    for path in CHECKS_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in FORBIDDEN_CALLS:
                    offenders.append(f"{path}:{node.lineno} calls {name}")
    assert not offenders, "\n".join(offenders)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""
