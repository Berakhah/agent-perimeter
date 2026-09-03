from agent_perimeter._contracts import Derivation
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.graph.build import build_graph
from agent_perimeter.model.edge import Capability


def _tool(
    name: str, description: str = "", properties: dict[str, object] | None = None
) -> ToolRecord:
    return ToolRecord(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": properties or {}},
    )


def test_name_derived_fs_read_edge() -> None:
    edges = build_graph([_tool("read_file", properties={"path": {"type": "string"}})])
    fs = [e for e in edges if e.capability is Capability.FS_READ]
    assert fs and fs[0].derivation is Derivation.NAME


def test_name_derived_net_out_edge_from_url_parameter() -> None:
    edges = build_graph([_tool("fetch", properties={"url": {"type": "string"}})])
    assert any(e.capability is Capability.NET_OUT for e in edges)


def test_description_derived_edge_is_marked_as_such() -> None:
    edges = build_graph([_tool("helper", description="Sends the result to our API endpoint.")])
    net = [e for e in edges if e.capability is Capability.NET_OUT]
    assert net and net[0].derivation is Derivation.DESCRIPTION


def test_name_evidence_outranks_description_for_the_same_capability() -> None:
    tool = _tool("fetch", description="Fetches a URL.", properties={"url": {"type": "string"}})
    net = [e for e in build_graph([tool]) if e.capability is Capability.NET_OUT]
    assert len(net) == 1
    assert net[0].derivation is Derivation.NAME


def test_exec_capability_from_command_parameter() -> None:
    edges = build_graph([_tool("run", properties={"command": {"type": "string"}})])
    assert any(e.capability is Capability.EXEC for e in edges)


def test_every_edge_carries_a_claim_and_a_rationale() -> None:
    for edge in build_graph([_tool("read_file", properties={"path": {"type": "string"}})]):
        assert edge.claim.derivation is edge.derivation
        assert edge.rationale.strip()


def test_description_derived_edge_carries_a_caveat() -> None:
    edges = build_graph([_tool("helper", description="Sends the result to our API endpoint.")])
    assert edges[0].claim.caveat is not None


def test_name_derived_edge_carries_a_caveat_and_reduced_confidence() -> None:
    """A name match is not schema structure -- B9's 'confidently wrong'
    pattern applied to the flagship screen. Revision §3, §7.4."""
    edges = build_graph([_tool("read_file", properties={"path": {"type": "string"}})])
    fs = [e for e in edges if e.capability is Capability.FS_READ][0]
    assert fs.claim.caveat is not None
    assert fs.claim.confidence is not None
    assert fs.claim.confidence < 1.0


def test_tool_with_no_signals_produces_no_edges() -> None:
    assert build_graph([_tool("ping", description="Returns pong.")]) == []
