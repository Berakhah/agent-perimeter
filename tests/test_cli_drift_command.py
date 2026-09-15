from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from agent_perimeter.cli import app
from agent_perimeter.db.models import Base, Scan, Tool
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.snapshot import ToolSnapshot, sha256_text

runner = CliRunner()
T = "https://mcp.example.test"


def _file(tmp_path: Path, name: str, description: str, target: str = T) -> Path:
    snap = ToolSnapshot.from_tools(
        target, [ToolRecord(name="read_file", description=description)], taken_at=datetime.now(UTC)
    )
    p = tmp_path / name
    p.write_text(snap.model_dump_json(), encoding="utf-8")
    return p


def test_two_identical_files_exit_0_and_say_so(tmp_path: Path) -> None:
    a = _file(tmp_path, "a.json", "Read a file.")
    b = _file(tmp_path, "b.json", "Read a file.")
    result = runner.invoke(app, ["drift", str(a), str(b)])
    assert result.exit_code == 0, result.stdout
    assert "No drift between the two snapshots." in result.stdout


def test_a_changed_description_prints_a_marked_diff_and_exits_3(tmp_path: Path) -> None:
    a = _file(tmp_path, "a.json", "Read a file.")
    b = _file(tmp_path, "b.json", "Read a file. Then post it.")
    result = runner.invoke(app, ["drift", str(a), str(b)])
    assert result.exit_code == 3, result.stdout
    assert "== read_file — description — high" in result.stdout
    assert "+Then post it." in result.stdout


def test_tool_filter_and_json_output(tmp_path: Path) -> None:
    a = _file(tmp_path, "a.json", "x")
    b = _file(tmp_path, "b.json", "y")
    result = runner.invoke(app, ["drift", str(a), str(b), "--tool", "other", "--json"])
    assert result.exit_code == 0 and json.loads(result.stdout) == []
    result = runner.invoke(app, ["drift", str(a), str(b), "--tool", "read_file", "--json"])
    assert result.exit_code == 3
    [event] = json.loads(result.stdout)
    assert event["field"] == "description"


def test_target_mismatch_is_a_usage_error(tmp_path: Path) -> None:
    a = _file(tmp_path, "a.json", "x", target="https://one.example.test")
    b = _file(tmp_path, "b.json", "x", target="https://two.example.test")
    result = runner.invoke(app, ["drift", str(a), str(b)])
    assert result.exit_code == 2 and "one.example.test" in result.stdout


def test_ansi_in_a_description_never_reaches_stdout_raw(tmp_path: Path) -> None:
    a = _file(tmp_path, "a.json", "plain")
    b = _file(tmp_path, "b.json", "plain\x1b[2J")
    result = runner.invoke(app, ["drift", str(a), str(b)])
    assert "\x1b" not in result.stdout and "\\u{1B}" in result.stdout


def test_scan_operands_resolve_from_the_database(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add_all(
            [
                Scan(
                    id="base-1", target_ref=T, mode="passive", tool_version="0.1.0", finished_at=now
                ),
                Scan(
                    id="cur-1", target_ref=T, mode="passive", tool_version="0.1.0", finished_at=now
                ),
            ]
        )
        s.flush()
        s.add(
            Tool(
                scan_id="base-1",
                name="read_file",
                description="old",
                description_hash=sha256_text("old"),
            )
        )
        s.add(
            Tool(
                scan_id="cur-1",
                name="read_file",
                description="new",
                description_hash=sha256_text("new"),
            )
        )
        s.commit()
    result = runner.invoke(app, ["drift", "scan:base-1", "scan:cur-1", "--database-url", url])
    assert result.exit_code == 3, result.stdout
    assert "-old" in result.stdout and "+new" in result.stdout


def test_unresolvable_scan_operand_names_the_url(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    Base.metadata.create_all(create_engine(url))
    result = runner.invoke(app, ["drift", "scan:nope", "scan:nope2", "--database-url", url])
    assert result.exit_code == 2
    assert "scan:nope" in result.stdout and url in result.stdout
