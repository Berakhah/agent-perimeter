from __future__ import annotations

from datetime import UTC, datetime

from agent_perimeter._contracts import Severity
from agent_perimeter.drift.render import (
    MAX_DIFF_TOKENS,
    SEVERITY_RANK,
    for_terminal,
    render_excerpt,
    word_diff,
)
from agent_perimeter.model.drift import DriftEvent, DriftField

NOW = datetime(2026, 9, 15, tzinfo=UTC)


def test_severity_rank_orders_critical_first() -> None:
    assert sorted(SEVERITY_RANK, key=SEVERITY_RANK.__getitem__) == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


def test_word_diff_marks_only_the_changed_words() -> None:
    runs = word_diff("Read a file from disk.", "Read any file from disk and post it.")
    assert ("delete", "a") in runs
    assert ("insert", "any") in runs
    assert ("delete", "disk.") in runs
    assert ("insert", "disk and post it.") in runs
    assert runs[0] == ("equal", "Read")


def test_word_diff_of_identical_text_is_one_equal_run() -> None:
    assert word_diff("same words", "same words") == [("equal", "same words")]


def test_word_diff_over_the_cap_returns_a_summary_run() -> None:
    old = " ".join(["w"] * (MAX_DIFF_TOKENS + 1))
    runs = word_diff(old, "short")
    assert len(runs) == 1
    assert runs[0][0] == "replace-summary"
    assert f"{MAX_DIFF_TOKENS + 1} tokens" in runs[0][1]


def test_for_terminal_escapes_ansi_and_controls_but_keeps_newlines() -> None:
    raw = "ok\x1b[2Jline\nnext\ttab\x00\x7f"
    out = for_terminal(raw)
    assert "\x1b" not in out and "\x00" not in out and "\x7f" not in out
    assert "\\u{1B}" in out
    assert "\n" in out and "\t" in out


def test_for_terminal_escapes_the_c1_control_range() -> None:
    # U+0080..U+009F carry CSI (U+009B) and NEL (U+0085); none may pass raw.
    out = for_terminal("a\x85b\x9bc\x9fd\xa0e")
    assert "\x85" not in out and "\x9b" not in out and "\x9f" not in out
    assert "\\u{85}" in out and "\\u{9B}" in out and "\\u{9F}" in out
    assert "\xa0" in out  # U+00A0 is the first code point past the range


def test_for_terminal_escapes_bidi_zero_width_and_tag_characters() -> None:
    raw = "a‮b​c\U000e0041d"
    out = for_terminal(raw)
    assert "‮" not in out and "​" not in out and "\U000e0041" not in out
    assert "\\u{202E}" in out and "\\u{200B}" in out and "\\u{E0041}" in out


def _event(field: DriftField, old: str | None, new: str | None) -> DriftEvent:
    return DriftEvent(
        tool_name="t",
        field=field,
        old_hash=None if old is None else "0" * 64,
        new_hash=None if new is None else "1" * 64,
        old_value=old,
        new_value=new,
        severity=Severity.HIGH,
        detected_at=NOW,
    )


def test_render_excerpt_for_a_description_is_a_marked_word_diff() -> None:
    text = render_excerpt(_event(DriftField.DESCRIPTION, "Read a file.", "Read any file."))
    assert "-a" in text and "+any" in text and "Read" in text


def test_render_excerpt_over_the_cap_is_a_bracketed_summary() -> None:
    old = " ".join(["w"] * (MAX_DIFF_TOKENS + 1))
    excerpt = render_excerpt(_event(DriftField.DESCRIPTION, old, old + " x"))
    assert excerpt.startswith("[") and excerpt.endswith("]")
    assert f"{MAX_DIFF_TOKENS + 1} tokens" in excerpt
    assert "w w w" not in excerpt


def test_render_excerpt_for_schema_is_a_hash_summary() -> None:
    text = render_excerpt(_event(DriftField.INPUT_SCHEMA, "{}", '{"x":1}'))
    assert text == "input_schema: 000000000000 → 111111111111"


def test_render_excerpt_for_added_names_the_absent_side() -> None:
    text = render_excerpt(_event(DriftField.TOOL_ADDED, None, "Fresh."))
    assert text == "tool_added: (absent) → 111111111111"


def test_render_events_groups_by_tool_and_sanitises() -> None:
    from agent_perimeter.drift.render import render_events

    ev = _event(DriftField.DESCRIPTION, "Read a file.", "Read a file.\x1b[2J and post it")
    lines = render_events([ev])
    assert lines[0].startswith("== t — description — high")
    assert any(line.startswith("+") for line in lines)
    assert not any("\x1b" in line for line in lines)


def test_render_events_over_the_cap_emits_one_summary_line() -> None:
    from agent_perimeter.drift.render import render_events

    old = " ".join(["w"] * (MAX_DIFF_TOKENS + 1))
    lines = render_events([_event(DriftField.DESCRIPTION, old, old + " x")])
    assert len(lines) == 2  # header + summary, not one line per token
    assert lines[1].startswith("?") and "diff too large" in lines[1]
