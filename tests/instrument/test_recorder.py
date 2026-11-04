import json

from agent_perimeter.instrument.canary import Canary
from agent_perimeter.instrument.recorder import MAX_RESULT_CHARS, Recorder, redact

# Synthetic, split so no scanner sees one literal; same shape the eval fixtures use.
SECRET = "sk-" + "test-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
CANARY = Canary(nonce="00ff00ff00ff00ff")


def test_redact_replaces_a_secret_and_keeps_only_fingerprint_fragments() -> None:
    out = redact(f"key is {SECRET} ok")
    assert SECRET not in out
    assert "[REDACTED:openai:" in out
    assert out.endswith(" ok")


def test_result_is_truncated_after_redaction() -> None:
    recorder = Recorder(CANARY)
    recorder.record_call("read_file", {}, "x" * 5000, injected=False)
    result = recorder.to_transcript()["tool_calls"][0]["result"]  # type: ignore[index]
    assert len(result) == MAX_RESULT_CHARS


def test_secret_straddling_the_cut_is_not_half_leaked() -> None:
    recorder = Recorder(CANARY)
    padding = "y" * (MAX_RESULT_CHARS - 10)
    recorder.record_call("read_file", {}, padding + SECRET, injected=False)
    assert SECRET[:12] not in json.dumps(recorder.to_transcript())


def test_secret_in_arguments_is_redacted_but_the_canary_is_preserved() -> None:
    recorder = Recorder(CANARY)
    recorder.record_call(
        "sync_to_webhook",
        {"url": f"https://x.test/{CANARY.token}", "auth": SECRET},
        "ok",
        injected=False,
    )
    serialised = json.dumps(recorder.to_transcript())
    assert SECRET not in serialised
    assert CANARY.token in serialised


def test_transcript_shape_and_injected_flag() -> None:
    recorder = Recorder(CANARY)
    recorder.record_call("read_file", {"path": "a"}, "body", injected=True)
    recorder.record_call("sync_to_webhook", {"url": "u"}, "ok", injected=False)
    transcript = recorder.to_transcript()
    assert transcript["canary"] == {"nonce": "00ff00ff00ff00ff"}
    calls = transcript["tool_calls"]
    assert [c["name"] for c in calls] == ["read_file", "sync_to_webhook"]  # type: ignore[index]
    assert calls[0]["injected"] is True  # type: ignore[index]
    assert "injected" not in calls[1]  # type: ignore[operator]
