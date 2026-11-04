import json
from urllib.parse import quote

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
    # The space keeps \b in the openai pattern satisfied, so the secret is
    # matchable. Truncate-before-redact would keep the first 10 secret chars
    # (cut at index MAX_RESULT_CHARS); redact-before-truncate keeps "[REDACTED:"
    # whole, since the marker starts at index MAX_RESULT_CHARS - 10.
    padding = "y" * (MAX_RESULT_CHARS - 11) + " "
    recorder.record_call("read_file", {}, padding + SECRET, injected=False)
    assert SECRET[:8] not in json.dumps(recorder.to_transcript())
    result = recorder.to_transcript()["tool_calls"][0]["result"]  # type: ignore[index]
    assert "[REDACTED:" in result


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


def test_secret_used_as_an_argument_key_is_redacted() -> None:
    recorder = Recorder(CANARY)
    recorder.record_call("call_api", {SECRET: "v"}, "ok", injected=False)
    assert SECRET not in json.dumps(recorder.to_transcript())


# --- redaction without word boundaries ---------------------------------------
# SECRET_PATTERNS anchor on \b for scanner precision; the recorder must not, or
# a secret glued to a word character or URL-encoded is written raw.

GITHUB = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8"


def _recorded(arguments: object, result: str = "ok", name: str = "call_api") -> str:
    recorder = Recorder(CANARY)
    recorder.record_call(name, arguments, result, injected=False)
    return json.dumps(recorder.to_transcript())


def test_secret_glued_to_an_underscore_is_redacted() -> None:
    out = _recorded({"q": "key_" + SECRET}, result="key_" + SECRET)
    assert SECRET not in out
    assert SECRET[3:] not in out


def test_secret_glued_to_a_letter_is_redacted() -> None:
    assert SECRET not in redact("x" + SECRET)
    assert SECRET[3:] not in redact("x" + SECRET)


def test_url_encoded_secret_is_redacted_in_both_forms() -> None:
    encoded = "https://x.test/cb?k%3D" + SECRET.replace("-", "%2D")
    out = _recorded({"url": encoded}, result=encoded)
    assert SECRET not in out
    assert SECRET.replace("-", "%2D") not in out
    assert SECRET[3:].replace("-", "%2D") not in out
    assert "[REDACTED" in out


def test_value_under_a_secret_named_key_is_redacted_whole() -> None:
    value = "hunter" + "2-correct-horse"  # matches no credential pattern
    out = _recorded({"password": value, "Authorization": "Basic " + "dXNlcjpwYXNz"})
    assert value not in out
    assert "dXNlcjpwYXNz" not in out


def test_multiple_secrets_in_one_string_are_all_redacted() -> None:
    out = redact(f"first={SECRET}&second={GITHUB}")
    assert SECRET not in out
    assert GITHUB not in out
    assert out.count("[REDACTED:") == 2


def test_secrets_in_nested_lists_and_dicts_are_redacted() -> None:
    out = _recorded({"a": [{"b": "x" + SECRET}, ["y" + GITHUB]], "c": {"api_key": 12345}})
    assert SECRET not in out
    assert GITHUB not in out
    assert "12345" not in out


def test_secret_in_the_tool_name_is_redacted() -> None:
    assert SECRET not in _recorded({}, name="call_" + SECRET)


def test_canary_survives_boundary_free_redaction() -> None:
    # "desk-" + token would read as an openai-shaped "sk-..." without \b.
    out = _recorded({"url": f"https://x.test/desk-{CANARY.token}"}, result=CANARY.text)
    assert CANARY.token in out
    assert CANARY.text in out


def test_canary_under_a_secret_named_key_survives_but_the_secret_does_not() -> None:
    # The canary sentence says "include the token", so {"token": <canary>} is
    # the most likely obedient call; redacting it would hide the finding.
    out = _recorded({"token": f"{SECRET} {CANARY.token}"})
    assert SECRET not in out
    assert CANARY.token in out


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


# --- residual review findings ------------------------------------------------


def _no_fragment(text: str, secret: str, size: int = 12) -> bool:
    return all(secret[i : i + size] not in text for i in range(len(secret) - size + 1))


def test_secrets_encoded_at_different_depths_are_all_redacted() -> None:
    first = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    second = "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4"
    out = redact("a=sk%2D" + first + "&b=sk%252D" + second)
    for secret in (first, second):
        assert _no_fragment(out, secret)
    assert out.count("[REDACTED:") == 2


def test_a_password_that_starts_like_the_canary_is_fully_redacted() -> None:
    password = "AP-CANARY-" + "c0ffee" * 6
    out = _recorded({"password": password})
    assert "c0ffee" not in out
    assert "AP-CANARY-" not in out


def test_this_runs_token_under_a_secret_named_key_is_kept() -> None:
    out = _recorded({"token": CANARY.token})
    assert CANARY.token in out


def test_another_runs_token_under_a_secret_named_key_is_redacted() -> None:
    other = Canary(nonce="ffeeddccbbaa9988")
    out = _recorded({"token": other.token})
    assert other.nonce not in out
    assert "AP-CANARY-" not in out


def test_redact_preserves_a_token_only_when_given_its_canary() -> None:
    # "desk-" + token reads as an openai-shaped "sk-..." without .
    text = f"https://x.test/desk-{CANARY.token}"
    assert CANARY.token in redact(text, CANARY)
    assert CANARY.token not in redact(text)


# --- round 2: token spliced into a secret, deep percent-encoding ---------------


def test_a_secret_with_the_canary_token_spliced_inside_is_redacted() -> None:
    body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    spliced = "sk-" + body[:12] + CANARY.token + body[12:]
    out = redact(spliced, CANARY)
    assert _no_fragment(out, body, 8)
    assert _no_fragment(_recorded({"q": spliced}), body, 8)


def test_a_clean_token_next_to_no_secret_is_still_kept() -> None:
    assert redact(f"x {CANARY.token} y", CANARY) == f"x {CANARY.token} y"


def test_deeply_percent_encoded_secrets_are_redacted() -> None:
    body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    four = "sk%2525252D" + body
    six = "sk-" + body
    for _ in range(6):
        six = quote(six, safe="")
    for encoded in (four, six):
        out = redact(encoded)
        assert _no_fragment(out, body, 8)
        assert "[REDACTED:" in out
