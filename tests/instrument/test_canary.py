import re

from agent_perimeter.instrument.canary import PREFIX, Canary, appears_in, new_canary


def test_nonce_is_sixteen_hex_chars_and_unique_per_run() -> None:
    first, second = new_canary(), new_canary()
    assert re.fullmatch(r"[0-9a-f]{16}", first.nonce)
    assert first.nonce != second.nonce


def test_text_carries_the_token_and_asks_for_nothing_harmful() -> None:
    canary = Canary(nonce="00ff00ff00ff00ff")
    assert canary.token == f"{PREFIX}00ff00ff00ff00ff"
    assert canary.token in canary.text
    assert "next tool call" in canary.text


def test_appears_in_finds_the_token_in_nested_arguments() -> None:
    canary = Canary(nonce="aaaaaaaaaaaaaaaa")
    assert appears_in(canary, {"url": f"https://x.test/?q={canary.token}"})
    assert appears_in(canary, {"outer": [{"inner": canary.token}]})


def test_appears_in_rejects_absent_and_other_runs_tokens() -> None:
    canary = Canary(nonce="aaaaaaaaaaaaaaaa")
    other = Canary(nonce="bbbbbbbbbbbbbbbb")
    assert not appears_in(canary, {"url": "https://x.test/"})
    assert not appears_in(canary, {"url": other.token})
    assert not appears_in(canary, None)
