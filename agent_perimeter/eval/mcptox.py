# agent_perimeter/eval/mcptox.py
"""Adapter re-using the MCPTox dataset as a scanner detection corpus.

MCPTox measures agent attack-success-rate across 45 live servers and 353 tools.
This re-uses its labelled poisoned metadata to measure *scanner detection*
instead. The labels support that, but it is not the use the paper made of it,
and the methodology page says so in the same table that reports the score.

Not vendored. The operator supplies a path; when absent, only the local corpus
runs, and the table records that.

Input format is unconfirmed. {id, tool_name, description, poisoned} below is a
placeholder shape, not a verified schema -- confirm it against
pure_tool.json / response_all.json in
github.com/zhiqiangwang4/MCPTox-Benchmark before implementing load_mcptox for
real.

1,312 cases are generated from only 3 templates by few-shot generation. A
detector tuned on this corpus will show inflated recall relative to
real-world description diversity -- state that alongside every number this
module feeds into docs/methodology.md.

MCPTox carries no licence as of 29 August 2026 (confirmed live: `gh api
repos/zhiqiangwang4/MCPTox-Benchmark` -> license: null, no LICENSE file). This
module must never vendor or bundle the dataset; it only reads a path the
operator supplies at run time.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.eval.corpus import CorpusCase

MCPTOX_REUSE_NOTE = (
    "MCPTox was published to measure agent attack success rate against tool "
    "poisoning. Here its labelled poisoned tool metadata is re-used as a "
    "detection corpus for this scanner. The labels support that use, but it is "
    "not the use the original paper made of the dataset, and the two numbers "
    "are not comparable. MCPTox's 1,312 cases are generated from only 3 "
    "templates by few-shot generation, a homogeneity limit that inflates "
    "recall relative to real-world description diversity. MCPTox carries no "
    "licence as of 29 August 2026; results here are reproducible only by a "
    "reader who independently obtains the dataset from "
    "github.com/zhiqiangwang4/MCPTox-Benchmark and supplies its path."
)

# Checks that each cover one poisoning mechanism MCPTox exercises. A poisoned
# sample is scored as detected if *any* of these fires -- see POISON_DETECTED.
# Requiring all of them marked a sample containing only an imperative, with
# no Unicode trick, as a false negative for unicode_anomaly even when the
# detector worked correctly, across ~1,312 cases (revision §4.4).
POISON_CHECKS = (
    "descriptions.imperative_injection",
    "descriptions.unicode_anomaly",
)

# Synthetic label scored in place of POISON_CHECKS on poisoned samples: "at
# least one poisoning check fired". Not a registered Check id -- run.py's
# _observe() synthesises it from whichever real check(s) actually fired.
POISON_DETECTED = "mcptox.poisoning_detected"

# Case id -> the tool the sample actually describes. An MCPTox case has no
# fixture server behind it: the sample *is* the tool listing, so the harness
# checks it directly rather than dispatching to the shared fixture.
_SAMPLE_TOOLS: dict[str, ToolRecord] = {}


def to_corpus_cases(samples: list[dict[str, object]]) -> list[CorpusCase]:
    cases: list[CorpusCase] = []
    for sample in samples:
        case_id = f"mcptox:{sample.get('id')}"
        _SAMPLE_TOOLS[case_id] = ToolRecord(
            name=str(sample.get("tool_name", "")),
            description=str(sample.get("description", "")),
            input_schema={"type": "object", "properties": {}},
        )
        poisoned = bool(sample.get("poisoned"))
        cases.append(
            CorpusCase(
                id=case_id,
                revision="2026-07-28",
                flaw="mcptox_sample",
                expect_findings=(POISON_DETECTED,) if poisoned else (),
                expect_clean=POISON_CHECKS if not poisoned else (),
                note=MCPTOX_REUSE_NOTE,
            )
        )
    return cases


def sample_tool(case_id: str) -> ToolRecord | None:
    """The tool metadata behind one MCPTox case id, for the harness to check
    directly. None for a case id that is not an MCPTox sample."""
    return _SAMPLE_TOOLS.get(case_id)


def load_mcptox(path: Path) -> list[CorpusCase]:
    samples = json.loads(path.read_text(encoding="utf-8"))
    return to_corpus_cases(samples if isinstance(samples, list) else [])
