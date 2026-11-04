"""Enumerate the tools a server exposes.

A server that will not list its tools is not an error condition — it is a
finding for `static/` to report. Enumeration returns what it got.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from agent_perimeter.transport.base import Transport, TransportError

logger = logging.getLogger(__name__)


MAX_TOOL_PAGES = 100


@dataclass(frozen=True)
class ToolRecord:
    name: str
    description: str
    input_schema: dict[str, object] = field(default_factory=dict)
    annotations: dict[str, object] = field(default_factory=dict)


def enumerate_tools(transport: Transport, notes: list[str] | None = None) -> list[ToolRecord]:
    """List every tool, following `nextCursor` across pages.

    `notes`, when given, receives one sentence for each early stop (repeat
    cursor, page cap, later-page failure) so the caller can surface that the
    listing is incomplete.

    A later page's entry for a name seen on an earlier page replaces it, keeping
    first-seen order. Duplicate names within one page are all kept. Paging
    stops when the cursor is absent, or early when it repeats, MAX_TOOL_PAGES
    is reached, or a later page raises TransportError (which keeps what
    earlier pages returned). All three early stops log a warning and add a
    note; run_scan surfaces the notes in the HTML report, the CLI summary, the
    API status body, the SSE terminal frame, SARIF toolExecutionNotifications
    and the web live-scan screen, skips drift, and marks the scan
    listing-incomplete so it never becomes a drift baseline. A TransportError
    on page 1 yields no tools and no note: an unlisted server is a finding
    for `static/`, not a truncated listing.
    """
    records: list[ToolRecord] = []
    index: dict[str, int] = {}  # name -> position of its first-seen record
    cursor: str | None = None
    seen: set[str] = set()
    for page in range(1, MAX_TOOL_PAGES + 1):
        params: dict[str, object] | None = {"cursor": cursor} if cursor is not None else None
        try:
            listing = transport.request("tools/list", params)
        except TransportError as exc:
            if page > 1:
                logger.warning(
                    "tools/list page %d failed (%s); keeping %d tools from earlier pages",
                    page,
                    exc,
                    len(records),
                )
                _note(
                    notes,
                    f"Tool listing incomplete: page {page} of tools/list failed with a "
                    f"transport error; checks ran on the {page - 1} page(s) received. "
                    "Re-run once the server answers every page.",
                )
            break
        merge_page(records, index, parse_tools(listing))
        following = listing.get("nextCursor")
        if not isinstance(following, str) or not following:
            break
        if following in seen:
            logger.warning("tools/list cursor repeated; listing may be incomplete")
            # The cursor is server-controlled and may embed a credential: never echo it.
            _note(
                notes,
                f"Tool listing incomplete: the server repeated a cursor after "
                f"{page} page(s); checks ran on the {page} page(s) received. "
                "Re-run once the server's pagination is fixed.",
            )
            break
        seen.add(following)
        cursor = following
    else:
        logger.warning(
            "tools/list still had a nextCursor after %d pages; listing is incomplete",
            MAX_TOOL_PAGES,
        )
        _note(
            notes,
            f"Tool listing incomplete: the server still offered a next page after "
            f"{MAX_TOOL_PAGES} pages (the page cap); checks ran on the {MAX_TOOL_PAGES} "
            "pages received. Re-run against a server that returns a bounded listing.",
        )
    return records


def _note(notes: list[str] | None, text: str) -> None:
    if notes is not None:
        notes.append(text)


def parse_tools(listing: dict[str, object]) -> list[ToolRecord]:
    """The well-formed tool entries of one tools/list page, in order."""
    raw_tools = listing.get("tools")
    if not isinstance(raw_tools, list):
        return []
    return [record for record in map(_parse, raw_tools) if record is not None]


def merge_page(records: list[ToolRecord], index: dict[str, int], page: list[ToolRecord]) -> None:
    """Fold one page into `records` in place; `index` maps name -> first-seen slot.

    A name seen on an earlier page is replaced in its slot; duplicate names
    within one page are all kept (drift and rug-pull checks key on them).
    Shared with the instrument proxy so both see the same listing.
    """
    earlier = dict(index)
    for record in page:
        if record.name in earlier:
            records[earlier[record.name]] = record
        else:
            index.setdefault(record.name, len(records))
            records.append(record)


def _parse(entry: object) -> ToolRecord | None:
    if not isinstance(entry, dict) or "name" not in entry:
        return None
    schema = entry.get("inputSchema")
    annotations = entry.get("annotations")
    return ToolRecord(
        name=str(entry["name"]),
        description=str(entry.get("description", "")),
        input_schema=schema if isinstance(schema, dict) else {},
        annotations=annotations if isinstance(annotations, dict) else {},
    )
