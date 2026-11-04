"""Enumerate the tools a server exposes.

A listing that fails is not fatal to the scan: enumeration returns what it
got and says, in `ToolListing.complete`, whether that is the whole listing.
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


METHOD_NOT_FOUND = -32601  # JSON-RPC: the server does not implement the method

NO_TOOLS_NOTE = (
    "The server does not offer tools (tools/list returned Method not found); "
    "tool checks had nothing to analyse."
)


@dataclass(frozen=True)
class ToolListing:
    """What `list_tools` read. `complete` is separate from `notes`: a note may
    be purely informational (a server with no tools capability), so callers
    must read completeness from `complete`, never from whether notes exist."""

    tools: list[ToolRecord]
    notes: tuple[str, ...]
    complete: bool


def enumerate_tools(transport: Transport, notes: list[str] | None = None) -> list[ToolRecord]:
    """`list_tools(transport).tools`, appending its notes to `notes` when given."""
    listing = list_tools(transport)
    if notes is not None:
        notes.extend(listing.notes)
    return listing.tools


def list_tools(transport: Transport) -> ToolListing:
    """List every tool, following `nextCursor` across pages.

    `notes` carries one sentence for each early stop (page failure, a reply
    with no tools list, repeat cursor, page cap), each of which also makes
    the listing incomplete, plus the informational NO_TOOLS_NOTE.

    A page-1 JSON-RPC -32601 (Method not found) means the server has no
    tools capability: a complete, empty listing, with NO_TOOLS_NOTE so the
    empty result is explained. On a later page -32601 is an early stop like
    any other failure.

    A later page's entry for a name seen on an earlier page replaces it, keeping
    first-seen order. Duplicate names within one page are all kept. Paging
    stops when the cursor is absent, or early when it repeats, MAX_TOOL_PAGES
    is reached, a page raises TransportError, or a page's reply has no `tools`
    list (both keep what earlier pages returned). Every early stop logs a
    warning and adds a note; run_scan surfaces the notes in the HTML report,
    the CLI summary, the API status body, the SSE terminal frame, SARIF
    toolExecutionNotifications and the web live-scan screen, skips drift, and
    marks the scan listing-incomplete so it never becomes a drift baseline.

    A failure on page 1 is not fatal (the scan's other checks still run on
    what is known) but it is an incomplete listing, not an empty one: read as
    "zero tools" it would report every baseline tool removed and, kept as a
    baseline, every tool added on the next full scan. Only a successful reply
    carrying `"tools": []`, or a page-1 Method not found, is a complete,
    empty listing.
    """
    notes: list[str] = []
    complete = True

    def stop(text: str) -> None:
        nonlocal complete
        complete = False
        notes.append(text)

    records: list[ToolRecord] = []
    index: dict[str, int] = {}  # name -> position of its first-seen record
    cursor: str | None = None
    seen: set[str] = set()
    for page in range(1, MAX_TOOL_PAGES + 1):
        params: dict[str, object] | None = {"cursor": cursor} if cursor is not None else None
        try:
            listing = transport.request("tools/list", params)
        except TransportError as exc:
            if page == 1 and exc.code == METHOD_NOT_FOUND:
                logger.info("tools/list is not implemented; the server offers no tools")
                notes.append(NO_TOOLS_NOTE)
                break
            logger.warning(
                "tools/list page %d failed (%s); keeping %d tools from earlier pages",
                page,
                exc,
                len(records),
            )
            # The error text is server-influenced: the note names only the cause.
            stop(_failed_page_note(page, "failed with a transport error"))
            break
        if not isinstance(listing.get("tools"), list):
            logger.warning("tools/list page %d had no tools list; listing is incomplete", page)
            if page == 1:
                stop(
                    "Tool listing incomplete: page 1 of tools/list answered with no tools "
                    "list, so no tools were listed and checks that read the listing saw "
                    'none. The server must answer tools/list with a tools array (`"tools": []` '
                    "when it has none); a plain re-run will not fix it."
                )
            else:
                stop(_failed_page_note(page, "answered with no tools list"))
            break
        merge_page(records, index, parse_tools(listing))
        following = listing.get("nextCursor")
        if not isinstance(following, str) or not following:
            break
        if following in seen:
            logger.warning("tools/list cursor repeated; listing may be incomplete")
            # The cursor is server-controlled and may embed a credential: never echo it.
            stop(
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
        stop(
            f"Tool listing incomplete: the server still offered a next page after "
            f"{MAX_TOOL_PAGES} pages (the page cap); checks ran on the {MAX_TOOL_PAGES} "
            "pages received. Re-run against a server that returns a bounded listing.",
        )
    return ToolListing(tools=records, notes=tuple(notes), complete=complete)


def _failed_page_note(page: int, cause: str) -> str:
    if page == 1:
        return (
            f"Tool listing incomplete: page 1 of tools/list {cause}, so no tools were "
            "listed and checks that read the listing saw none. "
            "Re-run once the server answers tools/list."
        )
    return (
        f"Tool listing incomplete: page {page} of tools/list {cause}; checks ran on "
        f"the {page - 1} page(s) received. Re-run once the server answers every page."
    )


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
