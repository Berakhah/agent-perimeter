"""Fetch the authorization server metadata document.

A .well-known document is a published, unauthenticated discovery endpoint —
the same category as robots.txt. Fetching one is not a crafted payload and
does not require a scope file. The Week 4 census does not use this path.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx

WELL_KNOWN = "/.well-known/oauth-authorization-server"


def fetch_oauth_metadata(
    target: str, *, client: httpx.Client | None = None
) -> dict[str, object] | None:
    if not target.startswith(("http://", "https://")):
        return None

    parts = urlsplit(target)
    url = urlunsplit((parts.scheme, parts.netloc, WELL_KNOWN, "", ""))
    owned = client is None
    http = client or httpx.Client(timeout=10.0)
    try:
        response = http.get(url)
    except httpx.HTTPError:
        return None
    finally:
        if owned:
            http.close()

    if response.status_code != 200:
        return None
    try:
        metadata = response.json()
    except ValueError:
        return None
    return metadata if isinstance(metadata, dict) else None
