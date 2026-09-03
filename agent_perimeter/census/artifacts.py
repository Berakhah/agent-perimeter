"""Download and read published package artifacts. Never execute one.

An sdist or npm tarball is attacker-controlled input from an untrusted third
party. It is downloaded to a temporary directory, size-capped, extracted with
traversal/symlink/bomb rejection, and left on disk for a later stage to read.
It is never executed here - no setup.py, no `npm install`, no import.

Extraction leans on `tarfile.extractall(filter="data")` (PEP 706, Python
3.12+) rather than a hand-rolled member walk: it is stdlib-maintained and
already rejects traversal, symlinks/hardlinks that escape the destination,
device files and setuid/setgid bits. `zipfile` has no equivalent `filter=`
parameter, so the zip path below still does a manual per-member check.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import httpx

from agent_perimeter import __version__
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
# A single member must not be able to exhaust the whole uncompressed budget by
# itself. Kept <= MAX_UNCOMPRESSED_BYTES per project convention.
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 20_000

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
NPM_JSON = "https://registry.npmjs.org/{name}"

USER_AGENT = (
    f"agent-perimeter/{__version__} "
    "(+https://github.com/USER/agent-perimeter/blob/main/docs/security.md)"
)

_TIMEOUT_S = 15.0


class ArchiveRejected(Exception):
    """The archive did something an honest archive does not do."""


@dataclass(slots=True)
class ArtifactResult:
    status: FetchStatus
    detail: str
    root: Path | None
    version: str | None


def _resolve_member(dest: Path, name: str) -> Path | None:
    """Where this member would land, or None if the name is unusable.

    Used as a fast pre-check ahead of the real extraction (tar: `filter="data"`
    still runs and is the deeper guard; zip: this check is the only guard,
    since `zipfile` has no filter hook). `filter="data"` itself only rejects an
    absolute member *name* if it stays absolute after stripping a leading
    slash (e.g. a Windows drive path) - a POSIX-style "/etc/passwd" name is
    silently relativized into the destination instead of rejected. Reject it
    outright here so a member never gets to choose an absolute-looking path.

    Also reject anything that looks like a Windows drive ("C:", "0:...") or
    UNC/rooted path, checked with `PureWindowsPath` regardless of host OS: a
    tar/zip member name is POSIX-style, so a colon-drive prefix has no
    business there, and on a Windows host `(dest / "0:").resolve()` discards
    `dest` entirely and lands on a different drive - `Path.resolve()` won't
    catch that for us, so it has to be rejected before the join.

    The containment check happens here too, not just in the caller: a name of
    "." resolves to `dest` itself (not a descendant of it) and ".." resolves
    to `dest`'s parent, and both must come back as None - a member is only
    ever "usable" if it lands strictly inside `dest`.
    """
    if not name or "\x00" in name:
        return None
    win = PureWindowsPath(name)
    if win.drive or win.root:
        return None
    resolved = (dest / name).resolve()
    if dest not in resolved.parents:
        return None
    return resolved


def _member_target(resolved_dest: Path, name: str) -> Path:
    target = _resolve_member(resolved_dest, name)
    if target is None or resolved_dest not in target.parents:
        raise ArchiveRejected(f"member resolves outside destination: {name}")
    return target


# ponytail: extraction into a temp dir with caps and traversal rejection, not a
# sandboxed container. Justified because nothing here is executed and every file is
# opened read-only; upgrade to the Week 1 container launcher if that ever changes.
def safe_extract(archive: Path, dest: Path) -> list[Path]:
    """Extract `archive` into `dest`. Raises `ArchiveRejected` for anything an
    honest archive wouldn't do. Returns the extracted regular-file paths."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveRejected(f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
    dest.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest.resolve()

    if tarfile.is_tarfile(archive):
        return _extract_tar(archive, resolved_dest)
    if zipfile.is_zipfile(archive):
        return _extract_zip(archive, resolved_dest)
    raise ArchiveRejected("not a recognised tar or zip archive")


def _extract_tar(archive: Path, resolved_dest: Path) -> list[Path]:
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ArchiveRejected(f"{len(members)} members exceeds {MAX_MEMBERS}")

        written: list[Path] = []
        total = 0
        for member in members:
            target = _member_target(resolved_dest, member.name)
            if member.isreg():
                if member.size > MAX_FILE_BYTES:
                    raise ArchiveRejected(
                        f"member exceeds {MAX_FILE_BYTES} bytes: {member.name}"
                    )
                total += member.size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise ArchiveRejected(f"uncompressed size exceeds {MAX_UNCOMPRESSED_BYTES}")
                written.append(target)

        try:
            tf.extractall(path=resolved_dest, filter="data")
        except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError) as exc:
            raise ArchiveRejected(f"symlink member: {exc.tarinfo.name}") from exc
        except tarfile.SpecialFileError as exc:
            raise ArchiveRejected(f"special file member: {exc.tarinfo.name}") from exc
        except tarfile.OutsideDestinationError as exc:
            raise ArchiveRejected(
                f"member resolves outside destination: {exc.tarinfo.name}"
            ) from exc
        except tarfile.FilterError as exc:
            raise ArchiveRejected(f"rejected by extraction filter: {exc}") from exc
    return written


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000  # S_IFMT
    return mode == 0o120000  # S_IFLNK


def _extract_zip(archive: Path, resolved_dest: Path) -> list[Path]:
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ArchiveRejected(f"{len(infos)} members exceeds {MAX_MEMBERS}")

        written: list[Path] = []
        total = 0
        for info in infos:
            if _is_zip_symlink(info):
                raise ArchiveRejected(f"symlink member: {info.filename}")
            target = _member_target(resolved_dest, info.filename)
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE_BYTES:
                raise ArchiveRejected(f"member exceeds {MAX_FILE_BYTES} bytes: {info.filename}")
            total += info.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ArchiveRejected(f"uncompressed size exceeds {MAX_UNCOMPRESSED_BYTES}")
            zf.extract(info, path=resolved_dest)
            written.append(target)
    return written


def _pypi_target(coords: PackageCoords, doc: dict[str, object]) -> tuple[str, str] | None:
    info = doc.get("info")
    version = coords.version or (info.get("version") if isinstance(info, dict) else None)
    if not isinstance(version, str):
        return None
    releases = doc.get("releases")
    files = releases.get(version) if isinstance(releases, dict) else None
    if not isinstance(files, list):
        return None
    for entry in files:
        if isinstance(entry, dict) and entry.get("packagetype") == "sdist":
            url = entry.get("url")
            if isinstance(url, str):
                return url, version
    return None


def _npm_target(coords: PackageCoords, doc: dict[str, object]) -> tuple[str, str] | None:
    dist_tags = doc.get("dist-tags")
    version = coords.version or (dist_tags.get("latest") if isinstance(dist_tags, dict) else None)
    if not isinstance(version, str):
        return None
    versions = doc.get("versions")
    entry = versions.get(version) if isinstance(versions, dict) else None
    dist = entry.get("dist") if isinstance(entry, dict) else None
    tarball = dist.get("tarball") if isinstance(dist, dict) else None
    if isinstance(tarball, str):
        return tarball, version
    return None


def _metadata(
    client: httpx.Client, coords: PackageCoords
) -> tuple[FetchStatus, str, dict[str, object] | None]:
    # Ecosystem (model/census.py) only ever has these two members today, so
    # mypy proves this match exhaustive - a third member would be a type
    # error here, not a silent UNSUPPORTED_COORDS at run time.
    match coords.ecosystem:
        case Ecosystem.PYPI:
            url = PYPI_JSON.format(name=coords.name)
        case Ecosystem.NPM:
            url = NPM_JSON.format(name=coords.name)

    try:
        response = client.get(url, headers={"User-Agent": USER_AGENT}, timeout=_TIMEOUT_S)
    except httpx.TimeoutException:
        return FetchStatus.TIMEOUT, f"metadata request timed out: {url}", None
    except httpx.HTTPError as exc:
        return FetchStatus.PARSE_ERROR, f"metadata request failed: {exc}", None

    if response.status_code == 404:
        return FetchStatus.NOT_FOUND, f"package not found: {coords.name}", None
    if response.status_code == 429:
        return FetchStatus.THROTTLED, f"metadata request throttled: {url}", None
    if response.status_code != 200:
        return (
            FetchStatus.PARSE_ERROR,
            f"metadata request returned {response.status_code}: {url}",
            None,
        )

    try:
        doc = response.json()
    except ValueError:
        return FetchStatus.PARSE_ERROR, f"metadata response was not valid JSON: {url}", None
    if not isinstance(doc, dict):
        return FetchStatus.PARSE_ERROR, f"metadata response was not a JSON object: {url}", None
    return FetchStatus.OK, "", doc


def _download(client: httpx.Client, url: str, dest: Path) -> tuple[FetchStatus, str]:
    """Stream `url` into `dest`, aborting the moment MAX_ARCHIVE_BYTES is exceeded."""
    try:
        with client.stream(
            "GET", url, headers={"User-Agent": USER_AGENT}, timeout=_TIMEOUT_S
        ) as response:
            if response.status_code == 404:
                return FetchStatus.NOT_FOUND, f"artifact not found: {url}"
            if response.status_code == 429:
                return FetchStatus.THROTTLED, f"artifact request throttled: {url}"
            if response.status_code != 200:
                return FetchStatus.PARSE_ERROR, f"artifact request returned {response.status_code}"

            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > MAX_ARCHIVE_BYTES:
                        return FetchStatus.TOO_LARGE, f"declared size exceeds {MAX_ARCHIVE_BYTES}"
                except ValueError:
                    pass

            written = 0
            with dest.open("wb") as fh:
                for chunk in response.iter_bytes():
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        return FetchStatus.TOO_LARGE, f"download exceeds {MAX_ARCHIVE_BYTES} bytes"
                    fh.write(chunk)
    except httpx.TimeoutException:
        return FetchStatus.TIMEOUT, f"artifact download timed out: {url}"
    except httpx.HTTPError as exc:
        return FetchStatus.PARSE_ERROR, f"artifact download failed: {exc}"
    return FetchStatus.OK, ""


def _fetch_into(
    client: httpx.Client, url: str, archive_path: Path, extract_dir: Path, version: str
) -> ArtifactResult:
    try:
        status, detail = _download(client, url, archive_path)
        if status is not FetchStatus.OK:
            return ArtifactResult(status=status, detail=detail, root=None, version=version)

        try:
            safe_extract(archive_path, extract_dir)
        except ArchiveRejected as exc:
            return ArtifactResult(
                status=FetchStatus.PARSE_ERROR,
                detail=f"archive rejected: {exc}",
                root=None,
                version=version,
            )

        archive_path.unlink(missing_ok=True)
        return ArtifactResult(status=FetchStatus.OK, detail="", root=extract_dir, version=version)
    except OSError as exc:
        return ArtifactResult(
            status=FetchStatus.PARSE_ERROR,
            detail=f"local filesystem error: {exc}",
            root=None,
            version=version,
        )


def fetch_artifact(client: httpx.Client, coords: PackageCoords) -> ArtifactResult:
    """Resolve `coords` to a published sdist/tarball, download, and extract it.

    Never raises into the run loop - one unfetchable or hostile package must
    not end a census of thousands. Every failure is reported through the
    returned `ArtifactResult.status`/`detail`.
    """
    status, detail, doc = _metadata(client, coords)
    if status is not FetchStatus.OK or doc is None:
        return ArtifactResult(status=status, detail=detail, root=None, version=None)

    target = (
        _pypi_target(coords, doc)
        if coords.ecosystem is Ecosystem.PYPI
        else _npm_target(coords, doc)
    )
    if target is None:
        return ArtifactResult(
            status=FetchStatus.NOT_FOUND,
            detail=f"no downloadable artifact for {coords.name} {coords.version or '(latest)'}",
            root=None,
            version=None,
        )
    url, version = target

    workdir = Path(tempfile.mkdtemp(prefix="ap-artifact-"))
    result = _fetch_into(client, url, workdir / "archive", workdir / "extracted", version)
    # A caller that gets FetchStatus.OK owns `root` and is responsible for
    # deleting the workdir once done reading it (Task 4 reads it; nothing here
    # executes it). Every other status means we clean up after ourselves.
    if result.status is not FetchStatus.OK:
        shutil.rmtree(workdir, ignore_errors=True)
    return result
