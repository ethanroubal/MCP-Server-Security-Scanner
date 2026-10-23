"""Source analysis: read the code a server runs, without running it.

Sources:
- a local script the config launches (`python server.py`, `node build/index.js`): that file, or
  its whole project when the directory has a pyproject.toml / package.json / .git;
- the npm tarball or PyPI wheel (sdist if there's no wheel) of the release the registry lookup
  resolved: downloaded, checked against the registry's hash, and read in memory. Nothing is
  extracted to disk or installed. Archives are cached in ~/.cache/mcpiranha/archives.

Python is parsed with `ast`, JavaScript/TypeScript with tree-sitter. What they find is stored on
the snapshot (`SourceTree.hits`), so saved snapshots can be rescanned offline; the MCP-SRC rules
judge it.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import zipfile
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePosixPath

import anyio
import anyio.to_thread
import httpx2

from mcpiranha import __version__
from mcpiranha.core.launch import command_line
from mcpiranha.core.models import ServerSnapshot, SourceHit, SourceTree
from mcpiranha.source import javascript, python
from mcpiranha.supply import cache_dir

PY = (".py",)
JS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx")
MAX_ARCHIVE = 50 * 1024 * 1024
MAX_FILE = 5 * 1024 * 1024
MAX_TOTAL = 80 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024  # stop reading an archive (bombs: tiny download, huge content)
MAX_HITS = 100
_PROJECT_MARKERS = ("pyproject.toml", "setup.py", "package.json", ".git")
_SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", ".git", "__pycache__", ".tox", "dist-info",
                        "test", "tests", "__tests__", "spec", "examples"})  # fmt: skip
_RUNNERS = frozenset({"python", "python3", "node", "bun", "deno", "tsx", "ts-node", "uv"})


class SourceError(Exception):
    pass


def _skip(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(p in _SKIP_DIRS for p in parts[:-1]) or path.endswith((".d.ts", ".map"))


def analyze_files(files: Iterator[tuple[str, bytes]], root: str) -> SourceTree:
    hits: list[SourceHit] = []
    seen: set[tuple[str, str]] = set()
    count, languages, skipped = 0, set[str](), list[str]()
    for path, data in files:
        if len(data) > MAX_FILE:
            skipped.append(f"{path}: larger than {MAX_FILE // 2**20} MB")
            continue
        count += 1
        if path.endswith(PY):
            languages.add("py")
            found = python.analyze(path, data.decode("utf-8", "replace"))
        else:
            languages.add("ts" if path.endswith((".ts", ".mts", ".cts", ".tsx")) else "js")
            found = javascript.analyze(path, data)
        for h in found:
            key = (h.kind, h.detail)  # one hit per distinct thing (bundles repeat code)
            if key not in seen and len(hits) < MAX_HITS:
                seen.add(key)
                hits.append(h)
    language = "py" if languages == {"py"} else "ts" if "ts" in languages else (
        "js" if languages else "other")  # fmt: skip
    return SourceTree(root=root, language=language, files=count, skipped=skipped, hits=hits)


# --- local scripts --------------------------------------------------------------------------------


def local_entry(snapshot: ServerSnapshot) -> Path | None:
    """The script a stdio config runs with an interpreter, if it's a file on this machine."""
    launch = snapshot.launch
    if launch is None or launch.transport != "stdio" or not launch.command:
        return None
    argv = command_line(launch)
    if Path(argv[0]).name.split(".")[0] not in _RUNNERS:
        return None
    # Relative paths: clients start servers in the project (the config's folder) or the cwd.
    bases = [Path(snapshot.origin.config_path).parent] if snapshot.origin.config_path else []
    for arg in argv[1:]:
        if arg.endswith(PY + JS):
            path = Path(arg).expanduser()
            for candidate in (
                [path] if path.is_absolute() else [b / path for b in [*bases, Path.cwd()]]
            ):
                if candidate.is_file():
                    return candidate.resolve()
    return None


def _local_files(entry: Path) -> Iterator[tuple[str, bytes]]:
    project = next((d for d in [entry.parent, entry.parent.parent]
                    if any((d / m).exists() for m in _PROJECT_MARKERS)), None)  # fmt: skip
    if project is None or project == Path.home():
        yield entry.name, entry.read_bytes()
        return
    total = 0
    for path in sorted(project.rglob("*")):
        rel = path.relative_to(project).as_posix()
        if path.suffix in PY + JS and path.is_file() and not _skip(rel):
            data = path.read_bytes()
            total += len(data)
            if total > MAX_TOTAL:
                return
            yield rel, data


# --- package archives -----------------------------------------------------------------------------


def verify(data: bytes, expected: str) -> bool:
    if expected.startswith("sha512-"):
        return base64.b64encode(hashlib.sha512(data).digest()).decode() == expected[7:]
    algorithm, _, digest = expected.partition(":")
    if algorithm in ("sha256", "sha1"):
        return hashlib.new(algorithm, data).hexdigest() == digest.lower()
    return False


async def _download(client: httpx2.AsyncClient, url: str, expected: str) -> bytes:
    cached = cache_dir().parent / "archives" / hashlib.sha256(expected.encode()).hexdigest()
    if cached.is_file():
        data = cached.read_bytes()
        if verify(data, expected):
            return data
    chunks: list[bytes] = []
    size = 0
    async with client.stream("GET", url) as response:
        if response.status_code >= 400:
            raise SourceError(f"{url} answered HTTP {response.status_code}")
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise SourceError(f"archive larger than {MAX_ARCHIVE // 2**20} MB")
            chunks.append(chunk)
    data = b"".join(chunks)
    if not verify(data, expected):
        raise SourceError(f"{url} doesn't match the registry's hash")
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(data)
    return data


def archive_files(data: bytes, name: str) -> Iterator[tuple[str, bytes]]:
    """Source files in a .tgz / .tar.gz / .whl / .zip, read in memory (never extracted)."""
    total = 0
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(i.file_size for i in archive.infolist()) > MAX_UNPACKED:
                yield "(archive)", b"x" * (MAX_FILE + 1)  # reported as skipped
                return
            for info in archive.infolist():
                if info.filename.endswith(PY + JS) and not _skip(info.filename):
                    if info.file_size > MAX_FILE:
                        yield info.filename, b"x" * (MAX_FILE + 1)  # reported as skipped
                        continue
                    total += info.file_size
                    if total > MAX_TOTAL:
                        return
                    yield info.filename, archive.read(info)
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        unpacked = 0
        for member in archive:
            unpacked += member.size
            if unpacked > MAX_UNPACKED:
                return
            if not member.isfile() or not member.name.endswith(PY + JS):
                continue
            path = member.name.split("/", 1)[-1]  # "package/..." (npm), "name-1.0/..." (sdist)
            if _skip(path):
                continue
            if member.size > MAX_FILE:
                yield path, b"x" * (MAX_FILE + 1)
                continue
            total += member.size
            if total > MAX_TOTAL:
                return
            extracted = archive.extractfile(member)
            if extracted is not None:
                yield path, extracted.read()


# --- collection -----------------------------------------------------------------------------------


async def collect(
    snapshots: Sequence[ServerSnapshot], *, download: bool = True, jobs: int = 4
) -> tuple[list[ServerSnapshot], list[str]]:
    """Snapshots with `source` filled in where code could be read, plus warnings."""
    out = list(snapshots)
    warnings: list[str] = []
    limiter = anyio.CapacityLimiter(jobs)
    headers = {"User-Agent": f"mcpiranha/{__version__}"}

    async with httpx2.AsyncClient(timeout=60, headers=headers, follow_redirects=True) as client:

        async def one(i: int, snapshot: ServerSnapshot) -> None:
            package = snapshot.package
            try:
                async with limiter:
                    if (entry := local_entry(snapshot)) is not None:
                        tree = await anyio.to_thread.run_sync(
                            lambda: analyze_files(_local_files(entry), str(entry.parent))
                        )
                        tree = tree.model_copy(update={"entrypoints": [entry.name]})
                    elif download and package and package.archive_url and package.archive_hash:
                        data = await _download(client, package.archive_url, package.archive_hash)
                        sep = "==" if package.registry == "pypi" else "@"
                        root = f"{package.registry}:{package.name}{sep}{package.version}"
                        name = package.archive_url.rsplit("/", 1)[-1]
                        tree = await anyio.to_thread.run_sync(
                            lambda: analyze_files(archive_files(data, name), root)
                        )
                    else:
                        return
            except (SourceError, httpx2.HTTPError, OSError, tarfile.TarError,
                    zipfile.BadZipFile) as exc:  # fmt: skip
                warnings.append(f"{snapshot.name}: source not analyzed: {exc}")
                return
            out[i] = snapshot.model_copy(update={"source": tree})

        async with anyio.create_task_group() as group:
            for i, snapshot in enumerate(snapshots):
                group.start_soon(one, i, snapshot)
    return out, warnings
