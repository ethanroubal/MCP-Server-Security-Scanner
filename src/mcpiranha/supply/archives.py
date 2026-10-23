"""Release archives (npm tarballs, PyPI wheels and sdists): downloaded once, checked against the
registry's hash, cached in ~/.cache/mcpiranha/archives, and only ever read in memory.

Shared by source analysis (the code) and dependency resolution (a wheel's METADATA).
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import zipfile

import httpx2

MAX_ARCHIVE = 50 * 1024 * 1024


class ArchiveError(Exception):
    pass


def verify(data: bytes, expected: str) -> bool:
    if expected.startswith("sha512-"):
        return base64.b64encode(hashlib.sha512(data).digest()).decode() == expected[7:]
    algorithm, _, digest = expected.partition(":")
    if algorithm in ("sha256", "sha1"):
        return hashlib.new(algorithm, data).hexdigest() == digest.lower()
    return False


async def download(client: httpx2.AsyncClient, url: str, expected: str) -> bytes:
    from mcpiranha.supply import cache_dir  # the package imports this module

    cached = cache_dir().parent / "archives" / hashlib.sha256(expected.encode()).hexdigest()
    if cached.is_file():
        data = cached.read_bytes()
        if verify(data, expected):
            return data
    chunks: list[bytes] = []
    size = 0
    async with client.stream("GET", url) as response:
        if response.status_code >= 400:
            raise ArchiveError(f"{url} answered HTTP {response.status_code}")
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise ArchiveError(f"archive larger than {MAX_ARCHIVE // 2**20} MB")
            chunks.append(chunk)
    data = b"".join(chunks)
    if not verify(data, expected):
        raise ArchiveError(f"{url} doesn't match the registry's hash")
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(data)
    return data


def python_metadata(data: bytes, name: str) -> str | None:
    """The core metadata (METADATA in a wheel, PKG-INFO in an sdist), for Requires-Dist."""
    try:
        if name.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                member = next((n for n in archive.namelist()
                               if n.endswith(".dist-info/METADATA")), None)  # fmt: skip
                return archive.read(member).decode("utf-8", "replace") if member else None
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive:
                if (
                    member.isfile()
                    and member.name.count("/") == 1
                    and member.name.endswith("/PKG-INFO")
                ):
                    extracted = archive.extractfile(member)
                    return extracted.read().decode("utf-8", "replace") if extracted else None
    except (tarfile.TarError, zipfile.BadZipFile, OSError, KeyError):
        return None
    return None
