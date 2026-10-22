"""Supply-chain lookups: what the registries and OSV know about each server's package.

Runs before the rules (which stay offline): for every npm or PyPI package a launch config runs,
resolve the version npx/uvx would install (or take the one --connect installed), then record its
publish time, publisher, install scripts, provenance and the release before it, and its OSV
advisories. The MCP-SC rules judge those facts.

This sends package names and versions to the npm registry, PyPI and osv.dev; `--offline` turns it
off. Responses are cached for an hour in ~/.cache/mcpiranha/registry (or $MCPIRANHA_CACHE_DIR).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import anyio
import httpx2

from mcpiranha import __version__
from mcpiranha.core.launch import package_ref
from mcpiranha.core.models import PackageMeta, ServerSnapshot
from mcpiranha.supply import osv
from mcpiranha.supply.registry import NotFound, RegistryError, npm_meta, pypi_meta

CACHE_SECONDS = 3600
TIMEOUT = 30.0


def cache_dir() -> Path:
    base = os.environ.get("MCPIRANHA_CACHE_DIR")
    return (Path(base) if base else Path.home() / ".cache" / "mcpiranha") / "registry"


def offline_by_default() -> bool:
    return os.environ.get("MCPIRANHA_OFFLINE", "") not in ("", "0")


class Fetcher(Protocol):
    async def get(self, url: str, headers: dict[str, str]) -> Any: ...
    async def post(self, url: str, body: Any) -> Any: ...


class Http:
    """JSON GET/POST with a small on-disk cache. A 404 is None, not an error; an HTML answer is
    returned as text."""

    def __init__(self, client: httpx2.AsyncClient, cache: Path | None) -> None:
        self._client, self._cache = client, cache

    def _path(self, key: str) -> Path | None:
        return (
            self._cache / f"{hashlib.sha256(key.encode()).hexdigest()}.json"
            if self._cache
            else None
        )

    async def _cached(self, key: str, fetch: Any) -> Any:
        path = self._path(key)
        if path and path.is_file() and time.time() - path.stat().st_mtime < CACHE_SECONDS:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                pass
        response: httpx2.Response = await fetch()
        if response.status_code == 404:
            data = None
        elif response.status_code >= 400:
            raise RegistryError(f"{response.request.url} answered HTTP {response.status_code}")
        elif "json" not in response.headers.get("content-type", "json"):
            data = response.text  # an index that only speaks HTML (PEP 503), e.g. pypiserver
        else:
            try:
                data = response.json()
            except ValueError as exc:
                raise RegistryError(f"{response.request.url} didn't return JSON") from exc
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
        return data

    async def get(self, url: str, headers: dict[str, str]) -> Any:
        key = f"GET {url} {sorted(headers.items())}"
        return await self._cached(key, lambda: self._client.get(url, headers=headers))

    async def post(self, url: str, body: Any) -> Any:
        key = f"POST {url} {json.dumps(body, sort_keys=True)}"
        return await self._cached(key, lambda: self._client.post(url, json=body))


@dataclass(frozen=True, slots=True)
class Registries:
    """Where to look packages up; None = $MCPIRANHA_NPM_REGISTRY / $MCPIRANHA_PYPI_INDEX, else
    the public registries."""

    npm: str | None = None
    pypi: str | None = None


PUBLIC = Registries()


async def lookup(
    snapshot: ServerSnapshot, http: Fetcher, registries: Registries = PUBLIC
) -> PackageMeta | None:
    ref = package_ref(snapshot.launch)
    if ref is None or ref.registry == "docker":
        return None
    installed = snapshot.package.version if snapshot.package else None
    try:
        if ref.registry == "npm":
            return await npm_meta(ref, installed, http.get, registries.npm)
        return await pypi_meta(ref, installed, http.get, registries.pypi)
    except NotFound:
        # Still worth asking OSV: taken-down malware keeps its MAL- advisory.
        exact = ref.spec if ref.pinned else None
        version = installed or (exact.removeprefix("==").removeprefix("@") if exact else None)
        return PackageMeta(registry=ref.registry, name=ref.name, version=version,
                           resolution="exact" if version else None, removed=True)  # fmt: skip


async def enrich(
    snapshots: Sequence[ServerSnapshot],
    *,
    http: Fetcher | None = None,
    registries: Registries = PUBLIC,
    jobs: int = 8,
) -> tuple[list[ServerSnapshot], list[str]]:
    """Snapshots with `package` filled in from the registries and OSV, plus warnings for packages
    that couldn't be looked up (the scan goes on without them)."""
    if http is None:
        headers = {"User-Agent": f"mcpiranha/{__version__}"}
        async with httpx2.AsyncClient(timeout=TIMEOUT, headers=headers,
                                      follow_redirects=True) as client:  # fmt: skip
            http = Http(client, cache_dir())
            return await enrich(snapshots, http=http, registries=registries, jobs=jobs)

    out = list(snapshots)
    warnings: dict[int, str] = {}
    limiter = anyio.CapacityLimiter(jobs)
    found: dict[int, PackageMeta] = {}

    async def one(i: int, snapshot: ServerSnapshot) -> None:
        async with limiter:
            try:
                meta = await lookup(snapshot, http, registries)
            except (RegistryError, httpx2.HTTPError, OSError) as exc:
                warnings[i] = f"{snapshot.name}: registry lookup failed: {exc}"
                return
        if meta is not None:
            found[i] = meta

    async with anyio.create_task_group() as group:
        for i, snapshot in enumerate(snapshots):
            group.start_soon(one, i, snapshot)

    order, now = sorted(found), datetime.now(UTC)
    try:
        advisories = await osv.vulnerabilities([found[i] for i in order], http.post, http.get)
    except (RegistryError, httpx2.HTTPError, OSError) as exc:
        advisories = [None] * len(order)
        warnings[len(out)] = f"OSV lookup failed, known vulnerabilities not checked: {exc}"
    for i, vulns in zip(order, advisories, strict=True):
        meta = found[i].model_copy(update={"vulnerabilities": vulns, "checked_at": now})
        out[i] = out[i].model_copy(update={"package": meta})
    return out, [warnings[k] for k in sorted(warnings)]
