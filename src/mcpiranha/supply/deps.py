"""Dependency trees: every package that installing a server pulls in, resolved from registry
metadata the way the installer would (nothing is installed).

npm: each release's dependencies, optional and required peer dependencies, resolved with npx's
range rules, breadth first. PyPI: each release's Requires-Dist, read from its wheel (or sdist)
METADATA, with environment markers evaluated for the sandbox (CPython 3.12 on Linux) and the
extras that were asked for.

Every dependency gets the same facts as the top-level package (publisher, install scripts,
provenance, the release before it, its archive) plus `via`, the chain that pulls it in.
Dependencies from git or tarball URLs bypass the registry and are recorded as `external`;
names the registry doesn't have are `removed` (anyone could publish them). Resolution stops at
MAX_DEPENDENCIES packages and says so.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
from packaging.markers import InvalidMarker
from packaging.requirements import InvalidRequirement, Requirement

from mcpiranha.core.launch import PackageRef
from mcpiranha.core.models import PackageMeta
from mcpiranha.supply.archives import python_metadata
from mcpiranha.supply.registry import (
    GetJson,
    NotFound,
    RegistryError,
    npm_meta,
    pypi_meta,
)

MAX_DEPENDENCIES = 400
JOBS = 8
# What the sandbox runs PyPI servers on (acquire/sandbox.py: UV_IMAGE).
PYTHON_ENVIRONMENT = {
    "python_version": "3.12", "python_full_version": "3.12.0", "implementation_name": "cpython",
    "implementation_version": "3.12.0", "platform_python_implementation": "CPython",
    "sys_platform": "linux", "platform_system": "Linux", "os_name": "posix",
    "platform_machine": "x86_64", "platform_release": "", "platform_version": "",
}  # fmt: skip
_EXTERNAL = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?:)|^[\w.-]+/[\w.-]+(#.*)?$")
_LOCAL = ("file:", "link:", "workspace:", "portal:")
# Node's core modules: listing one as a dependency is a mistake (calibration: "worker_threads"),
# not an opening, since npm won't let anyone publish these names.
NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
})  # fmt: skip

Archive = Callable[[str, str], Awaitable[bytes]]  # url, expected hash -> bytes


def _npm_spec(name: str, spec: str) -> tuple[str, str]:
    """npm aliases: "string-width-cjs": "npm:string-width@^4.2.0" installs string-width."""
    if spec.startswith("npm:"):
        target = spec[4:]
        at = target.find("@", 1)
        return (target[:at], target[at + 1 :] or "latest") if at > 0 else (target, "latest")
    return name, spec


async def _npm_dependency(name: str, spec: str, via: list[str], get: GetJson,
                          registry: str | None) -> PackageMeta | None:  # fmt: skip
    if spec.startswith(_LOCAL):
        return None  # a workspace link: only meaningful inside the package's own repository
    if _EXTERNAL.match(spec):
        return PackageMeta(registry="npm", name=name, via=via, external=spec)
    real, version_spec = _npm_spec(name, spec)
    ref = PackageRef("npm", real, version_spec or None, "dependency", 0)
    try:
        meta = await npm_meta(ref, None, get, registry)
    except NotFound:
        if real in NODE_BUILTINS:
            return None  # a broken dependency, but npm refuses to publish core-module names
        return PackageMeta(registry="npm", name=real, via=via, removed=True)
    return meta.model_copy(update={"via": via})


def python_requires(metadata: str, extras: frozenset[str] = frozenset()) -> dict[str, str]:
    """Requires-Dist that apply on the sandbox's Python with these extras: name -> specifier
    (or "@ <url>" for a direct URL requirement)."""
    out: dict[str, str] = {}
    for line in metadata.splitlines():
        if not line.lower().startswith("requires-dist:"):
            continue
        try:
            req = Requirement(line.split(":", 1)[1].strip())
        except InvalidRequirement:
            continue
        if req.marker is not None:
            try:
                applies = any(req.marker.evaluate({**PYTHON_ENVIRONMENT, "extra": extra})
                              for extra in ("", *extras))  # fmt: skip
            except (InvalidMarker, ValueError):
                applies = False
            if not applies:
                continue
        spec = f"@ {req.url}" if req.url else str(req.specifier)
        if req.extras:
            spec = f"[{','.join(sorted(req.extras))}]{spec}"
        out[req.name] = spec
    return out


def _split_extras(spec: str) -> tuple[frozenset[str], str]:
    if spec.startswith("["):
        extras, _, rest = spec[1:].partition("]")
        return frozenset(e.strip() for e in extras.split(",") if e.strip()), rest
    return frozenset(), spec


async def _python_requires(meta: PackageMeta, archive: Archive,
                           extras: frozenset[str]) -> dict[str, str]:  # fmt: skip
    if not meta.archive_url or not meta.archive_hash:
        return {}
    if meta.metadata_hash:  # a few KB instead of the whole wheel
        text: str | None = (await archive(f"{meta.archive_url}.metadata", meta.metadata_hash)
                            ).decode("utf-8", "replace")  # fmt: skip
    else:
        data = await archive(meta.archive_url, meta.archive_hash)
        text = python_metadata(data, meta.archive_url.rsplit("/", 1)[-1])
    return python_requires(text, extras) if text else {}


async def _pypi_dependency(name: str, spec: str, via: list[str], get: GetJson, index: str | None,
                           archive: Archive) -> PackageMeta | None:  # fmt: skip
    extras, spec = _split_extras(spec)
    if spec.startswith("@ "):
        return PackageMeta(registry="pypi", name=name, via=via, external=spec[2:])
    ref = PackageRef("pypi", name, spec or None, "dependency", 0)
    try:
        meta = await pypi_meta(ref, None, get, index)
    except NotFound:
        return PackageMeta(registry="pypi", name=name, via=via, removed=True)
    requires = await _python_requires(meta, archive, extras)
    return meta.model_copy(update={"via": via, "requires": requires})


async def resolve(root: PackageMeta, ref: PackageRef, get: GetJson, archive: Archive, *,
                  npm: str | None = None, pypi: str | None = None) -> PackageMeta:  # fmt: skip
    """`root` with `dependencies` (and, for PyPI, its own `requires`) filled in."""
    if root.removed or root.registry not in ("npm", "pypi"):
        return root
    skipped: list[str] = []
    if root.registry == "pypi":
        extras = frozenset(e.strip() for e in ref.extras.strip("[]").split(",") if e.strip())
        try:
            root = root.model_copy(update={"requires": await _python_requires(root, archive,
                                                                              extras)})  # fmt: skip
        except Exception as exc:  # the archive is also read for source; a failure is a note
            skipped.append(f"{root.name}: couldn't read its requirements: {exc}")
    found: dict[tuple[str, str], PackageMeta] = {}
    level = [(name, spec, [root.name]) for name, spec in sorted(root.requires.items())]
    seen_specs: set[tuple[str, str]] = set()
    limiter = anyio.CapacityLimiter(JOBS)

    while level and len(found) < MAX_DEPENDENCIES:
        results: list[PackageMeta | None] = [None] * len(level)

        async def one(i: int, name: str, spec: str, via: list[str],
                      results: list[PackageMeta | None] = results) -> None:  # fmt: skip
            async with limiter:
                try:
                    if root.registry == "npm":
                        results[i] = await _npm_dependency(name, spec, via, get, npm)
                    else:
                        results[i] = await _pypi_dependency(name, spec, via, get, pypi, archive)
                except (RegistryError, OSError, ValueError) as exc:
                    skipped.append(f"{name}@{spec}: {exc}")
                except Exception as exc:  # e.g. an archive download failing
                    skipped.append(f"{name}@{spec}: {type(exc).__name__}: {exc}")

        async with anyio.create_task_group() as group:
            for i, (name, spec, via) in enumerate(level):
                group.start_soon(one, i, name, spec, via)
        following: list[tuple[str, str, list[str]]] = []
        for meta in results:
            if meta is None:
                continue
            key = (meta.name, meta.version or meta.external or "")
            if key in found:
                continue
            found[key] = meta
            for name, spec in sorted(meta.requires.items()):
                if (name, spec) not in seen_specs:
                    seen_specs.add((name, spec))
                    following.append((name, spec, [*meta.via, meta.name]))
        level = following
    if level:
        skipped.append(f"stopped after {MAX_DEPENDENCIES} packages")
    dependencies = list(found.values())[:MAX_DEPENDENCIES]
    return root.model_copy(update={"dependencies": dependencies, "dependencies_skipped": skipped})


def flatten(packages: list[PackageMeta]) -> list[PackageMeta]:
    """Top-level packages and their dependencies, for OSV."""
    return [d for p in packages for d in [p, *(p.dependencies or [])]]


def assign(packages: list[PackageMeta], values: list[Any], field: str) -> list[PackageMeta]:
    """Inverse of flatten: set `field` on each package and dependency, in flatten's order."""
    out: list[PackageMeta] = []
    it = iter(values)
    for p in packages:
        top = p.model_copy(update={field: next(it)})
        deps = [d.model_copy(update={field: next(it)}) for d in (p.dependencies or [])]
        out.append(top.model_copy(update={"dependencies": deps}) if p.dependencies is not None
                   else top)  # fmt: skip
    return out
