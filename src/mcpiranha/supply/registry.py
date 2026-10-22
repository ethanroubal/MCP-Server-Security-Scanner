"""npm and PyPI metadata: which release a launch config runs, and facts to judge it by.

npm: the packument (`GET {registry}/{name}`) has every release's publish time, publishing account,
lifecycle scripts and provenance attestation. PyPI: the JSON simple API (PEP 691/700/740) has
every file's upload time and provenance URL; the provenance itself names the publishing
repository. `MCPIRANHA_NPM_REGISTRY` / `MCPIRANHA_PYPI_INDEX` point at another registry (a
mirror, or the zoo's local ones).
"""

from __future__ import annotations

import html
import os
import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, Literal, cast
from urllib.parse import quote

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from mcpiranha.core.launch import PackageRef
from mcpiranha.core.models import PackageMeta, ReleaseInfo

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_INDEX = "https://pypi.org/simple"
# npm lifecycle scripts that run when the package is installed as a dependency (`prepare` and
# the rest only run in the package's own checkout).
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
EARLIER_RELEASES = 10  # how far back "has this account published before" looks

Resolution = Literal["exact", "range", "latest", "installed"]
GetJson = Callable[[str, dict[str, str]], Awaitable[Any]]  # url, headers -> parsed JSON; None = 404


class RegistryError(Exception):
    pass


class NotFound(RegistryError):
    """The registry has no such package: taken down (often for malware), or a typo."""


def npm_registry() -> str:
    return os.environ.get("MCPIRANHA_NPM_REGISTRY", NPM_REGISTRY).rstrip("/")


def pypi_index() -> str:
    return os.environ.get("MCPIRANHA_PYPI_INDEX", PYPI_INDEX).rstrip("/")


def obj(value: Any) -> dict[str, Any]:
    """A JSON object, or {} for anything else (None from a 404 included)."""
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# --- npm ------------------------------------------------------------------------------------------

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_PARTIAL = re.compile(r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?$")
SemVer = tuple[int, int, int, tuple[tuple[int, int | str], ...]]


def parse_semver(text: str) -> SemVer | None:
    m = _SEMVER.match(text.strip())
    if not m:
        return None
    pre = tuple((0, int(p)) if p.isdigit() else (1, p) for p in (m.group(4) or "").split(".") if p)
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _key(v: SemVer) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
    major, minor, patch, pre = v
    return major, minor, patch, 0 if pre else 1, pre  # a prerelease sorts before its release


def _comparators(part: str) -> list[tuple[str, SemVer]] | None:
    """One `||` alternative of an npm range as (operator, version) pairs; None if unsupported."""
    part = re.sub(r"(<=|>=|<|>|=|\^|~)\s+", r"\1", part.strip())
    if m := re.match(r"^(\S+)\s+-\s+(\S+)$", part):  # hyphen range
        start, end = parse_semver(m.group(1)), parse_semver(m.group(2))
        return [(">=", start), ("<=", end)] if start and end else None
    out: list[tuple[str, SemVer]] = []
    for token in part.split() or ["*"]:
        op_match = re.match(r"^(<=|>=|<|>|=|\^|~)?(.*)$", token)
        op, rest = (op_match.group(1) or "", op_match.group(2)) if op_match else ("", token)
        m = _PARTIAL.match(rest)
        if not m:
            return None
        nums = [None if g is None or g in "xX*" else int(g) for g in m.groups()[:3]]
        pre = tuple((0, int(p)) if p.isdigit() else (1, p)
                    for p in (m.group(4) or "").split(".") if p)  # fmt: skip
        major, minor, patch = nums
        if major is None:
            continue  # "*": anything
        low: SemVer = (major, minor or 0, patch or 0, pre)
        if op in ("", "=") and minor is not None and patch is not None:
            out.append(("=", low))
        elif op in ("", "=", "~") and (op == "~" or minor is None or patch is None):
            high = (major + 1, 0, 0, ()) if minor is None else (major, minor + 1, 0, ())
            out += [(">=", low), ("<", high)]
        elif op == "^":
            if major > 0 or minor is None:
                high = (major + 1, 0, 0, ())
            elif minor > 0 or patch is None:
                high = (0, minor + 1, 0, ())
            else:
                high = (0, 0, (patch or 0) + 1, ())
            out += [(">=", low), ("<", high)]
        else:
            out.append((op, low))
    return out


def satisfies(version: SemVer, comparators: list[tuple[str, SemVer]]) -> bool:
    k = _key(version)
    for op, bound in comparators:
        b = _key(bound)
        ok = {"=": k == b, ">=": k >= b, ">": k > b, "<=": k <= b, "<": k < b}[op]
        if not ok:
            return False
    # npm: a prerelease only matches a range that names a prerelease of the same version
    return not version[3] or any(b[3] and b[:3] == version[:3] for _, b in comparators)


def npm_resolve(
    spec: str | None, versions: list[str], tags: dict[str, str]
) -> tuple[str, Resolution]:
    """(version, how) the way npx picks it: a dist-tag, an exact version, or the highest match."""
    if spec is None or spec in tags:
        version = tags.get(spec or "latest")
        if version is None:
            raise RegistryError("no `latest` dist-tag")
        return version, "latest" if spec in (None, "latest") else "range"
    if parse_semver(spec) and spec.lstrip("v") in versions:
        return spec.lstrip("v"), "exact"
    alternatives = [_comparators(p) for p in spec.split("||")]
    if any(a is None for a in alternatives):
        raise RegistryError(f"unsupported version range {spec!r}")
    matching = [
        (parse_semver(v), v) for v in versions
        if (sv := parse_semver(v)) and any(satisfies(sv, a) for a in alternatives if a is not None)
    ]  # fmt: skip
    latest = tags.get("latest")
    # npm prefers the `latest` tag when it satisfies the range
    if latest in {v for _, v in matching}:
        return latest, "range"
    if not matching:
        raise RegistryError(f"no release matches {spec!r}")
    return max(matching, key=lambda m: _key(cast(SemVer, m[0])))[1], "range"


def _npm_release(version: str, data: dict[str, Any], times: dict[str, Any]) -> ReleaseInfo:
    scripts = cast(dict[str, Any], data.get("scripts") or {})
    found = [f"{k}: {scripts[k]}" for k in INSTALL_SCRIPTS if isinstance(scripts.get(k), str)]
    if data.get("gypfile") and "install" not in scripts:
        found.append("install: node-gyp rebuild (implicit, binding.gyp)")
    user = cast(dict[str, Any], data.get("_npmUser") or {})
    dist = cast(dict[str, Any], data.get("dist") or {})
    trusted = cast(dict[str, Any], user.get("trustedPublisher") or {})
    publisher = (f"trusted publishing ({trusted.get('id', 'ci')})" if trusted
                 else str(user["name"]) if user.get("name") else None)  # fmt: skip
    return ReleaseInfo(
        version=version,
        published_at=_time(times.get(version)),
        publisher=publisher,
        install_scripts=found,
        provenance=bool(dist.get("attestations")),
        provenance_source=None,
    )


async def npm_meta(
    ref: PackageRef, version: str | None, get: GetJson, registry: str | None = None
) -> PackageMeta:
    """`version`: the one --connect installed; else resolve `ref.spec` against the registry."""
    base = (registry or npm_registry()).rstrip("/")
    data = obj(await get(f"{base}/{quote(ref.name, safe='@')}", {}))
    if not isinstance(data.get("versions"), dict):
        raise NotFound(f"npm has no package {ref.name!r}")
    releases = cast(dict[str, dict[str, Any]], data["versions"])
    times = cast(dict[str, Any], data.get("time") or {})
    tags = {k: str(v) for k, v in cast(dict[str, Any], data.get("dist-tags") or {}).items()}
    how: Resolution
    if version is not None:
        how = "installed"
    else:
        version, how = npm_resolve(ref.spec, list(releases), tags)
    if version not in releases:
        raise RegistryError(f"npm has no release {version} of {ref.name}")

    current = _npm_release(version, releases[version], times)
    stable = [v for v in releases if (sv := parse_semver(v)) and not sv[3]]
    cutoff = current.published_at
    published = sorted(
        (t, v) for v in stable
        if v != version and (t := _time(times.get(v))) and (cutoff is None or t < cutoff)
    )  # fmt: skip
    earlier = [v for _, v in published][-EARLIER_RELEASES:]
    previous = _npm_release(earlier[-1], releases[earlier[-1]], times) if earlier else None
    publishers = [
        r.publisher for v in earlier if (r := _npm_release(v, releases[v], times)).publisher
    ]
    people = cast(list[dict[str, Any]], releases[version].get("maintainers") or [])
    maintainers = [str(m.get("name")) for m in people]
    deprecated = releases[version].get("deprecated")
    return PackageMeta(
        registry="npm", name=ref.name, version=version, resolution=how,
        install_scripts=current.install_scripts, published_at=current.published_at,
        maintainers=maintainers, created_at=_time(times.get("created")),
        publisher=current.publisher, provenance=current.provenance,
        deprecated=str(deprecated) if deprecated else None, previous=previous,
        earlier_publishers=list(dict.fromkeys(publishers)),
    )  # fmt: skip


# --- PyPI -----------------------------------------------------------------------------------------

SIMPLE_JSON = {"Accept": "application/vnd.pypi.simple.v1+json"}
_DIST_VERSION = re.compile(r"^[A-Za-z0-9_.]+?-(?P<v>\d[^-]*?)(?:\.tar\.gz|\.zip|-.*\.whl)$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _file_version(filename: str) -> str | None:
    m = _DIST_VERSION.match(filename)
    return m.group("v") if m else None


async def _pypi_publisher(url: str | None, get: GetJson) -> str | None:
    if not url:
        return None
    data = obj(await get(url, {"Accept": "application/json"}))
    bundles = cast(list[dict[str, Any]], data.get("attestation_bundles") or [])
    for bundle in bundles:
        publisher = cast(dict[str, Any], bundle.get("publisher") or {})
        if publisher.get("repository"):
            return f"{publisher.get('kind', '')}:{publisher['repository']}".lstrip(":")
    return None


_ANCHOR = re.compile(r"<a\s+([^>]*)>([^<]+)</a>", re.IGNORECASE)
_ATTR = re.compile(r'([\w-]+)\s*=\s*"([^"]*)"')


def simple_html_files(page: str) -> list[dict[str, Any]]:
    """Files from a PEP 503 HTML index page, in the shape of the JSON API's (no upload times)."""
    files: list[dict[str, Any]] = []
    for attrs, text in _ANCHOR.findall(page):
        found = {k.lower(): html.unescape(v) for k, v in _ATTR.findall(attrs)}
        entry: dict[str, Any] = {"filename": html.unescape(text).strip(),
                                 "url": found.get("href", ""),
                                 "yanked": found.get("data-yanked", "")
                                 if "data-yanked" in found else False}  # fmt: skip
        if "data-provenance" in found:
            entry["provenance"] = found["data-provenance"]
        files.append(entry)
    return files


async def pypi_meta(
    ref: PackageRef, version: str | None, get: GetJson, index: str | None = None
) -> PackageMeta:
    base = (index or pypi_index()).rstrip("/")
    raw = await get(f"{base}/{_normalize(ref.name)}/", SIMPLE_JSON)
    data = {"files": simple_html_files(raw)} if isinstance(raw, str) else obj(raw)
    if not isinstance(data.get("files"), list):
        raise NotFound(f"PyPI has no project {ref.name!r}")
    # PEP 592: installers skip yanked releases, unless pinned to exactly that version
    all_versions: dict[str, list[dict[str, Any]]] = {}
    for f in cast(list[dict[str, Any]], data["files"]):
        if v := _file_version(str(f.get("filename", ""))):
            all_versions.setdefault(v, []).append(f)
    by_version = {v: live for v, fs in all_versions.items()
                  if (live := [f for f in fs if not f.get("yanked")])}  # fmt: skip

    def parsed(v: str) -> Version | None:
        try:
            return Version(v)
        except InvalidVersion:
            return None

    how: Resolution = "installed"
    if version is None:
        spec = (ref.spec or "").strip()
        spec = "==" + spec[1:] if spec.startswith("@") else spec
        try:
            specifier = SpecifierSet(spec)
        except InvalidSpecifier as exc:
            raise RegistryError(f"unsupported version specifier {spec!r}") from exc
        # like pip and uv: prereleases only when the specifier names one, or nothing else fits
        pre = bool(specifier.prereleases)
        candidates = [(pv, v) for v in by_version
                      if (pv := parsed(v)) and specifier.contains(pv, prereleases=pre)]  # fmt: skip
        candidates = candidates or [(pv, v) for v in by_version
                                    if (pv := parsed(v)) and pv in specifier]  # fmt: skip
        pinned = spec.removeprefix("==").strip()
        if not candidates and ref.pinned and pinned in all_versions:
            candidates = [(Version(pinned), pinned)]
        if not candidates:
            raise RegistryError(f"no release of {ref.name} matches {spec or 'any version'!r}")
        version = max(candidates)[1]
        how = "latest" if not spec else "exact" if ref.pinned else "range"
    if version not in all_versions:
        raise RegistryError(f"PyPI has no files for {ref.name} {version}")
    yanked: str | None = None
    if version not in by_version:
        reason = all_versions[version][0].get("yanked")
        yanked = reason if isinstance(reason, str) and reason else "no reason given"
        by_version[version] = all_versions[version]

    def release(v: str) -> ReleaseInfo:
        rel_files = by_version[v]
        uploads = [t for f in rel_files if (t := _time(f.get("upload-time")))]
        has_wheel = any(str(f.get("filename", "")).endswith(".whl") for f in rel_files)
        provenance = [f.get("provenance") for f in rel_files]
        return ReleaseInfo(
            version=v,
            published_at=min(uploads) if uploads else None,
            install_scripts=[] if has_wheel else ["setup.py (sdist only: runs at install)"],
            provenance=any(provenance) if "provenance" in rel_files[0] else None,
        )

    current = release(version)
    pv = parsed(version)
    earlier = sorted(
        (p, v) for v in by_version
        if (p := parsed(v)) and not p.is_prerelease and pv is not None and p < pv
    )  # fmt: skip
    previous = release(earlier[-1][1]) if earlier else None
    for info in filter(None, [current, previous]):
        if info.provenance:
            url = next((f.get("provenance") for f in by_version[info.version]
                        if f.get("provenance")), None)  # fmt: skip
            info.provenance_source = await _pypi_publisher(cast(str | None, url), get)
    first = [t for fs in by_version.values() for f in fs if (t := _time(f.get("upload-time")))]
    return PackageMeta(
        registry="pypi", name=ref.name, version=version, resolution=how,
        install_scripts=current.install_scripts, published_at=current.published_at,
        created_at=min(first) if first else None, provenance=current.provenance,
        provenance_source=current.provenance_source, previous=previous, yanked=yanked,
    )  # fmt: skip
