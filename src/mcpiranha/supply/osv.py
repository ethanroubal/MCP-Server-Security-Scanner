"""Known vulnerabilities and malicious-package reports from OSV (osv.dev).

One batch query finds the advisory ids for every (package, version); each advisory's details are
then fetched once. OSV includes GitHub advisories, PyPA's database and the OpenSSF malicious
packages list (ids starting MAL-), which covers packages like postmark-mcp.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, cast

from mcpiranha.core.models import PackageMeta, Severity, Vulnerability
from mcpiranha.supply.registry import obj

OSV_API = "https://api.osv.dev/v1"
ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}
_GHSA_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
}  # fmt: skip

PostJson = Callable[[str, Any], Awaitable[Any]]
GetJson = Callable[[str, dict[str, str]], Awaitable[Any]]


def osv_api() -> str:
    return os.environ.get("MCPIRANHA_OSV_API", OSV_API).rstrip("/")


def _severity(advisory: dict[str, Any]) -> Severity | None:
    if str(advisory.get("id", "")).startswith("MAL-"):
        return Severity.CRITICAL
    specific = cast(dict[str, Any], advisory.get("database_specific") or {})
    label = str(specific.get("severity") or "").upper()
    return _GHSA_SEVERITY.get(label)


def _fixed(advisory: dict[str, Any], name: str) -> list[str]:
    fixed: list[str] = []
    for affected in cast(list[dict[str, Any]], advisory.get("affected") or []):
        package = cast(dict[str, Any], affected.get("package") or {})
        if str(package.get("name", "")).lower() != name.lower():
            continue
        for r in cast(list[dict[str, Any]], affected.get("ranges") or []):
            fixed += [str(e["fixed"]) for e in cast(list[dict[str, Any]], r.get("events") or [])
                      if "fixed" in e]  # fmt: skip
    return list(dict.fromkeys(fixed))


async def vulnerabilities(
    packages: Sequence[PackageMeta], post: PostJson, get: GetJson
) -> list[list[Vulnerability]]:
    """Advisories for each package's version, in input order."""
    # Without a version (a removed package nobody pinned), OSV returns every advisory.
    queries = [{"package": {"name": p.name, "ecosystem": ECOSYSTEM[p.registry]},
                **({"version": p.version} if p.version else {})} for p in packages]  # fmt: skip
    if not queries:
        return []
    answer = await post(f"{osv_api()}/querybatch", {"queries": queries})
    results = cast(list[dict[str, Any]], obj(answer).get("results") or [])
    out: list[list[Vulnerability]] = []
    for package, result in zip(packages, results, strict=True):
        found: list[Vulnerability] = []
        for item in cast(list[dict[str, Any]], result.get("vulns") or []):
            advisory = obj(await get(f"{osv_api()}/vulns/{item['id']}", {}))
            found.append(Vulnerability(
                id=str(item["id"]),
                aliases=[str(a) for a in cast(list[Any], advisory.get("aliases") or [])],
                summary=str(advisory["summary"]) if advisory.get("summary") else None,
                severity=_severity({"id": item["id"], **advisory}),
                fixed=_fixed(advisory, package.name),
            ))  # fmt: skip
        out.append(found)
    return out
