"""Supply-chain lookups (mcpiranha.supply) against a fake registry, and the MCP-SC rules."""

from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import pytest

from mcpiranha.core.launch import package_ref
from mcpiranha.core.models import (
    Launch,
    Origin,
    PackageMeta,
    ReleaseInfo,
    ServerSnapshot,
    Severity,
    Vulnerability,
)
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.supply import enrich
from mcpiranha.supply.registry import npm_meta, npm_resolve, parse_semver, pypi_meta

NOW = datetime(2026, 10, 22, tzinfo=UTC)
SC_RULES = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-SC")]


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def _npm_release(version: str, user: str, *, scripts: dict[str, str] | None = None,
                 provenance: bool = False) -> dict[str, Any]:  # fmt: skip
    dist: dict[str, Any] = {"tarball": "https://example.invalid/t.tgz"}
    if provenance:
        dist["attestations"] = {"url": "https://example.invalid/a"}
    return {"name": "pkg", "version": version, "_npmUser": {"name": user}, "dist": dist,
            "scripts": scripts or {}, "maintainers": [{"name": "alice"}]}  # fmt: skip


PACKUMENT: dict[str, Any] = {
    "dist-tags": {"latest": "1.2.0", "next": "2.0.0-beta.1"},
    "time": {
        "created": _iso(400),
        "1.0.0": _iso(400),
        "1.1.0": _iso(100),
        "1.2.0": _iso(1),
        "2.0.0-beta.1": _iso(0.5),
    },
    "versions": {
        "1.0.0": _npm_release("1.0.0", "alice", provenance=True),
        "1.1.0": _npm_release("1.1.0", "alice", provenance=True),
        "1.2.0": _npm_release(
            "1.2.0", "mallory", scripts={"postinstall": "node x.js", "test": "vitest"}
        ),
        "2.0.0-beta.1": _npm_release("2.0.0-beta.1", "alice"),
    },
}


class FakeRegistry:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.posted: list[Any] = []
        self.archives: dict[str, bytes] = {}

    async def get(self, url: str, headers: dict[str, str]) -> Any:
        return self.responses.get(url)

    async def archive(self, url: str, expected_hash: str) -> bytes:
        return self.archives[url]

    async def post(self, url: str, body: Any) -> Any:
        self.posted.append(body)
        return self.responses.get(url, {"results": [{} for _ in body["queries"]]})


def _snapshot(*args: str, command: str = "npx") -> ServerSnapshot:
    return ServerSnapshot(
        id="t:project:s",
        name="s",
        origin=Origin(kind="config", client="t", ref="s"),
        launch=Launch(transport="stdio", command=command, args=list(args)),
        tools_listed=False,
    )


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        (None, ("1.2.0", "latest")),
        ("latest", ("1.2.0", "latest")),
        ("next", ("2.0.0-beta.1", "range")),
        ("1.0.0", ("1.0.0", "exact")),
        ("^1.0.0", ("1.2.0", "range")),  # `latest` satisfies it: npm takes it
        ("~1.0.0", ("1.0.0", "range")),
        ("1.1.x", ("1.1.0", "range")),
        ("<1.2.0", ("1.1.0", "range")),
        (">=1.0.0 <1.1.0 || 1.2.0", ("1.2.0", "range")),
        ("1.0.0 - 1.1.0", ("1.1.0", "range")),
        ("*", ("1.2.0", "range")),
    ],
)
def test_npm_resolves_like_npx(spec: str | None, expected: tuple[str, str]) -> None:
    versions = list(PACKUMENT["versions"])
    assert npm_resolve(spec, versions, PACKUMENT["dist-tags"]) == expected


def test_prereleases_need_to_be_asked_for() -> None:
    assert npm_resolve(">=1.0.0", ["1.0.0", "2.0.0-rc.1"], {"latest": "1.0.0"}) == (
        "1.0.0",
        "range",
    )
    assert parse_semver("2.0.0-rc.1") is not None and parse_semver("not.a.version") is None


def test_npm_meta_collects_the_facts() -> None:
    ref = package_ref(_snapshot("-y", "pkg").launch)
    assert ref is not None
    fake = FakeRegistry({"https://registry.npmjs.org/pkg": PACKUMENT})
    meta = anyio.run(npm_meta, ref, None, fake.get)
    assert (meta.version, meta.resolution, meta.publisher) == ("1.2.0", "latest", "mallory")
    assert meta.install_scripts == ["postinstall: node x.js"]  # not `test`
    assert meta.provenance is False and meta.previous is not None
    assert (meta.previous.version, meta.previous.provenance) == ("1.1.0", True)
    assert meta.earlier_publishers == ["alice"]


def test_installed_version_wins_over_the_spec() -> None:
    ref = package_ref(_snapshot("-y", "pkg").launch)
    assert ref is not None
    fake = FakeRegistry({"https://registry.npmjs.org/pkg": PACKUMENT})
    meta = anyio.run(npm_meta, ref, "1.1.0", fake.get)
    assert (meta.version, meta.resolution, meta.publisher) == ("1.1.0", "installed", "alice")


def _pypi_file(name: str, days_ago: float, provenance: str | None = None) -> dict[str, Any]:
    return {"filename": name, "upload-time": _iso(days_ago), "provenance": provenance,
            "yanked": False}  # fmt: skip


def test_pypi_meta_from_the_simple_json_api() -> None:
    prov = "https://pypi.org/integrity/tool/1.0/tool-1.0-py3-none-any.whl/provenance"
    index = {"files": [
        _pypi_file("tool-1.0-py3-none-any.whl", 50, prov),
        _pypi_file("tool-1.0.tar.gz", 50),
        _pypi_file("tool-1.1.tar.gz", 1),
        _pypi_file("tool-2.0a1.tar.gz", 0.5),
    ]}  # fmt: skip
    bundle = {"attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": "a/tool"}}]}
    fake = FakeRegistry({"https://pypi.org/simple/tool/": index, prov: bundle})
    ref = package_ref(_snapshot("tool", command="uvx").launch)
    assert ref is not None
    meta = anyio.run(pypi_meta, ref, None, fake.get)
    assert (meta.version, meta.resolution) == ("1.1", "latest")  # not the prerelease
    assert meta.install_scripts == ["setup.py (sdist only: runs at install)"]
    assert meta.provenance is False and meta.previous is not None
    assert meta.previous.provenance_source == "GitHub:a/tool"
    assert meta.previous.install_scripts == []


def test_enrich_fills_packages_and_osv_and_survives_failures() -> None:
    fixed = {"events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}
    advisory = {
        "summary": "bad",
        "aliases": ["CVE-2026-1"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "pkg"}, "ranges": [fixed]}],
    }
    fake = FakeRegistry({
        "https://registry.npmjs.org/pkg": PACKUMENT,
        "https://api.osv.dev/v1/querybatch": {"results": [{"vulns": [{"id": "GHSA-x"}]}, {}]},
        "https://api.osv.dev/v1/vulns/GHSA-x": advisory,
    })  # fmt: skip
    snapshots = [_snapshot("-y", "pkg"), _snapshot("-y", "gone@1.0.0"),
                 _snapshot("run", "-i", "image", command="docker")]  # fmt: skip
    out, warnings = anyio.run(lambda: enrich(snapshots, http=fake))
    assert warnings == []
    first, gone, docker = (s.package for s in out)
    assert first is not None and first.vulnerabilities is not None and first.checked_at
    [vuln] = first.vulnerabilities
    assert (vuln.id, vuln.severity, vuln.fixed) == ("GHSA-x", Severity.HIGH, ["1.3.0"])
    assert gone is not None and gone.removed and gone.version == "1.0.0"
    assert docker is None
    assert fake.posted[0]["queries"][1] == {"package": {"name": "gone", "ecosystem": "npm"},
                                            "version": "1.0.0"}  # fmt: skip


def _found(**package: Any) -> dict[str, Severity]:
    meta = PackageMeta(registry="npm", name="pkg", version="1.2.0", checked_at=NOW, **package)
    snapshot = _snapshot("-y", "pkg").model_copy(update={"package": meta})
    return {f.rule_id: f.severity for f in scan([snapshot], SC_RULES).findings}


def test_rules_only_judge_looked_up_packages() -> None:
    meta = PackageMeta(
        registry="npm", name="pkg", version="1", deprecated="x", install_scripts=["a"]
    )
    snapshot = _snapshot("-y", "pkg").model_copy(update={"package": meta})
    assert scan([snapshot], SC_RULES).findings == []  # no checked_at: --offline or --connect only


def test_vulnerabilities_and_malware() -> None:
    vulns = [Vulnerability(id="GHSA-1", severity=Severity.MEDIUM),
             Vulnerability(id="GHSA-2", severity=Severity.HIGH)]  # fmt: skip
    assert _found(vulnerabilities=vulns) == {"MCP-SC-001": Severity.HIGH}
    assert _found(vulnerabilities=[Vulnerability(id="MAL-2025-1")]) == {
        "MCP-SC-001": Severity.CRITICAL
    }
    assert _found(vulnerabilities=[]) == {}


def test_install_scripts_worst_when_just_added() -> None:
    scripts = ["postinstall: node x.js"]
    assert _found(install_scripts=scripts) == {"MCP-SC-002": Severity.LOW}
    previous = ReleaseInfo(version="1.1.0")
    assert _found(install_scripts=scripts, previous=previous) == {"MCP-SC-002": Severity.HIGH}


def test_provenance_lost_or_moved() -> None:
    had = ReleaseInfo(version="1.1.0", provenance=True, provenance_source="GitHub:a/tool")
    assert _found(provenance=False, previous=had) == {"MCP-SC-003": Severity.HIGH}
    assert _found(provenance=True, provenance_source="GitHub:evil/tool", previous=had) == {
        "MCP-SC-003": Severity.HIGH
    }
    assert _found(provenance=True, provenance_source="GitHub:a/tool", previous=had) == {}
    assert _found(provenance=True, provenance_source="GitHub:a/renamed", previous=had) == {}
    assert _found(provenance=False, previous=ReleaseInfo(version="1.1.0")) == {}  # never had it


def test_new_packages_and_releases() -> None:
    assert _found(created_at=NOW - timedelta(days=3)) == {"MCP-SC-004": Severity.MEDIUM}
    old = NOW - timedelta(days=400)
    fresh = {"created_at": old, "published_at": NOW - timedelta(hours=5)}
    assert _found(**fresh, resolution="latest") == {}  # MCP servers release almost daily
    assert _found(created_at=old, published_at=NOW - timedelta(days=30)) == {}


def test_new_publisher() -> None:
    assert _found(publisher="mallory", earlier_publishers=["alice"]) == {
        "MCP-SC-005": Severity.MEDIUM
    }
    assert _found(publisher="alice", earlier_publishers=["bob", "alice"]) == {}
    assert _found(publisher="trusted publishing (github)", earlier_publishers=["alice"]) == {}
    assert _found(publisher="alice", earlier_publishers=[]) == {}  # first release


def test_deprecated_and_removed() -> None:
    assert _found(deprecated="use pkg2") == {"MCP-SC-006": Severity.LOW}
    assert _found(removed=True) == {"MCP-SC-006": Severity.HIGH}
    assert _found(yanked="broken") == {"MCP-SC-006": Severity.MEDIUM}


def test_coverage_records_registry_and_osv_failures() -> None:
    from mcpiranha.core.coverage import summarize
    from mcpiranha.supply.registry import RegistryError

    class BrokenOSV(FakeRegistry):
        async def post(self, url: str, body: Any) -> Any:
            raise RegistryError("OSV unavailable")

    enriched, warnings = anyio.run(
        lambda: enrich(
            [_snapshot("pkg@1.0.0")],
            http=BrokenOSV({"https://registry.npmjs.org/pkg": PACKUMENT}),
        )
    )
    assert warnings and "OSV" in warnings[0]
    assert summarize(enriched[0])["package"].status == "partial"

    class BrokenRegistry(FakeRegistry):
        async def get(self, url: str, headers: dict[str, str]) -> Any:
            raise RegistryError("registry unavailable")

    enriched, warnings = anyio.run(
        lambda: enrich(
            [_snapshot("pkg@1.0.0")],
            http=BrokenRegistry({}),
        )
    )
    assert warnings
    assert summarize(enriched[0])["package"].status == "failed"
    assert summarize(enriched[0])["dependencies"].status == "failed"
