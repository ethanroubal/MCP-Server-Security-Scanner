"""Score mcpiranha against a corpus of known-bad servers (the zoo, `zoo/` in the repository).

Each sample is a directory with a `sample.yaml`: the servers to install together (client-config
entries), and the rules a correct scan must report. Samples whose attack the scanner can't see
yet carry a `gap` (why, and which phase closes it) instead: they are tracked, not failed, and
flagged for review once something does fire on them.

In `servers`, `${PYTHON}` is this interpreter and `${SAMPLE}` the sample's directory. Samples
are mcpiranha's own code and safe by construction, so they run on the host, like the tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

import anyio
import httpx2
import yaml

from mcpiranha.acquire import ConnectOptions, connect_all
from mcpiranha.core.lockfile import build_lockfile
from mcpiranha.core.models import Origin, ServerSnapshot, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.discovery import client_settings, to_launch
from mcpiranha.rules.base import Rule
from mcpiranha.source import collect
from mcpiranha.supply import PUBLIC, Registries, enrich

MANIFEST = "sample.yaml"
Status = Literal["pass", "fail", "gap", "gap-flagged", "skipped"]


class SampleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Sample:
    name: str
    directory: Path
    title: str
    attack: str
    servers: dict[str, dict[str, Any]]
    expect: frozenset[str]
    connect: bool = True
    gap: str | None = None
    source: str | None = None
    # Supply-chain samples: look packages up (in these registries, if given) before scanning.
    lookup: bool = False
    registries: Registries = PUBLIC
    # Rug pulls between sessions: these servers are locked first, then `servers` is scanned
    # against that lockfile.
    before: dict[str, dict[str, Any]] | None = None
    severity: dict[str, Severity] = field(default_factory=dict[str, Severity])  # minimums


@dataclass(slots=True)
class SampleResult:
    sample: Sample
    found: frozenset[str]
    worst: Severity | None
    errors: list[str] = field(default_factory=list[str])
    skipped: str | None = None  # why it couldn't run
    severities: dict[str, Severity] = field(default_factory=dict[str, Severity])  # worst per rule

    @property
    def too_weak(self) -> list[str]:
        """Expected rules that fired below the sample's minimum severity."""
        found = self.severities
        return [f"{rule} {found[rule].value} < {minimum.value}"
                for rule, minimum in self.sample.severity.items()
                if rule in found and found[rule].rank < minimum.rank]  # fmt: skip

    @property
    def missing(self) -> frozenset[str]:
        return self.sample.expect - self.found

    @property
    def extra(self) -> frozenset[str]:
        return self.found - self.sample.expect

    @property
    def status(self) -> Status:
        if self.skipped is not None:
            return "skipped"
        if self.sample.gap is not None:
            flagged = self.worst is not None and self.worst.rank >= Severity.MEDIUM.rank
            return "gap-flagged" if flagged else "gap"
        return "fail" if self.missing or self.errors or self.too_weak else "pass"


def _substitute(value: Any, variables: dict[str, str]) -> Any:
    if isinstance(value, str):
        for key, replacement in variables.items():
            value = value.replace(f"${{{key}}}", replacement)
        return value
    if isinstance(value, list):
        return [_substitute(v, variables) for v in cast(list[Any], value)]
    if isinstance(value, dict):
        return {k: _substitute(v, variables) for k, v in cast(dict[str, Any], value).items()}
    return value


def load_sample(directory: Path, python: str) -> Sample:
    path = directory / MANIFEST
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SampleError(f"{path}: {exc}") from exc
    data = cast(dict[str, Any], raw) if isinstance(raw, dict) else {}
    if not isinstance(data.get("servers"), dict):
        raise SampleError(f"{path}: needs a `servers` mapping")
    expect: Any = data.get("expect") or []
    if not isinstance(expect, list) or (not expect and not data.get("gap")):
        raise SampleError(f"{path}: `expect` must list rule ids, or `gap` say why it can't")
    variables = {"PYTHON": python, "SAMPLE": str(directory.resolve())}
    servers = _substitute(data["servers"], variables)
    before = (
        _substitute(data["before"], variables) if isinstance(data.get("before"), dict) else None
    )
    severity = {str(k): Severity(str(v)) for k, v in
                cast(dict[str, Any], data.get("severity") or {}).items()}  # fmt: skip
    registries = cast(dict[str, Any], data.get("registries") or {})
    return Sample(
        name=directory.name,
        directory=directory,
        title=str(data.get("title", directory.name)),
        attack=str(data.get("attack", "")),
        servers=cast(dict[str, dict[str, Any]], servers),
        expect=frozenset(str(r) for r in cast(list[Any], expect)),
        connect=bool(data.get("connect", True)),
        gap=str(data["gap"]).strip() if data.get("gap") else None,
        source=str(data["source"]) if data.get("source") else None,
        lookup=bool(data.get("lookup")) or bool(registries),
        registries=Registries(npm=registries.get("npm"), pypi=registries.get("pypi")),
        before=cast(dict[str, dict[str, Any]] | None, before),
        severity=severity,
    )


def load_samples(zoo: Path, python: str, only: Sequence[str] = ()) -> list[Sample]:
    """Every sample under `zoo` (a sample directory itself, or a tree of them)."""
    manifests = [zoo / MANIFEST] if (zoo / MANIFEST).is_file() else sorted(zoo.rglob(MANIFEST))
    samples = [load_sample(m.parent, python) for m in manifests]
    return [s for s in samples if not only or s.name in only]


def snapshots(
    sample: Sample, servers: dict[str, dict[str, Any]] | None = None
) -> list[ServerSnapshot]:
    """One client per sample, so its servers form one inventory (as if installed together)."""
    out: list[ServerSnapshot] = []
    for name, entry in (servers if servers is not None else sample.servers).items():
        launch = to_launch(entry)
        if launch is None:
            raise SampleError(f"{sample.name}: server {name!r} has neither a command nor a url")
        out.append(ServerSnapshot(
            id=f"bench:{sample.name}:{name}",
            name=name,
            origin=Origin(kind="config", client=f"bench:{sample.name}",
                          config_path=str(sample.directory / MANIFEST), ref=name),
            launch=launch,
            client_settings=client_settings(entry),
            tools_listed=False,
        ))  # fmt: skip
    return out


async def _unreachable(registries: Registries) -> str | None:
    urls = [u for u in (registries.npm, registries.pypi) if u]
    async with httpx2.AsyncClient(timeout=5) as client:
        for url in urls:
            try:
                await client.get(url)
            except httpx2.HTTPError:
                return f"{url} isn't running (start it: zoo/registries/registries.py up)"
    return None


async def run(samples: Sequence[Sample], rules: Sequence[Rule], *, timeout: float = 30.0,
              jobs: int = 4, lookup: bool = True) -> list[SampleResult]:  # fmt: skip
    """Connect to each sample's servers (`jobs` samples at a time) and scan each sample alone.
    `lookup`: run supply-chain samples' registry lookups; False skips those samples."""
    options = ConnectOptions(sandbox="none", timeout=timeout)
    limiter = anyio.CapacityLimiter(max(1, jobs))
    results: list[SampleResult | None] = [None] * len(samples)

    async def one(i: int, sample: Sample) -> None:
        snaps, errors = snapshots(sample), list[str]()
        if sample.lookup:
            why = "needs registry lookups (--offline)" if not lookup else (
                await _unreachable(sample.registries))  # fmt: skip
            if why:
                results[i] = SampleResult(sample, frozenset(), None, skipped=why)
                return
            snaps, errors = await enrich(snaps, registries=sample.registries)
        snaps, source_errors = await collect(snaps, download=sample.lookup)
        errors += source_errors
        lock = None
        if sample.connect:
            async with limiter:
                if sample.before is not None:
                    earlier, before_errors = await connect_all(
                        snapshots(sample, sample.before), options)  # fmt: skip
                    errors += before_errors
                    lock = build_lockfile(earlier)
                snaps, connect_errors = await connect_all(snaps, options)
            errors += connect_errors
        result = scan(snaps, list(rules), lock=lock)
        worst: dict[str, Severity] = {}
        for f in result.findings:
            if f.rule_id not in worst or f.severity.rank > worst[f.rule_id].rank:
                worst[f.rule_id] = f.severity
        results[i] = SampleResult(sample, frozenset(worst), result.max_severity(), errors,
                                  severities=worst)  # fmt: skip

    async with anyio.create_task_group() as group:
        for i, sample in enumerate(samples):
            group.start_soon(one, i, sample)
    return [r for r in results if r is not None]


THREATS = "threats.yaml"


@dataclass(frozen=True, slots=True)
class Threat:
    """One entry of the threat catalog (zoo/threats.yaml)."""

    id: str
    title: str
    status: str  # detected | partial | gap
    gap: str | None
    samples: tuple[str, ...]


def load_threats(zoo: Path) -> list[Threat]:
    """The catalog next to the samples, if there is one (a single sample's directory has none)."""
    path = zoo / THREATS
    if not path.is_file():
        return []
    entries = cast(list[dict[str, Any]], yaml.safe_load(path.read_text(encoding="utf-8")) or [])
    return [
        Threat(
            id=str(e["id"]),
            title=str(e.get("title", "")),
            status=str(e.get("status", "")),
            gap=" ".join(str(e["gap"]).split()) if e.get("gap") else None,
            samples=tuple(str(t)[4:] for t in e.get("tests", []) if str(t).startswith("zoo:")),
        )
        for e in entries
    ]
