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
import yaml

from mcpiranha.acquire import ConnectOptions, connect_all
from mcpiranha.core.models import Origin, ServerSnapshot, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.discovery import client_settings, to_launch
from mcpiranha.rules.base import Rule

MANIFEST = "sample.yaml"
Status = Literal["pass", "fail", "gap", "gap-flagged"]


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


@dataclass(slots=True)
class SampleResult:
    sample: Sample
    found: frozenset[str]
    worst: Severity | None
    errors: list[str] = field(default_factory=list[str])

    @property
    def missing(self) -> frozenset[str]:
        return self.sample.expect - self.found

    @property
    def extra(self) -> frozenset[str]:
        return self.found - self.sample.expect

    @property
    def status(self) -> Status:
        if self.sample.gap is not None:
            flagged = self.worst is not None and self.worst.rank >= Severity.MEDIUM.rank
            return "gap-flagged" if flagged else "gap"
        return "fail" if self.missing or self.errors else "pass"


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
    servers = _substitute(data["servers"], {"PYTHON": python, "SAMPLE": str(directory)})
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
    )


def load_samples(zoo: Path, python: str, only: Sequence[str] = ()) -> list[Sample]:
    """Every sample under `zoo` (a sample directory itself, or a tree of them)."""
    manifests = [zoo / MANIFEST] if (zoo / MANIFEST).is_file() else sorted(zoo.rglob(MANIFEST))
    samples = [load_sample(m.parent, python) for m in manifests]
    return [s for s in samples if not only or s.name in only]


def snapshots(sample: Sample) -> list[ServerSnapshot]:
    """One client per sample, so its servers form one inventory (as if installed together)."""
    out: list[ServerSnapshot] = []
    for name, entry in sample.servers.items():
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


async def run(samples: Sequence[Sample], rules: Sequence[Rule], *, timeout: float = 30.0,
              jobs: int = 4) -> list[SampleResult]:  # fmt: skip
    """Connect to each sample's servers (`jobs` samples at a time) and scan each sample alone."""
    options = ConnectOptions(sandbox="none", timeout=timeout)
    limiter = anyio.CapacityLimiter(max(1, jobs))
    results: list[SampleResult | None] = [None] * len(samples)

    async def one(i: int, sample: Sample) -> None:
        snaps, errors = snapshots(sample), list[str]()
        if sample.connect:
            async with limiter:
                snaps, errors = await connect_all(snaps, options)
        result = scan(snaps, list(rules))
        results[i] = SampleResult(sample, frozenset(f.rule_id for f in result.findings),
                                  result.max_severity(), errors)  # fmt: skip

    async with anyio.create_task_group() as group:
        for i, sample in enumerate(samples):
            group.start_soon(one, i, sample)
    return [r for r in results if r is not None]
