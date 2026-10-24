"""Coverage must distinguish absent evidence, partial collection, and a clean result."""

import json
from datetime import UTC, datetime
from io import StringIO

import anyio
import pytest
from rich.console import Console

from mcpiranha import source
from mcpiranha.acquire import ConnectOptions, connect_all
from mcpiranha.acquire.listing import EnumerationError
from mcpiranha.core.coverage import summarize
from mcpiranha.core.models import (
    ClientSettings,
    CoverageCheck,
    DynamicObservation,
    Launch,
    PackageMeta,
    ProbeRun,
    ServerSnapshot,
    SourceTree,
)
from mcpiranha.core.pipeline import scan
from mcpiranha.report import json_report, sarif, terminal
from tests.helpers import snapshot_with_description


def test_absent_tools_are_unknown_but_empty_list_is_valid() -> None:
    snapshot = snapshot_with_description("Adds numbers.")
    unknown = snapshot.model_copy(update={"tools_listed": False, "tools": []})
    empty = snapshot.model_copy(update={"tools": []})
    assert summarize(unknown)["tools"].status == "skipped"
    assert summarize(unknown)["tools"].count is None
    assert summarize(empty)["tools"].status == "completed"
    assert summarize(empty)["tools"].count == 0
    assert summarize(empty)["dynamic"].status == "skipped"


def test_partial_source_and_dependency_checks() -> None:
    snapshot = snapshot_with_description("Adds numbers.").model_copy(
        update={
            "source": SourceTree(
                root="test", language="py", files=2, skipped=["large.py: too big"]
            ),
            "package": PackageMeta(
                registry="npm",
                name="test",
                version="1",
                checked_at=datetime.now(UTC),
                dependencies=[PackageMeta(registry="npm", name="dep", version="2")],
                dependencies_skipped=["unresolved@x"],
            ),
        }
    )
    coverage = summarize(snapshot)
    assert coverage["source"].status == "partial"
    assert coverage["source"].count == 2
    assert "large.py" in coverage["source"].reason
    assert coverage["package"].status == "partial"  # registry checked, OSV unavailable
    assert coverage["dependencies"].status == "partial"
    assert "unresolved@x" in coverage["dependencies"].reason
    assert "1 dependency vulnerability" in coverage["dependencies"].reason
    package = snapshot.package
    assert package is not None
    clean = snapshot.model_copy(
        update={
            "package": package.model_copy(
                update={"dependencies": [], "dependencies_skipped": [], "vulnerabilities": []}
            )
        }
    )
    assert summarize(clean)["package"].status == "completed"
    assert summarize(clean)["dependencies"].status == "completed"
    assert summarize(clean)["dependencies"].count == 0


def test_probe_counts_and_older_runtime_evidence() -> None:
    snapshot = snapshot_with_description("Adds numbers.").model_copy(
        update={
            "probes": [
                ProbeRun(
                    id="call",
                    tool="add",
                    variant="baseline",
                    started_at=datetime.now(UTC),
                    status="error",
                )
            ],
            "observations": [
                DynamicObservation(
                    kind="file_open", phase="listing", syscall="openat", detail="test"
                )
            ],
        }
    )
    assert summarize(snapshot)["invocation"].status == "partial"
    assert summarize(snapshot)["invocation"].count == 0
    assert summarize(snapshot)["dynamic"].status == "unknown"


def test_reports_preserve_coverage_and_sarif_warnings() -> None:
    snapshot = snapshot_with_description("Adds numbers.").model_copy(
        update={"coverage": {"source": CoverageCheck(status="failed", reason="bad\x1b[31m source")}}
    )
    result = scan([snapshot], []).model_copy(update={"warnings": ["OSV unavailable"]})
    report = json.loads(json_report.render(result))
    assert report["schema_version"] == 2
    coverage = report["servers"][0]["coverage"]
    assert len(coverage) == 7
    assert coverage["source"]["status"] == "failed"
    run = json.loads(sarif.render(result, []))["runs"][0]
    assert run["properties"]["coverage"][0]["stages"] == coverage
    assert run["invocations"][0]["toolExecutionNotifications"] == [
        {"level": "warning", "message": {"text": "OSV unavailable"}}
    ]
    stream = StringIO()
    terminal.render(result, Console(file=stream, width=160, no_color=True))
    assert "source: failed" in stream.getvalue()
    assert "⟨U+001B⟩" in stream.getvalue()
    assert "\x1b" not in stream.getvalue()


def test_connection_failure_and_disabled_server_have_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*args: object, **kwargs: object) -> ServerSnapshot:
        raise EnumerationError("fixture failed")

    monkeypatch.setattr("mcpiranha.acquire.connect_one", fail)
    snapshot = snapshot_with_description("Adds numbers.").model_copy(
        update={"tools_listed": False, "launch": Launch(transport="stdio", command="fixture")}
    )
    disabled = snapshot.model_copy(
        update={"id": "disabled", "client_settings": ClientSettings(disabled=True)}
    )
    snapshots, warnings = anyio.run(connect_all, [snapshot, disabled], ConnectOptions(dynamic=True))
    assert len(warnings) == 1
    assert summarize(snapshots[0])["tools"].status == "failed"
    assert "fixture failed" in summarize(snapshots[0])["tools"].reason
    assert summarize(snapshots[0])["dynamic"].status == "failed"
    assert summarize(snapshots[1])["tools"].status == "skipped"
    assert "disabled" in summarize(snapshots[1])["tools"].reason


def test_source_byte_limit_is_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    def files():
        yield "first.py", b"x = 1"
        raise source.SourceLimit("Source byte limit reached")

    tree = source.analyze_files(files(), "test")
    assert tree.files == 1
    snapshot = snapshot_with_description("Adds numbers.").model_copy(update={"source": tree})
    assert summarize(snapshot)["source"].status == "partial"


@pytest.mark.parametrize("failure", ["none", "trace", "invocation", "startup"])
def test_tracing_and_invocation_have_independent_status(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from unittest.mock import Mock

    from mcpiranha.acquire import connect_one
    from mcpiranha.acquire.listing import Enumeration
    from mcpiranha.acquire.sandbox import Prepared

    async def collect() -> list[DynamicObservation]:
        return (
            [DynamicObservation(kind="probe_error", phase="listing", detail="trace truncated")]
            if failure == "trace"
            else []
        )

    prepared = Prepared(connect=Mock(), label="fixture", collect=collect)

    async def prepare(*args: object, **kwargs: object) -> Prepared:
        return prepared

    async def instrument(*args: object, **kwargs: object) -> None:
        pass

    async def enumerate_fixture(*args: object, **kwargs: object) -> Enumeration:
        if failure == "startup":
            raise EnumerationError("startup failed")
        return Enumeration(
            probes=[
                ProbeRun(
                    id="call",
                    tool="echo",
                    variant="baseline",
                    started_at=datetime.now(UTC),
                    status="completed",
                )
            ],
            observations=[
                DynamicObservation(
                    kind="probe_error", phase="invocation", detail="baseline rejected"
                )
            ]
            if failure == "invocation"
            else [],
        )

    monkeypatch.setattr("mcpiranha.acquire.prepare", prepare)
    monkeypatch.setattr("mcpiranha.dynamic.runtime.instrument", instrument)
    monkeypatch.setattr("mcpiranha.acquire.enumerate_server", enumerate_fixture)
    snapshot = snapshot_with_description("Adds numbers.").model_copy(
        update={"tools_listed": False, "launch": Launch(transport="stdio", command="fixture")}
    )
    listed = anyio.run(connect_one, snapshot, ConnectOptions(dynamic=True, invoke=("echo",)))
    coverage = summarize(listed)
    assert coverage["dynamic"].status == (
        "partial" if failure in ("trace", "startup") else "completed"
    )
    assert coverage["invocation"].status == (
        "partial" if failure in ("invocation", "startup") else "completed"
    )
    assert coverage["tools"].status == ("failed" if failure == "startup" else "completed")
    assert coverage["tools"].count == (None if failure == "startup" else 0)
    assert coverage["invocation"].count == (0 if failure == "startup" else 1)


def test_source_download_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(*args: object, **kwargs: object) -> bytes:
        raise source.SourceError("archive unavailable")

    monkeypatch.setattr(source, "_download", fail)
    snapshot = snapshot_with_description("Adds numbers.").model_copy(
        update={
            "package": PackageMeta(
                registry="npm",
                name="fixture",
                version="1",
                archive_url="https://example.invalid/pkg.tgz",
                archive_hash="hash",
            )
        }
    )
    snapshots, warnings = anyio.run(source.collect, [snapshot])
    assert warnings
    assert summarize(snapshots[0])["source"].status == "failed"
    assert "archive unavailable" in summarize(snapshots[0])["source"].reason
