"""Summarize collected evidence, including older snapshots without stage records."""

from mcpiranha.core.launch import package_ref
from mcpiranha.core.models import CoverageCheck, CoverageStage, ServerSnapshot


def record(snapshot: ServerSnapshot, stage: CoverageStage, check: CoverageCheck) -> ServerSnapshot:
    return snapshot.model_copy(update={"coverage": {**snapshot.coverage, stage: check}})


def summarize(snapshot: ServerSnapshot) -> dict[CoverageStage, CoverageCheck]:
    def skipped(reason: str) -> CoverageCheck:
        return CoverageCheck(status="skipped", reason=reason)

    result: dict[CoverageStage, CoverageCheck] = {
        "configuration": (
            CoverageCheck(
                status="completed", reason="Launch configuration available for inspection."
            )
            if snapshot.launch
            else skipped("No launch configuration in snapshot.")
        ),
        "tools": (
            CoverageCheck(
                status="completed",
                reason="Listed tool metadata available (may be saved).",
                count=len(snapshot.tools),
            )
            if snapshot.tools_listed
            else skipped("Not connected; tool metadata is unknown.")
        ),
        "source": skipped("No supported local source or verified package archive available."),
        "package": skipped("No supported npm/PyPI package identified."),
        "dependencies": skipped("No supported npm/PyPI package identified."),
        "dynamic": skipped("Dynamic tracing not requested or not recorded in snapshot."),
        "invocation": skipped("No explicit tool invocations requested or recorded."),
    }
    if tree := snapshot.source:
        result["source"] = CoverageCheck(
            status="partial" if tree.skipped or not tree.files else "completed",
            reason="; ".join(tree.skipped)
            if tree.skipped
            else (
                "Source evidence available (may be saved); supported files only."
                if tree.files
                else "No supported source files analyzed."
            ),
            count=tree.files,
        )
    package = snapshot.package
    if package_ref(snapshot.launch) or package:
        result["package"] = skipped("Registry and vulnerability lookups not performed.")
        result["dependencies"] = skipped("Dependency resolution not performed.")
    if package and package.checked_at:
        result["package"] = CoverageCheck(
            status="completed" if package.vulnerabilities is not None else "partial",
            reason="Registry and vulnerability evidence available (may be cached or saved)."
            if package.vulnerabilities is not None
            else "Known vulnerabilities not checked.",
        )
    if package and package.dependencies is not None:
        missing = sum(d.vulnerabilities is None for d in package.dependencies)
        reasons = [*package.dependencies_skipped]
        if missing:
            reasons.append(f"{missing} dependency vulnerability check(s) unavailable.")
        result["dependencies"] = CoverageCheck(
            status="partial" if reasons else "completed",
            reason="; ".join(reasons) or "Resolved dependency evidence available (may be saved).",
            count=len(package.dependencies),
        )
    if any(o.syscall for o in snapshot.observations):
        result["dynamic"] = CoverageCheck(
            status="unknown", reason="Saved runtime evidence; tracing completeness not recorded."
        )
    if snapshot.probes:
        completed = sum(p.status == "completed" for p in snapshot.probes)
        incomplete = any(o.kind == "probe_error" for o in snapshot.observations)
        result["invocation"] = CoverageCheck(
            status="partial" if incomplete or completed != len(snapshot.probes) else "completed",
            reason=f"{completed}/{len(snapshot.probes)} recorded calls completed; "
            "completion does not mean the tool accepted the input.",
            count=completed,
        )
    return {**result, **snapshot.coverage}
