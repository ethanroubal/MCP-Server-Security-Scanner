"""Machine-readable report: the `ScanResult` model as JSON (secrets already masked by the model)."""

from mcpiranha.core.models import ScanResult


def render(result: ScanResult) -> str:
    return result.model_dump_json(indent=2) + "\n"
