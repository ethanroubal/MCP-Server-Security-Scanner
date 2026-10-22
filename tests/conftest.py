import pytest


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """No registry or OSV lookups from tests; test_supply.py uses a fake registry instead."""
    monkeypatch.setenv("MCPIRANHA_OFFLINE", "1")
