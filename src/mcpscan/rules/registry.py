"""Rule discovery: built-in rules register through `@register`; third-party rule packs are found
through the `mcpscan.rules` entry-point group (importing them runs their `@register` decorators)."""

from __future__ import annotations

import importlib
import pkgutil
from importlib.metadata import entry_points

from mcpscan.rules.base import RULE_ID_PATTERN, Rule

ENTRY_POINT_GROUP = "mcpscan.rules"

_REGISTRY: dict[str, type[Rule]] = {}


def register[R: type[Rule]](cls: R) -> R:
    if not RULE_ID_PATTERN.match(cls.id):
        raise ValueError(f"invalid rule id {cls.id!r} on {cls.__qualname__}")
    existing = _REGISTRY.get(cls.id)
    if existing is not None and existing is not cls:
        raise ValueError(f"rule id {cls.id} registered twice: {existing.__qualname__}, "
                         f"{cls.__qualname__}")  # fmt: skip
    _REGISTRY[cls.id] = cls
    return cls


def _import_builtins() -> None:
    from mcpscan.rules import builtin

    for module in pkgutil.iter_modules(builtin.__path__, f"{builtin.__name__}."):
        importlib.import_module(module.name)


def _import_plugins() -> None:
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        ep.load()


def load_rules(*, plugins: bool = True) -> list[Rule]:
    """Instantiate every registered rule, sorted by id."""
    _import_builtins()
    if plugins:
        _import_plugins()
    return [_REGISTRY[rule_id]() for rule_id in sorted(_REGISTRY)]
