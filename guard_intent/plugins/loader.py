"""Plugin loading for external/custom GuardIntent detection rules."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from guard_intent.rules.base import BaseRule


def load_plugin_rules(paths: list[str]) -> list[type[BaseRule]]:
    loaded: list[type[BaseRule]] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue

        spec = importlib.util.spec_from_file_location(path.stem, path)
        if not spec or not spec.loader:
            continue

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        module_rules = getattr(module, "RULES", [])
        for rule_cls in module_rules:
            if isinstance(rule_cls, type) and issubclass(rule_cls, BaseRule):
                loaded.append(rule_cls)
    return loaded

