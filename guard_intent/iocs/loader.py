from __future__ import annotations

import json
from pathlib import Path

from guard_intent.iocs.validator import classify_ioc


def _flatten_json_values(payload: object) -> list[str]:
    if isinstance(payload, list):
        return [str(x).strip() for x in payload]
    if isinstance(payload, dict):
        if "iocs" in payload and isinstance(payload["iocs"], list):
            return [str(x).strip() for x in payload["iocs"]]
        values: list[str] = []
        for value in payload.values():
            values.extend(_flatten_json_values(value))
        return values
    return [str(payload).strip()]


def load_iocs(path: str) -> dict[str, set[str]]:
    p = Path(path)
    iocs: dict[str, set[str]] = {"ip": set(), "domain": set(), "url": set(), "sha256": set()}

    values: list[str]
    if p.suffix.lower() == ".json":
        values = _flatten_json_values(json.loads(p.read_text(encoding="utf-8")))
    else:
        values = [line.strip() for line in p.read_text(encoding="utf-8").splitlines()]

    for value in values:
        ioc_type = classify_ioc(value)
        if ioc_type:
            iocs[ioc_type].add(value)
    return iocs


def ioc_stats(iocs: dict[str, set[str]]) -> dict[str, int]:
    return {k: len(v) for k, v in iocs.items()}

