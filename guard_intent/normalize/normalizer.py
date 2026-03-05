from __future__ import annotations

from pathlib import Path

from guard_intent.models import Event


def _first(raw: dict, keys: list[str], default: str | None = None) -> str | None:
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _infer_source(raw: dict) -> str:
    source = str(raw.get("source", "")).lower()
    if source in {"firewall", "auth", "endpoint", "dns"}:
        return source
    if raw.get("process_name") or raw.get("process"):
        return "endpoint"
    if raw.get("domain") and raw.get("query"):
        return "dns"
    if raw.get("username") and raw.get("action"):
        return "auth"
    return "firewall"


def _infer_event_type(source: str) -> str:
    mapping = {
        "firewall": "network",
        "auth": "auth",
        "endpoint": "process",
        "dns": "dns",
    }
    return mapping.get(source, "network")


def normalize_record(raw: dict) -> Event:
    source = _infer_source(raw)
    return Event(
        timestamp=_first(raw, ["timestamp", "time", "ts"], "1970-01-01T00:00:00Z") or "1970-01-01T00:00:00Z",
        source=source,
        event_type=_first(raw, ["event_type", "type"], _infer_event_type(source)) or _infer_event_type(source),
        src_ip=_first(raw, ["src_ip", "source_ip", "client_ip", "ip"]),
        dst_ip=_first(raw, ["dst_ip", "destination_ip", "server_ip"]),
        domain=_first(raw, ["domain", "fqdn", "query"]),
        url=_first(raw, ["url", "uri"]),
        username=_first(raw, ["username", "user", "account"]),
        hostname=_first(raw, ["hostname", "host", "device"]),
        process_name=_first(raw, ["process_name", "process", "image"]),
        hash_sha256=_first(raw, ["hash_sha256", "sha256", "hash"]),
        action=_first(raw, ["action", "result", "status"]),
        raw=dict(raw),
    )


def parse_logs(path: str | Path) -> list[Event]:
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix in {".jsonl", ".json"}:
        from guard_intent.normalize.json_parser import JSONParser

        return JSONParser().parse(path)
    if suffix == ".csv":
        from guard_intent.normalize.csv_parser import CSVParser

        return CSVParser().parse(path)
    raise ValueError(f"Unsupported log file: {path}")

