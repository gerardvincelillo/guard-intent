from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Event:
    timestamp: str
    source: str
    event_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    domain: str | None = None
    url: str | None = None
    username: str | None = None
    hostname: str | None = None
    process_name: str | None = None
    hash_sha256: str | None = None
    action: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuleHit:
    rule_id: str
    name: str
    score: int
    evidence: dict[str, Any]
    recommendation: str
    entities: dict[str, Any]
    timestamp: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)


@dataclass
class Incident:
    title: str
    severity: str
    score: int
    rule_hits: list[str]
    entities: dict[str, Any]
    evidence: list[dict[str, Any]]
    recommendations: list[str]
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    enrichments: dict[str, Any] = field(default_factory=dict)
