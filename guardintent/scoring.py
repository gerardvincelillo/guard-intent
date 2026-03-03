from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from guardintent.models import Incident, RuleHit


def severity_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _hit_timestamp(hit: RuleHit) -> str | None:
    if hit.timestamp:
        return hit.timestamp
    timestamp = hit.evidence.get("timestamp")
    if isinstance(timestamp, str):
        return timestamp
    samples = hit.evidence.get("sample_timestamps")
    if isinstance(samples, list) and samples:
        sample = samples[0]
        if isinstance(sample, str):
            return sample
    event = hit.evidence.get("event")
    if isinstance(event, dict):
        event_ts = event.get("timestamp")
        if isinstance(event_ts, str):
            return event_ts
    return None


def _entity_tokens(hit: RuleHit) -> set[str]:
    tokens: set[str] = set()
    for value in hit.entities.values():
        if value:
            tokens.add(str(value).strip().lower())

    event = hit.evidence.get("event")
    if isinstance(event, dict):
        for key in ["src_ip", "dst_ip", "username", "hostname", "domain", "url", "hash_sha256"]:
            value = event.get(key)
            if value:
                tokens.add(str(value).strip().lower())

    for match in hit.evidence.get("matches", []):
        if isinstance(match, dict) and match.get("value"):
            tokens.add(str(match["value"]).strip().lower())

    return tokens


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1


def aggregate_hits(hits: list[RuleHit], grouping_window_seconds: int = 900) -> list[Incident]:
    if not hits:
        return []

    uf = _UnionFind(len(hits))

    entity_index: dict[str, list[int]] = defaultdict(list)
    for idx, hit in enumerate(hits):
        for token in _entity_tokens(hit):
            entity_index[token].append(idx)

    # Graph edge: shared entities connect rule hits.
    for related_indices in entity_index.values():
        first = related_indices[0]
        for other in related_indices[1:]:
            uf.union(first, other)

    # Temporal edge: nearby events are connected within a sliding window.
    dated_hits: list[tuple[datetime, int]] = []
    for idx, hit in enumerate(hits):
        ts = _parse_ts(_hit_timestamp(hit))
        if ts:
            dated_hits.append((ts, idx))
    dated_hits.sort(key=lambda x: x[0])

    start = 0
    for end in range(len(dated_hits)):
        end_ts, end_idx = dated_hits[end]
        while start <= end and (end_ts - dated_hits[start][0]).total_seconds() > grouping_window_seconds:
            start += 1
        for pos in range(start, end):
            uf.union(end_idx, dated_hits[pos][1])

    components: dict[int, list[RuleHit]] = defaultdict(list)
    for idx, hit in enumerate(hits):
        components[uf.find(idx)].append(hit)

    incidents: list[Incident] = []
    for group in components.values():
        score = sum(h.score for h in group)
        rule_ids = sorted({h.rule_id for h in group})
        entities: dict[str, object] = {}
        recommendations = sorted({h.recommendation for h in group})
        mitre_techniques = sorted({tech for h in group for tech in h.mitre_techniques})
        mitre_tactics = sorted({t for h in group for t in h.mitre_tactics})
        seen_timestamps = [_hit_timestamp(h) for h in group]
        valid_ts = [t for t in seen_timestamps if _parse_ts(t)]

        for hit in group:
            entities.update({k: v for k, v in hit.entities.items() if v})

        unique_names = []
        for hit in group:
            if hit.name not in unique_names:
                unique_names.append(hit.name)
        title = " & ".join(unique_names[:2])

        incidents.append(
            Incident(
                title=f"{title} detected",
                severity=severity_from_score(score),
                score=score,
                rule_hits=rule_ids,
                entities=entities,
                evidence=[h.evidence for h in group],
                recommendations=recommendations,
                mitre_techniques=mitre_techniques,
                mitre_tactics=mitre_tactics,
                first_seen=min(valid_ts) if valid_ts else None,
                last_seen=max(valid_ts) if valid_ts else None,
            )
        )

    incidents.sort(key=lambda i: i.score, reverse=True)
    return incidents


def filter_by_min_severity(incidents: list[Incident], min_severity: str) -> list[Incident]:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = rank[min_severity.lower()]
    return [i for i in incidents if rank[i.severity] >= threshold]
