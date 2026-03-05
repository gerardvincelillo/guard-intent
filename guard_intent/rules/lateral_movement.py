from __future__ import annotations

from datetime import datetime, timezone

from guard_intent.config import Config
from guard_intent.models import Event, RuleHit
from guard_intent.rules.base import BaseRule


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _is_internal_ip(ip: str | None) -> bool:
    if not ip:
        return False
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")


class LateralMovementRule(BaseRule):
    rule_id = "lateral_movement"
    name = "Lateral Movement Indicator"
    description = "Detects one source touching many internal hosts quickly"
    mitre_techniques = ["T1021", "T1210"]
    mitre_tactics = ["Lateral Movement"]

    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        network_events = [e for e in events if e.src_ip and e.dst_ip and _is_internal_ip(e.dst_ip)]
        by_src: dict[str, list[Event]] = {}
        for event in network_events:
            by_src.setdefault(event.src_ip or "unknown", []).append(event)

        hits: list[RuleHit] = []
        for src_ip, items in by_src.items():
            items.sort(key=lambda x: x.timestamp)
            start = 0
            for idx, event in enumerate(items):
                while start <= idx and (_parse_ts(event.timestamp) - _parse_ts(items[start].timestamp)).total_seconds() > config.lateral_window_seconds:
                    start += 1
                distinct_hosts = {e.dst_ip for e in items[start: idx + 1] if e.dst_ip}
                if len(distinct_hosts) >= config.lateral_unique_hosts_threshold:
                    hits.append(
                        RuleHit(
                            rule_id=self.rule_id,
                            name=self.name,
                            score=25,
                            evidence={"src_ip": src_ip, "distinct_internal_hosts": sorted(distinct_hosts)},
                            recommendation="Investigate host for lateral movement and restrict east-west traffic.",
                            entities={"src_ip": src_ip},
                            timestamp=event.timestamp,
                            mitre_techniques=self.mitre_techniques,
                            mitre_tactics=self.mitre_tactics,
                        )
                    )
                    break
        return hits

