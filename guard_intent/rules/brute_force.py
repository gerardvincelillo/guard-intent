from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from guard_intent.config import Config
from guard_intent.models import Event, RuleHit
from guard_intent.rules.base import BaseRule


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


class BruteForceRule(BaseRule):
    rule_id = "brute_force"
    name = "Brute-Force Attempts"
    description = "Detects repeated failed logins from same user or source IP"
    mitre_techniques = ["T1110"]
    mitre_tactics = ["Credential Access"]

    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        failures = [
            e for e in events
            if e.event_type == "auth" and (e.action or "").lower() in {"failed", "fail", "denied"}
        ]
        grouped: dict[str, list[Event]] = defaultdict(list)
        for event in failures:
            key = event.username or event.src_ip or "unknown"
            grouped[key].append(event)

        hits: list[RuleHit] = []
        for key, items in grouped.items():
            items.sort(key=lambda x: x.timestamp)
            window: list[Event] = []
            for event in items:
                current_ts = _parse_ts(event.timestamp)
                window = [w for w in window if (current_ts - _parse_ts(w.timestamp)).total_seconds() <= config.brute_force_window_seconds]
                window.append(event)
                if len(window) >= config.brute_force_threshold:
                    hits.append(
                        RuleHit(
                            rule_id=self.rule_id,
                            name=self.name,
                            score=30,
                            evidence={
                                "count": len(window),
                                "window_seconds": config.brute_force_window_seconds,
                                "sample_timestamps": [w.timestamp for w in window[-5:]],
                            },
                            recommendation="Reset credentials, enforce MFA, and block abusive source.",
                            entities={"src_ip": event.src_ip, "user": event.username},
                            timestamp=event.timestamp,
                            mitre_techniques=self.mitre_techniques,
                            mitre_tactics=self.mitre_tactics,
                        )
                    )
                    break
        return hits

