from __future__ import annotations

from guard_intent.config import Config
from guard_intent.iocs.matcher import match_iocs
from guard_intent.models import Event, RuleHit
from guard_intent.rules.base import BaseRule


class IOCMatchRule(BaseRule):
    rule_id = "ioc_match"
    name = "IOC Match"
    description = "Matches event fields against IOC feed values"
    mitre_techniques = ["T1595", "T1071.001", "T1105"]
    mitre_tactics = ["Reconnaissance", "Command and Control"]

    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        iocs: dict[str, set[str]] = kwargs.get("iocs", {})
        hits: list[RuleHit] = []
        for event in events:
            matches = match_iocs(event, iocs)
            if not matches:
                continue
            hits.append(
                RuleHit(
                    rule_id=self.rule_id,
                    name=self.name,
                    score=60,
                    evidence={"timestamp": event.timestamp, "matches": matches, "event": event.to_dict()},
                    recommendation="Block matched IOC and hunt for related activity.",
                    entities={"src_ip": event.src_ip, "user": event.username, "hostname": event.hostname},
                    timestamp=event.timestamp,
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                )
            )
        return hits

