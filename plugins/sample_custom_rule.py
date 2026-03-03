from __future__ import annotations

from guardintent.config import Config
from guardintent.models import Event, RuleHit
from guardintent.rules.base import BaseRule


class SuspiciousDomainBurstRule(BaseRule):
    rule_id = "suspicious_domain_burst"
    name = "Suspicious Domain Burst"
    description = "Flags repeated DNS queries for suspicious.example-like domains"
    mitre_techniques = ["T1071.004"]
    mitre_tactics = ["Command and Control"]

    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        dns_events = [e for e in events if e.domain and e.source == "dns"]
        suspicious = [e for e in dns_events if "malicious" in (e.domain or "")]
        if len(suspicious) < 1:
            return []
        event = suspicious[0]
        return [
            RuleHit(
                rule_id=self.rule_id,
                name=self.name,
                score=15,
                evidence={"domain": event.domain, "count": len(suspicious)},
                recommendation="Block DNS resolution and inspect host resolver cache.",
                entities={"src_ip": event.src_ip, "hostname": event.hostname},
                timestamp=event.timestamp,
                mitre_techniques=self.mitre_techniques,
                mitre_tactics=self.mitre_tactics,
            )
        ]


RULES = [SuspiciousDomainBurstRule]
