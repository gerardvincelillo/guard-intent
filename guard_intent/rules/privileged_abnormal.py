from __future__ import annotations

from guard_intent.config import Config
from guard_intent.models import Event, RuleHit
from guard_intent.rules.base import BaseRule


class PrivilegedAbnormalRule(BaseRule):
    rule_id = "privileged_abnormal"
    name = "Privileged Abnormal Activity"
    description = "Flags suspicious actions involving privileged users"
    mitre_techniques = ["T1078", "T1068"]
    mitre_tactics = ["Persistence", "Privilege Escalation", "Defense Evasion"]

    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        hits: list[RuleHit] = []
        priv = {x.lower() for x in config.privileged_accounts}
        for event in events:
            user = (event.username or "").lower()
            if not user or user not in priv:
                continue
            suspicious = (event.action or "").lower() in {"failed", "blocked", "denied"} or event.event_type in {"process", "network"}
            if suspicious:
                hits.append(
                    RuleHit(
                        rule_id=self.rule_id,
                        name=self.name,
                        score=25,
                        evidence={"event": event.to_dict()},
                        recommendation="Review privileged account activity and rotate credentials if needed.",
                        entities={"user": event.username, "src_ip": event.src_ip, "hostname": event.hostname},
                        timestamp=event.timestamp,
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )
        return hits

