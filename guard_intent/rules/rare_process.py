from __future__ import annotations

from collections import Counter

from guard_intent.config import Config
from guard_intent.models import Event, RuleHit
from guard_intent.rules.base import BaseRule


class RareProcessRule(BaseRule):
    rule_id = "rare_process"
    name = "Rare Process Execution"
    description = "Flags processes that appear infrequently"
    mitre_techniques = ["T1059", "T1204"]
    mitre_tactics = ["Execution", "User Execution"]

    def run(self, events: list[Event], config: Config, **kwargs) -> list[RuleHit]:
        process_events = [e for e in events if e.process_name]
        counts = Counter((e.process_name or "").lower() for e in process_events)
        hits: list[RuleHit] = []

        for event in process_events:
            process = (event.process_name or "").lower()
            if process and counts[process] <= config.rare_process_min_count:
                hits.append(
                    RuleHit(
                        rule_id=self.rule_id,
                        name=self.name,
                        score=20,
                        evidence={"process_name": event.process_name, "seen_count": counts[process], "event": event.to_dict()},
                        recommendation="Validate process origin and isolate host if unauthorized.",
                        entities={"hostname": event.hostname, "user": event.username, "src_ip": event.src_ip},
                        timestamp=event.timestamp,
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                    )
                )
        return hits

