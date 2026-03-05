from guard_intent.models import RuleHit
from guard_intent.scoring import aggregate_hits


def _hit(rule_id: str, ts: str, entities: dict[str, str], score: int = 10) -> RuleHit:
    return RuleHit(
        rule_id=rule_id,
        name=rule_id,
        score=score,
        evidence={"timestamp": ts},
        recommendation="investigate",
        entities=entities,
        timestamp=ts,
        mitre_techniques=["T0001"],
        mitre_tactics=["Discovery"],
    )


def test_aggregate_hits_groups_by_graph_and_time_window():
    hits = [
        _hit("r1", "2026-02-28T09:00:00Z", {"src_ip": "10.0.0.1"}, 20),
        _hit("r2", "2026-02-28T09:01:00Z", {"src_ip": "10.0.0.1"}, 25),
        _hit("r3", "2026-02-28T09:06:00Z", {"hostname": "HOST-A"}, 30),
        _hit("r4", "2026-02-28T10:40:00Z", {"hostname": "HOST-Z"}, 35),
    ]

    incidents = aggregate_hits(hits, grouping_window_seconds=300)

    assert len(incidents) == 2
    assert incidents[0].score == 75
    assert incidents[0].first_seen is not None
    assert incidents[0].last_seen is not None

