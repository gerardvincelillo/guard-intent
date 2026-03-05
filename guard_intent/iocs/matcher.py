from __future__ import annotations

from guard_intent.models import Event


def match_iocs(event: Event, iocs: dict[str, set[str]]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    fields = {
        "ip": [event.src_ip, event.dst_ip],
        "domain": [event.domain],
        "url": [event.url],
        "sha256": [event.hash_sha256],
    }
    for ioc_type, values in fields.items():
        feed = iocs.get(ioc_type, set())
        for value in values:
            if value and value in feed:
                matches.append({"type": ioc_type, "value": value})
    return matches

