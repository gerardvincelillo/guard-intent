from guard_intent.enrichment.virustotal import collect_iocs_for_enrichment


def test_collect_iocs_for_enrichment_extracts_nested_values():
    evidence = [
        {
            "event": {
                "src_ip": "203.0.113.9",
                "domain": "malicious.example",
                "url": "https://evil.example/payload",
                "hash_sha256": "a" * 64,
            },
            "details": "callback to https://c2.bad.example/dropper from 198.51.100.7",
        }
    ]
    entities = {"hostname": "WIN-007", "src_ip": "192.0.2.44"}

    iocs = collect_iocs_for_enrichment(evidence, entities)

    assert "203.0.113.9" in iocs
    assert "198.51.100.7" in iocs
    assert "malicious.example" in iocs
    assert "https://evil.example/payload" in iocs
    assert ("a" * 64) in iocs

