from guard_intent.iocs.loader import ioc_stats, load_iocs


def test_ioc_loader_counts():
    iocs = load_iocs("data/sample_iocs.txt")
    stats = ioc_stats(iocs)

    assert stats["ip"] == 1
    assert stats["domain"] == 1
    assert stats["url"] == 1
    assert stats["sha256"] == 1

