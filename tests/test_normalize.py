from guard_intent.normalize.normalizer import parse_logs


def test_parse_sample_logs():
    events = parse_logs("data/sample_logs.jsonl")
    assert len(events) == 12
    assert events[0].event_type == "auth"
    assert events[6].process_name == "mimikatz.exe"

