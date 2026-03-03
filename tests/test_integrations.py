import io
from urllib import error

import guardintent.enrichment.virustotal as vt
import guardintent.integrations.exporters as exporters
from guardintent.models import Incident


class _Resp:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _incident() -> Incident:
    return Incident(
        title="x",
        severity="high",
        score=55,
        rule_hits=["r1"],
        entities={"src_ip": "1.2.3.4"},
        evidence=[],
        recommendations=["r"],
        mitre_techniques=["T1110"],
        mitre_tactics=["Credential Access"],
    )


def test_webhook_retries_on_rate_limit(monkeypatch):
    calls = {"count": 0}

    def fake_urlopen(req, timeout=0):
        calls["count"] += 1
        if calls["count"] == 1:
            raise error.HTTPError(req.full_url, 429, "rate", {"Retry-After": "0"}, io.BytesIO(b""))
        return _Resp(b"{}")

    monkeypatch.setattr(exporters.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(exporters.time, "sleep", lambda *_: None)

    ok = exporters.post_webhook("https://example.test/hook", [_incident()], max_retries=2)
    assert ok is True
    assert calls["count"] == 2


def test_virustotal_returns_none_after_retry_exhaustion(monkeypatch):
    def failing_urlopen(req, timeout=0):
        raise error.URLError("network down")

    monkeypatch.setattr(vt.request, "urlopen", failing_urlopen)
    monkeypatch.setattr(vt.time, "sleep", lambda *_: None)

    client = vt.VirusTotalClient(api_key="k", max_retries=2)
    result = client.lookup_ioc("8.8.8.8")
    assert result is None


def test_jira_create_handles_non_json_response(monkeypatch):
    monkeypatch.setattr(exporters.request, "urlopen", lambda req, timeout=0: _Resp(b"not-json"))

    created = exporters.create_jira_issues(
        "https://jira.example.com",
        "user@example.com",
        "token",
        "SEC",
        "Task",
        [_incident()],
        max_retries=0,
    )
    assert created == []
