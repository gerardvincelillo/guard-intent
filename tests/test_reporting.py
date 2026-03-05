import json
from pathlib import Path

from guard_intent.reporting.html import write_html_report
from guard_intent.reporting.json import write_json_report
from guard_intent.reporting.markdown import write_markdown_report


def test_reports_handle_empty_incident_list(tmp_path: Path):
    run_meta = {
        "generated_at": "2026-03-03T00:00:00Z",
        "logs_path": "logs.jsonl",
        "iocs_path": "iocs.txt",
        "min_severity": "high",
    }

    md_path = write_markdown_report(tmp_path / "r.md", [], run_meta)
    html_path = write_html_report(tmp_path / "r.html", [], run_meta)
    json_path = write_json_report(tmp_path / "r.json", [], run_meta)

    assert "No incidents met" in md_path.read_text(encoding="utf-8")
    assert "No incidents found." in html_path.read_text(encoding="utf-8")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["incident_count"] == 0

