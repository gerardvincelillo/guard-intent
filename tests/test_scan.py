import json
from pathlib import Path

from typer.testing import CliRunner

from guardintent.cli import app


runner = CliRunner()


def test_scan_generates_reports(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--logs",
            "data/sample_logs.jsonl",
            "--iocs",
            "data/sample_iocs.txt",
            "--out",
            str(tmp_path),
            "--format",
            "md,json",
            "--min-severity",
            "medium",
        ],
    )
    assert result.exit_code == 0

    md_reports = list(tmp_path.glob("*.md"))
    json_reports = list(tmp_path.glob("*.json"))
    assert len(md_reports) == 1
    assert len(json_reports) == 1

    payload = json.loads(json_reports[0].read_text(encoding="utf-8"))
    assert payload["incident_count"] >= 1
    assert any(incident["mitre_techniques"] for incident in payload["incidents"])
    assert any(incident["mitre_tactics"] for incident in payload["incidents"])


def test_scan_supports_html_and_plugin_rule(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--logs",
            "data/sample_logs.jsonl",
            "--iocs",
            "data/sample_iocs.txt",
            "--out",
            str(tmp_path),
            "--format",
            "json,html",
            "--plugin",
            "plugins/sample_custom_rule.py",
            "--min-severity",
            "low",
        ],
    )
    assert result.exit_code == 0

    html_reports = list(tmp_path.glob("*.html"))
    json_reports = list(tmp_path.glob("*.json"))
    assert len(html_reports) == 1
    assert len(json_reports) == 1

    payload = json.loads(json_reports[0].read_text(encoding="utf-8"))
    all_rule_hits = [rule for incident in payload["incidents"] for rule in incident["rule_hits"]]
    assert "suspicious_domain_burst" in all_rule_hits
