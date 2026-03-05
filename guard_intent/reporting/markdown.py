from __future__ import annotations

from pathlib import Path

from guard_intent.models import Incident


def _section(title: str) -> str:
    return f"\n## {title}\n"


def write_markdown_report(path: str | Path, incidents: list[Incident], run_meta: dict) -> Path:
    p = Path(path)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in incidents:
        sev_counts[i.severity] += 1

    lines: list[str] = [
        "# GuardIntent Incident Report",
        _section("Executive Summary"),
        f"- Generated at: {run_meta['generated_at']}",
        f"- Input logs: {run_meta['logs_path']}",
        f"- IOC source: {run_meta.get('iocs_path', 'N/A')}",
        f"- Incidents: {len(incidents)}",
        _section("Incident Overview"),
    ]

    if not incidents:
        lines.append("No incidents met the configured severity threshold.")
    else:
        for idx, incident in enumerate(incidents, start=1):
            lines.extend(
                [
                    f"### Incident {idx}: {incident.title}",
                    f"- Severity: **{incident.severity.title()}**",
                    f"- Score: **{incident.score}**",
                    f"- Rule Hits: {', '.join(incident.rule_hits)}",
                    f"- First Seen: {incident.first_seen or 'N/A'}",
                    f"- Last Seen: {incident.last_seen or 'N/A'}",
                    f"- MITRE Tactics: {', '.join(incident.mitre_tactics) if incident.mitre_tactics else 'N/A'}",
                    f"- MITRE Techniques: {', '.join(incident.mitre_techniques) if incident.mitre_techniques else 'N/A'}",
                    f"- Entities: {incident.entities}",
                    "- Recommendations:",
                ]
            )
            lines.extend([f"  - {rec}" for rec in incident.recommendations])

    lines.extend(
        [
            _section("Severity Breakdown"),
            f"- Critical: {sev_counts['critical']}",
            f"- High: {sev_counts['high']}",
            f"- Medium: {sev_counts['medium']}",
            f"- Low: {sev_counts['low']}",
            _section("Rule Hits & Evidence"),
        ]
    )

    for idx, incident in enumerate(incidents, start=1):
        lines.append(f"### Incident {idx}")
        for evidence in incident.evidence:
            lines.append(f"- {evidence}")

    lines.extend(
        [
            _section("Matched IOCs"),
            "See incident evidence for IOC details.",
            _section("MITRE ATT&CK Mapping"),
            "Mapped tactics and techniques are listed in each incident overview.",
            _section("Affected Assets"),
            "See entities field per incident.",
            _section("Timeline"),
            "Timeline is inferred from event timestamps in evidence.",
            _section("Recommendations"),
        ]
    )

    for incident in incidents:
        for rec in incident.recommendations:
            lines.append(f"- {rec}")

    lines.extend(
        [
            _section("Appendix"),
            f"- Rule set version: {run_meta.get('rule_set_version', 'v1')}",
            f"- Minimum severity filter: {run_meta['min_severity']}",
        ]
    )

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p

