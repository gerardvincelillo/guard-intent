from __future__ import annotations

from html import escape
from pathlib import Path

from guardintent.models import Incident


def write_html_report(path: str | Path, incidents: list[Incident], run_meta: dict) -> Path:
    p = Path(path)
    cards: list[str] = []
    for incident in incidents:
        tactics = " ".join([f"<span class='tag'>{escape(t)}</span>" for t in incident.mitre_tactics]) or "<span class='tag'>N/A</span>"
        techniques = " ".join([f"<span class='tag'>{escape(t)}</span>" for t in incident.mitre_techniques]) or "<span class='tag'>N/A</span>"
        cards.append(
            """
            <article class='card'>
              <h3>{title}</h3>
              <p><strong>Severity:</strong> {severity} | <strong>Score:</strong> {score}</p>
              <p><strong>Rules:</strong> {rules}</p>
              <p><strong>First Seen:</strong> {first_seen} | <strong>Last Seen:</strong> {last_seen}</p>
              <p><strong>MITRE Tactics:</strong> {tactics}</p>
              <p><strong>MITRE Techniques:</strong> {techniques}</p>
              <p><strong>Entities:</strong> {entities}</p>
            </article>
            """.format(
                title=escape(incident.title),
                severity=escape(incident.severity.upper()),
                score=incident.score,
                rules=escape(", ".join(incident.rule_hits)),
                first_seen=escape(incident.first_seen or "N/A"),
                last_seen=escape(incident.last_seen or "N/A"),
                tactics=tactics,
                techniques=techniques,
                entities=escape(str(incident.entities)),
            )
        )

    html = """<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>GuardIntent Report</title>
  <style>
    :root {{ --bg:#0f172a; --panel:#111827; --text:#e5e7eb; --muted:#9ca3af; --accent:#22d3ee; }}
    body {{ margin:0; font-family:Segoe UI,Arial,sans-serif; background:linear-gradient(120deg,#0f172a,#1f2937); color:var(--text); }}
    main {{ max-width:1000px; margin:0 auto; padding:24px; }}
    .meta {{ color:var(--muted); margin-bottom:20px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
    .card {{ background:var(--panel); border:1px solid #1f2937; border-radius:12px; padding:16px; box-shadow:0 8px 24px rgba(0,0,0,0.25); }}
    .tag {{ display:inline-block; padding:2px 8px; border:1px solid var(--accent); border-radius:999px; margin-right:6px; color:var(--accent); font-size:12px; }}
  </style>
</head>
<body>
  <main>
    <h1>GuardIntent Incident Dashboard</h1>
    <p class='meta'>Generated: {generated_at} | Logs: {logs_path} | Incidents: {count}</p>
    <section class='grid'>
      {cards}
    </section>
  </main>
</body>
</html>
""".format(
        generated_at=escape(run_meta.get("generated_at", "")),
        logs_path=escape(run_meta.get("logs_path", "")),
        count=len(incidents),
        cards="\n".join(cards) if cards else "<p>No incidents found.</p>",
    )

    p.write_text(html, encoding="utf-8")
    return p
