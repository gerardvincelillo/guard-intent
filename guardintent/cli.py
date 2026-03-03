from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from guardintent.config import Config
from guardintent.enrichment.virustotal import VirusTotalClient, collect_iocs_for_enrichment
from guardintent.iocs.loader import ioc_stats, load_iocs
from guardintent.integrations.exporters import create_jira_issues, post_webhook
from guardintent.models import RuleHit
from guardintent.normalize.normalizer import parse_logs
from guardintent.plugins.loader import load_plugin_rules
from guardintent.reporting.html import write_html_report
from guardintent.reporting.json import write_json_report
from guardintent.reporting.markdown import write_markdown_report
from guardintent.rules.base import available_rules
from guardintent.scoring import aggregate_hits, filter_by_min_severity
from guardintent.utils import ensure_dir, now_utc_iso, ts_for_filename

app = typer.Typer(help="GuardIntent CLI: security automation and triage framework")
console = Console()


def _parse_formats(fmt: str) -> set[str]:
    allowed = {"md", "json", "html"}
    selected = {x.strip().lower() for x in fmt.split(",") if x.strip()}
    if not selected or not selected.issubset(allowed):
        raise typer.BadParameter("--format must use md, json, and/or html (comma-separated)")
    return selected


@app.command()
def parse(
    logs: str = typer.Option(..., "--logs", help="Input logs path (.jsonl/.json/.csv)"),
    out: str = typer.Option(..., "--out", help="Output normalized JSONL path"),
) -> None:
    """Normalize raw logs into the GuardIntent event schema."""
    events = parse_logs(logs)
    output_path = Path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(e.to_dict()) for e in events]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[green]Normalized {len(events)} events[/green] -> {output_path}")


@app.command("iocs")
def iocs_command(
    iocs: str = typer.Option(..., "--iocs", help="IOC file path (.txt/.json)"),
) -> None:
    """Load, validate, and count IOC entries."""
    loaded = load_iocs(iocs)
    stats = ioc_stats(loaded)

    table = Table(title="IOC Stats")
    table.add_column("Type")
    table.add_column("Count", justify="right")
    for key in ["ip", "domain", "url", "sha256"]:
        table.add_row(key, str(stats[key]))
    table.add_row("total", str(sum(stats.values())))
    console.print(table)


@app.command("rules")
def rules_command(
    list_rules: bool = typer.Option(False, "--list", help="List all rules"),
    show: str | None = typer.Option(None, "--show", help="Show details for a specific rule id"),
) -> None:
    """List available detection rules and details."""
    rules = [rule_cls() for rule_cls in available_rules()]
    if list_rules:
        for rule in rules:
            console.print(f"- [cyan]{rule.rule_id}[/cyan]: {rule.name}")
        return
    if show:
        target = next((r for r in rules if r.rule_id == show), None)
        if not target:
            raise typer.BadParameter(f"Unknown rule id: {show}")
        console.print(f"[bold]{target.name}[/bold]")
        console.print(f"id: {target.rule_id}")
        console.print(target.description)
        if target.mitre_techniques:
            console.print(f"mitre: {', '.join(target.mitre_techniques)}")
        if target.mitre_tactics:
            console.print(f"tactics: {', '.join(target.mitre_tactics)}")
        return
    raise typer.BadParameter("Use --list or --show <rule_id>")


@app.command()
def scan(
    logs: str = typer.Option(..., "--logs", help="Input log file"),
    iocs: str = typer.Option(..., "--iocs", help="IOC feed file"),
    out: str = typer.Option("reports", "--out", help="Output report directory"),
    format: str = typer.Option("md,json", "--format", help="Comma-separated formats: md,json,html"),
    config: str | None = typer.Option(None, "--config", help="Optional config.yaml path"),
    plugin: list[str] = typer.Option([], "--plugin", help="Path to custom plugin rule module (.py). Repeatable."),
    enrich_vt: bool = typer.Option(False, "--enrich-vt", help="Enable VirusTotal IOC enrichment"),
    vt_api_key: str | None = typer.Option(None, "--vt-api-key", help="VirusTotal API key (or VIRUSTOTAL_API_KEY env var)"),
    enrich_limit: int = typer.Option(5, "--enrich-limit", help="Max IOC enrichments per incident"),
    webhook_url: str | None = typer.Option(None, "--webhook-url", help="Send summary payload to webhook URL"),
    jira_url: str | None = typer.Option(None, "--jira-url", help="Jira Cloud base URL"),
    jira_user: str | None = typer.Option(None, "--jira-user", help="Jira user email"),
    jira_token: str | None = typer.Option(None, "--jira-token", help="Jira API token"),
    jira_project_key: str | None = typer.Option(None, "--jira-project-key", help="Jira project key, e.g. SEC"),
    jira_issue_type: str = typer.Option("Task", "--jira-issue-type", help="Jira issue type name"),
    min_severity: str = typer.Option("low", "--min-severity", help="low|medium|high|critical"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
) -> None:
    """Run full triage workflow: parse, detect, score, report."""
    min_severity = min_severity.lower()
    if min_severity not in {"low", "medium", "high", "critical"}:
        raise typer.BadParameter("--min-severity must be low|medium|high|critical")

    formats = _parse_formats(format)
    cfg = Config.load(config)
    events = parse_logs(logs)
    ioc_feed = load_iocs(iocs)

    if verbose:
        console.print(f"Loaded {len(events)} normalized events")
        console.print(f"IOC counts: {ioc_stats(ioc_feed)}")

    rule_classes = available_rules()
    configured_plugins = plugin or cfg.plugin_paths
    if configured_plugins:
        rule_classes.extend(load_plugin_rules(configured_plugins))

    hits: list[RuleHit] = []
    for rule_cls in rule_classes:
        rule = rule_cls()
        rule_hits = rule.run(events, cfg, iocs=ioc_feed)
        hits.extend(rule_hits)
        if verbose:
            console.print(f"Rule {rule.rule_id}: {len(rule_hits)} hit(s)")

    incidents = aggregate_hits(hits, grouping_window_seconds=cfg.incident_grouping_window_seconds)
    incidents = filter_by_min_severity(incidents, min_severity)

    vt_enabled = enrich_vt or cfg.enrich_virustotal
    vt_key = vt_api_key or cfg.virustotal_api_key
    vt_client = VirusTotalClient(
        vt_key,
        timeout=cfg.integration_timeout_seconds,
        max_retries=cfg.integration_max_retries,
        backoff_base_seconds=cfg.integration_backoff_base_seconds,
    )
    if vt_enabled and vt_client.enabled():
        for incident in incidents:
            ioc_candidates = sorted(collect_iocs_for_enrichment(incident.evidence, incident.entities))[:enrich_limit]
            vt_results = []
            for value in ioc_candidates:
                result = vt_client.lookup_ioc(value)
                if result:
                    vt_results.append(result)
            if vt_results:
                incident.enrichments["virustotal"] = vt_results

    output_dir = ensure_dir(out)
    stamp = ts_for_filename()
    run_meta = {
        "generated_at": now_utc_iso(),
        "logs_path": str(Path(logs).resolve()),
        "iocs_path": str(Path(iocs).resolve()),
        "min_severity": min_severity,
        "rule_set_version": "v1",
    }

    written: list[Path] = []
    if "md" in formats:
        md_path = output_dir / f"guardintent_report_{stamp}.md"
        written.append(write_markdown_report(md_path, incidents, run_meta))
    if "json" in formats:
        json_path = output_dir / f"guardintent_report_{stamp}.json"
        written.append(write_json_report(json_path, incidents, run_meta))
    if "html" in formats:
        html_path = output_dir / f"guardintent_report_{stamp}.html"
        written.append(write_html_report(html_path, incidents, run_meta))

    console.print(f"[green]Incidents generated:[/green] {len(incidents)}")
    for incident in incidents:
        console.print(f"- {incident.severity.upper()} ({incident.score}) {incident.title}")

    console.print("[bold]Reports:[/bold]")
    for path in written:
        console.print(f"- {path}")

    effective_webhook = webhook_url or cfg.export_webhook_url
    if effective_webhook:
        posted = post_webhook(
            effective_webhook,
            incidents,
            timeout=cfg.integration_timeout_seconds,
            max_retries=cfg.integration_max_retries,
            backoff_base_seconds=cfg.integration_backoff_base_seconds,
        )
        if verbose:
            console.print(f"Webhook export {'succeeded' if posted else 'failed'}: {effective_webhook}")

    jira_cfg = {
        "base": jira_url or cfg.jira_base_url,
        "user": jira_user or cfg.jira_user,
        "token": jira_token or cfg.jira_api_token,
        "project_key": jira_project_key or cfg.jira_project_key,
        "issue_type": jira_issue_type or cfg.jira_issue_type,
    }
    if jira_cfg["base"] and jira_cfg["user"] and jira_cfg["token"] and jira_cfg["project_key"]:
        created = create_jira_issues(
            jira_cfg["base"],
            jira_cfg["user"],
            jira_cfg["token"],
            jira_cfg["project_key"],
            jira_cfg["issue_type"],
            incidents,
            timeout=cfg.integration_timeout_seconds,
            max_retries=cfg.integration_max_retries,
            backoff_base_seconds=cfg.integration_backoff_base_seconds,
        )
        if verbose:
            console.print(f"Jira issues created: {len(created)}")


if __name__ == "__main__":
    app()
