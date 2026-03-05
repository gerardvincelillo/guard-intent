from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    brute_force_window_seconds: int = 300
    brute_force_threshold: int = 5
    lateral_window_seconds: int = 300
    lateral_unique_hosts_threshold: int = 5
    privileged_accounts: set[str] = field(default_factory=lambda: {"admin", "administrator", "root"})
    rare_process_min_count: int = 1
    plugin_paths: list[str] = field(default_factory=list)
    enrich_virustotal: bool = False
    virustotal_api_key: str | None = None
    export_webhook_url: str | None = None
    jira_base_url: str | None = None
    jira_user: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = "Task"
    integration_timeout_seconds: int = 8
    integration_max_retries: int = 3
    integration_backoff_base_seconds: float = 0.5
    incident_grouping_window_seconds: int = 900


    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        if not path:
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        privileged = data.get("privileged_accounts")
        if privileged is not None:
            data["privileged_accounts"] = set(privileged)
        return cls(**data)
