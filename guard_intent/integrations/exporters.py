from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib import error, request

from guard_intent.models import Incident


def _request_with_retry(req: request.Request, timeout: int, max_retries: int, backoff_base_seconds: float) -> bytes | None:
    for attempt in range(max_retries + 1):
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except error.HTTPError as exc:
            if exc.code == 429 and attempt < max_retries:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                wait = float(retry_after) if retry_after and retry_after.isdigit() else backoff_base_seconds * (2 ** attempt)
                time.sleep(wait)
                continue
            if 500 <= exc.code < 600 and attempt < max_retries:
                time.sleep(backoff_base_seconds * (2 ** attempt))
                continue
            return None
        except (error.URLError, TimeoutError):
            if attempt < max_retries:
                time.sleep(backoff_base_seconds * (2 ** attempt))
                continue
            return None
    return None


def post_webhook(
    url: str,
    incidents: list[Incident],
    timeout: int = 8,
    max_retries: int = 3,
    backoff_base_seconds: float = 0.5,
) -> bool:
    payload = {
        "source": "guard_intent",
        "incident_count": len(incidents),
        "incidents": [
            {
                "title": i.title,
                "severity": i.severity,
                "score": i.score,
                "rule_hits": i.rule_hits,
                "entities": i.entities,
                "mitre_techniques": i.mitre_techniques,
                "mitre_tactics": i.mitre_tactics,
            }
            for i in incidents
        ],
    }
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return _request_with_retry(req, timeout, max_retries, backoff_base_seconds) is not None


def create_jira_issues(
    base_url: str,
    user: str,
    token: str,
    project_key: str,
    issue_type: str,
    incidents: list[Incident],
    timeout: int = 8,
    max_retries: int = 3,
    backoff_base_seconds: float = 0.5,
) -> list[dict[str, Any]]:
    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
    created: list[dict[str, Any]] = []

    for incident in incidents:
        body = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[GuardIntent] {incident.severity.upper()} - {incident.title}",
                "description": (
                    f"Score: {incident.score}\n"
                    f"Rule hits: {', '.join(incident.rule_hits)}\n"
                    f"MITRE tactics: {', '.join(incident.mitre_tactics) if incident.mitre_tactics else 'N/A'}\n"
                    f"MITRE techniques: {', '.join(incident.mitre_techniques) if incident.mitre_techniques else 'N/A'}\n"
                    f"Entities: {incident.entities}\n"
                    f"Recommendations: {incident.recommendations}"
                ),
                "issuetype": {"name": issue_type},
            }
        }
        req = request.Request(
            f"{base_url.rstrip('/')}/rest/api/3/issue",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
            },
            method="POST",
        )
        response_bytes = _request_with_retry(req, timeout, max_retries, backoff_base_seconds)
        if not response_bytes:
            continue
        try:
            payload = json.loads(response_bytes.decode("utf-8"))
            created.append(payload)
        except json.JSONDecodeError:
            continue
    return created

