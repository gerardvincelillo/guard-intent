from __future__ import annotations

import json
import os
import re
import time
from typing import Any
from urllib import error, request

from guardintent.iocs.validator import classify_ioc

_IPV4_CANDIDATE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_CANDIDATE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_CANDIDATE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
_URL_CANDIDATE = re.compile(r"https?://[^\s'\"]+")


class VirusTotalClient:
    def __init__(
        self,
        api_key: str | None = None,
        timeout: int = 8,
        max_retries: int = 3,
        backoff_base_seconds: float = 0.5,
    ) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base_seconds = backoff_base_seconds

    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup_ioc(self, ioc: str) -> dict[str, Any] | None:
        if not self.api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
        req = request.Request(
            url,
            headers={
                "x-apikey": self.api_key,
                "accept": "application/json",
            },
            method="GET",
        )

        for attempt in range(self.max_retries + 1):
            try:
                with request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                    meta = payload.get("meta", {})
                    return {
                        "query": ioc,
                        "count": meta.get("count", 0),
                        "engine": "virustotal",
                    }
            except error.HTTPError as exc:
                if exc.code == 429 and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    wait = float(retry_after) if retry_after and retry_after.isdigit() else self.backoff_base_seconds * (2 ** attempt)
                    time.sleep(wait)
                    continue
                if 500 <= exc.code < 600 and attempt < self.max_retries:
                    time.sleep(self.backoff_base_seconds * (2 ** attempt))
                    continue
                return None
            except (error.URLError, TimeoutError, json.JSONDecodeError):
                if attempt < self.max_retries:
                    time.sleep(self.backoff_base_seconds * (2 ** attempt))
                    continue
                return None
        return None


def _yield_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, dict):
        collected: list[str] = []
        for item in value.values():
            collected.extend(_yield_strings(item))
        return collected
    if isinstance(value, list):
        collected: list[str] = []
        for item in value:
            collected.extend(_yield_strings(item))
        return collected
    return []


def _extract_candidates(text: str) -> set[str]:
    candidates: set[str] = set()
    candidates.update(_IPV4_CANDIDATE.findall(text))
    candidates.update(_HASH_CANDIDATE.findall(text))
    candidates.update(_DOMAIN_CANDIDATE.findall(text))
    candidates.update(_URL_CANDIDATE.findall(text))
    return {c.strip().strip(".,;)") for c in candidates if c}


def collect_iocs_for_enrichment(
    incident_evidence: list[dict[str, Any]],
    incident_entities: dict[str, Any] | None = None,
) -> set[str]:
    values: set[str] = set()

    merged_payload = {"evidence": incident_evidence, "entities": incident_entities or {}}
    for text in _yield_strings(merged_payload):
        raw = text.strip()
        if not raw:
            continue

        ioc_type = classify_ioc(raw)
        if ioc_type:
            values.add(raw)

        for candidate in _extract_candidates(raw):
            if classify_ioc(candidate):
                values.add(candidate)

    return values
