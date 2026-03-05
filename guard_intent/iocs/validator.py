from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def classify_ioc(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if SHA256_RE.match(v):
        return "sha256"
    parsed = urlparse(v)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    if DOMAIN_RE.match(v.lower()):
        return "domain"
    return None
