from __future__ import annotations

import json
from pathlib import Path

from guard_intent.models import Event
from guard_intent.normalize.base import BaseParser
from guard_intent.normalize.normalizer import normalize_record


class JSONParser(BaseParser):
    def parse(self, path: str | Path) -> list[Event]:
        p = Path(path)
        events: list[Event] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            events.append(normalize_record(raw))
        return events

