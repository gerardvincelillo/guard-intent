from __future__ import annotations

import csv
from pathlib import Path

from guard_intent.models import Event
from guard_intent.normalize.base import BaseParser
from guard_intent.normalize.normalizer import normalize_record


class CSVParser(BaseParser):
    def parse(self, path: str | Path) -> list[Event]:
        p = Path(path)
        events: list[Event] = []
        with p.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                events.append(normalize_record(row))
        return events

