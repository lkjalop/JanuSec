"""In-memory Decision Label Store (Stage 10 Scaffold)

Provides minimal persistence & query for analyst / automated labels.
Will be extended for DB-backed implementation later.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Iterable, Optional

VALID_LABELS = {"tp","fp","benign","suspicious","escalated"}

@dataclass
class DecisionLabel:
    event_id: str
    label: str
    source: str
    reviewer: str | None
    ts: float

class LabelsStore:
    def __init__(self):
        self._labels: Dict[str, List[DecisionLabel]] = {}

    def add_label(self, event_id: str, label: str, source: str, reviewer: str | None = None, ts: float | None = None) -> DecisionLabel:
        if label not in VALID_LABELS:
            raise ValueError(f"invalid_label: {label}")
        rec = DecisionLabel(event_id=event_id, label=label, source=source, reviewer=reviewer, ts=ts or time.time())
        self._labels.setdefault(event_id, []).append(rec)
        return rec

    def get(self, event_id: str) -> List[DecisionLabel]:
        return list(self._labels.get(event_id, []))

    def recent(self, limit: int = 500) -> List[DecisionLabel]:
        all_entries: List[DecisionLabel] = []
        for lst in self._labels.values():
            all_entries.extend(lst)
        return sorted(all_entries, key=lambda r: r.ts, reverse=True)[:limit]

LABELS = LabelsStore()

__all__ = ["LABELS","DecisionLabel","VALID_LABELS"]