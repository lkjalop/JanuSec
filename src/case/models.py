"""Case management models with file persistence."""
from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Evidence:
    id: str
    type: str
    details: dict[str, Any]
    ts: float = field(default_factory=lambda: time.time())


@dataclass
class Task:
    id: str
    title: str
    assignee: str | None = None
    status: str = 'open'
    ts: float = field(default_factory=lambda: time.time())


@dataclass
class Case:
    id: str
    org_id: str
    severity: str = 'low'
    status: str = 'open'
    assignee: str | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)
    evidences: list[Evidence] = field(default_factory=list)
    tasks: list[Task] = field(default_factory=list)

    def append_timeline(self, actor: str, action: str, details: dict[str, Any] | None = None):
        self.timeline.append({'ts': time.time(), 'actor': actor, 'action': action, 'details': details or {}})

    def add_evidence(self, ev: Evidence):
        self.evidences.append(ev)
        self.append_timeline('system', 'add_evidence', {'evidence_id': ev.id})

    def add_task(self, task: Task):
        self.tasks.append(task)
        self.append_timeline('system', 'add_task', {'task_id': task.id})


import dataclasses
import json
import os
import threading

_CASES_LOCK = threading.Lock()
_CASES: dict[str, Case] = {}


def _cases_path() -> str:
    return os.getenv('CASE_STORE_PATH', os.path.join('data', 'cases.jsonl'))


def _load_cases_from_disk() -> None:
    path = _cases_path()
    if not os.path.exists(path):
        return
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    evidences = [Evidence(**e) for e in (d.pop('evidences', None) or [])]
                    tasks = [Task(**t) for t in (d.pop('tasks', None) or [])]
                    c = Case(**d)
                    c.evidences = evidences
                    c.tasks = tasks
                    _CASES[c.id] = c
                except Exception:
                    pass
    except Exception:
        pass


def _persist_case(case: Case) -> None:
    path = _cases_path()
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        d = dataclasses.asdict(case)
        line = json.dumps(d, default=str)
        # Rewrite whole file to avoid duplicate entries for same case id
        all_cases = list(_CASES.values())
        with open(path, 'w', encoding='utf-8') as fh:
            for c in all_cases:
                fh.write(json.dumps(dataclasses.asdict(c), default=str) + '\n')
    except Exception:
        pass


# Load from disk on module import
_load_cases_from_disk()


def create_case(case: Case) -> Case:
    with _CASES_LOCK:
        _CASES[case.id] = case
    _persist_case(case)
    return case


def get_case(case_id: str) -> Case | None:
    return _CASES.get(case_id)


def update_case(case: Case) -> Case:
    """Persist any in-place mutations to a case."""
    with _CASES_LOCK:
        _CASES[case.id] = case
    _persist_case(case)
    return case


def list_cases(org_id: str | None = None) -> list[Case]:
    cases = list(_CASES.values())
    if org_id:
        cases = [c for c in cases if c.org_id == org_id]
    return sorted(cases, key=lambda c: c.timeline[-1]['ts'] if c.timeline else 0, reverse=True)
