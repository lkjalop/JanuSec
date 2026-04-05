from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .sandbox_adapters import build_sandbox_adapters, SandboxAdapter

class MemorySandboxRunner:
    """Best-effort sandbox runner that records submissions for evidence chains."""

    def __init__(self, *, storage_path: str | Path = 'data/memory_jobs/sandbox_runs.jsonl') -> None:
        self.path = Path(storage_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.adapters: List[SandboxAdapter] = build_sandbox_adapters()

    def submit(self, job: Any, analysis: Dict[str, Any]) -> Dict[str, Any]:
        submissions = []
        for adapter in self.adapters:
            try:
                submissions.append(adapter.submit(job, analysis))
            except Exception:
                submissions.append({'adapter': adapter.name, 'status': 'error'})
        payload = {
            'job_id': getattr(job, 'job_id', None),
            'host': getattr(job, 'host', None),
            'case_id': getattr(job, 'case_id', None),
            'submitted_at': time.time(),
            'status': 'submitted',
            'verdict': analysis.get('dread', {}).get('damage', 0.0),
            'factors': analysis.get('factors', []),
            'submissions': submissions,
        }
        try:
            with self.path.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(payload, separators=(',', ':')) + '\n')
        except Exception:
            pass
        return payload

    def recent(self, limit: int = 10) -> list[Dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: list[Dict[str, Any]] = []
        try:
            with self.path.open('r', encoding='utf-8') as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            return []
        return rows[-limit:]


__all__ = ['MemorySandboxRunner']
