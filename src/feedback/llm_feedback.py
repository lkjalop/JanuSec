"""Helpers for aggregating LLM feedback from analyst dispositions."""
from __future__ import annotations

import json
import os
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, List

FEEDBACK_PATH = Path(os.getenv('LLM_FEEDBACK_LOG', 'data/llm_feedback.jsonl'))
DATASET_PATH = Path(os.getenv('LLM_FEEDBACK_DATASET', 'data/llm_feedback_dataset.jsonl'))


def _load_entries(limit: int = 1000) -> List[Dict[str, Any]]:
    if not FEEDBACK_PATH.exists():
        return []
    entries: Deque[Dict[str, Any]] = deque(maxlen=limit)
    try:
        with FEEDBACK_PATH.open('r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return list(entries)


def summarize_feedback(limit: int = 1000) -> Dict[str, Any]:
    entries = _load_entries(limit)
    if not entries:
        return {'count': 0, 'models': {}, 'factors': {}, 'recent': []}
    model_counts: Dict[str, Counter] = {}
    factor_counter: Counter = Counter()
    recent = []
    for entry in reversed(entries):
        model = entry.get('model') or 'unknown'
        action = entry.get('analyst_action') or entry.get('disposition') or 'unknown'
        model_counts.setdefault(model, Counter()).update([action])
        for factor in entry.get('factors') or []:
            factor_counter.update([factor])
        if len(recent) < 20:
            recent.append(entry)
    return {
        'count': len(entries),
        'models': {m: dict(c) for m, c in model_counts.items()},
        'top_factors': factor_counter.most_common(20),
        'recent': recent,
    }


def export_dataset(limit: int = 5000) -> str:
    entries = _load_entries(limit)
    if not entries:
        return ''
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open('w', encoding='utf-8') as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + '\n')
    return str(DATASET_PATH.resolve())
