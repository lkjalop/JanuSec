"""Simple writeback DLQ: store failed writebacks to disk for retry.

This is intentionally minimal: in production use a durable queue (Redis/DB).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

DLQ_PATH = os.getenv('WRITEBACK_DLQ_PATH') or 'artifacts/writeback_dlq.jsonl'
os.makedirs(os.path.dirname(DLQ_PATH) or '.', exist_ok=True)


def enqueue(payload: dict[str, Any]) -> None:
    try:
        with open(DLQ_PATH, 'a', encoding='utf-8') as f:
            obj = {'ts': time.time(), 'payload': payload}
            f.write(json.dumps(obj) + '\n')
    except Exception:
        pass

def drain(limit: int = 100) -> list[dict[str, Any]]:
    """Return up to `limit` DLQ items for retry. This is a destructive read.

    For demo only: reads file, returns first N, and rewrites remainder.
    """
    out = []
    try:
        with open(DLQ_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return out
    remaining = lines[limit:]
    for line in lines[:limit]:
        try:
            obj = json.loads(line)
            out.append(obj.get('payload'))
        except Exception:
            pass
    try:
        with open(DLQ_PATH, 'w', encoding='utf-8') as f:
            for ln in remaining:
                f.write(ln)
    except Exception:
        pass
    return out


__all__ = ['enqueue','drain']
