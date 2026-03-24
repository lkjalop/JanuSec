"""Report Snapshots Repository

Provides immutable, integrity-checked snapshots for Executive/ingestion reports.
Files are stored under reports/snapshots/<report_id>.json with structure:
{
  "meta": { "report_id": str, "tenant_id": str|None, "generated_at": float, "sha256": str, "title": str|None, "notes": str|None },
  "payload": { ... ingestion report json ... }
}
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


_LOCK = threading.Lock()
_BASE = Path('reports') / 'snapshots'


@dataclass
class SnapshotMeta:
    report_id: str
    tenant_id: str | None
    generated_at: float
    sha256: str
    title: str | None = None
    notes: str | None = None
    artifact_type: str | None = None
    source_type: str | None = None
    source_id: str | None = None
    available_formats: list[str] | None = None


def _ensure_dir():
    try:
        _BASE.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _calc_digest(payload: dict) -> str:
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode('utf-8')
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        return ''


def save_snapshot(
    payload: dict,
    tenant_id: str | None = None,
    title: str | None = None,
    notes: str | None = None,
    report_id: str | None = None,
    artifact_type: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
    available_formats: list[str] | None = None,
) -> SnapshotMeta:
    _ensure_dir()
    ts = float(payload.get('generated_at') or time.time())
    rid = report_id or payload.get('report_id') or f"rep-{int(ts)}-{uuid.uuid4().hex[:8]}"
    digest = _calc_digest(payload)
    meta = SnapshotMeta(
        report_id=rid,
        tenant_id=tenant_id,
        generated_at=ts,
        sha256=digest,
        title=title,
        notes=notes,
        artifact_type=artifact_type,
        source_type=source_type,
        source_id=source_id,
        available_formats=available_formats or ['json', 'html', 'csv'],
    )
    blob = { 'meta': asdict(meta), 'payload': payload }
    p = _BASE / f"{rid}.json"
    with _LOCK:
        if not p.exists():
            try:
                with p.open('w', encoding='utf-8') as fh:
                    json.dump(blob, fh)
            except Exception:
                pass
    return meta


def list_snapshots(tenant_id: str | None = None, limit: int = 50) -> list[dict]:
    _ensure_dir()
    out: list[dict] = []
    try:
        for entry in _BASE.iterdir():
            if entry.is_file() and entry.suffix.lower() == '.json':
                try:
                    with entry.open(encoding='utf-8') as fh:
                        data = json.load(fh)
                    meta = data.get('meta') or {}
                    if tenant_id and meta.get('tenant_id') not in {tenant_id}:
                        continue
                    out.append({
                        'report_id': meta.get('report_id'),
                        'tenant_id': meta.get('tenant_id'),
                        'generated_at': meta.get('generated_at'),
                        'sha256': meta.get('sha256'),
                        'title': meta.get('title'),
                        'notes': meta.get('notes'),
                        'artifact_type': meta.get('artifact_type'),
                        'source_type': meta.get('source_type'),
                        'source_id': meta.get('source_id'),
                        'available_formats': meta.get('available_formats') or ['json', 'html', 'csv'],
                    })
                except Exception:
                    continue
        out.sort(key=lambda x: (-(x.get('generated_at') or 0), x.get('report_id') or ''))
    except Exception:
        pass
    return out[:limit]


def _load_snapshot_blob(report_id: str) -> dict | None:
    _ensure_dir()
    p = _BASE / f"{report_id}.json"
    if not p.exists():
        return None
    try:
        with p.open(encoding='utf-8') as fh:
            data = json.load(fh)
        payload = data.get('payload') or {}
        expected = (data.get('meta') or {}).get('sha256')
        calc = _calc_digest(payload)
        if expected and expected != calc:
            # Integrity failure; refuse to return payload
            return None
        return data
    except Exception:
        return None


def load_snapshot(report_id: str) -> dict | None:
    data = _load_snapshot_blob(report_id)
    if not data:
        return None
    return data.get('payload') or {}


def load_snapshot_meta(report_id: str) -> dict | None:
    data = _load_snapshot_blob(report_id)
    if not data:
        return None
    meta = data.get('meta')
    return meta if isinstance(meta, dict) else None


__all__ = ['save_snapshot', 'list_snapshots', 'load_snapshot', 'load_snapshot_meta', 'SnapshotMeta']
