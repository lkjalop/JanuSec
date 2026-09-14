"""Simple HopGraph ingest queue and session builder.

This module provides a durable file-backed queue for events intended for
correlation and a tiny session builder that computes pairwise overlap and
an EWMA-smoothed overlap metric. It's a stub suitable for local testing
and can be replaced by a real HopGraph client later.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, Iterable
import hashlib
import time

BASE = Path('data/sessions')
BASE.mkdir(parents=True, exist_ok=True)


def _session_id_for_event(ev: Dict[str, Any]) -> str:
    """Derive a session id for simple correlation by hashing key fields."""
    key = f"{ev.get('type')}-{ev.get('src_ip')}-{ev.get('dst_ip')}-{ev.get('dst_port', '')}"
    return hashlib.sha1(key.encode('utf-8')).hexdigest()


def enqueue_event(ev: Dict[str, Any]) -> str:
    """Persist event into a session-specific JSONL file and return session_id."""
    sid = _session_id_for_event(ev)
    # ensure base dir exists for current cwd (tests may change cwd)
    BASE.mkdir(parents=True, exist_ok=True)
    path = BASE / f"{sid}.events.jsonl"
    rec = dict(ev)
    rec.setdefault('ingest_ts', time.time())
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(rec))
        f.write('\n')
    # update session metadata if exporter provided
    exporter = ev.get('exporter') if isinstance(ev, dict) else None
    if exporter:
        try:
            _update_session_metadata(sid, exporter)
        except Exception:
            pass
    return sid


def _update_session_metadata(sid: str, exporter: Dict[str, Any]) -> None:
    """Add or update exporter metadata for a session.

    Stores metadata in `{sid}.meta.json` containing exporter address list and last_seen.
    """
    meta_path = BASE / f"{sid}.meta.json"
    meta = {'session_id': sid, 'exporters': [], 'created_ts': time.time()}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            meta = {'session_id': sid, 'exporters': [], 'created_ts': time.time()}

    # exporter expected shape: {'ip': '1.2.3.4', 'port': 4739}
    ip = exporter.get('ip') if isinstance(exporter, dict) else None
    port = exporter.get('port') if isinstance(exporter, dict) else None
    if not ip:
        return
    now = time.time()
    # find existing exporter entry
    for e in meta.get('exporters', []):
        if e.get('ip') == ip and e.get('port') == port:
            e['last_seen'] = now
            e['count'] = e.get('count', 0) + 1
            break
    else:
        meta.setdefault('exporters', []).append({'ip': ip, 'port': port, 'first_seen': now, 'last_seen': now, 'count': 1})

    try:
        meta_path.write_text(json.dumps(meta))
    except Exception:
        pass
    # Rebuild and persist the session summary so UI/clients can read a single
    # up-to-date `{sid}.summary.json` file after metadata changes.
    try:
        build_session_summary(sid)
    except Exception:
        # Non-fatal: metadata was written, but summary rebuild failed.
        pass


def _read_session_events(sid: str) -> Iterable[Dict[str, Any]]:
    path = BASE / f"{sid}.events.jsonl"
    if not BASE.exists() or not path.exists():
        return []
    out = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def compute_pairwise_overlap(events: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Compute simple pairwise overlap counts for keys seen per event.

    For each event we collect a set of 'features' (ip,port,service) and then
    compute counts of how often pairs co-occur across events.
    """
    # collect feature sets per event
    feat_sets = []
    for ev in events:
        s = set()
        if ev.get('src_ip'):
            s.add(f"src:{ev.get('src_ip')}")
        if ev.get('dst_ip'):
            s.add(f"dst:{ev.get('dst_ip')}")
        if ev.get('dst_port'):
            s.add(f"port:{ev.get('dst_port')}")
        if ev.get('service'):
            s.add(f"svc:{ev.get('service')}")
        feat_sets.append(s)

    # compute pairwise counts
    counts: Dict[str, Dict[str, int]] = {}
    for s in feat_sets:
        for a in s:
            counts.setdefault(a, {})
            for b in s:
                if a == b:
                    continue
                counts[a][b] = counts[a].get(b, 0) + 1
    return counts


def compute_ewma_matrix(raw_counts: Dict[str, Dict[str, int]], prev_ewma: Dict[str, Dict[str, float]] | None = None, alpha: float = 0.6) -> Dict[str, Dict[str, float]]:
    """Apply EWMA smoothing to raw pairwise counts.

    `prev_ewma` is optional historical matrix; alpha in (0,1]
    """
    if prev_ewma is None:
        prev_ewma = {}
    ewma: Dict[str, Dict[str, float]] = {}
    for a, row in raw_counts.items():
        ewma.setdefault(a, {})
        prow = prev_ewma.get(a, {})
        for b, v in row.items():
            p = prow.get(b, 0.0)
            ewma[a][b] = round(alpha * float(v) + (1 - alpha) * float(p), 3)
    return ewma


def build_session_summary(sid: str, alpha: float = 0.6) -> Dict[str, Any]:
    events = _read_session_events(sid)
    raw = compute_pairwise_overlap(events)
    # load prior ewma if exists (per-session)
    ewma_path = BASE / f'{sid}.ewma.json'
    prev = None
    if ewma_path.exists():
        try:
            prev = json.loads(ewma_path.read_text())
        except Exception:
            prev = None
    ewma = compute_ewma_matrix(raw, prev, alpha=alpha)
    # persist ewma history (per-session)
    try:
        ewma_path.write_text(json.dumps(ewma))
    except Exception:
        pass
    summary = {
        'session_id': sid,
        'event_count': len(events),
        'raw_overlap': raw,
        'ewma_overlap': ewma,
        'alpha': alpha,
    }
    # include exporter metadata if present
    meta_path = BASE / f'{sid}.meta.json'
    if meta_path.exists():
        try:
            summary['exporters'] = json.loads(meta_path.read_text()).get('exporters', [])
        except Exception:
            summary['exporters'] = []
    else:
        summary['exporters'] = []
    # persist summary
    summary_path = BASE / f'{sid}.summary.json'
    try:
        summary_path.write_text(json.dumps(summary))
    except Exception:
        pass
    return summary


def list_sessions() -> Dict[str, Dict[str, any]]:
    """List available sessions with basic metadata."""
    out = {}
    if not BASE.exists():
        return out
    for p in BASE.glob('*.events.jsonl'):
        sid = p.name.split('.')[0]
        stats = p.stat()
        summary_path = BASE / f'{sid}.summary.json'
        out[sid] = {
            'session_id': sid,
            'events_file': str(p),
            'summary_exists': summary_path.exists(),
            'size_bytes': stats.st_size,
            'modified_ts': stats.st_mtime,
        }
    return out


def cleanup_sessions(ttl_seconds: int = 60 * 60 * 24 * 7) -> int:
    """Remove session files older than `ttl_seconds` and return deleted count.

    Also removes per-session summaries and EWMA files.
    """
    now = time.time()
    removed = 0
    for p in list(BASE.glob('*.events.jsonl')):
        if now - p.stat().st_mtime > ttl_seconds:
            sid = p.name.split('.')[0]
            try:
                # remove events file
                p.unlink()
                removed += 1
                # remove summary and ewma
                for ext in ('.summary.json', '.ewma.json'):
                    f = BASE / f'{sid}{ext}'
                    if f.exists():
                        f.unlink()
            except Exception:
                continue
    return removed


def get_session_events(sid: str):
    return list(_read_session_events(sid))
