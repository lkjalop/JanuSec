"""Simple in-memory co-occurrence store for factor pairs.

This module provides a lightweight frequency map and a PMI-like scoring helper
used by the graph session builder. It's intentionally simple for prototype use
and exposes simple pruning/decay hooks.
"""
from __future__ import annotations

import threading
import time
import os
import yaml
from typing import Dict, Tuple, List, Optional
import sqlite3
from pathlib import Path

_lock = threading.Lock()
# key: (a,b) sorted tuple -> (count, last_ts)
_pairs: Dict[Tuple[str,str], Tuple[float,float]] = {}

# suppression rules loaded from config (tuple->adjustment)
_suppression_templates: Dict[Tuple[str,str], float] = {}

def _load_config(path: Optional[str] = None) -> None:
    global _suppression_templates
    cfg_path = path or os.getenv('COOCCURRENCE_CONFIG_PATH', 'config/cooccurrence.yaml')
    try:
        if not os.path.exists(cfg_path):
            return
        with open(cfg_path, 'r', encoding='utf-8') as fh:
            doc = yaml.safe_load(fh) or {}
        sup = doc.get('suppression_templates') or {}
        new = {}
        for k,v in sup.items():
            # keys may be 'a,b' or list
            if isinstance(k, str):
                parts = [p.strip() for p in k.split(',') if p.strip()]
            elif isinstance(k, (list,tuple)):
                parts = [str(x).strip() for x in k]
            else:
                continue
            if len(parts) != 2:
                continue
            new[tuple(sorted((parts[0],parts[1])))] = float(v)
        _suppression_templates = new
    except Exception:
        # on error, keep existing templates
        pass

_load_config()

def add_pairs(pairs: List[Tuple[str,str]]) -> None:
    now = time.time()
    with _lock:
        for a,b in pairs:
            key = tuple(sorted((str(a),str(b))))
            c, _ = _pairs.get(key, (0.0, now))
            _pairs[key] = (c + 1.0, now)
    # persist incrementally if configured
    try:
        db = os.getenv('COOCCURRENCE_SQLITE_PATH')
        if db:
            Path(os.path.dirname(db)).mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db, timeout=5)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS pair_counts(key TEXT PRIMARY KEY, count REAL, last_ts REAL)")
            for a,b in pairs:
                key = '__'.join(sorted((str(a),str(b))))
                cur.execute("INSERT INTO pair_counts(key,count,last_ts) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET count=count+excluded.count, last_ts=excluded.last_ts", (key, 1.0, now))
            conn.commit(); conn.close()
    except Exception:
        pass

def get_top(n: int = 100) -> List[Tuple[Tuple[str,str], float, float]]:
    with _lock:
        items = [ (k, v[0], v[1]) for k,v in _pairs.items() ]
    items.sort(key=lambda x: x[1], reverse=True)
    return items[:n]

def get_counts() -> Tuple[Dict[Tuple[str,str], float], Dict[str, float], float]:
    """Return (pair_counts, marginal_counts, total_count).

    - pair_counts: map (a,b) -> count
    - marginal_counts: map factor -> count
    - total_count: sum of all pair counts (pairs counted once)
    """
    # If persistent DB configured, load marginals from DB to include historical counts
    pair_counts: Dict[Tuple[str,str], float] = {}
    try:
        db = os.getenv('COOCCURRENCE_SQLITE_PATH')
        if db and Path(db).exists():
            conn = sqlite3.connect(db, timeout=5)
            cur = conn.cursor()
            cur.execute("SELECT key,count FROM pair_counts")
            for row in cur.fetchall():
                key = tuple(row[0].split('__'))
                pair_counts[key] = float(row[1])
            conn.close()
    except Exception:
        # fallback to in-memory snapshot
        with _lock:
            pair_counts = {k: v[0] for k,v in _pairs.items()}
    marg: Dict[str, float] = {}
    total = 0.0
    for (a,b), c in pair_counts.items():
        marg[a] = marg.get(a, 0.0) + c
        marg[b] = marg.get(b, 0.0) + c
        total += c
    return (pair_counts, marg, total)


def flush_to_db(path: Optional[str] = None) -> None:
    """Atomic flush of in-memory counts to the configured SQLite DB."""
    db = path or os.getenv('COOCCURRENCE_SQLITE_PATH')
    if not db:
        return
    try:
        Path(os.path.dirname(db)).mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db, timeout=10)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS pair_counts(key TEXT PRIMARY KEY, count REAL, last_ts REAL)")
        with _lock:
            for (a,b), (c, ts) in _pairs.items():
                key = '__'.join((a,b))
                cur.execute("INSERT INTO pair_counts(key,count,last_ts) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET count=count+excluded.count, last_ts=excluded.last_ts", (key, c, ts))
        conn.commit(); conn.close()
    except Exception:
        pass

def prune_older(threshold_seconds: float = 60*60*24*7) -> int:
    """Prune pairs not updated within threshold_seconds.
    Returns number pruned.
    """
    now = time.time()
    removed = 0
    with _lock:
        keys = list(_pairs.keys())
        for k in keys:
            _, ts = _pairs[k]
            if now - ts > threshold_seconds:
                del _pairs[k]
                removed += 1
    return removed

def clear() -> None:
    with _lock:
        _pairs.clear()

def stats() -> Dict[str,int]:
    with _lock:
        return {'unique_pairs': len(_pairs)}

def get_suppression_templates() -> Dict[Tuple[str,str], float]:
    return dict(_suppression_templates)

def reload_config(path: Optional[str] = None) -> None:
    _load_config(path)
