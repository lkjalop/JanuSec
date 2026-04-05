import json
import os
import time
from threading import Lock
from typing import Dict, Any, List, Optional
import sqlite3

STORE_PATH = os.getenv('EVENT_STORE_PATH', 'data/events.jsonl')
STORE_TTL = int(os.getenv('EVENT_STORE_TTL_SECONDS', str(60*60*24*7)))  # default 7 days
BACKEND = (os.getenv('EVENT_STORE_BACKEND') or 'jsonl').lower()
SQLITE_PATH = os.getenv('EVENT_STORE_SQLITE_PATH', 'data/events.db')

_lock = Lock()

def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _sqlite_conn() -> Optional[sqlite3.Connection]:
    if BACKEND != 'sqlite':
        return None
    try:
        _ensure_dir(SQLITE_PATH)
        conn = sqlite3.connect(SQLITE_PATH, timeout=5)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                event_id TEXT UNIQUE,
                sensor TEXT,
                ts_event REAL,
                user TEXT,
                host TEXT,
                ip TEXT,
                ip_dst TEXT,
                domain TEXT,
                file_hash TEXT,
                payload TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_filehash ON events(file_hash)")
        return conn
    except Exception:
        return None

def append_event(event: Dict[str, Any]) -> bool:
    if BACKEND == 'sqlite':
        try:
            conn = _sqlite_conn()
            if not conn:
                return False
            with _lock:
                ts_now = time.time()
                ev_id = event.get('event_id')
                sensor = event.get('sensor')
                ts_event = event.get('ts') or ts_now
                payload = json.dumps(event, default=str)
                # extract common entity fields
                user = event.get('user')
                host = event.get('host') or event.get('hostname')
                ip = event.get('ip') or event.get('src_ip')
                ip_dst = event.get('ip_dst') or event.get('dest_ip') or event.get('dst_ip')
                domain = event.get('domain')
                file_hash = event.get('file_hash') or event.get('sha256')
                conn.execute(
                    "INSERT OR REPLACE INTO events(ts, event_id, sensor, ts_event, user, host, ip, ip_dst, domain, file_hash, payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (ts_now, ev_id, sensor, float(ts_event), user, host, ip, ip_dst, domain, file_hash, payload)
                )
                conn.commit()
            return True
        except Exception:
            return False
    # JSONL fallback
    try:
        _ensure_dir(STORE_PATH)
        line = json.dumps({'ts': time.time(), 'event': event}, default=str)
        with _lock:
            with open(STORE_PATH, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
        return True
    except Exception:
        return False

def load_events(limit: int = 1000) -> List[Dict[str, Any]]:
    if BACKEND == 'sqlite':
        try:
            conn = _sqlite_conn()
            if not conn:
                return []
            cur = conn.execute("SELECT ts, payload FROM events ORDER BY id DESC LIMIT ?", (int(limit),))
            rows = cur.fetchall()
            out: List[Dict[str, Any]] = []
            for ts_val, payload in rows[::-1]:  # oldest to newest
                try:
                    event = json.loads(payload)
                    out.append({'ts': ts_val, 'event': event})
                except Exception:
                    continue
            return out
        except Exception:
            return []
    out: List[Dict[str, Any]] = []
    if not os.path.exists(STORE_PATH):
        return out
    try:
        with open(STORE_PATH, 'r', encoding='utf-8') as fh:
            for l in fh:
                try:
                    rec = json.loads(l)
                    out.append(rec)
                except Exception:
                    continue
        return out[-limit:]
    except Exception:
        return []

def get_event_by_id(event_id: str) -> Optional[Dict[str, Any]]:
    if BACKEND == 'sqlite':
        try:
            conn = _sqlite_conn()
            if not conn:
                return None
            cur = conn.execute("SELECT payload FROM events WHERE event_id = ? LIMIT 1", (event_id,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])
        except Exception:
            return None
    # JSONL scan (not optimized)
    if not os.path.exists(STORE_PATH):
        return None
    try:
        with open(STORE_PATH, 'r', encoding='utf-8') as fh:
            for l in fh:
                try:
                    rec = json.loads(l)
                    ev = rec.get('event') or {}
                    if ev.get('event_id') == event_id:
                        return ev
                except Exception:
                    continue
    except Exception:
        return None
    return None


def query_events_by_entity(filters: Dict[str, Any], limit: int = 200) -> List[Dict[str, Any]]:
    """Return events matching simple entity filters (user, host, ip, ip_dst, domain, file_hash), ordered by ts_event asc.

    Supports both SQLite and JSONL backends; SQLite uses indexed columns.
    """
    fields = ['user','host','ip','ip_dst','domain','file_hash']
    applied = {k: str(v) for k, v in filters.items() if k in fields and v}
    if BACKEND == 'sqlite':
        try:
            conn = _sqlite_conn()
            if not conn:
                return []
            where = []
            params = []
            for k, v in applied.items():
                where.append(f"{k} = ?")
                params.append(v)
            if not where:
                return []
            sql = "SELECT ts_event, payload FROM events WHERE " + " AND ".join(where) + " ORDER BY ts_event ASC LIMIT ?"
            params.append(int(limit))
            cur = conn.execute(sql, tuple(params))
            rows = cur.fetchall()
            out: List[Dict[str, Any]] = []
            for ts_event, payload in rows:
                try:
                    ev = json.loads(payload)
                    if ev.get('ts') is None:
                        ev['ts'] = ts_event
                    out.append(ev)
                except Exception:
                    continue
            return out
        except Exception:
            return []
    # JSONL fallback: load recent and filter in memory (best-effort)
    events = load_events(limit=5000)
    out2: List[Dict[str, Any]] = []
    for rec in events:
        ev = rec.get('event') or {}
        ok = True
        for k, v in applied.items():
            if str(ev.get(k) or '') != v:
                ok = False
                break
        if ok:
            if ev.get('ts') is None:
                ev['ts'] = rec.get('ts')
            out2.append(ev)
        if len(out2) >= limit:
            break
    out2.sort(key=lambda e: e.get('ts') or 0)
    return out2

def cleanup_expired(ttl: int = STORE_TTL):
    if BACKEND == 'sqlite':
        try:
            conn = _sqlite_conn()
            if not conn:
                return
            cutoff = time.time() - ttl
            with _lock:
                conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                conn.commit()
        except Exception:
            return
        return
    # JSONL rewrite without expired entries
    if not os.path.exists(STORE_PATH):
        return
    cutoff = time.time() - ttl
    tmp = STORE_PATH + '.tmp'
    try:
        with _lock:
            with open(STORE_PATH, 'r', encoding='utf-8') as fh_in, open(tmp, 'w', encoding='utf-8') as fh_out:
                for l in fh_in:
                    try:
                        rec = json.loads(l)
                        if rec.get('ts', 0) >= cutoff:
                            fh_out.write(json.dumps(rec) + '\n')
                    except Exception:
                        continue
            os.replace(tmp, STORE_PATH)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
