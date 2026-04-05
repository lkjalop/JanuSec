from __future__ import annotations

import json
import time
import threading
import queue
import logging
import sqlite3
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Single DB path used by click storage
_DB_PATH = Path('data') / 'clicks.db'

# In-process enrichment queue
_CLICK_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue()


def _ensure_db() -> None:
    p = _DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT,
            event_id TEXT,
            user TEXT,
            tenant_id TEXT,
            url TEXT,
            verdict TEXT,
            ts REAL,
            meta TEXT
        )
        '''
    )
    cur.execute('CREATE INDEX IF NOT EXISTS idx_clicks_ts ON clicks(ts)')
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            reason TEXT,
            ts REAL,
            raw TEXT
        )
        '''
    )
    conn.commit()
    conn.close()


def record_click(record: Dict[str, Any]) -> bool:
    """Persist a click record after normalization/validation. Accepts either `message_id` or `event_id`."""
    try:
        if not isinstance(record, dict):
            logger.warning('record_click called with non-dict: %s', type(record))
            return False
        # Normalize & validate
        try:
            from src.schemas.normalized import normalize_and_validate
            normalized, ok, errs = normalize_and_validate('click_event', record)
        except Exception:
            normalized, ok, errs = record, True, []
        if not ok:
            logger.warning('invalid click_event, quarantining: %s', errs)
            _ensure_db()
            conn_q = sqlite3.connect(str(_DB_PATH))
            cur_q = conn_q.cursor()
            cur_q.execute('INSERT INTO quarantine (domain,reason,ts,raw) VALUES (?,?,?,?)', (
                'click_event', ','.join(errs), float(record.get('timestamp') or record.get('ts') or time.time()), json.dumps(record, separators=(',', ':'))
            ))
            conn_q.commit()
            conn_q.close()
            return False
        _ensure_db()
        conn = sqlite3.connect(str(_DB_PATH))
        cur = conn.cursor()
        ts = float(normalized.get('timestamp') or time.time())
        meta = json.dumps(normalized.get('meta') or {}, separators=(',', ':'))
        cur.execute(
            'INSERT INTO clicks (message_id,event_id,user,tenant_id,url,verdict,ts,meta) VALUES (?,?,?,?,?,?,?,?)',
            (
                normalized.get('message_id'),
                normalized.get('event_id'),
                normalized.get('user'),
                record.get('tenant_id'),
                normalized.get('url'),
                normalized.get('verdict'),
                ts,
                meta,
            ),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        logger.exception('record_click failed')
        return False


def add_click(event: Dict[str, Any]) -> None:
    """Compatibility alias for record_click with enrichment enqueue."""
    if not isinstance(event, dict):
        logger.warning('add_click called with non-dict event: %s', type(event))
        return
    try:
        from src.schemas.normalized import normalize_and_validate
        payload, ok, errs = normalize_and_validate('click_event', event)
    except Exception:
        payload, ok, errs = event, True, []
    if not ok:
        logger.warning('invalid click_event in add_click, quarantining: %s', errs)
        try:
            _ensure_db()
            conn_q = sqlite3.connect(str(_DB_PATH))
            cur_q = conn_q.cursor()
            cur_q.execute('INSERT INTO quarantine (domain,reason,ts,raw) VALUES (?,?,?,?)', (
                'click_event', ','.join(errs), float(event.get('timestamp') or event.get('ts') or time.time()), json.dumps(event, separators=(',', ':'))
            ))
            conn_q.commit()
            conn_q.close()
        except Exception:
            logger.exception('failed to persist quarantine record')
        return

    # persist
    try:
        record_click(payload)
    except Exception:
        logger.exception('failed to persist click')

    # enqueue for enrichment
    try:
        _CLICK_QUEUE.put_nowait(payload)
    except Exception:
        logger.exception('failed to enqueue click for enrichment')


try:
    from src.connectors.email.click_events import ClickEvent
except Exception:
    ClickEvent = None


def enqueue_click(evt) -> None:
    if ClickEvent is not None and isinstance(evt, ClickEvent):
        payload = {
            'message_id': getattr(evt, 'message_id', None),
            'event_id': getattr(evt, 'event_id', None),
            'user': getattr(evt, 'user', None),
            'url': getattr(evt, 'url', None),
            'verdict': getattr(evt, 'verdict', None),
            'ts': time.time(),
            'meta': {'ua': getattr(evt, 'user_agent', None), 'ip': getattr(evt, 'ip', None)},
        }
        add_click(payload)
    elif isinstance(evt, dict):
        add_click(evt)
    else:
        logger.warning('enqueue_click received unsupported type: %s', type(evt))


def _enrichment_worker_loop(correlation_engine, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            item = _CLICK_QUEUE.get(timeout=1)
        except Exception:
            continue
        try:
            if correlation_engine is not None and hasattr(correlation_engine, 'enrich_click'):
                try:
                    correlation_engine.enrich_click(item)
                except Exception:
                    logger.exception('correlation_engine.enrich_click failed')
        except Exception:
            logger.exception('failed enrich click')
        finally:
            try:
                _CLICK_QUEUE.task_done()
            except Exception:
                pass


def start_enrichment_worker(correlation_engine, daemon: bool = True):
    stop_event = threading.Event()
    t = threading.Thread(target=_enrichment_worker_loop, args=(correlation_engine, stop_event), daemon=daemon)
    t.start()
    return stop_event


def fetch_recent_clicks(limit: int = 100) -> List[Dict[str, Any]]:
    try:
        _ensure_db()
        conn = sqlite3.connect(str(_DB_PATH))
        cur = conn.cursor()
        cur.execute('SELECT id,message_id,event_id,user,tenant_id,url,verdict,ts,meta FROM clicks ORDER BY ts DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        conn.close()
        out: List[Dict[str, Any]] = []
        for r in rows:
            meta = None
            try:
                meta = json.loads(r[8]) if r[8] else None
            except Exception:
                meta = r[8]
            out.append({'id': r[0], 'message_id': r[1], 'event_id': r[2], 'user': r[3], 'tenant_id': r[4], 'url': r[5], 'verdict': r[6], 'timestamp': r[7], 'meta': meta})
        return out
    except Exception:
        logger.exception('failed to fetch recent clicks')
        return []


__all__ = ['record_click', 'add_click', 'enqueue_click', 'fetch_recent_clicks', 'start_enrichment_worker']
