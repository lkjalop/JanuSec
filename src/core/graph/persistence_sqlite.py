"""SQLite persistence helpers for HopGraph variants.

MVP scope: identity graph adjacency + ewma/high_value metadata.

Future extensions:
  - network graph edges (src,dst,etype,ts,weight,asn,prefix)
  - cloud graph resources (arn,type,last_seen,risk)
  - multi-tenant partitioning (tenant_id column)
  - Redis high-availability cache as write-through to SQLite

Environment variables:
  HOPGRAPH_SQLITE_PATH  -> path to sqlite DB file (default: data/hopgraph.db)
  HOPGRAPH_AUTOSAVE_INTERVAL_SECONDS -> periodic snapshot interval (0 disables)

Usage:
  from src.core.graph.persistence_sqlite import HopGraphPersistence
  PERSIST = HopGraphPersistence()
  PERSIST.save_identity(identity_graph)
  PERSIST.load_identity(identity_graph)

Thread-safety: SQLite writes are serialized with a lock. Reads are cheap.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict

DEFAULT_DB_PATH = os.getenv('HOPGRAPH_SQLITE_PATH', 'data/hopgraph.db')


class HopGraphPersistence:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._lock = threading.Lock()
        self._initialized = False
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        try:
            import sqlite3
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=10)
            cur = conn.cursor()
            # Identity graph tables
            cur.execute("CREATE TABLE IF NOT EXISTS identity_edges(src TEXT, dst TEXT, etype TEXT, ts REAL, weight REAL)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_identity_edges_src ON identity_edges(src)")
            cur.execute("CREATE TABLE IF NOT EXISTS identity_meta(k TEXT PRIMARY KEY, v TEXT)")
            conn.commit()
            conn.close()
            self._initialized = True
        except Exception:
            pass

    # --- Identity Graph ---
    def save_identity(self, identity_graph) -> bool:
        """Persist identity graph (adjacency, ewma, high_value)."""
        try:
            import sqlite3, json
            with self._lock:
                conn = sqlite3.connect(self.db_path, timeout=15)
                cur = conn.cursor()
                cur.execute("DELETE FROM identity_edges")
                to_insert = []
                for src, lst in identity_graph._adj.items():  # noqa: SLF001 (intentional internal access MVP)
                    for (dst, etype, ts, w) in lst:
                        to_insert.append((src, dst, etype, float(ts), float(w)))
                if to_insert:
                    cur.executemany("INSERT INTO identity_edges(src,dst,etype,ts,weight) VALUES(?,?,?,?,?)", to_insert)
                cur.execute("DELETE FROM identity_meta")
                cur.execute("INSERT OR REPLACE INTO identity_meta(k,v) VALUES(?,?)", ('ewma', json.dumps(identity_graph._ewma)))  # noqa: SLF001
                cur.execute("INSERT OR REPLACE INTO identity_meta(k,v) VALUES(?,?)", ('high_value', json.dumps(list(identity_graph._high_value))))  # noqa: SLF001
                conn.commit()
                conn.close()
            return True
        except Exception:
            return False

    def load_identity(self, identity_graph) -> bool:
        """Load previously persisted identity graph snapshot into memory."""
        try:
            import sqlite3, json
            if not os.path.exists(self.db_path):
                return False
            with self._lock:
                conn = sqlite3.connect(self.db_path, timeout=15)
                cur = conn.cursor()
                cur.execute("SELECT src,dst,etype,ts,weight FROM identity_edges")
                rows = cur.fetchall()
                from collections import defaultdict
                identity_graph._adj = defaultdict(list)  # noqa: SLF001
                for (src, dst, etype, ts, w) in rows:
                    try:
                        identity_graph._adj[src].append((dst, etype, float(ts), float(w)))  # noqa: SLF001
                    except Exception:
                        pass
                cur.execute("SELECT k,v FROM identity_meta")
                meta = {k: v for k, v in cur.fetchall()}
                import json as _json
                try:
                    identity_graph._ewma = _json.loads(meta.get('ewma', '{}'))  # noqa: SLF001
                except Exception:
                    identity_graph._ewma = {}
                try:
                    identity_graph._high_value = set(_json.loads(meta.get('high_value', '[]')))  # noqa: SLF001
                except Exception:
                    identity_graph._high_value = set()
                conn.close()
            return True
        except Exception:
            return False

    # --- Periodic autosave (optional) ---
    def start_autosave(self, identity_graph) -> None:
        interval = int(os.getenv('HOPGRAPH_AUTOSAVE_INTERVAL_SECONDS', '0') or '0')
        if interval <= 0:
            return
        def _loop():
            while True:
                try:
                    self.save_identity(identity_graph)
                except Exception:
                    pass
                time.sleep(interval)
        th = threading.Thread(target=_loop, name='hopgraph-autosave', daemon=True)
        th.start()


# Singleton persistence handle
GLOBAL_HOPGRAPH_PERSIST = HopGraphPersistence()

def maybe_load(identity_graph) -> None:
    """Attempt to load snapshot at startup (non-blocking failure)."""
    try:
        GLOBAL_HOPGRAPH_PERSIST.load_identity(identity_graph)
    except Exception:
        pass
