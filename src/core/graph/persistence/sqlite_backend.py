from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict, List, Tuple


class SQLiteHopGraphBackend:
    """Lightweight SQLite backend for HopGraph persistence.

    Schema:
      - nodes(id TEXT PRIMARY KEY, type TEXT, label TEXT, last_seen REAL, json_meta TEXT)
      - edges(id TEXT PRIMARY KEY, src TEXT, dst TEXT, etype TEXT, last_seen REAL, json_meta TEXT)
      - wal_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, tenant TEXT, kind TEXT, payload TEXT)

    TTL pruning governed by env:
      - HOPGRAPH_NODE_TTL_HOURS (default 168)
      - HOPGRAPH_EDGE_TTL_HOURS (default 168)
    WAL retention:
      - HOPGRAPH_WAL_TTL_HOURS (default 24)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        return conn

    def _init(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                  id TEXT PRIMARY KEY,
                  type TEXT,
                  label TEXT,
                  last_seen REAL,
                  json_meta TEXT
                );
                CREATE TABLE IF NOT EXISTS edges (
                  id TEXT PRIMARY KEY,
                  src TEXT,
                  dst TEXT,
                  etype TEXT,
                  last_seen REAL,
                  json_meta TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_edges_last_seen ON edges(last_seen);
                CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
                CREATE TABLE IF NOT EXISTS wal_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts REAL,
                  tenant TEXT,
                  kind TEXT,
                                    payload TEXT
                );
                                CREATE TABLE IF NOT EXISTS snapshot_meta (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    snapshot_id TEXT,
                                    saved_seq_max INTEGER,
                                    edge_version INTEGER,
                                    nodes_json TEXT,
                                    adj_json TEXT,
                                    ts REAL
                                );
                """
            )
        finally:
            conn.close()

    # --- Node/Edge upserts ---
    def save_node(self, node_id: str, node_type: str, metadata: Dict[str, Any] | None = None, label: str | None = None, tenant: str | None = None) -> None:
        if not node_id:
            return
        now = time.time()
        import json
        # include tenant in metadata for multi-tenant lookups
        md = dict(metadata or {})
        if tenant:
            md.setdefault('_tenant', tenant)
        meta_json = json.dumps(md)
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO nodes(id, type, label, last_seen, json_meta)
                VALUES(?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  type=excluded.type,
                  label=COALESCE(excluded.label, nodes.label),
                  last_seen=excluded.last_seen,
                  json_meta=excluded.json_meta
                """,
                (node_id, node_type, label, now, meta_json)
            )
            conn.commit()
        finally:
            conn.close()

    def save_edge(self, src_id: str, dst_id: str, etype: str, metadata: Dict[str, Any] | None = None, tenant: str | None = None) -> None:
        if not src_id or not dst_id:
            return
        now = time.time()
        import json
        edge_id = f"{src_id}->{dst_id}:{etype}"
        md = dict(metadata or {})
        if tenant:
            md.setdefault('_tenant', tenant)
        meta_json = json.dumps(md)
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO edges(id, src, dst, etype, last_seen, json_meta)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  last_seen=excluded.last_seen,
                  json_meta=excluded.json_meta
                """,
                (edge_id, src_id, dst_id, etype, now, meta_json)
            )
            conn.commit()
        finally:
            conn.close()

    # --- Snapshots ---
    def snapshot(self, node_limit: int = 500, edge_limit: int = 1000) -> Dict[str, Any]:
        conn = self._conn()
        try:
            nodes = []
            edges = []
            for row in conn.execute("SELECT id,type,label,last_seen,json_meta FROM nodes ORDER BY last_seen DESC LIMIT ?", (node_limit,)):
                import json
                nodes.append({
                    'id': row[0], 'type': row[1], 'label': row[2], 'last_seen': row[3],
                    'metadata': json.loads(row[4] or '{}')
                })
            for row in conn.execute("SELECT id,src,dst,etype,last_seen,json_meta FROM edges ORDER BY last_seen DESC LIMIT ?", (edge_limit,)):
                import json
                edges.append({
                    'id': row[0], 'src': row[1], 'dst': row[2], 'etype': row[3], 'last_seen': row[4],
                    'metadata': json.loads(row[5] or '{}')
                })
            return {'nodes': nodes, 'edges': edges}
        finally:
            conn.close()

    # --- WAL / snapshot meta helpers for HopGraph ---
    def save_wal_record(self, seq: int, kind: str, record: Dict[str, Any], tenant: str | None = None) -> None:
        conn = self._conn()
        try:
            import json
            payload = json.dumps(record)
            conn.execute("INSERT INTO wal_events(ts, tenant, kind, payload) VALUES(?,?,?,?)", (time.time(), tenant or 'default', kind or '', payload))
            conn.commit()
        finally:
            conn.close()

    def load_wal_from(self, from_seq: int = 0, limit: int | None = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.cursor()
            q = "SELECT id, payload FROM wal_events ORDER BY id ASC"
            if limit:
                q = q + " LIMIT ?"
                rows = cur.execute(q, (limit,)).fetchall()
            else:
                rows = cur.execute(q).fetchall()
            import json
            out: List[Dict[str, Any]] = []
            for rid, payload in rows:
                try:
                    rec = json.loads(payload or '{}')
                except Exception:
                    continue
                # Use autoincrement id as fallback seq when record lacks seq
                if isinstance(rec, dict) and 'seq' not in rec:
                    rec['seq'] = int(rid)
                if int(rid) > int(from_seq):
                    out.append({'id': int(rid), 'rec': rec})
            return out
        finally:
            conn.close()

    def load_wal(self) -> List[Dict[str, Any]]:
        return self.load_wal_from(0, None)

    def save_snapshot_meta(self, snapshot_id: str, saved_seq_max: int, edge_version: int, nodes: Dict[str, Any], adj: Dict[str, Any], _tenant: str | None = None) -> None:
        conn = self._conn()
        try:
            import json
            nodes_json = json.dumps(nodes or {})
            adj_json = json.dumps(adj or {})
            conn.execute("INSERT INTO snapshot_meta(snapshot_id, saved_seq_max, edge_version, nodes_json, adj_json, ts) VALUES(?,?,?,?,?,?)",
                         (snapshot_id, int(saved_seq_max or 0), int(edge_version or 0), nodes_json, adj_json, time.time()))
            conn.commit()
        finally:
            conn.close()

    def load_latest_snapshot_meta(self, _tenant: str | None = None) -> Dict[str, Any] | None:
        conn = self._conn()
        try:
            cur = conn.execute("SELECT snapshot_id, saved_seq_max, edge_version, nodes_json, adj_json, ts FROM snapshot_meta ORDER BY ts DESC LIMIT 1")
            row = cur.fetchone()
            if not row:
                return None
            import json
            return {
                'snapshot_id': row[0],
                'saved_seq_max': int(row[1] or 0),
                'edge_version': int(row[2] or 0),
                'nodes': json.loads(row[3] or '{}'),
                'adj': json.loads(row[4] or '{}'),
                'ts': float(row[5] or 0.0)
            }
        finally:
            conn.close()

    def load_graph(self, tenant: str | None = None) -> Dict[str, Any]:
        """Return a HopGraph-friendly structure.

        The backend snapshot stores `nodes` as a list of dictionaries, but the
        in-memory HopGraph expects a node-id keyed mapping when preloading from
        persistence.  Returning a normalized shape here keeps both the direct
        backend tests and the HopGraph bootstrap path consistent.
        """
        data = self.snapshot()
        raw_nodes = data.get('nodes', []) or []
        raw_edges = data.get('edges', []) or []

        def _tenant_match(meta: Dict[str, Any] | None) -> bool:
            if tenant is None:
                return True
            if not meta:
                return True
            return meta.get('_tenant') == tenant

        nodes = {
            n['id']: {
                'id': n['id'],
                'type': n.get('type'),
                'label': n.get('label'),
                'last_seen': n.get('last_seen'),
                **(n.get('metadata') or {}),
            }
            for n in raw_nodes
            if n.get('id') and _tenant_match(n.get('metadata'))
        }
        edges = [e for e in raw_edges if _tenant_match(e.get('metadata'))]
        return {'nodes': nodes, 'edges': edges}

    # --- Pruning / Compaction ---
    def prune_old_edges(self, max_age_hours: int) -> int:
        cutoff = time.time() - (max_age_hours * 3600)
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM edges WHERE last_seen < ?", (cutoff,))
            conn.commit()
            return cur.rowcount or 0
        finally:
            conn.close()

    def prune_old_nodes(self, max_age_hours: int) -> int:
        cutoff = time.time() - (max_age_hours * 3600)
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM nodes WHERE last_seen < ?", (cutoff,))
            conn.commit()
            return cur.rowcount or 0
        finally:
            conn.close()

    def prune_wal(self, max_age_hours: int) -> int:
        cutoff = time.time() - (max_age_hours * 3600)
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM wal_events WHERE ts < ?", (cutoff,))
            conn.commit()
            return cur.rowcount or 0
        finally:
            conn.close()

    def vacuum(self) -> None:
        conn = self._conn()
        try:
            conn.execute('VACUUM')
        finally:
            conn.close()

    # --- WAL append (optional) ---
    def append_wal(self, tenant: str | None, kind: str, payload_json: str) -> None:
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO wal_events(ts, tenant, kind, payload) VALUES(?,?,?,?)",
                (time.time(), tenant or 'default', kind, payload_json)
            )
            conn.commit()
        finally:
            conn.close()

