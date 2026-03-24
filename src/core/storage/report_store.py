from __future__ import annotations
import os
import json
import time
import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


class BaseAdapter:
    def get(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError()

    def save(self, assessment_id: str, payload: Dict[str, Any], persist_path: Optional[str] = None) -> None:
        raise NotImplementedError()

    def list_keys(self) -> Iterable[str]:
        raise NotImplementedError()

    def delete(self, assessment_id: str) -> None:
        raise NotImplementedError()


class InMemoryAdapter(BaseAdapter):
    def __init__(self, initial: Optional[Dict[str, Dict[str, Any]]] = None):
        self.store: Dict[str, Dict[str, Any]] = dict(initial or {})

    def get(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(assessment_id)

    def save(self, assessment_id: str, payload: Dict[str, Any], persist_path: Optional[str] = None) -> None:
        self.store[assessment_id] = payload

    def list_keys(self) -> Iterable[str]:
        return list(self.store.keys())

    def delete(self, assessment_id: str) -> None:
        self.store.pop(assessment_id, None)


class FileAdapter(BaseAdapter):
    def __init__(self, base_dir: Optional[str] = None):
        repo_root = os.getcwd()
        self.base = base_dir or os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        os.makedirs(self.base, exist_ok=True)
        self.index_dir = os.path.join(self.base, 'index')
        os.makedirs(self.index_dir, exist_ok=True)

    def _path_for(self, assessment_id: str) -> str:
        safe = str(assessment_id)
        return os.path.join(self.base, f"{safe}.json")

    def get(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        path = self._path_for(assessment_id)
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    return json.load(fh)
            except Exception:
                logger.exception('Failed reading assessment file %s', path)
                return None
        # try index lookup
        idx = os.path.join(self.index_dir, f"{assessment_id}.path")
        if os.path.exists(idx):
            try:
                with open(idx, 'r', encoding='utf-8') as fh:
                    p = fh.read().strip()
                if p and os.path.exists(p):
                    with open(p, 'r', encoding='utf-8') as fh:
                        return json.load(fh)
            except Exception:
                logger.exception('Failed reading index path for %s', assessment_id)
        return None

    def save(self, assessment_id: str, payload: Dict[str, Any], persist_path: Optional[str] = None) -> None:
        path = persist_path or self._path_for(assessment_id)
        tmp = path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, default=str)
            os.replace(tmp, path)
            # write index
            idx = os.path.join(self.index_dir, f"{assessment_id}.path")
            ttmp = idx + '.tmp'
            with open(ttmp, 'w', encoding='utf-8') as fh:
                fh.write(path)
            os.replace(ttmp, idx)
        except Exception:
            logger.exception('Failed to persist assessment %s to %s', assessment_id, path)

    def list_keys(self) -> Iterable[str]:
        for fname in os.listdir(self.base):
            if not fname.endswith('.json'):
                continue
            yield fname[:-5]

    def delete(self, assessment_id: str) -> None:
        path = self._path_for(assessment_id)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            logger.exception('Failed deleting %s', path)
        try:
            idx = os.path.join(self.index_dir, f"{assessment_id}.path")
            if os.path.exists(idx):
                os.remove(idx)
        except Exception:
            pass


class RedisAdapter(BaseAdapter):
    def __init__(self, url: Optional[str] = None, prefix: str = 'assessment'):
        try:
            import redis as _redis  # type: ignore
        except Exception:
            raise
        red_url = url or os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
        self.client = _redis.from_url(red_url) if red_url else _redis.Redis()
        self.prefix = prefix

    def _key(self, aid: str) -> str:
        return f"{self.prefix}:{aid}"

    def get(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        try:
            raw = self.client.get(self._key(assessment_id))
            if not raw:
                return None
            return json.loads(raw)
        except Exception:
            logger.exception('Redis get failed for %s', assessment_id)
            return None

    def save(self, assessment_id: str, payload: Dict[str, Any], persist_path: Optional[str] = None) -> None:
        try:
            self.client.set(self._key(assessment_id), json.dumps(payload, default=str))
        except Exception:
            logger.exception('Redis save failed for %s', assessment_id)

    def list_keys(self) -> Iterable[str]:
        try:
            for k in self.client.scan_iter(f"{self.prefix}:*"):
                try:
                    kstr = k.decode() if isinstance(k, bytes) else str(k)
                    yield kstr.split(':', 1)[1]
                except Exception:
                    continue
        except Exception:
            return []

    def delete(self, assessment_id: str) -> None:
        try:
            self.client.delete(self._key(assessment_id))
        except Exception:
            logger.exception('Redis delete failed for %s', assessment_id)


class PostgresAdapter(BaseAdapter):
    def __init__(self, dsn: Optional[str] = None):
        try:
            import psycopg2
            import psycopg2.extras
        except Exception:
            raise
        self.dsn = dsn or os.getenv('APP_DB_DSN') or os.getenv('DATABASE_URL')
        # ensure table exists lazily
        try:
            with psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS reports (
                            id TEXT PRIMARY KEY,
                            payload JSONB,
                            created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
                            updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
                        )
                        """
                    )
                    conn.commit()
        except Exception:
            logger.exception('Failed ensuring reports table')

    def _conn(self):
        import psycopg2
        import psycopg2.extras
        return psycopg2.connect(self.dsn)

    def get(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self._conn() as conn:
                with conn.cursor(cursor_factory=None) as cur:
                    cur.execute('SELECT payload FROM reports WHERE id=%s', (assessment_id,))
                    row = cur.fetchone()
                    if not row:
                        return None
                    return row[0]
        except Exception:
            logger.exception('Postgres get failed for %s', assessment_id)
            return None

    def save(self, assessment_id: str, payload: Dict[str, Any], persist_path: Optional[str] = None) -> None:
        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO reports (id,payload,updated_at) VALUES (%s,%s,now()) ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()",
                        (assessment_id, json.dumps(payload, default=str)),
                    )
                    conn.commit()
        except Exception:
            logger.exception('Postgres save failed for %s', assessment_id)

    def list_keys(self) -> Iterable[str]:
        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT id FROM reports')
                    for row in cur.fetchall():
                        yield row[0]
        except Exception:
            logger.exception('Postgres list_keys failed')
            return []

    def delete(self, assessment_id: str) -> None:
        try:
            with self._conn() as conn:
                with conn.cursor() as cur:
                    cur.execute('DELETE FROM reports WHERE id=%s', (assessment_id,))
                    conn.commit()
        except Exception:
            logger.exception('Postgres delete failed for %s', assessment_id)


class ReportStoreProxy:
    def __init__(self, adapter: Optional[BaseAdapter] = None):
        self.adapter = adapter or InMemoryAdapter()

    def get(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self.adapter.get(assessment_id)

    def save(self, assessment_id: str, payload: Dict[str, Any], persist_path: Optional[str] = None) -> None:
        try:
            self.adapter.save(assessment_id, payload, persist_path=persist_path)
        except Exception:
            logger.exception('Adapter save failed; falling back to in-memory')
            # best-effort fallback to in-memory
            if not isinstance(self.adapter, InMemoryAdapter):
                try:
                    mem = InMemoryAdapter()
                    mem.save(assessment_id, payload, persist_path=persist_path)
                    self.adapter = mem
                except Exception:
                    pass

    def list_keys(self) -> List[str]:
        return list(self.adapter.list_keys())

    def delete(self, assessment_id: str) -> None:
        return self.adapter.delete(assessment_id)

    # Mapping-like convenience methods used by callers
    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: str) -> Dict[str, Any]:
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: Dict[str, Any]) -> None:
        return self.save(key, value)

    def get_all_items(self) -> Iterable[tuple[str, Dict[str, Any]]]:
        for k in self.list_keys():
            v = self.get(k)
            if v is not None:
                yield (k, v)

    def items(self):
        return list(self.get_all_items())

    def keys(self):
        return self.list_keys()

    def setdefault(self, key: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        existing = self.get(key)
        if existing is not None:
            return existing
        val = default or {}
        self.save(key, val)
        return val

    def pop(self, key: str, default: Optional[Any] = None) -> Any:
        val = self.get(key)
        if val is None:
            return default
        try:
            self.delete(key)
        except Exception:
            pass
        return val

    def update(self, mapping: Dict[str, Dict[str, Any]]) -> None:
        for k, v in (mapping or {}).items():
            try:
                self.save(k, v)
            except Exception:
                logger.exception('Failed updating key %s', k)


# Factory to choose adapter
def _build_default_adapter() -> BaseAdapter:
    backend = os.getenv('STORAGE_BACKEND', '').lower().strip()
    if not backend:
        env_mode = os.getenv('ENV', os.getenv('JANUSEC_ENV', 'dev')).lower().strip()
        if os.getenv('APP_DB_DSN') or os.getenv('DATABASE_URL'):
            backend = 'postgres' if env_mode in {'staging', 'prod', 'production'} else 'file'
        elif os.getenv('SESSION_PERSIST_DIR') or os.getenv('REPORTS_PERSIST_DIR'):
            backend = 'file'
        else:
            backend = 'memory'
    if backend == 'memory':
        return InMemoryAdapter()
    if backend == 'file':
        return FileAdapter()
    if backend == 'redis':
        try:
            return RedisAdapter()
        except Exception:
            logger.exception('RedisAdapter init failed; falling back to file')
            return FileAdapter()
    if backend == 'postgres' or backend == 'postgresql':
        try:
            return PostgresAdapter()
        except Exception:
            logger.exception('PostgresAdapter init failed; falling back to file')
            return FileAdapter()
    return InMemoryAdapter()


# Singleton instance used by application modules
report_store = ReportStoreProxy(adapter=_build_default_adapter())


def migrate_from_inmemory(source: Dict[str, Dict[str, Any]], target: Optional[ReportStoreProxy] = None) -> int:
    """Migrate records from an in-memory dict into the active adapter or specified target.

    Returns number of migrated records.
    """
    if target is None:
        target = report_store
    count = 0
    for k, v in (source or {}).items():
        try:
            target.save(k, v, persist_path=(v.get('persisted_path') if isinstance(v, dict) else None))
            count += 1
        except Exception:
            logger.exception('Failed migrating %s', k)
            continue
    return count


def incremental_rerank(assessment_id: str, new_scores: Dict[str, float], target: Optional[ReportStoreProxy] = None) -> None:
    """Merge new_scores into the assessment's ranking and persist.

    `new_scores` is a mapping of item_id -> numeric score (higher is better).
    This updates `rep['ranking']` (list of dicts with keys 'id','score','updated_ts').
    """
    if target is None:
        target = report_store
    try:
        rep = target.get(assessment_id) or {}
        ranking = rep.get('ranking') or []
        # convert to dict for easy merge
        rank_map: Dict[str, Dict] = {r['id']: r for r in ranking if isinstance(r, dict) and 'id' in r}
        now = time.time()
        for iid, sc in (new_scores or {}).items():
            try:
                entry = rank_map.get(iid) or {'id': iid, 'score': float(sc), 'updated_ts': now}
                entry['score'] = float(sc)
                entry['updated_ts'] = now
                rank_map[iid] = entry
            except Exception:
                continue
        # produce sorted ranking (highest score first)
        merged = sorted(rank_map.values(), key=lambda x: x.get('score', 0.0), reverse=True)
        rep['ranking'] = merged
        target.save(assessment_id, rep)
    except Exception:
        logger.exception('Failed incremental_rerank for %s', assessment_id)
