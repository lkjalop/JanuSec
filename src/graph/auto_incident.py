import os
import time
import threading
import traceback
import hashlib
import json as _json
from typing import Optional, Dict, Any

from src.graph.hopgraph import HopGraph, GLOBAL_HOPGRAPH

# Optional Redis for persistent dedup across restarts. Use redis-py if available.
_REDIS_URL = os.getenv('INCIDENT_AUTOGEN_DEDUP_REDIS')
_use_redis = False
_redis_client = None
if _REDIS_URL:
    try:
        import redis
        _redis_client = redis.from_url(_REDIS_URL)
        # verify conn
        try:
            _redis_client.ping()
            _use_redis = True
        except Exception:
            _use_redis = False
    except Exception:
        _use_redis = False

# Optional outbox path for autogen incidents (if you prefer decoupled persistence)
_OUTBOX_PATH = os.getenv('INCIDENT_AUTOGEN_OUTBOX')  # e.g. data/autogen_outbox.jsonl


def _create_incident(payload: Dict[str, Any]) -> bool:
    try:
        # Prefer test-friendly API modules first (src.api.incidents, src.api.server),
        # then fall back to repository adapter.
        tenant = payload.get('tenant') or payload.get('tenant_id') or os.getenv('DEFAULT_TENANT', 'default')
        iid = payload.get('id') or f"autoinc-{int(time.time()*1000)}"

        repo_payload = {
            'artifact_id': payload.get('artifact_id') or payload.get('source_node') or f"auto-{int(time.time()*1000)}",
            'title': payload.get('title') or f"AutoIncident: {payload.get('reason')}",
            'severity': payload.get('severity') or 'high',
            'status': payload.get('status') or 'open',
            'summary': payload.get('description') or f"Auto-generated incident (score={payload.get('score')})",
            'metadata': {
                'autogen': True,
                'score': payload.get('score'),
                'chain': payload.get('chain'),
                'reason': payload.get('reason'),
                'timestamp': payload.get('timestamp'),
            },
        }
        # If a legacy/internal module exists that tests may monkeypatch, prefer that
        try:
            import importlib
            try:
                mod = importlib.import_module('src.api.incidents')
                if hasattr(mod, 'create_incident'):
                    try:
                        # call synchronously if test shim provided
                        mod.create_incident(payload)
                        return True
                    except Exception:
                        # ignore and continue to repo path
                        pass
            except Exception:
                pass
        except Exception:
            pass

        # Try server in-memory incident store next (tests often inject this)
        try:
            import src.api.server as _server
            item = {
                'id': iid,
                'artifact_id': repo_payload.get('artifact_id'),
                'title': repo_payload.get('title'),
                'severity': repo_payload.get('severity'),
                'status': repo_payload.get('status'),
                'summary': repo_payload.get('summary'),
                'metadata': repo_payload.get('metadata'),
                'created_at': time.time(),
                'tenant_id': tenant,
            }
            try:
                _server._INCIDENT_STORE.append(item)
                return True
            except Exception:
                pass
        except Exception:
            pass

        # Finally, prefer repository adapter if available
        try:
            from src.repositories import incidents_repo
        except Exception:
            incidents_repo = None  # type: ignore

        if incidents_repo and hasattr(incidents_repo, 'upsert_incident'):
            try:
                import asyncio
                coro = incidents_repo.upsert_incident(iid, repo_payload, tenant)
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop is not None and loop.is_running():
                    asyncio.create_task(coro)
                else:
                    # run in new loop (best-effort); avoid blocking long
                    try:
                        asyncio.run(coro)
                    except Exception:
                        try:
                            import concurrent.futures
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                                ex.submit(asyncio.run, coro).result(timeout=5)
                        except Exception:
                            pass
                return True
            except Exception:
                pass

        # last resort: write JSONL
        try:
            path = os.getenv('INCIDENT_AUTOGEN_DUMP', 'data/autogen_incidents.jsonl')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'a', encoding='utf-8') as f:
                f.write(_json.dumps({'id': iid, 'tenant': tenant, 'payload': repo_payload}) + '\n')
            return True
        except Exception:
            return False
    except Exception:
        return False


class AutoIncidentScanner:
    def __init__(self, hop: Optional[HopGraph] = None):
        self.hop = hop or GLOBAL_HOPGRAPH
        self.interval = max(5, int(os.getenv('INCIDENT_AUTOGEN_INTERVAL_SECONDS','60') or 60))
        self.enabled = os.getenv('INCIDENT_AUTOGEN_ENABLED','0').lower() in {'1','true','yes'}
        self.threshold = float(os.getenv('INCIDENT_AUTOGEN_SCORE_THRESHOLD','0.8') or 0.8)
        self._thread = None
        self._stop = threading.Event()
        # Dedup cache: map chain_hash -> last_emit_ts
        try:
            self._dedup_ttl = int(os.getenv('INCIDENT_AUTOGEN_DEDUP_TTL_SECONDS','3600') or 3600)
        except Exception:
            self._dedup_ttl = 3600
        self._dedup: Dict[str, float] = {}
        # Per-tenant rate limiting (timestamps queue)
        try:
            self._tenant_rate_max = int(os.getenv('INCIDENT_AUTOGEN_TENANT_RATE_MAX','10') or 10)
        except Exception:
            self._tenant_rate_max = 10
        try:
            self._tenant_rate_window = int(os.getenv('INCIDENT_AUTOGEN_TENANT_RATE_WINDOW_SECONDS','3600') or 3600)
        except Exception:
            self._tenant_rate_window = 3600
        self._tenant_map: Dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def start(self):
        if not self.enabled:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='auto-incident', daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=2)

    def _scan_once(self):
        try:
            # 1) Detect domain pivot sequences and emit factors (idempotent)
            try:
                self.hop.detect_domain_pivot_sequences(window_seconds=600, min_prefixes=5)
            except Exception:
                pass

            # 2) For processes with the factor 'corr_domain_pivot_sequence', explain from that node
            now = time.time()
            candidates = []
            for nid, meta in list(self.hop.nodes.items()):
                try:
                    if meta.get('type') == 'process' and 'corr_domain_pivot_sequence' in (meta.get('factors') or []):
                        candidates.append(nid)
                except Exception:
                    continue

            for c in sorted(candidates):
                try:
                    res = self.hop.explain_chain(c, max_depth=4, beam_width=6, top_k=3)
                    for ch in res.get('chains', []):
                        score = float(ch.get('score', 0.0) or 0.0)
                        try:
                            from src.security.threshold_jitter import get_jittered_threshold as _jitter
                            _effective_threshold = _jitter(self.threshold)
                        except Exception:
                            _effective_threshold = self.threshold
                        if score < _effective_threshold:
                            continue
                        tenant = (self.hop.nodes.get(c) or {}).get('tenant') or os.getenv('DEFAULT_TENANT','default')
                        # Create a deterministic chain hash for dedup
                        try:
                            chain_ser = _json.dumps(ch.get('nodes', []) + [h.get('etype') for h in ch.get('hops', [])], sort_keys=True)
                            chain_hash = hashlib.sha256(chain_ser.encode('utf-8')).hexdigest()
                        except Exception:
                            chain_hash = hashlib.sha256(str(ch).encode('utf-8')).hexdigest()
                        emit = False
                        now_ts = time.time()
                        # Dedup with Redis if available
                        if _use_redis and _redis_client is not None:
                            try:
                                key = f"autogen:dedup:{chain_hash}"
                                # SETNX with expiry
                                was_set = _redis_client.set(name=key, value=str(int(now_ts)), nx=True, ex=self._dedup_ttl)
                                if was_set:
                                    emit = True
                                else:
                                    emit = False
                            except Exception:
                                # fallback to in-memory below
                                emit = False
                        if not emit:
                            with self._lock:
                                # prune old dedup entries
                                try:
                                    expired = [k for k,v in self._dedup.items() if (now_ts - v) > self._dedup_ttl]
                                    for k in expired:
                                        try: del self._dedup[k]
                                        except Exception: pass
                                except Exception:
                                    pass
                                last = self._dedup.get(chain_hash)
                                if last is None or (now_ts - last) >= 0:
                                    # check tenant rate window
                                    q = self._tenant_map.setdefault(tenant, [])
                                    # prune old timestamps
                                    cutoff = now_ts - self._tenant_rate_window
                                    while q and q[0] < cutoff:
                                        q.pop(0)
                                    if len(q) < self._tenant_rate_max:
                                        # allow emit
                                        emit = True
                                        q.append(now_ts)
                                        self._dedup[chain_hash] = now_ts
                        if emit:
                            incident = {
                                'tenant': tenant,
                                'source_node': c,
                                'score': score,
                                'chain': ch,
                                'timestamp': now_ts,
                                'autogen': True,
                                'reason': 'corr_domain_pivot_sequence',
                            }
                            # Optional outbox write for decoupled persistence
                            if _OUTBOX_PATH:
                                try:
                                    os.makedirs(os.path.dirname(_OUTBOX_PATH), exist_ok=True)
                                    with open(_OUTBOX_PATH, 'a', encoding='utf-8') as f:
                                        f.write(_json.dumps(incident) + '\n')
                                except Exception:
                                    pass
                            _create_incident(incident)
                except Exception:
                    traceback.print_exc()
                    continue
        except Exception:
            traceback.print_exc()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception:
                traceback.print_exc()
            # sleep with early exit
            for _ in range(max(1, int(self.interval))):
                if self._stop.is_set():
                    break
                time.sleep(1)


_AUTO_SCANNER: Optional[AutoIncidentScanner] = None


def register_auto_incident(app=None):
    global _AUTO_SCANNER
    if _AUTO_SCANNER is None:
        _AUTO_SCANNER = AutoIncidentScanner()
    try:
        _AUTO_SCANNER.start()
    except Exception:
        pass
    return _AUTO_SCANNER
