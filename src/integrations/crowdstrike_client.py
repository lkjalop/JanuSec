import os
import json
from typing import Any, Dict, List, Optional, Tuple
import time
import httpx

from src.core.security.secret_provider import SecretProvider
from src.core.connectors.checkpoint_store_v2 import CheckpointStoreV2
try:
    from src.integrations.checkpoint_store import CheckpointStore as LegacyCheckpointStore
except Exception:
    LegacyCheckpointStore = None
from src.core.http.client import request_with_retry_sync
from src.core.metrics.connectors_metrics import events_ingested_total, ingest_errors_total, retry_attempts_total, ingest_latency_seconds, queue_depth


class CrowdStrikeClient:
    def __init__(self, base_url: str, client_id: Optional[str] = None, client_secret: Optional[str] = None, client: Optional[httpx.Client] = None):
        self.base_url = base_url.rstrip('/')
        self.sp = SecretProvider()
        # allow explicit override from constructor (tests pass id/secret as positionals)
        self.client_id = client_id or self.sp.get('CROWDSTRIKE_CLIENT_ID')
        self.client_secret = client_secret or self.sp.get('CROWDSTRIKE_CLIENT_SECRET')
        self.token = self.sp.get('CROWDSTRIKE_API_TOKEN', 'test-token')
        self.store = None
        self.checkpoint = CheckpointStoreV2()
        # optional httpx.Client provided by tests for mock transport
        self.client = client

    def _ensure_store(self):
        # CheckpointStoreV2 is ready on init; keep for compatibility
        if getattr(self, 'store', None) is None:
            # If tests set an explicit per-connector checkpoint path after
            # client construction, prefer the legacy single-file CheckpointStore
            # so test expectations remain valid. Build an adapter lazily here.
            cp_path = os.getenv('CROWDSTRIKE_CHECKPOINT_PATH')
            if cp_path and LegacyCheckpointStore is not None:
                legacy = LegacyCheckpointStore(cp_path)

                class _LegacyAdapter:
                    def __init__(self, legacy_store):
                        self.legacy = legacy_store

                    def load(self, source: str, stream_id: str):
                        val = self.legacy.load(stream_id)
                        if val is None:
                            return None
                        if stream_id == 'crowdstrike:last' and isinstance(val, str):
                            return {'timestamp': val}
                        return val

                    def save(self, source: str, stream_id: str, payload):
                        if stream_id == 'crowdstrike:last' and isinstance(payload, dict) and 'timestamp' in payload:
                            self.legacy.save('crowdstrike:last', payload.get('timestamp'))
                        else:
                            # legacy.save expects (key, value) where key is the stream_id
                            self.legacy.save(stream_id, payload)

                self.store = _LegacyAdapter(legacy)
            else:
                self.store = self.checkpoint

    def _headers(self) -> Dict[str, str]:
        return {'Authorization': f'Bearer {self.token}', 'Accept': 'application/json'}

    def _get_token(self) -> str:
        # prefer explicit token from SecretProvider; fallback to token exchange if service provided
        token = self.sp.get('CROWDSTRIKE_API_TOKEN')
        if token:
            self.token = token
            return self.token
        auth_url = os.getenv('CROWDSTRIKE_AUTH_URL')
        if auth_url and self.client_id and self.client_secret:
            try:
                if self.client is not None:
                    # Prefer generic .request if available, otherwise fall back to .post
                    if hasattr(self.client, 'request'):
                        r = self.client.request('POST', auth_url, data={'client_id': self.client_id, 'client_secret': self.client_secret})
                    elif hasattr(self.client, 'post'):
                        r = self.client.post(auth_url, data={'client_id': self.client_id, 'client_secret': self.client_secret})
                    else:
                        r = request_with_retry_sync('POST', auth_url, data={'client_id': self.client_id, 'client_secret': self.client_secret})
                else:
                    r = request_with_retry_sync('POST', auth_url, data={'client_id': self.client_id, 'client_secret': self.client_secret})
                if getattr(r, 'status_code', 200) < 400:
                    body = r.json()
                    self.token = body.get('access_token', self.token)
            except Exception:
                pass
        return self.token

    def list_events(self, url: Optional[str] = None) -> Tuple[Dict[str, Any], int]:
        fixture = os.getenv('CROWDSTRIKE_FIXTURE_PATH')
        if fixture and os.path.exists(fixture):
            with open(fixture, 'r', encoding='utf-8') as f:
                return json.load(f), 200
        target = url or f"{self.base_url}/events"
        self._get_token()
        start = time.time()
        if self.client is not None:
            # perform local retry loop when a test provides an httpx.Client
            import time as _time, random as _random
            attempt = 0
            retries = int(os.getenv('CROWDSTRIKE_MAX_RETRIES', '3'))
            backoff = float(os.getenv('CROWDSTRIKE_BACKOFF_BASE', '0.5'))
            while True:
                # Support test clients that expose .request or .get
                if hasattr(self.client, 'request'):
                    r = self.client.request('GET', target, headers=self._headers())
                elif hasattr(self.client, 'get'):
                    r = self.client.get(target, headers=self._headers())
                else:
                    r = request_with_retry_sync('GET', target, headers=self._headers())
                if r.status_code < 400:
                    break
                attempt += 1
                if attempt > retries or r.status_code not in (429, 500, 502, 503, 504):
                    break
                wait = backoff * (2 ** (attempt - 1)) + _random.uniform(0, 0.25)
                _time.sleep(wait)
        else:
            r = request_with_retry_sync('GET', target, headers=self._headers())
        elapsed = time.time() - start
        retry_attempts_total.labels(connector='crowdstrike').inc(0)
        ingest_latency_seconds.labels(connector='crowdstrike').observe(elapsed)
        status = r.status_code
        if status >= 400:
            ingest_errors_total.labels(connector='crowdstrike', code=str(status)).inc()
            r.raise_for_status()
        return r.json(), status

    def canonicalize(self, item: Dict[str, Any]) -> Dict[str, Any]:
        ev = item.get('event', {})
        return {
            'ts': ev.get('timestamp'),
            'host': ev.get('aid'),
            'user': ev.get('UserName')
        }

    def fetch_since(self, limit: int = 100, app=None) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        # Support stream-id or timestamp modes using CheckpointStoreV2
        self._ensure_store()
        stream_id = os.getenv('CROWDSTRIKE_STREAM_ID')
        if stream_id:
            cursor_key = f'crowdstrike:stream:{stream_id}:cursor'
            last_cursor_obj = self.store.load('crowdstrike', cursor_key)
            last_cursor = last_cursor_obj.get('cursor') if last_cursor_obj else None
            params = []
            if last_cursor:
                params.append(f"cursor={last_cursor}")
            params.append(f"limit={limit}")
            base = f"{self.base_url}/events/{stream_id}"
            url = base + (('?' + '&'.join(params)) if params else '')
            data, status = self.list_events(url)
            items = data.get('resources', [])
            canon = [self.canonicalize(i) for i in items]
            meta = data.get('meta') or {}
            new_cursor = meta.get('cursor') or data.get('next_token') or data.get('cursor')
            if new_cursor:
                self.store.save('crowdstrike', cursor_key, {'cursor': str(new_cursor)})
            # queue depth metric update if app provided
            if app is not None and hasattr(app.state, 'connector_queues'):
                q = app.state.connector_queues.get('crowdstrike')
                if q is not None:
                    queue_depth.labels(connector='crowdstrike').set(q.qsize())
            events_ingested_total.labels(connector='crowdstrike').inc(len(canon))
            return canon, new_cursor
        else:
            last_obj = self.store.load('crowdstrike', 'crowdstrike:last')
            last = last_obj.get('timestamp') if last_obj else None
            params = []
            if last:
                params.append(f"offset={last}")
            params.append(f"limit={limit}")
            base = f"{self.base_url}/events"
            url = base + (('?' + '&'.join(params)) if params else '')
            data, status = self.list_events(url)
            items = data.get('resources', [])
            canon = [self.canonicalize(i) for i in items]
            if last:
                canon = [c for c in canon if c.get('ts') and int(c['ts']) > int(last)]
            next_token = data.get('next_token')
            while next_token:
                page_url = f"{base}?next_token={next_token}&limit={limit}"
                page, _ = self.list_events(page_url)
                more = [self.canonicalize(i) for i in page.get('resources', [])]
                canon.extend([c for c in more if not last or (c.get('ts') and int(c['ts']) > int(last))])
                next_token = page.get('next_token')
            max_ts = None
            for c in canon:
                t = c.get('ts')
                if t and (max_ts is None or int(t) > int(max_ts)):
                    max_ts = t
            if max_ts is None:
                max_ts = int(last) if last is not None else None
            else:
                if str(last) != str(max_ts):
                    self.store.save('crowdstrike', 'crowdstrike:last', {'timestamp': str(max_ts)})
            events_ingested_total.labels(connector='crowdstrike').inc(len(canon))
            return canon, max_ts
