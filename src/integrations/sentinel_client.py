import os
import json
from typing import Any, Dict, List, Optional, Tuple
import time

from src.core.security.secret_provider import SecretProvider
from src.core.connectors.checkpoint_store_v2 import CheckpointStoreV2
try:
    from src.integrations.checkpoint_store import CheckpointStore as LegacyCheckpointStore
except Exception:
    LegacyCheckpointStore = None
from src.core.http.client import request_with_retry_sync
from src.core.metrics.connectors_metrics import events_ingested_total, ingest_errors_total, ingest_latency_seconds, queue_depth, retry_attempts_total


class SentinelClient:
    def __init__(self, base_url: str, tenant_id: str, client_id: Optional[str] = None, client_secret: Optional[str] = None, client: Optional[object] = None):
        self.base_url = base_url.rstrip('/')
        self.tenant_id = tenant_id
        self.sp = SecretProvider()
        self.client_id = client_id or self.sp.get('SENTINEL_CLIENT_ID')
        self.client_secret = client_secret or self.sp.get('SENTINEL_CLIENT_SECRET')
        self.token: Optional[str] = self.sp.get('SENTINEL_API_TOKEN')
        self.token_expiry: float = 0
        self.store = CheckpointStoreV2()
        # Defer legacy adapter selection to allow tests to set env vars after init
        self._legacy_adapter_installed = False
        # optional httpx.Client for tests (allows MockTransport)
        self.client = client

    def _get_token(self) -> str:
        if self.token and time.time() < self.token_expiry - 60:
            return self.token
        auth_url = os.getenv('SENTINEL_AUTH_URL')
        if auth_url and self.client_id and self.client_secret:
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': os.getenv('SENTINEL_SCOPE', 'https://management.azure.com/.default')
            }
            if self.client is not None:
                r = self.client.request('POST', auth_url, data=data)
            else:
                r = request_with_retry_sync('POST', auth_url, data=data)
            if r.status_code < 400:
                body = r.json()
                self.token = body.get('access_token')
                self.token_expiry = time.time() + int(body.get('expires_in', 3600))
        else:
            self.token = self.token or 'test-token'
            self.token_expiry = time.time() + 3600
        return self.token

    def _headers(self) -> Dict[str, str]:
        return {'Authorization': f'Bearer {self._get_token()}', 'Accept': 'application/json'}

    def list_alerts(self, url: Optional[str] = None) -> Dict[str, Any]:
        fixture = os.getenv('SENTINEL_FIXTURE_PATH')
        if fixture and os.path.exists(fixture):
            with open(fixture, 'r', encoding='utf-8') as f:
                return json.load(f)
        api_mode = os.getenv('SENTINEL_API_MODE', 'ARM').upper()
        base = self.base_url
        target = url or (f"{base}/alerts?api-version=2023-11-01" if api_mode == 'ARM' else f"{base}/security/alerts")
        headers = self._headers()
        if api_mode == 'GRAPH':
            headers.update({'ConsistencyLevel': 'eventual', 'Content-Type': 'application/json'})
        start = time.time()
        if self.client is not None:
            # light retry using provided client
            import random as _rand
            attempt = 0
            retries = int(os.getenv('SENTINEL_MAX_RETRIES', '3'))
            backoff = float(os.getenv('SENTINEL_BACKOFF_BASE', '0.5'))
            while True:
                r = self.client.request('GET', target, headers=headers)
                if r.status_code < 400:
                    break
                attempt += 1
                if attempt > retries or r.status_code not in (429, 500, 502, 503, 504):
                    break
                time.sleep(backoff * (2 ** (attempt - 1)) + _rand.uniform(0, 0.25))
        else:
            r = request_with_retry_sync('GET', target, headers=headers)
        elapsed = time.time() - start
        ingest_latency_seconds.labels(connector='sentinel').observe(elapsed)
        if r.status_code == 401:
            self.token_expiry = 0
            self._get_token()
            headers = self._headers()
            if self.client is not None:
                r = self.client.request('GET', target, headers=headers)
            else:
                r = request_with_retry_sync('GET', target, headers=headers)
        if r.status_code >= 400:
            ingest_errors_total.labels(connector='sentinel', code=str(r.status_code)).inc()
            r.raise_for_status()
        return r.json()

    def canonicalize(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'ts': item.get('timeGenerated'),
            'tenant': item.get('tenantId'),
            'severity': (item.get('properties') or {}).get('severity')
        }

    def fetch_since(self, app=None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        # Ensure a legacy adapter is used if tests configured a per-connector path
        if not self._legacy_adapter_installed:
            cp_path = os.getenv('SENTINEL_CHECKPOINT_PATH')
            if cp_path and LegacyCheckpointStore is not None:
                legacy = LegacyCheckpointStore(cp_path)

                class _LegacyAdapter:
                    def __init__(self, legacy_store):
                        self.legacy = legacy_store

                    def load(self, source: str, stream_id: str):
                        val = self.legacy.load(stream_id)
                        if val is None:
                            return None
                        if stream_id == 'sentinel:last' and isinstance(val, str):
                            return {'timestamp': val}
                        return val

                    def save(self, source: str, stream_id: str, payload):
                        if stream_id == 'sentinel:last' and isinstance(payload, dict) and 'timestamp' in payload:
                            self.legacy.save('sentinel:last', payload.get('timestamp'))
                        else:
                            self.legacy.save(stream_id, payload)

                self.store = _LegacyAdapter(legacy)
            self._legacy_adapter_installed = True

        last_obj = self.store.load('sentinel', 'sentinel:last')
        last = last_obj.get('timestamp') if last_obj else None
        data = self.list_alerts()
        items = data.get('value', [])
        canon = [self.canonicalize(i) for i in items]
        if last:
            canon = [c for c in canon if c.get('ts') and c['ts'] > last]
        next_link = data.get('nextLink')
        while next_link:
            self.token_expiry = 0
            page = self.list_alerts(next_link)
            more = [self.canonicalize(i) for i in page.get('value', [])]
            canon.extend([c for c in more if not last or (c.get('ts') and c['ts'] > last)])
            next_link = page.get('nextLink')
        max_ts = None
        for c in canon:
            t = c.get('ts')
            if t and (max_ts is None or t > max_ts):
                max_ts = t
        if max_ts is None:
            max_ts = last
        else:
            if last != max_ts:
                self.store.save('sentinel', 'sentinel:last', {'timestamp': max_ts})
        events_ingested_total.labels(connector='sentinel').inc(len(canon))
        if app is not None and hasattr(app.state, 'connector_queues'):
            q = app.state.connector_queues.get('sentinel')
            if q is not None:
                queue_depth.labels(connector='sentinel').set(q.qsize())
        return canon, max_ts
