"""CrowdStrike connector (Phase 1).

Provides minimal OAuth2 token handling and a small fetch_detections method that can
be used in demo/dev. Real integration should handle paging, retries, and full
schema mapping.
"""
from __future__ import annotations
import os
import time
import logging
from typing import Any, Dict, List, Optional
from .cs_secrets import get_crowdstrike_credentials
from .cs_persistence import save_token_metadata, get_token_metadata, persist_detection
import json
import threading
from pathlib import Path
DEFAULT_TENANT = os.getenv('DEFAULT_TENANT', 'default')

logger = logging.getLogger(__name__)
try:
    from prometheus_client import Counter, Histogram
    CS_SYNC_RUNS = Counter('cs_sync_runs_total', 'Total crowdstrike sync runs')
    CS_SYNC_FAILURES = Counter('cs_sync_failures_total', 'Total crowdstrike sync failures')
    CS_DETECTIONS_RECEIVED = Counter('cs_detections_received_total', 'Total detections received')
    CS_DETECTIONS_PERSISTED = Counter('cs_detections_persisted_total', 'Total detections persisted/dedupe pass')
    CS_SYNC_DURATION = Histogram('cs_sync_duration_seconds', 'Crowdstrike sync duration seconds')
except Exception:
    CS_SYNC_RUNS = CS_SYNC_FAILURES = CS_DETECTIONS_RECEIVED = CS_DETECTIONS_PERSISTED = CS_SYNC_DURATION = None


class CrowdStrikeRealClient:
    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None, base_url: Optional[str] = None):
        # Try secrets manager first then env
        creds = get_crowdstrike_credentials()
        self.client_id = client_id or creds.get('client_id') or os.getenv('CROWDSTRIKE_CLIENT_ID')
        self.client_secret = client_secret or creds.get('client_secret') or os.getenv('CROWDSTRIKE_CLIENT_SECRET')
        self.base_url = base_url or os.getenv('CROWDSTRIKE_BASE_URL', 'https://api.crowdstrike.com')
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        # token cache file configurable via env (fallback only)
        default_cache = os.path.join(os.getcwd(), '.cs_token.json')
        self._token_cache_file = os.getenv('CROWDSTRIKE_TOKEN_CACHE', default_cache)
        # protect file writes with a lock
        self._lock = threading.Lock()
        # load cached token if present
        try:
            self._load_token_cache()
        except Exception:
            pass

    def _needs_token(self) -> bool:
        return not self._token or time.time() + 30 >= self._token_expiry

    def fetch_token(self) -> bool:
        # Demo: do not call real endpoints if credentials missing
        if not self.client_id or not self.client_secret:
            logger.debug('CrowdStrike credentials missing; running in stub mode')
            # create a fake token
            self._token = 'dev-fake-token'
            self._token_expiry = time.time() + 3600
            try:
                # persist token metadata to redis if available
                save_token_metadata(self._token, self._token_expiry)
            except Exception:
                try:
                    self._save_token_cache()
                except Exception:
                    pass
            return True
        # Real implementation: call OAuth2 token endpoint
        try:
            import requests
            token_url = f"{self.base_url}/oauth2/token"
            try:
                from src.security.egress_guard import ssrf_check  # type: ignore
            except Exception:
                from security.egress_guard import ssrf_check  # type: ignore
            ok, reason = ssrf_check(token_url)
            if not ok:
                logger.warning('CrowdStrike token fetch blocked by SSRF guard: %s', reason)
                return False
            # CrowdStrike expects form-encoded body with grant_type=client_credentials
            r = requests.post(token_url, data={'grant_type': 'client_credentials', 'client_id': self.client_id, 'client_secret': self.client_secret}, timeout=6)
            if r.status_code != 200:
                logger.warning('CrowdStrike token fetch failed: %s', r.status_code)
                return False
            j = r.json()
            self._token = j.get('access_token')
            self._token_expiry = time.time() + float(j.get('expires_in', 3600))
            try:
                save_token_metadata(self._token, self._token_expiry)
            except Exception:
                try:
                    self._save_token_cache()
                except Exception:
                    pass
            return True
        except Exception as e:
            logger.exception('CrowdStrike token error: %s', e)
            return False

    def _save_token_cache(self) -> None:
        try:
            data = {'token': self._token, 'expiry': self._token_expiry}
            p = Path(self._token_cache_file)
            # Write atomically
            tmp = p.with_suffix('.tmp')
            with self._lock:
                with open(tmp, 'w', encoding='utf-8') as f:
                    json.dump(data, f)
                # set safe permissions where possible (POSIX)
                try:
                    os.chmod(tmp, 0o600)
                except Exception:
                    pass
                tmp.replace(p)
        except Exception:
            logger.debug('Failed to persist CS token cache', exc_info=True)

    def _load_token_cache(self) -> None:
        p = Path(self._token_cache_file)
        if not p.exists():
            return
        try:
            with open(p, 'r', encoding='utf-8') as f:
                j = json.load(f)
            tok = j.get('token')
            exp = float(j.get('expiry', 0))
            if tok and exp and exp > time.time() + 10:
                self._token = tok
                self._token_expiry = exp
        except Exception:
            logger.debug('Failed to load CS token cache', exc_info=True)

    def fetch_detections(self, since_seconds: int = 3600) -> List[Dict[str, Any]]:
        # New signature: accept either seconds-or since timestamp; keep compat by interpreting positive > 1e9 as ts
        if isinstance(since_seconds, (int, float)) and since_seconds > 1e9:
            since_ts = float(since_seconds)
        else:
            since_ts = time.time() - float(since_seconds or 3600)

        # Ensure token present: try redis metadata first
        try:
            meta = get_token_metadata()
            if meta and meta.get('token') and float(meta.get('expiry', 0)) > time.time() + 10:
                self._token = meta.get('token')
                self._token_expiry = float(meta.get('expiry'))
        except Exception:
            pass
        if self._needs_token():
            self.fetch_token()

        # Demo/stub path when no credentials
        if not self.client_id or not self.client_secret:
            return [{
                'id': 'cs-demo-1',
                'observables': [{'type': 'ip', 'value': '1.2.3.4'}],
                'severity': 'medium',
                'ts': time.time(),
                'raw': {'description': 'Demo detection from CrowdStrike'},
                'vendor_url': 'https://demo.crowdstrike.local/d/1'
            }]

        # Real implementation: perform a query for detects since timestamp with paging
        out: List[Dict[str, Any]] = []
        import requests
        # SSRF guard for base URL
        try:
            try:
                from src.security.egress_guard import ssrf_check  # type: ignore
            except Exception:
                from security.egress_guard import ssrf_check  # type: ignore
            ok, reason = ssrf_check(self.base_url)
            if not ok:
                logger.warning('CrowdStrike fetch blocked by SSRF guard: %s', reason)
                return []
        except Exception:
            pass
        def _backoff_sleep(attempt: int):
            # exponential backoff with jitter
            base = min(30, (2 ** attempt))
            jitter = base * 0.1
            sleep = base + (jitter * (0.5 - (time.time() % 1)))
            time.sleep(sleep)

        try:
            if CS_SYNC_RUNS:
                try: CS_SYNC_RUNS.inc()
                except Exception: pass
            timer = CS_SYNC_DURATION.time() if CS_SYNC_DURATION else None
            headers = {'Authorization': f'Bearer {self._token}'}

            # Prepare filter string for CrowdStrike API: prefer first_found range or updated_at>
            # If since_ts was given as absolute timestamp, format as ISO8601 UTC
            try:
                import datetime
                since_iso = datetime.datetime.utcfromtimestamp(float(since_ts)).isoformat() + 'Z'
            except Exception:
                since_iso = None

            q_url = f"{self.base_url}/detects/queries/detects/v1"
            params = {'limit': 500}
            if since_iso:
                # use updated_at filter by default
                params['filter'] = f"updated_at:>'{since_iso}'"

            ids: List[str] = []
            attempt = 0
            next_cursor = None
            # Page through detection IDs using cursor-based paging
            while True:
                if next_cursor:
                    params['cursor'] = next_cursor
                # enforce token presence
                if self._needs_token():
                    self.fetch_token()
                    headers = {'Authorization': f'Bearer {self._token}'}
                r = requests.get(q_url, headers=headers, params=params, timeout=15)
                if r.status_code in (429, 503):
                    attempt += 1
                    if attempt > 6:
                        logger.warning('CrowdStrike query IDs giving repeated %s', r.status_code)
                        break
                    _backoff_sleep(attempt)
                    continue
                if r.status_code != 200:
                    logger.warning('CrowdStrike query ids failed: %s %s', r.status_code, r.text[:200])
                    if CS_SYNC_FAILURES:
                        try: CS_SYNC_FAILURES.inc()
                        except Exception: pass
                    break
                j = r.json()
                page_ids = j.get('resources', []) or []
                ids.extend([str(x) for x in page_ids])
                # detect cursor in response: common fields are 'meta'/'pagination' or 'resources_meta' or top-level 'meta'
                next_cursor = None
                try:
                    m = j.get('meta') or j.get('resources_meta') or {}
                    # common patterns: m.get('pagination', {}).get('cursor')
                    pagination = m.get('pagination') if isinstance(m, dict) else None
                    if pagination and pagination.get('cursor'):
                        next_cursor = pagination.get('cursor')
                except Exception:
                    next_cursor = None
                # fallback to header-based cursor
                if not next_cursor:
                    next_cursor = r.headers.get('X-Cursor') or r.headers.get('x-cursor')
                if not next_cursor:
                    break

            if not ids:
                if timer:
                    try: timer.close()
                    except Exception: pass
                return []

            # Batch fetch details for ids collected (respect batch size to keep url length safe)
            batch_size = 50
            for i in range(0, len(ids), batch_size):
                slice_ids = ids[i:i+batch_size]
                details_url = f"{self.base_url}/detects/entities/detects/v2"
                params2 = {'ids': ','.join(slice_ids)}
                det_attempt = 0
                while True:
                    if self._needs_token():
                        self.fetch_token()
                        headers = {'Authorization': f'Bearer {self._token}'}
                    r2 = requests.get(details_url, headers=headers, params=params2, timeout=20)
                    if r2.status_code in (429, 503):
                        det_attempt += 1
                        if det_attempt > 6:
                            logger.warning('CrowdStrike details fetch giving repeated %s', r2.status_code)
                            break
                        _backoff_sleep(det_attempt)
                        continue
                    if r2.status_code != 200:
                        logger.warning('CrowdStrike details fetch failed: %s %s', r2.status_code, r2.text[:200])
                        break
                    j2 = r2.json()
                    resources = j2.get('resources', []) or []
                    for item in resources:
                        # Normalize detection resource to our schema
                        det_id = item.get('id') or item.get('detection_id') or str(item.get('cid') or '')
                        det = {
                            'id': det_id,
                            'observables': [],
                            'severity': item.get('severity') or item.get('risk_score') or item.get('risk') or 'unknown',
                            'ts': float(item.get('first_found') or item.get('last_found') or item.get('timestamp') or time.time()),
                            'raw': item,
                            'vendor_url': f"https://falcon.crowdstrike.com/detection/{det_id}"
                        }
                        # Extract observables if present
                        try:
                            obs_list = item.get('observables') or item.get('indicator') or []
                            if isinstance(obs_list, dict):
                                obs_list = [obs_list]
                            for obs in obs_list or []:
                                # obs can be a string or dict
                                if isinstance(obs, dict):
                                    det['observables'].append({'type': obs.get('type') or obs.get('observable_type'), 'value': obs.get('value') or obs.get('observable_value')})
                                else:
                                    det['observables'].append({'type': 'unknown', 'value': str(obs)})
                        except Exception:
                            pass
                        # Fallback: try to pull ip/indicator from nested fields
                        if not det['observables']:
                            try:
                                ip = None
                                if isinstance(item.get('device', None), dict):
                                    ip = item.get('device', {}).get('ip')
                                ip = ip or item.get('indicator') or item.get('ip')
                                if ip:
                                    det['observables'].append({'type': 'ip', 'value': ip})
                            except Exception:
                                pass
                        # metrics and dedupe/persist logic
                        try:
                            if CS_DETECTIONS_RECEIVED:
                                try: CS_DETECTIONS_RECEIVED.inc()
                                except Exception: pass
                            # attach tenant context for metrics (low-cardinality)
                            tenant = DEFAULT_TENANT
                            dedup_ok = persist_detection(det['id'], det, tenant=tenant)
                            if dedup_ok:
                                if CS_DETECTIONS_PERSISTED:
                                    try: CS_DETECTIONS_PERSISTED.inc()
                                    except Exception: pass
                                out.append(det)
                        except Exception:
                            out.append(det)
                    break

            if timer:
                try: timer.close()
                except Exception: pass
            return out
        except Exception as e:
            logger.exception('CrowdStrike fetch error: %s', e)
            if CS_SYNC_FAILURES:
                try: CS_SYNC_FAILURES.inc()
                except Exception: pass
            return []


CLIENT = CrowdStrikeRealClient()

__all__ = ['CLIENT', 'CrowdStrikeRealClient']
