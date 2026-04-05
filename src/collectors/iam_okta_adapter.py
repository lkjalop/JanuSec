from __future__ import annotations
import os, time, json
from typing import List, Dict, Any, Tuple
from .base import EventCollector
import psycopg2

# Import third-party libs at module level so tests can monkeypatch these names
try:
    import requests
except Exception:
    requests = None

try:
    from okta.client import Client as OktaClient
except Exception:
    OktaClient = None

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')

def _get_conn():
    return psycopg2.connect(DB_DSN)

class OktaIAMCollector(EventCollector):
    source = "okta"

    def __init__(self, tenant_id: str = 'default'):
        self.tenant_id = tenant_id
        self._token = os.getenv("OKTA_API_TOKEN")
        self._org_url = os.getenv("OKTA_ORG_URL")
        self._client = None
        if self._token and self._org_url:
            try:
                from okta.client import Client as OktaClient
                self._client = OktaClient({
                    'orgUrl': self._org_url,
                    'token': self._token
                })
            except Exception as e:
                import logging
                logging.error(f"Failed to initialize Okta client: {e}")
                self._client = None

    # ---------------- Cursor Persistence ----------------
    def _load_cursor(self) -> Tuple[float | None, str | None]:
        try:
            conn = _get_conn()
            with conn.cursor() as cur:
                cur.execute("SELECT extract(epoch from last_ts), last_event_id FROM okta_log_cursor WHERE tenant_id=%s", (self.tenant_id,))
                row = cur.fetchone()
            conn.close()
            if row:
                return float(row[0]) if row[0] is not None else None, row[1]
        except Exception:
            pass
        return None, None

    def _save_cursor(self, last_ts: float, last_event_id: str | None):
        try:
            conn = _get_conn()
            with conn.cursor() as cur:
                cur.execute("""
                INSERT INTO okta_log_cursor(tenant_id,last_ts,last_event_id,updated_at)
                VALUES (%s,to_timestamp(%s),%s,now())
                ON CONFLICT (tenant_id) DO UPDATE SET last_ts=EXCLUDED.last_ts, last_event_id=EXCLUDED.last_event_id, updated_at=now()
                """, (self.tenant_id, last_ts, last_event_id))
            conn.commit(); conn.close()
        except Exception:
            pass

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        import logging
        from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
        import datetime
        events: List[Dict[str, Any]] = []
        if not self._client:
            return []

        # Decide starting point: use provided since_ts vs stored cursor (prefer max).
        stored_ts, _stored_event_id = self._load_cursor()
        effective_since = since_ts
        if stored_ts is not None:
            # small overlap (5s) to reduce risk of missing tail events between runs
            overlap = max(0, stored_ts - 5)
            effective_since = max(effective_since, overlap)
        # Guard: avoid future timestamps
        now = time.time()
        if effective_since > now:
            effective_since = now - 60

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry=retry_if_exception_type(Exception))
        def get_okta_logs():
            # Okta API: /api/v1/logs
            # Use since parameter for pagination
            # Okta SDK does not expose logs directly, so use requests as fallback
            if requests is None:
                raise RuntimeError('requests library not available')
            url = f"{self._org_url}/api/v1/logs"
            headers = {
                "Authorization": f"SSWS {self._token}",
                "Accept": "application/json"
            }
            params = {
                "since": datetime.datetime.utcfromtimestamp(effective_since).isoformat() + "Z",
                "limit": 1000
            }
            next_url = url
            newest_ts = effective_since
            newest_id = None
            while next_url:
                resp = requests.get(next_url, headers=headers, params=params if next_url == url else None, timeout=15)
                if resp.status_code != 200:
                    logging.error(f"Okta logs fetch failed: {resp.status_code} {resp.text}")
                    break
                try:
                    batch = resp.json()
                except ValueError:
                    batch = []
                for event in batch:
                    try:
                        # Okta events often have 'published' timestamp and 'uuid'
                        published = event.get('published') or event.get('eventTime') or event.get('timestamp')
                        ts_val = None
                        if isinstance(published, str):
                            try:
                                # parse ISO8601
                                from dateutil import parser as _dtp  # optional
                                ts_val = _dtp.parse(published).timestamp()
                            except Exception:
                                try:
                                    # Fallback: strip Z
                                    if published.endswith('Z'):
                                        published = published[:-1]
                                    ts_val = datetime.datetime.fromisoformat(published).timestamp()
                                except Exception:
                                    ts_val = None
                        if ts_val is not None and ts_val < effective_since:
                            # Skip events older than effective window
                            continue
                        if ts_val is not None and ts_val > newest_ts:
                            newest_ts = ts_val
                            newest_id = event.get('uuid') or event.get('id')
                        events.append(event)
                    except Exception:
                        events.append(event)
                # Pagination: look for 'link' header
                links = resp.headers.get('link')
                next_url = None
                if links:
                    for part in links.split(','):
                        if 'rel="next"' in part:
                            next_url = part[part.find('<')+1:part.find('>')]
                            break
            # Persist cursor if we advanced
            if newest_ts > effective_since:
                self._save_cursor(newest_ts, newest_id)
            return events

        try:
            return get_okta_logs()
        except Exception as e:
            logging.error(f"Okta fetch_events error: {e}")
            return []

__all__ = ["OktaIAMCollector"]