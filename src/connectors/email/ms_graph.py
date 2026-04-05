
from typing import List, Dict, Any, Optional
import time
import logging
import os
import requests

logger = logging.getLogger(__name__)


class MSGraphHTTPConnector:
    """Requests-based Microsoft Graph helper with client-credentials token flow.

    Behaviour is gated by environment variable `MS_GRAPH_ENABLED`. When not
    enabled the methods return safe empty responses suitable for unit tests.

    Configurable env vars:
    - MS_GRAPH_ENABLED (1 to enable)
    - MS_GRAPH_CLIENT_ID, MS_GRAPH_CLIENT_SECRET, MS_GRAPH_TENANT_ID
    - MS_GRAPH_SEARCH_ENDPOINT (optional override)
    - MS_GRAPH_QUARANTINE_ENDPOINT (optional override)
    """

    def __init__(self):
        self.enabled = os.getenv('MS_GRAPH_ENABLED', '0') in ('1', 'true', 'yes')
        self.client_id = os.getenv('MS_GRAPH_CLIENT_ID')
        self.client_secret = os.getenv('MS_GRAPH_CLIENT_SECRET')
        self.tenant = os.getenv('MS_GRAPH_TENANT_ID')
        self._token = None
        self._token_expiry = 0
        self.search_endpoint = os.getenv('MS_GRAPH_SEARCH_ENDPOINT')
        self.quarantine_endpoint = os.getenv('MS_GRAPH_QUARANTINE_ENDPOINT')

    def _get_token(self) -> Optional[str]:
        if not self.enabled:
            return None
        now = int(time.time())
        if self._token and now < self._token_expiry - 30:
            return self._token
        if not (self.client_id and self.client_secret and self.tenant):
            logger.warning('MSGraph enabled but missing client credentials')
            return None
        token_url = f'https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token'
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        try:
            r = requests.post(token_url, data=data, timeout=5)
            r.raise_for_status()
            j = r.json()
            self._token = j.get('access_token')
            expires_in = int(j.get('expires_in') or 3600)
            self._token_expiry = now + expires_in
            return self._token
        except Exception:
            logger.exception('failed to obtain MS Graph token')
            return None

    def _auth_header(self) -> Dict[str, str]:
        t = self._get_token()
        return {'Authorization': f'Bearer {t}'} if t else {}

    def search_similar_messages(self, tenant: str, query: str, top: int = 250) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []
        if not self.search_endpoint:
            logger.warning('MSGraph search endpoint not configured')
            return []

        headers = self._auth_header()
        results: List[Dict[str, Any]] = []
        url = self.search_endpoint
        params = {'q': query, 'top': min(top, 250)}
        remaining = top
        attempt = 0
        while url and remaining > 0 and attempt < 5:
            attempt += 1
            try:
                r = requests.get(url, params=params, headers=headers, timeout=10)
                r.raise_for_status()
                j = r.json()
                batch = j.get('messages') or []
                results.extend(batch[:remaining])
                remaining = top - len(results)
                # follow nextLink if present
                url = j.get('@odata.nextLink') or None
                params = {}
                if remaining <= 0:
                    break
            except Exception:
                logger.exception('msgraph search attempt failed')
                # simple backoff
                import time as _t
                _t.sleep(min(1 * attempt, 5))
                # refresh token and retry
                self._get_token()
                headers = self._auth_header()
                continue
        return results

    def quarantine_messages(self, tenant: str, message_ids: List[str], reason: str = 'phish') -> Dict[str, Any]:
        if not self.enabled:
            return {'quarantined': 0, 'failed': len(message_ids)}
        if not self.quarantine_endpoint:
            logger.warning('MSGraph quarantine endpoint not configured')
            return {'quarantined': 0, 'failed': len(message_ids)}
        headers = self._auth_header()
        max_batch = 50
        total_quarantined = 0
        total_failed = 0
        for i in range(0, len(message_ids), max_batch):
            batch = message_ids[i:i+max_batch]
            try:
                r = requests.post(self.quarantine_endpoint, json={'message_ids': batch, 'reason': reason}, headers=headers, timeout=10)
                r.raise_for_status()
                j = r.json()
                q = int(j.get('quarantined', len(batch)))
                f = int(j.get('failed', 0))
                total_quarantined += q
                total_failed += f
            except Exception:
                logger.exception('msgraph quarantine batch failed')
                total_failed += len(batch)
        return {'quarantined': total_quarantined, 'failed': total_failed}

    def get_mailbox_messages(self, mailbox: str, since_ts: Optional[float] = None) -> List[Dict[str, Any]]:
        # Not implemented for tenant-wide; maintain stub for compatibility
        return []


class MSGraphConnector:
    # Backwards-compat wrapper preserving old name
    def __init__(self):
        self._inner = MSGraphHTTPConnector()

    def search_similar_messages(self, tenant: str, query: str, top: int = 250):
        return self._inner.search_similar_messages(tenant, query, top=top)

    def quarantine_messages(self, tenant: str, message_ids: List[str], reason: str = 'phish'):
        return self._inner.quarantine_messages(tenant, message_ids, reason=reason)

    def get_mailbox_messages(self, mailbox: str, since_ts: Optional[float] = None):
        return self._inner.get_mailbox_messages(mailbox, since_ts=since_ts)

"""Microsoft Graph connector scaffold (streaming / subscriptions placeholder)."""
from typing import List, Dict, Any


class MSGraphConnector:
    def __init__(self, tenant: str = None, client_id: str = None, client_secret: str = None):
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret

    def subscribe_safe_links(self):
        # placeholder for Graph subscription creation
        print('subscribe safe links')


__all__ = ["MSGraphConnector"]
