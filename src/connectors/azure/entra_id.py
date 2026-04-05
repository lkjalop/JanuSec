from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterable, Optional

from .base import AzureConnectorConfig, load_checkpoint, save_checkpoint, azure_envelope
from .normalizer import normalize_entra_audit, normalize_entra_signin

logger = logging.getLogger(__name__)

try:
    import msal as _msal
    _MSAL_AVAILABLE = True
except ImportError:
    _msal = None  # type: ignore[assignment]
    _MSAL_AVAILABLE = False


class EntraIDConnector:
    def __init__(
        self,
        cfg: AzureConnectorConfig,
        request_json: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        self.cfg = cfg
        self.name = 'entra_id'
        self.ck = load_checkpoint(self.name, cfg)
        # request_json is kept for test injection.
        # In production, the real MSAL + Graph API path is used when msal is
        # installed and client_id / client_secret / tenant_id are configured.
        self._request_json = request_json
        self._msal_app: Optional[Any] = None

    # ------------------------------------------------------------------
    # Token acquisition
    # ------------------------------------------------------------------

    def _get_token(self, scope: str = 'https://graph.microsoft.com/.default') -> str:
        if not _MSAL_AVAILABLE:
            raise RuntimeError('msal not installed; pip install msal')
        if not (self.cfg.client_id and self.cfg.client_secret and self.cfg.tenant_id):
            raise RuntimeError('client_id, client_secret, and tenant_id are required for Entra connector')
        if self._msal_app is None:
            self._msal_app = _msal.ConfidentialClientApplication(
                self.cfg.client_id,
                authority=f'https://login.microsoftonline.com/{self.cfg.tenant_id}',
                client_credential=self.cfg.client_secret,
            )
        result = self._msal_app.acquire_token_for_client(scopes=[scope])
        if 'access_token' not in result:
            raise RuntimeError(
                f"MSAL token error: {result.get('error_description', result.get('error', 'unknown'))}"
            )
        return result['access_token']

    def _graph_get(self, endpoint: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """GET from MS Graph with automatic 401 token refresh (one retry)."""
        base = (self.cfg.graph_base_url or 'https://graph.microsoft.com/v1.0').rstrip('/')
        url = f'{base}/{endpoint}'
        if params:
            url = f'{url}?{urllib.parse.urlencode(params)}'

        for attempt in range(2):
            token = self._get_token()
            req = urllib.request.Request(
                url,
                headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'},
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    # Force token refresh: clear cached app so next _get_token re-authenticates
                    logger.warning('Graph 401 on %s — forcing token refresh', endpoint)
                    self._msal_app = None
                    continue
                logger.error('Graph HTTP error %s on %s: %s', exc.code, endpoint, exc.reason)
                raise
        return {}

    # ------------------------------------------------------------------
    # Fetch helpers: real Graph path or injected test path
    # ------------------------------------------------------------------

    def _use_real_graph(self) -> bool:
        return (
            _MSAL_AVAILABLE
            and bool(self.cfg.client_id)
            and bool(self.cfg.client_secret)
            and bool(self.cfg.tenant_id)
            and self._request_json is None
        )

    def _signins_from_graph(self, since_ts: Any) -> Dict[str, Any]:
        params: Dict[str, str] = {'$top': '100'}
        if since_ts:
            from datetime import datetime, timezone
            try:
                iso = datetime.fromtimestamp(float(since_ts), tz=timezone.utc).strftime(
                    '%Y-%m-%dT%H:%M:%SZ'
                )
                params['$filter'] = f"createdDateTime ge {iso}"
            except Exception:
                pass
        return self._graph_get('auditLogs/signIns', params)

    def _audits_from_graph(self, since_ts: Any) -> Dict[str, Any]:
        params: Dict[str, str] = {'$top': '100'}
        if since_ts:
            from datetime import datetime, timezone
            try:
                iso = datetime.fromtimestamp(float(since_ts), tz=timezone.utc).strftime(
                    '%Y-%m-%dT%H:%M:%SZ'
                )
                params['$filter'] = f"activityDateTime ge {iso}"
            except Exception:
                pass
        return self._graph_get('auditLogs/directoryAudits', params)

    # ------------------------------------------------------------------
    # Public fetch interface
    # ------------------------------------------------------------------

    def fetch_signins(self, since_ts: Any = None) -> Iterable[Dict[str, Any]]:
        since_ts = since_ts or self.ck.get('signins_last_ts')
        if self._use_real_graph():
            try:
                payload = self._signins_from_graph(since_ts)
            except Exception:
                logger.exception('entra signin Graph fetch failed')
                return
        elif self._request_json is not None:
            payload = self._request_json('signins', {'since_ts': since_ts})
        else:
            logger.error('EntraIDConnector: no MSAL config and no request_json injected')
            return

        newest = self.ck.get('signins_last_ts')
        for row in (payload.get('value') or []):
            normalized = normalize_entra_signin(row, self.cfg.tenant_id)
            env = azure_envelope(
                normalized,
                'azure_entra_signin',
                tenant_id=self.cfg.tenant_id,
                subscription_id=self.cfg.subscription_id,
            )
            env.update(normalized)
            newest = normalized.get('ts') or newest
            yield env
        if newest:
            self.ck['signins_last_ts'] = newest
            save_checkpoint(self.name, self.cfg, self.ck)

    def fetch_audits(self, since_ts: Any = None) -> Iterable[Dict[str, Any]]:
        since_ts = since_ts or self.ck.get('audits_last_ts')
        if self._use_real_graph():
            try:
                payload = self._audits_from_graph(since_ts)
            except Exception:
                logger.exception('entra audit Graph fetch failed')
                return
        elif self._request_json is not None:
            payload = self._request_json('audits', {'since_ts': since_ts})
        else:
            logger.error('EntraIDConnector: no MSAL config and no request_json injected')
            return

        newest = self.ck.get('audits_last_ts')
        for row in (payload.get('value') or []):
            normalized = normalize_entra_audit(row, self.cfg.tenant_id)
            env = azure_envelope(
                normalized,
                'azure_entra_audit',
                tenant_id=self.cfg.tenant_id,
                subscription_id=self.cfg.subscription_id,
            )
            env.update(normalized)
            newest = normalized.get('ts') or newest
            yield env
        if newest:
            self.ck['audits_last_ts'] = newest
            save_checkpoint(self.name, self.cfg, self.ck)
