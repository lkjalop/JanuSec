from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterable, Optional

from .base import AzureConnectorConfig, load_checkpoint, save_checkpoint, azure_envelope
from .normalizer import normalize_defender_cloud_finding

logger = logging.getLogger(__name__)

try:
    import msal as _msal
    _MSAL_AVAILABLE = True
except ImportError:
    _msal = None  # type: ignore[assignment]
    _MSAL_AVAILABLE = False

_ARM_SCOPE = 'https://management.azure.com/.default'
_ALERTS_API_VERSION = '2022-01-01'


class DefenderCloudConnector:
    def __init__(
        self,
        cfg: AzureConnectorConfig,
        request_json: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        self.cfg = cfg
        self.name = 'defender_cloud'
        self.ck = load_checkpoint(self.name, cfg)
        self._request_json = request_json
        self._msal_app: Optional[Any] = None
        if not _MSAL_AVAILABLE and (cfg.client_id or cfg.client_secret):
            logger.warning(
                'DefenderCloudConnector: msal not installed but Azure credentials are configured. '
                'Auth will fail at first use. pip install msal'
            )

    @staticmethod
    def check_ready(cfg: Optional[AzureConnectorConfig] = None) -> tuple[bool, str]:
        """Return (ok, reason) — call at startup to surface missing dependencies."""
        if not _MSAL_AVAILABLE:
            return False, 'msal not installed; pip install msal'
        if cfg is not None and not (cfg.client_id and cfg.client_secret and cfg.tenant_id):
            return False, 'client_id, client_secret, and tenant_id are required'
        return True, 'ok'

    # ------------------------------------------------------------------
    # Token acquisition (ARM scope)
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        if not _MSAL_AVAILABLE:
            raise RuntimeError('msal not installed; pip install msal')
        if not (self.cfg.client_id and self.cfg.client_secret and self.cfg.tenant_id):
            raise RuntimeError('client_id, client_secret, and tenant_id are required for Defender connector')
        if self._msal_app is None:
            self._msal_app = _msal.ConfidentialClientApplication(
                self.cfg.client_id,
                authority=f'https://login.microsoftonline.com/{self.cfg.tenant_id}',
                client_credential=self.cfg.client_secret,
            )
        result = self._msal_app.acquire_token_for_client(scopes=[_ARM_SCOPE])
        if 'access_token' not in result:
            raise RuntimeError(
                f"MSAL token error: {result.get('error_description', result.get('error', 'unknown'))}"
            )
        return result['access_token']

    def _arm_get(self, url: str) -> Dict[str, Any]:
        """GET from Azure Resource Manager with automatic 401 token refresh."""
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
                    logger.warning('ARM 401 on %s — forcing token refresh', url)
                    self._msal_app = None
                    continue
                logger.error('ARM HTTP error %s on %s: %s', exc.code, url, exc.reason)
                raise
        return {}

    def _alerts_url(self, since_ts: Any) -> str:
        base = (self.cfg.defender_base_url or 'https://management.azure.com').rstrip('/')
        sub = self.cfg.subscription_id or ''
        params: Dict[str, str] = {'api-version': _ALERTS_API_VERSION}
        if since_ts:
            from datetime import datetime, timezone
            try:
                iso = datetime.fromtimestamp(float(since_ts), tz=timezone.utc).strftime(
                    '%Y-%m-%dT%H:%M:%SZ'
                )
                params['$filter'] = f"properties/timeGeneratedUtc ge {iso}"
            except Exception:
                pass
        qs = urllib.parse.urlencode(params)
        return f'{base}/subscriptions/{sub}/providers/Microsoft.Security/alerts?{qs}'

    def _use_real_api(self) -> bool:
        return (
            _MSAL_AVAILABLE
            and bool(self.cfg.client_id)
            and bool(self.cfg.client_secret)
            and bool(self.cfg.tenant_id)
            and bool(self.cfg.subscription_id)
            and self._request_json is None
        )

    # ------------------------------------------------------------------
    # Public fetch interface
    # ------------------------------------------------------------------

    def fetch_findings(self, since_ts: Any = None) -> Iterable[Dict[str, Any]]:
        since_ts = since_ts or self.ck.get('last_ts')

        if self._use_real_api():
            try:
                url = self._alerts_url(since_ts)
                payload = self._arm_get(url)
                # ARM list responses use 'value'; follow nextLink for pagination
                all_rows = list(payload.get('value') or [])
                next_link = payload.get('nextLink')
                while next_link:
                    try:
                        page = self._arm_get(next_link)
                        all_rows.extend(page.get('value') or [])
                        next_link = page.get('nextLink')
                    except Exception:
                        logger.exception('Defender nextLink fetch failed; stopping pagination')
                        break
            except Exception:
                logger.exception('Defender Cloud ARM fetch failed')
                return
        elif self._request_json is not None:
            payload = self._request_json({'since_ts': since_ts})
            all_rows = list(payload.get('value') or payload.get('findings') or [])
        else:
            missing = []
            if not _MSAL_AVAILABLE:
                missing.append('msal SDK (pip install msal)')
            if not self.cfg.subscription_id:
                missing.append('subscription_id')
            if not self.cfg.client_id:
                missing.append('client_id')
            logger.error('DefenderCloudConnector: cannot fetch — missing: %s', ', '.join(missing))
            return

        newest = self.ck.get('last_ts')
        for row in all_rows:
            if not isinstance(row, dict):
                continue
            normalized = normalize_defender_cloud_finding(row, self.cfg.tenant_id)
            env = azure_envelope(
                normalized,
                'azure_defender_cloud',
                tenant_id=self.cfg.tenant_id,
                subscription_id=self.cfg.subscription_id,
            )
            env.update(normalized)
            newest = normalized.get('ts') or newest
            yield env
        if newest:
            self.ck['last_ts'] = newest
            save_checkpoint(self.name, self.cfg, self.ck)
