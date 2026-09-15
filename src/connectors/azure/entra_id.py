from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional

from .base import AzureConnectorConfig, load_checkpoint, save_checkpoint, azure_envelope, checkpoint_path
from src.core.event_time import event_epoch
from src.core.evidence_contract.records import canonical_hash
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
        self.defer_checkpoint = False
        self._pending_checkpoint = None
        self._request_json = request_json
        self._msal_app: Optional[Any] = None
        if not _MSAL_AVAILABLE and (cfg.client_id or cfg.client_secret):
            logger.warning(
                'EntraIDConnector: msal not installed but Azure credentials are configured. '
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
        url = endpoint if endpoint.startswith('https://') else f'{base}/{endpoint}'
        target, origin = urllib.parse.urlsplit(url), urllib.parse.urlsplit(base)
        if (target.scheme != 'https' or target.netloc != origin.netloc
                or target.username or target.password or target.fragment):
            raise ValueError('untrusted_graph_pagination_url')
        if params:
            url = f'{url}?{urllib.parse.urlencode(params)}'

        for attempt in range(2):
            token = self._get_token()
            req = urllib.request.Request(
                url,
                headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'},
            )
            try:
                # A redirect must not forward a bearer token to another origin.
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        raise ValueError('graph_redirect_not_allowed')
                with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as resp:
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
                epoch = event_epoch(since_ts)
                if epoch is None:
                    raise ValueError('invalid_connector_cursor')
                iso = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
                    '%Y-%m-%dT%H:%M:%SZ'
                )
                params['$filter'] = f"createdDateTime ge {iso}"
            except (ValueError, TypeError, OverflowError) as exc:
                raise ValueError('invalid_connector_cursor') from exc
        return self._graph_get('auditLogs/signIns', params)

    def _audits_from_graph(self, since_ts: Any) -> Dict[str, Any]:
        params: Dict[str, str] = {'$top': '100'}
        if since_ts:
            from datetime import datetime, timezone
            try:
                epoch = event_epoch(since_ts)
                if epoch is None:
                    raise ValueError('invalid_connector_cursor')
                iso = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
                    '%Y-%m-%dT%H:%M:%SZ'
                )
                params['$filter'] = f"activityDateTime ge {iso}"
            except (ValueError, TypeError, OverflowError) as exc:
                raise ValueError('invalid_connector_cursor') from exc
        return self._graph_get('auditLogs/directoryAudits', params)

    # ------------------------------------------------------------------
    # Public fetch interface
    # ------------------------------------------------------------------

    @staticmethod
    def _streaming_active() -> bool:
        return os.environ.get('JANUSEC_STREAMING_MODE', '').lower() in ('1', 'true', 'yes')

    @staticmethod
    def _stream_emit(rows: List[Dict[str, Any]], source: str) -> None:
        if not rows:
            return
        try:
            from src.connectors.stream_emitter import emit_to_stream_sync
            emit_to_stream_sync(rows, source=source)
        except Exception as exc:
            logger.warning('EntraID stream emit (%s) failed: %s', source, exc)

    def fetch_signins(self, since_ts: Any = None) -> Iterable[Dict[str, Any]]:
        yield from self._fetch('signins', since_ts)

    def fetch_audits(self, since_ts: Any = None) -> Iterable[Dict[str, Any]]:
        yield from self._fetch('audits', since_ts)

    def acknowledge_delivery(self) -> None:
        if self._pending_checkpoint is not None:
            save_checkpoint(self.name, self.cfg, self._pending_checkpoint)
            self.ck = self._pending_checkpoint
            self._pending_checkpoint = None

    def _fetch(self, kind: str, since_ts: Any) -> Iterable[Dict[str, Any]]:
        self._pending_checkpoint = None
        key = kind + '_last_ts'
        since_ts = since_ts if since_ts is not None else self.ck.get(key)
        if self._use_real_graph():
            payload = (self._signins_from_graph if kind == 'signins' else self._audits_from_graph)(since_ts)
        elif self._request_json is not None:
            payload = self._request_json(kind, {'since_ts': since_ts})
        else:
            raise RuntimeError('entra_connector_not_configured')
        newest = self.ck.get(key)
        collected: List[Dict[str, Any]] = []
        seen_links = set()
        seen_records = set()
        customer = self.cfg.customer_tenant_id or self.cfg.tenant_id
        normalizer = normalize_entra_signin if kind == 'signins' else normalize_entra_audit
        while True:
            if not isinstance(payload, dict) or not isinstance(payload.get('value'), list):
                raise ValueError('invalid_graph_collection_response')
            for row in payload['value']:
                if not isinstance(row, dict) or not row.get('id'):
                    raise ValueError('provider_native_stable_id_required')
                normalized = normalizer(row, customer)
                ts = event_epoch(normalized.get('ts'))
                if ts is None:
                    raise ValueError('provider_native_timestamp_required')
                digest = canonical_hash(row)
                identity = (row['id'], digest)
                if identity in seen_records:
                    continue
                seen_records.add(identity)
                receipt_dir = Path(checkpoint_path(self.name, self.cfg)).parent / 'raw_receipts' / kind
                receipt_dir.mkdir(parents=True, exist_ok=True)
                receipt_file = receipt_dir / (digest + '.json')
                receipt = {'schema_version': 'janusec.connector-raw/v1', 'tenant_id': customer,
                           'provider_tenant_id': self.cfg.tenant_id, 'provider_record_id': row['id'],
                           'observed_at': normalized['ts'], 'received_at': datetime.now(timezone.utc).isoformat(),
                           'native_hash': digest, 'provider_native': row}
                if receipt_file.exists():
                    existing = json.loads(receipt_file.read_text(encoding='utf-8'))
                    if canonical_hash(existing['provider_native']) != digest or existing['tenant_id'] != customer:
                        raise ValueError('raw_receipt_integrity_failure')
                else:
                    from src.api.persist_utils import atomic_write_json
                    write_path = str(receipt_file.resolve())
                    if os.name == 'nt' and not write_path.startswith('\\\\?\\'):
                        write_path = ('\\\\?\\UNC\\' + write_path[2:] if write_path.startswith('\\\\')
                                      else '\\\\?\\' + write_path)
                    atomic_write_json(write_path, receipt)
                env = {**normalized, 'id': row['id'], 'provider_record_id': row['id'],
                       'provider_tenant_id': self.cfg.tenant_id, 'raw_receipt_hash': digest,
                       'raw_receipt_path': str(receipt_file)}
                if newest is None or ts > (event_epoch(newest) or 0):
                    newest = normalized['ts']
                collected.append(env)
                yield env
            link = payload.get('@odata.nextLink')
            if not link:
                break
            target = urllib.parse.urlsplit(str(link))
            origin = urllib.parse.urlsplit(self.cfg.graph_base_url)
            if target.scheme != 'https' or target.netloc != origin.netloc or target.username or target.password or target.fragment:
                raise ValueError('untrusted_graph_pagination_url')
            if link in seen_links or len(seen_links) >= 1000:
                raise ValueError('graph_pagination_loop_or_limit')
            seen_links.add(link)
            payload = (self._request_json(kind, {'next_link': link}) if self._request_json is not None
                       else self._graph_get(link))
        if self._streaming_active():
            self._stream_emit(collected, 'azure_signin' if kind == 'signins' else 'azure_entra_audit')
        if newest is not None:
            self._pending_checkpoint = {**self.ck, key: newest}
            if not self.defer_checkpoint:
                self.acknowledge_delivery()
