"""Azure Sentinel workspace connector — production-grade.

Covers the three primary Sentinel API surfaces:

1. **Incidents** — GET/PATCH incidents via ARM
   ``/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.SecurityInsights/incidents``

2. **Watchlists** — GET watchlist items for threat intelligence lookup
   ``/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.SecurityInsights/watchlists/{alias}/watchlistItems``

3. **Log Analytics (KQL)** — POST queries to the workspace
   ``https://api.loganalytics.io/v1/workspaces/{workspace_id}/query``

Authentication:
  - Uses MSAL client_credentials flow (same as EntraIDConnector)
  - Falls back to ``SENTINEL_API_TOKEN`` env var for demos / test injection
  - All tokens cached with 5-minute early-refresh buffer

Env vars::

    AZURE_TENANT_ID
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET
    AZURE_SUBSCRIPTION_ID
    SENTINEL_RESOURCE_GROUP
    SENTINEL_WORKSPACE_NAME
    SENTINEL_WORKSPACE_ID      # for Log Analytics queries
    SENTINEL_ARM_BASE          # default: https://management.azure.com
    SENTINEL_LA_BASE           # default: https://api.loganalytics.io
    SENTINEL_API_VERSION       # default: 2023-11-01
    SENTINEL_API_TOKEN         # override for demos/tests
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

try:
    import msal as _msal
    _MSAL_AVAILABLE = True
except ImportError:
    _msal = None  # type: ignore
    _MSAL_AVAILABLE = False

_ARM_SCOPE = 'https://management.azure.com/.default'
_LA_SCOPE = 'https://api.loganalytics.io/.default'
_ARM_BASE = os.getenv('SENTINEL_ARM_BASE', 'https://management.azure.com')
_LA_BASE = os.getenv('SENTINEL_LA_BASE', 'https://api.loganalytics.io')
_API_VERSION = os.getenv('SENTINEL_API_VERSION', '2023-11-01')


# ── Config ────────────────────────────────────────────────────────────

@dataclass
class SentinelWorkspaceConfig:
    tenant_id: str = field(default_factory=lambda: os.getenv('AZURE_TENANT_ID', ''))
    client_id: str = field(default_factory=lambda: os.getenv('AZURE_CLIENT_ID', ''))
    client_secret: str = field(default_factory=lambda: os.getenv('AZURE_CLIENT_SECRET', ''))
    subscription_id: str = field(default_factory=lambda: os.getenv('AZURE_SUBSCRIPTION_ID', ''))
    resource_group: str = field(default_factory=lambda: os.getenv('SENTINEL_RESOURCE_GROUP', ''))
    workspace_name: str = field(default_factory=lambda: os.getenv('SENTINEL_WORKSPACE_NAME', ''))
    workspace_id: str = field(default_factory=lambda: os.getenv('SENTINEL_WORKSPACE_ID', ''))
    # Optionally inject a test token directly
    static_token: Optional[str] = field(default_factory=lambda: os.getenv('SENTINEL_API_TOKEN'))

    @property
    def is_configured(self) -> bool:
        return bool(self.tenant_id and self.subscription_id and self.resource_group and self.workspace_name)

    @property
    def workspace_base(self) -> str:
        return (
            f'{_ARM_BASE}/subscriptions/{self.subscription_id}'
            f'/resourceGroups/{self.resource_group}'
            f'/providers/Microsoft.SecurityInsights'
            f'/workspaces/{self.workspace_name}'
        )


# ── Token provider ────────────────────────────────────────────────────

class _TokenProvider:
    def __init__(self, cfg: SentinelWorkspaceConfig) -> None:
        self._cfg = cfg
        self._cache: Dict[str, tuple[str, float]] = {}  # scope -> (token, expiry)
        self._msal_app: Optional[Any] = None

    def get(self, scope: str) -> str:
        if self._cfg.static_token:
            return self._cfg.static_token
        token, expiry = self._cache.get(scope, ('', 0))
        if token and time.time() < expiry - 300:
            return token
        token, expiry = self._acquire(scope)
        self._cache[scope] = (token, expiry)
        return token

    def _acquire(self, scope: str) -> tuple[str, float]:
        cfg = self._cfg
        if _MSAL_AVAILABLE and cfg.client_id and cfg.client_secret:
            if self._msal_app is None:
                self._msal_app = _msal.ConfidentialClientApplication(
                    client_id=cfg.client_id,
                    client_credential=cfg.client_secret,
                    authority=f'https://login.microsoftonline.com/{cfg.tenant_id}',
                )
            result = self._msal_app.acquire_token_silent([scope], account=None)
            if not result:
                result = self._msal_app.acquire_token_for_client(scopes=[scope])
            if result and 'access_token' in result:
                expiry = time.time() + result.get('expires_in', 3600)
                return result['access_token'], expiry

        # Fallback: raw HTTP client_credentials POST
        auth_url = f'https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token'
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials',
            'client_id': cfg.client_id,
            'client_secret': cfg.client_secret,
            'scope': scope,
        }).encode()
        req = urllib.request.Request(auth_url, data=body, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.load(resp)
            return data['access_token'], time.time() + int(data.get('expires_in', 3600))
        except Exception as exc:
            raise RuntimeError(
                f'Sentinel token acquisition failed for tenant {cfg.tenant_id!r}: {exc}. '
                'Check AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, '
                'and network connectivity to login.microsoftonline.com.'
            ) from exc

    def headers(self, scope: str) -> Dict[str, str]:
        return {
            'Authorization': f'Bearer {self.get(scope)}',
            'Content-Type': 'application/json',
        }


# ── HTTP helper ───────────────────────────────────────────────────────

def _http(method: str, url: str, headers: Dict[str, str],
          body: Optional[Dict] = None) -> Dict[str, Any]:
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        content = exc.read().decode('utf-8', errors='replace')
        raise RuntimeError(f'Sentinel API {method} {url} → {exc.code}: {content}') from exc


# ── Incident normalisation ────────────────────────────────────────────

def _normalize_incident(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get('properties') or {}
    return {
        'id': raw.get('name') or raw.get('id'),
        'title': props.get('title'),
        'description': props.get('description'),
        'severity': (props.get('severity') or 'Informational').lower(),
        'status': (props.get('status') or 'New').lower(),
        'created_ts': props.get('createdTimeUtc'),
        'last_modified_ts': props.get('lastModifiedTimeUtc'),
        'incident_number': props.get('incidentNumber'),
        'classification': props.get('classification'),
        'owner': (props.get('owner') or {}).get('email'),
        'labels': [l.get('labelName') for l in (props.get('labels') or [])],
        'alert_ids': [a.get('id') for a in (props.get('alerts') or [])],
        'tactics': props.get('tactics') or [],
        'raw': raw,
    }


# ── Main connector ────────────────────────────────────────────────────

class SentinelWorkspaceConnector:
    """Production Sentinel connector: incidents, watchlists, KQL queries."""

    def __init__(
        self,
        cfg: Optional[SentinelWorkspaceConfig] = None,
        _http_fn=None,  # injectable for tests
    ) -> None:
        self.cfg = cfg or SentinelWorkspaceConfig()
        self._tokens = _TokenProvider(self.cfg)
        self._http = _http_fn or _http
        if not _MSAL_AVAILABLE and (self.cfg.client_id or self.cfg.client_secret):
            logger.warning(
                'SentinelWorkspaceConnector: msal not installed but Azure credentials are configured. '
                'Auth will fail at first use. pip install msal'
            )

    @staticmethod
    def check_ready(cfg: Optional[SentinelWorkspaceConfig] = None) -> tuple[bool, str]:
        """Return (ok, reason) — call at startup to surface missing dependencies."""
        if not _MSAL_AVAILABLE:
            return False, 'msal not installed; pip install msal'
        _cfg = cfg or SentinelWorkspaceConfig()
        if not _cfg.is_configured:
            return False, 'AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, and SENTINEL_WORKSPACE_NAME are required'
        return True, 'ok'

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        top: int = 50,
        order_by: str = 'properties/createdTimeUtc desc',
    ) -> List[Dict[str, Any]]:
        """Fetch incidents from the Sentinel workspace.

        Parameters
        ----------
        status_filter : 'New' | 'Active' | 'Closed' | None
        severity_filter : 'High' | 'Medium' | 'Low' | 'Informational' | None
        top : max incidents to return
        order_by : OData $orderby expression
        """
        url = (
            f'{self.cfg.workspace_base}/incidents'
            f'?api-version={_API_VERSION}&$top={top}&$orderby={urllib.parse.quote(order_by)}'
        )
        filters = []
        if status_filter:
            filters.append(f"properties/status eq '{status_filter}'")
        if severity_filter:
            filters.append(f"properties/severity eq '{severity_filter}'")
        if filters:
            url += '&$filter=' + urllib.parse.quote(' and '.join(filters))

        headers = self._tokens.headers(_ARM_SCOPE)
        data = self._http('GET', url, headers)
        return [_normalize_incident(i) for i in data.get('value', [])]

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        """Fetch a single incident by name/id."""
        url = (
            f'{self.cfg.workspace_base}/incidents/{incident_id}'
            f'?api-version={_API_VERSION}'
        )
        raw = self._http('GET', url, self._tokens.headers(_ARM_SCOPE))
        return _normalize_incident(raw)

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        classification: Optional[str] = None,
        owner_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """PATCH an incident status (New → Active → Closed)."""
        current = self._http(
            'GET',
            f'{self.cfg.workspace_base}/incidents/{incident_id}?api-version={_API_VERSION}',
            self._tokens.headers(_ARM_SCOPE),
        )
        props = current.get('properties') or {}
        props['status'] = status
        if classification:
            props['classification'] = classification
        if owner_email:
            props.setdefault('owner', {})['email'] = owner_email

        url = f'{self.cfg.workspace_base}/incidents/{incident_id}?api-version={_API_VERSION}'
        body = {'etag': current.get('etag', '*'), 'properties': props}
        raw = self._http('PUT', url, self._tokens.headers(_ARM_SCOPE), body=body)
        return _normalize_incident(raw)

    def push_janusec_verdict(
        self,
        incident_id: str,
        verdict: str,
        confidence: float = 0.0,
        mitre_tags: Optional[List[str]] = None,
        persona_summary: str = '',
    ) -> Dict[str, Any]:
        """Write-back a Janusec pipeline verdict to a Sentinel incident.

        Delegates to :mod:`src.connectors.azure.sentinel_writeback` so all
        classification/comment logic lives in one place.
        """
        try:
            from src.connectors.azure.sentinel_writeback import SentinelWriteback
            wb = SentinelWriteback(workspace_id=self.cfg.workspace_id)
            return wb.push_pipeline_result(
                incident_id=incident_id,
                verdict=verdict,
                confidence=confidence,
                mitre_tags=mitre_tags,
                persona_summary=persona_summary,
            )
        except Exception as exc:
            import logging as _log
            _log.getLogger(__name__).error(
                'sentinel_workspace: push_janusec_verdict failed: %s', exc
            )
            return {'error': str(exc)}

    def list_incident_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        """List alerts attached to an incident."""
        url = (
            f'{self.cfg.workspace_base}/incidents/{incident_id}/alerts'
            f'?api-version={_API_VERSION}'
        )
        data = self._http('POST', url, self._tokens.headers(_ARM_SCOPE), body={})
        return data.get('value', [])

    # ------------------------------------------------------------------
    # Watchlists
    # ------------------------------------------------------------------

    def list_watchlists(self) -> List[Dict[str, Any]]:
        url = f'{self.cfg.workspace_base}/watchlists?api-version={_API_VERSION}'
        data = self._http('GET', url, self._tokens.headers(_ARM_SCOPE))
        return data.get('value', [])

    def get_watchlist_items(
        self,
        watchlist_alias: str,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Return items from a specific watchlist (e.g. 'HighValueAssets')."""
        url = (
            f'{self.cfg.workspace_base}/watchlists/{watchlist_alias}/watchlistItems'
            f'?api-version={_API_VERSION}&$top={limit}'
        )
        items = []
        while url:
            data = self._http('GET', url, self._tokens.headers(_ARM_SCOPE))
            items.extend(data.get('value', []))
            url = data.get('nextLink')
        return items

    def lookup_watchlist(
        self,
        watchlist_alias: str,
        field: str,
        value: str,
    ) -> Optional[Dict[str, Any]]:
        """Find a single watchlist item by field value."""
        items = self.get_watchlist_items(watchlist_alias)
        for item in items:
            props = item.get('properties') or {}
            row = props.get('itemsKeyValue') or {}
            if str(row.get(field, '')).lower() == value.lower():
                return row
        return None

    # ------------------------------------------------------------------
    # Log Analytics KQL
    # ------------------------------------------------------------------

    def query(
        self,
        kql: str,
        timespan: Optional[str] = 'P1D',
    ) -> List[Dict[str, Any]]:
        """Execute a KQL query against the Log Analytics workspace.

        Parameters
        ----------
        kql : KQL query string, e.g. ``SecurityEvent | where EventID == 4624 | top 100``
        timespan : ISO 8601 duration (default last 24 h) or None
        """
        if not self.cfg.workspace_id:
            raise ValueError('SENTINEL_WORKSPACE_ID not configured for KQL queries')

        url = f'{_LA_BASE}/v1/workspaces/{self.cfg.workspace_id}/query'
        body: Dict[str, Any] = {'query': kql}
        if timespan:
            body['timespan'] = timespan

        data = self._http('POST', url, self._tokens.headers(_LA_SCOPE), body=body)
        return _flatten_kql_result(data)

    # ------------------------------------------------------------------
    # Convenience: fetch new incidents since last checkpoint
    # ------------------------------------------------------------------

    def fetch_new_incidents(self, since_ts: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch new/active incidents, optionally filtered by creation time."""
        incidents = self.list_incidents(status_filter='New', top=100)
        if since_ts:
            incidents = [i for i in incidents
                         if (i.get('created_ts') or '') > since_ts]
        return incidents

    # ------------------------------------------------------------------
    # Healthcheck
    # ------------------------------------------------------------------

    def ping(self) -> Dict[str, Any]:
        """Validate connectivity and auth by listing incidents (top=1)."""
        try:
            incidents = self.list_incidents(top=1)
            return {'ok': True, 'incident_count_sample': len(incidents)}
        except Exception as exc:
            return {'ok': False, 'error': str(exc)}


# ── KQL result flattener ──────────────────────────────────────────────

def _flatten_kql_result(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert the table-format KQL response into a list of dicts."""
    rows = []
    for table in data.get('tables', []):
        columns = [c.get('name') for c in table.get('columns', [])]
        for row in table.get('rows', []):
            rows.append(dict(zip(columns, row)))
    return rows


# ── Singleton ─────────────────────────────────────────────────────────

_GLOBAL_CONNECTOR: Optional[SentinelWorkspaceConnector] = None


def get_sentinel_connector() -> SentinelWorkspaceConnector:
    global _GLOBAL_CONNECTOR
    if _GLOBAL_CONNECTOR is None:
        _GLOBAL_CONNECTOR = SentinelWorkspaceConnector()
    return _GLOBAL_CONNECTOR
