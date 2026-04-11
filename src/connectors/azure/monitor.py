"""Azure Monitor connector — diagnostic logs and platform metrics.

Pulls from:
- Azure Monitor Logs (Log Analytics workspace) via REST API
- Azure Monitor Metrics (resource-level metrics) via REST API
- Diagnostic settings log categories

Environment variables
---------------------
AZURE_MONITOR_WORKSPACE_ID  : Log Analytics workspace GUID (required for logs)
AZURE_MONITOR_SUBSCRIPTION  : Azure subscription ID (required)
AZURE_MONITOR_RESOURCE_GROUP: Resource group filter (optional)
AZURE_MONITOR_QUERY         : KQL query override (default: broad security events)
AZURE_MONITOR_LOOKBACK_HOURS: How many hours back on first poll (default: 1)
AZURE_MONITOR_MAX_ROWS      : Max rows per query (default: 1000)
AZURE_MONITOR_METRICS_ENABLED: '1' to pull resource metrics (default: '0')
AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID: Service principal auth
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_CHECKPOINT_FILE = 'data/checkpoints/azure_monitor.checkpoint.json'

# Default KQL query for security-relevant logs
_DEFAULT_QUERY = """
union
    AzureActivity | where TimeGenerated > ago(1h) | project TimeGenerated, OperationName, ResourceGroup, ResourceId, Caller, ActivityStatus, AuthorizationInfo, Properties,
    SecurityEvent | where TimeGenerated > ago(1h) | project TimeGenerated, EventID, Account, Computer, Activity, IpAddress, LogonType, SubjectAccount,
    AuditLogs | where TimeGenerated > ago(1h) | project TimeGenerated, OperationType, Result, InitiatedBy, TargetResources, AdditionalDetails,
    SigninLogs | where TimeGenerated > ago(1h) | project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, LocationDetails, Status, ConditionalAccessStatus
| order by TimeGenerated asc
| take 1000
"""

_SECURITY_QUERY = """\
union
  (AzureActivity | where TimeGenerated > ago({lookback}) and ActivityStatus == 'Failed'),
  (SecurityEvent | where TimeGenerated > ago({lookback})),
  (AuditLogs | where TimeGenerated > ago({lookback})),
  (SigninLogs | where TimeGenerated > ago({lookback}) and ResultType != '0')
| order by TimeGenerated asc
| take {max_rows}
"""


def _load_checkpoint() -> dict:
    try:
        if os.path.exists(_CHECKPOINT_FILE):
            with open(_CHECKPOINT_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_checkpoint(data: dict) -> None:
    import os as _os
    _os.makedirs(os.path.dirname(_CHECKPOINT_FILE), exist_ok=True)
    tmp = _CHECKPOINT_FILE + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        _os.replace(tmp, _CHECKPOINT_FILE)
    except Exception:
        pass


def _get_access_token(tenant_id: str, client_id: str, client_secret: str, resource: str = 'https://api.loganalytics.io') -> str:
    """Obtain an OAuth2 bearer token via client credentials."""
    import urllib.request
    import urllib.parse
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    data = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': resource,
    }).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    token = body.get('access_token')
    if not token:
        raise RuntimeError(f"No access_token in response: {body}")
    return token


def _build_auth_headers() -> Dict[str, str]:
    """Build Authorization header using service principal or managed identity."""
    client_id = os.getenv('AZURE_CLIENT_ID', '')
    client_secret = os.getenv('AZURE_CLIENT_SECRET', '')
    tenant_id = os.getenv('AZURE_TENANT_ID', '')
    if client_id and client_secret and tenant_id:
        token = _get_access_token(tenant_id, client_id, client_secret)
        return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    # Try azure-identity DefaultAzureCredential
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.core.credentials import TokenRequestOptions  # type: ignore
        cred = DefaultAzureCredential()
        tok = cred.get_token('https://api.loganalytics.io/.default')
        return {'Authorization': f'Bearer {tok.token}', 'Content-Type': 'application/json'}
    except Exception:
        pass
    raise RuntimeError(
        'Azure Monitor: no credentials configured. '
        'Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID or use managed identity.'
    )


def _normalize_row(row: Dict[str, Any], source: str = 'azure_monitor') -> Dict[str, Any]:
    """Map a Log Analytics row dict to the canonical event envelope."""
    env: Dict[str, Any] = {
        'ingest_source': source,
        'source_type': 'azure',
        'raw': row,
    }
    # Timestamp
    ts_raw = row.get('TimeGenerated') or row.get('time') or row.get('timestamp')
    if ts_raw:
        try:
            dt = datetime.fromisoformat(str(ts_raw).replace('Z', '+00:00'))
            env['ts'] = dt.timestamp()
        except Exception:
            env['ts'] = time.time()
    else:
        env['ts'] = time.time()

    # Identity — structured separately to avoid ternary-precedence trap
    user: Optional[str] = (
        row.get('Caller')
        or row.get('UserPrincipalName')
        or row.get('Account')
        or row.get('SubjectAccount')
    )
    if user is None:
        initiated_by = row.get('InitiatedBy')
        if isinstance(initiated_by, dict):
            user = (initiated_by.get('user') or {}).get('userPrincipalName')
    env['user'] = user
    env['host'] = row.get('Computer') or row.get('ResourceId') or row.get('ResourceGroup')
    env['src_ip'] = row.get('IpAddress') or row.get('CallerIPAddress') or row.get('IPAddress')

    # Operation / event metadata
    env['event_name'] = row.get('OperationName') or row.get('Activity') or row.get('OperationType')
    env['severity'] = _map_severity(row)
    env['status'] = row.get('ActivityStatus') or row.get('ResultType') or row.get('Result')
    env['resource'] = row.get('ResourceId') or row.get('ResourceGroup')

    # Factors
    factors: List[str] = ['azure_monitor:event']
    if env['severity'] in ('HIGH', 'CRITICAL', 'WARNING'):
        factors.append(f"azure_monitor:{env['severity'].lower()}_event")
    ev_id = row.get('EventID')
    if ev_id:
        factors.append(f"winevent:{ev_id}")
    env['factors'] = factors

    try:
        from src.connectors.correlation_keys import build_correlation_keys
        env['correlation_keys'] = build_correlation_keys(env)
    except Exception:
        env['correlation_keys'] = {}

    return env


def _map_severity(row: Dict[str, Any]) -> str:
    status = str(row.get('ActivityStatus') or row.get('ResultType') or row.get('Result') or '').lower()
    if status in ('failed', 'failure', '50126', '50053', '50055', '50074'):
        return 'WARNING'
    level = str(row.get('Level') or row.get('category') or '').lower()
    if level in ('critical', 'error'):
        return 'HIGH'
    return 'INFO'


class AzureMonitorConnector:
    """Azure Monitor / Log Analytics connector."""

    def __init__(self) -> None:
        self.workspace_id = os.getenv('AZURE_MONITOR_WORKSPACE_ID', '')
        self.subscription_id = os.getenv('AZURE_MONITOR_SUBSCRIPTION', '')
        self.ck = _load_checkpoint()
        self._token_cache: Optional[str] = None
        self._token_expiry: float = 0.0

    def _headers(self) -> Dict[str, str]:
        return _build_auth_headers()

    def _run_query(self, kql: str, timespan: str = 'PT1H') -> List[Dict[str, Any]]:
        """Execute a KQL query against the Log Analytics workspace."""
        if not self.workspace_id:
            raise RuntimeError('AZURE_MONITOR_WORKSPACE_ID not configured')
        import urllib.request
        url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
        body = json.dumps({'query': kql, 'timespan': timespan}).encode()
        headers = self._headers()
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
        rows: List[Dict[str, Any]] = []
        for table in result.get('tables') or []:
            cols = [c['name'] for c in (table.get('columns') or [])]
            for row_vals in (table.get('rows') or []):
                rows.append(dict(zip(cols, row_vals)))
        return rows

    def fetch_events(self) -> Iterable[Dict[str, Any]]:
        """Yield normalized events from Log Analytics."""
        if not self.workspace_id:
            logger.warning('AzureMonitor: AZURE_MONITOR_WORKSPACE_ID not set')
            return

        lookback_hours = int(os.getenv('AZURE_MONITOR_LOOKBACK_HOURS', '1'))
        max_rows = int(os.getenv('AZURE_MONITOR_MAX_ROWS', '1000'))
        custom_query = os.getenv('AZURE_MONITOR_QUERY', '')

        if custom_query:
            kql = custom_query
        else:
            kql = _SECURITY_QUERY.format(
                lookback=f'{lookback_hours}h',
                max_rows=max_rows,
            )

        try:
            rows = self._run_query(kql)
            newest_ts = self.ck.get('last_ts', 0.0)
            for row in rows:
                env = _normalize_row(row)
                newest_ts = max(newest_ts, env.get('ts', 0.0))
                yield env
            if newest_ts:
                self.ck['last_ts'] = newest_ts
                _save_checkpoint(self.ck)
            logger.debug('AzureMonitor: fetched %d events', len(rows))
        except Exception:
            logger.exception('AzureMonitor: fetch_events failed')

    def fetch_metrics(self, resource_id: str, metric_names: List[str], interval: str = 'PT5M') -> Dict[str, Any]:
        """Pull Azure Monitor metrics for a specific resource (CPU, memory, etc.)."""
        if not self.subscription_id:
            return {'error': 'AZURE_MONITOR_SUBSCRIPTION not configured'}
        try:
            # Use ARM metrics endpoint
            from urllib.parse import quote
            import urllib.request
            token = _get_access_token(
                os.getenv('AZURE_TENANT_ID', ''),
                os.getenv('AZURE_CLIENT_ID', ''),
                os.getenv('AZURE_CLIENT_SECRET', ''),
                resource='https://management.azure.com',
            )
            names = ','.join(metric_names[:20])
            url = (
                f"https://management.azure.com{resource_id}/providers/microsoft.insights/metrics"
                f"?api-version=2018-01-01&metricnames={quote(names)}&interval={interval}"
            )
            req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
            return result
        except Exception as exc:
            logger.warning('AzureMonitor metrics fetch failed: %s', exc)
            return {'error': str(exc)}
