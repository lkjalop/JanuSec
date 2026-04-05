"""Azure Activity Log connector — pull Azure Resource Manager control-plane events.

Fetches Azure Activity (Audit) Log entries from Log Analytics workspace via
KQL, or directly from the ARM Insights API as a fallback.

Captures:
  - Resource create/update/delete operations
  - Role assignment changes
  - Policy assignment events
  - Subscription-level administrative actions

Required permissions:
  Log Analytics Reader on workspace  (KQL path)
  Reader on subscription             (ARM Insights fallback)

Environment variables:
  AZURE_TENANT_ID
  AZURE_CLIENT_ID
  AZURE_CLIENT_SECRET
  AZURE_SUBSCRIPTION_ID
  AZURE_LOG_ANALYTICS_WORKSPACE_ID   — optional; enables KQL path
  AZURE_ACTIVITY_LOG_TABLE           — KQL table name (default: AzureActivity)
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional

from .base import AzureConnectorConfig, load_checkpoint, save_checkpoint, azure_envelope
from src.connectors.correlation_keys import build_correlation_keys

logger = logging.getLogger(__name__)

_ARM_SCOPE = 'https://management.azure.com/.default'
_GRAPH_SCOPE = 'https://api.loganalytics.io/.default'
_TOKEN_CACHE: Dict[str, tuple] = {}

# Map ARM operation status to canonical severity
_STATUS_SEVERITY = {
    'Failed': 'high',
    'Critical': 'critical',
    'Warning': 'medium',
    'Succeeded': 'low',
}


def _acquire_token(cfg: AzureConnectorConfig, scope: str) -> Optional[str]:
    if not (cfg.tenant_id and cfg.client_id and cfg.client_secret):
        return None
    cache_key = f'{cfg.tenant_id}:{cfg.client_id}:{scope}'
    cached = _TOKEN_CACHE.get(cache_key)
    if cached and time.time() + 30 < cached[1]:
        return cached[0]
    try:
        import msal
        app = msal.ConfidentialClientApplication(
            cfg.client_id,
            authority=f'https://login.microsoftonline.com/{cfg.tenant_id}',
            client_credential=cfg.client_secret,
        )
        result = app.acquire_token_for_client(scopes=[scope])
        token = result.get('access_token')
        expires_in = int(result.get('expires_in', 3600))
    except ImportError:
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials',
            'client_id': cfg.client_id,
            'client_secret': cfg.client_secret,
            'scope': scope,
        }).encode()
        url = f'https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token'
        try:
            req = urllib.request.Request(
                url, data=body, method='POST',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
                data = json.loads(resp.read())
            token = data.get('access_token')
            expires_in = int(data.get('expires_in', 3600))
        except Exception as exc:
            logger.warning('ActivityLog: token acquisition failed: %s', exc)
            return None
    if token:
        _TOKEN_CACHE[cache_key] = (token, time.time() + expires_in)
        return token
    return None


def _kql_query(workspace_id: str, kql: str, token: str, timespan: str = 'P1D') -> Optional[List[Dict]]:
    url = f'https://api.loganalytics.io/v1/workspaces/{workspace_id}/query'
    payload = json.dumps({'query': kql, 'timespan': timespan}).encode()
    req = urllib.request.Request(
        url, data=payload, method='POST',
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            data = json.loads(resp.read())
        tables = data.get('tables') or []
        if not tables:
            return []
        table = tables[0]
        cols = [c.get('name') for c in (table.get('columns') or [])]
        return [dict(zip(cols, row)) for row in (table.get('rows') or [])]
    except Exception as exc:
        logger.warning('ActivityLog KQL failed: %s', exc)
        return None


def _arm_get_events(
    subscription_id: str,
    token: str,
    filter_str: str,
) -> Optional[List[Dict]]:
    """Fallback: query ARM Activity Log API directly."""
    url = (
        f'https://management.azure.com/subscriptions/{subscription_id}'
        f'/providers/microsoft.insights/eventtypes/management/values'
        f'?api-version=2015-04-01&$filter={urllib.parse.quote(filter_str)}'
    )
    req = urllib.request.Request(
        url,
        headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            data = json.loads(resp.read())
        return data.get('value') or []
    except Exception as exc:
        logger.warning('ActivityLog ARM fallback failed: %s', exc)
        return None


def _to_canonical(raw: Dict[str, Any], subscription_id: Optional[str]) -> Dict[str, Any]:
    """Map a raw activity log record to a canonical envelope."""
    # Raw may come from KQL (flat) or ARM API (nested properties)
    props = raw.get('properties') or raw
    caller = (
        raw.get('Caller_s')
        or props.get('caller')
        or (raw.get('Claims_d') or {}).get('upn')
    )
    status_raw = raw.get('ActivityStatusValue_s') or (props.get('status') or {}).get('value') or props.get('status') or ''
    operation = raw.get('OperationNameValue') or props.get('operationName') or raw.get('OperationName_s') or ''
    resource = raw.get('ResourceId') or props.get('resourceId') or raw.get('_ResourceId')
    ts = raw.get('TimeGenerated') or props.get('eventTimestamp') or raw.get('ts')

    env = azure_envelope(raw, 'azure_activity', subscription_id=subscription_id)
    env['user'] = caller
    env['actor'] = caller
    env['resource'] = resource
    env['action'] = operation
    env['status'] = status_raw
    env['severity'] = _STATUS_SEVERITY.get(status_raw, 'low')
    env['resource_group'] = raw.get('ResourceGroup') or props.get('resourceGroupName')
    env['subscription'] = subscription_id or raw.get('SubscriptionId')
    env['correlation_id'] = raw.get('CorrelationId') or props.get('correlationId')
    if ts:
        env['ts'] = ts
    env['factors'] = ['cloud:azure_activity']
    # Elevate severity for sensitive operations
    op_lower = operation.lower()
    if any(k in op_lower for k in ('roleassignment', 'policyassignment', 'delete', 'write')):
        env['factors'].append('cloud:privileged_operation')
    env['correlation_keys'] = build_correlation_keys(
        env,
        extra_values={'subscription_id': subscription_id, 'actor': caller},
    )
    return {k: v for k, v in env.items() if v is not None}


class AzureActivityLogConnector:
    """Pull Azure Activity / Audit log entries."""

    def __init__(self, cfg: AzureConnectorConfig):
        self.cfg = cfg
        self.name = 'azure_activity'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_events(self, lookback_hours: int = 1) -> Iterable[Dict[str, Any]]:
        """Yield canonical envelopes for Azure Activity Log entries.

        Priority: KQL (Log Analytics workspace) → ARM Insights API fallback.
        """
        import os
        workspace_id = os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID')
        subscription_id = self.cfg.subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')

        last_ts = self.ck.get('last_ts')
        newest_ts: Optional[str] = None

        # ── KQL path ──────────────────────────────────────────────────────
        if workspace_id:
            token = _acquire_token(self.cfg, _GRAPH_SCOPE)
            if token:
                table = os.getenv('AZURE_ACTIVITY_LOG_TABLE', 'AzureActivity')
                since_clause = f"| where TimeGenerated >= ago({lookback_hours}h)"
                if last_ts:
                    since_clause = f"| where TimeGenerated > datetime({last_ts})"
                kql = (
                    f"{table} {since_clause} "
                    "| project TimeGenerated, Caller_s, OperationNameValue, "
                    "ActivityStatusValue_s, ResourceId, ResourceGroup, "
                    "SubscriptionId, CorrelationId, _ResourceId, Properties "
                    "| order by TimeGenerated asc | limit 5000"
                )
                rows = _kql_query(workspace_id, kql, token, timespan=f'PT{lookback_hours}H')
                if rows is not None:
                    for row in rows:
                        env = _to_canonical(row, subscription_id)
                        ts = env.get('ts')
                        if ts:
                            newest_ts = str(ts)
                        yield env
                    if newest_ts:
                        self.ck['last_ts'] = newest_ts
                        save_checkpoint(self.name, self.cfg, self.ck)
                    return

        # ── ARM Insights fallback ─────────────────────────────────────────
        if not subscription_id:
            logger.warning('ActivityLog: no workspace_id or subscription_id configured; skipping')
            return

        token = _acquire_token(self.cfg, _ARM_SCOPE)
        if not token:
            logger.warning('ActivityLog: could not acquire ARM token')
            return

        from datetime import datetime, timezone, timedelta
        now = datetime.now(tz=timezone.utc)
        start_dt = (
            datetime.fromisoformat(str(last_ts).replace('Z', '+00:00'))
            if last_ts
            else now - timedelta(hours=lookback_hours)
        )
        filter_str = (
            f"eventTimestamp ge '{start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
            f"and eventTimestamp le '{now.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
        )
        events = _arm_get_events(subscription_id, token, filter_str)
        if not events:
            return

        for ev in events:
            env = _to_canonical(ev, subscription_id)
            ts = env.get('ts')
            if ts:
                newest_ts = str(ts)
            yield env

        if newest_ts:
            self.ck['last_ts'] = newest_ts
            save_checkpoint(self.name, self.cfg, self.ck)

    def commit(self, marker: Any) -> None:
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
