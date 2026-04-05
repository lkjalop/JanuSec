"""Azure NSG Flow Logs connector — pull Network Security Group flow records.

Fetches NSG flow logs from Azure Monitor / Log Analytics workspace using
the Log Analytics Query API (application/json POST).

Requires permissions on the registered app:
  Log Analytics Reader role on the workspace

Environment variables:
  AZURE_TENANT_ID
  AZURE_CLIENT_ID
  AZURE_CLIENT_SECRET
  AZURE_LOG_ANALYTICS_WORKSPACE_ID   — Log Analytics workspace GUID
  AZURE_NSG_FLOW_TABLE               — KQL table name (default: AzureNetworkAnalytics_CL or AzureNSGFlowLog)

When the workspace ID is absent the connector emits nothing and logs a
configuration-missing warning so the rest of the pipeline continues.

MSAL is an optional dependency; when absent the connector falls back to
urllib-based client-credential token acquisition.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, Iterator, Optional

from .base import AzureConnectorConfig, load_checkpoint, save_checkpoint, azure_envelope
from src.connectors.correlation_keys import build_correlation_keys

logger = logging.getLogger(__name__)

_MONITOR_SCOPE = 'https://api.loganalytics.io/.default'
_TOKEN_CACHE: Dict[str, tuple] = {}  # {key: (token, expiry)}


def _acquire_token(cfg: AzureConnectorConfig) -> Optional[str]:
    """Acquire an OAuth2 bearer token for the Log Analytics API."""
    if not (cfg.tenant_id and cfg.client_id and cfg.client_secret):
        return None
    cache_key = f'{cfg.tenant_id}:{cfg.client_id}:loganalytics'
    cached = _TOKEN_CACHE.get(cache_key)
    if cached and time.time() + 30 < cached[1]:
        return cached[0]

    # Try MSAL first, fall back to urllib
    try:
        import msal
        app = msal.ConfidentialClientApplication(
            cfg.client_id,
            authority=f'https://login.microsoftonline.com/{cfg.tenant_id}',
            client_credential=cfg.client_secret,
        )
        result = app.acquire_token_for_client(scopes=[_MONITOR_SCOPE])
        token = result.get('access_token')
        expires_in = int(result.get('expires_in', 3600))
    except ImportError:
        # urllib fallback
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials',
            'client_id': cfg.client_id,
            'client_secret': cfg.client_secret,
            'scope': _MONITOR_SCOPE,
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
            logger.warning('NSGFlow: token acquisition failed: %s', exc)
            return None

    if token:
        _TOKEN_CACHE[cache_key] = (token, time.time() + expires_in)
        return token
    return None


def _run_kql(workspace_id: str, query: str, token: str, timespan: str = 'P1D') -> Optional[list]:
    """Execute a KQL query against a Log Analytics workspace and return rows."""
    url = f'https://api.loganalytics.io/v1/workspaces/{workspace_id}/query'
    payload = json.dumps({'query': query, 'timespan': timespan}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method='POST',
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
    except urllib.error.HTTPError as exc:
        body = ''
        try:
            body = exc.read().decode()[:300]
        except Exception:
            pass
        logger.warning('NSGFlow: KQL query failed HTTP %s: %s', exc.code, body)
        return None
    except Exception as exc:
        logger.warning('NSGFlow: KQL query error: %s', exc)
        return None


class NSGFlowConnector:
    """Pull NSG Flow log records from a Log Analytics workspace."""

    def __init__(self, cfg: AzureConnectorConfig):
        self.cfg = cfg
        self.name = 'nsg_flow'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_flows(self, lookback_hours: int = 1) -> Iterable[Dict[str, Any]]:
        """Yield canonical envelopes for NSG flow log records.

        Args:
            lookback_hours: How many hours of data to query (honoured as KQL
                ``ago()`` window; checkpoint suppresses duplicate processing).
        """
        import os
        workspace_id = os.getenv('AZURE_LOG_ANALYTICS_WORKSPACE_ID') or self.cfg.__dict__.get('log_analytics_workspace_id')
        if not workspace_id:
            logger.warning('NSGFlow: AZURE_LOG_ANALYTICS_WORKSPACE_ID not set; skipping pull')
            return

        token = _acquire_token(self.cfg)
        if not token:
            logger.warning('NSGFlow: could not acquire token; check AZURE_CLIENT_ID/SECRET/TENANT_ID')
            return

        table = os.getenv('AZURE_NSG_FLOW_TABLE', 'AzureNetworkAnalytics_CL')
        last_ts = self.ck.get('last_ts')
        since_clause = f"| where TimeGenerated >= ago({lookback_hours}h)"
        if last_ts:
            since_clause = f"| where TimeGenerated > datetime({last_ts})"

        kql = (
            f"{table} {since_clause} "
            "| project TimeGenerated, SrcIP_s, DestIP_s, SrcPort_d, DestPort_d, "
            "L4Protocol_s, FlowDirection_s, FlowStatus_s, "
            "InboundBytes_d, OutboundBytes_d, NSGName_s, Subnet_s "
            "| order by TimeGenerated asc "
            "| limit 5000"
        )

        rows = _run_kql(workspace_id, kql, token, timespan=f'PT{lookback_hours}H')
        if rows is None:
            return

        newest_ts: Optional[str] = None
        for row in rows:
            ts_raw = row.get('TimeGenerated')
            env = azure_envelope(row, 'nsg_flow', subscription_id=self.cfg.subscription_id)
            env['src_ip'] = row.get('SrcIP_s')
            env['dst_ip'] = row.get('DestIP_s')
            env['src_port'] = row.get('SrcPort_d')
            env['dst_port'] = row.get('DestPort_d')
            env['protocol'] = row.get('L4Protocol_s')
            env['direction'] = row.get('FlowDirection_s')
            env['action'] = row.get('FlowStatus_s')
            env['bytes_in'] = row.get('InboundBytes_d')
            env['bytes_out'] = row.get('OutboundBytes_d')
            env['nsg_name'] = row.get('NSGName_s')
            env['subnet'] = row.get('Subnet_s')
            env['factors'] = ['network:flow_record', 'cloud:azure_nsg']
            env['correlation_keys'] = build_correlation_keys(
                env,
                extra_values={'subscription_id': self.cfg.subscription_id},
            )
            if ts_raw:
                env['ts'] = ts_raw
                newest_ts = str(ts_raw)
            env = {k: v for k, v in env.items() if v is not None}
            yield env

        if newest_ts:
            self.ck['last_ts'] = newest_ts
            save_checkpoint(self.name, self.cfg, self.ck)

    def commit(self, marker: Any) -> None:
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
