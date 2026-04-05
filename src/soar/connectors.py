from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Callable, Dict, Optional

import httpx

from src.soar.connector_audit import record_audit
try:
    from src.integrations.ms_graph_connector import MicrosoftGraphConnector
except Exception:
    MicrosoftGraphConnector = None

LOGGER = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 5
DEFAULT_AUTH_HEADER = 'Authorization'


class ConnectorError(Exception):
    pass


class ConnectorRegistry:
    """Simple registry to hold connector callables used by PlaybookRunner.

    Each connector is an async callable accepting (params: Dict[str, Any]) and
    returning a dict-like result or raising ConnectorError on failure.
    """

    def __init__(self):
        self._connectors: Dict[str, Callable[[Dict[str, Any]], Any]] = {}

    def register(self, name: str, func: Callable[[Dict[str, Any]], Any]):
        self._connectors[name] = func

    def get(self, name: str) -> Optional[Callable[[Dict[str, Any]], Any]]:
        return self._connectors.get(name)


_REGISTRY = ConnectorRegistry()


def get_registry() -> ConnectorRegistry:
    return _REGISTRY


async def http_post(url: str, json_payload: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    try:
        headers = {}
        # support api_key in payload for simple auth
        api_key = json_payload.get('_api_key') or json_payload.get('api_key') or json_payload.get('apikey')
        if api_key:
            headers[DEFAULT_AUTH_HEADER] = f'ApiKey {api_key}'
        # support bearer token from env (VAULT or runtime provider could be added)
        bearer_env = json_payload.get('_bearer_env') or json_payload.get('bearer_env')
        if bearer_env:
            token = os.getenv(bearer_env)
            if token:
                headers[DEFAULT_AUTH_HEADER] = f'Bearer {token}'
        async with httpx.AsyncClient(timeout=timeout) as c:
            resp = await c.post(url, json=json_payload, headers=headers)
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return {"status": "ok", "code": resp.status_code}
    except Exception as e:  # pragma: no cover - network paths
        LOGGER.exception('http_post failed')
        raise ConnectorError(str(e))


# Demo connector implementations (can be replaced by real integration code)
async def idp_revoke_sessions(params: Dict[str, Any]) -> Dict[str, Any]:
    user = params.get('user') or params.get('username')
    if not user:
        raise ConnectorError('missing user')
    # Example: call IdP API (placeholder)
    # If an http endpoint is provided, use it
    url = params.get('api_url') or params.get('url')
    if url:
        # perform a POST with basic payload; allow api_key or bearer_env in params
        payload = {'action': 'revoke_sessions', 'user': user}
        if 'api_key' in params:
            payload['api_key'] = params.get('api_key')
        if 'bearer_env' in params:
            payload['_bearer_env'] = params.get('bearer_env')
        res = await http_post(url, payload)
        # audit the connector call
        try:
            record_audit({'connector': 'idp.revoke_sessions', 'user': user, 'url': url, 'tenant': params.get('tenant'), 'playbook': params.get('playbook')})
        except Exception:
            pass
        return res
    await asyncio.sleep(0.01)
    return {"revoked": True, "user": user}


async def firewall_block_ip(params: Dict[str, Any]) -> Dict[str, Any]:
    ip = params.get('ip')
    if not ip:
        raise ConnectorError('missing ip')
    url = params.get('api_url')
    if url:
        return await http_post(url, {"action": "block", "ip": ip})
    await asyncio.sleep(0.01)
    return {"blocked": True, "ip": ip}


async def mailbox_disable_rule(params: Dict[str, Any]) -> Dict[str, Any]:
    mailbox = params.get('user') or params.get('mailbox')
    rule = params.get('rule_name')
    if not mailbox:
        raise ConnectorError('missing mailbox')
    await asyncio.sleep(0.01)
    return {"disabled": True, "mailbox": mailbox, "rule": rule}


async def quarantine_file_connector(params: Dict[str, Any]) -> Dict[str, Any]:
    file_hash = params.get('file_hash')
    if not file_hash:
        raise ConnectorError('missing file_hash')
    await asyncio.sleep(0.01)
    return {"quarantined": True, "file_hash": file_hash}


# Register built-in connectors
def _severity_to_priority(level: str | None) -> int:
    table = {'critical': 5, 'high': 4, 'warning': 3, 'medium': 3, 'low': 2, 'info': 1}
    if not level:
        return 2
    return table.get(level.lower(), 2)


def _ticket_details(params: Dict[str, Any]) -> Dict[str, Any]:
    recommendations = params.get('recommendations') or []
    if not isinstance(recommendations, list):
        recommendations = [recommendations]
    return {
        'tenant': params.get('tenant'),
        'connector_id': params.get('connector_id'),
        'idle_seconds': params.get('seconds_since_event'),
        'ttl_seconds': params.get('ttl_seconds'),
        'last_event_ts': params.get('last_event_ts'),
        'auto_ticket_reason': params.get('auto_ticket_reason') or 'iam_missing_logs',
        'recommendations': recommendations,
        'severity': params.get('severity'),
    }


async def _dispatch_ticket(url: Optional[str], payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not url:
        return None
    return await http_post(url, payload)


async def cortex_ticket(params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    url = os.getenv('CORTEX_TICKET_URL')
    details = _ticket_details(params)
    payload = {
        'name': params.get('title') or f"[Missing Logs] {params.get('connector_id')}",
        'type': params.get('ticket_type') or 'connector_missing_logs',
        'severity': _severity_to_priority(params.get('severity')),
        'details': details,
        'data': details,
        'queue': params.get('queue') or 'Connector Reliability',
        'owner': params.get('owner') or 'Connector Reliability',
        '_api_key': os.getenv('CORTEX_TICKET_API_KEY'),
    }
    if os.getenv('CORTEX_TICKET_BEARER'):
        payload['_bearer_env'] = 'CORTEX_TICKET_BEARER'
    return await _dispatch_ticket(url, payload)


async def phantom_ticket(params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    url = os.getenv('PHANTOM_TICKET_URL')
    details = _ticket_details(params)
    idle_desc = details.get('idle_seconds')
    ttl_desc = details.get('ttl_seconds')
    container = {
        'name': params.get('title') or f"[Missing Logs] {params.get('connector_id')}",
        'description': params.get('description') or params.get('summary') or f"Connector idle {idle_desc}s (TTL {ttl_desc}s).",
        'severity': (params.get('severity') or 'medium').lower(),
        'label': params.get('label') or 'connector_missing_logs',
        'source_data_identifier': f"{params.get('tenant')}:{params.get('connector_id')}",
        'custom_fields': {
            'tenant': details.get('tenant'),
            'connector_id': details.get('connector_id'),
            'idle_seconds': idle_desc,
            'ttl_seconds': ttl_desc,
        },
    }
    payload = {
        'container': container,
        'artifacts': [
            {
                'name': 'connector_missing_log',
                'label': 'connector_missing_log',
                'severity': (params.get('severity') or 'medium').lower(),
                'data': {**details},
            }
        ],
        '_api_key': os.getenv('PHANTOM_TICKET_TOKEN'),
    }
    return await _dispatch_ticket(url, payload)


async def tines_ticket(params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    url = os.getenv('TINES_TICKET_URL')
    payload = {
        'event': {
            'title': params.get('title'),
            'tenant': params.get('tenant'),
            'connector_id': params.get('connector_id'),
            'severity': params.get('severity'),
            'idle_seconds': params.get('seconds_since_event'),
            'ttl_seconds': params.get('ttl_seconds'),
            'details': _ticket_details(params),
            'queue': params.get('queue') or 'Connector Reliability',
        },
        '_bearer_env': 'TINES_TICKET_BEARER' if os.getenv('TINES_TICKET_BEARER') else None,
    }
    return await _dispatch_ticket(url, payload)


async def ticket_create_connector(params: Dict[str, Any]) -> Dict[str, Any]:
    tasks = []
    title = params.get('title') or f"[Missing Logs] {params.get('connector_id')}"
    description = params.get('description') or f"Tenant {params.get('tenant')} missing telemetry on connector {params.get('connector_id')}"
    common = {
        'title': title,
        'description': description,
        'severity': params.get('severity') or 'warning',
        'connector_id': params.get('connector_id'),
        'tenant': params.get('tenant'),
        'queue': params.get('queue') or 'Connector Reliability',
        'owner': params.get('owner') or 'Connector Reliability',
        'summary': params.get('recommendations'),
        'seconds_since_event': params.get('seconds_since_event'),
        'ttl_seconds': params.get('ttl_seconds'),
        'last_event_ts': params.get('last_event_ts'),
        'auto_ticket_reason': params.get('auto_ticket_reason') or 'iam_missing_logs',
        'recommendations': params.get('recommendations'),
    }
    providers = []
    if os.getenv('CORTEX_TICKET_URL'):
        tasks.append(('cortex', cortex_ticket({**params, **common})))
    if os.getenv('PHANTOM_TICKET_URL'):
        tasks.append(('phantom', phantom_ticket({**params, **common})))
    if os.getenv('TINES_TICKET_URL'):
        tasks.append(('tines', tines_ticket({**params, **common})))
    results = []
    for name, coro in tasks:
        try:
            res = await coro
            results.append({'provider': name, 'result': res or {'status': 'sent'}})
        except Exception as exc:  # pragma: no cover - network failures
            results.append({'provider': name, 'error': str(exc)})
    if not tasks:
        results.append({'provider': 'noop', 'result': {'status': 'noop'}})
    return {'providers': results, 'title': title}


_REGISTRY.register('idp.revoke_sessions', idp_revoke_sessions)
_REGISTRY.register('firewall.block_ip', firewall_block_ip)
_REGISTRY.register('mailbox.disable_rule', mailbox_disable_rule)
_REGISTRY.register('file.quarantine', quarantine_file_connector)
_REGISTRY.register('ticket.create', ticket_create_connector)
_REGISTRY.register('ticket.create.cortex', cortex_ticket)
_REGISTRY.register('ticket.create.phantom', phantom_ticket)
_REGISTRY.register('ticket.create.tines', tines_ticket)


async def _msgraph_fetch_signins(params: Dict[str, Any]) -> Dict[str, Any]:
    tenant = params.get('tenant') or os.getenv('DEFAULT_TENANT', 'default')
    client_id = params.get('client_id') or os.getenv('O365_CLIENT_ID')
    client_secret = params.get('client_secret') or os.getenv('O365_CLIENT_SECRET')
    if MicrosoftGraphConnector is None:
        raise ConnectorError('ms_graph connector not available')
    try:
        conn = MicrosoftGraphConnector(tenant_id=tenant, client_id=client_id, client_secret=client_secret)
        events, cursor = await conn.fetch_since(None, limit=int(params.get('limit', 200)))
        # ack/save cursor for continuity
        if cursor:
            await conn.ack(cursor)
        return {'events': events, 'cursor': cursor}
    except Exception as exc:
        raise ConnectorError(str(exc))


async def _msgraph_fetch_security_alerts(params: Dict[str, Any]) -> Dict[str, Any]:
    # Lightweight wrapper to fetch from /security/alerts (simple polling)
    tenant = params.get('tenant') or os.getenv('DEFAULT_TENANT', 'default')
    client_id = params.get('client_id') or os.getenv('O365_CLIENT_ID')
    client_secret = params.get('client_secret') or os.getenv('O365_CLIENT_SECRET')
    if MicrosoftGraphConnector is None:
        raise ConnectorError('ms_graph connector not available')
    try:
        conn = MicrosoftGraphConnector(tenant_id=tenant, client_id=client_id, client_secret=client_secret)
        # Reuse fetch_since with a different base path by temporarily calling the session directly
        # This keeps the wrapper simple; full implementation belongs in the connector class.
        headers = {'Authorization': f'Bearer {conn._access_token}'}
        url = 'https://graph.microsoft.com/v1.0/security/alerts'
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        return {'alerts': data.get('value', [])}
    except Exception as exc:
        raise ConnectorError(str(exc))


_REGISTRY.register('msgraph.fetch_signins', _msgraph_fetch_signins)
_REGISTRY.register('msgraph.fetch_security_alerts', _msgraph_fetch_security_alerts)
