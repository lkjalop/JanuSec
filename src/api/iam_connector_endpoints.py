from __future__ import annotations

import json
import logging
import os
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

try:
    from src.security.auth import AuthContext, require_api_key
except Exception:
    try:
        from security.auth import AuthContext, require_api_key
    except Exception:
        AuthContext = None
        require_api_key = None

from src.secrets.vault import set_secret as vault_set_secret
from src.api.tenant_helpers import resolve_tenant_id

try:
    from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime  # type: ignore
except Exception:  # pragma: no cover
    get_server_runtime_state = None  # type: ignore
    persist_tenant_runtime = None  # type: ignore

try:
    from src.services.missing_log_monitor import dispatch_missing_log_alerts  # type: ignore
except Exception:  # pragma: no cover
    dispatch_missing_log_alerts = None  # type: ignore

ARTIFACTS_CONFIG_DIR = Path('artifacts/config')
MISSING_TTL_DEFAULT = float(os.getenv('IAM_CONNECTOR_MISSING_TTL', '900') or 900.0)
CONNECTOR_TTL_DEFAULTS: Dict[str, float] = {
    'okta': 300.0,
    'azure_ad': 300.0,
    'sailpoint_identitynow': 600.0,
    'pingidentity': 600.0,
    'onelogin': 600.0,
    'active_directory': 1800.0,
    'duo_security': 600.0,
    'cyberark_epm': 600.0,
    'forgerock': 600.0,
}

logger = logging.getLogger(__name__)


def _vault_storage_allowed() -> bool:
    return os.getenv('IAM_CONNECTOR_VAULT_ENABLED', '1').lower() not in {'0', 'false', 'no'}


def _vault_secret_key(tenant: str, connector: str, field: str) -> str:
    safe_tenant = tenant.replace('/', '_').replace('\\', '_')
    safe_field = field.replace('/', '_')
    return f'iam/{safe_tenant}/{connector}/{safe_field}'


def _store_secret_value(tenant: str, connector: str, field: str, value: str) -> Any:
    if not value:
        return value
    if not _vault_storage_allowed():
        return value
    if not isinstance(value, str):
        value = str(value)
    key = _vault_secret_key(tenant, connector, field)
    persisted = False
    try:
        persisted = vault_set_secret(key, value)
    except Exception:
        logger.warning('vault_set_secret_failed connector=%s field=%s tenant=%s', connector, field, tenant, exc_info=True)
    if persisted:
        return {'_vault_key': key}
    return value


def _secret_present(value: Any) -> bool:
    if isinstance(value, dict) and value.get('_vault_key'):
        return True
    return bool(value)

router = APIRouter(prefix='/api/v1/iam/connectors', tags=['iam_connectors'])

# Optional health endpoints for AWS/GCP workers (UI visibility)
try:
    from src.collectors.iam_aws_worker import AWSIAMCollector  # type: ignore
except Exception:
    AWSIAMCollector = None  # type: ignore
try:
    from src.collectors.iam_gcp_worker import GCPIAMCollector  # type: ignore
except Exception:
    GCPIAMCollector = None  # type: ignore

@router.get('/aws/health')
async def aws_health(request: Request, tenant_id: Optional[str] = Query(default=None), region: Optional[str] = Query(default=None), auth: AuthContext = Depends(require_api_key)) -> Dict[str, Any]:
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT', 'default')
    if AWSIAMCollector is None:
        raise HTTPException(status_code=503, detail='aws_worker_unavailable')
    try:
        c = AWSIAMCollector(tenant_id=tenant, region=region)
        return c.health_snapshot()
    except Exception:
        raise HTTPException(status_code=500, detail='health_error')

@router.get('/gcp/health')
async def gcp_health(request: Request, tenant_id: Optional[str] = Query(default=None), project_id: Optional[str] = Query(default=None), auth: AuthContext = Depends(require_api_key)) -> Dict[str, Any]:
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT', 'default')
    if GCPIAMCollector is None:
        raise HTTPException(status_code=503, detail='gcp_worker_unavailable')
    try:
        c = GCPIAMCollector(tenant_id=tenant, project_id=project_id)
        return c.health_snapshot()
    except Exception:
        raise HTTPException(status_code=500, detail='health_error')


def _config_path() -> Path:
    target = os.getenv('IAM_CONNECTORS_PATH')
    if target:
        return Path(target)
    return ARTIFACTS_CONFIG_DIR / 'iam_connectors.json'


def _ensure_dir() -> None:
    try:
        _config_path().parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _load_config() -> Dict[str, Any]:
    path = _config_path()
    if not path.exists():
        return {'tenants': {}, 'settings': {}}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            data.setdefault('tenants', {})
            data.setdefault('settings', {})
            return data
    except Exception:
        pass
    return {'tenants': {}, 'settings': {}}


def _save_config(data: Dict[str, Any]) -> None:
    _ensure_dir()
    path = _config_path()
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')
    tmp.replace(path)


def _secret_field(name: str) -> bool:
    return any(token in name.lower() for token in ('secret', 'token', 'password', 'key'))


def _load_env_defaults() -> Dict[str, Any]:
    raw = os.getenv('IAM_CONNECTOR_DEFAULTS_JSON', '').strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _tenant_settings(cfg: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    settings = cfg.setdefault('settings', {})
    tenant_settings = settings.setdefault(tenant, {})
    if not isinstance(tenant_settings, dict):
        tenant_settings = {}
        settings[tenant] = tenant_settings
    return tenant_settings


def _ensure_ttl_overrides(cfg: Dict[str, Any], tenant: str) -> Dict[str, float]:
    tenant_settings = _tenant_settings(cfg, tenant)
    overrides = tenant_settings.setdefault('ttl_overrides', {})
    if not isinstance(overrides, dict):
        overrides = {}
        tenant_settings['ttl_overrides'] = overrides
    return overrides


def _get_ttl_overrides(cfg: Dict[str, Any], tenant: str) -> Dict[str, float]:
    settings = cfg.get('settings') or {}
    tenant_settings = settings.get(tenant) or {}
    overrides = tenant_settings.get('ttl_overrides') or {}
    if not isinstance(overrides, dict):
        return {}
    return {k: float(v) for k, v in overrides.items() if isinstance(v, (int, float))}


def _resolve_ttl(connector_id: str, overrides: Dict[str, float]) -> float:
    override = overrides.get(connector_id)
    if override:
        return max(60.0, float(override))
    return float(CONNECTOR_TTL_DEFAULTS.get(connector_id, MISSING_TTL_DEFAULT))


def _recommended_actions(connector_id: str) -> List[str]:
    base = [
        'Verify the connector worker is enabled in the 21-stage ingest pipeline.',
        'Inject a test event via the IAM connectors UI to confirm routing through HopGraph.',
    ]
    connector_specific = {
        'okta': ['Confirm the Okta Event Hook subscription is active and API token still valid.'],
        'azure_ad': ['Verify Microsoft Graph subscriptions are renewed and client secrets not expired.'],
        'active_directory': ['Ensure the LDAPS bind account password is valid and domain controller reachable.'],
        'sailpoint_identitynow': ['Check the IdentityNow event trigger secret rotation history.'],
        'pingidentity': ['Validate PingOne audit API credentials and webhook HMAC secret configuration.'],
        'onelogin': ['Confirm the OneLogin webhook bearer token matches the configured secret.'],
    }
    return base + connector_specific.get(connector_id, [])


def _runtime_health_maps(request: Request, tenant: str, include_health: bool) -> tuple[Dict[str, Any], Dict[str, Any], Any]:
    if not include_health or get_server_runtime_state is None:
        return {}, {}, None
    try:
        runtime = get_server_runtime_state(request.app)
        tmap = runtime.tenants.setdefault(tenant, {})
        ref = tmap.setdefault('iam_connector_health', {})
        snapshot = deepcopy(ref)
        return snapshot, ref, runtime
    except Exception:
        return {}, {}, None


def _merge_dispatch_metadata(missing_alerts: List[Dict[str, Any]], dispatched: List[Dict[str, Any]]) -> None:
    if not missing_alerts or not dispatched:
        return
    index: Dict[str, Dict[str, Any]] = {}
    for entry in dispatched:
        connector_id = entry.get('connector')
        if not connector_id:
            continue
        if connector_id not in index:
            index[connector_id] = entry
    for alert in missing_alerts:
        connector_id = alert.get('connector')
        if not connector_id:
            continue
        meta = index.get(connector_id)
        if not meta:
            continue
        if meta.get('suppressed'):
            alert['suppressed'] = True
        auto_ticket = meta.get('auto_ticket')
        if auto_ticket:
            alert['auto_ticket'] = auto_ticket
        result_meta = meta.get('result')
        if result_meta and 'auto_ticket' not in alert:
            alert['auto_ticket'] = {'status': meta.get('status'), 'action': meta.get('action'), 'result': result_meta}


CONNECTOR_DEFINITIONS: List[Dict[str, Any]] = [
    {
        'id': 'okta',
        'label': 'Okta Workforce Identity',
        'category': 'SaaS IdP',
        'description': 'Streams Okta system logs for sign-ins, MFA policy changes, and lifecycle actions.',
        'fields': [
            {'name': 'org_url', 'label': 'Org URL', 'placeholder': 'https://acme.okta.com', 'type': 'url', 'required': True},
            {'name': 'api_token', 'label': 'API Token', 'placeholder': 'SSWS ...', 'type': 'password', 'required': True, 'secret': True},
            {'name': 'webhook_secret', 'label': 'Event Hook Secret', 'placeholder': 'Optional verification shared secret', 'type': 'password', 'secret': True},
            {'name': 'event_filter', 'label': 'Event Filter', 'placeholder': 'user.session.start,user.account.update', 'type': 'text'},
        ],
        'webhook': {
            'endpoint': '/api/v1/iam/okta/webhook',
            'headers': ['x-okta-verification-challenge', 'x-api-key'],
            'notes': 'Okta Admin → Workflow → Event Hooks. Reply with verification token on first call.',
        },
        'api': {
            'poll_endpoint': '/api/v1/iam/okta/poll',
            'env': {'org_url': 'OKTA_ORG_URL', 'api_token': 'OKTA_API_TOKEN', 'webhook_secret': 'OKTA_WEBHOOK_SECRET'},
        },
    },
    {
        'id': 'azure_ad',
        'label': 'Azure AD / Entra ID',
        'category': 'Cloud IdP',
        'description': 'Microsoft Graph audit + sign-in events via application registration and webhook subscription.',
        'fields': [
            {'name': 'tenant_id', 'label': 'Directory (Tenant) ID', 'placeholder': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'type': 'text', 'required': True},
            {'name': 'client_id', 'label': 'Client ID', 'placeholder': 'App registration client id', 'type': 'text', 'required': True},
            {'name': 'client_secret', 'label': 'Client Secret', 'type': 'password', 'secret': True, 'required': True},
            {'name': 'subscription_id', 'label': 'Graph Subscription ID', 'placeholder': 'Optional existing subscription id', 'type': 'text'},
        ],
        'webhook': {
            'endpoint': '/api/v1/iam/azure/webhook',
            'headers': ['x-api-key'],
            'notes': 'Graph sends GET with validationToken on subscription creation. Use HTTPS listener only.',
        },
        'api': {
            'poll_endpoint': '/api/v1/iam/azure/poll',
            'env': {'tenant_id': 'AAD_TENANT_ID', 'client_id': 'AAD_CLIENT_ID', 'client_secret': 'AAD_CLIENT_SECRET'},
        },
    },
    {
        'id': 'active_directory',
        'label': 'Active Directory (LDAP)',
        'category': 'On-Prem Directory',
        'description': 'Binds directly to domain controllers when Windows Event Forwarding is not deployed.',
        'fields': [
            {'name': 'domain_controller', 'label': 'Domain Controller (LDAPS)', 'placeholder': 'ldaps://dc01.corp.local:636', 'type': 'text', 'required': True},
            {'name': 'bind_dn', 'label': 'Bind DN', 'placeholder': 'CN=Svc,OU=Svc,DC=corp,DC=local', 'type': 'text', 'required': True},
            {'name': 'bind_password', 'label': 'Bind Password', 'type': 'password', 'secret': True, 'required': True},
            {'name': 'base_dn', 'label': 'Base DN', 'placeholder': 'DC=corp,DC=local', 'type': 'text', 'required': True},
        ],
        'webhook': None,
        'api': {
            'poll_endpoint': '/api/v1/iam/active_directory/import',
            'env': {
                'domain_controller': 'AD_DOMAIN_CONTROLLER',
                'bind_dn': 'AD_BIND_DN',
                'bind_password': 'AD_BIND_PASSWORD',
                'base_dn': 'AD_BASE_DN',
            },
        },
    },
    {
        'id': 'sailpoint_identitynow',
        'label': 'SailPoint IdentityNow',
        'category': 'IGA / SaaS',
        'description': 'Ingests certification, approval, and provisioning events for governance context.',
        'fields': [
            {'name': 'tenant_url', 'label': 'Tenant URL', 'placeholder': 'https://acme.api.identitynow.com', 'type': 'url', 'required': True},
            {'name': 'client_id', 'label': 'Client ID', 'type': 'text', 'required': True},
            {'name': 'client_secret', 'label': 'Client Secret', 'type': 'password', 'secret': True, 'required': True},
            {'name': 'event_token', 'label': 'Event Hook Token', 'type': 'password', 'secret': True},
        ],
        'webhook': {
            'endpoint': '/api/v1/iam/sailpoint/webhook',
            'headers': ['x-api-key'],
            'notes': 'IdentityNow event triggers deliver JSON payloads with optional HMAC token.',
        },
        'api': {
            'poll_endpoint': '/api/v1/iam/sailpoint/poll',
            'env': {'tenant_url': 'SAILPOINT_TENANT_URL', 'client_id': 'SAILPOINT_CLIENT_ID', 'client_secret': 'SAILPOINT_CLIENT_SECRET'},
        },
    },
    {
        'id': 'pingidentity',
        'label': 'Ping Identity / PingOne',
        'category': 'SaaS IdP',
        'description': 'Captures PingOne audit events via REST API and optional webhook bridge.',
        'fields': [
            {'name': 'environment_id', 'label': 'Environment ID', 'placeholder': 'envId', 'type': 'text', 'required': True},
            {'name': 'client_id', 'label': 'Client ID', 'type': 'text', 'required': True},
            {'name': 'client_secret', 'label': 'Client Secret', 'type': 'password', 'secret': True, 'required': True},
            {'name': 'webhook_shared_secret', 'label': 'Webhook HMAC Secret', 'type': 'password', 'secret': True},
        ],
        'webhook': {
            'endpoint': '/api/v1/iam/pingidentity/webhook',
            'headers': ['x-api-key', 'x-ping-signature'],
            'notes': 'When signing enabled, send value in x-ping-signature; platform matches against stored secret.',
        },
        'api': {
            'poll_endpoint': '/api/v1/iam/pingidentity/poll',
            'env': {
                'environment_id': 'PING_ENVIRONMENT_ID',
                'client_id': 'PING_CLIENT_ID',
                'client_secret': 'PING_CLIENT_SECRET',
            },
        },
    },
    {
        'id': 'onelogin',
        'label': 'OneLogin',
        'category': 'SaaS IdP',
        'description': 'Pulls OneLogin event API stream (client credentials) with optional webhook fallback.',
        'fields': [
            {'name': 'region', 'label': 'Region', 'placeholder': 'us', 'type': 'text'},
            {'name': 'client_id', 'label': 'Client ID', 'type': 'text', 'required': True},
            {'name': 'client_secret', 'label': 'Client Secret', 'type': 'password', 'secret': True, 'required': True},
            {'name': 'webhook_bearer', 'label': 'Webhook Bearer Token', 'type': 'password', 'secret': True},
        ],
        'webhook': {
            'endpoint': '/api/v1/iam/onelogin/webhook',
            'headers': ['authorization', 'x-api-key'],
            'notes': 'Set Authorization: Bearer <token> in OneLogin webhook configuration to gate ingestion.',
        },
        'api': {
            'poll_endpoint': '/api/v1/iam/onelogin/poll',
            'env': {'client_id': 'ONELOGIN_CLIENT_ID', 'client_secret': 'ONELOGIN_CLIENT_SECRET', 'region': 'ONELOGIN_REGION'},
        },
    },
    {
        'id': 'duo_security',
        'label': 'Duo Security',
        'category': 'MFA Provider',
        'description': 'Streams Duo admin actions and authentication reports for anomaly detection.',
        'fields': [
            {'name': 'api_hostname', 'label': 'API Hostname', 'placeholder': 'api-XXXXXXXX.duosecurity.com', 'type': 'text', 'required': True},
            {'name': 'integration_key', 'label': 'Integration Key', 'type': 'text', 'required': True},
            {'name': 'secret_key', 'label': 'Secret Key', 'type': 'password', 'secret': True, 'required': True},
        ],
        'webhook': None,
        'api': {
            'poll_endpoint': '/api/v1/iam/duo/poll',
            'env': {'api_hostname': 'DUO_API_HOSTNAME', 'integration_key': 'DUO_INTEGRATION_KEY', 'secret_key': 'DUO_SECRET_KEY'},
        },
    },
    {
        'id': 'cyberark_epm',
        'label': 'CyberArk EPM',
        'category': 'PAM',
        'description': 'Captures privileged session events and credential checkout activity.',
        'fields': [
            {'name': 'tenant_id', 'label': 'Tenant ID', 'type': 'text', 'required': True},
            {'name': 'client_id', 'label': 'Client ID', 'type': 'text', 'required': True},
            {'name': 'client_secret', 'label': 'Client Secret', 'type': 'password', 'secret': True, 'required': True},
        ],
        'webhook': None,
        'api': {
            'poll_endpoint': '/api/v1/iam/cyberark/poll',
            'env': {'tenant_id': 'CYBERARK_TENANT_ID', 'client_id': 'CYBERARK_CLIENT_ID', 'client_secret': 'CYBERARK_CLIENT_SECRET'},
        },
    },
    {
        'id': 'forgerock',
        'label': 'ForgeRock / PingAM',
        'category': 'Access Management',
        'description': 'Audit streams for ForgeRock AM or PingAM policy decisions.',
        'fields': [
            {'name': 'base_url', 'label': 'Base URL', 'placeholder': 'https://forgerock.example.com', 'type': 'url', 'required': True},
            {'name': 'realm', 'label': 'Realm', 'placeholder': '/', 'type': 'text'},
            {'name': 'access_token', 'label': 'Admin Access Token', 'type': 'password', 'secret': True, 'required': True},
        ],
        'webhook': None,
        'api': {
            'poll_endpoint': '/api/v1/iam/forgerock/poll',
            'env': {'base_url': 'FORGEROCK_BASE_URL', 'access_token': 'FORGEROCK_ACCESS_TOKEN'},
        },
    },
]

CONNECTOR_MAP = {c['id']: c for c in CONNECTOR_DEFINITIONS}


def _scrub_connector_config(defn: Dict[str, Any], stored: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    effective = deepcopy(stored) if stored else {}
    defaults_fields = defaults or {}
    for key, value in (defaults_fields or {}).items():
        effective.setdefault(key, value)
    result: Dict[str, Any] = {}
    for field in defn.get('fields', []):
        name = field['name']
        value = effective.get(name)
        if field.get('secret') or _secret_field(name):
            result[name] = {'present': _secret_present(value)}
        else:
            result[name] = value
    if '_updated_at' in stored:
        result['_updated_at'] = stored['_updated_at']
    if defaults_fields and not stored:
        result['_from_defaults'] = True
    return result


def _merge_configs(
    defn: Dict[str, Any],
    existing: Dict[str, Any],
    incoming: Dict[str, Any],
    tenant: str,
    connector_id: str,
) -> tuple[Dict[str, Any], bool]:
    merged = deepcopy(existing) if existing else {}
    changed = False
    field_map = {f['name']: f for f in defn.get('fields', [])}
    for key, value in incoming.items():
        if key not in field_map:
            continue
        field = field_map[key]
        is_secret = field.get('secret') or _secret_field(key)
        if isinstance(value, str):
            value = value.strip()
        if is_secret:
            if value:
                stored_value = _store_secret_value(tenant, connector_id, key, value)
                if merged.get(key) != stored_value:
                    merged[key] = stored_value
                    changed = True
            continue
        if value in (None, ''):
            if key in merged:
                merged.pop(key, None)
                changed = True
        else:
            if merged.get(key) != value:
                merged[key] = value
                changed = True
    if changed:
        merged['_updated_at'] = time.time()
    return merged, changed


def _build_health_entry(entry: Dict[str, Any], configured: bool, ttl: float, default_ttl: float, override_ttl: Optional[float]) -> Dict[str, Any]:
    record = entry or {}
    last_ts = record.get('last_event_ts')
    now = time.time()
    seconds_since = max(0.0, now - float(last_ts)) if last_ts else None
    missing = bool(configured and (not last_ts or (seconds_since or 0) > ttl))
    severity = None
    if missing:
        if not last_ts:
            severity = 'critical'
        elif seconds_since and seconds_since > ttl * 2:
            severity = 'critical'
        elif seconds_since and seconds_since > ttl * 1.5:
            severity = 'high'
        else:
            severity = 'warning'
    deadline = (float(last_ts) + ttl) if last_ts else None
    seconds_until_deadline = (deadline - now) if deadline else None
    return {
        'last_event_ts': last_ts,
        'seconds_since_event': seconds_since,
        'seconds_until_deadline': seconds_until_deadline,
        'heartbeat_deadline_ts': deadline,
        'total_ingested': record.get('total_ingested', 0),
        'last_event_count': record.get('last_event_count'),
        'missing_log': missing,
        'missing_severity': severity,
        'ttl_seconds': ttl,
        'default_ttl': default_ttl,
        'override_ttl': override_ttl,
        'ttl_source': 'override' if override_ttl else 'default',
    }


@router.get('/status')
async def connectors_status(
    request: Request,
    tenant_id: Optional[str] = Query(default=None),
    include_health: bool = Query(default=False),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    tenant = tenant_id or os.getenv('DEFAULT_TENANT', 'default')
    cfg = _load_config()
    tenant_cfg = cfg.get('tenants', {}).get(tenant, {})
    env_defaults = _load_env_defaults().get(tenant, {})
    ttl_overrides = _get_ttl_overrides(cfg, tenant) if include_health else {}
    health_snapshot, health_ref, runtime = _runtime_health_maps(request, tenant, include_health)
    connectors: List[Dict[str, Any]] = []
    missing_alerts: List[Dict[str, Any]] = []
    for definition in CONNECTOR_DEFINITIONS:
        stored = tenant_cfg.get(definition['id'], {})
        defaults = env_defaults.get(definition['id'], {})
        config = _scrub_connector_config(definition, stored, defaults)
        configured = bool(stored) or bool(defaults)
        default_ttl = CONNECTOR_TTL_DEFAULTS.get(definition['id'], MISSING_TTL_DEFAULT)
        override_ttl = ttl_overrides.get(definition['id']) if include_health else None
        ttl_value = override_ttl or default_ttl
        health_entry = health_snapshot.get(definition['id']) if include_health else None
        health_block = _build_health_entry(health_entry or {}, configured, ttl_value, default_ttl, override_ttl) if include_health else None
        if health_block and health_block.get('missing_log'):
            missing_alerts.append(
                {
                    'connector': definition['id'],
                    'label': definition['label'],
                    'severity': health_block.get('missing_severity') or 'warning',
                    'seconds_since_event': health_block.get('seconds_since_event'),
                    'ttl_seconds': health_block.get('ttl_seconds'),
                    'last_event_ts': health_block.get('last_event_ts'),
                    'recommendations': _recommended_actions(definition['id']),
                }
            )
        connectors.append(
            {
                'id': definition['id'],
                'label': definition['label'],
                'category': definition['category'],
                'description': definition['description'],
                'fields': definition['fields'],
                'webhook': definition.get('webhook'),
                'api': definition.get('api'),
                'config': config,
                'config_source': 'saved' if stored else ('default' if defaults else 'none'),
                'health': health_block,
            }
        )
    response: Dict[str, Any] = {'tenant': tenant, 'connectors': connectors, 'heartbeat_ttl_defaults': CONNECTOR_TTL_DEFAULTS}
    if include_health:
        response['missing_alerts'] = missing_alerts
        if missing_alerts and health_ref and dispatch_missing_log_alerts:
            try:
                triggered = await dispatch_missing_log_alerts(tenant, health_ref, missing_alerts)
                if triggered:
                    _merge_dispatch_metadata(missing_alerts, triggered)
                if triggered and runtime is not None and persist_tenant_runtime:
                    try:
                        persist_tenant_runtime(runtime, tenant)
                    except Exception:
                        pass
            except Exception:
                logger.warning('missing_log_alert_dispatch_failed tenant=%s', tenant, exc_info=True)
    return response


@router.post('/config')
async def save_connector_config(
    payload: Dict[str, Any] = Body(...),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    connector_id = payload.get('connector')
    if not connector_id or connector_id not in CONNECTOR_MAP:
        raise HTTPException(status_code=400, detail='unknown_connector')
    defn = CONNECTOR_MAP[connector_id]
    tenant = payload.get('tenant_id') or os.getenv('DEFAULT_TENANT', 'default')
    incoming = payload.get('config') or {}
    cfg = _load_config()
    tenant_cfg = cfg.setdefault('tenants', {}).setdefault(tenant, {})
    existing = tenant_cfg.get(connector_id, {})
    merged, changed = _merge_configs(defn, existing, incoming, tenant, connector_id)
    if not changed:
        return {'saved': False, 'reason': 'no_changes'}
    tenant_cfg[connector_id] = merged
    _save_config(cfg)
    env_defaults = _load_env_defaults().get(tenant, {}).get(connector_id, {})
    sanitized = _scrub_connector_config(defn, merged, env_defaults)
    return {'saved': True, 'connector': connector_id, 'tenant': tenant, 'config': sanitized}


@router.post('/heartbeat')
async def update_connector_heartbeat(
    payload: Dict[str, Any] = Body(...),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    connector_id = payload.get('connector')
    if not connector_id or connector_id not in CONNECTOR_MAP:
        raise HTTPException(status_code=400, detail='unknown_connector')
    tenant = payload.get('tenant_id') or os.getenv('DEFAULT_TENANT', 'default')
    if 'ttl_seconds' not in payload:
        raise HTTPException(status_code=400, detail='ttl_required')
    ttl_val = payload.get('ttl_seconds')
    override_value: Optional[float]
    if ttl_val in (None, ''):
        override_value = None
    else:
        try:
            override_value = float(ttl_val)
        except Exception:
            raise HTTPException(status_code=400, detail='invalid_ttl')
        if override_value < 60:
            raise HTTPException(status_code=400, detail='ttl_too_low')
    cfg = _load_config()
    overrides = _ensure_ttl_overrides(cfg, tenant)
    changed = False
    if override_value is None:
        if connector_id in overrides:
            overrides.pop(connector_id, None)
            changed = True
    else:
        if overrides.get(connector_id) != override_value:
            overrides[connector_id] = override_value
            changed = True
    if changed:
        _save_config(cfg)
    default_ttl = CONNECTOR_TTL_DEFAULTS.get(connector_id, MISSING_TTL_DEFAULT)
    effective = overrides.get(connector_id, default_ttl)
    return {
        'connector': connector_id,
        'tenant': tenant,
        'ttl_seconds': effective,
        'default_ttl': default_ttl,
        'overridden': connector_id in overrides,
    }


__all__ = ['router']
