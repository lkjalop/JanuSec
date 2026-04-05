from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.graph.hopgraph_lite import get_graph

PII_PATTERNS: Dict[str, re.Pattern[str]] = {
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
    'email': re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
}

RESTRICTED_HEADERS = {'content-security-policy', 'strict-transport-security', 'x-frame-options'}
SENSITIVE_ENDPOINT_HINTS = {'/admin', '/finance', '/payout', '/transfer', '/account'}
RANSOMWARE_HINTS = {'/encrypt', '/encrypt-files', '/wipe', '/destroy-backup', '/delete-backup', '/snapshot/delete'}
SUPPLY_CHAIN_HINTS = {'/packages', '/package', '/registry', '/artifact', '/deploy', '/pipeline', '/ci/', '/npm', '/pypi'}
AUTOMATION_HINTS = {'/runbook', '/automation', '/script/', '/execute', '/remote-command', '/workflow/run'}
PHISHING_HINTS = {'/mail/send', '/messages/bulk', '/email/send', '/notify/bulk', '/campaign'}
AI_HINTS = {'/llm', '/ai/', '/model', '/prompt', '/completion', '/chat'}
API_SPEC_PATH = Path(os.getenv('API_SPEC_PATH', 'docs/api/openapi.json'))
INVENTORY_EXTRA_PATH = Path(os.getenv('API_INVENTORY_EXTRA_PATH', 'config/api_inventory_overrides.json'))
BUSINESS_FLOW_PATH = Path(os.getenv('API_BUSINESS_FLOWS_PATH', 'config/api_business_flows.json'))
DEFAULT_BUSINESS_FLOWS: List[Dict[str, Any]] = [
    {'name': 'payout_flow', 'path_prefix': '/api/v1/payouts', 'required_scopes': ['payments:write'], 'methods': ['POST']},
    {'name': 'transfer_flow', 'path_prefix': '/api/v1/transfers', 'required_scopes': ['transfers:approve'], 'methods': ['POST']},
]


@lru_cache(maxsize=1)
def _extra_inventory_routes() -> List[str]:
    """Static overrides for tenant-specific routes not captured in the canonical spec."""
    if not INVENTORY_EXTRA_PATH.exists():
        return []
    try:
        payload = json.loads(INVENTORY_EXTRA_PATH.read_text(encoding='utf-8'))
        if isinstance(payload, dict):
            routes = payload.get('routes') or []
        elif isinstance(payload, list):
            routes = payload
        else:
            routes = []
        normalized: List[str] = []
        for route in routes:
            if not isinstance(route, str):
                continue
            route = route.strip()
            if not route:
                continue
            normalized.append(route.rstrip('/') or '/')
        return sorted(set(normalized))
    except Exception:
        return []


@lru_cache(maxsize=1)
def _spec_metadata() -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        'routes': [],
        'route_set': set(),
        'version': 'unknown',
        'hash': None,
        'path': str(API_SPEC_PATH),
    }
    try:
        if API_SPEC_PATH.exists():
            raw = API_SPEC_PATH.read_text(encoding='utf-8')
            payload = json.loads(raw)
            paths = payload.get('paths') or {}
            normalized = []
            for route in paths.keys():
                if not route:
                    continue
                normalized.append(route.rstrip('/') or '/')
            unique_routes = sorted(set(normalized))
            extra_routes = _extra_inventory_routes()
            if extra_routes:
                merged = sorted(set(unique_routes).union(extra_routes))
            else:
                merged = unique_routes
            metadata['routes'] = merged
            metadata['route_set'] = set(merged)
            metadata['version'] = payload.get('info', {}).get('version') or 'unknown'
            metadata['hash'] = hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]
    except Exception:
        metadata['routes'] = []
        metadata['route_set'] = set()
        metadata['version'] = 'unknown'
        metadata['hash'] = None
    return metadata


@dataclass
class APIAnalysis:
    factors: List[str] = field(default_factory=list)
    confidence_delta: float = 0.0
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    pii_matches: List[Dict[str, Any]] = field(default_factory=list)
    missing_logs: List[str] = field(default_factory=list)
    hopgraph_observations: List[Dict[str, Any]] = field(default_factory=list)
    forensics: List[Dict[str, Any]] = field(default_factory=list)
    llm_context: Dict[str, Any] = field(default_factory=dict)
    correlation_hints: List[Dict[str, Any]] = field(default_factory=list)


_ALLOWLIST_SERVICES = {
    item.strip().lower()
    for item in os.getenv('API_SECURITY_SERVICE_ALLOWLIST', '').split(',')
    if item.strip()
}
_BEHAVIOR_BASELINE: Dict[str, Dict[str, float]] = defaultdict(lambda: {'avg_bytes': 0.0, 'count': 0.0})
_LATENCY_BASELINE: Dict[str, Dict[str, float]] = defaultdict(lambda: {'count': 0.0, 'mean': 0.0, 'm2': 0.0})
_ERROR_RATE_BASELINE: Dict[str, Dict[str, float]] = defaultdict(lambda: {'errors': 0.0, 'total': 0.0})
_TOKEN_USAGE_BASELINE: Dict[str, Dict[str, float]] = defaultdict(lambda: {'count': 0.0, 'mean': 0.0, 'm2': 0.0})


def is_api_event(event: Dict[str, Any]) -> bool:
    if not isinstance(event, dict):
        return False
    if event.get('event_type') == 'api_request':
        return True
    uri = event.get('uri') or event.get('path') or event.get('request_uri')
    if uri:
        return True
    if event.get('api_service') or event.get('api_gateway'):
        return True
    return False


def analyze_api_event(event: Dict[str, Any]) -> APIAnalysis:
    """Return factors + rich context for a single API event."""
    if not is_api_event(event):
        return APIAnalysis()

    result = APIAnalysis()
    uri = str(event.get('uri') or event.get('path') or '')
    method = str(event.get('method') or event.get('http_method') or (event.get('params') or {}).get('method') or '').upper()
    auth_user = (event.get('auth_user') or event.get('user') or event.get('principal') or '').strip()
    owner = _extract_requested_owner(event, uri)
    service_host = _extract_service_identifier(event)
    if service_host and service_host.lower() in _ALLOWLIST_SERVICES:
        return APIAnalysis()
    status = event.get('status') or event.get('response_status')
    resp_headers = _normalized_headers(event.get('response_headers') or event.get('headers') or {})
    response_body = _coerce_str(event.get('response_body') or event.get('body_raw') or event.get('message') or '')
    response_size = _normalize_int(event.get('response_size_bytes') or event.get('response_bytes') or (len(response_body) if response_body else None))
    auth_ctx = event.get('auth_context') or {}
    latency = _normalize_int(event.get('latency_ms') or event.get('duration_ms') or event.get('latency'))

    # Authorization-aware BOLA/IDOR
    base_context = {'uri': uri, 'user': auth_user, 'service': service_host or event.get('service')}

    if owner and auth_user and owner != auth_user and not _has_privileged_role(event):
        ctx = dict(base_context)
        ctx['owner'] = owner
        _add_alert(result, 'api:bola_resource_mismatch', 'high', f'{auth_user} accessed owner {owner}', ctx)
    elif event.get('is_owner') is False:
        _add_alert(result, 'api:idor_ownership_violation', 'medium', 'Request lacked explicit ownership flag', base_context)

    # Excessive data exposure and PII detection
    pii_hits = _detect_pii(response_body)
    if pii_hits:
        result.pii_matches.extend(pii_hits)
        ctx = dict(base_context)
        ctx['matches'] = pii_hits
        _add_alert(result, 'api:data_exposure_pii', 'high', 'PII patterns found in response body', ctx)
    if response_size and _is_response_outlier(uri, response_size):
        ctx = dict(base_context)
        ctx['bytes'] = response_size
        _add_alert(result, 'api:data_exposure_massive', 'medium', 'Response size outlier', ctx)

    # Security misconfiguration checks
    if resp_headers.get('access-control-allow-origin') == '*':
        _add_alert(result, 'api:cors_wildcard', 'medium', 'CORS allows wildcard origin', base_context)
    missing_headers = [h for h in RESTRICTED_HEADERS if h not in resp_headers]
    if missing_headers and _endpoint_suggests_browser_content(uri, response_body):
        ctx = dict(base_context)
        ctx['missing'] = missing_headers
        _add_alert(result, 'api:missing_security_headers', 'low', 'Missing hardening headers', ctx)
    tls_version = str(event.get('tls_version') or '').upper()
    if tls_version and any(tls_version.startswith(prefix) for prefix in ('SSL', 'TLS1.0', 'TLS1.1')):
        ctx = dict(base_context)
        ctx['tls_version'] = tls_version
        _add_alert(result, 'api:weak_tls_version', 'medium', f'Legacy TLS {tls_version}', ctx)

    # Broken authentication / token handling heuristics
    token_alg = str(auth_ctx.get('token_alg') or auth_ctx.get('alg') or '').lower()
    if token_alg in {'none', 'hs256'} and not bool(auth_ctx.get('signature_valid', False)):
        ctx = dict(base_context)
        ctx['token_alg'] = token_alg
        _add_alert(result, 'api:jwt_weak_algorithm', 'high', f'JWT alg={token_alg} without signature validation', ctx)
    if auth_ctx.get('session_id') and auth_ctx.get('session_reuse_count', 0) > 3:
        ctx = dict(base_context)
        ctx['reuse_count'] = auth_ctx.get('session_reuse_count')
        _add_alert(result, 'api:session_fixation_suspected', 'medium', 'Session reused across multiple clients', ctx)

    # SSRF / request tampering heuristics (reuse existing message field)
    if _looks_like_ssrf(event):
        _add_alert(result, 'api:ssrf_pattern', 'medium', 'Request body/uri references localhost or internal metadata service', base_context)

    # Business logic anomalies
    if _business_flow_anomaly(event):
        ctx = dict(base_context)
        ctx['amount'] = event.get('transaction_amount')
        _add_alert(result, 'api:business_flow_anomaly', 'high', 'Suspicious payment/business flow detected', ctx)

    # Rate limiting abuse (reuse existing heuristics)
    if _rate_limit_triggered(event):
        _add_alert(result, 'api:rate_limit_abuse', 'medium', 'HTTP 429 or depleted quota detected', base_context)

    matched_flow = _match_business_flow(uri, method)
    if matched_flow:
        ctx = dict(base_context)
        ctx['flow'] = matched_flow.get('name')
        missing_scopes = []
        required_scopes = matched_flow.get('required_scopes') or []
        scopes = set(auth_ctx.get('scopes') or [])
        for scope in required_scopes:
            if scope not in scopes:
                missing_scopes.append(scope)
        if missing_scopes:
            ctx['missing_scopes'] = missing_scopes
            _add_alert(result, 'api:business_flow_policy_gap', 'high', 'Business flow invoked without required scopes', ctx)

    normalized_path = _normalize_route(uri)
    if normalized_path and not _route_in_inventory(normalized_path):
        ctx = dict(base_context)
        ctx['uri'] = normalized_path
        spec_meta = _spec_metadata()
        ctx['spec_version'] = spec_meta.get('version')
        ctx['spec_hash'] = spec_meta.get('hash')
        _add_alert(result, 'api:inventory_route_unknown', 'low', 'Route missing from OpenAPI inventory', ctx)

    # Behavioral baselines
    if latency and _latency_anomaly(f"{service_host}:{method}", latency):
        ctx = dict(base_context)
        ctx['latency_ms'] = latency
        _add_alert(result, 'api:latency_anomaly', 'medium', 'Latency exceeded historical baseline', ctx)
    if _error_rate_anomaly(f"{service_host}:{method}", status):
        _add_alert(result, 'api:error_rate_spike', 'medium', 'Error rate spike detected for service', base_context)
    token_usage = _normalize_int(auth_ctx.get('token_usage') or event.get('token_usage'))
    if token_usage and _token_usage_anomaly(auth_user or service_host, token_usage):
        ctx = dict(base_context)
        ctx['token_usage'] = token_usage
        _add_alert(result, 'api:token_usage_anomaly', 'medium', 'Token usage deviated from baseline', ctx)

    # Scenario detection
    scenario_tags: List[str] = []
    for factor, severity, note, ctx in _detect_scenarios(event, uri, response_body, base_context):
        _add_alert(result, factor, severity, note, ctx)
        scenario_tags.append(factor)

    # Missing telemetry hints
    result.missing_logs.extend(_infer_missing_logs(event))

    # Forensics timeline entry
    result.forensics.append({
        'ts': event.get('timestamp') or int(time.time()),
        'method': method or event.get('http_method') or 'GET',
        'status': status,
        'uri': uri,
        'user': auth_user or owner,
        'service': service_host,
    })

    # HopGraph context
    if auth_user and service_host:
        obs = {
            'user': auth_user,
            'host': service_host,
            'edge_type': 'auth',
            'context_api': True,
            'uri': uri,
            'status': status,
        }
        result.hopgraph_observations.append(obs)

    # Suggested LLM context block
    result.llm_context = {
        'alerts': result.alerts,
        'pii_matches': result.pii_matches,
        'missing_logs': result.missing_logs,
        'service': service_host,
        'uri': uri,
        'method': method,
        'scenario_factors': scenario_tags,
    }
    return result


def _extract_requested_owner(event: Dict[str, Any], uri: str) -> str:
    params = event.get('params') or {}
    body = event.get('body') or {}
    for key in ('user_id', 'account_id', 'customer_id', 'owner'):
        if params.get(key):
            return str(params[key]).strip()
        if body.get(key):
            return str(body[key]).strip()
    match = re.search(r'/users/([^/]+)/', uri or '')
    if match:
        return match.group(1)
    return ''


def _extract_service_identifier(event: Dict[str, Any]) -> str:
    headers = event.get('headers') or {}
    resp_headers = event.get('response_headers') or {}
    for key in ('host', 'x-forwarded-host', 'service', 'apigateway', 'operationname'):
        val = headers.get(key) or resp_headers.get(key)
        if val:
            return str(val)
    return str(event.get('api_service') or event.get('service') or '')


def _normalized_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        if not isinstance(k, str):
            continue
        key = k.lower()
        if isinstance(v, str):
            out[key] = v
        elif v is None:
            continue
        else:
            out[key] = str(v)
    return out


def _coerce_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8', errors='ignore')
        except Exception:
            return ''
    return ''


def _has_privileged_role(event: Dict[str, Any]) -> bool:
    roles = event.get('roles') or event.get('auth_context', {}).get('roles') or []
    if isinstance(roles, str):
        roles = [roles]
    return any(str(r).lower() in {'admin', 'support', 'superuser', 'service_account'} for r in roles)


def _detect_pii(response_body: str) -> List[Dict[str, str]]:
    matches: List[Dict[str, str]] = []
    if not response_body:
        return matches
    for name, pattern in PII_PATTERNS.items():
        found = pattern.findall(response_body)
        if found:
            matches.append({'type': name, 'sample': found[0]})
    return matches


def _infer_missing_logs(event: Dict[str, Any]) -> List[str]:
    missing = []
    if not event.get('headers'):
        missing.append('api_gateway_request_headers')
    if not event.get('response_headers'):
        missing.append('api_gateway_response_headers')
    if event.get('response_body') in (None, ''):
        missing.append('api_response_body')
    if not (event.get('auth_context') or event.get('jwt') or event.get('token')):
        missing.append('api_auth_context')
    if not event.get('trace_id') and not (event.get('headers') or {}).get('x-request-id'):
        missing.append('api_trace_ids')
    return missing


def _normalize_route(uri: str) -> str:
    if not uri:
        return ''
    path = uri
    if uri.startswith(('http://', 'https://')):
        try:
            from urllib.parse import urlparse
            path = urlparse(uri).path
        except Exception:
            path = uri
    path = path.split('?', 1)[0]
    if len(path) > 1 and path.endswith('/'):
        path = path[:-1]
    return path or '/'


@lru_cache(maxsize=1)
def _route_inventory() -> set[str]:
    metadata = _spec_metadata()
    route_set = metadata.get('route_set')
    if isinstance(route_set, set):
        return set(route_set)
    return set(metadata.get('routes') or [])


def _route_in_inventory(path: str) -> bool:
    if not path:
        return False
    inventory = _route_inventory()
    if not inventory:
        return True
    return path in inventory


@lru_cache(maxsize=1)
def _business_flow_fixtures() -> List[Dict[str, Any]]:
    if BUSINESS_FLOW_PATH.exists():
        try:
            data = json.loads(BUSINESS_FLOW_PATH.read_text(encoding='utf-8'))
            if isinstance(data, list):
                return data
        except Exception:
            return DEFAULT_BUSINESS_FLOWS
    return DEFAULT_BUSINESS_FLOWS


def _match_business_flow(uri: str, method: str) -> Dict[str, Any] | None:
    path = _normalize_route(uri)
    if not path:
        return None
    for fixture in _business_flow_fixtures():
        prefix = fixture.get('path_prefix')
        if not prefix:
            continue
        if path.startswith(prefix):
            methods = [m.upper() for m in (fixture.get('methods') or [])]
            if methods and method and method not in methods:
                continue
            return fixture
    return None


def _endpoint_suggests_browser_content(uri: str, body: str) -> bool:
    if not uri:
        return False
    if any(hint in uri.lower() for hint in ('/web', '/portal', '/dashboard')):
        return True
    return '<html' in body.lower() if body else False


def _normalize_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _is_response_outlier(uri: str, response_size: int) -> bool:
    key = uri.split('?')[0]
    baseline = _BEHAVIOR_BASELINE[key]
    baseline['count'] += 1
    count = baseline['count']
    prev_avg = baseline['avg_bytes']
    if count <= 1:
        baseline['avg_bytes'] = response_size
        return False
    new_avg = ((prev_avg * (count - 1)) + response_size) / count
    baseline['avg_bytes'] = new_avg
    threshold = max(500_000, new_avg * 5)
    return response_size >= threshold and count >= 10


def _look_for_private_targets(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(token in lowered for token in ('127.0.0.1', '169.254.', '10.', '192.168.', '172.16.', 'metadata.google.internal'))


def _looks_like_ssrf(event: Dict[str, Any]) -> bool:
    uri = event.get('uri') or ''
    body = _coerce_str(event.get('body') or '')
    msg = _coerce_str(event.get('message') or '')
    return any(_look_for_private_targets(chunk) for chunk in (uri, body, msg))


def _business_flow_anomaly(event: Dict[str, Any]) -> bool:
    flow = str(event.get('business_flow') or event.get('flow') or '').lower()
    amount = _normalize_amount(event.get('transaction_amount'))
    risk = float(event.get('risk_score') or 0.0)
    if not flow and not amount:
        return False
    if amount and amount >= 100000 and risk >= 0.6:
        return True
    if flow in {'payout', 'transfer'} and event.get('geo_anomaly'):
        return True
    return False


def _normalize_amount(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _rate_limit_triggered(event: Dict[str, Any]) -> bool:
    status = int(event.get('status') or event.get('response_status') or 0)
    if status == 429:
        return True
    headers = _normalized_headers(event.get('headers') or {})
    remaining = headers.get('x-rate-limit-remaining') or headers.get('ratelimit_remaining')
    try:
        return remaining is not None and int(remaining) <= 1
    except Exception:
        return False


def _add_alert(result: APIAnalysis, factor: str, severity: str, note: str, context: Dict[str, Any] | None) -> None:
    if factor not in result.factors:
        result.factors.append(factor)
    weight = {'low': 0.01, 'medium': 0.04, 'high': 0.08}.get(severity, 0.02)
    result.confidence_delta = max(result.confidence_delta, weight)
    alert = {
        'factor': factor,
        'severity': severity,
        'note': note,
        'context': context or {},
    }
    result.alerts.append(alert)

    if factor.startswith('api:') and context and context.get('uri'):
        uri = context['uri']
        for hint in SENSITIVE_ENDPOINT_HINTS:
            if hint in uri.lower():
                alert.setdefault('tags', []).append('sensitive_endpoint')

    # HopGraph update (best-effort)
    try:
        graph = get_graph()
        user = context.get('user') if context else None
        host = context.get('service') if context else None
        if user and host:
            graph.observe({'user': user, 'host': host, 'edge_type': 'auth', 'context_api': True})
    except Exception:
        pass


def _latency_anomaly(key: str, latency_ms: int) -> bool:
    stats = _LATENCY_BASELINE[key]
    stats['count'] += 1
    count = stats['count']
    delta = latency_ms - stats['mean']
    stats['mean'] += delta / count
    stats['m2'] += delta * (latency_ms - stats['mean'])
    if count < 20:
        return False
    variance = max(1.0, stats['m2'] / max(1.0, (count - 1)))
    std = variance ** 0.5
    threshold = stats['mean'] + (3.0 * std)
    return latency_ms > threshold


def _error_rate_anomaly(key: str, status: Any) -> bool:
    stats = _ERROR_RATE_BASELINE[key]
    stats['total'] += 1
    if int(status or 0) >= 500:
        stats['errors'] += 1
    total = stats['total']
    if total < 20:
        return False
    error_rate = stats['errors'] / max(1.0, total)
    return stats['errors'] >= 5 and error_rate >= 0.4


def _token_usage_anomaly(key: str, usage: int) -> bool:
    stats = _TOKEN_USAGE_BASELINE[key]
    stats['count'] += 1
    count = stats['count']
    delta = usage - stats['mean']
    stats['mean'] += delta / count
    stats['m2'] += delta * (usage - stats['mean'])
    if count < 15:
        return False
    variance = max(1.0, stats['m2'] / max(1.0, (count - 1)))
    std = variance ** 0.5
    return usage > stats['mean'] + (2.5 * std)


def _detect_scenarios(event: Dict[str, Any], uri: str, response_body: str, base_context: Dict[str, Any]) -> List[Tuple[str, str, str, Dict[str, Any]]]:
    findings: List[Tuple[str, str, str, Dict[str, Any]]] = []
    lowered_uri = uri.lower()
    method = (event.get('method') or event.get('http_method') or '').upper()
    file_count = _normalize_int(event.get('file_count') or event.get('objects_touched'))
    template_name = str(event.get('template_name') or event.get('campaign_name') or '').lower()

    if any(h in lowered_uri for h in RANSOMWARE_HINTS) or (file_count and file_count >= 500):
        ctx = dict(base_context)
        ctx['file_count'] = file_count
        findings.append(('api:ransomware_api_activity', 'high', 'API endpoint performing mass encryption or destructive backup actions', ctx))

    if method in {'POST', 'PUT', 'PATCH'} and any(h in lowered_uri for h in SUPPLY_CHAIN_HINTS):
        ctx = dict(base_context)
        ctx['ci_stage'] = event.get('supply_chain_stage') or event.get('ci_stage')
        findings.append(('api:supply_chain_pipeline_modification', 'high', 'Potential package or pipeline tampering via API', ctx))

    if any(h in lowered_uri for h in AUTOMATION_HINTS) and method in {'POST', 'PUT'}:
        ctx = dict(base_context)
        ctx['automation'] = True
        findings.append(('api:automation_runbook_abuse', 'medium', 'Remote automation API invoked with potential living-off-the-land behavior', ctx))

    if (any(h in lowered_uri for h in PHISHING_HINTS) or 'phish' in template_name) and (event.get('bulk_recipients') or 0) >= 100:
        ctx = dict(base_context)
        ctx['recipient_count'] = event.get('bulk_recipients')
        findings.append(('api:phish_campaign_bulk_send', 'medium', 'Bulk messaging API likely sending phishing content', ctx))

    if _is_ai_event(event, lowered_uri, response_body):
        ctx = dict(base_context)
        ctx['model'] = event.get('model')
        ctx['prompt'] = (event.get('prompt') or '')[:120]
        findings.append(('api:llm_atlas_risk', 'medium', 'AI/LLM API usage exhibits prompt-injection or data exfil traits', ctx))

    return findings


def _is_ai_event(event: Dict[str, Any], uri: str, response_body: str) -> bool:
    if event.get('domain') == 'ai':
        return True
    if event.get('model') or event.get('prompt') or event.get('chain'):
        return True
    return any(h in uri for h in AI_HINTS) or 'BEGIN PROMPT INJECTION' in response_body.upper()


def refresh_api_inventory_cache() -> None:
    _route_inventory.cache_clear()
    _spec_metadata.cache_clear()


def get_inventory_snapshot(observed_routes: List[str] | None = None) -> Dict[str, Any]:
    metadata = _spec_metadata()
    inventory = sorted(set(metadata.get('routes') or []))
    observed: List[str] = []
    if observed_routes:
        for route in observed_routes:
            normalized = _normalize_route(route)
            if normalized:
                observed.append(normalized)
    unique_observed = sorted(set(observed))
    missing = sorted(route for route in unique_observed if route not in inventory)
    return {
        'spec_path': metadata.get('path'),
        'spec_version': metadata.get('version'),
        'spec_hash': metadata.get('hash'),
        'route_count': len(inventory),
        'routes': inventory,
        'observed_routes': unique_observed,
        'missing_routes': missing,
        'generated_ts': int(time.time()),
    }
