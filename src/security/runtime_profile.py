"""Fail-closed configuration boundaries for staging and production."""
from __future__ import annotations

import json
import os
import re

TRUE = {'1', 'true', 'yes', 'on'}
LIVE = {'prod', 'production', 'staging'}
DEV = {'dev', 'development', 'local', 'test', 'demo'}
UNSAFE_FLAGS = (
    'PLATFORM_LITE_INIT', 'FAST_TEST_MODE', 'TEST_HELPERS_ENABLED',
    'PERMISSIVE_TEST_AUTH', 'ADMIN_PERMISSIVE_TEST', 'ALLOW_TENANT_OVERRIDE',
    'ALLOW_DEFAULT_TENANT', 'ALLOW_INSECURE_FALLBACK', 'JANUSEC_DEV_MODE',
    'ALLOW_UNSIGNED_FIXTURE_LABELS',
)


def is_live_environment() -> bool:
    return any(os.getenv(name, '').strip().lower() in LIVE
               for name in ('ENV', 'APP_ENV', 'JANUSEC_RUNTIME_PROFILE'))


def validate_live_auth_configuration() -> None:
    """Reject unsafe settings without echoing any credential values."""
    if not is_live_environment():
        return
    if any(os.getenv(name, '').strip().lower() in DEV
           for name in ('ENV', 'APP_ENV', 'JANUSEC_RUNTIME_PROFILE')):
        raise RuntimeError('live_configuration: conflicting environment profiles')
    unsafe = [name for name in UNSAFE_FLAGS if os.getenv(name, '').lower() in TRUE]
    if unsafe:
        raise RuntimeError('live_configuration: unsafe flags: ' + ', '.join(unsafe))
    if os.getenv('STRICT_API_KEY_ENFORCEMENT', '1').lower() not in TRUE:
        raise RuntimeError('live_configuration: API authentication cannot be disabled')
    raw = os.getenv('API_KEYS_JSON', '')
    try:
        entries = json.loads(raw) if raw else []
        if not isinstance(entries, list):
            raise ValueError()
        keys = set()
        for entry in entries:
            key = entry['key']
            tenant = entry.get('tenant_id') or entry.get('tenant')
            scopes = entry.get('scopes')
            if (not isinstance(key, str) or len(key) < 32 or key in keys
                    or len(set(key)) < 12
                    or not isinstance(tenant, str)
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', tenant)
                    or tenant.endswith('.')
                    or not isinstance(scopes, list) or not scopes
                    or any(not isinstance(scope, str) or not scope for scope in scopes)):
                raise ValueError()
            keys.add(key)
    except (ValueError, TypeError, KeyError):
        raise RuntimeError('live_configuration: API keys need unique strong values, tenant bindings and scopes') from None
    jwt_secret = os.getenv('JWT_SECRET', '')
    if jwt_secret and (len(jwt_secret) < 32 or len(set(jwt_secret)) < 12
                       or not os.getenv('JWT_ISSUER') or not os.getenv('JWT_AUDIENCE')):
        raise RuntimeError('live_configuration: JWT requires a strong secret, issuer and audience')
    if not entries and not jwt_secret:
        raise RuntimeError('live_configuration: no supported authentication configured')
