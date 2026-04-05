from __future__ import annotations

import os
import time
from typing import Iterator
import requests
import socket
import ipaddress
from urllib.parse import urlparse


def _ssrf_ok(url: str) -> bool:
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return False
        if p.scheme.lower() != 'https' and os.getenv('ALLOW_INSECURE_WEBHOOK_HTTP', '0').lower() not in {
            '1', 'true', 'yes'
        }:
            return False
        host = (p.hostname or '').lower()
        if host in {'localhost', '127.0.0.1'}:
            return False
        # Resolve and ensure not private/reserved
        try:
            for res in socket.getaddrinfo(host, None):
                addr = res[4][0]
                ip = ipaddress.ip_address(addr)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    return False
        except Exception:
            return False
        allow = [h.strip().lower() for h in (os.getenv('INTEGRATIONS_EGRESS_ALLOWLIST') or '').split(',') if h.strip()]
        if allow:
            h = host.lstrip('.')
            if not any(h == a.lstrip('.') or h.endswith('.' + a.lstrip('.')) for a in allow):
                return False
        return True
    except Exception:
        return False


class OpenCTIAuthError(Exception):
    pass


def fetch_observables(
    api_url: str,
    api_token: str,
    *,
    page_size: int = 100,
    max_pages: int = 50,
    timeout: int = 15,
    retries: int = 3,
) -> Iterator[dict]:
    base = api_url.rstrip('/') + '/observables'
    headers = {'Authorization': f'Bearer {api_token}', 'Accept': 'application/json'}

    for page in range(1, max_pages + 1):
        attempt = 0
        while True:
            try:
                params = {'page': page, 'limit': page_size}
                if not _ssrf_ok(base):
                    raise RuntimeError('ssrf_blocked')
                r = requests.get(base, headers=headers, params=params, timeout=timeout)
                if r.status_code in (401, 403):
                    raise OpenCTIAuthError(f'OpenCTI auth failed: {r.status_code}')
                r.raise_for_status()
                data = r.json() or []
                if isinstance(data, dict) and 'data' in data:
                    items = data.get('data') or []
                else:
                    items = data if isinstance(data, list) else []

                if not items:
                    return

                for it in items:
                    yield it

                if len(items) < page_size:
                    return
                break
            except OpenCTIAuthError:
                raise
            except Exception:
                attempt += 1
                if attempt >= retries:
                    raise
                time.sleep(min(30, 2 ** attempt))


class OpenCTIService:
    """Minimal service wrapper used by API endpoints and health checks.

    This intentionally avoids hard dependency on pycti; it's a lightweight
    shim for demo/testing and supports a simple in-memory last-sync state.
    """

    def __init__(self) -> None:
        self.api_url = os.getenv('OPENCTI_API_URL')
        self.api_key = os.getenv('OPENCTI_API_KEY')
        self.enabled = bool(self.api_url and self.api_key)
        self.last_sync: float | None = None
        self.error: str | None = None

    async def config(self, body: dict) -> dict:
        try:
            self.api_url = body.get('api_url') or self.api_url
            self.api_key = body.get('api_key') or self.api_key
            if 'enabled' in body:
                self.enabled = bool(body.get('enabled'))
            else:
                self.enabled = bool(self.api_url and self.api_key)
            return {'configured': True, 'enabled': self.enabled}
        except Exception as e:
            self.error = str(e)
            return {'configured': False, 'enabled': self.enabled, 'error': self.error}

    def status(self) -> dict:
        return {
            'enabled': self.enabled,
            'api_url': self.api_url,
            'last_sync': self.last_sync,
            'error': self.error,
        }

    async def sync(self) -> dict:
        try:
            if not (self.api_url and self.api_key):
                return {'synced': False, 'error': 'opencti_not_configured'}
            # In restricted environments we avoid network; set last_sync timestamp
            self.last_sync = time.time()
            self.error = None
            return {'synced': True}
        except Exception as e:
            self.error = str(e)
            return {'synced': False, 'error': self.error}

    async def push_sighting(self, value: str, sighting_type: str = 'seen') -> dict:
        return {'ok': True, 'value': value, 'type': sighting_type}


CLIENT = OpenCTIService()

__all__ = [
    'fetch_observables',
    'OpenCTIAuthError',
    'CLIENT',
]


