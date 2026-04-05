from __future__ import annotations

import os
import time
from typing import Any, Dict, Iterator, Optional


class MISPClient:
    def __init__(self):
        self.enabled = os.getenv('MISP_ENABLED', '0').lower() in {'1', 'true', 'yes'}
        self.api_url = os.getenv('MISP_URL', '')
        self.api_key = os.getenv('MISP_API_KEY', '')
        self.cache: Dict[str, Any] = {'attributes': [], 'ts': 0}

    def refresh_24h(self) -> int:
        """Fetch last 24h attributes via pymisp if available, cache in memory.
        Returns count of attributes ingested.
        """
        if not self.enabled:
            return 0
        try:
            from pymisp import PyMISP  # type: ignore
        except Exception:
            return 0
        try:
            misp = PyMISP(self.api_url, self.api_key, False)
            attrs = misp.search(controller='attributes', last='24h') or []
            self.cache = {'attributes': attrs, 'ts': time.time()}
            path = os.getenv('MISP_CACHE_PATH', os.path.join('data', 'ti', 'misp_attributes.json'))
            try:
                import json
                import pathlib

                pathlib.Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
                with open(path, 'w', encoding='utf-8') as fh:
                    json.dump(attrs, fh)
            except Exception:
                pass
            return len(attrs)
        except Exception:
            return 0


CLIENT = MISPClient()


class MispAuthError(Exception):
    """Raised when the MISP API returns an authentication error (401/403)."""


def _ssrf_ok(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        import socket
        import ipaddress

        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return False
        if p.scheme.lower() != 'https' and os.getenv('ALLOW_INSECURE_WEBHOOK_HTTP', '0').lower() not in {'1', 'true', 'yes'}:
            return False
        host = p.hostname or ''
        if host.lower() in {'localhost', '127.0.0.1'}:
            return False
        for _, _, _, _, addr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(addr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
        allow = [h.strip() for h in (os.getenv('INTEGRATIONS_EGRESS_ALLOWLIST', '') or '').split(',') if h.strip()]
        if allow:
            h = host.lower().lstrip('.')
            if not any(h == a.lstrip('.').lower() or h.endswith('.' + a.lstrip('.').lower()) for a in allow):
                return False
        return True
    except Exception:
        return False


def fetch_attributes(api_url: str, api_key: str, *, page_size: int = 100, max_pages: int = 50,
                     timeout: int = 15, retries: int = 3) -> Iterator[dict]:
    """Yield attribute dicts from MISP attributes/index with simple pagination.

    Args:
        api_url: Base URL for MISP (e.g. https://misp.example.com)
        api_key: API key for Authorization header
        page_size: number of items to request per page (passed as 'limit')
        max_pages: maximum pages to request before stopping
        timeout: requests timeout per call
        retries: number of retry attempts on transient failures

    Yields:
        attribute dictionaries as returned by the MISP API.
    """
    import requests
    import time as _time

    base = api_url.rstrip('/') + '/attributes/index'
    headers = {'Authorization': api_key, 'Accept': 'application/json'}

    for page in range(1, max_pages + 1):
        attempt = 0
        while True:
            try:
                params = {'page': page, 'limit': page_size}
                if not _ssrf_ok(base):
                    raise RuntimeError('ssrf_blocked')
                r = requests.get(base, headers=headers, params=params, timeout=timeout)
                if r.status_code in (401, 403):
                    raise MispAuthError(f'MISP auth failed: {r.status_code}')
                r.raise_for_status()
                data = r.json() or []
                if isinstance(data, dict) and 'Attribute' in data:
                    attrs = data.get('Attribute') or []
                elif isinstance(data, dict) and 'response' in data:
                    attrs = data.get('response') or []
                else:
                    attrs = data if isinstance(data, list) else []

                if not attrs:
                    return

                for a in attrs:
                    yield a

                if len(attrs) < page_size:
                    return

                break
            except MispAuthError:
                raise
            except Exception:
                attempt += 1
                if attempt >= retries:
                    raise
                _time.sleep(min(30, 2 ** attempt))


__all__ = ['fetch_attributes', 'MispAuthError', 'CLIENT']

