from __future__ import annotations
import os, time
from typing import List, Dict, Any
from .base import EventCollector

import logging
try:
    import msal
except Exception:
    # Provide a module-like shim so unit tests can patch attributes like
    # `msal.ConfidentialClientApplication` even when the real `msal` package
    # is not installed in the environment.
    try:
        import types as _types
        _msal_mod = _types.ModuleType('msal')
        # Expose a placeholder attribute so `patch('...msal.ConfidentialClientApplication')`
        # can safely replace it during tests.
        setattr(_msal_mod, 'ConfidentialClientApplication', None)
        msal = _msal_mod
    except Exception:
        msal = None

try:
    import requests
except Exception:
    requests = None

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except Exception:
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        # Attempt to preserve signature on fallback decorator factory
        try:
            from src.security.signature_helpers import preserve_signature
            try:
                preserve_signature(decorator, decorator)
            except Exception:
                import inspect as _inspect
                try:
                    decorator.__signature__ = _inspect.signature(decorator)
                except Exception:
                    pass
        except Exception:
            try:
                import inspect as _inspect
                decorator.__signature__ = _inspect.signature(decorator)
            except Exception:
                pass
        return decorator

    def stop_after_attempt(n):
        return None

    def wait_exponential(**kwargs):
        return None

    def retry_if_exception_type(exc):
        return (lambda e: True)

import datetime


class AzureADCollector(EventCollector):
    source = "aad"

    def __init__(self):
        self._tenant = os.getenv("AAD_TENANT_ID")
        self._client = os.getenv("AAD_CLIENT_ID")
        self._secret = os.getenv("AAD_CLIENT_SECRET")
        self._token = None
        self._session = None
        if self._tenant and self._client and self._secret and msal is not None and requests is not None:
            try:
                self._app = msal.ConfidentialClientApplication(
                    self._client,
                    authority=f"https://login.microsoftonline.com/{self._tenant}",
                    client_credential=self._secret
                )
                self._token = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
                self._session = requests.Session()
            except Exception as e:
                logging.error(f"Failed to initialize MSAL client: {e}")
                self._app = None
                self._session = None

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        if not (self._app and self._session):
            return []

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry=retry_if_exception_type(Exception))
        def get_aad_logs():
            # Use MS Graph API: /auditLogs/directoryAudits
            url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
            token = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            if "access_token" not in token:
                logging.error(f"AAD token error: {token}")
                return []
            headers = {"Authorization": f"Bearer {token['access_token']}", "Accept": "application/json"}
            params = {
                "$filter": f"activityDateTime ge {datetime.datetime.utcfromtimestamp(since_ts).isoformat()}Z",
                "$top": 100
            }
            next_url = url
            while next_url:
                resp = self._session.get(next_url, headers=headers, params=params if next_url == url else None, timeout=15)
                if resp.status_code != 200:
                    logging.error(f"AAD logs fetch failed: {resp.status_code} {resp.text}")
                    break
                data = resp.json()
                for event in data.get('value', []):
                    events.append(event)
                next_url = data.get('@odata.nextLink')
            return events

        try:
            return get_aad_logs()
        except Exception as e:
            logging.error(f"AAD fetch_events error: {e}")
            return []


__all__ = ["AzureADCollector"]