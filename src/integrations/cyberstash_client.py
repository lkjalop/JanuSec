"""CyberStash API client (polling + write-back).

Provides minimal methods for fetch_alerts, get_alert, update_alert and annotate_alert.
Uses API key or mTLS if configured. Retries on transient errors.
"""
from __future__ import annotations

import os
import time
import json
from typing import Any, List, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception:
    requests = None  # type: ignore

BASE = os.getenv('CYBERSTASH_API_URL', '').rstrip('/')
API_KEY = os.getenv('CYBERSTASH_API_KEY')
CLIENT_CERT = os.getenv('CYBERSTASH_CLIENT_CERT')  # file path or cert tuple


class CyberStashClient:
    def __init__(self):
        self.base = BASE
        self.api_key = API_KEY
        self.cert = CLIENT_CERT or None
        self.session = None
        if requests is not None:
            self.session = requests.Session()
            retries = Retry(total=3, backoff_factor=0.8, status_forcelist=(500,502,503,504))
            self.session.mount('https://', HTTPAdapter(max_retries=retries))
            self.session.mount('http://', HTTPAdapter(max_retries=retries))
            if self.api_key:
                self.session.headers.update({'Authorization': f'Bearer {self.api_key}', 'Accept': 'application/json'})

    def _url(self, path: str) -> str:
        if not self.base:
            raise RuntimeError('CYBERSTASH_API_URL not configured')
        return f"{self.base}/{path.lstrip('/')}"

    def fetch_alerts(self, since: Optional[str] = None) -> List[dict[str, Any]]:
        if self.session is None:
            return []
        params = {}
        if since:
            params['since'] = since
        try:
            r = self.session.get(self._url('/alerts'), params=params, timeout=10, cert=self.cert)
            r.raise_for_status()
            j = r.json()
            return j.get('alerts') or j.get('data') or []
        except Exception:
            return []

    def get_alert(self, alert_id: str) -> Optional[dict[str, Any]]:
        if self.session is None:
            return None
        try:
            r = self.session.get(self._url(f'/alerts/{alert_id}'), timeout=8, cert=self.cert)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def update_alert(self, alert_id: str, fields: dict[str, Any]) -> bool:
        """Patch alert fields (tags, severity, notes)."""
        if self.session is None:
            return False
        try:
            r = self.session.patch(self._url(f'/alerts/{alert_id}'), json=fields, timeout=8, cert=self.cert)
            r.raise_for_status()
            return True
        except Exception:
            return False

    def annotate_alert(self, alert_id: str, note: str) -> bool:
        try:
            return self.update_alert(alert_id, {'note': note})
        except Exception:
            return False


CLIENT = CyberStashClient()

__all__ = ['CLIENT', 'CyberStashClient']
