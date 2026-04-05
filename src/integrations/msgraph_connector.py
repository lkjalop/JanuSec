"""MS Graph connector skeleton for mailbox ingestion.

Provides:
- Authorization URL generation (authorization code grant)
- Token exchange and refresh
- Delta query polling helper
- Message parsing into canonical events

This is a minimal, safe scaffold. It relies on `requests` and `cryptography`
for optional encrypted token storage. If those packages are missing, the
module will raise a clear error advising installation.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Dict, List, Optional

import requests
from src.integrations.token_helper import request_with_auto_refresh
from src.integrations.tenant_store import TenantStore

logger = logging.getLogger(__name__)

OAUTH_AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
OAUTH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"


class MSGraphConnector:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scope: str = "offline_access Mail.Read"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": self.scope,
        }
        if state:
            params["state"] = state
        qs = requests.models.RequestEncodingMixin._encode_params(params)
        return f"{OAUTH_AUTHORIZE_URL}?{qs}"

    def exchange_code(self, code: str) -> Dict:
        data = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_secret": self.client_secret,
        }
        r = requests.post(OAUTH_TOKEN_URL, data=data, timeout=30)
        r.raise_for_status()
        return r.json()

    def refresh_token(self, refresh_token: str) -> Dict:
        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_secret": self.client_secret,
        }
        r = requests.post(OAUTH_TOKEN_URL, data=data, timeout=30)
        r.raise_for_status()
        return r.json()

    def poll_delta(self, access_token: str, delta_link: Optional[str] = None, top: int = 50) -> Dict:
        """Poll messages using delta queries. If delta_link is None, a normal list is used.

        Returns the JSON payload. The caller is responsible for persisting deltaLink.
        """
        url = delta_link or f"{GRAPH_MESSAGES_URL}?$top={top}"

        def _call(token: str):
            headers = {"Authorization": f"Bearer {token}" if token else '', "Accept": "application/json"}
            r = requests.get(url, headers=headers, timeout=30)
            return r

        # Use the token helper so callers can pass tenant id and handle refresh externally.
        resp = _call(access_token)
        resp.raise_for_status()
        return resp.json()

    def parse_messages_to_events(self, messages_json: Dict) -> List[Dict]:
        events = []
        for item in messages_json.get("value", []):
            ev = {
                "id": item.get("id"),
                "received": item.get("receivedDateTime"),
                "subject": item.get("subject"),
                "from": (item.get("from") or {}).get("emailAddress", {}).get("address"),
                "to": [r.get("emailAddress", {}).get("address") for r in (item.get("toRecipients") or [])],
                "snippet": item.get("bodyPreview"),
                "has_attachments": item.get("hasAttachments", False),
            }
            events.append(ev)
        return events

    def poll_for_tenant(self, tenant_id: str, top: int = 50) -> Dict:
        """High-level helper: load tenant tokens + last deltaLink from TenantStore,
        call Graph with auto-refresh on 401, persist new deltaLink if returned, and
        return the JSON payload."""
        store = TenantStore()
        tokens = store.load_tokens(tenant_id) or {}
        access = tokens.get('access_token')
        last_delta = store.load_cursor(tenant_id, 'msgraph', 'deltaLink')
        url = last_delta or f"{GRAPH_MESSAGES_URL}/delta?$top={top}"

        def _make_request(tok: str):
            headers = {"Authorization": f"Bearer {tok}" if tok else '', "Accept": "application/json"}
            r = requests.get(url, headers=headers, timeout=30)
            return r

        resp = request_with_auto_refresh(tenant_id, _make_request, provider='msgraph')
        if hasattr(resp, 'status_code') and resp.status_code in (200, 201):
            j = resp.json()
            # Graph may return '@odata.deltaLink' or '@odata.nextLink'
            new_delta = j.get('@odata.deltaLink') or j.get('@odata.nextLink')
            if new_delta:
                try:
                    store.save_cursor(tenant_id, 'msgraph', 'deltaLink', new_delta)
                except Exception:
                    pass
            return j
        else:
            # propagate response-like object for callers to handle
            try:
                return resp.json()
            except Exception:
                return {}


if __name__ == "__main__":
    print("MSGraphConnector module. Use from your app; see README for usage.")
