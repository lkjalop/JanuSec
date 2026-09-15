"""Gmail connector skeleton for mailbox ingestion.

Provides:
- Authorization URL generation (OAuth2 installed/web app flows)
- Token exchange and refresh
- History-based polling helper
- MIME parsing helper for message parts and attachments metadata

Minimal scaffold built on `requests` and the Python `email` package.
"""
from __future__ import annotations

import email
import json
import logging
from base64 import urlsafe_b64decode
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_MESSAGES_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
GMAIL_HISTORY_URL = "https://gmail.googleapis.com/gmail/v1/users/me/history"


class GmailConnector:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scope: str = "https://www.googleapis.com/auth/gmail.readonly"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "access_type": "offline",
            "prompt": "consent",
        }
        if state:
            params["state"] = state
        qs = requests.models.RequestEncodingMixin._encode_params(params)
        return f"{OAUTH_AUTHORIZE_URL}?{qs}"

    def exchange_code(self, code: str) -> Dict:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        r = requests.post(OAUTH_TOKEN_URL, data=data, timeout=30)
        r.raise_for_status()
        return r.json()

    def refresh_token(self, refresh_token: str) -> Dict:
        data = {
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
        }
        r = requests.post(OAUTH_TOKEN_URL, data=data, timeout=30)
        r.raise_for_status()
        return r.json()

    def list_messages(self, access_token: str, q: Optional[str] = None, page_token: Optional[str] = None, max_results: int = 100) -> Dict:
        headers = {"Authorization": f"Bearer {access_token}" if access_token else ''}
        params = {"maxResults": max_results}
        if q:
            params["q"] = q
        if page_token:
            params["pageToken"] = page_token
        r = requests.get(f"{GMAIL_MESSAGES_URL}", headers=headers, params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def get_message(self, access_token: str, message_id: str) -> Dict:
        headers = {"Authorization": f"Bearer {access_token}" if access_token else ''}
        r = requests.get(f"{GMAIL_MESSAGES_URL}/{message_id}", headers=headers, params={"format": "raw"}, timeout=30)
        r.raise_for_status()
        return r.json()

    def list_history(self, access_token: str, start_history_id: str, page_token: Optional[str] = None, max_results: int = 100) -> Dict:
        headers = {"Authorization": f"Bearer {access_token}" if access_token else ''}
        params = {
            "startHistoryId": start_history_id,
            "historyTypes": "messageAdded",
            "maxResults": max_results,
        }
        if page_token:
            params["pageToken"] = page_token
        r = requests.get(GMAIL_HISTORY_URL, headers=headers, params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def parse_raw_message(self, raw_message_payload: Dict) -> Dict:
        # raw is base64url encoded string
        raw = raw_message_payload.get("raw")
        decoded = urlsafe_b64decode(raw + "=")
        msg = email.message_from_bytes(decoded)
        parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get("Content-Disposition")
            if disp and "attachment" in disp:
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                parts.append({"type": "attachment", "filename": filename, "size": len(payload) if payload else 0})
            elif ctype == "text/plain" or ctype == "text/html":
                body = part.get_payload(decode=True)
                parts.append({"type": "body", "content_type": ctype, "size": len(body) if body else 0})
        headers = dict(msg.items())
        return {"headers": headers, "parts": parts, "historyId": raw_message_payload.get("historyId")}


if __name__ == "__main__":
    print("GmailConnector module. Use from your app; see README for usage.")
