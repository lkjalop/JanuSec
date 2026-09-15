from __future__ import annotations
import os, time
from typing import List, Dict, Any
from .base import EventCollector

import logging
from src.integrations.tenant_store import TenantStore
from src.integrations.gmail_connector import GmailConnector
from src.integrations.token_helper import request_with_auto_refresh
try:
    from google.oauth2 import service_account
except Exception:
    class _ServiceAccountStub:
        class Credentials:  # type: ignore
            @staticmethod
            def from_service_account_file(*args, **kwargs):
                raise RuntimeError('google.oauth2 not available')

    service_account = _ServiceAccountStub()

try:
    from googleapiclient.discovery import build
except Exception:
    def build(*args, **kwargs):
        raise RuntimeError('googleapiclient not available')

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except Exception:
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator

    # Ensure the no-op retry decorator exposes the original signature when frameworks introspect it
    try:
        from src.security.signature_helpers import preserve_signature
        try:
            preserve_signature(retry, retry)
        except Exception:
            import inspect as _inspect
            try:
                retry.__signature__ = _inspect.signature(retry)
            except Exception:
                pass
    except Exception:
        try:
            import inspect as _inspect
            retry.__signature__ = _inspect.signature(retry)
        except Exception:
            pass

    def stop_after_attempt(n):
        return None

    def wait_exponential(**kwargs):
        return None

    def retry_if_exception_type(exc):
        return (lambda e: True)

import datetime


class GmailEmailCollector(EventCollector):
    source = "gmail"

    def __init__(self):
        # Prefer delegated OAuth tokens stored in TenantStore. Admin service account path is fallback.
        self._service_account = os.getenv("GMAIL_SERVICE_ACCOUNT_JSON")
        self._service = None
        if self._service_account and os.path.exists(self._service_account) and service_account is not None and build is not None:
            try:
                scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
                creds = service_account.Credentials.from_service_account_file(self._service_account, scopes=scopes)
                self._service = build('gmail', 'v1', credentials=creds)
            except Exception as e:
                logging.error(f"Failed to initialize Gmail API client: {e}")
                self._service = None

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        # If service account client is configured, use it (admin fetch). Otherwise use tenant delegated tokens.
        if self._service:
            @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
                   retry=retry_if_exception_type(Exception))
            def get_gmail_messages():
                user_id = os.getenv('GMAIL_USER_ID', 'me')
                query = f"after:{int(since_ts)}"
                try:
                    response = self._service.users().messages().list(userId=user_id, q=query, maxResults=100).execute()
                    msg_ids = [msg['id'] for msg in response.get('messages', [])]
                    for msg_id in msg_ids:
                        msg = self._service.users().messages().get(userId=user_id, id=msg_id, format='metadata').execute()
                        events.append(msg)
                except Exception as e:
                    logging.error(f"Gmail API error: {e}")
                return events

            try:
                return get_gmail_messages()
            except Exception as e:
                logging.error(f"Gmail fetch_events error: {e}")
                return []

        # Otherwise, iterate tenants with tokens (demo: single default tenant)
        tenant = os.getenv('TENANT_ID') or os.getenv('DEFAULT_TENANT') or 'default'
        store = TenantStore()
        tokens = store.load_tokens(tenant)
        if not tokens or not tokens.get('access_token'):
            return []

        connector = GmailConnector('', '', '')
        # Use request_with_auto_refresh at the orchestration layer when calling connector methods.
        try:
            # load last history id cursor
            last_history = store.load_cursor(tenant, 'gmail', 'historyId')
            access = tokens.get('access_token')
            if last_history:
                resp = connector.list_history(access, last_history)
                # if messages found, update cursor
                if isinstance(resp, dict) and resp.get('historyId'):
                    store.save_cursor(tenant, 'gmail', 'historyId', str(resp.get('historyId')))
                # transform history -> messages if present
                for item in (resp.get('messages') or []):
                    events.append(item)
        except Exception as e:
            logging.error('gmail tenant fetch failed: %s', e)
        return events

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry=retry_if_exception_type(Exception))
        def get_gmail_messages():
            # For demo, fetch messages for a test user
            user_id = os.getenv('GMAIL_USER_ID', 'me')
            query = f"after:{int(since_ts)}"
            try:
                response = self._service.users().messages().list(userId=user_id, q=query, maxResults=100).execute()
                msg_ids = [msg['id'] for msg in response.get('messages', [])]
                for msg_id in msg_ids:
                    msg = self._service.users().messages().get(userId=user_id, id=msg_id, format='metadata').execute()
                    events.append(msg)
            except Exception as e:
                logging.error(f"Gmail API error: {e}")
            return events

        try:
            return get_gmail_messages()
        except Exception as e:
            logging.error(f"Gmail fetch_events error: {e}")
            return []


__all__ = ["GmailEmailCollector"]
