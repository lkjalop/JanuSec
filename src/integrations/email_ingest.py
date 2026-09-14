"""Higher-level ingest flow wiring transports, token managers and the adapter."""

from typing import List, Dict, Any, Optional
from .email_transports import M365GraphTransport, GmailTransport, OAuthConfig
from .email_adapter import EmailAdapter
from .msal_mock import MSALMock
from .gmail_mock import GmailMock
from .http_exceptions import RefreshTokenRevoked, HTTPRetryError


class IngestController:
    def __init__(self, transport_type: str, oauth_cfg: OAuthConfig, provider: str = 'm365'):
        self.oauth_cfg = oauth_cfg
        self.provider = provider
        if transport_type == 'graph':
            self.transport = M365GraphTransport(oauth_cfg)
        else:
            self.transport = GmailTransport(oauth_cfg)
        self.adapter = EmailAdapter(self.transport)
        # internal mocks used by tests
        self._msal = None
        self._gmail = None

    def attach_msal(self, msal: MSALMock):
        self._msal = msal

    def attach_gmail(self, gm: GmailMock):
        self._gmail = gm

    def fetch(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        # Ensure token
        try:
            if self._msal is not None:
                tk = self._msal.acquire_token_silent(['Mail.Read'])
                if not tk:
                    # try refresh
                    rt = self._msal.get_refresh_token()
                    tk = self._msal.acquire_token_by_refresh_token(rt, ['Mail.Read'])
            if self._gmail is not None:
                at = self._gmail.access_token()
                if not at:
                    self._gmail.refresh()
        except RefreshTokenRevoked:
            raise
        except HTTPRetryError as e:
            # Surface as-is for retry logic to inspect
            raise

        return self.adapter.fetch_and_canonicalize(since=since)
