import pytest
import time
from src.integrations.msal_mock import MSALMock
from src.integrations.gmail_mock import GmailMock
from src.integrations.email_ingest import IngestController
from src.integrations.email_transports import OAuthConfig
from src.integrations.http_exceptions import RefreshTokenRevoked, HTTPRetryError


def test_msal_refresh_and_fetch(monkeypatch):
    cfg = OAuthConfig(client_id='cid', client_secret='sec')
    ms = MSALMock('cid', 'sec')
    ic = IngestController('graph', cfg)
    ic.attach_msal(ms)

    # initial silent returns None so refresh is used
    res = ic.fetch()
    assert isinstance(res, list)


def test_msal_revoked_refresh_raises():
    cfg = OAuthConfig(client_id='cid', client_secret='sec')
    ms = MSALMock('cid', 'sec')
    # Simulate revoked refresh token
    ms._refresh_token = 'revoked'
    ic = IngestController('graph', cfg)
    ic.attach_msal(ms)
    with pytest.raises(RefreshTokenRevoked):
        ic.fetch()


def test_msal_refresh_401_surfaces_http_retry_error():
    cfg = OAuthConfig(client_id='cid', client_secret='sec')
    ms = MSALMock('cid', 'sec')
    ms._refresh_token = 'bad-401'
    ic = IngestController('graph', cfg)
    ic.attach_msal(ms)
    with pytest.raises(HTTPRetryError) as ei:
        ic.fetch()
    assert ei.value.status_code == 401


def test_gmail_refresh_and_revoked():
    cfg = OAuthConfig(client_id='gid', client_secret='gsec')
    gm = GmailMock('gid', 'gsec')
    ic = IngestController('gmail', cfg, provider='gmail')
    ic.attach_gmail(gm)

    # success path
    res = ic.fetch()
    assert isinstance(res, list)

    # revoke and ensure exception
    gm.force_revoke_refresh()
    with pytest.raises(RefreshTokenRevoked):
        ic.fetch()
