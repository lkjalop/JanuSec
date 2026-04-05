import pytest
import time
from src.integrations.msal_mock import MSALMock
from src.integrations.gmail_mock import GmailMock
from src.integrations.tenant_store import TenantStore


def test_tenant_store_save_and_load(tmp_path, monkeypatch):
    ts = TenantStore(backend='memory')
    payload = {'access_token': 'at', 'refresh_token': 'rt', 'client_id': 'cid', 'client_secret': 'sec'}
    ts.save_tokens('t1', payload)
    got = ts.load_tokens('t1')
    assert got.get('access_token') == 'at'


def test_gmail_mock_refresh(monkeypatch):
    gm = GmailMock('cid','sec')
    data = gm.refresh()
    assert 'access_token' in data


def test_msal_mock_refresh(monkeypatch):
    mm = MSALMock('cid','sec')
    res = mm.acquire_token_by_refresh_token(mm.get_refresh_token(), ['Mail.Read'])
    assert 'access_token' in res
