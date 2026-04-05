import pytest

from src.integrations import threat_intel_store as tis


def test_misp_pagination(monkeypatch, tmp_path):
    api_url = 'https://misp.test'
    api_key = 'testkey'

    # prepare fake attributes (page1 then page2)
    page1 = [{'value': f'192.0.2.{i}', 'type': 'ip-src'} for i in range(1, 6)]
    page2 = [{'value': 'malicious.example.com', 'type': 'domain'}]

    def fake_fetch_attributes(api_url_arg, api_key_arg, **kwargs):
        for a in page1:
            yield a
        for a in page2:
            yield a

    # Patch the fetch_attributes used by sync_misp
    monkeypatch.setattr(tis, 'fetch_attributes', fake_fetch_attributes)

    # Use a temporary STORE with its own sqlite DB
    tmp_db = str(tmp_path / 'ti.sqlite')
    tmp_store = tis.ThreatIntelStore(db_path=tmp_db)
    monkeypatch.setattr(tis, 'STORE', tmp_store)

    res = tis.sync_misp(api_url=api_url, api_key=api_key)
    assert 'added' in res and isinstance(res['added'], dict)
    assert res['added']['ips'] == 5
    assert res['added']['domains'] == 1


def test_misp_auth_failure(monkeypatch, tmp_path):
    api_url = 'https://misp.test'
    api_key = 'badkey'

    from src.integrations.misp_client import MispAuthError

    def fake_fail(api_url_arg, api_key_arg, **kwargs):
        raise MispAuthError('401')

    monkeypatch.setattr(tis, 'fetch_attributes', fake_fail)
    tmp_store = tis.ThreatIntelStore(db_path=str(tmp_path / 'ti2.sqlite'))
    monkeypatch.setattr(tis, 'STORE', tmp_store)

    res = tis.sync_misp(api_url=api_url, api_key=api_key)
    assert 'error' in res
    assert res.get('auth') is True
