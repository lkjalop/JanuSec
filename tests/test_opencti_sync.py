import pytest

from src.integrations import threat_intel_store as tis


def test_opencti_pagination(monkeypatch, tmp_path):
    api_url = 'https://opencti.test'
    api_token = 'token'

    page1 = [{'observable_value': '203.0.113.1', 'entity_type': 'IPv4-Addr'}, {'observable_value': '203.0.113.2', 'entity_type': 'IPv4-Addr'}]
    page2 = [{'observable_value': 'bad.example.com', 'entity_type': 'Domain-Name'}]

    def fake_fetch(api_url_arg, api_token_arg, **kwargs):
        for a in page1:
            yield a
        for a in page2:
            yield a

    monkeypatch.setattr('src.integrations.opencti_client.fetch_observables', fake_fetch)
    tmp_store = tis.ThreatIntelStore(db_path=str(tmp_path / 'ot.sqlite'))
    monkeypatch.setattr(tis, 'STORE', tmp_store)

    res = tis.sync_opencti(api_url=api_url, api_token=api_token)
    assert 'added' in res
    assert res['added']['ips'] == 2
    assert res['added']['domains'] == 1


def test_opencti_auth_failure(monkeypatch, tmp_path):
    api_url = 'https://opencti.test'
    api_token = 'bad'

    from src.integrations.opencti_client import OpenCTIAuthError

    def fake_fail(api_url_arg, api_token_arg, **kwargs):
        raise OpenCTIAuthError('401')

    monkeypatch.setattr('src.integrations.opencti_client.fetch_observables', fake_fail)
    tmp_store = tis.ThreatIntelStore(db_path=str(tmp_path / 'ot2.sqlite'))
    monkeypatch.setattr(tis, 'STORE', tmp_store)

    res = tis.sync_opencti(api_url=api_url, api_token=api_token)
    assert 'error' in res
    assert res.get('auth') is True
