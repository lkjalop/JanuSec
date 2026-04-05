from __future__ import annotations
from src.adapters.qualys_connector import QualysConnector
from src.adapters.tenable_connector import TenableConnector


def test_qualys_connector_token_and_list():
    q = QualysConnector('https://qualys.example')
    t = q.fetch_token()
    assert 'access_token' in t
    assert isinstance(q.get_token(), str)
    assert isinstance(q.list_vulnerabilities(), list)


def test_tenable_connector_fetch_assets():
    t = TenableConnector()
    res = t.fetch_assets()
    assert isinstance(res, list)
    assert isinstance(t.last_fetched(), int)
