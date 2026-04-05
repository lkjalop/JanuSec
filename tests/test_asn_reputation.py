import os
import json
import tempfile
from unittest import mock

import pytest

from src.core.enrichment import asn_reputation


def test_load_initial_files():
    # data files included in repo should be loaded on import
    tor = asn_reputation.get_tor_exits()
    asns = asn_reputation.get_bad_asns()
    assert isinstance(tor, set)
    assert isinstance(asns, set)


def test_refresh_once_writes(tmp_path, monkeypatch):
    tor_content = '4.4.4.4\n#comment\n5.5.5.5\n'
    asn_content = '999\n1000\n'

    class DummyResp:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status

    def fake_get(url, timeout=10):
        if 'tor' in url:
            return DummyResp(tor_content)
        if 'asn' in url:
            return DummyResp(asn_content)
        return DummyResp('', status=404)

    monkeypatch.setenv('TOR_EXIT_LIST_URL', 'https://example.local/tor')
    monkeypatch.setenv('BAD_ASNS_URL', 'https://example.local/asn')
    monkeypatch.setenv('TOR_EXIT_NODES_PATH', str(tmp_path / 'tor.txt'))
    monkeypatch.setenv('BAD_ASNS_PATH', str(tmp_path / 'asn.txt'))

    with mock.patch('src.core.enrichment.asn_reputation.requests.get', side_effect=fake_get):
        res = asn_reputation.refresh_once()
    assert res.get('tor') is True
    assert res.get('asn') is True
    # files created
    assert os.path.exists(os.getenv('TOR_EXIT_NODES_PATH'))
    assert os.path.exists(os.getenv('BAD_ASNS_PATH'))

    # verify loaded sets
    t = asn_reputation.get_tor_exits()
    a = asn_reputation.get_bad_asns()
    assert '4.4.4.4' in t
    assert 999 in a
