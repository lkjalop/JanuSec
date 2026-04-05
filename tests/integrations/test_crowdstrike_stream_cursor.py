import os
import json
import tempfile

import pytest
import httpx

from src.integrations.crowdstrike_client import CrowdStrikeClient


class DummyResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError('err', request=None, response=None)


def test_stream_cursor_mode(tmp_path, monkeypatch):
    # Prepare fixture file for client to read
    data_page1 = {'resources': [{'event': {'timestamp': '100', 'aid': 'h1', 'UserName': 'u1'}}], 'meta': {'cursor': 'c1'}}
    data_page2 = {'resources': [{'event': {'timestamp': '200', 'aid': 'h2', 'UserName': 'u2'}}], 'meta': {'cursor': 'c2'}}

    calls = {'GET': []}

    class FakeClient:
        def __init__(self):
            pass

        def post(self, url, data=None):
            return DummyResp({'access_token': 'tok'})

        def get(self, url, headers=None):
            calls['GET'].append(url)
            if 'cursor=c1' in url:
                return DummyResp(data_page2)
            return DummyResp(data_page1)

    tmp_file = tmp_path / 'cp.json'
    cp_path = str(tmp_file)
    monkeypatch.setenv('CROWDSTRIKE_CHECKPOINT_PATH', cp_path)
    monkeypatch.setenv('CROWDSTRIKE_STREAM_ID', 'stream-xyz')

    client = CrowdStrikeClient('https://api.example', 'id', 'secret', client=FakeClient())

    items1, cursor1 = client.fetch_since(limit=10)
    assert cursor1 == 'c1'
    assert len(items1) == 1

    # subsequent call should include cursor param and return next page
    items2, cursor2 = client.fetch_since(limit=10)
    assert cursor2 == 'c2'
    assert len(items2) >= 1

    # ensure checkpoint file was written and contains stream cursor key
    with open(cp_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert 'crowdstrike:stream:stream-xyz:cursor' in data


def test_timestamp_fallback(tmp_path, monkeypatch):
    # ensure when no stream id present it uses timestamp mode and saves last ts
    data = {'resources': [
        {'event': {'timestamp': '300', 'aid': 'h3', 'UserName': 'u3'}},
        {'event': {'timestamp': '400', 'aid': 'h4', 'UserName': 'u4'}}
    ], 'next_token': None}

    class FakeClient2:
        def post(self, url, data=None):
            return DummyResp({'access_token': 'tok'})

        def get(self, url, headers=None):
            return DummyResp(data)

    tmp_file = tmp_path / 'cp2.json'
    cp_path = str(tmp_file)
    monkeypatch.setenv('CROWDSTRIKE_CHECKPOINT_PATH', cp_path)
    monkeypatch.delenv('CROWDSTRIKE_STREAM_ID', raising=False)

    client = CrowdStrikeClient('https://api.example', 'id', 'secret', client=FakeClient2())
    items, max_ts = client.fetch_since(limit=50)
    assert max_ts == '400'
    with open(cp_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert data.get('crowdstrike:last') == '400'
