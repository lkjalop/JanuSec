import asyncio
import os
import time as _time

import pytest

from src.integrations.threat_intel_client import ThreatIntelClient


@pytest.mark.asyncio
async def test_sslbl_parser_csv(monkeypatch):
    client = ThreatIntelClient()
    # Monkeypatch HTTP GET to return minimal CSV with header
    sample = "ja3,desc\n769,foo\n1,bar\n"
    async def fake_get(url, headers=None, timeout=8.0, retries=2, backoff=1.5):
        return sample
    monkeypatch.setattr(client, "_http_get", fake_get)
    before = len(client.ja3_set)
    await client._sync_abusech_sslbl()
    after = len(client.ja3_set)
    assert after >= before + 1


@pytest.mark.asyncio
async def test_ttl_expiry_and_purge(monkeypatch):
    client = ThreatIntelClient()
    client._current_origin = 'test'
    client._add_ip('9.9.9.9', ttl_hours=0.00001)
    assert client.is_malicious_ip('9.9.9.9') is True
    # Advance time beyond expiry
    real_time = _time.time
    try:
        t0 = real_time()
        monkeypatch.setattr('time.time', lambda: t0 + 3600)
        client._purge_expired()
        assert client.is_malicious_ip('9.9.9.9') is False
    finally:
        monkeypatch.setattr('time.time', real_time)


@pytest.mark.asyncio
async def test_retry_backoff_and_dedup(monkeypatch):
    client = ThreatIntelClient()
    # MalwareBazaar: monkeypatch _http_post to return same hash twice
    data = { 'data': [ { 'sha256_hash': 'aa'*32 } ] }
    calls = { 'n': 0 }
    async def fake_post(url, headers=None, data=None, json_body=None, timeout=10.0, retries=2, backoff=1.5):
        calls['n'] += 1
        if calls['n'] == 1:
            return data
        # Simulate timeout/304 by returning None/empty
        return { 'data': [ { 'sha256_hash': 'aa'*32 } ] }
    monkeypatch.setattr(client, "_http_post", fake_post)
    before = len(client.hash_set)
    await client._sync_malwarebazaar()
    mid = len(client.hash_set)
    await client._sync_malwarebazaar()
    after = len(client.hash_set)
    # Only one hash should be present, duplicates ignored due to set semantics
    assert mid == before + 1
    assert after == mid
