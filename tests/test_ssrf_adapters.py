from __future__ import annotations

import os
import pytest


import asyncio


@pytest.mark.asyncio
async def test_eclipse_adapter_ssrf_block(monkeypatch):
    os.environ['PLATFORM_LITE_INIT'] = '1'
    from src.integrations.eclipse_adapter import EclipseClient
    c = EclipseClient()
    monkeypatch.setenv('ECLIPSE_API_URL', 'http://127.0.0.1:1234')
    # Recreate client to pick up env
    c = EclipseClient()
    monkeypatch.setenv('ECLIPSE_API_KEY', 'test')
    c.key = 'test'
    c.enabled = True
    r = await c.update_alert('a1')
    assert isinstance(r, dict)
    assert r.get('ok') is False and 'ssrf_blocked' in (r.get('error') or '')


def test_crowdstrike_real_ssrf_block():
    from integrations.crowdstrike_real import CrowdStrikeRealClient
    c = CrowdStrikeRealClient(client_id='id', client_secret='secret', base_url='http://localhost:8080')
    ok = c.fetch_token()
    assert ok is False
