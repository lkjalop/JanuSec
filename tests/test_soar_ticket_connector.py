import asyncio
import os

import pytest

from src.soar.connectors import get_registry


@pytest.mark.asyncio
async def test_ticket_create_dispatches_multiple_providers(monkeypatch):
    calls = []

    async def fake_http_post(url, json_payload, timeout=5):
        calls.append({'url': url, 'payload': json_payload})
        return {'status': 'ok', 'url': url}

    monkeypatch.setattr('src.soar.connectors.http_post', fake_http_post)
    monkeypatch.setenv('CORTEX_TICKET_URL', 'https://cortex/api/incidents')
    monkeypatch.setenv('PHANTOM_TICKET_URL', 'https://phantom/rest/container')
    monkeypatch.setenv('TINES_TICKET_URL', 'https://tines/hooks/missing')
    registry = get_registry()
    connector = registry.get('ticket.create')
    assert connector is not None
    params = {
        'tenant': 'acme',
        'connector_id': 'syslog_udp',
        'severity': 'high',
        'recommendations': ['Restart collector'],
        'seconds_since_event': 420,
        'ttl_seconds': 300,
    }
    result = await connector(params)
    assert len(calls) == 3
    provider_names = {entry['provider'] for entry in result['providers']}
    assert provider_names == {'cortex', 'phantom', 'tines'}
    assert calls[0]['payload']['queue'] == 'Connector Reliability'
    cortex_payload = calls[0]['payload']
    assert cortex_payload['details']['idle_seconds'] == 420
    phantom_payload = calls[1]['payload']
    assert phantom_payload['container']['custom_fields']['connector_id'] == 'syslog_udp'
    tines_payload = calls[2]['payload']
    assert tines_payload['event']['idle_seconds'] == 420


@pytest.mark.asyncio
async def test_ticket_create_no_provider(monkeypatch):
    env_vars = ['CORTEX_TICKET_URL', 'PHANTOM_TICKET_URL', 'TINES_TICKET_URL']
    for var in env_vars:
        monkeypatch.delenv(var, raising=False)
    connector = get_registry().get('ticket.create')
    result = await connector({'tenant': 'acme', 'connector_id': 'syslog'})
    assert result['providers'][0]['provider'] == 'noop'
