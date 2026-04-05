import asyncio
import os
import struct
import time

import pytest

from src.collectors.syslog_listener import SyslogListener, parse_syslog_message
from src.collectors.netflow_listener import NetFlowListener
from src.api.runtime_state import get_server_runtime_state


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.mark.asyncio
async def test_syslog_listener_parses_and_invokes_callbacks(monkeypatch):
    events = []
    health = []

    def _event_cb(tenant, connector, normalized, raw):
        events.append((tenant, connector, normalized, raw))

    def _health_cb(tenant, connector, count):
        health.append((tenant, connector, count))

    cfg = {
        'listeners': [],
        'sources': [
            {'tenant': 'acme', 'cidrs': ['203.0.113.0/24'], 'shared_secret': 'demo', 'connector_id': 'syslog_acme', 'eps_limit': 10, 'burst': 10}
        ],
    }
    listener = SyslogListener(cfg, event_callback=_event_cb, health_callback=_health_cb, force_enable=True)
    msg = b'<34>Oct 11 22:14:15 fw1 app[1234]: tenant=acme secret=demo User login succeeded'
    await listener.process_datagram(msg, ('203.0.113.10', 12345))
    assert events and events[0][0] == 'acme'
    assert events[0][1] == 'syslog_acme'
    assert events[0][2]['host'] == 'fw1'
    assert health[0] == ('acme', 'syslog_acme', 1)


def test_parse_syslog_extracts_fields():
    parsed = parse_syslog_message(b'<134>Mar 10 07:12:21 host1 sshd[222]: tenant=blue secret=tok connect')
    assert parsed['facility'] == 16
    assert parsed['severity'] == 6
    assert parsed['tenant'] == 'blue'
    assert parsed['shared_secret'] == 'tok'
    assert parsed['host'] == 'host1'


@pytest.mark.asyncio
async def test_netflow_listener_parses_packets(monkeypatch):
    events = []
    health = []

    def _event_cb(tenant, connector, flows, meta):
        events.append((tenant, connector, flows, meta))

    def _health_cb(tenant, connector, count):
        health.append((tenant, connector, count))

    cfg = {
        'listeners': [],
        'sources': [{'tenant': 'net-tenant', 'cidrs': ['198.51.100.0/24'], 'connector_id': 'netflow', 'eps_limit': 10, 'burst': 10}],
    }
    listener = NetFlowListener(cfg, event_callback=_event_cb, health_callback=_health_cb, force_enable=True)
    header = struct.pack('!HHIIIIHH', 5, 1, int(time.time()), 0, 0, 0, 0, 0)
    record = struct.pack(
        '!IIIHHIIIIHHBBBBHHBBH',
        0xC0000201,
        0xC0000202,
        0,
        1,
        1,
        10,
        2048,
        1000,
        2000,
        443,
        51515,
        0,
        19,
        6,
        0,
        64512,
        64513,
        24,
        24,
        0,
    )
    packet = header + record
    await listener.process_datagram(packet, ('198.51.100.5', 2055))
    assert events
    tenant, connector, flows, meta = events[0]
    assert tenant == 'net-tenant'
    assert connector == 'netflow'
    assert flows[0]['src_ip'].startswith('192.0.2.')
    assert meta['flow_count'] == 1
    assert health[0] == ('net-tenant', 'netflow', 1)


def test_network_status_endpoint(client):
    runtime = get_server_runtime_state(client.app)
    tenant_map = runtime.tenants.setdefault('default', {})
    tenant_map['network_connector_health'] = {
        'syslog_udp': {'last_event_ts': time.time(), 'total_ingested': 5, 'last_event_count': 1}
    }
    resp = client.get('/api/v1/network/status', headers={'x-api-key': os.getenv('TEST_API_KEY', 'devkey123')})
    assert resp.status_code == 200
    data = resp.json()
    assert data['tenant'] == 'default'
    assert data['connectors'][0]['id'] == 'syslog_udp'
