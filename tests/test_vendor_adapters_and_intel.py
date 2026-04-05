import asyncio
import pytest

from src.integrations.crowdstrike_adapter import CrowdStrikeAdapter
from src.integrations.splunk_adapter import SplunkAdapter
from src.integrations.sentinel_adapter import SentinelAdapter
from src.integrations.threat_intel_shim import ThreatIntelShim


@pytest.mark.asyncio
async def test_crowdstrike_adapter_returns_event():
    a = CrowdStrikeAdapter()
    # consume generator
    gen = a.fetch_detections()
    item = await gen.__anext__()
    assert item['source'] == 'crowdstrike'


@pytest.mark.asyncio
async def test_splunk_adapter_returns_event():
    a = SplunkAdapter()
    gen = a.fetch_notable_events()
    item = await gen.__anext__()
    assert item['source'] == 'splunk'


@pytest.mark.asyncio
async def test_sentinel_adapter_returns_event():
    a = SentinelAdapter()
    gen = a.fetch_incidents()
    item = await gen.__anext__()
    assert item['source'] == 'sentinel'


def test_threat_intel_shim():
    s = ThreatIntelShim()
    assert s.lookup_ip('1.2.3.4')['malicious'] is True
    assert s.lookup_domain('not-bad.example')['malicious'] is False
