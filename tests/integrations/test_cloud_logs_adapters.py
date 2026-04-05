import pytest

from src.integrations.cloudtrail_adapter import CloudTrailAdapter
from src.integrations.cloudwatch_adapter import CloudWatchAdapter


@pytest.mark.asyncio
async def test_cloudtrail_adapter_normalization():
    c = CloudTrailAdapter()
    await c.connect()
    events, cursor = await c.fetch_since()
    assert len(events) == 2
    assert cursor is not None
    e0 = events[0]
    assert "action" in e0 and "resource" in e0
    assert "ip" in e0 and "user_agent" in e0


@pytest.mark.asyncio
async def test_cloudwatch_adapter_normalization():
    c = CloudWatchAdapter()
    await c.connect()
    logs, cursor = await c.fetch_since()
    assert len(logs) == 2
    assert cursor is not None
    l0 = logs[0]
    assert "message" in l0 and "group" in l0
