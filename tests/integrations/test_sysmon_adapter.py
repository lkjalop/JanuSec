import pytest

from src.integrations.sysmon_adapter import SysmonAdapter


@pytest.mark.asyncio
async def test_sysmon_normalization_and_factors_stub():
    s = SysmonAdapter()
    ok = await s.connect()
    assert ok
    events, cursor = await s.fetch_since()
    assert len(events) == 3
    assert cursor is not None
    e0 = events[0]
    # Check canonical fields are present
    assert "process" in e0 and e0["process"].endswith(".exe")
    assert e0["parent"] == "parent.exe"
    assert e0["hash"].startswith("deadbeef")
    assert "cmdline" in e0 and e0["cmdline"].startswith("C\\")
    assert e0["user"] == "DOMAIN\\User"
    # No container_id expected in synthetic
    assert e0["container_id"] is None
    # Ack
    a = await s.ack(cursor)
    assert a
    h = await s.health()
    assert h["connected"] is True
