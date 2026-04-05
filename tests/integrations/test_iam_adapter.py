import asyncio
import pytest

from src.integrations.iam_adapter import IAMAdapter


@pytest.mark.asyncio
async def test_iam_token_refresh_and_cursor_idempotency(tmp_path, monkeypatch):
    monkeypatch.setenv("IAM_CURSOR_DIR", str(tmp_path))
    a = IAMAdapter("azure", {})
    ok = await a.connect()
    assert ok

    # First fetch with no cursor
    events1, cursor1 = await a.fetch_since()
    assert len(events1) == 3
    assert cursor1 is not None

    # Ack cursor
    ack_ok = await a.ack(cursor1)
    assert ack_ok

    # Fetch again with stored cursor; expect next cursor progression
    events2, cursor2 = await a.fetch_since()
    assert len(events2) == 3
    assert cursor2 is not None
    assert cursor2 != cursor1

    # Force token expiry and ensure refresh happens
    a._token_expiry_ts = 0
    health = await a.health()
    assert health["authenticated"] is True
