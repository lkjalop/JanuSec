import asyncio
import time
import pytest

from src.workers.token_rotation import TokenRotationWorker
from src.integrations.auth.token_store import TokenStore


@pytest.mark.asyncio
async def test_list_tokens_empty():
    ts = TokenStore()
    lst = await ts.list_tokens()
    assert isinstance(lst, list)


# Note: full refresh requires network; here we ensure rotation worker runs a single loop without error
@pytest.mark.asyncio
async def test_rotation_worker_iteration(monkeypatch):
    async def fake_list_tokens():
        return [{'tenant_id': 't1', 'provider': 'gmail', 'expiry': time.time() + 1}]

    w = TokenRotationWorker(interval=1)
    monkeypatch.setattr(w._store, 'list_tokens', fake_list_tokens)

    # run one iteration then stop
    async def run_once():
        await asyncio.wait_for(asyncio.shield(w.run()), timeout=0.5)

    # Ensure it doesn't raise immediately (we expect timeout)
    try:
        await run_once()
    except asyncio.TimeoutError:
        pass
    w.stop()
