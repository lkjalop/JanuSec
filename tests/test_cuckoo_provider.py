import asyncio

from src.integrations.sandbox.cuckoo_provider import CuckooProvider


async def _run_submit_and_result():
    p = CuckooProvider()
    # ensure base not set to trigger simulation
    p.base = ''

    task_id = await p.submit(b"hello", "test.bin", None)
    assert task_id.startswith("sim-")

    res = await p.result(task_id)
    assert res is None


def test_cuckoo_sim_mode():
    asyncio.get_event_loop().run_until_complete(_run_submit_and_result())
