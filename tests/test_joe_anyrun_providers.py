import asyncio
from src.integrations.sandbox.joe_provider import JoeProvider
from src.integrations.sandbox.anyrun_provider import AnyRunProvider


async def _run_providers():
    j = JoeProvider()
    a = AnyRunProvider()

    j.base = ''
    a.base = ''

    tid_j = await j.submit(b"x", "f.bin", None)
    tid_a = await a.submit(None, None, "http://example.com/malware")

    assert tid_j.startswith("sim-")
    assert tid_a.startswith("sim-")

    assert (await j.result(tid_j)) is None
    assert (await a.result(tid_a)) is None


def test_joe_anyrun_sim():
    asyncio.get_event_loop().run_until_complete(_run_providers())
