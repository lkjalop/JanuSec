import asyncio
import types

from src.integrations.sandbox.cuckoo_provider import CuckooProvider


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class DummyClient:
    def __init__(self, responses):
        # responses is a list of (method, url, kwargs) to payload mapping
        self._responses = responses
        self._calls = []

    async def request(self, method, url, **kwargs):
        self._calls.append((method, url, kwargs))
        # find first matching response by method substring
        key = method.upper(), url
        payload = None
        # orders: POST submit -> return task_id; GET report -> return completed report
        if url.endswith('/tasks/create/file'):
            payload = {'task_id': 'abc123'}
        elif '/tasks/report/' in url:
            payload = {'status': 'reported', 'report': {'verdict': 'suspicious', 'iocs': {'domains': ['bad.example.com']}}}
        else:
            payload = {}

        return DummyResponse(payload)


async def _run_http_integration():
    p = CuckooProvider()
    # set base so provider uses HTTP paths
    p.base = 'http://dummy'

    # patch _get_client to return our dummy
    async def _get_client():
        return DummyClient([])

    p._get_client = _get_client  # type: ignore

    task_id = await p.submit(b"abc", "sample.bin", None)
    assert task_id == 'abc123'

    res = await p.result('abc123', poll_interval=0.01, timeout=1)
    assert res is not None
    assert res['iocs']['domains'] == ['bad.example.com']
    assert 'sandbox:suspicious' in res['factors'] or res.get('verdict')


def test_cuckoo_http_integration():
    asyncio.get_event_loop().run_until_complete(_run_http_integration())
