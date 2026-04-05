import httpx
import pytest

from src.integrations.splunk_client import SplunkClient

class MockTransport(httpx.BaseTransport):
    def __init__(self, handler):
        self.handler = handler
    def handle_request(self, request):
        return self.handler(request)

def make_response(status_code: int, json_body: dict, content_type: str = 'application/json'):
    return httpx.Response(status_code, json=json_body, headers={'content-type': content_type})

@pytest.mark.asyncio
async def test_splunk_job_lifecycle_and_timeout(monkeypatch):
    states = ['QUEUED','RUNNING','DONE']
    def handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith('/services/search/jobs') and request.method == 'POST':
            return make_response(201, {"sid":"job123"})
        if '/services/search/jobs/job123' in url and request.method == 'GET':
            state = states.pop(0) if states else 'DONE'
            return make_response(200, {"entry":[{"content":{"dispatchState": state}}]})
        if '/services/search/jobs/job123/results' in url:
            return make_response(200, {"results":[{"_time":"t1","host":"h1","user":"u1","action":"a"}]})
        return make_response(404, {})
    client = httpx.Client(transport=MockTransport(handler))
    s = SplunkClient('https://splunk.example', token='t', client=client)
    sid = s.create_job('search index=main')
    assert sid == 'job123'
    # poll status helper should eventually complete
    assert s.wait_for_job(sid, timeout_seconds=2, poll_interval=0.01) is True
    # results parsing robustness
    res = s.results(sid, offset=0, count=10)
    assert 'results' in res

@pytest.mark.asyncio
async def test_splunk_job_timeout(monkeypatch):
    def handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith('/services/search/jobs') and request.method == 'POST':
            return make_response(201, {"sid":"job456"})
        if '/services/search/jobs/job456' in url and request.method == 'GET':
            return make_response(200, {"entry":[{"content":{"dispatchState": "RUNNING"}}]})
        return make_response(404, {})
    client = httpx.Client(transport=MockTransport(handler))
    s = SplunkClient('https://splunk.example', token='t', client=client)
    sid = s.create_job('search index=main')
    assert sid == 'job456'
    # wait_for_job should return False due to persistent RUNNING
    assert s.wait_for_job(sid, timeout_seconds=0.1, poll_interval=0.01) is False
