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
async def test_splunk_job_invalid_status_returns_false(monkeypatch):
    def handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith('/services/search/jobs') and request.method == 'POST':
            return make_response(201, {"sid":"job999"})
        if '/services/search/jobs/job999' in url and request.method == 'GET':
            return make_response(200, {"entry":[{"content":{"dispatchState": "UNKNOWN"}}]})
        return make_response(404, {})
    client = httpx.Client(transport=MockTransport(handler))
    s = SplunkClient('https://splunk.example', token='t', client=client)
    sid = s.create_job('search index=main')
    assert sid == 'job999'
    assert s.wait_for_job(sid, timeout_seconds=1, poll_interval=0.01) is False
