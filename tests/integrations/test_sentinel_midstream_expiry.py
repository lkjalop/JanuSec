import httpx
import pytest
import os

from src.integrations.sentinel_client import SentinelClient

class MockTransport(httpx.BaseTransport):
    def __init__(self, handler):
        self.handler = handler
    def handle_request(self, request):
        return self.handler(request)

def make_response(status_code: int, json_body: dict):
    return httpx.Response(status_code, json=json_body)


@pytest.mark.asyncio
async def test_sentinel_midstream_token_expiry_refresh():
    calls = {'page': 0}

    def handler(request: httpx.Request):
        url = str(request.url)
        if 'oauth2' in url:
            return make_response(200, {"access_token": "newtoken", "expires_in": 3600})
        if 'alerts' in url:
            if calls['page'] == 0:
                calls['page'] += 1
                return make_response(200, {"value": [{"timeGenerated": "t1", "tenantId": "demo", "properties": {"severity": "Low"}}], "nextLink": "https://sentinel.example/alerts?page=2"})
            else:
                # Simulate 401 then success after refresh
                if 'attempt' not in calls:
                    calls['attempt'] = 1
                    return make_response(401, {})
                return make_response(200, {"value": [{"timeGenerated": "t2", "tenantId": "demo", "properties": {"severity": "High"}}]})
        return make_response(404, {})

    client = httpx.Client(transport=MockTransport(handler))
    sc = SentinelClient('https://sentinel.example', 'tenant', 'id', 'secret', client=client)
    os.environ['SENTINEL_AUTH_URL'] = 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token'
    events, last = sc.fetch_since()
    assert [e['ts'] for e in events] == ['t1','t2']
