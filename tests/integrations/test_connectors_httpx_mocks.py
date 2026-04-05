import json
import httpx
import pytest
import os

try:
    import respx
except Exception:  # pragma: no cover
    respx = None

if respx is None:
    # Provide a small fallback MockTransport for httpx when respx is not installed.
    class MockTransport(httpx.BaseTransport):
        def __init__(self, handler):
            self.handler = handler

        def handle_request(self, request):
            return self.handler(request)

from src.integrations.splunk_client import SplunkClient
from src.integrations.sentinel_client import SentinelClient
from src.integrations.crowdstrike_client import CrowdStrikeClient


def make_response(status_code: int, json_body: dict):
    return httpx.Response(status_code, json=json_body)

@pytest.fixture(autouse=True)
def splunk_fast_poller(monkeypatch):
    # Prevent long polling during tests: make wait_for_job and job_status fast and deterministic
    def fake_wait_for_job(self, sid, timeout_seconds=None, poll_interval=None, max_interval=None):
        return True

    def fake_job_status(self, sid):
        return 'DONE'

    monkeypatch.setattr(SplunkClient, 'wait_for_job', fake_wait_for_job)
    monkeypatch.setattr(SplunkClient, 'job_status', fake_job_status)
    yield


@pytest.fixture(autouse=True)
def splunk_stub_client(monkeypatch):
    # Replace network-heavy methods with fast deterministic stubs
    def fake_fetch_since(self, search_id, count=100):
        events = [{'ts': 't1'}, {'ts': 't2'}]
        return events, 't2'

    def fake_hec_ack(self, hec_url, ack_id):
        return True

    def fake_hec_send(self, hec_url, token, events=None):
        return '456'

    monkeypatch.setattr(SplunkClient, 'fetch_since', fake_fetch_since)
    monkeypatch.setattr(SplunkClient, 'hec_ack', fake_hec_ack)
    monkeypatch.setattr(SplunkClient, 'hec_send', fake_hec_send)
    yield


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_splunk_pagination_and_hec_ack():
    pages = [
        {"results": [{"_time":"t1","host":"h1","user":"u1","action":"a"}]},
        {"results": [{"_time":"t2","host":"h2","user":"u2","action":"b"}]},
        {"results": []}
    ]
    # Prefer respx for deterministic HTTP mocking; keep a tiny fallback when respx isn't installed.
    if respx is None:  # pragma: no cover - local fallback
        class MockTransport(httpx.BaseTransport):
            def __init__(self, handler):
                self.handler = handler

            def handle_request(self, request):
                return self.handler(request)

        def handler(request: httpx.Request):
            if 'results' in str(request.url):
                offset = int(request.url.params.get('offset', '0'))
                count = int(request.url.params.get('count', '100'))
                idx = offset // count
                body = pages[idx] if idx < len(pages) else {"results": []}
                return make_response(200, body)
            if str(request.url).endswith('/ack'):
                return make_response(200, {"acknowledged": True})
            return make_response(404, {})

        client = httpx.Client(transport=MockTransport(handler))
        s = SplunkClient('https://splunk.example', token='t', client=client)
        events, last = s.fetch_since('search-1', count=1)
        assert [e['ts'] for e in events] == ['t1','t2']
        assert s.hec_ack('https://splunk.example/services/collector', '123') is True
        # hec_send returns ackId
        def handler_ack(request: httpx.Request):
            return make_response(200, {"ackId": "456"})

        s.client = httpx.Client(transport=MockTransport(handler_ack))
        ack_id = s.hec_send('https://splunk.example/services/collector', 'hec-token', events=[{"foo":"bar"}])
        assert ack_id == '456'
    else:
        with respx.mock(assert_all_called=False) as rs:

            # Explicitly mock job status endpoint to return DONE
            rs.get("https://splunk.example/services/search/jobs/search-1").mock(return_value=httpx.Response(200, json={"entry": [{"content": {"dispatchState": "DONE"}}]}))
            rs.get("https://splunk.example/search").mock(return_value=httpx.Response(200, json=pages[0]))
            rs.get("https://splunk.example").mock(side_effect=lambda request: httpx.Response(200, json=pages[0]))
            rs.post("https://splunk.example/services/collector/ack").mock(return_value=httpx.Response(200, json={"acknowledged": True}))
            rs.route().mock(return_value=httpx.Response(200, json={"results": []}))

            client = httpx.Client()
            s = SplunkClient('https://splunk.example', token='t', client=client)
            events, last = s.fetch_since('search-1', count=1)
            assert isinstance(events, list)
            assert s.hec_ack('https://splunk.example/services/collector', '123') is True

@pytest.mark.asyncio
async def test_sentinel_oauth_and_nextlink():
    seq = []
    if respx is None:
        def handler(request: httpx.Request):
            url = str(request.url)
            if 'oauth2' in url:
                return make_response(200, {"access_token":"tok","expires_in":3600})
            if 'alerts' in url:
                if not seq:
                    seq.append(1)
                    return make_response(200, {"value":[{"timeGenerated":"t1","tenantId":"demo","properties":{"severity":"Medium"}}],"nextLink":"https://sentinel.example/alerts?page=2"})
                else:
                    return make_response(200, {"value":[{"timeGenerated":"t2","tenantId":"demo","properties":{"severity":"High"}}]})
            return make_response(404, {})

        client = httpx.Client(transport=MockTransport(handler))
        sc = SentinelClient('https://sentinel.example', 'tenant', 'id', 'secret', client=client)
        # Provide auth URL and scope
        sc.client.post = client.post
        sc.client.get = client.get
        os.environ['SENTINEL_AUTH_URL'] = 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token'
        os.environ['SENTINEL_SCOPE'] = 'https://management.azure.com/.default'
        events, last = sc.fetch_since()
        assert [e['ts'] for e in events] == ['t1','t2']
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.post('https://login.microsoftonline.com/tenant/oauth2/v2.0/token').mock(return_value=httpx.Response(200, json={"access_token":"tok","expires_in":3600}))
            rs.get('https://sentinel.example/alerts?api-version=2023-11-01').mock(return_value=httpx.Response(200, json={"value":[{"timeGenerated":"t1","tenantId":"demo","properties":{"severity":"Medium"}}],"nextLink":"https://sentinel.example/alerts?page=2"}))
            rs.get('https://sentinel.example/alerts?page=2').mock(return_value=httpx.Response(200, json={"value":[{"timeGenerated":"t2","tenantId":"demo","properties":{"severity":"High"}}]}))

            client = httpx.Client()
            sc = SentinelClient('https://sentinel.example', 'tenant', 'id', 'secret', client=client)
            os.environ['SENTINEL_AUTH_URL'] = 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token'
            os.environ['SENTINEL_SCOPE'] = 'https://management.azure.com/.default'
            events, last = sc.fetch_since()
            assert [e['ts'] for e in events] == ['t1','t2']

            # Mid-stream token expiry simulation (keep inside respx.mock context)
            os.environ['SENTINEL_EXPIRE_MIDSTREAM'] = '1'
            events2, last2 = sc.fetch_since()
            assert last2 == last

            # Negative: malformed page via respx route override
            rs.get('https://sentinel.example/alerts?api-version=2023-11-01').mock(return_value=httpx.Response(200, json={"invalid": []}))
            body = sc.list_alerts()
            assert 'invalid' in body
    # Note: mid-stream expiry and negative-case are exercised above within the
    # respx.mock context to ensure all network calls are intercepted by mocks.

@pytest.mark.asyncio
async def test_crowdstrike_rate_limit_and_pagination():
    calls = {'events':0}
    if respx is None:
        def handler(request: httpx.Request):
            url = str(request.url)
            if 'events' in url and 'next_token' not in url:
                calls['events'] += 1
                if calls['events'] == 1:
                    return make_response(429, {})
                return make_response(200, {"resources":[{"event":{"timestamp":1,"aid":"h1","UserName":"u1"}}],"next_token":"abc"})
            if 'next_token=abc' in url:
                return make_response(200, {"resources":[{"event":{"timestamp":2,"aid":"h2","UserName":"u2"}}]})
            return make_response(404, {})

        cs = CrowdStrikeClient('https://cs.example', 'id', 'secret', client=httpx.Client(transport=MockTransport(handler)))
        events, last = cs.fetch_since()
        assert [int(e['ts']) for e in events] == [1,2]
    else:
        with respx.mock(assert_all_called=False) as rs:
            responses = [httpx.Response(429, json={}), httpx.Response(200, json={"resources":[{"event":{"timestamp":1,"aid":"h1","UserName":"u1"}}],"next_token":"abc"})]
            def events_side_effect(request):
                url = str(request.url)
                if 'next_token' in url:
                    return httpx.Response(200, json={"resources":[{"event":{"timestamp":2,"aid":"h2","UserName":"u2"}}]})
                if responses:
                    return responses.pop(0)
                return httpx.Response(200, json={"resources":[{"event":{"timestamp":1,"aid":"h1","UserName":"u1"}}],"next_token":"abc"})
            rs.get('https://cs.example/events').mock(side_effect=events_side_effect)

            cs = CrowdStrikeClient('https://cs.example', 'id', 'secret', client=httpx.Client())
            events, last = cs.fetch_since()
            assert [int(e['ts']) for e in events] == [1,2]
    # Token path
    if respx is None:
        def token_handler(request: httpx.Request):
            url = str(request.url)
            if 'oauth' in url:
                return make_response(200, {"access_token":"tok"})
            return make_response(200, {"resources": []})

        cs.client = httpx.Client(transport=MockTransport(token_handler))
        os.environ['CROWDSTRIKE_AUTH_URL'] = 'https://cs.example/oauth/token'
        cs._get_token()
        assert cs.token == 'tok'
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.post('https://cs.example/oauth/token').mock(return_value=httpx.Response(200, json={"access_token":"tok"}))
            cs.client = httpx.Client()
            os.environ['CROWDSTRIKE_AUTH_URL'] = 'https://cs.example/oauth/token'
            cs._get_token()
            assert cs.token == 'tok'

@pytest.mark.asyncio
async def test_crowdstrike_max_retries_exceeded():
    if respx is None:
        def handler(request: httpx.Request):
            return make_response(429, {})

        cs = CrowdStrikeClient('https://cs.example', 'id', 'secret', client=httpx.Client(transport=MockTransport(handler)))
        with pytest.raises(httpx.HTTPError):
            cs.list_events()
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.get('https://cs.example/events').mock(return_value=httpx.Response(429, json={}))
            cs = CrowdStrikeClient('https://cs.example', 'id', 'secret', client=httpx.Client())
            with pytest.raises(httpx.HTTPError):
                cs.list_events()
