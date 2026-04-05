import httpx
import pytest
import os

from src.integrations.crowdstrike_client import CrowdStrikeClient
from src.integrations.checkpoint_store import CheckpointStore

class MockTransport(httpx.BaseTransport):
    def __init__(self, handler):
        self.handler = handler
    def handle_request(self, request):
        return self.handler(request)

def make_response(status_code: int, json_body: dict):
    return httpx.Response(status_code, json=json_body)


@pytest.mark.asyncio
async def test_crowdstrike_malformed_resources_and_checkpoint(tmp_path):
    calls = {'first': True}

    def handler(request: httpx.Request):
        url = str(request.url)
        if 'events' in url and 'next_token' not in url:
            # Return malformed resources (missing event) and next_token
                return make_response(200, {"resources": [{"invalid": True}], "next_token": "tkn"})
        if 'next_token=tkn' in url:
            # Next page returns valid resources
            return make_response(200, {"resources": [{"event": {"timestamp": 10, "aid": "h1", "UserName": "u1"}}]})
        return make_response(404, {})

    client = httpx.Client(transport=MockTransport(handler))
    cs = CrowdStrikeClient('https://cs.example', 'id', 'secret', client=client)
    cp = tmp_path / 'cs.json'
    os.environ['CROWDSTRIKE_CHECKPOINT_PATH'] = str(cp)
    events, last = cs.fetch_since()
    # malformed resource should be skipped; only valid entries remain
    assert all('ts' in e for e in events)
    # checkpoint should be saved
    store = CheckpointStore(str(cp))
    assert store.load('crowdstrike:last') is not None
