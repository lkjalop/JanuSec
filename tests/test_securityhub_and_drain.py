import json
from unittest import mock

import pytest

from src.integrations import security_hub_adapter
from src.core import durable_dlq


def test_securityhub_push_idempotent(monkeypatch):
    # Prepare adapter with no SQS (direct path)
    adapter = security_hub_adapter.SecurityHubAdapter()
    # Mock resilient_post in the resilient_ingest module to capture meta and avoid network I/O
    called = {}

    def fake_resilient_post(post_fn, meta, attempts=4):
        called['meta'] = meta
        return True

    import src.integrations.resilient_ingest as ri
    monkeypatch.setattr(ri, 'resilient_post', fake_resilient_post)

    # Use real IdempotencyStore for test (writes to artifacts/idempotency.sqlite by default)

    findings = [{'Id': 'f1', 'Title': 'T1'}]
    # Call push_findings (synchronous wrapper) via asyncio loop run
    import asyncio
    asyncio.get_event_loop().run_until_complete(adapter.push_findings('https://example', 'key1', 'tenant1', findings))

    assert 'meta' in called
    assert 'idempotency_key' in called['meta']


def test_drain_s3_only(monkeypatch):
    # Configure S3-only retention
    monkeypatch.setattr(durable_dlq, '_has_aws', True)
    monkeypatch.setattr(durable_dlq, 'S3_BUCKET', 'test-bucket')
    durable_dlq.SQS_URL = ''

    fake_s3 = mock.MagicMock()
    # pretend list_objects_v2 returns one object
    fake_s3.list_objects_v2.return_value = {'Contents': [{'Key': 'dlq/1-abc.json'}]}
    payload = {'base_url': 'https://example', 'events': [{'a': 9}]}
    fake_s3.get_object.return_value = {'Body': mock.MagicMock(read=lambda: json.dumps(payload).encode('utf-8'))}

    durable_dlq.boto3 = mock.MagicMock()
    durable_dlq.boto3.client.return_value = fake_s3

    out = durable_dlq.drain(limit=10)
    assert isinstance(out, list)
    assert out and out[0].get('base_url') == 'https://example'


def test_drain_repost_http(monkeypatch, tmp_path):
    # Create a fake file-based DLQ entry to exercise repost logic
    from scripts import drain_writeback_dlq
    item = {'base_url': 'https://example', 'api_key': 'key', 'tenant_id': 't1', 'events': [{'a': 1}]}
    # Monkeypatch drain() to return our single item
    monkeypatch.setattr(durable_dlq, 'drain', lambda limit=100: [item])

    class FakeResponse:
        def read(self):
            return b'ok'

    def fake_urlopen(req, timeout=10):
        return FakeResponse()

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)

    # Run main drain script which will call attempt_repost
    # Capture stdout by running function directly
    drain_writeback_dlq.main()
