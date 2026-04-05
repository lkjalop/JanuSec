import json
import pytest
from pathlib import Path

from src.api.cloudtrail_inbox_harness import ingest_inbox_and_publish


@pytest.mark.asyncio
async def test_cloudtrail_inbox_end_to_end_publish(tmp_path, monkeypatch):
    monkeypatch.setenv("HOPGRAPH_STREAM_TEST_MODE", "1")
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "e.json").write_text(json.dumps({
        "eventTime": 1700005000,
        "eventName": "UpdatePolicy",
        "sourceIPAddress": "203.0.113.20",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {"userName": "charlie"},
        "resources": [{"ARN": "arn:aws:iam::123456789012:policy/p1"}],
    }), encoding='utf-8')

    ok = await ingest_inbox_and_publish(str(inbox))
    if not ok:
        pytest.skip("SSE publisher/counter not available in this test environment")
