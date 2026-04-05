import json
import os
import pytest

from src.integrations.cloudtrail_adapter import CloudTrailAdapter


@pytest.mark.asyncio
async def test_cloudtrail_s3_inbox_listing_and_loading(tmp_path):
    # Create sample inbox dir with two objects
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    obj1 = inbox / "event1.json"
    obj2 = inbox / "events.json"
    obj1.write_text(json.dumps({
        "eventTime": 1700004000,
        "eventName": "CreateRole",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.0",
        "userIdentity": {"userName": "alice"},
        "resources": [{"ARN": "arn:aws:iam::123456789012:role/role1"}],
    }), encoding='utf-8')
    obj2.write_text(json.dumps([
        {
            "eventTime": 1700004001,
            "eventName": "DeleteRole",
            "sourceIPAddress": "203.0.113.11",
            "userAgent": "aws-cli/2.0",
            "userIdentity": {"userName": "bob"},
            "resources": [{"ARN": "arn:aws:iam::123456789012:role/role2"}],
        }
    ]), encoding='utf-8')

    c = CloudTrailAdapter()
    paths = await c.list_inbox(str(inbox))
    assert len(paths) == 2
    # Load first object
    events = await c.load_object(paths[0])
    assert len(events) >= 1
    e0 = events[0]
    assert "action" in e0 and "resource" in e0
