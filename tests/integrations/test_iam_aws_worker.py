from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import pytest

from src.collectors.iam_aws_worker import AWSIAMCollector


class _MemoryStore:
    def __init__(self) -> None:
        self.saved: Dict[Tuple[str, str], Optional[str]] = {}

    def load_cursor(self, tenant: str, provider: str, key: str) -> Optional[str]:
        return self.saved.get((provider, key))

    def save_cursor(self, tenant: str, provider: str, key: str, value: str) -> None:
        self.saved[(provider, key)] = value


class _StubCloudTrail:
    def __init__(self, pages: List[Dict[str, Any]]):
        self._pages = pages
        self.calls: List[Dict[str, Any]] = []
        self._idx = 0

    def lookup_events(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append(kwargs)
        if self._idx >= len(self._pages):
            return {"Events": []}
        page = self._pages[self._idx]
        self._idx += 1
        return page


class _StubHTTP:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    async def post(self, url: str, headers: Dict[str, str], json: Dict[str, Any]) -> Any:  # noqa: A003 - param name
        self.calls.append({"url": url, "headers": headers, "json": json})

        class _Resp:
            @staticmethod
            def raise_for_status() -> None:
                return None

        return _Resp()


@pytest.mark.asyncio
async def test_poll_cloudtrail_paginates_and_persists_cursors(monkeypatch, tmp_path):
    pages = [
        {
            "Events": [
                {
                    "EventName": "CreateUser",
                    "CloudTrailEvent": json.dumps(
                        {
                            "eventTime": "2026-01-01T00:00:00Z",
                            "eventSource": "iam.amazonaws.com",
                            "requestParameters": {"userName": "a"},
                        }
                    ),
                }
            ],
            "NextToken": "next-token",
        },
        {
            "Events": [
                {
                    "EventName": "AttachRolePolicy",
                    "CloudTrailEvent": json.dumps(
                        {
                            "eventTime": "2026-01-01T00:05:00Z",
                            "eventSource": "iam.amazonaws.com",
                            "requestParameters": {"roleName": "Admin"},
                        }
                    ),
                }
            ]
        },
    ]
    store = _MemoryStore()
    log_path = tmp_path / "aws-run.log"
    monkeypatch.setenv("AWS_IAM_RUN_LOG", str(log_path))
    collector = AWSIAMCollector(
        "tenant",
        region="us-west-2",
        client_factory=lambda: _StubCloudTrail(pages),
        tenant_store=store,
        max_events=10,
    )
    events = await collector.poll_cloudtrail()
    assert len(events) == 2
    assert events[0]["eventName"] == "CreateUser"
    assert store.saved[("aws", "cloudtrailLastTs")] == "2026-01-01T00:05:00Z"
    assert log_path.exists()


@pytest.mark.asyncio
async def test_forward_to_ingest_uses_http_client(monkeypatch, tmp_path):
    store = _MemoryStore()
    collector = AWSIAMCollector(
        "tenant",
        tenant_store=store,
        client_factory=lambda: _StubCloudTrail([]),
        http_client=_StubHTTP(),
    )
    monkeypatch.setenv("AWS_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    events = [{"eventName": "CreateUser", "eventTime": "2026-01-01T00:00:00Z"}]
    count = await collector.forward_to_ingest(events)
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001 - test visibility
