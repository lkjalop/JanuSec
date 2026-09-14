from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from src.collectors.iam_gcp_worker import GCPIAMCollector


class _MemoryStore:
    def __init__(self) -> None:
        self.saved: Dict[Tuple[str, str], Optional[str]] = {}

    def load_cursor(self, tenant: str, provider: str, key: str) -> Optional[str]:
        return self.saved.get((provider, key))

    def save_cursor(self, tenant: str, provider: str, key: str, value: str) -> None:
        self.saved[(provider, key)] = value


class _Iterator:
    def __init__(self, entries: List[Dict[str, Any]], token: Optional[str] = None):
        self.entries = entries
        self.next_page_token = token

    def __iter__(self):
        yield from self.entries


class _StubLoggingClient:
    def __init__(self, entries: List[Dict[str, Any]], token: Optional[str] = None):
        self.entries = entries
        self.token = token
        self.calls: List[Dict[str, Any]] = []

    def list_entries(self, **kwargs: Any) -> _Iterator:
        self.calls.append(kwargs)
        return _Iterator(self.entries, self.token)


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
async def test_poll_audit_logs_tracks_page_tokens(monkeypatch, tmp_path):
    entries = [
        {
            "protoPayload": {
                "methodName": "SetIamPolicy",
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "a@example.com"},
            },
            "timestamp": "2026-01-01T00:00:00Z",
            "severity": "INFO",
        }
    ]
    store = _MemoryStore()
    log_path = tmp_path / "gcp-run.log"
    monkeypatch.setenv("GCP_IAM_RUN_LOG", str(log_path))
    collector = GCPIAMCollector(
        "tenant",
        project_id="proj",
        logging_client_factory=lambda: _StubLoggingClient(entries, token="next-page"),
        tenant_store=store,
    )
    events = await collector.poll_audit_logs()
    assert len(events) == 1
    assert store.saved[("gcp", "auditPageToken")] == "next-page"
    assert events[0]["methodName"] == "SetIamPolicy"
    assert log_path.exists()


@pytest.mark.asyncio
async def test_forward_to_ingest_uses_http_client(monkeypatch, tmp_path):
    store = _MemoryStore()
    monkeypatch.setenv("GCP_IAM_RUN_LOG", str(tmp_path / "forward.log"))
    collector = GCPIAMCollector(
        "tenant",
        project_id="proj",
        logging_client_factory=lambda: _StubLoggingClient([], None),
        tenant_store=store,
        http_client=_StubHTTP(),
    )
    events = [{"methodName": "SetIamPolicy"}]
    count = await collector.forward_to_ingest(events)
    assert count == 1
    assert collector._last_forward_count == 1  # noqa: SLF001 - test visibility
