from __future__ import annotations

import json
from unittest.mock import patch

from src.integrations.memory.sandbox_adapters import HTTPSandboxAdapter


class _Resp:
    def __init__(self, payload: dict) -> None:
        self._bytes = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_http_sandbox_adapter_handles_success(monkeypatch):
    adapter = HTTPSandboxAdapter(name="joe", endpoint="https://example.com/api", token="abc")

    with patch("urllib.request.urlopen", return_value=_Resp({"status": "accepted", "adapter": "joe"})):
        result = adapter.submit(type("Job", (), {"job_id": "job1", "host": "h1"})(), {"factors": []})
    assert result["status"] == "accepted"
    assert result["adapter"] == "joe"
