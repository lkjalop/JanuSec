from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from src.security import hsm_attestor


class _DummyProvider(hsm_attestor._BaseProvider):  # type: ignore[attr-defined]
    name = "dummy"

    def __init__(self) -> None:
        self.raise_error = False

    def attest(self, scope: str, version: int) -> dict[str, str]:
        if self.raise_error:
            raise hsm_attestor.HSMIntegrityError(self.name, "forced_error")
        return {"proof": f"{scope}-{version}", "backend": self.name}


def test_hsm_attestor_health_snapshot_and_webhooks(tmp_path):
    log_path = tmp_path / "log.jsonl"
    cache_path = tmp_path / "cache.json"
    alert_path = tmp_path / "alerts.log"
    with patch.dict(
        os.environ,
        {
            "MEMORY_HSM_BACKEND": "local",
            "MEMORY_HSM_CUSTOMER_WEBHOOKS": "https://cust-a.invalid, https://cust-b.invalid",
        },
    ):
        with patch("src.security.hsm_attestor.post_webhook") as mocked_hook:
            client = hsm_attestor.HardwareAttestorClient(
                log_path=log_path,
                cache_path=cache_path,
                alert_path=alert_path,
                health_interval=0,
                alert_webhook=None,
            )
            dummy = _DummyProvider()
            client.provider = dummy
            result = client.run_health_check()
            assert result["status"] == "ok"
            snapshot = client.health_snapshot()
            assert snapshot["last_status"] == "ok"
            assert snapshot["last_ok_ts"] is not None
            dummy.raise_error = True
            client.run_health_check()
            snapshot = client.health_snapshot()
            assert snapshot["last_status"] == "error"
            assert snapshot["last_tamper_detail"]["detail"] == "forced_error"
            assert mocked_hook.call_count == 2, "customer webhooks should fire on tamper"
            assert snapshot["customer_webhook_count"] == 2
            assert hsm_attestor.get_latest_attestor() is client
