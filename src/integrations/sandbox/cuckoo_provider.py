from __future__ import annotations

import os
import io
import json
import time
import uuid
from typing import Any

from ..sandbox.provider_base import SandboxProvider, normalize_output
from src.security.crypto_utils import decrypt_secret

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


class CuckooProvider(SandboxProvider):
    """Cuckoo sandbox HTTP provider.

    Expects environment variables:
    - SANDBOX_API_URL (base URL, e.g. http://cuckoo:8090)
    - SANDBOX_API_KEY (optional)

    This implementation posts to `/tasks/create/file` for file uploads and
    `/tasks/create/url` for URL submissions. It polls `/tasks/report/{task_id}`
    for results until completion or timeout.
    """

    def __init__(self, timeout: int = 30, max_retries: int = 3):
        super().__init__(timeout=timeout, max_retries=max_retries)
        # allow provider-specific config file at data/integrations/cuckoo.json
        name = os.getenv('SANDBOX_NAME', 'cuckoo')
        cfg_path = os.path.join('data', 'integrations', f'{name}.json')
        api_key = None
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, 'r', encoding='utf-8') as fh:
                    cfg = json.load(fh)
                    api_key = cfg.get('api_key')
                    if api_key and cfg.get('_api_key_encrypted'):
                        api_key = decrypt_secret(api_key)
            except Exception:
                api_key = None

        self.base = os.getenv("SANDBOX_API_URL", "").rstrip("/")
        self.key = os.getenv("SANDBOX_API_KEY") or api_key

    async def submit(self, file_bytes: bytes | None, filename: str | None, url: str | None) -> str:
        # If httpx not available, return a simulated id for local tests
        if httpx is None or not self.base:
            return "sim-" + uuid.uuid4().hex

        headers = {}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"

        # Idempotency: add content hash header for files
        files = None
        data = None
        endpoint = None

        if file_bytes is not None and filename is not None:
            endpoint = f"{self.base}/tasks/create/file"
            headers.update(self._content_hash_header(file_bytes))
            files = {"file": (filename, io.BytesIO(file_bytes))}
        elif url is not None:
            endpoint = f"{self.base}/tasks/create/url"
            data = {"url": url}
            # include idempotency for URL stub
            headers.update(self._content_hash_header(url.encode()))
        else:
            raise ValueError("Either file_bytes+filename or url must be provided")

        # Perform request
        try:
            if files:
                resp = await self._do_request("POST", endpoint, files=files, headers=headers)
            else:
                resp = await self._do_request("POST", endpoint, json=data, headers=headers)

            payload = resp.json()
            # Expecting something like {'task_id': '...'}
            task_id = payload.get("task_id") or payload.get("id") or payload.get("uuid")
            if not task_id:
                # Fallback: generate a local id but warn
                task_id = "sim-" + uuid.uuid4().hex
                self._log_warning_no_task(payload)

            return str(task_id)

        except Exception as exc:  # pragma: no cover - network/runtime
            # Return simulated id to avoid blocking callers; caller should handle lack of real results
            LOG = __import__("logging").getLogger(__name__)
            LOG.exception("Cuckoo submit failed: %s", exc)
            return "sim-" + uuid.uuid4().hex

    def _log_warning_no_task(self, payload: dict[str, Any]) -> None:
        LOG = __import__("logging").getLogger(__name__)
        LOG.warning("Cuckoo returned unexpected submit payload: %s", json.dumps(payload)[:1000])

    async def result(self, task_id: str, poll_interval: float = 2.0, timeout: int = 300) -> dict[str, Any] | None:
        """Poll /tasks/report/{task_id} until the analysis completes or until timeout.

        Returns normalized result dict or None if still pending or if the task id is simulated.
        """
        # If simulated id, return None to indicate no real result
        if task_id.startswith("sim-"):
            return None

        if httpx is None or not self.base:
            return None

        endpoint = f"{self.base}/tasks/report/{task_id}"
        start = time.time()

        while True:
            try:
                resp = await self._do_request("GET", endpoint, headers={"Authorization": f"Bearer {self.key}"} if self.key else {})
                payload = resp.json()

                # Cuckoo-style status handling: check status/completed flag
                status = payload.get("status") or payload.get("state") or payload.get("task", {}).get("status") if isinstance(payload.get("task"), dict) else None

                # Many Cuckoo instances return nested reports under 'report' or 'data'
                report = payload.get("report") or payload.get("data") or payload

                if status in ("reported", "completed", "success") or report.get("completed") or report.get("verdict"):
                    # Map report to normalized schema
                    normalized = normalize_output(report)
                    # attach raw for debugging
                    normalized["raw"] = report
                    return normalized

                # Not ready yet
                if time.time() - start > timeout:
                    return None

                await asyncio.sleep(poll_interval)

            except Exception as exc:  # pragma: no cover - network/runtime
                LOG = __import__("logging").getLogger(__name__)
                LOG.exception("Error polling cuckoo report %s: %s", task_id, exc)
                # Back off a bit on errors
                await asyncio.sleep(min(5, poll_interval * 2))

