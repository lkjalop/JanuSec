from __future__ import annotations

import os
import io
import time
import uuid
from typing import Any

from ..sandbox.provider_base import SandboxProvider, normalize_output
from src.security.crypto_utils import decrypt_secret

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


class JoeProvider(SandboxProvider):
    """Joe Sandbox provider implementation (best-effort generic HTTP wrapper).

    Uses `/tasks/create/file` and `/tasks/create/url` for submissions and
    `/tasks/report/{id}` for polling, similar to the Cuckoo provider pattern.
    """

    def __init__(self, timeout: int = 30, max_retries: int = 3):
        super().__init__(timeout=timeout, max_retries=max_retries)
        name = os.getenv('SANDBOX_NAME', 'joe')
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
        if httpx is None or not self.base:
            return "sim-" + uuid.uuid4().hex

        headers = {}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"

        if file_bytes is not None and filename is not None:
            endpoint = f"{self.base}/tasks/create/file"
            headers.update(self._content_hash_header(file_bytes))
            files = {"file": (filename, io.BytesIO(file_bytes))}
            resp = await self._do_request("POST", endpoint, files=files, headers=headers)
        elif url is not None:
            endpoint = f"{self.base}/tasks/create/url"
            headers.update(self._content_hash_header(url.encode()))
            resp = await self._do_request("POST", endpoint, json={"url": url}, headers=headers)
        else:
            raise ValueError("Either file_bytes+filename or url must be provided")

        payload = resp.json()
        task_id = payload.get("task_id") or payload.get("id") or payload.get("uuid")
        if not task_id:
            task_id = "sim-" + uuid.uuid4().hex
        return str(task_id)

    async def result(self, task_id: str, poll_interval: float = 2.0, timeout: int = 300) -> dict[str, Any] | None:
        if task_id.startswith("sim-") or httpx is None or not self.base:
            return None

        endpoint = f"{self.base}/tasks/report/{task_id}"
        start = time.time()

        while True:
            try:
                resp = await self._do_request("GET", endpoint, headers={"Authorization": f"Bearer {self.key}"} if self.key else {})
                payload = resp.json()
                report = payload.get("report") or payload.get("data") or payload
                status = payload.get("status") or report.get("status") or payload.get("state")

                if status in ("reported", "completed", "success") or report.get("completed") or report.get("verdict"):
                    normalized = normalize_output(report)
                    normalized["raw"] = report
                    return normalized

                if time.time() - start > timeout:
                    return None

                await asyncio.sleep(poll_interval)
            except Exception as exc:  # pragma: no cover - network/runtime
                LOG = __import__("logging").getLogger(__name__)
                LOG.exception("JoeProvider polling error for %s: %s", task_id, exc)
                await asyncio.sleep(min(5, poll_interval * 2))
