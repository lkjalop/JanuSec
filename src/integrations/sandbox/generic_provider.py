from __future__ import annotations

import io
import json
import os
import time
import hashlib
from typing import Any, Dict

from ..sandbox.provider_base import SandboxProvider, normalize_output
from src.security.crypto_utils import decrypt_secret

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


def _load_config(name: str) -> Dict[str, Any]:
    path = os.path.join('data', 'integrations', f'{name}.json')
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


class GenericSandboxProvider(SandboxProvider):
    """Config-driven sandbox provider.

    Expects config JSON at `data/integrations/{name}.json` with keys:
      - base_url
      - submit_file_path (e.g. /tasks/create/file)
      - submit_url_path (e.g. /tasks/create/url)
      - report_path_template (e.g. /tasks/report/{task_id})
      - headers (dict)
      - webhook_secret_header (optional header name used to verify webhooks)
    """

    def __init__(self, name: str, timeout: int = 30, max_retries: int = 3):
        super().__init__(timeout=timeout, max_retries=max_retries)
        self.name = name
        self.cfg = _load_config(name)
        self.base = (self.cfg.get('base_url') or '').rstrip('/')
        self.headers = dict(self.cfg.get('headers') or {})
        # if api_key stored encrypted, decrypt and inject into headers
        api_key = self.cfg.get('api_key')
        if api_key and self.cfg.get('_api_key_encrypted'):
            try:
                secret = decrypt_secret(api_key)
                header_name = self.cfg.get('api_key_header') or 'Authorization'
                if header_name.lower() == 'authorization' and not self.headers.get('Authorization'):
                    self.headers['Authorization'] = f'Bearer {secret}'
                else:
                    self.headers[header_name] = secret
            except Exception:
                pass

    async def submit(self, file_bytes: bytes | None, filename: str | None, url: str | None) -> str:
        if not self.base or httpx is None:
            # fallback simulated id
            return 'sim-' + __import__('uuid').uuid4().hex

        headers = dict(self.headers)

        if file_bytes is not None and filename is not None:
            endpoint = f"{self.base}{self.cfg.get('submit_file_path','/tasks/create/file')}"
            headers.update(self._content_hash_header(file_bytes))
            files = {'file': (filename, io.BytesIO(file_bytes))}
            resp = await self._do_request('POST', endpoint, files=files, headers=headers)
        elif url is not None:
            endpoint = f"{self.base}{self.cfg.get('submit_url_path','/tasks/create/url')}"
            headers.update(self._content_hash_header(url.encode()))
            resp = await self._do_request('POST', endpoint, json={'url': url}, headers=headers)
        else:
            raise ValueError('Either file_bytes+filename or url must be provided')

        payload = resp.json()
        task_id = payload.get('task_id') or payload.get('id') or payload.get('uuid')
        if not task_id:
            task_id = 'sim-' + __import__('uuid').uuid4().hex
        return str(task_id)

    async def result(self, task_id: str) -> Dict[str, Any] | None:
        if task_id.startswith('sim-') or httpx is None or not self.base:
            return None
        template = self.cfg.get('report_path_template', '/tasks/report/{task_id}')
        endpoint = f"{self.base}{template.format(task_id=task_id)}"
        start = time.time()
        timeout = int(self.cfg.get('report_poll_timeout', 300) or 300)
        poll_interval = float(self.cfg.get('report_poll_interval', 2.0) or 2.0)

        while True:
            resp = await self._do_request('GET', endpoint, headers=self.headers)
            payload = resp.json()
            report = payload.get('report') or payload.get('data') or payload
            status = payload.get('status') or report.get('status') or payload.get('state')

            if status in ('reported', 'completed', 'success') or report.get('completed') or report.get('verdict'):
                normalized = normalize_output(report)
                normalized['raw'] = report
                return normalized

            if time.time() - start > timeout:
                return None

            await __import__('asyncio').sleep(poll_interval)
