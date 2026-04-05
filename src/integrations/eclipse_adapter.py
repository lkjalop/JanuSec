from __future__ import annotations

import os
from typing import Any

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


class EclipseClient:
    def __init__(self):
        self.base = (os.getenv('ECLIPSE_API_URL') or '').rstrip('/')
        try:
            from src.core.secrets import SecretLoader  # type: ignore
        except Exception:
            from core.secrets import SecretLoader  # type: ignore
        self._secrets = SecretLoader()
        self.key = self._secrets.get('ECLIPSE_API_KEY')
        self.enabled = bool(self.base and self.key)

    def _headers(self) -> dict[str, str]:
        # Refresh on demand in case of rotation
        if not self.key:
            self.key = self._secrets.get('ECLIPSE_API_KEY')
        return {'Authorization': f'Bearer {self.key}'} if self.key else {}

    async def update_alert(self, alert_id: str, add_tags: list[str] | None = None, severity: str | None = None, note: str | None = None) -> dict[str, Any]:
        if not self.enabled or httpx is None:
            return {'ok': False, 'error': 'not_configured'}
        data: dict[str, Any] = {}
        if add_tags: data['add_tags'] = add_tags
        if severity: data['severity'] = severity
        if note: data['note'] = note
        try:
            try:
                from src.security.egress_guard import ssrf_check  # type: ignore
            except Exception:
                from security.egress_guard import ssrf_check  # type: ignore
            ok, reason = ssrf_check(f"{self.base}/alerts/{alert_id}/update")
            if not ok:
                return {'ok': False, 'error': f'ssrf_blocked:{reason}'}
            async with httpx.AsyncClient(timeout=8, headers=self._headers()) as client:
                r = await client.post(f"{self.base}/alerts/{alert_id}/update", json=data)
                return {'ok': 200 <= r.status_code < 300, 'status': r.status_code}
        except Exception as e:
            return {'ok': False, 'error': str(e)}


CLIENT = EclipseClient()

__all__ = ['CLIENT','EclipseClient']
