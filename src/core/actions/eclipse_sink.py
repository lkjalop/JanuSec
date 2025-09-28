"""Eclipse Action Sink (stub)

Posts block actions back to Eclipse.XDR if outbound URL configured.
Failure is logged and swallowed for resilience.
"""
from __future__ import annotations
import os, logging
from .models import ActionDecision
try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

logger = logging.getLogger(__name__)

class EclipseActionSink:
    def __init__(self, base_url: str | None, api_key: str | None):
        self.base_url = base_url.rstrip('/') if base_url else None
        self.api_key = api_key

    async def post_action(self, decision: ActionDecision):
        if not self.base_url or httpx is None:
            return False
        url = f"{self.base_url}/actions/block"
        headers = {}
        if self.api_key:
            headers['Authorization'] = f"Bearer {self.api_key}"
        payload = {
            'event_id': decision.event_id,
            'tenant_id': decision.tenant_id,
            'decision': decision.decision,
            'reasons': decision.reasons,
            'severity': decision.severity,
            'factors': decision.factors,
            'ts': decision.ts
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code >= 300:
                    logger.warning(f"Eclipse sink post failed: {resp.status_code} {resp.text}")
                    return False
                return True
        except Exception as e:  # pragma: no cover
            logger.debug(f"Eclipse sink exception: {e}")
            return False
