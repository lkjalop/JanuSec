from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, Iterable, List

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

from src.schemas.email import NormalizedEmailEvent


def normalized_event_to_ingest(event: NormalizedEmailEvent) -> Dict[str, Any]:
    """Convert a `NormalizedEmailEvent` into the ingest payload shape."""
    try:
        raw_event = event.model_dump(mode="json")  # type: ignore[attr-defined]
    except Exception:
        try:
            raw_event = json.loads(event.json())
        except Exception:  # pragma: no cover - fallback
            raw_event = event.dict()
    return {
        "from": event.sender or event.sender_domain or "",
        "to": event.recipient,
        "subject": event.subject,
        "timestamp": event.timestamp.isoformat(),
        "spf_result": event.spf_result,
        "dkim_result": event.dkim_result,
        "dmarc_result": event.dmarc_result,
        "raw": raw_event,
    }


async def forward_normalized_events(
    tenant_id: str,
    events: Iterable[NormalizedEmailEvent],
    *,
    source: str,
    batch_env_prefix: str | None = None,
) -> int:
    """Forward normalized events to `/api/v1/email/ingest` with batch fallback."""
    payloads = [normalized_event_to_ingest(evt) for evt in events]
    if not payloads:
        return 0
    base = os.getenv("API_BASE_URL", "http://localhost:8080")
    api_key = os.getenv("API_KEY")
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}

    def _env(name: str, default: str) -> str:
        if batch_env_prefix:
            specific = os.getenv(f"{batch_env_prefix}_{name}")
            if specific:
                return specific
        return os.getenv(f"EMAIL_{name}", default)

    try:
        batch_size = int(_env("INGEST_BATCH_SIZE", "200"))
    except Exception:
        batch_size = 200
    try:
        per_event_conc = int(_env("INGEST_CONCURRENCY", "8"))
    except Exception:
        per_event_conc = 8

    if httpx is None:  # pragma: no cover - only hit when httpx missing at runtime
        raise RuntimeError("httpx is required to forward email events")

    chunks: List[List[Dict[str, Any]]] = [payloads[i : i + batch_size] for i in range(0, len(payloads), batch_size)]
    sent = 0
    async with httpx.AsyncClient(timeout=30) as client:
        url_single = f"{base.rstrip('/')}/api/v1/email/ingest"
        url_batch = f"{base.rstrip('/')}/api/v1/email/ingest/batch"
        for chunk in chunks:
            try:
                resp = await client.post(url_batch, headers=headers, json={"events": chunk})
                if resp.status_code == 404:
                    raise RuntimeError("batch_not_supported")
                if resp.status_code == 429:
                    await asyncio.sleep(1.0)
                    raise RuntimeError("batch_rate_limited")
                resp.raise_for_status()
                sent += len(chunk)
                continue
            except Exception:
                sem = asyncio.Semaphore(max(1, per_event_conc))

                async def _send(ev: Dict[str, Any]) -> int:
                    async with sem:
                        r = await client.post(url_single, headers=headers, json=ev)
                        if r.status_code == 429:
                            await asyncio.sleep(1.0)
                            r = await client.post(url_single, headers=headers, json=ev)
                        r.raise_for_status()
                        return 1

                results = await asyncio.gather(*[_send(ev) for ev in chunk], return_exceptions=True)
                for res in results:
                    if isinstance(res, Exception):
                        continue
                    sent += res
    return sent


__all__ = ["normalized_event_to_ingest", "forward_normalized_events"]
