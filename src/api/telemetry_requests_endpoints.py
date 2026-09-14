from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.core.telemetry_requests import TelemetryRequest

router = APIRouter(prefix="/api/v1/telemetry_requests", tags=["telemetry"])


class CreateTelemetryRequest(BaseModel):
    domain: str
    entity: str
    window: Optional[str] = None
    connector: str = "purview"


@router.get("")
async def list_requests(request: Request, limit: int = 50) -> Dict[str, Any]:
    app = request.app
    store = getattr(app.state, "telemetry_store", None)
    if not store:
        # Initialize lazily to avoid import-time dependencies
        from src.core.telemetry_requests import TelemetryStore
        app.state.telemetry_store = TelemetryStore()
        store = app.state.telemetry_store
    try:
        rows = await store.list_recent(limit=limit)
    except Exception:
        rows = []
    return {"count": len(rows), "items": rows}


@router.post("")
async def enqueue_request(body: CreateTelemetryRequest, request: Request) -> Dict[str, Any]:
    app = request.app
    # lazy init
    try:
        from src.core.telemetry_requests import TelemetryStore
        if not getattr(app.state, "telemetry_store", None):
            app.state.telemetry_store = TelemetryStore()
        if not getattr(app.state, "telemetry_queue", None):
            import asyncio
            app.state.telemetry_queue = asyncio.Queue(maxsize=100)
    except Exception:
        pass
    rid = str(uuid.uuid4())
    now = time.time()
    req = TelemetryRequest(
        id=rid,
        domain=body.domain,
        entity=body.entity,
        window=body.window,
        connector=body.connector,
        status="pending",
        created_at=now,
        updated_at=now,
    )
    # Persist and enqueue
    try:
        await app.state.telemetry_store.upsert(req)
    except Exception:
        pass
    try:
        await app.state.telemetry_queue.put(req)
    except Exception:
        pass

    # In fast-test mode, process immediately without background loop
    if os.getenv("FAST_TEST_MODE","0").lower() in {"1","true","yes"} or os.getenv("PYTEST_CURRENT_TEST"):
        try:
            # inline worker path
            from src.core.telemetry_requests import _execute_connector
            start = time.perf_counter()
            try:
                res = await _execute_connector(req.connector, req.domain, req.entity, req.window)
                req.result_json = __import__('json').dumps(res)
                req.status = "done"
                req.latency_ms = int((time.perf_counter() - start) * 1000)
            except Exception as exc:
                req.status = "error"
                req.error = str(exc).split('\n',1)[0]
            finally:
                req.updated_at = time.time()
                try:
                    await app.state.telemetry_store.upsert(req)
                except Exception:
                    pass
        except Exception:
            pass
    return {"id": rid, "status": req.status}
