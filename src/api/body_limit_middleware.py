"""body_limit_middleware.py — ASGI middleware that enforces a per-request body
size limit on ingest routes.

Rationale
---------
FastAPI/Starlette does not enforce a default body size cap.  Without one, a
caller can POST an arbitrarily large JSON payload to any connector ingest
route, causing unconstrained memory allocation (OWASP API4:2023).

This middleware reads ``Content-Length`` when present and refuses requests
that declare a body over the limit before the body is read.  For chunked
transfers (no Content-Length), it reads the stream and accumulates up to the
limit, replacing the scope body so downstream handlers work normally.

Configuration
-------------
``INGEST_BODY_LIMIT_BYTES``  — env var (default 10 MB).
``INGEST_BODY_LIMIT_PATHS``  — comma-separated path prefixes that are subject
                               to the limit (default: ``/api/v1/ingest``).
                               Set to ``*`` to apply globally.

The middleware is intentionally skipped for binary PCAP uploads
(``/api/v1/ingest/stream-pcap``) because that endpoint enforces its own limit
internally via ``stream_ingest.MAX_BYTES``.
"""
from __future__ import annotations

import os
from typing import Awaitable, Callable

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

_DEFAULT_LIMIT = 10 * 1024 * 1024  # 10 MB
_BODY_LIMIT: int = int(os.getenv("INGEST_BODY_LIMIT_BYTES", str(_DEFAULT_LIMIT)))

_raw_prefixes = os.getenv("INGEST_BODY_LIMIT_PATHS", "/api/v1/ingest")
_LIMIT_PREFIXES: list[str] = (
    [] if _raw_prefixes == "*"
    else [p.strip() for p in _raw_prefixes.split(",") if p.strip()]
)
_GLOBAL_LIMIT = (_raw_prefixes == "*")

# Routes with their own internal size enforcement — skip middleware to avoid
# double-reading the stream.
_SKIP_PATHS: set[str] = {"/api/v1/ingest/stream-pcap"}


class BodyLimitMiddleware:
    """ASGI middleware enforcing a per-request body size cap on ingest routes."""

    def __init__(self, app: ASGIApp, limit: int = _BODY_LIMIT) -> None:
        self._app = app
        self._limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Check whether this path is subject to limits
        if path in _SKIP_PATHS:
            await self._app(scope, receive, send)
            return

        if not _GLOBAL_LIMIT and not any(path.startswith(p) for p in _LIMIT_PREFIXES):
            await self._app(scope, receive, send)
            return

        # Fast path: Content-Length header present
        headers = Headers(scope=scope)
        cl = headers.get("content-length")
        if cl is not None:
            try:
                length = int(cl)
            except ValueError:
                length = 0
            if length > self._limit:
                response = JSONResponse(
                    {"detail": "payload_too_large", "limit_bytes": self._limit},
                    status_code=413,
                )
                await response(scope, receive, send)
                return

        # Slow path: chunked / unknown length — buffer and enforce
        body_chunks: list[bytes] = []
        total = 0
        too_large = False

        async def limited_receive() -> dict:
            nonlocal total, too_large
            if too_large:
                # Return an empty body-complete message so the app can finish
                return {"type": "http.request", "body": b"", "more_body": False}
            message = await receive()
            chunk: bytes = message.get("body", b"")
            total += len(chunk)
            if total > self._limit:
                too_large = True
                return {"type": "http.request", "body": b"", "more_body": False}
            body_chunks.append(chunk)
            return message

        # We cannot buffer the whole body here without breaking streaming —
        # instead wrap receive and let the endpoint read normally but abort
        # after limit exceeded.  After reading we replay the buffered bytes
        # if within limit (needed for Body(...) parameters).
        messages: list[dict] = []
        more = True
        while more:
            msg = await limited_receive()
            messages.append(msg)
            more = msg.get("more_body", False)
            if too_large:
                break

        if too_large:
            response = JSONResponse(
                {"detail": "payload_too_large", "limit_bytes": self._limit},
                status_code=413,
            )
            await response(scope, receive, send)
            return

        # Replay buffered messages to the app
        _idx = 0

        async def replay_receive() -> dict:
            nonlocal _idx
            if _idx < len(messages):
                msg = messages[_idx]
                _idx += 1
                return msg
            return {"type": "http.request", "body": b"", "more_body": False}

        await self._app(scope, replay_receive, send)
