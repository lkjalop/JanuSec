from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from typing import Callable
import os
import secrets

CSRF_COOKIE = os.getenv('ADMIN_CSRF_COOKIE', 'janusec_csrf')
CSRF_HEADER = 'x-csrf-token'


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        path = request.url.path or ''
        # Only enable CSRF protection for admin UI and DLQ admin APIs
        admin_paths = ['/admin', '/api/v1/dlq']
        is_admin_path = any(path.startswith(p) for p in admin_paths)
        # For non-admin paths, skip CSRF enforcement entirely
        if not is_admin_path:
            return await call_next(request)
        # For admin GETs, ensure CSRF cookie exists
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            resp = await call_next(request)
            if CSRF_COOKIE not in request.cookies:
                token = generate_csrf_token()
                resp.set_cookie(CSRF_COOKIE, token, httponly=False, samesite='Lax')
            return resp
        # For state-changing admin requests, require header matching cookie
        cookie_val = request.cookies.get(CSRF_COOKIE)
        header_val = request.headers.get(CSRF_HEADER)
        if not cookie_val or not header_val or cookie_val != header_val:
            return Response('Invalid CSRF token', status_code=403)
        return await call_next(request)
