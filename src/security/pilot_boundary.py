"""Explicit access and pre-parser admission boundary for the isolated pilot."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import shutil
import tempfile

from fastapi import HTTPException
from src.security.auth import auth_dependency


def required_scope(method: str, path: str) -> str:
    # Default-deny new routes for restricted principals. Route handlers still
    # enforce tenant ownership and any finer-grained domain scopes.
    if method in {'GET', 'HEAD'} and (
        re.fullmatch(r'/api/v1/assessments/?', path)
        or re.fullmatch(r'/api/v1/assessments/[^/]+/(progress(?:/poll)?|evidence|case-view|cases(?:/[^/]+)?|grc-action-pack|model-runs(?:/compare)?|model-jobs/[^/]+)', path)
        or path == '/api/v1/model-providers'
        or path.startswith('/api/v1/report/')
    ):
        return 'pilot.read'
    if method == 'POST' and re.fullmatch(r'/api/v1/assessments/[^/]+/(?:cases/[^/]+/)?evidence-pack', path):
        return 'pilot.read'
    if method == 'POST' and path == '/api/v1/assessments/upload':
        return 'pilot.upload'
    return 'pilot.admin'


class PilotBoundary:
    """Authenticate before receiving bodies; spool a bounded body before parsing.

    Limits are per single-writer process. Disk admission protects configured state
    headroom; a filesystem quota is still needed for a hard total storage boundary.
    """
    def __init__(self, app, state: Path, *, max_body=68 * 1024**2,
                 max_requests=16, max_uploads=1, min_free=1024**3,
                 state_budget=8 * 1024**3, body_timeout=60):
        self.app, self.state = app, Path(state)
        self.max_body, self.max_requests = max_body, max_requests
        self.max_uploads, self.min_free = max_uploads, min_free
        self.state_budget, self.body_timeout = state_budget, body_timeout
        self.active = self.uploads = 0

    async def reject(self, send, status, detail):
        body = json.dumps({'detail': detail}).encode()
        await send({'type': 'http.response.start', 'status': status,
                    'headers': [(b'content-type', b'application/json'),
                                (b'cache-control', b'no-store')]})
        await send({'type': 'http.response.body', 'body': body})

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        path, method = scope['path'], scope['method']
        api = (path.startswith('/api/') or path in {'/metrics', '/docs', '/redoc', '/openapi.json'}
               or method not in {'GET', 'HEAD'})
        if api:
            headers = {key.lower(): value.decode('latin1') for key, value in scope['headers']}
            try:
                ctx = await auth_dependency(headers.get(b'x-api-key'), headers.get(b'authorization'), [])
                required = required_scope(method, path)
                if '*' not in ctx.scopes and required not in ctx.scopes:
                    raise HTTPException(403, 'insufficient_pilot_scope')
                scope.setdefault('state', {})['auth'] = ctx
            except HTTPException as exc:
                return await self.reject(send, exc.status_code, exc.detail)
        if self.active >= self.max_requests:
            return await self.reject(send, 503, 'request_capacity_exhausted')
        upload = method == 'POST' and path == '/api/v1/assessments/upload'
        if upload and self.uploads >= self.max_uploads:
            return await self.reject(send, 503, 'upload_capacity_exhausted')
        self.active += 1
        if upload:
            self.uploads += 1
        try:
            if method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
                return await self.app(scope, receive, send)
            headers = dict(scope['headers'])
            try:
                declared = int(headers.get(b'content-length', b'0'))
                if declared < 0:
                    raise ValueError()
            except ValueError:
                return await self.reject(send, 400, 'invalid_content_length')
            if declared > self.max_body:
                return await self.reject(send, 413, 'request_body_too_large')
            if upload:
                used = sum(p.stat().st_size for p in self.state.rglob('*') if p.is_file())
                # Reserve space for spool, parser copy, raw capture and derived data.
                reserve = self.max_body * 5
                if (used + reserve > self.state_budget
                        or shutil.disk_usage(self.state).free < self.min_free + reserve):
                    return await self.reject(send, 507, 'insufficient_storage_headroom')
            with tempfile.TemporaryFile(dir=self.state) as body:
                total = 0
                try:
                    async with asyncio.timeout(self.body_timeout):
                        while True:
                            message = await receive()
                            if message['type'] == 'http.disconnect':
                                return
                            chunk = message.get('body', b'')
                            total += len(chunk)
                            if total > self.max_body:
                                return await self.reject(send, 413, 'request_body_too_large')
                            body.write(chunk)
                            if not message.get('more_body', False):
                                break
                except TimeoutError:
                    return await self.reject(send, 408, 'request_body_timeout')
                body.seek(0)
                complete = False
                async def replay():
                    nonlocal complete
                    if complete:
                        return await receive()
                    data = body.read(1024 * 1024)
                    more = body.tell() < total
                    complete = not more
                    return {'type': 'http.request', 'body': data, 'more_body': more}
                await self.app(scope, replay, send)
        finally:
            self.active -= 1
            if upload:
                self.uploads -= 1
