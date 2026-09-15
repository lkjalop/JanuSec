import asyncio
import json
import secrets
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from scripts.pilot_credentials import change
from src.security.pilot_boundary import PilotBoundary


@pytest.fixture
def access(monkeypatch, tmp_path):
    keys = {role: secrets.token_urlsafe(48) for role in ('viewer', 'analyst', 'admin')}
    entries = [{'key': key, 'subject': role, 'tenant_id': 'pilot-a',
                'scopes': {'viewer': ['pilot.read'], 'analyst': ['pilot.read', 'pilot.upload'], 'admin': ['*']}[role]}
               for role, key in keys.items()]
    monkeypatch.setenv('ENV', 'production')
    monkeypatch.setenv('API_KEYS_JSON', json.dumps(entries))
    return keys, entries


@pytest.mark.parametrize('method,path,role,expected', [
    ('GET', '/api/v1/assessments/a/evidence', 'viewer', 200),
    ('POST', '/api/v1/assessments/upload', 'viewer', 403),
    ('POST', '/api/v1/assessments/upload', 'analyst', 200),
    ('GET', '/api/v1/admin/secrets', 'viewer', 403),
    ('POST', '/api/v1/unreviewed-new-route', 'analyst', 403),
    ('GET', '/api/v1/admin/secrets', 'admin', 200),
])
def test_scoped_access_default_denies_unknown_routes(access, tmp_path, method, path, role, expected):
    app = FastAPI()
    @app.api_route('/{path:path}', methods=['GET', 'POST'])
    def endpoint(path: str):
        return {'ok': True}
    client = TestClient(PilotBoundary(app, tmp_path, min_free=0, state_budget=10**12))
    assert client.request(method, path, headers={'x-api-key': access[0][role]}).status_code == expected


def test_unauthenticated_upload_rejected_before_body_receive(tmp_path):
    async def run():
        async def forbidden(*args):
            pytest.fail('unauthenticated body was read or dispatched')
        output = []
        async def send(message): output.append(message)
        await PilotBoundary(forbidden, tmp_path)(
            {'type': 'http', 'path': '/api/v1/assessments/upload', 'method': 'POST', 'headers': []}, forbidden, send)
        assert output[0]['status'] == 401
    asyncio.run(run())


@pytest.mark.parametrize('declared', [False, True])
def test_oversized_body_never_reaches_parser(access, tmp_path, declared):
    async def run():
        calls = 0
        async def forbidden(*args): pytest.fail('oversize body reached parser')
        async def receive():
            nonlocal calls
            calls += 1
            return {'type': 'http.request', 'body': b'x' * 5, 'more_body': True}
        messages = []
        async def send(message): messages.append(message)
        headers = [(b'x-api-key', access[0]['admin'].encode())]
        if declared: headers.append((b'content-length', b'20'))
        boundary = PilotBoundary(forbidden, tmp_path, max_body=8)
        await boundary({'type': 'http', 'path': '/api/v1/example', 'method': 'POST', 'headers': headers}, receive, send)
        assert messages[0]['status'] == 413
        assert calls == (0 if declared else 2)
        assert boundary.active == 0
    asyncio.run(run())


def test_upload_storage_and_capacity_rejection(access, tmp_path):
    app = FastAPI()
    boundary = PilotBoundary(app, tmp_path, state_budget=1)
    client = TestClient(boundary)
    headers = {'x-api-key': access[0]['analyst']}
    assert client.post('/api/v1/assessments/upload', headers=headers).status_code == 507
    boundary.uploads = 1
    assert client.post('/api/v1/assessments/upload', headers=headers).status_code == 503
    boundary.active = 16
    assert client.get('/api/v1/assessments/', headers=headers).status_code == 503


def test_body_deadline_releases_admission_slot(access, tmp_path):
    async def run():
        async def forbidden(*args): pytest.fail('slow body reached parser')
        async def receive(): await asyncio.sleep(1)
        messages = []
        async def send(message): messages.append(message)
        boundary = PilotBoundary(forbidden, tmp_path, body_timeout=0.01)
        await boundary({'type': 'http', 'path': '/api/v1/example', 'method': 'POST',
                        'headers': [(b'x-api-key', access[0]['admin'].encode())]}, receive, send)
        assert messages[0]['status'] == 408
        assert boundary.active == 0
    asyncio.run(run())


def test_named_credential_rotation_and_revocation(access, tmp_path, monkeypatch):
    from src.security.auth import auth_dependency
    state = tmp_path / 'state'; state.mkdir()
    (state / 'pilot.json').write_text(json.dumps({'tenant_id': 'pilot-a'}))
    (state / 'secrets.json').write_text(json.dumps({'API_KEYS_JSON': json.dumps(access[1])}))
    first = tmp_path / 'first.json'; second = tmp_path / 'second.json'
    change(state, 'alice@example.test', 'viewer', 'add', first)
    old = json.loads(first.read_text())['key']
    change(state, 'alice@example.test', 'viewer', 'rotate', second)
    fresh = json.loads(second.read_text())['key']
    assert old != fresh
    def reload(): monkeypatch.setenv('API_KEYS_JSON', json.loads((state / 'secrets.json').read_text())['API_KEYS_JSON'])
    reload()
    from fastapi import HTTPException
    with pytest.raises(HTTPException): asyncio.run(auth_dependency(old, None, []))
    ctx = asyncio.run(auth_dependency(fresh, None, []))
    assert ctx.subject == 'alice@example.test' and '*' not in ctx.scopes
    change(state, 'alice@example.test', 'viewer', 'revoke', None)
    reload()
    with pytest.raises(HTTPException): asyncio.run(auth_dependency(fresh, None, []))


def test_expired_api_key_rejected(access, monkeypatch):
    from src.security.auth import auth_dependency
    from fastapi import HTTPException
    entry = {**access[1][0], 'expires_at': 1}
    monkeypatch.setenv('API_KEYS_JSON', json.dumps([entry]))
    with pytest.raises(HTTPException, match='expired_api_key'):
        asyncio.run(auth_dependency(entry['key'], None, []))


def test_certificate_installation_validates_and_preserves_previous_version(tmp_path, monkeypatch):
    from scripts.pilot_state import initialize
    from src.security.pilot_tls import install, tls_paths
    state = tmp_path / 'state'
    initialize(state, tmp_path / 'recovery.key', 'pilot-a')
    cert, key = state / 'tls-cert.pem', state / 'tls-key.pem'
    with pytest.raises(ValueError, match='hostname_mismatch'):
        install(state, cert, key, 'customer.example.test')
    with pytest.raises(ValueError, match='must_be_issued'):
        install(state, cert, key, 'localhost')
    install(state, cert, key, 'localhost', local_test=True)
    previous = tls_paths(state)
    assert previous[0].read_bytes() == cert.read_bytes()
    import os
    def fail_replace(*args): raise OSError('simulated failed activation')
    monkeypatch.setattr(os, 'replace', fail_replace)
    with pytest.raises(OSError): install(state, cert, key, 'localhost', local_test=True)
    assert tls_paths(state) == previous


def test_route_audit_handles_prefixed_lazy_and_flat_routers():
    from fastapi import APIRouter
    from src.api.router_registry import effective_http_routes
    from types import SimpleNamespace
    router = APIRouter()
    @router.get('/evidence')
    def evidence(): return {}
    nested = APIRouter(); nested.include_router(router, prefix='/cases')
    app = FastAPI(); app.include_router(nested, prefix='/api/v1')
    assert ('GET', '/api/v1/cases/evidence') in set(effective_http_routes(app.routes))
    wrapper = SimpleNamespace(effective_candidates=lambda: [
        SimpleNamespace(starlette_route=SimpleNamespace(path='/prefixed', methods={'GET'}))])
    assert list(effective_http_routes([wrapper])) == [('GET', '/prefixed')]
    lazy_api = SimpleNamespace(path='/api/prefixed', methods={'POST'}, starlette_route=None)
    assert list(effective_http_routes([lazy_api])) == [('POST', '/api/prefixed')]
