import os
import json
import sys
import pytest

from fastapi.testclient import TestClient

# Ensure real security.auth (not the conftest permissive stub) is wired before server import.
# test_api_security.py tests that auth enforcement works; the stub would make all routes return 200.
try:
    import src.security.auth as _real_auth
    sys.modules['security.auth'] = _real_auth
    if 'security' not in sys.modules:
        import types
        sys.modules['security'] = types.ModuleType('security')
except Exception:
    pass

import src.api.server as server_mod

client = TestClient(server_mod.app)


def test_graph_reconstruct_requires_api_key():
    # Missing header -> 401 or 403 depending on implementation
    r = client.post('/api/v1/graph/reconstruct', json={'user':'u1'})
    # Debug: print response for triage when assertion fails
    print('DEBUG: graph_reconstruct status', r.status_code)
    try:
        print('DEBUG: request url', r.request.url)
        print('DEBUG: request headers', dict(r.request.headers))
        print('DEBUG: request body', r.request.body)
    except Exception:
        pass
    try:
        print('DEBUG: graph_reconstruct body', r.json())
    except Exception:
        print('DEBUG: graph_reconstruct body raw', r.text)
    assert r.status_code in (401, 403)


def test_incident_attack_subgraph_requires_api_key():
    r = client.get('/api/v1/incidents/some-id/attack_subgraph')
    assert r.status_code in (401, 403)


def test_graph_reconstruct_with_bad_key():
    r = client.post('/api/v1/graph/reconstruct', json={'user':'u1'}, headers={'x-api-key':'bad'})
    # If key is invalid should be forbidden
    assert r.status_code in (401, 403)
