import os
import json
import time

# Ensure API keys are present before the application and TestClient are imported/created
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])

from fastapi.testclient import TestClient
from src.api.server import app
from core.recalibrator import propose_and_write, get_last_proposal
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS
from repositories import calibration_proposals_repo as repo

client = TestClient(app)


def test_auto_accept_and_repo(tmp_path):
    # Ensure security.auth reloads API keys (tests may have imported it earlier)
    try:
        import importlib
        import security.auth as _sa
        # set the cached API_KEYS directly to ensure auth passes for TestClient
        _sa._API_KEYS = {'k3': ['factors.search']}
    except Exception:
        # best-effort; proceed if reload not possible
        pass
    # prepare samples
    for i in range(60):
        eid = f'aa-{i}'
        snap = FactorAttributionSnapshot(event_id=eid, ts=time.time(), factors=['z'], breakdown=[{'factor':'z','contribution':0.6}], score=0.6, raw_score=0.58, confidence=0.9, variance=0.0, ci95=(0.5,0.7))
        FACTOR_ATTRIBUTIONS.add_snapshot(snap)
        LABELS.add_label(eid,'tp' if i%2==0 else 'fp','t')
    p = propose_and_write(limit=200)
    assert p is not None
    # simulate auto-accept without apply
    # Use JWT auth to avoid API key import-time caching issues
    try:
        import jwt
        os.environ['JWT_SECRET'] = 'test-jwt-secret'
        token = jwt.encode({'sub': 't', 'scopes': ['factors.search']}, os.environ['JWT_SECRET'], algorithm='HS256')
        auth_hdr = {'Authorization': f'Bearer {token}'}
    except Exception:
        # fallback to API key header if jwt not available
        auth_hdr = {'x-api-key': 'k3'}
    resp = client.post('/api/v1/risk/calibration/auto_accept', headers=auth_hdr)
    if resp.status_code != 200:
        try:
            print('AUTO_ACCEPT DBG STATUS', resp.status_code, resp.text)
        except Exception:
            pass
    assert resp.status_code == 200
    j = resp.json()
    # now apply
    resp2 = client.post('/api/v1/risk/calibration/auto_accept?apply=true', headers=auth_hdr)
    assert resp2.status_code == 200
    # persist to repo
    # check repo returns entries
    rows = repo.list_proposals(limit=5)
    assert isinstance(rows, list)