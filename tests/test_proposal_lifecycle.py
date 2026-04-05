import os
import json
import time
from fastapi.testclient import TestClient
from src.api.server import app
from core.recalibrator import propose_and_write, PROPOSAL_HISTORY, LAST_PROPOSAL
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS

client = TestClient(app)


def test_proposal_accept_apply(tmp_path):
    # prepare labeled samples: create several snapshots and labels
    for i in range(5):
        eid = f'pl-{i}'
        snap = FactorAttributionSnapshot(
            event_id=eid,
            ts=time.time(),
            factors=['f1','f2'] if i%2==0 else ['f3'],
            breakdown=[{'factor':'f1','contribution':0.6}],
            score=0.6,
            raw_score=0.58,
            confidence=0.9,
            variance=0.0,
            ci95=(0.5,0.7),
        )
        FACTOR_ATTRIBUTIONS.add_snapshot(snap)
        LABELS.add_label(eid,'tp' if i%2==0 else 'fp','t')
    # create API key
    os.environ['API_KEYS_JSON'] = json.dumps([{'key':'k2','scopes':['factors.search']}])
    # propose
    p = propose_and_write(limit=50)
    assert p is not None
    ts = p['ts']
    # set auto apply and out path
    os.environ['RISK_SIGMOID_AUTO_APPLY'] = '1'
    out_file = tmp_path / 'sig.json'
    os.environ['RISK_SIGMOID_OUT'] = str(out_file)
    # accept via API
    resp = client.post(f'/api/v1/risk/calibration/proposals/{ts}/accept', headers={'x-api-key':'k2'})
    assert resp.status_code == 200
    # file should exist
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert 'k' in data and 'x0' in data
 