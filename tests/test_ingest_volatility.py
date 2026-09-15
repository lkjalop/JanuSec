import json, time, os
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

SURICATA_EVENT = {"src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"Sig A","severity":3},"proto":"http","ts": time.time()}

# Force adaptive alpha enabled
os.environ['ADAPTIVE_EWMA'] = '1'
os.environ['ADAPTIVE_EWMA_BASE_ALPHA'] = '0.6'
os.environ['ADAPTIVE_EWMA_MIN_ALPHA'] = '0.3'
os.environ['ADAPTIVE_EWMA_MAX_ALPHA'] = '0.85'
os.environ['ADAPTIVE_EWMA_VOL_SCALE'] = '0.4'


def test_volatility_endpoint_and_alpha_change():
    # Send multiple events to generate factors and volatility changes
    for i in range(25):
        ev = dict(SURICATA_EVENT)
        ev['alert']['signature'] = f"Sig {i%3}"  # vary signature to create factor variety
        ev['ts'] = time.time()
        client.post('/api/v1/ingest/suricata', data=json.dumps(ev))
        time.sleep(0.05)
    # Force flush to record volatility history deterministically
    client.post('/api/v1/ingest/force_flush')
    # Query status
    status = client.get('/api/v1/ingest/status').json()['detail']
    assert 'volatility_history_size' in status
    # Query volatility history endpoint
    vol = client.get('/api/v1/ingest/volatility').json()['detail']
    assert vol['history_size'] >= 1, f"history_size={vol['history_size']} entries={vol['entries']}"
    assert isinstance(vol['entries'], list)
    # Ensure alpha within configured bounds
    alpha = vol['current_alpha']
    assert 0.29 < alpha < 0.86
