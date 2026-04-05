import os, time
from fastapi.testclient import TestClient
import src.api.app as appmod

def test_email_homograph_factor_emitted():
    os.environ.setdefault('PLATFORM_LITE_INIT','1')
    client = TestClient(appmod.app)
    payload = {"from_addr": "ceo@paypa1.com", "to_addr": "finance@example.com", "subject": "Quarterly"}
    r = client.post('/api/v1/email/ingest', json=payload)
    assert r.status_code == 200
    # Inspect hopgraph node factors
    hg = getattr(appmod.app, 'GLOBAL_HOPGRAPH', None)
    assert hg is not None
    factors = hg.get_node_factors('email:ceo@paypa1.com')
    assert 'email:domain_homograph' in factors
