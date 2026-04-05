import os, time
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('FAST_TEST_MODE','1')
from src.api.app import app
from fastapi.testclient import TestClient
from src.graph.hopgraph import HopGraph
app.GLOBAL_HOPGRAPH = HopGraph()
with TestClient(app) as client:
    payload = {
        'sbom_id': 'sbom-test-quick',
        'components': [
            {'name':'A','version':'1.0.0','dependencies':{'B':'^1.0.0','C':'~2.0.0'}},
            {'name':'B','version':'1.0.0'},
            {'name':'C','version':'2.0.1'},
        ]
    }
    r = client.post('/api/v1/sbom/upload', json=payload, headers={'x-api-key':os.getenv('API_KEY','devkey123')})
    print('status', r.status_code)
    hg = getattr(app.state, 'hopgraph', getattr(app, 'GLOBAL_HOPGRAPH', None))
    print('hg is None?', hg is None)
    print('nodes count', len(hg.nodes) if hg else -1)
    print('adj A', hg.adj.get('package:A:1.0.0') if hg else None)
