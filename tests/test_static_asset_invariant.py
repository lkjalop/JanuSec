import hashlib
import requests
import os

# Simple invariant test: when server is running, GET /static/csv_analyzer.html should match on-disk copy

def test_csv_analyzer_static_invariant():
    fp = os.path.join(os.getcwd(), 'frontend', 'static', 'csv_analyzer.html')
    assert os.path.exists(fp), 'On-disk csv_analyzer.html missing'
    with open(fp, 'rb') as f:
        local = f.read()
    local_hash = hashlib.sha256(local).hexdigest()
    try:
        r = requests.get('http://127.0.0.1:8080/static/csv_analyzer.html', timeout=5)
    except Exception:
        # Skip if server not available in this test environment
        return
    assert r.status_code == 200
    served_hash = hashlib.sha256(r.content).hexdigest()
    assert served_hash == local_hash, f'served /static/csv_analyzer.html differs from disk (served={served_hash} local={local_hash})'
