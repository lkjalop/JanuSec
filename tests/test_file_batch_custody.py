import asyncio
import hashlib
import json
import os
import time
import uuid

from fastapi.testclient import TestClient

# Assuming the FastAPI app object is named 'app' in server module
from src.api.server import FILE_HASH_FACTORS, app

client = TestClient(app)

def test_file_batch_custody_and_index():
    batch_id = f"test-{uuid.uuid4().hex[:6]}"
    payload = {
        "batch_id": batch_id,
        "files": [
            {"name":"a.exe","sha256":"hashA","size":400,"entropy":7.9,"signed":True,"signature_valid":False},
            {"name":"b.bin","sha256":"hashB","size":128,"entropy":6.8}
        ]
    }
    r = client.post('/files/batch', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data['batch_id'] == batch_id
    # Index should contain hashA since factors emitted
    assert 'hashA' in FILE_HASH_FACTORS
    # Retrieve batch analysis
    r2 = client.get(f'/files/batch/analysis/{batch_id}')
    assert r2.status_code == 200
    # Custody log should contain at least one line with hashA
    path = 'data/file_batches/custody.jsonl'
    assert os.path.exists(path)
    found = False
    with open(path,encoding='utf-8') as fh:
        for line in fh:
            if 'hashA' in line:
                obj = json.loads(line)
                # Recompute digest
                blob = json.dumps({k: obj[k] for k in sorted(obj) if k != 'custody_hash'}, sort_keys=True, separators=(',',':')).encode()
                digest = hashlib.sha256(blob).hexdigest()
                assert digest == obj['custody_hash']
                found = True
                break
    assert found
