import json
import os
import shutil
import tempfile
import time

from src.live import evidence_store

# Use temp directory

def test_evidence_rotation(tmp_path):
    # Override path & small max size
    os.environ['EVIDENCE_FILE_PATH'] = str(tmp_path / 'evidence.jsonl')
    os.environ['EVIDENCE_MAX_BYTES'] = '150'
    # Reload module to pick new env
    from importlib import reload
    reload(evidence_store)
    # Write lines until rotation
    for i in range(25):
        evidence_store.append({'event_id': f'id{i}','ts': time.time(), 'evidence': [{'score':i}]})
    files = list(tmp_path.iterdir())
    rotated = [p for p in files if 'rotated' in p.name]
    assert rotated, 'Rotation did not occur'
    # Ensure current file below threshold
    current_size = (tmp_path / 'evidence.jsonl').stat().st_size
    assert current_size < 150
