import os
import json
from src.analysis.auto_llm import build_llm_row


def test_build_llm_row_schema_deterministic():
    row = {'process_name': 'svc.exe', 'file_path': '/bin/svc.exe', 'sha256': 'deadbeef'*8}
    ctx = {'auto_llm': True}
    r1 = build_llm_row(row, ctx)
    r2 = build_llm_row(row, ctx)
    assert isinstance(r1, dict)
    assert 'fingerprint' in r1
    assert r1['fingerprint'] == r2['fingerprint']
    assert 'risk_level' in r1
    assert 'what_it_does' in r1
