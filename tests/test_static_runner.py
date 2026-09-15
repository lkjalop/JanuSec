from src.core.malware.static_runner import run_static_analysis
from pathlib import Path


def test_run_static_analysis(tmp_path):
    p = tmp_path / 'sample.bin'
    data = b"This is a test sample\x00\x01\x02malicious_string.exe\x00" * 10
    p.write_bytes(data)
    res = run_static_analysis(str(p))
    assert res['size'] == len(data)
    assert 'entropy' in res
    assert isinstance(res['top_strings'], list)
    # pe info may be empty if pefile not installed
    assert 'pe' in res
