import os
import tempfile
from src.domains.binary.static_analyzer import analyze_path


def test_analyze_unknown_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world")
        path = f.name
    try:
        res = analyze_path(path)
        assert res['kind'] in ('unknown','pe','elf')
        assert res['entropy'] is not None
        assert 'sections' in res
    finally:
        os.unlink(path)
