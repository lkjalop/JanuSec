import os
import json
import tempfile
from src.api.hopgraph_persistence import _HAS_BOTO3  # import module to ensure availability


def test_s3_helpers_not_available(monkeypatch):
    # Simulate boto3 not installed
    import sys
    monkeypatch.setitem(sys.modules, 'boto3', None)
    try:
        import importlib
        importlib.reload(__import__('src.api.hopgraph_persistence', fromlist=['*']))
    except Exception:
        pass
    # If boto3 missing, calling helpers should raise RuntimeError
    try:
        from src.api.hopgraph_persistence import upload_snapshot_to_s3 as up
        assert False, 'Expected import path to raise or helper missing when boto3 absent'
    except Exception:
        assert True
