import sys
from pathlib import Path

import pytest

from src.core.event_pipeline.pipeline import EventPipeline


def _make_min_event():
    return {'id': 'test-1', 'type': 'test', 'payload': {}}


@pytest.mark.asyncio
async def test_pipeline_runs_without_modules_shim(monkeypatch, tmp_path):
    # Temporarily ensure top-level modules package cannot be found by
    # removing repo root from sys.path if present.
    repo_root = Path(__file__).resolve().parents[2]
    str_repo = str(repo_root)
    removed = False
    if str_repo in sys.path:
        sys.path.remove(str_repo)
        removed = True

    try:
        cfg = type('C', (), {})()
        pipeline = EventPipeline(cfg)
        # Initialize and process a minimal event; any optional analyzers
        # missing should be handled gracefully by the lazy runner.
        try:
            await pipeline.initialize()
        except Exception:
            pass
        res = await pipeline.process_event(_make_min_event())
        assert res is not None
        assert hasattr(res, 'confidence')
    finally:
        if removed:
            sys.path.insert(0, str_repo)
