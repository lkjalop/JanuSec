import asyncio
import importlib
import types
import pytest

from src.core.event_pipeline.pipeline import EventPipeline
from src.core.event_pipeline.stages.base import StageDefinition, StageResult


class DummyConfig(dict):
    def __init__(self):
        super().__init__()
        self['pipeline'] = {'use_process_pool': True, 'process_pool_timeout': 5}


@pytest.mark.asyncio
async def test_heavy_sleep_runs_in_process(monkeypatch, tmp_path):
    # Create a pipeline with a single heavy stage that sleeps 1s
    cfg = DummyConfig()
    pipeline = EventPipeline(cfg)

    # Import test stage module
    mod = importlib.import_module('tests.support.heavy_test_stage')
    sd = StageDefinition('heavy_sleep', getattr(mod, 'heavy_sleep_stage'), heavy=True, timeout_ms=3000)
    pipeline._active_stage_definitions = [sd]

    event = {'id': 'evt1', 'sleep_seconds': 1.0}
    res = await pipeline.process_event(event)
    assert res is not None
    assert 'heavy:done' in res.factors


@pytest.mark.asyncio
async def test_heavy_crash_isolated(monkeypatch):
    cfg = DummyConfig()
    pipeline = EventPipeline(cfg)
    mod = importlib.import_module('tests.support.heavy_test_stage')
    sd = StageDefinition('heavy_crash', getattr(mod, 'heavy_crash_stage'), heavy=True, timeout_ms=2000)
    pipeline._active_stage_definitions = [sd]
    event = {'id': 'evt2'}
    res = await pipeline.process_event(event)
    # Crash should not raise to caller; pipeline should return with safe metadata
    assert res is not None
    assert isinstance(res.metadata, dict)
    # Expect an entry in metadata.stage_errors or an empty factor list
    assert ('stage_errors' in res.metadata and res.metadata['stage_errors']) or res.factors == []
