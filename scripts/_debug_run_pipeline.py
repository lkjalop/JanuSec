import sys, os, importlib, asyncio
# Ensure repo root on path for ad-hoc script execution
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from src.core.event_pipeline.pipeline import EventPipeline
mod = importlib.import_module('tests.support.heavy_test_stage')
from src.core.event_pipeline.stages.base import StageDefinition
class DummyConfig(dict):
    def __init__(self):
        super().__init__()
        self['pipeline'] = {'use_process_pool': True, 'process_pool_timeout': 5}

async def run():
    cfg=DummyConfig()
    pipeline=EventPipeline(cfg)
    sd=StageDefinition('heavy_crash', getattr(mod,'heavy_crash_stage'), heavy=True, timeout_ms=2000)
    pipeline._active_stage_definitions=[sd]
    res=await pipeline.process_event({'id':'evt2'})
    print('RESULT METADATA:', res.metadata)
    print('FACTORS:', res.factors)

asyncio.run(run())
