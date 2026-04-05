import importlib
import sys
import types

import pytest

from src.core.event_pipeline.stages import _lazy_runner
from src.core.event_pipeline.stages import StageContext


class DummyConfig: pass


@pytest.mark.asyncio
async def test_lazy_runner_import_failure_returns_safe_result():
    # Simulate that the target module cannot be imported by ensuring it's not
    # in sys.modules and the import will raise ImportError.
    name = 'nonexistent_pkg.analyzer'
    # Ensure import will fail
    sys.modules.pop('nonexistent_pkg', None)

    runner = _lazy_runner('nonexistent_pkg.analyzer', 'Analyzer', 'nonexistent')
    ctx = StageContext(registry=None, config=DummyConfig(), logger=None, state={})

    res = await runner({}, ctx)
    assert res.name == 'nonexistent'
    assert isinstance(res.factors, list)
    # When import fails we expect metadata to capture the error
    assert res.metadata and 'error' in res.metadata


@pytest.mark.asyncio
async def test_lazy_runner_success_with_fake_module():
    # Create a fake module with a fake Analyzer class
    mod = types.ModuleType('fake_mod')

    class FakeAnalyzer:
        def __init__(self, cfg):
            self.cfg = cfg

        async def analyze_event(self, event):
            return {'factors': ['f1', 'f2'], 'confidence_delta': 0.1}

    setattr(mod, 'Analyzer', FakeAnalyzer)
    sys.modules['fake_mod'] = mod

    runner = _lazy_runner('fake_mod', 'Analyzer', 'fake')
    ctx = StageContext(registry=None, config=DummyConfig(), logger=None, state={})
    res = await runner({}, ctx)
    assert res.name == 'fake'
    assert 'f1' in res.factors
    assert res.confidence_delta == pytest.approx(0.1)
