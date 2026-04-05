import time
from src.core.event_pipeline.stages.base import StageResult


def heavy_sleep_stage(event, ctx):
    # Simulate a heavy stage that sleeps for a duration defined in the event
    dur = float(event.get('sleep_seconds', 2.0))
    time.sleep(dur)
    return StageResult(name='heavy_sleep', factors=['heavy:done'], confidence_delta=0.1, duration_ms=dur*1000)


def heavy_crash_stage(event, ctx):
    raise RuntimeError('simulated crash')
