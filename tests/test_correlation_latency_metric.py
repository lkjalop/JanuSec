import asyncio
import pytest

from core.correlation.hunt_correlation import create_correlation_engine
from core.metrics.registry import get_registry


class DummyConfig(dict):
    correlation_window_seconds = 60


@pytest.mark.asyncio
async def test_correlation_latency_histogram_emitted():
    eng = create_correlation_engine(DummyConfig())
    # Simple correlate with and without event
    await eng.correlate(['ssl:ja3_rare'], event={'host': 'h1'})
    await eng.correlate(['ssl:ja3_rare'])

    # Scrape metrics
    try:
        from prometheus_client import generate_latest
        metrics_text = generate_latest(get_registry()).decode()
    except Exception:
        metrics_text = ''

    assert 'hunt_correlation_latency_seconds' in metrics_text
    # Expect both had_event=1 and had_event=0 cases
    assert 'had_event="1"' in metrics_text
    assert 'had_event="0"' in metrics_text