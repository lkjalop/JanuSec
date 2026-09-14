import os
import importlib
import time

import pytest


def test_outbox_metrics_registered(monkeypatch):
    # enable metrics test mode so ensure_metrics uses test-friendly registry
    monkeypatch.setenv('METRICS_TEST_MODE', '1')
    # import metrics_init and ensure metrics are initialized
    from src.api import metrics_init

    # ensure project-level metrics are registered
    metrics_init.ensure_metrics()

    # import the async_consumer which should register outbox gauges via metrics_init
    # reload to ensure monkeypatched env is seen
    async_consumer = importlib.reload(importlib.import_module('src.outbox.async_consumer'))

    # Give a moment for any lazy registrations (if any)
    time.sleep(0.1)

    # In METRICS_TEST_MODE the metrics are in-memory objects returned by _safe_gauge/_safe_counter
    # confirm the async_consumer module exposed the OUTBOX gauge objects
    assert hasattr(async_consumer, 'OUTBOX_QUEUE_LEN')
    assert hasattr(async_consumer, 'OUTBOX_OLDEST_AGE')
    assert hasattr(async_consumer, 'OUTBOX_INFLIGHT')
    assert async_consumer.OUTBOX_QUEUE_LEN is not None
    assert async_consumer.OUTBOX_OLDEST_AGE is not None
    assert async_consumer.OUTBOX_INFLIGHT is not None
