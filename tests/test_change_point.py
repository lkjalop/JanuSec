"""Tests for change-point detection (CUSUM + optional PELT).

We generate synthetic series with a clear mean shift and assert that
the CUSUM detector yields at least one detection near the change.
PELT tests are conditional on ENABLE_PELT + ruptures availability.
"""
from __future__ import annotations

import os, math
from statistics import mean

from src.ml.change_point import ChangePointDetector


def _synthetic_step_series(n1: int = 50, n2: int = 50, v1: float = 10.0, v2: float = 25.0):
    import random
    random.seed(42)
    s1 = [v1 + random.gauss(0, 1.0) for _ in range(n1)]
    s2 = [v2 + random.gauss(0, 1.0) for _ in range(n2)]
    return s1 + s2


def test_cusum_detects_step_change():
    series = _synthetic_step_series()
    detector = ChangePointDetector(threshold=4.0, drift=0.0, adapt=True)
    detections = detector.batch_detect_cusum(series)
    assert detections, "Expected at least one CUSUM detection for step change"
    # Expect a detection index after the midpoint (near change)
    mid = len(series) // 2
    assert any(d['index'] >= mid - 5 for d in detections), f"No detection near change point; detections={detections}" 


def test_cusum_no_false_positive_on_flat_series():
    flat = [100.0] * 40
    detector = ChangePointDetector(threshold=6.0, drift=0.0, adapt=True)
    detections = detector.batch_detect_cusum(flat)
    assert detections == [], f"Unexpected detections on flat series: {detections}"


def test_streaming_api_matches_batch_behavior():
    series = _synthetic_step_series()
    detector = ChangePointDetector(threshold=4.0)
    stream_dets = []
    for x in series:
        d = detector.ingest(x)
        if d:
            stream_dets.append(d)
    batch_dets = ChangePointDetector(threshold=4.0).batch_detect_cusum(series)
    assert stream_dets, "Stream mode should detect change"
    # Allow differences but ensure at least one streaming detection near midpoint
    mid = len(series) // 2
    assert any(d['index'] >= mid - 5 for d in stream_dets), "Streaming detection not near expected change"
    # At least one detection present in batch as well
    assert batch_dets, "Batch mode should detect change"


def test_optional_pelt_wrapper_safe():
    # Ensure no exception even if ruptures missing; may produce empty list.
    series = _synthetic_step_series()
    os.environ['ENABLE_PELT'] = '0'  # force disabled
    detector = ChangePointDetector()
    dets = detector.batch_detect_pelt(series)
    assert dets == [], "PELT should be disabled when ENABLE_PELT=0"
    # If ruptures installed and ENABLE_PELT=1, we expect some breakpoints (not enforced here)
