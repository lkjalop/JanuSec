from __future__ import annotations

import contextlib
import time
from typing import Any, Dict, Generator


@contextlib.contextmanager
def span(name: str, attrs: Dict[str, Any] | None = None) -> Generator[None, None, None]:
    # Minimal span for metrics/logging; can be replaced by OpenTelemetry
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        # Hook for metrics: in a fuller impl, export to OTel
        try:
            from core.metrics.registry import emit_generic_metric  # type: ignore
            emit_generic_metric('trace_span_seconds', duration, labels={'name': name})
        except Exception:
            pass
