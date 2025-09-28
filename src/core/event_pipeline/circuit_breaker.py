from __future__ import annotations

import time
from typing import Any

from .metrics import PipelineMetrics
from .utils import cfg_get


class MemoryCircuitBreaker:
    """Lightweight process RSS watchdog to disable heavy stages under pressure."""

    def __init__(self, config: Any, metrics: PipelineMetrics | None, logger) -> None:
        perf_cfg = cfg_get(config, 'performance', {})
        self.limit_mb = float(cfg_get(perf_cfg, 'memory_limit_mb', 0) or 0)
        self.check_interval = float(cfg_get(perf_cfg, 'memory_check_interval_s', 5) or 5)
        self.recover_ratio = float(cfg_get(perf_cfg, 'memory_reenable_ratio', 0.8) or 0.8)
        self.metrics = metrics
        self.logger = logger
        self._last_check = 0.0
        self._disabled = False

    @property
    def disabled(self) -> bool:
        return self._disabled

    def evaluate(self) -> bool:
        if self.limit_mb <= 0:
            return self._disabled
        now = time.time()
        if (now - self._last_check) < self.check_interval:
            return self._disabled
        self._last_check = now
        try:
            import psutil  # type: ignore
        except Exception:
            return self._disabled
        try:
            rss_mb = psutil.Process().memory_info().rss / (1024 * 1024)
        except Exception:
            return self._disabled

        if self.metrics:
            self.metrics.ensure_memory_metrics()
            self.metrics.set_rss(rss_mb)

        if rss_mb > self.limit_mb:
            if not self._disabled:
                self._disabled = True
                if self.metrics:
                    self.metrics.record_mem_trip('disable_correlation')
                try:
                    self.logger.warning(
                        "Memory circuit breaker triggered (rss=%.1fMB > limit %.1fMB); disabling correlation stage",
                        rss_mb,
                        self.limit_mb,
                    )
                except Exception:
                    pass
        elif self._disabled and rss_mb < (self.limit_mb * self.recover_ratio):
            self._disabled = False
            if self.metrics:
                self.metrics.record_mem_trip('enable_correlation')
            try:
                self.logger.info(
                    "Memory pressure cleared (rss=%.1fMB < %.1fMB); re-enabling correlation stage",
                    rss_mb,
                    self.limit_mb * self.recover_ratio,
                )
            except Exception:
                pass
        return self._disabled
