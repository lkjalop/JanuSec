from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict

from .metrics import PipelineMetrics
from .utils import cfg_get


class MemoryCircuitBreaker:
    """Lightweight process RSS watchdog to disable heavy stages under pressure."""

    def __init__(self, config: Any, metrics: PipelineMetrics | None, logger) -> None:
        perf_cfg = cfg_get(config, 'performance', {})
        self.limit_mb = float(cfg_get(perf_cfg, 'memory_limit_mb', 0) or 0)
        self.check_interval = float(cfg_get(perf_cfg, 'memory_check_interval_s', 5) or 5)
        self.recover_ratio = float(cfg_get(perf_cfg, 'memory_reenable_ratio', 0.8) or 0.8)
        self._fallback_cfg = cfg_get(perf_cfg, 'fallbacks', {'bgp': True, 'redis_cache': True}) or {}
        self.metrics = metrics
        self.logger = logger
        self._last_check = 0.0
        self._disabled = False
        self._last_rss = 0.0
        self._fallback_status: Dict[str, Any] = {}

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
        self._last_rss = rss_mb

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
            self._fallback_status = {}
        if self.metrics:
            self.metrics.record_breaker_state(self._disabled)
        if self._disabled:
            self._activate_fallbacks('memory_pressure')
        return self._disabled

    def snapshot(self) -> Dict[str, Any]:
        return {
            'disabled': self._disabled,
            'limit_mb': self.limit_mb,
            'rss_mb': self._last_rss,
            'last_check_ts': self._last_check,
            'fallbacks': self._fallback_status,
        }

    def _activate_fallbacks(self, reason: str) -> None:
        if not isinstance(self._fallback_cfg, dict):
            return
        statuses: Dict[str, Any] = {}
        if self._fallback_cfg.get('bgp', True):
            statuses['bgp'] = self._bgp_fallback()
        if self._fallback_cfg.get('redis_cache', True):
            statuses['redis_cache'] = self._redis_fallback()
        if statuses:
            statuses['reason'] = reason
            statuses['ts'] = time.time()
            self._fallback_status = statuses
            if self.metrics:
                for name, info in statuses.items():
                    if name in ('reason', 'ts'):
                        continue
                    self.metrics.record_breaker_fallback(name, bool(info.get('ok')))

    def _bgp_fallback(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {'ok': False}
        try:
            from src.integrations.bgp_client import CLIENT

            prefixes = CLIENT.get_prefixes()
            info.update({'ok': True, 'count': len(prefixes)})
            if self._schedule_coroutine(CLIENT.refresh()):
                info['refresh_scheduled'] = True
            else:
                info['refresh_scheduled'] = False
        except Exception as exc:
            info['ok'] = False
            info['error'] = str(exc)
        return info

    def _redis_fallback(self) -> Dict[str, Any]:
        url = os.getenv('REDIS_URL') or os.getenv('CACHE_REDIS_URL')
        if not url:
            return {'ok': False, 'error': 'redis_url_missing'}
        try:
            import redis  # type: ignore
        except Exception as exc:
            return {'ok': False, 'error': f'redis_unavailable:{exc}'}
        try:
            client = redis.Redis.from_url(url, socket_connect_timeout=2)
            client.ping()
            return {'ok': True, 'url': url}
        except Exception as exc:
            return {'ok': False, 'error': str(exc)}

    def _schedule_coroutine(self, coro: Any) -> bool:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            loop.create_task(coro)
            return True
        try:
            asyncio.run(coro)
        except RuntimeError:
            return False
        return False
