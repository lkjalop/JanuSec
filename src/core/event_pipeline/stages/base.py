from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional


StageRunner = Callable[[Dict[str, Any], 'StageContext'], Awaitable['StageResult']]


@dataclass
class StageResult:
    name: str
    factors: List[str]
    confidence_delta: float = 0.0
    terminal: bool = False
    duration_ms: float = 0.0
    metadata: Dict[str, Any] | None = None


@dataclass
class StageDefinition:
    name: str
    runner: StageRunner
    heavy: bool = False


@dataclass
class StageContext:
    registry: Any
    config: Any
    logger: Any
    state: Dict[str, Any]

    async def resolve_module(self, name: str) -> Any:
        if not self.registry:
            return None
        try:
            module = await self.registry.get_module(name)
        except Exception as exc:
            try:
                self.logger.debug("Stage module %s unavailable: %s", name, exc)
            except Exception:
                pass
            return None
        return module


async def maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value):
        return await value
    if isinstance(value, Awaitable):
        return await value
    return value


def timed_stage(name: str):
    def decorator(func: StageRunner) -> StageRunner:
        async def wrapper(event: Dict[str, Any], ctx: StageContext) -> StageResult:
            start = time.perf_counter()
            result = await func(event, ctx)
            duration = (time.perf_counter() - start) * 1000
            if isinstance(result, StageResult):
                result.duration_ms = duration
                return result
            factors, delta, terminal, metadata = result  # type: ignore[misc]
            return StageResult(name=name, factors=factors, confidence_delta=delta, terminal=terminal, duration_ms=duration, metadata=metadata)
        return wrapper
    return decorator
