"""Central registry for API background tasks."""

from __future__ import annotations

import asyncio
import random
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from fastapi import FastAPI


TaskFactory = Callable[[], Awaitable[Any]]


@dataclass
class ManagedTaskState:
    name: str
    started_at: float = field(default_factory=time.time)
    last_success_ts: float | None = None
    last_error_ts: float | None = None
    last_error: str | None = None
    run_count: int = 0
    status: str = "starting"


class BackgroundTaskManager:
    """Track, cancel, and report long-running asyncio background tasks."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._states: dict[str, ManagedTaskState] = {}
        self._stop = asyncio.Event()

    @property
    def stop_event(self) -> asyncio.Event:
        return self._stop

    def start_once(self, name: str, factory: TaskFactory) -> asyncio.Task[Any] | None:
        existing = self._tasks.get(name)
        if existing and not existing.done():
            return existing
        state = self._states.setdefault(name, ManagedTaskState(name=name))
        state.status = "running"
        task = asyncio.create_task(self._runner(name, factory), name=name)
        self._tasks[name] = task
        return task

    def track_existing(self, name: str, task: asyncio.Task[Any]) -> asyncio.Task[Any]:
        state = self._states.setdefault(name, ManagedTaskState(name=name))
        state.status = "running"
        self._tasks[name] = task

        def _done(done_task: asyncio.Task[Any]) -> None:
            try:
                if done_task.cancelled():
                    state.status = "cancelled"
                    return
                exc = done_task.exception()
                if exc:
                    state.status = "failed"
                    state.last_error_ts = time.time()
                    state.last_error = f"{type(exc).__name__}: {exc}"
                    return
                state.status = "completed"
                state.last_success_ts = time.time()
                state.run_count += 1
            except Exception as exc:
                state.status = "failed"
                state.last_error_ts = time.time()
                state.last_error = f"{type(exc).__name__}: {exc}"

        task.add_done_callback(_done)
        return task

    async def _runner(self, name: str, factory: TaskFactory) -> None:
        state = self._states.setdefault(name, ManagedTaskState(name=name))
        try:
            await factory()
            state.status = "completed"
            state.last_success_ts = time.time()
            state.run_count += 1
        except asyncio.CancelledError:
            state.status = "cancelled"
            raise
        except Exception as exc:
            state.status = "failed"
            state.last_error_ts = time.time()
            state.last_error = f"{type(exc).__name__}: {exc}"
            raise

    def start_periodic(
        self,
        name: str,
        callback: Callable[[], Awaitable[Any] | Any],
        *,
        interval_seconds: float,
        backoff_seconds: float = 5.0,
        jitter_seconds: float = 0.0,
    ) -> asyncio.Task[Any] | None:
        async def _loop() -> None:
            state = self._states.setdefault(name, ManagedTaskState(name=name))
            while not self._stop.is_set():
                try:
                    result = callback()
                    if asyncio.iscoroutine(result):
                        await result
                    state.status = "running"
                    state.last_success_ts = time.time()
                    state.last_error = None
                    state.run_count += 1
                    delay = interval_seconds
                except asyncio.CancelledError:
                    state.status = "cancelled"
                    raise
                except Exception as exc:
                    state.status = "error_backoff"
                    state.last_error_ts = time.time()
                    state.last_error = "".join(
                        traceback.format_exception_only(type(exc), exc)
                    ).strip()
                    delay = max(backoff_seconds, interval_seconds)
                if jitter_seconds > 0:
                    delay += random.uniform(0, jitter_seconds)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=max(0.0, delay))
                except asyncio.TimeoutError:
                    pass

        return self.start_once(name, _loop)

    async def shutdown(self, *, timeout_seconds: float = 5.0) -> None:
        self._stop.set()
        tasks = [task for task in self._tasks.values() if task and not task.done()]
        for task in tasks:
            task.cancel()
        if not tasks:
            return
        try:
            await asyncio.wait(tasks, timeout=timeout_seconds)
        except Exception:
            pass

    def snapshot(self) -> dict[str, Any]:
        tasks: dict[str, Any] = {}
        for name, state in self._states.items():
            task = self._tasks.get(name)
            tasks[name] = {
                "status": state.status,
                "started_at": state.started_at,
                "last_success_ts": state.last_success_ts,
                "last_error_ts": state.last_error_ts,
                "last_error": state.last_error,
                "run_count": state.run_count,
                "done": bool(task.done()) if task else True,
                "cancelled": bool(task.cancelled()) if task else False,
            }
        return {"task_count": len(tasks), "tasks": tasks}


def get_background_manager(app: FastAPI) -> BackgroundTaskManager:
    manager = getattr(app.state, "background_manager", None)
    if manager is None:
        manager = BackgroundTaskManager()
        app.state.background_manager = manager
    return manager


def background_status(app: FastAPI) -> dict[str, Any]:
    manager = getattr(app.state, "background_manager", None)
    if manager is None:
        return {"task_count": 0, "tasks": {}}
    return manager.snapshot()
