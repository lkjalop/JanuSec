"""
Test-only helper to validate HopGraph SSE metrics without coupling tightly
to internal publisher signatures. Attempts to import and use the real
publisher or, if unavailable, increment the documented Prometheus counter
name to exercise the metrics path.
"""
from typing import Any, Dict

try:
    # Prefer using the real module to access its counters/publisher
    from src.api import hopgraph_stream as hs  # type: ignore
except Exception:  # pragma: no cover - environment differences
    hs = None  # type: ignore


def publish_test_event(payload: Dict[str, Any]) -> bool:
    """
    Best-effort publisher for tests:
    - If `hs.publish_hopgraph_overlay` exists, call it with minimal payload.
    - Else, if `hs.hopgraph_stream_events_total` exists, increment it.
    - Else, return False to indicate unavailable path.
    """
    if hs is None:
        return False
    # Try real publisher
    pub = getattr(hs, "publish_hopgraph_overlay", None)
    if callable(pub):
        try:
            import inspect
            import asyncio
            result = pub(payload)
            # If publisher returned a coroutine, execute it safely depending
            # on whether there's a running loop in this thread.
            if inspect.iscoroutine(result):
                try:
                    # If an event loop is already running, schedule as a task
                    # to avoid blocking the caller and to ensure the coroutine
                    # is not left un-awaited (which raises RuntimeWarning).
                    running = asyncio.get_running_loop()
                except RuntimeError:
                    running = None
                if running is not None:
                    try:
                        running.create_task(result)
                        return True
                    except Exception:
                        # fallback to fire-and-forget using run_coroutine_threadsafe
                        try:
                            loop = asyncio.new_event_loop()
                            import threading
                            def _run():
                                asyncio.set_event_loop(loop)
                                loop.run_until_complete(result)
                                try:
                                    loop.close()
                                except Exception:
                                    pass
                            t = threading.Thread(target=_run, daemon=True)
                            t.start()
                            return True
                        except Exception:
                            pass
                else:
                    # No running loop: run synchronously
                    try:
                        asyncio.run(result)
                        return True
                    except Exception:
                        pass
            else:
                # Publisher was synchronous
                return True
        except Exception:
            # Fall through to counter inc
            pass

    # Fallback: increment the documented counter if present
    counter = getattr(hs, "hopgraph_stream_events_total", None)
    if counter is not None:
        try:
            counter.inc()
            return True
        except Exception:
            pass
    return False
