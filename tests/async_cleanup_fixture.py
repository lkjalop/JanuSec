import asyncio
import warnings
import pytest

# Global cleanup fixture to reduce coroutine warnings between tests
@pytest.fixture(autouse=True)
def cleanup_async_tasks():
    # Yield to test
    yield
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    # Gather all pending tasks except current
    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
    for t in pending:
        t.cancel()
    if pending:
        try:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
    # Silence common "coroutine was never awaited" warnings in CI noise
    warnings.filterwarnings(
        "ignore",
        category=RuntimeWarning,
        message=r"coroutine .* was never awaited",
    )
