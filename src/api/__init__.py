from __future__ import annotations

import inspect

try:
    from httpx import AsyncClient, ASGITransport
    if 'app' not in inspect.signature(AsyncClient.__init__).parameters:
        _orig_async_init = AsyncClient.__init__

        def _patched_async_init(self, *args, app=None, transport=None, **kwargs):
            if app is not None and transport is None:
                transport = ASGITransport(app=app)
            _orig_async_init(self, *args, transport=transport, **kwargs)

        AsyncClient.__init__ = _patched_async_init  # type: ignore[attr-defined]
except Exception:
    pass
