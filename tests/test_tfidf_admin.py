from __future__ import annotations
import importlib
import src.api.tfidf_admin as ta


def test_trigger_decay_no_admin(monkeypatch):
    # with no ADMIN_API_KEY set, endpoint should accept any header
    importlib.reload(ta)
    resp = None
    try:
        import asyncio
        resp = asyncio.get_event_loop().run_until_complete(ta.trigger_decay(None))
    except Exception as e:
        resp = {'error': str(e)}
    assert isinstance(resp, dict)
    assert resp.get('status') == 'ok'
    