import time
import json
import importlib
from fastapi.testclient import TestClient

# Import app module dynamically to avoid name-binding issues in pytest
appmod = importlib.import_module('src.api.app')
import time
import json
import importlib
from fastapi.testclient import TestClient

# Import app module dynamically to avoid name-binding issues in pytest
appmod = importlib.import_module('src.api.app')
create_app = appmod.create_app
reset_rate_limit_for_tests = getattr(appmod, 'reset_rate_limit_for_tests', lambda: None)

# Build app instance and explicitly mount deep_analyze router for the test client
app = create_app()
try:
    da = importlib.import_module('src.api.deep_analyze_endpoints')
    if hasattr(da, 'router'):
        try:
            # mount under test-specific prefix to avoid collisions with other mounts
            app.include_router(da.router, prefix='/test_assessments')
        except Exception:
            pass
except Exception:
    pass

client = TestClient(app)


def _mk_request(payload: dict):
    class _Req:
        def __init__(self, payload):
            self._payload = payload
        async def json(self):
            return self._payload
        async def is_disconnected(self):
            return False
        @property
        def headers(self):
            return {}
    return _Req(payload)


def _call_async(func, payload: dict):
    import asyncio
    req = _mk_request(payload)
    return asyncio.get_event_loop().run_until_complete(func(req))


def test_llm_end_to_end_smoke():
    # Ensure rate limit state reset for deterministic test behavior
    reset_rate_limit_for_tests()
    # Prepare sample rows
    rows = [
        { 'row_index': 0, 'raw': {'process_name': 'suspicious.exe', 'file_path': 'C:\\Windows\\System32\\evil.exe', 'sha256': 'deadbeef', 'host': 'host1', 'avPositives': 12, 'verdict': 'SUSPICIOUS'} },
        { 'row_index': 1, 'raw': {'process_name': 'benign.exe', 'file_path': 'C:\\Program Files\\good.exe', 'sha256': 'cafebabe', 'host': 'host2', 'avPositives': 0, 'verdict': 'GOOD'} },
    ]
    payload = {'rows': rows, 'options': {'auto_llm': False}, 'org': 'testorg'}
    # Call deep_analyze directly
    da = importlib.import_module('src.api.deep_analyze_endpoints')
    resp = _call_async(da.deep_analyze, payload)
    # resp is a JSONResponse object; extract body
    try:
        body = json.loads(resp.body.decode())
    except Exception:
        # Some versions may return dict directly
        body = resp if isinstance(resp, dict) else {}
    assert 'assessment_id' in body
    aid = body['assessment_id']

    # Request generate_llm_summaries for top 1 by calling function directly
    gen_payload = {'assessment_id': aid, 'limit': 1}
    resp2 = _call_async(da.generate_llm_summaries, gen_payload)
    try:
        j2 = json.loads(resp2.body.decode())
    except Exception:
        j2 = resp2 if isinstance(resp2, dict) else {}
    assert 'rows' in j2 and isinstance(j2['rows'], list)
    assert 'aggregate_cost' in j2
    rows_ret = j2['rows']
    if not rows_ret:
        # fetch rows from get_assessment_rows (signature: request, assessment_id)
        import asyncio
        req_stub = _mk_request({})
        try:
            resp_get = asyncio.get_event_loop().run_until_complete(
                da.get_assessment_rows(req_stub, aid)
            )
        except Exception:
            resp_get = None
        try:
            rg = json.loads(resp_get.body.decode()) if resp_get else {}
        except Exception:
            rg = resp_get if isinstance(resp_get, dict) else {}
        rows_ret = rg.get('rows') or []
    assert isinstance(rows_ret, list)
    if rows_ret:
        target_idx = rows_ret[0].get('row_index')
        rp = _call_async(da.generate_persona, {'assessment_id': aid, 'row_index': target_idx, 'persona': 'manager'})
        try:
            jr = json.loads(rp.body.decode())
        except Exception:
            jr = rp if isinstance(rp, dict) else {}
        assert jr.get('persona') == 'manager'
        assert 'text' in jr

    # Final check: generate_llm_summaries should report aggregate_cost numeric
    resp3 = _call_async(da.generate_llm_summaries, {'assessment_id': aid, 'limit': 5})
    try:
        j3 = json.loads(resp3.body.decode())
    except Exception:
        j3 = resp3 if isinstance(resp3, dict) else {}
    val = j3.get('aggregate_cost')
    assert isinstance(val, (int, float)) or (isinstance(val, str) and str(val).replace('.','',1).isdigit())