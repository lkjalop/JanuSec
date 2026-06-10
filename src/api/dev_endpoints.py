from fastapi import APIRouter, Request, HTTPException
import os
import io
import time
from .runtime_state import get_file_batch_analysis

router = APIRouter(prefix='/api/v1/dev')


@router.get('/info')
async def dev_info():
    """Return a small object that indicates demo/dev mode and provides the demo API key when safe."""
    # Only surface an explicitly configured demo key when running in a local/demo environment
    demo_key = os.getenv('DEV_DEMO_API_KEY')
    is_dev = os.getenv('JANUSEC_DEV_MODE', '1').lower() in {'1','true','yes'}
    return {'dev': bool(is_dev), 'demo_key': demo_key}


@router.post('/upload_sync')
async def dev_upload_sync(request: Request):
    """Test-only helper: accept JSON {csv: '...'} or multipart form with file
    and create a tabular session synchronously. Only available when
    PLATFORM_LITE_INIT=1 to avoid accidental exposure.
    """
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=404, detail='not_found')
    # Try JSON body first
    try:
        js = await request.json()
    except Exception:
        js = None
    content = None
    if isinstance(js, dict) and 'csv' in js:
        content = js.get('csv')
    # If no JSON, try to read multipart file from body
    if not content:
        try:
            form = await request.form()
            for k, v in form.items():
                # v may be UploadFile
                try:
                    if hasattr(v, 'file'):
                        raw = await v.read()
                        content = raw.decode('utf8', errors='replace')
                        break
                except Exception:
                    continue
        except Exception:
            content = None
    if not content:
        raise HTTPException(status_code=400, detail='missing_csv')
    # Use the upload helper to create a tabular session (best-effort)
    try:
        from .upload_endpoints import _maybe_create_tabular_session
        # Build proper parameters for _maybe_create_tabular_session
        headers = ['user', 'host', 'sha256']
        total_rows = max(0, content.count('\n'))
        store_bytes = content.encode('utf8') if isinstance(content, str) else None
        session = _maybe_create_tabular_session(
            original_filename='sample_small.csv',
            file_type='csv',
            headers=headers,
            total_rows=total_rows,
            store_bytes=store_bytes,
            mode='csv',
            sheet_name=None,
            patterns=None,
        )
        sessions = [session] if session else []
        # Best-effort: seed the runtime file_batch_analysis with richer synthetic batches
        try:
            from . import runtime_state
            runtime = getattr(runtime_state, '_RUNTIME', None)
            if runtime is None:
                runtime = runtime_state.ServerRuntime()
                runtime_state._RUNTIME = runtime
            module_map = get_file_batch_analysis(runtime)
            runtime_map = runtime.file_batch_analysis
            now = int(time.time())
            for sid in sessions:
                bid = sid if isinstance(sid, str) else f'batch-{int(time.time()*1000)}'
                entry = {
                    'files': [
                        {
                            'sha256': f'{bid}-hash1',
                            'observed_ts': now,
                            'factors': ['high_entropy'],
                            'ja3': '771,49200-49196-49195-49188-49187-49162-49161-49172-57-51-47-53-10-5,0-11-10,23-24,0',
                            'tls_cert': {'subject': 'CN=example.com', 'issuer': 'CN=TestCA', 'not_after': now + 86400}
                        },
                        {
                            'sha256': f'{bid}-hash2',
                            'observed_ts': now,
                            'factors': ['signature_mismatch'],
                            'ja3s': '771,4865-4866,0-23-35-11,0',
                            'tls_cert': {'subject': 'CN=api.example.com', 'issuer': 'CN=TestCA', 'not_after': now + 3600}
                        }
                    ],
                    'registry_artifacts': [
                        {'key': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'value': f'{bid}-autorun', 'type': 'autorun'},
                    ],
                    'service_artifacts': [
                        {'service_name': f'{bid}-svc', 'display_name': f'{bid} Service', 'start_type': 'auto'}
                    ],
                    'mapping_preview': {'user': ['alice','bob'], 'host': ['host1','host2'], 'file': [f'{bid}-hash1']}
                }
                module_map[bid] = entry
                runtime_map[bid] = entry
            # keep references aligned
            runtime_state.FILE_BATCH_ANALYSIS = module_map
            runtime_state._RUNTIME.file_batch_analysis = runtime_map
        except Exception:
            pass
        return {'sessions': sessions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'create_failed:{e}')


@router.post('/review_score')
async def dev_review_score(payload: dict, request: Request):
    """Test-only: accept analyst review on an incident.

    Payload example: {incident_id: '...', reviewer: 'analyst1', verdict: 'fp'|'tp', note: '...'}
    Persists review into the incident object (when GLOBAL_INCIDENTS available) and
    calls a placeholder hook `ingest_review_feedback(review)` which later can be
    wired to rules/ML training.
    """
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=404, detail='not_found')
    iid = (payload.get('incident_id') or payload.get('id'))
    if not iid:
        raise HTTPException(status_code=400, detail='incident_id_required')
    reviewer = payload.get('reviewer') or 'anonymous'
    verdict = payload.get('verdict') or payload.get('decision')
    note = payload.get('note') or ''
    try:
        from src.incidents.aggregator import GLOBAL_INCIDENTS
        if not GLOBAL_INCIDENTS:
            raise Exception('no_incident_store')
        # locate incident
        inc_list = GLOBAL_INCIDENTS.list_incidents()
        inc = next((i for i in inc_list if i['id'] == iid), None)
        if not inc:
            raise HTTPException(status_code=404, detail='incident_not_found')
        # persist review
        try:
            # incident objects in aggregator store are mutable; attempt to attach
            stored = GLOBAL_INCIDENTS.incidents.get(iid)
            if stored is not None:
                stored.setdefault('reviews', []).append({'reviewer': reviewer, 'verdict': verdict, 'note': note, 'ts': int(time.time())})
        except Exception:
            pass
        # placeholder hook for ML/rules feedback ingestion
        try:
            from src.api import review_feedback as _rf
            try:
                _rf.ingest_review_feedback({'incident_id': iid, 'reviewer': reviewer, 'verdict': verdict, 'note': note})
            except Exception:
                pass
        except Exception:
            pass
        return {'status': 'ok', 'incident_id': iid}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'review_failed:{e}')



@router.get('/active_investigation')
async def dev_active_investigation(request: Request):
    """Return a deterministic active investigation payload for UI tests.

    This endpoint is guarded so it only appears in lite/test/dev runs. Tests
    should set `PLATFORM_LITE_INIT=1` or `TEST_HELPERS_ENABLED=1` in the
    environment (or call from localhost) to access it.
    """
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} and os.getenv('TEST_HELPERS_ENABLED','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=404, detail='not_found')
    # Deterministic demo payload matching what the LIVE console expects
    return {
        'investigation_id': 'demo-001',
        'target': 'powerscan.exe',
        'sha256': 'a7c24b7dc90e8a67f9c3b1d4e5f6789abcdef123456789',
        'first_seen': '2025-09-23T14:32:00Z',
        'affected_hosts': ['DESKTOP-A1B2C3', 'LAPTOP-X4Y5Z6'],
        'mitre_techniques': ['T1059', 'T1105', 'T1057'],
        'status': 'active',
        'severity': 'critical',
        'confidence': 0.95,
        'evidence_count': 3,
    }


@router.post('/seed_decisions')
async def dev_seed_decisions(payload: dict, request: Request):
    """Test-only: seed a small set of deterministic decisions into DECISION_CACHE.

    Payload example: {count: 3, prefix: 'demo', tenant_id: 'demo'}
    Guarded by `PLATFORM_LITE_INIT` or `TEST_HELPERS_ENABLED` to avoid accidental exposure.
    """
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} and os.getenv('TEST_HELPERS_ENABLED','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=404, detail='not_found')
    try:
        cnt = int(payload.get('count') or 3)
    except Exception:
        cnt = 3
    try:
        prefix = str(payload.get('prefix') or 'demo-decision')
    except Exception:
        prefix = 'demo-decision'
    try:
        tenant = payload.get('tenant_id') or payload.get('tenant') or 'demo'
    except Exception:
        tenant = 'demo'
    try:
        from . import runtime_state
        # Clear existing cache for determinism (best-effort)
        try:
            runtime_state.reset_for_tests()
        except Exception:
            pass
        now = int(time.time())
        seeded: list[str] = []
        seeded_store = getattr(runtime_state, 'SEEDED_DECISIONS', None)
        if not isinstance(seeded_store, dict):
            seeded_store = {}
            try:
                setattr(runtime_state, 'SEEDED_DECISIONS', seeded_store)
            except Exception:
                pass
        for i in range(1, max(1, cnt) + 1):
            eid = f"{prefix}-{i}"
            rec = {
                'event_id': eid,
                'id': eid,
                'verdict': 'SUSPICIOUS' if i % 2 == 0 else 'OBSERVE',
                'confidence': round(0.6 + (i * 0.1), 3) if i < 9 else 0.99,
                'factors': ['demo:seeded', f'demo:f{i}'],
                'tenant_id': tenant,
                'ts': now + i,
                'mitre_techniques': ['T1059'],
            }
            try:
                seeded_store[eid] = rec
            except Exception:
                pass
            try:
                # Use cache_set helper for normalization
                runtime_state.cache_set(eid, rec)
            except Exception:
                try:
                    # Fallback: write directly to DECISION_CACHE mapping
                    try:
                        DEC = getattr(runtime_state, 'DECISION_CACHE')
                        DEC[eid] = rec
                    except Exception:
                        pass
                except Exception:
                    pass
            seeded.append(eid)
            # Mirror into any app/server DECISION_CACHE bindings to keep routes consistent
            try:
                from . import app as app_module
                app_obj = getattr(app_module, 'app', None)
                if app_obj is not None:
                    app_seeded_store = getattr(app_obj.state, '_seeded_decisions', None)
                    if not isinstance(app_seeded_store, dict):
                        app_seeded_store = {}
                        setattr(app_obj.state, '_seeded_decisions', app_seeded_store)
                    app_seeded_store[eid] = rec
                app_cache = getattr(app_module, 'DECISION_CACHE', None)
                if isinstance(app_cache, dict):
                    app_cache[eid] = rec
            except Exception:
                pass
            try:
                from . import server as server_module
                server_cache = getattr(server_module, 'DECISION_CACHE', None)
                if isinstance(server_cache, dict):
                    server_cache[eid] = rec
            except Exception:
                pass
        return {'seeded': seeded, 'count': len(seeded), 'tenant_id': tenant}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'seed_failed:{e}')


@router.post('/reinit_llm')
async def dev_reinit_llm(request: Request = None):
    """Dev-only: clear TEST_HELPERS_ENABLED from process env and reinitialize the DEFAULT_CLIENT.

    Useful when the server was started with TEST_HELPERS_ENABLED=1 accidentally; calling this
    endpoint forces a fresh _select_default_client() call which will pick up LLM_PROVIDER from
    the .env-loaded environment. Only available when APP_ENV=dev or ENV=dev.
    """
    if os.getenv('APP_ENV','prod').lower() not in {'dev','local','test'} and os.getenv('ENV','prod').lower() not in {'dev','local','test'}:
        raise HTTPException(status_code=404, detail='not_found')
    # Unset the test-mode flags so _select_default_client() picks the real provider
    for _var in ('TEST_HELPERS_ENABLED', 'FAST_TEST_MODE', 'PYTEST_CURRENT_TEST'):
        os.environ.pop(_var, None)
    # Re-initialize the module-level DEFAULT_CLIENT
    try:
        import src.integrations.llm_client as _llm_mod
        new_client = _llm_mod._select_default_client()
        _llm_mod.DEFAULT_CLIENT = new_client
        client_class = type(new_client).__name__
        ollama_reachable = getattr(new_client, 'ollama_reachable', None)
        ollama_model = getattr(new_client, 'ollama_model', None)
        return {
            'reinit': 'ok',
            'client_class': client_class,
            'ollama_reachable': ollama_reachable,
            'ollama_model': ollama_model,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post('/llm_explain')
async def dev_llm_explain(payload: dict = None, request: Request = None):
    """Test-only: deterministic LLM explain response for UI/E2E tests.

    When `PLATFORM_LITE_INIT=1` or `TEST_HELPERS_ENABLED=1` this endpoint
    returns a stable explain payload to avoid flakiness in tests and to let
    Playwright exercise copy/export behavior against a real backend route.
    """
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} and os.getenv('TEST_HELPERS_ENABLED','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=404, detail='not_found')
    # Deterministic explain body
    body = {
        'narrative': 'Deterministic explain narrative for tests.',
        'summary': 'Deterministic LLM summary: investigate seed artifacts',
        'evidence': 'Seeded evidence: powerscan.exe, deadbeef, hosts: DESKTOP-A1B2C3',
        'factors': ['high_entropy', 'signature_mismatch'],
        'recommendations': ['isolate_host', 'collect_memory'],
        'confidence': 0.87,
    }
    return body
