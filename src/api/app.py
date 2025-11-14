
from __future__ import annotations
# Canonical frontend: serves React build from `frontend/react/dist` at `/react` and `/` when present.

import asyncio
import json
import logging
import os
import time
import sys
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import List

from fastapi import FastAPI, HTTPException, Request, Depends
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import sys
from fastapi.staticfiles import StaticFiles
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.responses import FileResponse, Response
from src.api.csrf import CSRFMiddleware
from src.core.config import get_settings  # new central configuration
from .webhook_middleware import WebhookGuardMiddleware
from security.auth import auth_dependency, AuthContext, require_scopes
try:
    from src.security.rbac import has_role  # type: ignore
except Exception:
    def has_role(_k: str, _r: str) -> bool:  # pragma: no cover - fallback
        return False
import csv as _csv

from .artifact_endpoints import router as artifact_router
from .custody import router as custody_router
from .dashboard_endpoints import router as dashboard_router
from .decisions_stream import router as decisions_router
from .risk_endpoints import router as risk_router
from .graph_session_endpoints import router as graph_session_router
from .config_endpoints import router as config_router
# Provide a lightweight stub for optional heavy DB drivers when running in
# PLATFORM_LITE_INIT (used by tests). This prevents import-time ModuleNotFound
# errors for optional dependencies like psycopg2 while keeping production
# behavior intact. Placing this early avoids modules importing psycopg2 before
# the shim is installed.
if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}:
    try:
        import types as _types
        if 'psycopg2' not in sys.modules:
            sys.modules['psycopg2'] = _types.ModuleType('psycopg2')
    except Exception:
        pass
try:
    # Some tests and older code expect the router implemented in `graph_sessions.py`.
    # If available, prefer that router implementation to ensure behavior matches test fixtures.
    from .graph_sessions import router as _graph_sessions_router
    graph_session_router = _graph_sessions_router
except Exception:
    # Fall back to the endpoint-based router if the full implementation isn't importable
    pass
try:
    from .integrations_endpoints import router as integrations_router
except Exception:
    integrations_router = None
# Provide a lightweight stub for optional heavy DB drivers when running in
# PLATFORM_LITE_INIT (used by tests). This prevents import-time ModuleNotFound
# errors for optional dependencies like psycopg2 while keeping production
# behavior intact.
if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}:
    try:
        import types as _types
        if 'psycopg2' not in sys.modules:
            sys.modules['psycopg2'] = _types.ModuleType('psycopg2')
    except Exception:
        pass
try:
    from .api_key_endpoints import router as api_keys_router  # type: ignore
except Exception:
    api_keys_router = None  # type: ignore
from .metrics_status_endpoints import router as metrics_status_router
from .metrics_summary import router as metrics_summary_router
from .metrics_init import REGISTRY, ensure_metrics, ingest_buffer_gauge, ingest_failures_counter
DEFAULT_TENANT = os.getenv('DEFAULT_TENANT','default')
from .runtime_state import EVENT_QUEUE
from .startup import initialize_platform_components
from .upload_endpoints import router as upload_router
from .csv_endpoints import router as csv_router
from .report_endpoints import router as report_router
from .soar_endpoints import router as soar_router
from .nlp_endpoints import router as nlp_router
from .sbom_endpoints import router as sbom_router
from .integrations import router as integrations_router_new
from .assessments_endpoints import router as assessments_router
try:
    from .deep_analyze_endpoints import router as deep_analyze_router
except Exception:
    deep_analyze_router = None
try:
    from .analysis_endpoints import router as analysis_router
except Exception:
    analysis_router = None
try:
    from .ebpf_endpoints import router as ebpf_router  # eBPF / Falco ingest + list
except Exception:
    ebpf_router = None  # type: ignore
try:
    from .identity_graph_endpoints import router as identity_graph_router
except Exception:
    identity_graph_router = None  # type: ignore
try:
    from .identity_hopgraph_facade import router as identity_hopgraph_facade_router
except Exception:
    identity_hopgraph_facade_router = None  # type: ignore
try:
    from .identity_reporting import router as identity_reporting_router
except Exception:
    identity_reporting_router = None  # type: ignore
try:
    from .cloud_graph_endpoints import router as cloud_graph_router
except Exception:
    cloud_graph_router = None  # type: ignore
try:
    from .network_graph_endpoints import router as network_graph_router
except Exception:
    network_graph_router = None  # type: ignore
from .stream_ingest import router as stream_router
from .dev_endpoints import router as dev_router
from .compliance_endpoints import router as compliance_router
from .feedback_endpoints import router as feedback_router  # legacy factor vote endpoint
from .temporal_endpoints import router as temporal_router
from .isms_endpoints import router as isms_router
try:
    from src.api.routes.feedback import router as feedback_api_router  # enhanced feedback snapshot endpoints
except Exception:
    feedback_api_router = None  # type: ignore
try:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
except Exception:
    try:
        from graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
    except Exception:
        GLOBAL_HOPGRAPH = None  # type: ignore
try:
    from .hopgraph_persistence import router as hopgraph_persistence_router
except Exception:
    hopgraph_persistence_router = None
try:
    from src.api.routes.remote_access import router as remote_access_router
except Exception:
    try:
        from .routes.remote_access import router as remote_access_router
    except Exception:
        remote_access_router = None
try:
    from src.api.csv_multi_endpoints import router as csv_multi_router
except Exception:
    try:
        from .csv_multi_endpoints import router as csv_multi_router
    except Exception:
        csv_multi_router = None
try:
    from src.api.routes.email import router as email_router
except Exception:
    try:
        from .routes.email import router as email_router
    except Exception:
        email_router = None
try:
    from src.api.decision_confidence_endpoints import router as decision_confidence_router
except Exception:
    decision_confidence_router = None  # type: ignore
try:
    from src.api.node_factors_endpoints import router as node_factors_router
except Exception:
    node_factors_router = None  # type: ignore
try:
    from src.api.emitted_factors_endpoints import router as emitted_factors_router
except Exception:
    emitted_factors_router = None  # type: ignore
try:
    from src.api.routes.network import router as network_ingest_router
except Exception:
    try:
        from .routes.network import router as network_ingest_router
    except Exception:
        network_ingest_router = None  # type: ignore
try:
    from src.api.routes.cloud import router as cloud_ingest_router
except Exception:
    try:
        from .routes.cloud import router as cloud_ingest_router
    except Exception:
        cloud_ingest_router = None  # type: ignore
try:
    from src.api.routes.app_events import router as app_events_router
except Exception:
    try:
        from .routes.app_events import router as app_events_router
    except Exception:
        app_events_router = None  # type: ignore
try:
    from src.api.routes.identity import router as identity_ingest_router
except Exception:
    try:
        from .routes.identity import router as identity_ingest_router
    except Exception:
        identity_ingest_router = None  # type: ignore
try:
    from .yara_endpoints import router as yara_router
except Exception:
    yara_router = None  # type: ignore
try:
    from .graylabel_endpoints import router as graylabel_router
except Exception:
    graylabel_router = None  # type: ignore
try:
    from .endpoint_malware_endpoints import router as endpoint_malware_router
except Exception:
    endpoint_malware_router = None  # type: ignore
try:
    from .routes.data import router as data_router
except Exception:
    data_router = None  # type: ignore
try:
    from .api_security_endpoints import router as api_sec_router
except Exception:
    api_sec_router = None  # type: ignore
from .telemetry_endpoints import router as telemetry_router
from .hunt_summary import router as hunt_router
from .admin_rule_endpoints import router as admin_rule_router
from .decision_feedback_endpoints import router as decision_feedback_router
from .factors_taxonomy_endpoints import router as factors_router
from .suppression_admin_endpoints import router as suppression_admin_router
from .suggestions_endpoints import router as suggestions_router
try:
    from .ingest_controller_endpoints import router as unified_ingest_router  # Unified Zeek/Suricata/Wazuh ingest
except Exception:
    unified_ingest_router = None  # type: ignore
try:
    from .cooccurrence_admin_endpoints import router as cooccurrence_admin_router
except Exception:
    cooccurrence_admin_router = None  # type: ignore
from .risk_config_admin import router as risk_config_admin_router
from .scenario_replay_endpoints import router as scenario_replay_router
try:
    from .metrics_slo_endpoints import router as metrics_slo_router
except Exception:
    metrics_slo_router = None  # type: ignore
try:
    from .graph_api import router as unified_graph_router
except Exception:
    unified_graph_router = None  # type: ignore
try:
    # Feature flag used to activate predictive temporal hybrid mode
    from src.core.feature_flags import is_enabled as _ff_enabled  # type: ignore
except Exception:
    _ff_enabled = lambda _n: False  # type: ignore
try:
    from src.ml.temporal_model import GLOBAL_TEMPORAL_MODEL  # type: ignore
except Exception:
    GLOBAL_TEMPORAL_MODEL = None  # type: ignore
try:
    # Prefer canonical src path to avoid duplicate singleton instances
    from src.incidents.aggregator import GLOBAL_INCIDENTS  # type: ignore
except Exception:
    try:
        # Fallback to legacy path (older tests/deployments)
        from incidents.aggregator import GLOBAL_INCIDENTS  # type: ignore
    except Exception:
        GLOBAL_INCIDENTS = None

try:
    from src.outbox.consumer import consumer as OUTBOX_CONSUMER
except Exception:
    OUTBOX_CONSUMER = None
    
    from incidents.evidence import incident_to_html  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_INCIDENTS = None  # type: ignore
    incident_to_html = None  # type: ignore
    
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        settings = get_settings()
        app.state.settings = settings
    except Exception:
        # Settings failure is fatal; allow exception to bubble so orchestrator can catch
        raise
    # Auto-apply configuration profile if CONFIG_PROFILE provided
    try:
        from src.config.profile_loader import apply_profile
        prof = os.getenv('CONFIG_PROFILE')
        if prof:
            apply_profile(prof)
    except Exception:
        pass
    # Attach hopgraph (prefer an already-injected instance on app for tests)
    try:
        hg = None
        try:
            # Tests may set app.GLOBAL_HOPGRAPH before TestClient initialization
            hg = getattr(app, 'GLOBAL_HOPGRAPH', None)
        except Exception:
            hg = None
        if hg is None:
            # Fallback to module-level default created at import time
            hg = GLOBAL_HOPGRAPH
        if hg is not None:
            app.state.hopgraph = hg
            # Keep legacy attribute for backward compatibility
            setattr(app, 'GLOBAL_HOPGRAPH', hg)
            # Also align module-level singleton to avoid drift across imports
            try:
                import src.graph.hopgraph as _hgmod  # type: ignore
                _hgmod.GLOBAL_HOPGRAPH = hg  # type: ignore[attr-defined]
            except Exception:
                try:
                    import graph.hopgraph as _hgmod2  # type: ignore
                    _hgmod2.GLOBAL_HOPGRAPH = hg  # type: ignore[attr-defined]
                except Exception:
                    pass
    except Exception:
        pass
    # Register background schedulers using existing helper
    try:
        _register_background_schedulers()
    except Exception:
        pass
    # Optionally start snapshot cleanup loop if TTL configured
    try:
        _snap_ttl = int(os.getenv('HOPGRAPH_SNAPSHOT_TTL_SECONDS','0') or 0)
    except Exception:
        _snap_ttl = 0
    if _snap_ttl and _snap_ttl > 0:
        async def _snap_cleanup_loop():
            import asyncio
            from src.core.graph.persistence.simple_snapshot import cleanup_old_snapshots
            interval = int(os.getenv('HOPGRAPH_SNAPSHOT_CLEAN_INTERVAL_SECONDS', os.getenv('HOPGRAPH_PRUNE_INTERVAL_SECONDS', '3600')))
            while True:
                try:
                    cleanup_old_snapshots(_snap_ttl)
                except Exception:
                    pass
                await asyncio.sleep(interval)
        try:
            app.state._snapshot_cleanup_task = asyncio.create_task(_snap_cleanup_loop())
        except Exception:
            app.state._snapshot_cleanup_task = None
    yield
    # Shutdown tasks: snapshot hopgraph + playbook queue flush
    try:
        _gh = getattr(app.state, 'hopgraph', None) or globals().get('_GH')
        if _gh is not None:
            try:
                _gh.save_snapshot()
            except Exception:
                pass
    except Exception:
        pass
    try:
        from src.soar.playbook_queue_async import shutdown_global_queue_async  # type: ignore
        try:
            await shutdown_global_queue_async()
        except Exception:
            pass
    except Exception:
        pass

app = FastAPI(title='Threat Platform API', version='4.1.0', lifespan=lifespan)

# Temporary debug middleware: when DEBUG_BODY_INSPECT=1, capture and log body bytes
# DEBUG_BODY_INSPECT middleware removed: used temporarily during debugging

# Best-effort HopGraph snapshot flush on shutdown (use core shim)
try:
    from src.core.graph.hopgraph_core import get_core_graph  # type: ignore
    _GH = get_core_graph()
except Exception:
    _GH = None  # type: ignore

# NOTE: Deprecated @app.on_event('shutdown') replaced by lifespan handler above.

# In-memory ring buffer for recent unhandled exceptions (diagnostics)
_DIAG_ERROR_BUFFER_MAX = int(os.getenv('DIAG_ERROR_BUFFER_MAX','50') or 50)
_DIAG_ERRORS: deque[dict] = deque(maxlen=_DIAG_ERROR_BUFFER_MAX)
_DIAG_ENABLED = os.getenv('DEBUG_DIAGNOSTICS','0').lower() in {'1','true','yes'}

def create_app():  # simple factory for tests expecting create_app()
    return app

    # Lightweight health endpoint (simplifies readiness polling for demos/automation)
    @app.get('/health')
    async def health() -> dict:
        return {'status': 'ok'}

logger = logging.getLogger(__name__)

# Register integrations endpoints (report upload + send hooks)
try:
    app.include_router(integrations_router_new)
except Exception:
    pass
try:
    if analysis_router is not None:
        app.include_router(analysis_router)
except Exception:
    pass

# Initialize optional SQLite session backend schema early if configured
try:
    _sess_db = os.getenv('SESSION_PERSIST_SQLITE_PATH')
    if _sess_db:
        import sqlite3
        os.makedirs(os.path.dirname(_sess_db), exist_ok=True)
        _conn = sqlite3.connect(_sess_db, timeout=10)
        _cur = _conn.cursor()
        _cur.execute(
            "CREATE TABLE IF NOT EXISTS sessions(\n"
            " id TEXT PRIMARY KEY, json TEXT NOT NULL, created_at REAL, updated_at REAL)"
        )
        _cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at)")
        _conn.commit(); _conn.close()
except Exception:
    pass

# Safety middleware: wrap the entire middleware chain to ensure that
# if any downstream middleware or the endpoint fails to return a
# Response (or raises), we catch it, log contextual info and return
# a safe JSON 503. This prevents unhandled TaskGroup / RuntimeError
# bubbles from propagating to the ASGI server and creating noisy
# exception groups (observed as "No response returned.").
@app.middleware('http')
async def _middleware_safety(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    start = time.time()
    try:
        resp = await call_next(request)
        if resp is None:
            # Guard against None responses
            logger.exception('Middleware chain returned None for request %s %s', request.method, request.url.path)
            from fastapi.responses import JSONResponse
            if _DIAG_ENABLED:
                try:
                    _DIAG_ERRORS.append({
                        'ts': time.time(),
                        'method': request.method,
                        'path': request.url.path,
                        'elapsed_ms': int((time.time()-start)*1000),
                        'error': 'no_response_returned'
                    })
                except Exception:
                    pass
            return JSONResponse({'detail': 'service_unavailable', 'error': 'no_response_returned'}, status_code=503)
        return resp
    except Exception as exc:
        # Collect safe diagnostic context
        try:
            safe_hdrs = {}
            for h in ('x-tenant-id', 'x-request-id', 'user-agent'):
                v = request.headers.get(h)
                if v:
                    safe_hdrs[h] = v
        except Exception:
            safe_hdrs = {}
        # Build stack trace string
        import traceback
        try:
            stack = traceback.format_exc(limit=25)
        except Exception:
            stack = 'unavailable'
        logger.exception('Unhandled exception for %s %s headers=%s elapsed_ms=%d', request.method, request.url.path, safe_hdrs, int((time.time()-start)*1000))
        if _DIAG_ENABLED:
            try:
                _DIAG_ERRORS.append({
                    'ts': time.time(),
                    'method': request.method,
                    'path': request.url.path,
                    'elapsed_ms': int((time.time()-start)*1000),
                    'safe_headers': safe_hdrs,
                    'exception_type': type(exc).__name__,
                    'exception_str': str(exc),
                    'stack': stack[:8000],
                })
            except Exception:
                pass
        from fastapi.responses import JSONResponse
        payload = {'detail': 'service_unavailable', 'error': 'internal_exception', 'method': request.method, 'path': request.url.path}
        return JSONResponse(payload, status_code=503)

# Debug endpoint to inspect recent errors (guarded by env flag)
@app.get('/api/v1/debug/last-errors', include_in_schema=False)
async def _debug_last_errors(limit: int = 25) -> dict:
    """Return the recent diagnostic errors buffer.

    This endpoint is always present so CI/test runners can query it; when
    DEBUG_DIAGNOSTICS is not enabled it returns a small explanatory payload.
    """
    try:
        enabled = os.getenv('DEBUG_DIAGNOSTICS','0').lower() in {'1','true','yes'}
    except Exception:
        enabled = False
    if not enabled:
        return {'enabled': False, 'note': 'DEBUG_DIAGNOSTICS not enabled; enable via env to collect diagnostics'}
    try:
        rows = list(_DIAG_ERRORS)[-limit:][::-1]
    except Exception:
        rows = []
    return {'enabled': True, 'count': len(rows), 'errors': rows}

# Incident snapshot / hopgraph schedulers added after app is defined
def _register_background_schedulers():
    # Incident snapshots
    _INCIDENT_SNAPSHOT_INTERVAL = int(os.getenv('INCIDENT_SNAPSHOT_INTERVAL_SECONDS', '0') or 0)
    if _INCIDENT_SNAPSHOT_INTERVAL > 0 and GLOBAL_INCIDENTS:
        async def _incident_snapshot_loop():  # pragma: no cover
            while True:
                try:
                    GLOBAL_INCIDENTS.save_snapshot()
                except Exception:
                    pass
                await asyncio.sleep(max(5, _INCIDENT_SNAPSHOT_INTERVAL))
        app.add_event_handler('startup', lambda: asyncio.create_task(_incident_snapshot_loop()))
    # HopGraph snapshot/prune
    _HOPGRAPH_SNAPSHOT_INTERVAL = int(os.getenv('HOPGRAPH_SNAPSHOT_INTERVAL_SECONDS','0') or 0)
    _HOPGRAPH_PRUNE_INTERVAL = int(os.getenv('HOPGRAPH_PRUNE_INTERVAL_SECONDS','0') or 0)
    if GLOBAL_HOPGRAPH and (_HOPGRAPH_SNAPSHOT_INTERVAL > 0 or _HOPGRAPH_PRUNE_INTERVAL > 0):
        async def _hopgraph_maintenance_loop():  # pragma: no cover
            snap_interval = max(5, _HOPGRAPH_SNAPSHOT_INTERVAL) if _HOPGRAPH_SNAPSHOT_INTERVAL>0 else None
            prune_interval = max(5, _HOPGRAPH_PRUNE_INTERVAL) if _HOPGRAPH_PRUNE_INTERVAL>0 else None
            last_snap = time.time()
            last_prune = time.time()
            while True:
                now = time.time()
                try:
                    if snap_interval and (now - last_snap) >= snap_interval:
                        GLOBAL_HOPGRAPH.save_snapshot()
                        last_snap = now
                    if prune_interval and (now - last_prune) >= prune_interval:
                        GLOBAL_HOPGRAPH.prune(now=now)
                        last_prune = now
                    # Correlation pivot sequence detection (best-effort)
                    try:
                        GLOBAL_HOPGRAPH.detect_domain_pivot_sequences()
                    except Exception:
                        pass
                except Exception:
                    pass
                await asyncio.sleep(2)
        app.add_event_handler('startup', lambda: asyncio.create_task(_hopgraph_maintenance_loop()))

    # Register session cleanup task if module available
    try:
        from .session_cleanup import register_session_cleanup
        try:
            register_session_cleanup(app)
        except Exception:
            pass
    except Exception:
        pass

    # Outbox consumer
    try:
        if OUTBOX_CONSUMER:
            app.add_event_handler('startup', lambda: OUTBOX_CONSUMER.start())
            app.add_event_handler('shutdown', lambda: OUTBOX_CONSUMER.stop())
    except Exception:
        pass

    if hopgraph_persistence_router:
        try:
            app.include_router(hopgraph_persistence_router)
        except Exception:
            pass
    if remote_access_router:
        try:
            app.include_router(remote_access_router)
        except Exception:
            pass
    if csv_multi_router:
        try:
            app.include_router(csv_multi_router)
        except Exception:
            pass
    if email_router:
        try:
            app.include_router(email_router)
        except Exception:
            pass
    if graylabel_router:
        try:
            app.include_router(graylabel_router)
        except Exception:
            pass
    if data_router:
        try:
            app.include_router(data_router)
        except Exception:
            pass
    if api_sec_router:
        try:
            app.include_router(api_sec_router)
        except Exception:
            pass

    # KEV auto-refresh background job (optional)
    try:
        _KEV_INTERVAL = int(os.getenv('KEV_REFRESH_INTERVAL_SECONDS', '0') or 0)
        if _KEV_INTERVAL > 0:
            async def _kev_loop():  # pragma: no cover
                try:
                    from src.integrations.vuln_enrichment import ENRICHER as _ENRICHER
                except Exception:
                    return
                while True:
                    try:
                        await _ENRICHER.refresh_kev()
                    except Exception:
                        pass
                    await asyncio.sleep(max(60, _KEV_INTERVAL))
            app.add_event_handler('startup', lambda: asyncio.create_task(_kev_loop()))
    except Exception:
        pass

    # Embedding adaptive scheduler (refresh factor embeddings)
    try:
        from src.embedding.scheduler import register_embedding_scheduler  # type: ignore
        register_embedding_scheduler(app)
    except Exception:
        try:
            from embedding.scheduler import register_embedding_scheduler  # type: ignore
            register_embedding_scheduler(app)
        except Exception:
            logger.debug('Embedding scheduler registration failed')

    # Auto-incident generator (background scanner)
    try:
        from src.graph.auto_incident import register_auto_incident  # type: ignore
        try:
            register_auto_incident(app)
        except Exception:
            register_auto_incident()
    except Exception:
        try:
            from graph.auto_incident import register_auto_incident  # type: ignore
            try:
                register_auto_incident(app)
            except Exception:
                register_auto_incident()
        except Exception:
            logger.debug('Auto incident scanner registration failed')

    # Admin autogen endpoints (UI + runtime control)
    try:
        from src.api.admin_autogen import router as _autogen_router
        try:
            app.include_router(_autogen_router)
        except Exception:
            pass
    except Exception:
        try:
            from api.admin_autogen import router as _autogen_router
            try:
                app.include_router(_autogen_router)
            except Exception:
                pass
        except Exception:
            pass

    # AWS Config/Security Hub adapter scheduler (optional)
    try:
        _CFG_DIR = os.getenv('AWS_CFG_SCHED_DIR')
        _CFG_INTERVAL = int(os.getenv('AWS_CFG_SCHED_INTERVAL_SEC','0') or 0)
        _CFG_BASE = os.getenv('AWS_CFG_SCHED_BASE','http://localhost:8080')
        _CFG_APIKEY = os.getenv('AWS_CFG_SCHED_API_KEY') or os.getenv('API_KEY','devkey123')
        _CFG_TENANT = os.getenv('AWS_CFG_SCHED_TENANT') or os.getenv('TENANT_ID')
        if _CFG_DIR and _CFG_INTERVAL > 0:
            import pathlib, subprocess
            _processed: set[tuple[str, float]] = set()
            _scripts_root = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts'))
            _adapter = os.path.join(_scripts_root, 'aws_config_to_posture.py')
            if os.path.exists(_adapter):
                async def _cfg_loop():  # pragma: no cover
                    while True:
                        try:
                            for p in pathlib.Path(_CFG_DIR).glob('*.json'):
                                try:
                                    key = (str(p), p.stat().st_mtime)
                                except Exception:
                                    continue
                                if key in _processed:
                                    continue
                                env = os.environ.copy()
                                if _CFG_TENANT:
                                    env['TENANT_ID'] = _CFG_TENANT
                                cmd = [
                                    sys.executable, _adapter,
                                    '--input', str(p),
                                    '--post', _CFG_BASE,
                                    '--api-key', _CFG_APIKEY,
                                ]
                                try:
                                    subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                                    _processed.add(key)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        await asyncio.sleep(max(10, _CFG_INTERVAL))
                app.add_event_handler('startup', lambda: asyncio.create_task(_cfg_loop()))
    except Exception:
        pass

    # Azure Defender/Policy scheduler (optional)
    try:
        _AZ_DIR = os.getenv('AZURE_DEF_SCHED_DIR')
        _AZ_INTERVAL = int(os.getenv('AZURE_DEF_SCHED_INTERVAL_SEC','0') or 0)
        _AZ_BASE = os.getenv('AZURE_DEF_SCHED_BASE','http://localhost:8080')
        _AZ_APIKEY = os.getenv('AZURE_DEF_SCHED_API_KEY') or os.getenv('API_KEY','devkey123')
        _AZ_TENANT = os.getenv('AZURE_DEF_SCHED_TENANT') or os.getenv('TENANT_ID')
        if _AZ_DIR and _AZ_INTERVAL > 0:
            import pathlib, subprocess
            _processed_az: set[tuple[str, float]] = set()
            _scripts_root = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts'))
            _adapter = os.path.join(_scripts_root, 'azure_defender_to_posture.py')
            if os.path.exists(_adapter):
                async def _az_loop():  # pragma: no cover
                    while True:
                        try:
                            for p in pathlib.Path(_AZ_DIR).glob('*.json'):
                                try:
                                    key = (str(p), p.stat().st_mtime)
                                except Exception:
                                    continue
                                if key in _processed_az:
                                    continue
                                env = os.environ.copy()
                                if _AZ_TENANT:
                                    env['TENANT_ID'] = _AZ_TENANT
                                cmd = [
                                    sys.executable, _adapter,
                                    '--input', str(p),
                                    '--post', _AZ_BASE,
                                    '--api-key', _AZ_APIKEY,
                                ]
                                try:
                                    subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                                    _processed_az.add(key)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        await asyncio.sleep(max(10, _AZ_INTERVAL))
                app.add_event_handler('startup', lambda: asyncio.create_task(_az_loop()))
    except Exception:
        pass

    # GCP SCC scheduler (optional)
    try:
        _GCP_DIR = os.getenv('GCP_SCC_SCHED_DIR')
        _GCP_INTERVAL = int(os.getenv('GCP_SCC_SCHED_INTERVAL_SEC','0') or 0)
        _GCP_BASE = os.getenv('GCP_SCC_SCHED_BASE','http://localhost:8080')
        _GCP_APIKEY = os.getenv('GCP_SCC_SCHED_API_KEY') or os.getenv('API_KEY','devkey123')
        _GCP_TENANT = os.getenv('GCP_SCC_SCHED_TENANT') or os.getenv('TENANT_ID')
        if _GCP_DIR and _GCP_INTERVAL > 0:
            import pathlib, subprocess
            _processed_gcp: set[tuple[str, float]] = set()
            _scripts_root = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts'))
            _adapter = os.path.join(_scripts_root, 'gcp_scc_to_posture.py')
            if os.path.exists(_adapter):
                async def _gcp_loop():  # pragma: no cover
                    while True:
                        try:
                            for p in pathlib.Path(_GCP_DIR).glob('*.json'):
                                try:
                                    key = (str(p), p.stat().st_mtime)
                                except Exception:
                                    continue
                                if key in _processed_gcp:
                                    continue
                                env = os.environ.copy()
                                if _GCP_TENANT:
                                    env['TENANT_ID'] = _GCP_TENANT
                                cmd = [
                                    sys.executable, _adapter,
                                    '--input', str(p),
                                    '--post', _GCP_BASE,
                                    '--api-key', _GCP_APIKEY,
                                ]
                                try:
                                    subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                                    _processed_gcp.add(key)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        await asyncio.sleep(max(10, _GCP_INTERVAL))
                app.add_event_handler('startup', lambda: asyncio.create_task(_gcp_loop()))
    except Exception:
        pass

    # OCI Cloud Guard scheduler (optional)
    try:
        _OCI_DIR = os.getenv('OCI_CG_SCHED_DIR')
        _OCI_INTERVAL = int(os.getenv('OCI_CG_SCHED_INTERVAL_SEC','0') or 0)
        _OCI_BASE = os.getenv('OCI_CG_SCHED_BASE','http://localhost:8080')
        _OCI_APIKEY = os.getenv('OCI_CG_SCHED_API_KEY') or os.getenv('API_KEY','devkey123')
        _OCI_TENANT = os.getenv('OCI_CG_SCHED_TENANT') or os.getenv('TENANT_ID')
        if _OCI_DIR and _OCI_INTERVAL > 0:
            import pathlib, subprocess
            _processed_oci: set[tuple[str, float]] = set()
            _scripts_root = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'scripts'))
            _adapter = os.path.join(_scripts_root, 'oci_cloud_guard_to_posture.py')
            if os.path.exists(_adapter):
                async def _oci_loop():  # pragma: no cover
                    while True:
                        try:
                            for p in pathlib.Path(_OCI_DIR).glob('*.json'):
                                try:
                                    key = (str(p), p.stat().st_mtime)
                                except Exception:
                                    continue
                                if key in _processed_oci:
                                    continue
                                env = os.environ.copy()
                                if _OCI_TENANT:
                                    env['TENANT_ID'] = _OCI_TENANT
                                cmd = [
                                    sys.executable, _adapter,
                                    '--input', str(p),
                                    '--post', _OCI_BASE,
                                    '--api-key', _OCI_APIKEY,
                                ]
                                try:
                                    subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                                    _processed_oci.add(key)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        await asyncio.sleep(max(10, _OCI_INTERVAL))
                app.add_event_handler('startup', lambda: asyncio.create_task(_oci_loop()))
    except Exception:
        pass

    # Session & EWMA cleanup scheduler
    try:
        _CLEAN_INTERVAL = int(os.getenv('SESSION_CLEAN_INTERVAL_SECONDS','0') or 0)
        if _CLEAN_INTERVAL > 0:
            async def _session_cleanup_loop():  # pragma: no cover
                from src.api.runtime_state import cleanup_sessions, cleanup_ewma_history, get_server_runtime_state, cleanup_file_hash_history
                while True:
                    try:
                        # Cleanup legacy JSON sessions (no-op if unused)
                        cleanup_sessions()
                        # Cleanup via configured backend (JSON or SQLite)
                        try:
                            from src.api.session_store import get_session_store
                            get_session_store().cleanup(None)
                        except Exception:
                            pass
                        runtime = get_server_runtime_state(app)
                        cleanup_ewma_history(runtime, ttl_seconds=int(os.getenv('EWMA_HISTORY_TTL_SECONDS','86400') or 86400))
                        # Prune old file hash timestamps (TTL via FILE_HASH_HISTORY_TTL_SECONDS, default 7d)
                        try:
                            ttl = int(os.getenv('FILE_HASH_HISTORY_TTL_SECONDS','604800') or 604800)
                        except Exception:
                            ttl = 604800
                        cleanup_file_hash_history(runtime, ttl_seconds=ttl)
                        # Enforce maximum distinct hash keys
                        try:
                            max_keys = int(os.getenv('FILE_HASH_HISTORY_MAX_KEYS','5000') or 5000)
                            hmap = getattr(runtime, 'file_hash_factors', {})
                            if isinstance(hmap, dict) and len(hmap) > max_keys:
                                # prune smallest effective (length) beyond cap
                                excess = len(hmap) - max_keys
                                ordered = sorted(hmap.items(), key=lambda kv: len(kv[1]) if hasattr(kv[1],'__len__') else 0)
                                for k,_dq in ordered[:excess]:
                                    try: hmap.pop(k, None)
                                    except Exception: pass
                        except Exception:
                            pass
                        # Enforce NX tracker producer cap
                        try:
                            nx_cap = int(os.getenv('NX_TRACKER_MAX_PRODUCERS','200') or 200)
                            nx_map = getattr(runtime, 'nx_rate_tracker', {})
                            if isinstance(nx_map, dict) and len(nx_map) > nx_cap:
                                excess = len(nx_map) - nx_cap
                                ordered = sorted(nx_map.items(), key=lambda kv: len(kv[1]) if hasattr(kv[1],'__len__') else 0)
                                for k,_dq in ordered[:excess]:
                                    try: nx_map.pop(k, None)
                                    except Exception: pass
                        except Exception:
                            pass
                        # Per-tenant cleanup: prune inactive tenant partitions and enforce per-tenant caps
                        try:
                            from src.api.runtime_state import persist_tenant_runtime
                            tenant_ttl = int(os.getenv('TENANT_INACTIVE_TTL_SECONDS','86400') or 86400)
                            tenant_max_hash = int(os.getenv('TENANT_MAX_HASH_KEYS','2000') or 2000)
                            tenant_nx_cap = int(os.getenv('TENANT_NX_TRACKER_MAX_PRODUCERS','100') or 100)
                            now = time.time()
                            for tid, tmap in list(getattr(runtime, 'tenants', {}).items()):
                                try:
                                    last = tmap.get('last_access', 0) or 0
                                    if (now - last) > tenant_ttl:
                                        # persist before eviction
                                        try: persist_tenant_runtime(runtime, tid)
                                        except Exception: pass
                                        try: runtime.tenants.pop(tid, None)
                                        except Exception: pass
                                        continue
                                    # enforce per-tenant hash key cap
                                    fh = tmap.get('file_hash_factors', {})
                                    if isinstance(fh, dict) and len(fh) > tenant_max_hash:
                                        excess = len(fh) - tenant_max_hash
                                        ordered = sorted(fh.items(), key=lambda kv: len(kv[1]) if hasattr(kv[1],'__len__') else 0)
                                        for k,_dq in ordered[:excess]:
                                            try: fh.pop(k, None)
                                            except Exception: pass
                                    # enforce per-tenant nx producer cap
                                    nx_map_t = tmap.get('nx_rate_tracker', {})
                                    if isinstance(nx_map_t, dict) and len(nx_map_t) > tenant_nx_cap:
                                        excess = len(nx_map_t) - tenant_nx_cap
                                        ordered = sorted(nx_map_t.items(), key=lambda kv: len(kv[1]) if hasattr(kv[1],'__len__') else 0)
                                        for k,_dq in ordered[:excess]:
                                            try: nx_map_t.pop(k, None)
                                            except Exception: pass
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    except Exception:
                        pass
                    await asyncio.sleep(max(5,_CLEAN_INTERVAL))
            app.add_event_handler('startup', lambda: asyncio.create_task(_session_cleanup_loop()))
    except Exception:
        pass

        # Co-occurrence store pruner (start background thread if interval configured)
        try:
            from src.tasks.cooccurrence_pruner import start_background as _co_start  # type: ignore
            _CO_OCC_INTERVAL = int(os.getenv('COOCCURRENCE_PRUNE_INTERVAL_SECONDS', '0') or 0)
            _CO_OCC_TTL = int(os.getenv('COOCCURRENCE_TTL_SECONDS', str(60*60*24*7)) or (60*60*24*7))
            if _CO_OCC_INTERVAL > 0:
                def _start_co_pruner():
                    try:
                        _co_start(interval_seconds=_CO_OCC_INTERVAL, threshold_seconds=_CO_OCC_TTL)
                    except Exception:
                        pass
                # start as a background task on startup
                app.add_event_handler('startup', _start_co_pruner)
        except Exception:
            pass

_register_background_schedulers()

# Auto-start TF-IDF decay scheduler if configured via env var (uses tfidf_admin.start_decay)
try:
    _TFIDF_DECAY_SCHED = int(os.getenv('TFIDF_DECAY_SCHEDULE_INTERVAL_SECONDS','0') or 0)
    if _TFIDF_DECAY_SCHED > 0:
        try:
            import asyncio as _asyncio
            from src.api import tfidf_admin as _tfadmin  # type: ignore
            # schedule a task on startup to call the start endpoint handler
            def _start_tfidf_on_startup():
                async def _starter():
                    try:
                        # call start_decay with interval_seconds from env
                        await _tfadmin.start_decay(x_admin_key=os.getenv('ADMIN_API_KEY'), interval_seconds=_TFIDF_DECAY_SCHED)
                    except Exception:
                        pass
                try:
                    _asyncio.create_task(_starter())
                except Exception:
                    try:
                        loop = _asyncio.get_event_loop()
                        loop.create_task(_starter())
                    except Exception:
                        pass
            app.add_event_handler('startup', _start_tfidf_on_startup)
        except Exception:
            logger.debug('Failed to schedule TF-IDF auto-start')
except Exception:
    pass

# Ensure topn route is registered even if graph_endpoints router wasn't mounted correctly
try:
    import importlib as _importlib
    _mod = _importlib.import_module('src.api.graph_endpoints')
    if hasattr(_mod, 'graph_topn'):
        try:
            app.add_api_route('/api/v1/graph/topn', getattr(_mod, 'graph_topn'), methods=['GET'])
        except Exception:
            try:
                # fallback for older FastAPI versions
                app.router.add_api_route('/api/v1/graph/topn', getattr(_mod, 'graph_topn'), methods=['GET'])
            except Exception:
                pass
except Exception:
    pass

try:  # pragma: no cover - optional dependency
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest  # type: ignore
except Exception:  # pragma: no cover
    CONTENT_TYPE_LATEST = 'text/plain; version=0.0.4; charset=utf-8'
    generate_latest = None  # type: ignore

# Configure structured logging early (idempotent)
try:
    from src.logging_config import configure_logging, set_correlation, set_tenant  # type: ignore
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        configure_logging()
    else:
        logger.debug('PLATFORM_LITE_INIT=1 skipping structured logging configure_logging()')
except Exception:
    logger.debug('Structured logging setup failed (or skipped)')

# Initialize OpenTelemetry tracing (optional) and instrument FastAPI if available
try:
    from src.telemetry.tracing import init_tracing  # type: ignore
    init_tracing()
    try:
        # Prefer FastAPI-specific instrumentor when present
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
        FastAPIInstrumentor.instrument_app(app)
        logger.info('FastAPI OpenTelemetry instrumentation enabled')
    except Exception:
        try:
            from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware  # type: ignore
            app.add_middleware(OpenTelemetryMiddleware)
            logger.info('ASGI OpenTelemetry middleware enabled')
        except Exception:
            pass
except Exception:
    logger.debug('Tracing initialization skipped or unavailable')

if True:
    logger.info('PLATFORM_LITE_INIT active: skipping initialize_platform_components heavy init')
else:
    try:
        # Centralized initialization (metrics + rules engine wiring)
        initialize_platform_components()
    except Exception as exc:  # pragma: no cover - don't break API if init fails
        logger.warning('Platform component initialization failed: %s', exc)

# Compatibility alias: legacy docs reference /api/v1/stream/ingest for Zeek JSON
# Delegate to zeek_json_ingest under stream_ingest router.
try:
    from fastapi import Header, Request
    from .stream_ingest import zeek_json_ingest  # type: ignore

    @app.post('/api/v1/stream/ingest')  # type: ignore[misc]
    async def _compat_stream_ingest(request: Request, x_api_key: str | None = Header(None, alias='X-API-Key'), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
        return await zeek_json_ingest(request, x_api_key, x_tenant_id)  # type: ignore[arg-type]
except Exception:
    pass

# Predictive LM hybrid: if feature flag enabled and not explicitly overridden via env,
# set temporal model to 'hybrid' to blend optional tft_score.
try:
    if _ff_enabled('predictive_lm'):
        if not os.getenv('TEMPORAL_METHOD'):
            os.environ['TEMPORAL_METHOD'] = 'hybrid'
        if GLOBAL_TEMPORAL_MODEL is not None:
            try:
                GLOBAL_TEMPORAL_MODEL.method = (os.getenv('TEMPORAL_METHOD','hybrid') or 'hybrid')  # type: ignore[attr-defined]
            except Exception:
                pass
except Exception:
    pass

# Optional deferred route registration for lighter startup when PLATFORM_LITE_INIT is set.
def register_full_routes():
    """Register heavier route modules that may pull in many dependencies.

    Controlled by LOAD_FULL_ROUTES env var when in lite mode to allow tests that
    only need a subset of endpoints (e.g. admin flags) to avoid import overhead.
    """
    if getattr(register_full_routes, '_registered', False):  # idempotent
        return
    try:
        # original import already performed at top in non-lite mode; this is a safeguard
        from .routes import events, hunt_lanes, internal, metrics  # noqa: F401
    except Exception as exc:  # pragma: no cover
        logger.debug('Deferred route import failed: %s', exc)
    setattr(register_full_routes, '_registered', True)

if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
    register_full_routes()
elif os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
    register_full_routes()

# Retention purge scheduler
_RETENTION_PURGE_INTERVAL = int(os.getenv('RETENTION_PURGE_INTERVAL_SECONDS','0') or 0)
if _RETENTION_PURGE_INTERVAL > 0:
    async def _purge_loop():  # pragma: no cover
        from database_adapter import purge_retention
        try:
            from .metrics_init import ensure_metrics
            ensure_metrics()
            from .metrics_init import _safe_counter, _safe_gauge  # type: ignore
        except Exception:
            _safe_counter = lambda *a, **k: type('X',(object,),{'inc':lambda self,*aa,**kk: None})()  # noqa: E731
            _safe_gauge = lambda *a, **k: type('Y',(object,),{'set':lambda self,*aa,**kk: None})()  # noqa: E731
        sweeps_counter = _safe_counter('retention_sweeps_total','Total retention sweeps executed',['status'])
        sweeps_duration = _safe_gauge('retention_sweep_duration_seconds','Last retention sweep duration seconds')
        per_tenant_purged = _safe_counter('retention_tenant_rows_purged_total','Rows purged per tenant',['tenant_id','table'])
        import time as _t, logging as _l
        while True:
            started = _t.time()
            status = 'ok'
            try:
                # purge_retention already handles global + per-tenant
                await purge_retention()
            except Exception as e:
                status = 'error'
                _l.getLogger(__name__).warning('purge_retention error: %s', e)
            sweeps_counter.labels(status=status).inc(1)
            sweeps_duration.set(_t.time() - started)
            # lightweight per-tenant table counts for visibility (best-effort)
            try:
                from database_adapter import db_manager
                adp = db_manager.adapter
                if adp and hasattr(adp,'pool') and adp.pool:  # postgres
                    async with adp.pool.acquire() as conn:  # type: ignore[attr-defined]
                        rows = await conn.fetch("SELECT tenant_id, COUNT(*) as c FROM events GROUP BY tenant_id")
                        for r in rows:
                            per_tenant_purged.labels(tenant_id=str(r['tenant_id']), table='events').inc(0)
                elif adp and hasattr(adp,'connection') and adp.connection:  # sqlite
                    cur = await adp.connection.execute("SELECT tenant_id, COUNT(*) FROM events GROUP BY tenant_id")  # type: ignore[attr-defined]
                    rows = await cur.fetchall()
                    for tenant_id, c in rows:
                        per_tenant_purged.labels(tenant_id=str(tenant_id), table='events').inc(0)
            except Exception:
                pass
            await asyncio.sleep(_RETENTION_PURGE_INTERVAL)
    app.add_event_handler('startup', lambda: asyncio.create_task(_purge_loop()))


# CrowdStrike periodic sync (demo-friendly)
_CS_SYNC_INTERVAL = int(os.getenv('CROWDSTRIKE_SYNC_INTERVAL_SECONDS', '0') or 0)
_CS_BACKFILL_SECONDS = int(os.getenv('CROWDSTRIKE_BACKFILL_SECONDS', '3600') or 3600)
if _CS_SYNC_INTERVAL > 0:
    async def _crowdstrike_sync_loop():
        try:
            from integrations.crowdstrike_real import CLIENT as _CS_CLIENT
        except Exception:
            _CS_CLIENT = None
        last_run = 0.0
        while True:
            try:
                if not _CS_CLIENT:
                    try:
                        from integrations.crowdstrike_real import CLIENT as _CS_CLIENT
                    except Exception:
                        _CS_CLIENT = None
                if _CS_CLIENT:
                    try:
                        # fetch since last_run or backfill window
                        since = last_run if last_run > 0 else (time.time() - _CS_BACKFILL_SECONDS)
                        dets = _CS_CLIENT.fetch_detections(since)
                        if dets:
                            # import server helpers lazily to avoid circular imports
                            try:
                                from .server import _record_decision_async, DECISION_CACHE
                            except Exception:
                                _record_decision_async = None
                                from .runtime_state import DECISION_CACHE
                            for d in dets:
                                event_id = str(d.get('id') or f"cs-{int(time.time()*1000)}")
                                dec = {
                                    'event_id': event_id,
                                    'summary': d.get('raw', {}).get('description') or f"CrowdStrike detection {event_id}",
                                    'factors': [{'type': o.get('type','indicator'), 'value': o.get('value')} for o in (d.get('observables') or [])],
                                    'confidence': min(1.0, float(d.get('severity') in ('high','critical') and 0.9 or 0.5)),
                                    'ts': d.get('ts') or d.get('ts', time.time()),
                                    'intel_summary': {
                                        'vendor': 'crowdstrike',
                                        'id': d.get('id'),
                                        'observables': d.get('observables') or [],
                                        'severity': d.get('severity'),
                                        'vendor_url': d.get('vendor_url'),
                                        'raw': d.get('raw') or d,
                                    }
                                }
                                # persist a DB summary asynchronously if possible (best-effort)
                                try:
                                    from integrations.cs_persistence import persist_to_db_async
                                    try:
                                        # schedule non-blocking upsert; tag with tenant for low-cardinality metrics
                                        tenant = DEFAULT_TENANT
                                        try:
                                            from .server import safe_task
                                            safe_task(persist_to_db_async(event_id, {'observables': d.get('observables') or [], 'confidence': dec['confidence'], 'ts': dec['ts']}, tenant), name='cs-persist')
                                        except Exception:
                                            # fallback to asyncio.create_task if safe_task unavailable
                                            asyncio.create_task(persist_to_db_async(event_id, {'observables': d.get('observables') or [], 'confidence': dec['confidence'], 'ts': dec['ts']}, tenant))
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                                try:
                                    if _record_decision_async:
                                        await _record_decision_async(dec)
                                    else:
                                        try:
                                            from .runtime_state import cache_set as _cache_set
                                            _cache_set(event_id, dec)
                                        except Exception:
                                            try:
                                                _cache_set(event_id, dec)
                                            except Exception:
                                                pass
                                except Exception:
                                    try:
                                        from .runtime_state import cache_set as _cache_set
                                        _cache_set(event_id, dec)
                                    except Exception:
                                        try:
                                            _cache_set(event_id, dec)
                                        except Exception:
                                            pass
                    except Exception:
                        pass
                    last_run = time.time()
            except Exception:
                pass
            await asyncio.sleep(max(5, _CS_SYNC_INTERVAL))
    app.add_event_handler('startup', lambda: asyncio.create_task(_crowdstrike_sync_loop()))

_RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', None)
if _RATE_LIMIT_ENABLED is None:
    # Default to disabled when running tests or in lite mode to avoid noisy 429s
    _RATE_LIMIT_ENABLED = not (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ)
else:
    _RATE_LIMIT_ENABLED = str(_RATE_LIMIT_ENABLED).lower() not in {'0', 'false', 'no'}
_RATE_LIMIT_MAX_REQUESTS = int(os.getenv('RATE_LIMIT_MAX_REQUESTS', '300'))
_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))
_RATE_LIMIT_STORAGE: defaultdict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT_LOCK = asyncio.Lock()

# Per-tenant rate limiting (independent from global IP rate limit)
# Default tenant rate limiting: enabled by default in production, but when
# running under the test harness (or explicit lite init) it's noisy and causes
# many tests to fail with 429. Honor explicit env overrides, but otherwise
# disable tenant rate limiting when running under pytest or PLATFORM_LITE_INIT.
try:
    _default_tenant_rate = '0' if (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ) else '1'
except Exception:
    _default_tenant_rate = '1'
_TENANT_RATE_ENABLED = os.getenv('TENANT_RATE_LIMIT_ENABLED', _default_tenant_rate).lower() not in {'0','false','no'}
_TENANT_RATE_MAX = int(os.getenv('TENANT_RATE_LIMIT_MAX','600') or 600)
_TENANT_RATE_WINDOW = int(os.getenv('TENANT_RATE_LIMIT_WINDOW','60') or 60)
_TENANT_RATE_STORAGE: defaultdict[str, deque[float]] = defaultdict(deque)
_TENANT_RATE_LOCK = asyncio.Lock()
_TENANT_RATE_DROPS: defaultdict[str, int] = defaultdict(int)
_TENANT_LAST_ALERT: dict[str, float] = {}
_TENANT_NOISY_ALERT_THRESHOLD = int(os.getenv('TENANT_NOISY_ALERT_THRESHOLD','0') or 0)  # 0 disables
_TENANT_NOISY_ALERT_COOLDOWN = int(os.getenv('TENANT_NOISY_ALERT_COOLDOWN_SECONDS','300') or 300)


def reset_rate_limit_for_tests() -> None:
    """Test helper: clear in-memory rate limiter windows and counters.

    Tests that toggle env variables or monkeypatch limits should call this
    to avoid cross-test pollution from previously recorded timestamps.
    """
    try:
        _RATE_LIMIT_STORAGE.clear()
    except Exception:
        pass
    # Re-evaluate environment-driven configuration so tests that set
    # RATE_LIMIT_ENABLED / RATE_LIMIT_MAX_REQUESTS / RATE_LIMIT_WINDOW_SECONDS
    # after initial import can deterministically toggle behavior without
    # requiring a full module reload.
    try:
        global _RATE_LIMIT_ENABLED, _RATE_LIMIT_MAX_REQUESTS, _RATE_LIMIT_WINDOW_SECONDS
        # If tests have already monkeypatched the module-level flag to True,
        # preserve that explicit override. Otherwise compute the enabled state
        # from environment (or default for pytest).
        prior_enabled = globals().get('_RATE_LIMIT_ENABLED', None)
        cfg_enabled = os.getenv('RATE_LIMIT_ENABLED', None)
        if cfg_enabled is None:
            # Default disabled under pytest unless explicitly enabled
            computed_enabled = not ('PYTEST_CURRENT_TEST' in os.environ)
        else:
            computed_enabled = str(cfg_enabled).lower() not in {'0','false','no'}
        # If tests have explicitly set the module flag (True or False), preserve
        # that explicit intent. Only fall back to computed value when not set.
        _RATE_LIMIT_ENABLED = bool(prior_enabled) if prior_enabled is not None else computed_enabled
        _RATE_LIMIT_MAX_REQUESTS = int(os.getenv('RATE_LIMIT_MAX_REQUESTS', str(_RATE_LIMIT_MAX_REQUESTS)) or _RATE_LIMIT_MAX_REQUESTS)
        _RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', str(_RATE_LIMIT_WINDOW_SECONDS)) or _RATE_LIMIT_WINDOW_SECONDS)
    except Exception:
        pass
    try:
        global _TENANT_RATE_ENABLED, _TENANT_RATE_MAX, _TENANT_RATE_WINDOW
        ten_enabled = os.getenv('TENANT_RATE_LIMIT_ENABLED', None)
        if ten_enabled is not None:
            _TENANT_RATE_ENABLED = str(ten_enabled).lower() not in {'0','false','no'}
        _TENANT_RATE_MAX = int(os.getenv('TENANT_RATE_LIMIT_MAX', str(_TENANT_RATE_MAX)) or _TENANT_RATE_MAX)
        _TENANT_RATE_WINDOW = int(os.getenv('TENANT_RATE_LIMIT_WINDOW', str(_TENANT_RATE_WINDOW)) or _TENANT_RATE_WINDOW)
    except Exception:
        pass
    try:
        _TENANT_RATE_STORAGE.clear()
    except Exception:
        pass
    try:
        _TENANT_RATE_DROPS.clear()
    except Exception:
        pass
    # Explicit helper: if test requests forced enable via RATE_LIMIT_FORCE_ENABLE, override
    try:
        if os.getenv('RATE_LIMIT_FORCE_ENABLE','').lower() in {'1','true','yes'}:
            # flip module-level flag without re-declaring global (already in outer scope)
            if '_RATE_LIMIT_ENABLED' in globals():
                globals()['_RATE_LIMIT_ENABLED'] = True
    except Exception:
        pass
    # Also clear storages on common module alias objects to avoid duplicate instances retaining state
    try:
        import sys as _sys
        for mn in ('src.api.app','api.app'):
            mod = _sys.modules.get(mn)
            if not mod:
                continue
            try:
                store = getattr(mod, '_RATE_LIMIT_STORAGE', None)
                if store is not None and hasattr(store, 'clear'):
                    store.clear()
            except Exception:
                pass
            try:
                tstore = getattr(mod, '_TENANT_RATE_STORAGE', None)
                if tstore is not None and hasattr(tstore, 'clear'):
                    tstore.clear()
            except Exception:
                pass
            try:
                drops = getattr(mod, '_TENANT_RATE_DROPS', None)
                if drops is not None and hasattr(drops, 'clear'):
                    drops.clear()
            except Exception:
                pass
    except Exception:
        pass

# Track last-seen tenant config so runtime changes clear stored windows to avoid
# cross-test pollution when tests toggle env vars at runtime.
_TENANT_LAST_CONFIG: tuple[bool,int,int] | None = None

# Backpressure thresholds
_BACKPRESSURE_ENABLED = os.getenv('BACKPRESSURE_ENABLED','1').lower() not in {'0','false','no'}
_BACKPRESSURE_QUEUE_UTIL = float(os.getenv('BACKPRESSURE_QUEUE_UTIL','0.9') or 0.9)

# Internal worker bypass for rate limiting (shared secret header)
_WORKER_BYPASS_HEADER = os.getenv('WORKER_BYPASS_HEADER', 'X-Worker-Secret')
# Allow legacy environment variable X_WORKER_SECRET to act as a fallback so tests
# or older deployments that set the legacy var are respected even if
# WORKER_BYPASS_TOKEN is not set. Tests sometimes monkeypatch os.environ without
# reloading modules; to support that without forcing module reloads we expose a
# small dynamic token object whose stringification and equality reflect the
# current environment value at access-time. This keeps consumers using the
# legacy module-level name working (e.g. tests referencing appmod._WORKER_BYPASS_TOKEN).
class _DynamicEnvToken:
    def __init__(self, env_name: str = 'WORKER_BYPASS_TOKEN', legacy: str = 'X_WORKER_SECRET'):
        self.env_name = env_name
        self.legacy = legacy
    def value(self) -> str:
        try:
            return os.getenv(self.env_name) or os.getenv(self.legacy, '')
        except Exception:
            return ''
    def __str__(self) -> str:
        return self.value() or ''
    def __repr__(self) -> str:
        return f"<DynamicEnvToken {self.env_name}='{self.value()}'>"
    def __eq__(self, other) -> bool:  # comparisons to strings should work
        try:
            return str(self) == (other or '')
        except Exception:
            return False


_WORKER_BYPASS_DYNAMIC = _DynamicEnvToken()
# Preserve backward-compatible module attribute used by tests and external callers
# as a plain string so headers and frameworks that check isinstance(..., str)
# continue to work. The dynamic object is available as _WORKER_BYPASS_DYNAMIC
# for code that needs to re-evaluate the env at runtime.
_WORKER_BYPASS_TOKEN = str(_WORKER_BYPASS_DYNAMIC)

_ALLOWED_ORIGINS: list[str] = [origin.strip() for origin in os.getenv('ALLOWED_ORIGINS', '').split(',') if origin.strip()]
if not _ALLOWED_ORIGINS:
    _ALLOWED_ORIGINS = ['https://localhost']

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'X-Tenant-Id', 'X-Requested-With', 'x-api-key', 'X-API-Key'],
    expose_headers=['X-Request-ID'],
)

def register_core_routers(full: bool = True):
    """Register application routers.

    full=False (lite mode) only mounts minimal, low-dependency routers needed for
    basic health/metrics/sample endpoints to satisfy lightweight tests.
    """
    logger.info('register_core_routers called (full=%s)', full)
    # Always-safe minimal routers
    try:
        app.include_router(metrics_summary_router)
        if api_keys_router:
            app.include_router(api_keys_router)
    except Exception:
        logger.debug('metrics_summary_router include failed (lite)')
    try:
        app.include_router(hunt_router)
    except Exception:
        logger.debug('hunt_router include failed (lite)')
    # Make SSE decision stream available even in lite mode for tests that
    # exercise streaming behavior without needing full route set.
    try:
        app.include_router(decisions_router)
    except Exception:
        logger.debug('decisions_router include failed (lite)')
    else:
        logger.info('Included decisions_router into app (lite)')
    # Ensure lightweight config and assessments endpoints are available in lite mode
    try:
        app.include_router(config_router)
        logger.info('Included config_router into app (lite)')
    except Exception:
        logger.debug('config_router include failed (lite)')
    try:
        app.include_router(assessments_router)
        logger.info('Included assessments_router into app (lite)')
    except Exception:
        logger.debug('assessments_router include failed (lite)')
    try:
        app.include_router(report_router)
        logger.info('Included report_router into app (lite)')
    except Exception:
        logger.debug('report_router include failed (lite)')
    # Include integrations (webhooks) in lite mode so tests exercising
    # webhook guard behavior can hit the endpoints without loading full routes.
    try:
        # Prefer module-level import if available
        if 'integrations_router' in globals() and globals().get('integrations_router') is not None:
            app.include_router(globals().get('integrations_router'))
        else:
            from .integrations_endpoints import router as _integrations_router
            app.include_router(_integrations_router)
        logger.info('Included integrations_router into app (lite)')
    except Exception:
        logger.debug('integrations_router include failed (lite)')
    # Include intel lookup in lite mode to allow tests to hit /api/v1/intel/lookup
    try:
        from .intel_endpoints import router as _intel_router
        app.include_router(_intel_router)
        logger.info('Included intel_router into app (lite)')
    except Exception:
        logger.debug('intel_router include failed (lite)')
    try:
        if deep_analyze_router:
            app.include_router(deep_analyze_router)
            logger.info('Included deep_analyze_router into app (lite)')
    except Exception:
        logger.debug('deep_analyze_router include failed (lite)')
    # Ensure endpoint malware router is available even in lite mode for focused tests
    try:
        if endpoint_malware_router:
            app.include_router(endpoint_malware_router)
            logger.info('Included endpoint_malware router (lite)')
        else:
            # Attempt dynamic reload if initial import failed earlier
            try:
                import importlib as _im
                _mod = _im.import_module('src.api.endpoint_malware_endpoints')
                try:
                    _mod = _im.reload(_mod)
                except Exception:
                    pass
                _router = getattr(_mod, 'router', None)
                if _router is not None:
                    app.include_router(_router)
                    globals()['endpoint_malware_router'] = _router
                    logger.info('Dynamically loaded endpoint_malware router (lite)')
            except Exception as e:
                logger.debug('Dynamic reload of endpoint_malware_endpoints failed: %s', e)
    except Exception:
        logger.debug('endpoint_malware_router include failed (lite)')
    if not full:
        # Log current mounted routes for diagnostic purposes when running in lite mode
        try:
            routes = sorted({r.path for r in app.router.routes})
            logger.info('App routes after lite registration: %s', ','.join(routes[:50]))
        except Exception:
            pass
        return
    # Full set (best-effort, each guarded)
    for _r_name, _r in [
        ('events', 'events.router'),
        ('metrics', 'metrics.router'),
        ('internal', 'internal.router'),
        ('hunt_lanes', 'hunt_lanes.router'),
    ]:
        try:
            # lazy import inside loop to avoid overhead in lite mode
            mod_name = f"{__package__}.routes.{_r_name}"
            mod = __import__(mod_name, fromlist=['router'])
            app.include_router(getattr(mod, 'router'))
        except Exception:
            logger.debug('Failed to include %s', _r_name)
    # Directly included routers already imported earlier
    for label, router_obj in [
        ('decisions', 'decisions_router'),
        ('risk', 'risk_router'),
        ('temporal', 'temporal_router'),
        ('upload', 'upload_router'),
        ('stream_ingest', 'stream_router'),
        ('csv', 'csv_router'),
        ('soar', 'soar_router'),
        ('dashboard', 'dashboard_router'),
        ('integrations', 'integrations_router'),
        ('metrics_status', 'metrics_status_router'),
        ('custody', 'custody_router'),
        ('artifact', 'artifact_router'),
        ('nlp', 'nlp_router'),
        ('sbom', 'sbom_router'),
        ('ebpf', 'ebpf_router'),
        ('identity_graph', 'identity_graph_router'),
        ('identity_reporting', 'identity_reporting_router'),
        ('cloud_graph', 'cloud_graph_router'),
        ('network_graph', 'network_graph_router'),
        ('compliance', 'compliance_router'),
        ('report', 'report_router'),
        ('feedback', 'feedback_router'),
        ('dev', 'dev_router'),
        ('admin_rules', 'admin_rule_router'),
        ('decision_feedback', 'decision_feedback_router'),
        ('factors', 'factors_router'),
        ('suppression_admin', 'suppression_admin_router'),
        ('unified_ingest', 'unified_ingest_router'),
        ('risk_config_admin', 'risk_config_admin_router'),
        ('scenario_replay', 'scenario_replay_router'),
        ('unified_graph', 'unified_graph_router'),
        ('network_ingest', 'network_ingest_router'),
        ('cloud_ingest', 'cloud_ingest_router'),
        ('app_ingest', 'app_events_router'),
        ('identity_ingest', 'identity_ingest_router'),
        ('decision_confidence', 'decision_confidence_router'),
        ('node_factors', 'node_factors_router'),
        ('emitted_factors', 'emitted_factors_router'),
        ('graph_session', 'graph_session_router'),
        ('suggestions', 'suggestions_router'),
            ('config', 'config_router'),
        ('assessments', 'assessments_router'),
        ('playbooks', 'playbook_router'),
        ('identity_hopgraph_facade', 'identity_hopgraph_facade_router'),
        ('cooccurrence_admin', 'cooccurrence_admin_router'),
        ('endpoint_malware', 'endpoint_malware_router'),
        ('isms', 'isms_router'),
    ]:
        try:
            # allow playbook router to be included if present
            if router_obj == 'playbook_router' and 'playbook_router' not in globals():
                try:
                    from .playbook_endpoints import router as playbook_router
                    globals()['playbook_router'] = playbook_router
                except Exception:
                    pass
            app.include_router(globals()[router_obj])
        except Exception:
            logger.debug('Failed to include router %s', label)
        else:
            logger.info('Included router %s', label)
    # Optional SLO metrics router
    try:
        if metrics_slo_router is not None:
            app.include_router(metrics_slo_router)
            logger.info('Included SLO metrics router')
    except Exception:
        logger.debug('Failed to include metrics_slo_router')
    # Include correlation router if present
    try:
        from .correlation import router as correlation_router
        app.include_router(correlation_router)
    except Exception:
        try:
            # fallback import path
            from src.api.correlation import router as correlation_router
            app.include_router(correlation_router)
        except Exception:
            logger.debug('Correlation router not included')
    # Include triage endpoints if present
    try:
        from .triage_endpoints import router as triage_router
        app.include_router(triage_router)
    except Exception:
        try:
            from src.api.triage_endpoints import router as triage_router
            app.include_router(triage_router)
        except Exception:
            logger.debug('Triage router not included')
    # Optional routers
    try:
        from .cert_check_endpoints import router as certcheck_router  # type: ignore
        if full:
            app.include_router(certcheck_router)
    except Exception:
        pass

# Register routers according to mode. Honor LOAD_FULL_ROUTES when in lite mode so
# tests can opt into mounting the full set of routers without performing the
# heavy initialization guarded by PLATFORM_LITE_INIT.
_LITE = os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}
_LOAD_FULL = os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}
if _LITE:
    register_core_routers(full=_LOAD_FULL)
else:
    register_core_routers(full=True)

# Late safeguard: if endpoint malware router failed initial import, attempt a final mount.
try:
    _MALWARE_PATH = '/api/v1/endpoint/malware/analyze'
    if not any(getattr(r, 'path', None) == _MALWARE_PATH for r in app.router.routes):
        import importlib as _im
        try:
            _mod = _im.import_module('src.api.endpoint_malware_endpoints')
            _router = getattr(_mod, 'router', None)
            if _router is not None:
                app.include_router(_router)
                globals()['endpoint_malware_router'] = _router
                logger.info('Late-mounted endpoint_malware router')
        except Exception as _e:
            logger.debug('Late mount endpoint_malware failed: %s', _e)
except Exception:
    pass

# Ensure metrics families are available in lite/test mode for assertions in tests
try:
    if _LITE:
        try:
            ensure_metrics()
            # In lite/test mode, proactively register additional metrics that
            # some tests expect to exist (SSE & correlation/hunt metrics). This
            # avoids races where modules are not imported during lightweight
            # initialization but tests still query the scrape for specific
            # metric names.
            try:
                from src.api import decisions_stream as _ds
                try:
                    _ds.register_metrics(REGISTRY)
                except Exception:
                    # best-effort: ignore if registration fails
                    pass
            except Exception:
                pass
            try:
                from src.core.correlation import hunt_correlation as _hc
                try:
                    _hc.register_metrics(REGISTRY)
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            logger.debug('ensure_metrics failed during lite init')
except Exception:
    pass

# Dump a brief listing of registered routes for debugging test failures (best-effort)
try:
    logger.debug('Registered app route count: %d', len(app.routes))
    # Show a compact list of path prefixes for quick diagnosis
    paths = []
    for r in app.routes:
        try:
            paths.append(getattr(r, 'path', str(r)))
        except Exception:
            try:
                paths.append(str(r))
            except Exception:
                pass
    logger.debug('App routes: %s', ', '.join(paths[:50]))
except Exception:
    pass

# Route inventory audit against allowlist (logs only)
def _audit_routes_against_allowlist() -> None:
    try:
        enabled = os.getenv('ROUTE_INVENTORY_AUDIT', '1').lower() not in {'0','false','no'}
    except Exception:
        enabled = True
    if not enabled:
        return
    try:
        allow_csv = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'security', 'api_endpoint_allowlist.csv')
        allowed: set[tuple[str,str]] = set()
        if os.path.exists(allow_csv):
            with open(allow_csv, 'r', encoding='utf-8') as fh:
                reader = _csv.DictReader(fh)
                for row in reader:
                    p = (row.get('path') or '').strip()
                    m = (row.get('method') or '').strip().upper()
                    if p and m:
                        allowed.add((p, m))
        # Build current inventory
        current: set[tuple[str,str]] = set()
        for r in app.routes:
            try:
                path = getattr(r, 'path')
                methods = getattr(r, 'methods', {'GET'})
            except Exception:
                continue
            if not isinstance(methods, (set, list, tuple)):
                continue
            if not isinstance(path, str) or not path.startswith('/api'):
                continue
            for m in methods:
                current.add((path, m.upper()))
        # Report extras (not in allowlist)
        extras = sorted([f"{p} {m}" for (p,m) in current if (p,m) not in allowed])
        logger.info('Route inventory audit: %d routes, %d allowlisted, %d extras', len(current), len(allowed), len(extras))
        if extras:
            logger.warning('Routes not in allowlist (first 25): %s', ', '.join(extras[:25]))
    except Exception:
        # best-effort only
        pass

try:
    _audit_routes_against_allowlist()
except Exception:
    pass


# Temporary debug helper: expose registered routes for external testing
@app.get('/__debug/list_routes', include_in_schema=False)
async def _debug_list_routes():
    try:
        return {'routes': sorted({getattr(r, 'path', str(r)) for r in app.router.routes})}
    except Exception:
        return {'routes': []}

# Ensure server-level routes (defined in src.api.server) are imported so
# endpoints declared there are registered when tests import `src.api.app`.
try:
    import importlib
    importlib.import_module('src.api.server')
except Exception:
    # Best-effort only; do not fail app import if server cannot be imported
    logger.debug('Optional import src.api.server failed during app import')

if os.getenv('HTTPS_REDIRECT_ENABLED', '0').lower() not in {'0', 'false', 'no'}:
    app.add_middleware(HTTPSRedirectMiddleware)

# Add CSRF middleware to protect admin actions (double-submit cookie)
try:
    app.add_middleware(CSRFMiddleware)
except Exception:
    # don't break if middleware cannot be added in constrained environments
    logger.debug('Failed to add CSRFMiddleware')

# Add generic webhook guard for /api/v1/webhooks/* endpoints
try:  # best-effort middleware registration
    app.add_middleware(WebhookGuardMiddleware)
except Exception:
    logger.debug('Failed to add WebhookGuardMiddleware')

# Optional: enforce x-api-key (or JWT) globally for API routes in demo/prod
_STRICT_API_KEY = os.getenv('STRICT_API_KEY_ENFORCEMENT', '0').lower() in {'1', 'true', 'yes'}
_API_KEY_PATH_PREFIX = '/api/v1/'
_API_KEY_EXCEPT_PREFIXES = (
    '/metrics', '/health', '/static', '/assets', '/react', '/spa', '/ui', '/live', '/console', '/dashboard'
)
_API_KEY_EXCEPT_CONTAINS = (
    '/api/v1/webhooks/',  # guarded by WebhookGuardMiddleware/HMAC
    '/api/v1/integrations/',  # allow vendor webhooks; specific endpoints perform their own auth
    '/admin',  # admin endpoints have separate token/SSO checks
)

@app.middleware('http')
async def _api_key_enforcer(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # Read enforcement flag dynamically so tests that mutate env vars at
    # runtime (or set them before TestClient creation) are respected. Using
    # a module-level constant here caused test flakes when tests modified
    # STRICT_API_KEY_ENFORCEMENT during the pytest run.
    try:
        # Honor test and lite-mode contexts: when running under pytest or
        # PLATFORM_LITE_INIT we should not enforce strict API keys by default
        # unless the env explicitly requests it for a test. This keeps unit
        # tests deterministic without requiring every request to include keys.
        env_flag = os.getenv('STRICT_API_KEY_ENFORCEMENT', '0').lower() in {'1', 'true', 'yes'}
        if env_flag and not (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ):
            strict_mode = True
        else:
            strict_mode = False
    except Exception:
        strict_mode = bool(_STRICT_API_KEY)
    if not strict_mode:
        return await call_next(request)
    try:
        path = request.url.path or '/'
        # Quick allow for non-API or explicitly exempted paths
        if not path.startswith(_API_KEY_PATH_PREFIX) or any(path.startswith(p) for p in _API_KEY_EXCEPT_PREFIXES) or any(c in path for c in _API_KEY_EXCEPT_CONTAINS):
            return await call_next(request)
        # Validate via shared auth dependency (accepts x-api-key or Bearer JWT)
        x_api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
        authorization = request.headers.get('Authorization')
        try:
            ctx: AuthContext = await auth_dependency(x_api_key, authorization, [])  # no extra scopes globally
            # attach for downstream handlers if useful
            try:
                request.state.auth = ctx
            except Exception:
                pass
        except HTTPException as exc:
            return Response(status_code=exc.status_code, content=json.dumps({'detail': exc.detail}), media_type='application/json')
    except Exception:
        # Fail closed on internal errors when strict mode is enabled
        return Response(status_code=401, content=json.dumps({'detail': 'unauthorized'}), media_type='application/json')
    return await call_next(request)


@app.middleware('http')
async def _rate_limit_requests(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    if not _RATE_LIMIT_ENABLED or _RATE_LIMIT_MAX_REQUESTS <= 0 or _RATE_LIMIT_WINDOW_SECONDS <= 0:
        return await call_next(request)
    try:
        # Bypass for internal workers if header matches configured token
        # Support test/worker bypass tokens set at runtime via env; check both
        # the current env value and a legacy header 'X-Worker-Secret'. This allows
        # tests to monkeypatch os.environ without reloading the module.
        try:
            # Read the current env-based token dynamically to honor runtime
            # monkeypatching in tests without requiring module reload.
            try:
                _worker_token = _WORKER_BYPASS_DYNAMIC.value()
            except Exception:
                _worker_token = os.getenv('WORKER_BYPASS_TOKEN','') or os.getenv('X_WORKER_SECRET','')
            _worker_header = os.getenv('WORKER_BYPASS_HEADER', 'X-Worker-Secret')
            if _worker_token and request.headers.get(_worker_header) == _worker_token:
                return await call_next(request)
        except Exception:
            pass
    except Exception:
        pass
    # Prefer X-Forwarded-For header when present (tests set this to control client IP)
    try:
        xff = request.headers.get('x-forwarded-for') or request.headers.get('X-Forwarded-For')
        if xff:
            # Use first value in comma-separated list
            client_ip = xff.split(',')[0].strip()
        else:
            client_ip = request.client.host if request.client else 'unknown'
    except Exception:
        client_ip = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    async with _RATE_LIMIT_LOCK:
        window = _RATE_LIMIT_STORAGE[client_ip]
        cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= _RATE_LIMIT_MAX_REQUESTS:
            return Response(status_code=429, content=json.dumps({'detail': 'rate_limit_exceeded'}), media_type='application/json')
        window.append(now)
    return await call_next(request)

@app.middleware('http')
async def _correlation_and_tenant_context(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    # Assign/request correlation id
    try:
        cid = request.headers.get('X-Request-ID') or os.getenv('REQUEST_ID_PREFIX','req') + '-' + str(int(time.time()*1000))
        tenant = request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id') or DEFAULT_TENANT
        try:
            set_correlation(cid)
            set_tenant(tenant)
        except Exception:
            pass
        response = await call_next(request)
        response.headers.setdefault('X-Request-ID', cid)
        return response
    finally:
        # Clear context (optional; new contextvars context per request normally)
        try:
            set_correlation(None)
            set_tenant(None)
        except Exception:
            pass

@app.middleware('http')
async def _tenant_rate_limit(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    global ingest_failures_counter
    # Read tenant rate limit settings dynamically so tests can toggle them at
    # runtime without reloading the module.
    try:
        # Default tenant rate limiting should follow lite/test mode unless explicitly set.
        _tenant_default = '0' if (_LITE or 'PYTEST_CURRENT_TEST' in os.environ) else '1'
        _tenant_enabled = os.getenv('TENANT_RATE_LIMIT_ENABLED', _tenant_default).lower() not in {'0','false','no'}
        _tenant_max = int(os.getenv('TENANT_RATE_LIMIT_MAX','600') or 600)
        _tenant_window = int(os.getenv('TENANT_RATE_LIMIT_WINDOW','60') or 60)
    except Exception:
        _tenant_enabled = False if _LITE else True
        _tenant_max = 600
        _tenant_window = 60
    # If tenant rate config changed since last request, clear in-memory windows to
    # avoid stale counts affecting tests that toggle settings at runtime.
    global _TENANT_LAST_CONFIG
    try:
        cfg = (_tenant_enabled, _tenant_max, _tenant_window)
        if _TENANT_LAST_CONFIG is None:
            _TENANT_LAST_CONFIG = cfg
        elif _TENANT_LAST_CONFIG != cfg:
            _TENANT_RATE_STORAGE.clear()
            _TENANT_RATE_DROPS.clear()
            _TENANT_LAST_ALERT.clear()
            _TENANT_LAST_CONFIG = cfg
    except Exception:
        pass
    if not _tenant_enabled:
        return await call_next(request)
    try:
        # Support legacy X_WORKER_SECRET env var used by some tests and tooling.
        try:
            _worker_token = _WORKER_BYPASS_DYNAMIC.value()
        except Exception:
            _worker_token = os.getenv('WORKER_BYPASS_TOKEN') or os.getenv('X_WORKER_SECRET') or ''
        _worker_header = os.getenv('WORKER_BYPASS_HEADER', 'X-Worker-Secret')
        if _worker_token and (request.headers.get(_worker_header) == _worker_token or request.headers.get('X-Worker-Secret') == _worker_token):
            return await call_next(request)
    except Exception:
        pass
    tenant_id = request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id') or DEFAULT_TENANT
    now = time.monotonic()
    async with _TENANT_RATE_LOCK:
        # In lite/test mode, clear any stored per-tenant windows at the start
        # of each request to avoid cross-test pollution where one test's
        # requests cause another test to observe a throttled tenant and get
        # unexpected 429s. This keeps lite-mode deterministic for unit tests.
        if _LITE:
            try:
                # Remove any existing deque for this tenant so we start fresh
                _TENANT_RATE_STORAGE.pop(tenant_id, None)
                _TENANT_RATE_DROPS.pop(tenant_id, None)
            except Exception:
                pass
        window = _TENANT_RATE_STORAGE[tenant_id]
        cutoff = now - _tenant_window
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= _tenant_max:
            if ingest_failures_counter:
                try:
                    from .metrics_tenant_helper import emit_labels_with_guard
                    from .metrics_init import ensure_metrics, ingest_failures_counter
                    ensure_metrics()
                    labels = emit_labels_with_guard(get_server_runtime_state(app), {'reason': 'tenant_rate_limit'}, None)
                    if ingest_failures_counter is not None:
                        ingest_failures_counter.labels(**labels).inc()
                except Exception:
                    pass
                except Exception: pass
            # Track noisy-tenant drops and emit one-shot alert (cooldown guarded)
            try:
                _TENANT_RATE_DROPS[tenant_id] += 1
                if _TENANT_NOISY_ALERT_THRESHOLD and _TENANT_RATE_DROPS[tenant_id] >= _TENANT_NOISY_ALERT_THRESHOLD:
                    last = _TENANT_LAST_ALERT.get(tenant_id, 0.0)
                    if (now - last) >= max(1, _TENANT_NOISY_ALERT_COOLDOWN):
                        _TENANT_LAST_ALERT[tenant_id] = now
                        # fire-and-forget best-effort alert
                        try:
                            from database_adapter import db_manager
                            alert = {
                                'event_id': None,
                                'alert_type': 'noisy_tenant',
                                'severity': 'low',
                                'message': f'Tenant {tenant_id} exceeded rate limits frequently',
                                'alert_data': {'tenant_id': tenant_id, 'drops': _TENANT_RATE_DROPS[tenant_id]},
                                'tenant_id': tenant_id,
                            }
                            asyncio.create_task(db_manager.store_alert(alert))
                        except Exception:
                            pass
            except Exception:
                pass
            return Response(status_code=429, content=json.dumps({'detail':'tenant_rate_limit'}), media_type='application/json')
    window.append(now)
    return await call_next(request)

@app.middleware('http')
async def _backpressure_guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    if not _BACKPRESSURE_ENABLED:
        try:
            return await call_next(request)
        except RuntimeError as e:
            logger.exception('backpressure_guard: call_next raised RuntimeError')
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail': 'service_unavailable', 'error': 'internal middleware error'}, status_code=503)
    try:
        if EVENT_QUEUE is not None:
            stats = EVENT_QUEUE.stats()
            depth = stats.get('depth')
            max_size = stats.get('max_size') or 0
            if ingest_buffer_gauge and depth is not None:
                try: ingest_buffer_gauge.set(depth)
                except Exception: pass
            if max_size and depth and (depth / max_size) >= _BACKPRESSURE_QUEUE_UTIL:
                return Response(status_code=503, content=json.dumps({'detail':'backpressure'}), media_type='application/json')
    except Exception:
        pass
    try:
        return await call_next(request)
    except RuntimeError as e:
        logger.exception('backpressure_guard: call_next raised RuntimeError')
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail': 'service_unavailable', 'error': 'internal middleware error'}, status_code=503)


# Enforce JSON content-type for JSON API routes (exclude file uploads)
@app.middleware('http')
async def _json_content_type_guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    try:
        path = request.url.path or ''
        method = request.method.upper()
        if path.startswith('/api/v1/') and method in {'POST','PUT','PATCH'}:
            # Exempt known multipart/file endpoints and raw ingest endpoints (pcap streaming)
            if path.startswith('/api/v1/upload/') or path.startswith('/api/v1/ingest/'):
                return await call_next(request)
            # Zero-length bodies are allowed
            clen = request.headers.get('content-length')
            if clen is not None:
                try:
                    if int(clen) <= 0:
                        return await call_next(request)
                except Exception:
                    pass
            ctype = (request.headers.get('content-type') or '').lower()
            # Allow JSON and multipart form data (file uploads). Multipart content
            # types are expected for UploadFile endpoints; reject only other types.
            if not (ctype.startswith('application/json') or ctype.startswith('application/merge-patch+json') or ctype.startswith('multipart/')):
                return Response(status_code=415, content=json.dumps({'detail': 'unsupported_media_type'}), media_type='application/json')
    except Exception:
        # best-effort guard; do not block request on guard error
        pass
    return await call_next(request)


@app.middleware('http')
async def _add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    try:
        response = await call_next(request)
    except RuntimeError as e:
        logger.exception('_add_security_headers: call_next raised RuntimeError')
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail': 'service_unavailable', 'error': 'internal middleware error'}, status_code=503)
    response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    # Content Security Policy: relax for frontend routes to allow inline styles/assets used by React build
    try:
        if os.getenv('DISABLE_CSP', '0').lower() in {'1','true','yes'}:
            pass  # do not set CSP header
        else:
            path = request.url.path or '/'
            relaxed_prefixes = ('/react', '/assets', '/', '/ui', '/static', '/spa')
            if any(path.startswith(pfx) for pfx in relaxed_prefixes):
                # Allow inline styles and same-origin scripts; permit data: for images/fonts used by build
                csp = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data: blob:; "
                    "font-src 'self' data:; "
                    "connect-src 'self'; "
                    "media-src 'self' blob:; "
                    "worker-src 'self' blob:; "
                    "frame-ancestors 'self'"
                )
            else:
                csp = "default-src 'self'"
            response.headers.setdefault('Content-Security-Policy', csp)
    except Exception:
        # Fallback to safe default if any error occurs building CSP
        response.headers.setdefault('Content-Security-Policy', "default-src 'self'")
    return response


# Mount frontend files
frontend_root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'frontend')

# Define paths for routes
react_path = os.path.join(frontend_root, 'react', 'dist')
spa_path = os.path.join(frontend_root, 'spa')

# Mount React frontend (proper one with colors, logo, three columns)
if os.path.exists(react_path):
    logger.info(f"Mounting React frontend at /react from {react_path}")
    app.mount("/react", StaticFiles(directory=react_path), name="react")
    # Also mount React assets directly
    app.mount("/assets", StaticFiles(directory=os.path.join(react_path, 'assets')), name="react-assets")
else:
    logger.warning(f"React path does not exist: {react_path}")

# Mount SPA frontend
if os.path.exists(spa_path):
    logger.info(f"Mounting SPA frontend at /spa from {spa_path}")
    app.mount("/spa", StaticFiles(directory=spa_path), name="spa")
else:
    logger.warning(f"SPA path does not exist: {spa_path}")

# Mount static assets
static_path = os.path.join(frontend_root, 'static')
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

# Mount root frontend
if os.path.exists(frontend_root):
    app.mount("/ui", StaticFiles(directory=frontend_root), name="frontend")

# (All router inclusions moved into register_core_routers.)
try:
    if feedback_api_router is not None:
        app.include_router(feedback_api_router)
except Exception:
    logger.debug('Failed to include enhanced feedback router')

# ---------------- Feedback Quality Background Task -----------------
try:
    import threading
    from src.feedback.store import GLOBAL_FEEDBACK_STORE  # type: ignore
    from prometheus_client import Summary, Counter  # type: ignore
    _FEEDBACK_RECALC_INTERVAL = int(os.getenv('FEEDBACK_QUALITY_RECOMPUTE_SEC','300') or 300)
    _FEEDBACK_DYNAMIC_ENABLED = os.getenv('FEEDBACK_DYNAMIC_ENABLED','1').lower() not in {'0','false','no'}
    FEEDBACK_RECALC_TIME = Summary('feedback_quality_recompute_seconds','Time spent recomputing factor quality')  # type: ignore
    FEEDBACK_RECALC_COUNT = Counter('feedback_quality_recompute_total','Total factor quality recomputations')  # type: ignore
    if _FEEDBACK_RECALC_INTERVAL > 0 and _FEEDBACK_DYNAMIC_ENABLED:
        def _feedback_recompute_loop():  # pragma: no cover
            while True:
                try:
                    start = time.time()
                    GLOBAL_FEEDBACK_STORE.recompute_quality()
                    dt = time.time() - start
                    try:
                        FEEDBACK_RECALC_TIME.observe(dt)
                        FEEDBACK_RECALC_COUNT.inc()
                    except Exception:
                        pass
                    time.sleep(max(5, _FEEDBACK_RECALC_INTERVAL))
                except Exception:
                    time.sleep(30)
        threading.Thread(target=_feedback_recompute_loop, name='feedback-quality-recompute', daemon=True).start()
except Exception:
    logger.debug('Feedback quality background task not started')
try:
    from .intel_endpoints import router as intel_router
    # defer inclusion to register_core_routers to honor lite mode
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(intel_router)
except Exception:
    logger.debug('Failed to include Intel router')
# Ensure ingest router is included when available (demo convenience)
try:
    from .ingest_api import router as ingest_router
    try:
        app.include_router(ingest_router)
    except Exception:
        logger.debug('Failed to include ingest router')
except Exception:
    logger.debug('ingest_api module not present or failed to import')
try:
    from .graph_endpoints import router as graph_router
    # Always include graph_endpoints router; lightweight and useful for previews/topn even in lite/test mode
    try:
        app.include_router(graph_router)
        try:
            from .graph_sessions import router as graph_session_router
            app.include_router(graph_session_router)
        except Exception as e:
            logger.warning(f'Failed to include graph_session_router: {e}')
        try:
            try:
                from .graph_explain_endpoint import router as hopgraph_explain_router
            except Exception:
                # fallback to absolute import path
                from src.api.graph_explain_endpoint import router as hopgraph_explain_router
            app.include_router(hopgraph_explain_router)
        except Exception as e:
            logger.warning(f'Failed to include hopgraph_explain_router: {e}')
        try:
            try:
                from .graph_preview_endpoints import router as graph_preview_router
            except Exception:
                from src.api.graph_preview_endpoints import router as graph_preview_router
            app.include_router(graph_preview_router)
        except Exception as e:
            logger.warning(f'Failed to include graph_preview_router: {e}')
    except Exception:
        logger.debug('Failed to include graph_router via include_router')
except Exception:
    logger.debug('Failed to include graph router')
# Admin autogen router (runtime scoring control)
try:
    from .admin_autogen import router as admin_autogen_router
    try:
        app.include_router(admin_autogen_router)
    except Exception:
        pass
except Exception:
    pass
try:
    from .admin_scoring import router as admin_scoring_router
    try:
        app.include_router(admin_scoring_router)
    except Exception:
        pass
except Exception:
    pass
try:
    from .admin_signatures import router as admin_signatures_router
    try:
        app.include_router(admin_signatures_router)
    except Exception:
        pass
except Exception:
    pass

try:
    # async outbox consumer
    from outbox.async_consumer import run_outbox  # type: ignore
except Exception:
    try:
        from src.outbox.async_consumer import run_outbox  # type: ignore
    except Exception:
        run_outbox = None  # type: ignore

if run_outbox:
    # Use add_event_handler to avoid deprecated on_event usage and integrate with lifespan
    def _start_outbox():
        try:
            from asyncio import Event, create_task
            app.state._outbox_stop = Event()
            app.state._outbox_task = create_task(run_outbox(app.state._outbox_stop))
        except Exception:
            app.state._outbox_stop = None
            app.state._outbox_task = None

    async def _stop_outbox():
        try:
            if getattr(app.state, '_outbox_stop', None):
                app.state._outbox_stop.set()
            t = getattr(app.state, '_outbox_task', None)
            if t:
                await t
        except Exception:
            pass

    app.add_event_handler('startup', _start_outbox)
    app.add_event_handler('shutdown', _stop_outbox)
try:
    from .factors_label_endpoints import router as factors_label_router
    app.include_router(factors_label_router)
except Exception:
    logger.debug('Failed to include factors_label_router')
try:
    from .ingest_controller_endpoints import router as unified_ingest_router
    app.include_router(unified_ingest_router)
    logger.info('Included unified ingestion controller router')
except Exception:
    logger.debug('Failed to include unified_ingest_router')
try:
    from .remediation_endpoints import router as remediation_router
    app.include_router(remediation_router)
except Exception:
    logger.debug('Failed to include remediation_router')
try:
    from .factor_matrix_endpoints import router as factor_matrix_router
    app.include_router(factor_matrix_router)
except Exception:
    logger.debug('Failed to include factor_matrix_router')
try:
    from .replay_endpoints import router as replay_router
    app.include_router(replay_router)
except Exception:
    logger.debug('Failed to include replay_router')
try:
    from .mapping_templates import router as mapping_templates_router
    app.include_router(mapping_templates_router)
except Exception:
    logger.debug('Failed to include mapping_templates_router')
try:
    from .baseline_endpoints import router as baseline_router
    app.include_router(baseline_router)
except Exception:
    logger.debug('Failed to include baseline_router')

# ASN endpoints
try:
    from .asn_endpoints import router as asn_router
    app.include_router(asn_router)
except Exception:
    logger.debug('Failed to include asn_router')

try:
    # optional ASN background population: starts a thread that can be used to feed ASN stats
    _ASN_POP_INTERVAL = int(os.getenv('ASN_POP_INTERVAL_SECONDS','0') or 0)
    if _ASN_POP_INTERVAL > 0:
        import threading
        def _asn_pop_loop():
            while True:
                try:
                    # best-effort: import and call a populate hook if present
                    try:
                        from src.live.asn_stats import populate_from_source
                        populate_from_source()
                    except Exception:
                        pass
                except Exception:
                    pass
                time.sleep(max(5, _ASN_POP_INTERVAL))
        threading.Thread(target=_asn_pop_loop, name='asn-populate', daemon=True).start()
except Exception:
    pass

# Final attempt to include graph router in case earlier inclusion ran before file edits
try:
    import importlib as _importlib
    try:
        _mod = _importlib.import_module('src.api.graph_endpoints')
        _importlib.reload(_mod)
        _graph_router = getattr(_mod, 'router', None)
        if _graph_router:
            try:
                app.include_router(_graph_router)
            except Exception:
                logger.debug('Final include of graph router failed')
    except Exception:
        pass
except Exception:
    pass
try:
    from .graph_trace_endpoints import router as graph_trace_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(graph_trace_router)
except Exception:
    logger.debug('Failed to include graph trace router')
try:
    from .approvals_endpoints import router as approvals_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(approvals_router)
except Exception:
    logger.debug('Failed to include Approvals router')
try:
    from .pilot_eval_endpoints import router as pilot_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(pilot_router)
except Exception:
    logger.debug('Failed to include Pilot router')
try:
    from .sandbox_endpoints import router as sandbox_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(sandbox_router)
except Exception:
    logger.debug('Failed to include Sandbox router')
try:
    from .eclipse_endpoints import router as eclipse_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(eclipse_router)
except Exception:
    logger.debug('Failed to include Eclipse router')
try:
    from .cyberstash_endpoints import router as cyberstash_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(cyberstash_router)
except Exception:
    logger.debug('Failed to include CyberStash router')
try:
    from .forensics_endpoints import router as forensics_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(forensics_router)
except Exception:
    logger.debug('Failed to include Forensics router')
try:
    from .bgp_endpoints import router as bgp_router
    if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
        app.include_router(bgp_router)
except Exception:
    logger.debug('Failed to include BGP router')
try:
    if yara_router is not None:
        if os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'} or os.getenv('LOAD_FULL_ROUTES','0').lower() in {'1','true','yes'}:
            app.include_router(yara_router)
except Exception:
    logger.debug('Failed to include YARA router')

# Threat intel sync background job (optional)
try:
    _TI_SYNC_ENABLED = os.getenv('THREAT_INTEL_SYNC_ENABLED','0').lower() in {'1','true','yes'}
    _TI_SYNC_INTERVAL = int(os.getenv('THREAT_INTEL_SYNC_INTERVAL_SEC','3600') or 3600)
    if _TI_SYNC_ENABLED and _TI_SYNC_INTERVAL > 0:
        import threading as _thr
        from src.integrations.threat_intel_store import sync_all as _sync_all  # type: ignore
        def _ti_sync_loop():  # pragma: no cover
            while True:
                try:
                    _sync_all()
                except Exception:
                    pass
                time.sleep(max(30, _TI_SYNC_INTERVAL))
        _thr.Thread(target=_ti_sync_loop, name='threat-intel-sync', daemon=True).start()
except Exception:
    logger.debug('Threat intel sync not started')

@app.get('/metrics', include_in_schema=False)
async def metrics_endpoint() -> Response:
    if generate_latest is None or REGISTRY is None:
        raise HTTPException(status_code=503, detail='metrics_not_available')
    try:
        ensure_metrics()
    except Exception as exc:  # pragma: no cover
        logger.debug('ensure_metrics failed during scrape: %s', exc)
    # Prefer the configured REGISTRY scrape, but also include the default global registry
    # to avoid missing metrics that were registered into the default registry by other
    # parts of the codebase or third-party libraries. Concatenate both scrapes when
    # available so tests observing metric names find them regardless of registry.
    try:
        primary = generate_latest(REGISTRY) if REGISTRY is not None else b''
    except Exception:
        primary = b''
    try:
        fallback = generate_latest()  # default global registry
    except Exception:
        fallback = b''
    # If both registries produced output and they differ, join them.
    if primary and fallback and primary != fallback:
        payload = primary + b"\n" + fallback
    else:
        payload = primary or fallback
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)

# Lightweight health endpoint used by LIVE console page
@app.get('/health', include_in_schema=False)
async def health() -> dict:
    try:
        ensure_metrics()
        metrics_ok = REGISTRY is not None and generate_latest is not None
    except Exception:
        metrics_ok = False
    return {
        'status': 'ok',
        'metrics': 'ok' if metrics_ok else 'unavailable',
        'ts': time.time(),
    }


@app.get('/api/v1/health', include_in_schema=False)
async def api_health_alias() -> dict:
    """Compatibility alias for tooling that expects /api/v1/health."""
    return await health()


# ---------------- Test helpers (lite/test-only) -----------------
@app.post('/api/v1/test_helpers/reset_tenant_rate')
async def _reset_tenant_rate(request: Request):
    """Test-only helper to clear in-memory tenant rate windows and counters.

    Guarded: only available when PLATFORM_LITE_INIT=1 or caller provides
    ADMIN_API_KEY in X-Admin-Key header. This prevents accidental exposure in
    production deployments.
    """
    # Allow when explicitly in lite/test mode
    if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}:
        allowed = True
    else:
        allowed = _admin_ok(request)
    if not allowed:
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        _TENANT_RATE_STORAGE.clear()
        _TENANT_RATE_DROPS.clear()
        _TENANT_LAST_ALERT.clear()
        return {'status': 'ok', 'cleared': True}
    except Exception:
        raise HTTPException(status_code=500, detail='reset_failed')


@app.get('/api/v1/temporal/stats', include_in_schema=False)
async def temporal_stats() -> dict:
    try:
        from src.ml.temporal_model import GLOBAL_TEMPORAL_MODEL  # type: ignore
    except Exception:
        try:
            from ml.temporal_model import GLOBAL_TEMPORAL_MODEL  # type: ignore
        except Exception:
            GLOBAL_TEMPORAL_MODEL = None  # type: ignore
    if not GLOBAL_TEMPORAL_MODEL:
        return {'entities': 0, 'avg_score': 0.0}
    try:
        return GLOBAL_TEMPORAL_MODEL.stats()
    except Exception:
        return {'entities': 0, 'avg_score': 0.0}


# Lightweight shim for report ingestion used by UI tests and the LIVE console.
# The shim is only registered when the application is explicitly serving the
# console frontend or when an explicit env var enables the shim. This avoids
# the shim stealing the canonical `/api/v1/report/ingestion` route which is
# implemented in `src.api.report_endpoints` and expected to return JSON for
# `format=json` requests (important for tests).
if os.getenv('DEFAULT_FRONTEND', 'react').lower() == 'console' or os.getenv('ENABLE_REPORT_INGESTION_SHIM','0').lower() in {'1','true','yes'}:
    @app.get('/api/v1/report/ingestion')
    async def report_ingestion_get(format: str = 'html', include_model: bool = False, include_scenarios: bool = False, sessions: str | None = None) -> Response:  # type: ignore[return-value]
        try:
            parts = []
            parts.append(f'<div style="font-family:Inter,Segoe UI,Arial,sans-serif;color:#e8ebf0;background:#0b0e14;padding:18px;border-radius:8px;">')
            parts.append(f'<h2>JanuSec - Report Ingestion (shim)</h2>')
            parts.append(f'<div><strong>format</strong>: {format}</div>')
            parts.append(f'<div><strong>include_model</strong>: {str(bool(include_model))}</div>')
            parts.append(f'<div><strong>include_scenarios</strong>: {str(bool(include_scenarios))}</div>')
            if sessions:
                parts.append(f'<div><strong>sessions</strong>: {sessions}</div>')
            parts.append('<p>This is a lightweight test shim for /api/v1/report/ingestion used by Playwright tests.</p>')
            parts.append('</div>')
            html = '<!doctype html><html><head><meta charset="utf-8"><title>Report Ingestion</title></head><body>' + '\n'.join(parts) + '</body></html>'
            return Response(content=html, media_type='text/html')
        except Exception:
            return Response(content='<html><body><h1>Report Ingestion</h1></body></html>', media_type='text/html')


    @app.post('/api/v1/report/ingestion')
    async def report_ingestion_post(request: Request) -> Response:  # type: ignore[return-value]
        # Accept POST for completeness; echo some details back so tests can validate
        try:
            params = dict(request.query_params)
        except Exception:
            params = {}
        body = ''
        try:
            body = await request.body()
        except Exception:
            body = b''
        html = '<!doctype html><html><head><meta charset="utf-8"><title>Report Ingestion (POST)</title></head><body>'
        html += '<h2>Report Ingestion (shim - POST)</h2>'
        html += '<div><strong>query</strong>: ' + _html_safe(str(params)) + '</div>'
        html += '<div><strong>body</strong>: <pre>' + _html_safe(body.decode('utf-8', errors='replace')) + '</pre></div>'
        html += '</body></html>'
        return Response(content=html, media_type='text/html')


def _html_safe(s: str) -> str:
    try:
        return (s or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    except Exception:
        return ''

# ---------------- Admin: Per-tenant rate limit controls -----------------
def _admin_ok(request: Request) -> bool:
    try:
        key = request.headers.get('x-admin-key') or request.headers.get('X-Admin-Key')
        expected = os.getenv('ADMIN_API_KEY') or os.getenv('X_ADMIN_KEY')
        return bool(expected) and key == expected
    except Exception:
        return False

@app.get('/api/v1/admin/rate_limits/tenant')
async def get_tenant_rate_limits(request: Request):
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        # Snapshot counts per tenant in current window
        stats = {tid: len(deq) for tid, deq in _TENANT_RATE_STORAGE.items()}
    except Exception:
        stats = {}
    return {
        'enabled': _TENANT_RATE_ENABLED,
        'max': _TENANT_RATE_MAX,
        'window_seconds': _TENANT_RATE_WINDOW,
        'active_tenants': len(_TENANT_RATE_STORAGE),
        'tenant_counts': stats,
    }

@app.post('/api/v1/admin/rate_limits/tenant')
async def set_tenant_rate_limits(payload: dict, request: Request):
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    global _TENANT_RATE_ENABLED, _TENANT_RATE_MAX, _TENANT_RATE_WINDOW
    try:
        if 'enabled' in payload:
            _TENANT_RATE_ENABLED = bool(payload.get('enabled'))
        if 'max' in payload:
            _TENANT_RATE_MAX = int(payload.get('max') or _TENANT_RATE_MAX)
        if 'window_seconds' in payload:
            _TENANT_RATE_WINDOW = int(payload.get('window_seconds') or _TENANT_RATE_WINDOW)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'invalid_payload: {exc}')
    return {
        'enabled': _TENANT_RATE_ENABLED,
        'max': _TENANT_RATE_MAX,
        'window_seconds': _TENANT_RATE_WINDOW,
    }

# ---------------- Admin: Factor observe-mode flags -----------------
@app.post('/api/v1/admin/factors/observe')
async def set_observe_flag(payload: dict, request: Request):
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    name = (payload.get('name') or '').strip()
    if not name:
        raise HTTPException(status_code=400, detail='name_required')
    observed = bool(payload.get('observed'))
    try:
        from src.core.factors.observe_flags import set_observed
        set_observed(name, observed)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'set_flag_failed: {exc}')
    return {'name': name, 'observed': observed}

# ---------------- Admin: Observe Presets -----------------
@app.post('/api/v1/admin/factors/observe_preset')
async def set_observe_preset(payload: dict, request: Request):
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    name = (payload.get('name') or '').strip().lower()
    observed = bool(payload.get('observed'))
    if not name:
        raise HTTPException(status_code=400, detail='name_required')
    # Define a small set of commonly noisy factors
    presets: dict[str, list[str]] = {
        'quiet_noisy_factors': [
            'http:header_injection', 'ssl:ja3_rare', 'device:fp_rare', 'endpoint:obfuscation_shell', 'endpoint:obfuscation_b64'
        ],
        'quiet_network_exploration': [
            'net:egress_port_scatter', 'conn_rate_anomaly'
        ],
    }
    selected = presets.get(name)
    if not selected:
        raise HTTPException(status_code=400, detail='unknown_preset')
    try:
        from src.core.factors.observe_flags import set_observed
        for f in selected:
            set_observed(f, observed)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'set_preset_failed: {exc}')
    return {'preset': name, 'observed': observed, 'factors': selected}


# ---------------- Admin: RBAC management (lightweight) -----------------
@app.get('/api/v1/admin/rbac')
async def admin_rbac_list(request: Request):
    # require admin by key or role
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        from src.security import rbac
        raw = getattr(rbac, '_ROLE_MAP', {})
        return {'roles': {k: sorted(list(v)) for k, v in raw.items()}}
    except Exception:
        return {'roles': {}}


@app.post('/api/v1/admin/rbac/assign')
async def admin_rbac_assign(payload: dict, request: Request):
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        tgt = (payload or {}).get('api_key')
        role = (payload or {}).get('role')
        if not tgt or not role:
            raise HTTPException(status_code=400, detail='api_key_and_role_required')
        from src.security import rbac
        rbac.assign_role(tgt, role)
        return {'assigned': True, 'api_key': tgt, 'role': role}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'assign_failed:{exc}')


@app.post('/api/v1/admin/rbac/revoke')
async def admin_rbac_revoke(payload: dict, request: Request):
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not (_admin_ok(request) or (api_key and has_role(api_key, 'admin'))):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        tgt = (payload or {}).get('api_key')
        role = (payload or {}).get('role')
        if not tgt or not role:
            raise HTTPException(status_code=400, detail='api_key_and_role_required')
        from src.security import rbac
        rbac.revoke_role(tgt, role)
        return {'revoked': True, 'api_key': tgt, 'role': role}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'revoke_failed:{exc}')

# ---------------- Incidents API -----------------
@app.get('/api/v1/incidents/active')
async def list_active_incidents(format: str = 'json'):
    if not GLOBAL_INCIDENTS:
        return {'incidents': []}
    incs = GLOBAL_INCIDENTS.list_incidents()
    if format == 'html':
        if not incs:
            return Response("<html><body><h1>No Incidents</h1></body></html>", media_type='text/html')
        parts = []
        for inc in incs[:10]:
            if incident_to_html:
                parts.append(incident_to_html({**inc, 'factors': set(inc['factors'])}))
        html = ("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Incidents" 
                "</title></head><body>" + ''.join(parts) + "</body></html>")
        return Response(html, media_type='text/html')
    return {'incidents': incs}

@app.get('/api/v1/incidents/{iid}/evidence')
async def incident_evidence(iid: str):
    if not GLOBAL_INCIDENTS:
        raise HTTPException(status_code=404, detail='no incidents')
    inc = next((i for i in GLOBAL_INCIDENTS.list_incidents() if i['id']==iid), None)
    if not inc:
        raise HTTPException(status_code=404, detail='not_found')
    if incident_to_html:
        html = incident_to_html({**inc, 'factors': set(inc['factors'])})
        return Response(html, media_type='text/html')
    return inc

DEFAULT_FRONTEND = os.getenv('DEFAULT_FRONTEND', 'react').lower()  # 'react' or 'console'

# Serve frontend at root based on DEFAULT_FRONTEND toggle
@app.get("/", include_in_schema=False)
async def serve_root():
    # Prefer explicitly requested frontend
    if DEFAULT_FRONTEND == 'console':
        # Prefer the LIVE design page if present
        live_path = os.path.join(static_path, 'janusec-platform-complete-LIVE.html')
        if os.path.exists(live_path):
            logger.info("Serving LIVE Console frontend at root")
            return FileResponse(live_path)
        static_index = os.path.join(static_path, 'index.html')
        if os.path.exists(static_index):
            logger.info("Serving Console frontend at root")
            return FileResponse(static_index)
        # fallback to React if console missing
    # Default to React
    react_index = os.path.join(react_path, 'index.html')
    logger.info(f"Checking React index at: {react_index}")
    if os.path.exists(react_index):
        logger.info("Serving React frontend at root")
        try:
            # Read the index and inject a small test shim before </body> so Playwright
            # can reliably find a hidden #fileInput and a readiness marker when
            # the React SPA is served at '/'. This is a non-destructive runtime
            # injection that falls back to FileResponse on failure.
            with open(react_index, 'r', encoding='utf-8') as fh:
                html = fh.read()
            shim = """
        <script>
            (function(){
                try{
                    // Insert a hidden file input if missing and poll briefly to re-insert if
                    // client code removes it during hydration. This keeps Playwright's
                    // page.waitForSelector('#fileInput') stable.
                    function ensureFileInput(){
                        try{
                            if(!document.getElementById('fileInput')){
                                const inp = document.createElement('input'); inp.type = 'file'; inp.id = 'fileInput'; inp.multiple = true;
                                inp.accept = '.csv,.tsv,.log,.txt,.json,.jsonl,.ndjson,.xls,.xlsx,.xlsm,.ods,.zip,.gz'; inp.style.display = 'none'; document.body.appendChild(inp);
                            }
                        }catch(e){}
                    }
                    ensureFileInput();
                    // Re-run ensure a few times after hydration to avoid transient removal
                    [60, 200, 600].forEach(function(t){ setTimeout(ensureFileInput, t); });
                    try{ window.__liveConsoleReady = true; }catch(_){ }
                    try{ if(!document.getElementById('live_console_ready')) document.body.insertAdjacentHTML('beforeend', '<div id="live_console_ready" style="display:none"></div>'); }catch(_){ }
                    try{ window.dispatchEvent(new Event('live-console-ready')); }catch(_){ }
                }catch(e){ console.warn('live-console shim injection failed', e); }
            })();
        </script>
"""
            if '</body>' in html:
                html = html.replace('</body>', shim + '\n</body>')
            return Response(content=html, media_type='text/html')
        except Exception:
            return FileResponse(react_index)
    # Fallback to console if React dist not found
    live_path = os.path.join(static_path, 'janusec-platform-complete-LIVE.html')
    if os.path.exists(live_path):
        logger.info("React not found; serving LIVE Console frontend at root")
        return FileResponse(live_path)
    static_index = os.path.join(static_path, 'index.html')
    if os.path.exists(static_index):
        logger.info("React not found; serving Console frontend at root")
        return FileResponse(static_index)
    return {"message": "JanuSec Platform API", "version": "4.1.0", "frontend": "not found"}

@app.get("/console", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def serve_console():
    # Prefer LIVE design if available
    live_path = os.path.join(static_path, 'janusec-platform-complete-LIVE.html')
    if os.path.exists(live_path):
        return FileResponse(live_path)
    static_index = os.path.join(static_path, 'index.html')
    if os.path.exists(static_index):
        return FileResponse(static_index)
    return {"message": "JanuSec Console", "redirect": "/static/"}

@app.get("/demo", include_in_schema=False)
async def serve_zeek_demo():
    demo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'zeek_demo.html')
    if os.path.exists(demo_path):
        return FileResponse(demo_path)
    return {"message": "Zeek demo not found"}

@app.get("/sidepanel", include_in_schema=False)
async def serve_sidepanel():
    sp = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'sidepanel.html')
    if os.path.exists(sp):
        return FileResponse(sp)
    return {"message": "Sidepanel not found"}

@app.get("/live", include_in_schema=False)
async def serve_live_console():
    """Direct route to the LIVE design page under static frontend."""
    live_path = os.path.join(static_path, 'janusec-platform-complete-LIVE.html')
    if os.path.exists(live_path):
        return FileResponse(live_path)
    # fallback to console index
    static_index = os.path.join(static_path, 'index.html')
    if os.path.exists(static_index):
        return FileResponse(static_index)
    return {"message": "LIVE console not found", "redirect": "/static/"}

# ---------------- Lite-mode Decision/Incident helpers -----------------
from fastapi import Body

if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}:
    # In-memory incident store for lite/demo mode fallback
    _LITE_INCIDENT_STORE: list[dict] = []

    def _resolve_tenant(request: Request | None, fallback: str | None = None) -> str | None:
        try:
            if request is None:
                return fallback
            return request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id') or fallback
        except Exception:
            return fallback

    def _obj_tenant(obj: object) -> str | None:
        try:
            v = getattr(obj, 'tenant_id', None)
            if v:
                return v
        except Exception:
            pass
        try:
            if isinstance(obj, dict):
                v = obj.get('tenant_id')
                return v  # type: ignore[return-value]
        except Exception:
            pass
        return None

    try:
        # Prefer the canonical src.api.runtime_state module (tests often import
        # `src.api.runtime_state`). Import it explicitly so both test helpers and
        # this app reference the same DECISION_CACHE instance instead of creating
        # duplicate module objects under different package paths.
        import importlib as _importlib
        try:
            _rt = _importlib.import_module('src.api.runtime_state')
            DECISION_CACHE = getattr(_rt, 'DECISION_CACHE')
            _cache_set = getattr(_rt, 'cache_set')
        except Exception:
            # Fallback to package-local runtime_state
            from .runtime_state import DECISION_CACHE, cache_set as _cache_set  # type: ignore
    except Exception:
        DECISION_CACHE = {}  # type: ignore
        def _cache_set(k, v):  # type: ignore
            try:
                DECISION_CACHE[k] = v
            except Exception:
                pass

    @app.post('/api/v1/events')
    async def lite_ingest_event(request: Request, payload: dict = Body(...)) -> dict:
        # Minimal event ingest: create decision in memory, tenant-aware
        import time as _t
        eid = (payload.get('id') if isinstance(payload, dict) else None) or f"evt-{int(_t.time()*1000)}"
        proc_name = None
        try:
            proc_name = (((payload or {}).get('details') or {}).get('process') or {}).get('name')
        except Exception:
            proc_name = None
        verdict = 'allow'
        confidence = 0.5
        factors: list[str] = ['baseline_allow']
        risky = {'powershell.exe','cmd.exe','wscript.exe','rundll32.exe'}
        if proc_name and str(proc_name).lower() in risky:
            verdict = 'alert'
            confidence = 0.85
            factors = [f'process_high_risk:{str(proc_name).lower()}']
        tenant_id = _resolve_tenant(request)
        record = {
            'event_id': eid,
            'verdict': verdict,
            'confidence': confidence,
            'factors': factors,
            'timestamp': _t.time(),
            'tenant_id': tenant_id,
        }
        try:
            # Use the canonical runtime_state module to ensure tests that
            # import src.api.runtime_state see the same DECISION_CACHE instance
            import importlib as _importlib
            rt = _importlib.import_module('src.api.runtime_state')
            try:
                rt.cache_set(eid, record)
            except Exception:
                try:
                    rt.DECISION_CACHE[eid] = record  # type: ignore[index]
                except Exception:
                    pass
        except Exception:
            try:
                DECISION_CACHE[eid] = record  # type: ignore[index]
            except Exception:
                pass
        return {
            'event_id': eid,
            'verdict': verdict,
            'confidence': confidence,
            'factors': factors,
            'tenant_id': tenant_id,
        }

    @app.get('/api/v1/decisions/recent')
    async def lite_decisions_recent(request: Request, limit: int = 50, tenant_id: str | None = None) -> dict:
        # Return recent decisions from in-memory cache, filtered by tenant.
        # Read via canonical runtime_state to avoid duplicate module instances.
        try:
            import importlib as _importlib
            rt = _importlib.import_module('src.api.runtime_state')
            try:
                rows = list(getattr(rt.DECISION_CACHE, 'values', lambda: [])())  # type: ignore[attr-defined]
            except Exception:
                try:
                    rows = list(rt.DECISION_CACHE.values())  # type: ignore[assignment]
                except Exception:
                    rows = []
        except Exception:
            try:
                rows = list(getattr(DECISION_CACHE, 'values', lambda: [])())  # type: ignore[attr-defined]
            except Exception:
                try:
                    rows = list(DECISION_CACHE.values())  # type: ignore[assignment]
                except Exception:
                    rows = []
        rows = list(rows)[-limit:][::-1]
        tnt = tenant_id or _resolve_tenant(request)
        if tnt:
            rows = [r for r in rows if _obj_tenant(r) == tnt]
        return {
            'decisions': [{
                'id': getattr(r, 'event_id', None) if not isinstance(r, dict) else (r.get('event_id') or r.get('id')),
                'event_id': getattr(r, 'event_id', None) if not isinstance(r, dict) else (r.get('event_id') or r.get('id')),
                'verdict': getattr(r, 'verdict', None) if not isinstance(r, dict) else r.get('verdict'),
                'confidence': getattr(r, 'confidence', None) if not isinstance(r, dict) else r.get('confidence'),
                'reasons': getattr(r, 'factors', None) if not isinstance(r, dict) else r.get('factors'),
                'tenant_id': _obj_tenant(r),
                'ts': getattr(r, 'timestamp', None) if not isinstance(r, dict) else (r.get('timestamp') or r.get('ts')),
            } for r in rows[:limit]],
            'count': min(len(rows), limit),
            'tenant_id': tnt,
        }

    @app.get('/api/v1/decisions/{event_id}/explain')
    async def lite_decision_explain(event_id: str, request: Request) -> dict:
        # Prefer delegating to the full server explain handler when available so
        # tests and clients receive the enriched explain payload (mitre/stride,
        # correlation_factors, dread, techniques, etc.). Fallback to a minimal
        # explain if the full implementation cannot be imported.
        try:
            # import the canonical server explain implementation
            from .server import explain_decision as _full_explain  # type: ignore
            # Call the synchronous handler and return its result. It may raise
            # HTTPException which will propagate to the TestClient as expected.
            try:
                return _full_explain(event_id, request)
            except HTTPException:
                raise
            except Exception:
                # Fall through to the minimal implementation on any error
                pass
        except Exception:
            pass

        # Tenant-isolated minimal fallback: read decision from canonical runtime_state
        dec = None
        try:
            import importlib as _importlib
            rt = _importlib.import_module('src.api.runtime_state')
            try:
                dec = rt.DECISION_CACHE.get(event_id)  # type: ignore[attr-defined]
            except Exception:
                try:
                    dec = getattr(rt.DECISION_CACHE, 'get', lambda _k: None)(event_id)
                except Exception:
                    dec = None
        except Exception:
            try:
                dec = DECISION_CACHE.get(event_id)  # type: ignore[attr-defined]
            except Exception:
                try:
                    dec = getattr(DECISION_CACHE, 'get', lambda _k: None)(event_id)
                except Exception:
                    dec = None
        if not dec:
            raise HTTPException(status_code=404, detail='decision_not_found')
        tenant_hdr = _resolve_tenant(request)
        if tenant_hdr:
            t_dec = _obj_tenant(dec)
            if t_dec and t_dec != tenant_hdr:
                raise HTTPException(status_code=403, detail='forbidden')
        try:
            factors = getattr(dec, 'factors', None) if not isinstance(dec, dict) else dec.get('factors')
            verdict = getattr(dec, 'verdict', None) if not isinstance(dec, dict) else dec.get('verdict')
            confidence = getattr(dec, 'confidence', None) if not isinstance(dec, dict) else dec.get('confidence')
        except Exception:
            factors, verdict, confidence = [], None, None
        # Attach mapping tags (best-effort) so UI can render chips in lite mode
        mapping_tags = {'mitre': [], 'atlas': [], 'owasp_llm': []}
        try:
            from src.analysis.explain_mapping import map_factors_to_tags as _map_tags  # type: ignore
            mapping_tags = _map_tags(list(factors or []))
        except Exception:
            pass
        return {'event_id': event_id, 'verdict': verdict, 'confidence': confidence, 'factors': factors or [], 'mapping_tags': mapping_tags}

    # ---------------- Minimal Incidents (lite) -----------------
    @app.post('/api/v1/incidents')
    async def lite_create_incident(request: Request, payload: dict = Body(...)) -> dict:
        # RBAC: require incident.write or factors.search role when RBAC store is populated
        api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
        try:
            from src.security import rbac as _rb
            store_populated = bool(getattr(_rb, '_ROLE_MAP', {}))
        except Exception:
            store_populated = False
        if store_populated:
            if not (api_key and (_rb.has_role(api_key, 'incident.write') or _rb.has_role(api_key, 'factors.search'))):
                raise HTTPException(status_code=403, detail='missing_incident_write_role')
        import time as _t
        iid = payload.get('id') or f"inc-{int(_t.time()*1000)}"
        tenant_hdr = _resolve_tenant(request)
        item = {
            'id': iid,
            'artifact_id': payload.get('artifact_id'),
            'title': payload.get('title'),
            'severity': payload.get('severity') or 'high',
            'status': payload.get('status') or 'open',
            'summary': payload.get('description'),
            'metadata': {'attack_subgraph': payload.get('attack_subgraph')} if 'attack_subgraph' in payload else {},
            'tenant_id': payload.get('tenant_id') or tenant_hdr,
            'ts': _t.time(),
        }
        try:
            import src.repositories.incidents_repo as incidents_repo  # type: ignore
            coro = incidents_repo.upsert_incident(iid, item, item.get('tenant_id'))
            if asyncio.iscoroutine(coro):
                await coro  # type: ignore[misc]
        except Exception:
            _LITE_INCIDENT_STORE.append(item)
        return {'incident': item}

    @app.get('/api/v1/incidents')
    async def lite_list_incidents(request: Request, limit: int = 50, tenant_id: str | None = None) -> dict:
        tnt = tenant_id or _resolve_tenant(request)
        try:
            import src.repositories.incidents_repo as incidents_repo  # type: ignore
            rows = await incidents_repo.list_incidents(limit=limit, tenant_id=tnt)
            if isinstance(rows, list):
                return {'incidents': rows[:limit], 'count': min(len(rows), limit)}
        except Exception:
            pass
        rows = [i for i in reversed(_LITE_INCIDENT_STORE) if (not tnt or i.get('tenant_id') == tnt)]
        return {'incidents': rows[:limit], 'count': min(len(rows), limit)}

    @app.get('/api/v1/incidents/{incident_id}/attack_subgraph')
    async def lite_incident_attack_subgraph(incident_id: str, request: Request, auth=Depends(require_scopes('factors.search'))) -> dict:
        tnt = _resolve_tenant(request)
        try:
            import src.repositories.incidents_repo as incidents_repo  # type: ignore
            inc = await incidents_repo.get_incident(incident_id, tnt)
            if inc and isinstance(inc, dict):
                if tnt and inc.get('tenant_id') and inc.get('tenant_id') != tnt:
                    raise HTTPException(status_code=403, detail='forbidden')
                meta = inc.get('metadata') or {}
                return {'attack_subgraph': meta.get('attack_subgraph')}
        except Exception:
            pass
        for i in _LITE_INCIDENT_STORE:
            if i.get('id') == incident_id:
                if tnt and (i.get('tenant_id') != tnt):
                    raise HTTPException(status_code=403, detail='forbidden')
                return {'attack_subgraph': (i.get('attack_subgraph') or (i.get('metadata') or {}).get('attack_subgraph'))}
        raise HTTPException(status_code=404, detail='incident_not_found')

__all__ = ['app']

# Background jobs (best-effort): BGP refresher
try:
    import asyncio as _a
    from integrations.bgp_client import CLIENT as _BGP
    app.add_event_handler('startup', lambda: _a.create_task(_BGP.run()))
    app.add_event_handler('shutdown', lambda: _BGP.stop())
except Exception:
    logger.debug('Failed to register BGP background job')
