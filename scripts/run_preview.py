"""Loopback-only deterministic preview and isolated test runner."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'tmp_preview'
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
state = OUT / ('server_state' if sys.argv[1] == 'server' else 'test_state')
state.mkdir(parents=True, exist_ok=True)
settings = {
    'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8',
    'PLATFORM_LITE_INIT': '1', 'SKIP_ISMS_SCAN': '1',
    'DISABLE_METRICS_AT_IMPORT': '1', 'DB_DISABLE_NETWORK_CONNECT': '1',
    'DEFAULT_FRONTEND': 'console', 'ENV': 'dev', 'APP_ENV': 'dev',
    'API_KEY': 'devkey123', 'API_KEYS_JSON': '[{"key":"devkey123","scopes":["*"],"tenant_id":"default"}]',
    'LLM_PROVIDER': 'deterministic', 'LLM_SUMMARIES_ENABLED': '0',
    'LLM_ALLOW_LOCAL_DETERMINISTIC': '1', 'DISABLE_BACKGROUND_TASKS': '1',
    'SESSION_CLEAN_INTERVAL_SECONDS': '0',
    'DB_FALLBACK_PATH': str(state / 'fallback.sqlite'),
    'JANUSEC_INGEST_DB': str(state / 'ingest.duckdb'),
    'JANUSEC_RAW_DIR': str(state / 'raw'),
    'SESSION_PERSIST_DIR': str(state / 'sessions'),
    'EWMA_HISTORY_PATH': str(state / 'ewma.json'),
    'HOPGRAPH_DB_PATH': str(state / 'hopgraph.db'),
    'TENANT_STORE_DIR': str(state / 'tenant_store'),
    'POLLING_STATE_DIR': str(state / 'polling_state'),
    'CONNECTORS_CHECKPOINT_DIR': str(state / 'checkpoints'),
    'TENANT_PERSIST_DIR': str(state / 'tenants'),
}
os.environ.update(settings)
if sys.argv[1] == 'server':
    import uvicorn
    uvicorn.run('src.api.server:app', host='127.0.0.1',
                port=int(os.getenv('JANUSEC_PREVIEW_PORT', '8081')), log_level='warning')
elif sys.argv[1] == 'pytest':
    import pytest
    raise SystemExit(pytest.main(sys.argv[2:]))
