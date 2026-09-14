import os
import os, json, importlib, sys, pytest, time

LOG_PATH = os.path.join(os.getcwd(), 'logs', 'probe_httpx.log')
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

def _snapshot(phase: str, nodeid: str):
    try:
        httpx_mod = importlib.import_module('httpx') if 'httpx' in sys.modules else None
    except Exception:
        httpx_mod = None
    try:
        consumer = importlib.import_module('scripts.redis_streams_consumer')
        consumer_httpx = getattr(consumer, 'httpx', None)
        module_flag = getattr(consumer, 'MODULE_TEST_MODE', None)
    except Exception:
        consumer_httpx = None
        module_flag = None
    entry = {
        'ts': time.time(),
        'phase': phase,
        'test': nodeid,
        'env_JANUSEC_TEST_MODE': os.environ.get('JANUSEC_TEST_MODE'),
        'module_test_mode': module_flag,
        'httpx_repr': repr(httpx_mod)[:140],
        'consumer_httpx_repr': repr(consumer_httpx)[:140],
        'httpx_id': id(httpx_mod) if httpx_mod else None,
        'consumer_httpx_id': id(consumer_httpx) if consumer_httpx else None,
    }
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception:
        pass
    # Also emit a small debug log so pytest CLI logging can capture it when enabled
    try:
        import logging
        _log = logging.getLogger('tests.probe')
        _log.debug('PROBE %s: %s httpx_id=%s consumer_httpx_id=%s module_test_mode=%s env=%s', phase.upper(), nodeid, entry.get('httpx_id'), entry.get('consumer_httpx_id'), entry.get('module_test_mode'), entry.get('env_JANUSEC_TEST_MODE'))
    except Exception:
        pass

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    _snapshot('setup', item.nodeid)

@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item, nextitem):
    _snapshot('teardown', item.nodeid)



