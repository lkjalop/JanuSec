import os
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('METRICS_DEBUG','1')

print('starting debug')
try:
    import importlib, sys, pathlib
    # Ensure repo root is on sys.path so `src` package can be imported
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    mi = importlib.import_module('src.api.metrics_init')
    print('imported metrics_init, REGISTRY=', getattr(mi,'REGISTRY',None))
    from prometheus_client import generate_latest
    try:
        txt = generate_latest(getattr(mi,'REGISTRY',None))
        if isinstance(txt, bytes):
            txt = txt.decode('utf-8',errors='ignore')
        print('generate_latest output len=', len(txt))
        print(txt.splitlines()[:10])
    except Exception as e:
        print('generate_latest raised:', type(e), e)
except Exception as e:
    import traceback
    print('exception importing metrics_init:')
    traceback.print_exc()
