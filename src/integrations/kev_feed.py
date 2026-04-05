from __future__ import annotations

import os
import json
import time
import threading
from typing import Dict, Any

KEV_PATH = os.getenv('KEV_LOCAL_PATH','data/kev.json')
KEV_SOURCE = os.getenv('KEV_SOURCE_URL','https://example.com/kev.json')
_CACHE: Dict[str,Any] = {'data':{}, 'updated':0}

def load_local():
    try:
        if os.path.exists(KEV_PATH):
            with open(KEV_PATH,'r',encoding='utf-8') as f:
                _CACHE['data'] = json.load(f)
                _CACHE['updated'] = time.time()
    except Exception:
        pass

def tag_component(component_name: str) -> Dict[str,Any]:
    # naive lookup
    data = _CACHE.get('data',{})
    hits = data.get('components',{}).get(component_name, {})
    return hits

# simple background refresher thread
def start_refresher(interval: int = 3600):
    def _loop():
        while True:
            try:
                load_local()
            except Exception:
                pass
            time.sleep(interval)
    if not (os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST')):
        t = threading.Thread(target=_loop, name='kev-refresher', daemon=True)
        t.start()
