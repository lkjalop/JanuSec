from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

AUDIT_PATH = os.getenv('PLAYBOOK_CONNECTOR_AUDIT_PATH', 'data/playbook_connector_audit.log')


def record_audit(entry: Dict[str, Any]):
    os.makedirs(os.path.dirname(AUDIT_PATH) or '.', exist_ok=True)
    payload = dict(entry)
    payload.setdefault('ts', time.time())
    try:
        with open(AUDIT_PATH, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(payload, separators=(',', ':')) + '\n')
    except Exception:
        # best-effort; don't raise
        pass
