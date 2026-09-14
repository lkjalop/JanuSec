import os
import json
import time
from typing import Any, Dict, Optional

DATA_DIR = os.getenv('TENANT_PERSIST_DIR', os.path.join(os.getcwd(), 'data', 'tenants'))
TTL_DEFAULT = int(os.getenv('TENANT_INACTIVE_TTL_SECONDS', '3600'))

def _ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass

def tenant_path(tenant: str) -> str:
    return os.path.join(DATA_DIR, tenant)

def persist_tenant_partition(tenant: str, payload: Dict[str, Any]) -> bool:
    try:
        _ensure_dir(tenant_path(tenant))
        path = os.path.join(tenant_path(tenant), 'partition.json')
        payload = payload.copy()
        payload['_persisted_ts'] = time.time()
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh)
        return True
    except Exception:
        return False

def load_tenant_partition(tenant: str) -> Optional[Dict[str, Any]]:
    try:
        path = os.path.join(tenant_path(tenant), 'partition.json')
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None

def prune_inactive_tenants(ttl_seconds: int | None = None) -> int:
    """Remove tenant dirs whose persisted timestamp is older than TTL.

    Returns number of pruned tenants.
    """
    ttl = ttl_seconds if ttl_seconds is not None else TTL_DEFAULT
    pruned = 0
    try:
        if not os.path.isdir(DATA_DIR):
            return 0
        for name in os.listdir(DATA_DIR):
            tdir = os.path.join(DATA_DIR, name)
            if not os.path.isdir(tdir):
                continue
            part = load_tenant_partition(name)
            if not part:
                # no partition file — consider stale and remove
                try:
                    # best-effort remove file tree
                    for root, dirs, files in os.walk(tdir, topdown=False):
                        for f in files:
                            try:
                                os.remove(os.path.join(root, f))
                            except Exception:
                                pass
                        for d in dirs:
                            try:
                                os.rmdir(os.path.join(root, d))
                            except Exception:
                                pass
                    try:
                        os.rmdir(tdir)
                        pruned += 1
                    except Exception:
                        pass
                except Exception:
                    pass
                continue
            ts = float(part.get('_persisted_ts') or 0)
            if (time.time() - ts) >= ttl:
                try:
                    for root, dirs, files in os.walk(tdir, topdown=False):
                        for f in files:
                            try:
                                os.remove(os.path.join(root, f))
                            except Exception:
                                pass
                        for d in dirs:
                            try:
                                os.rmdir(os.path.join(root, d))
                            except Exception:
                                pass
                    try:
                        os.rmdir(tdir)
                        pruned += 1
                    except Exception:
                        pass
                except Exception:
                    pass
    except Exception:
        pass
    return pruned
