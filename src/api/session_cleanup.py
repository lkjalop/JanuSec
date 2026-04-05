"""
Background session & EWMA cleanup task registration.
Runs a periodic pass to delete old session files under SESSION_PERSIST_DIR
and prune EWMA history file entries older than configured TTL.
"""
import os, time, json
from typing import Any

def register_session_cleanup(app):
    try:
        interval = int(os.getenv('SESSION_CLEAN_INTERVAL_SECONDS','0') or 0)
    except Exception:
        interval = 0
    if interval <= 0:
        return

    sess_dir = os.getenv('SESSION_PERSIST_DIR', os.path.join('data','sessions'))
    assessments_dir = os.getenv('ASSESSMENTS_PERSIST_DIR') or os.path.join('data', 'assessments')
    ewma_path = os.getenv('EWMA_HISTORY_PATH', os.path.join(sess_dir, 'ewma_history.json'))
    ttl = int(os.getenv('SESSION_TTL_SECONDS','86400') or 86400)
    ewma_ttl = int(os.getenv('EWMA_HISTORY_TTL_SECONDS','86400') or 86400)

    def _prune_assessment_tree(base: str, cutoff: float) -> None:
        if not os.path.isdir(base):
            return
        for orgdir in list(os.listdir(base)):
            org_path = os.path.join(base, orgdir)
            if not os.path.isdir(org_path):
                continue
            for datedir in list(os.listdir(org_path)):
                date_path = os.path.join(org_path, datedir)
                if not os.path.isdir(date_path):
                    continue
                for fname in list(os.listdir(date_path)):
                    path = os.path.join(date_path, fname)
                    try:
                        if os.path.isfile(path) and (os.path.getmtime(path) < cutoff):
                            os.remove(path)
                    except Exception:
                        pass
                # remove empty date directories
                try:
                    if not os.listdir(date_path):
                        os.rmdir(date_path)
                except Exception:
                    pass
            try:
                if not os.listdir(org_path):
                    os.rmdir(org_path)
            except Exception:
                pass

    async def _loop():
        import asyncio
        while True:
            try:
                now = time.time()
                # prune session files older than ttl
                try:
                    if os.path.isdir(sess_dir):
                        for fn in os.listdir(sess_dir):
                            if not fn.lower().endswith('.json'):
                                continue
                            p = os.path.join(sess_dir, fn)
                            try:
                                stat = os.stat(p)
                                if (now - stat.st_mtime) > ttl:
                                    try:
                                        os.remove(p)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                except Exception:
                    pass
                # prune persisted assessment artifacts
                try:
                    cutoff = now - ttl
                    _prune_assessment_tree(assessments_dir, cutoff)
                except Exception:
                    pass
                # prune ewma history entries older than ewma_ttl
                try:
                    if os.path.exists(ewma_path):
                        with open(ewma_path,'r',encoding='utf-8') as fh:
                            h = json.load(fh)
                        changed = False
                        for k in list(h.keys()):
                            ts = h.get(k, {}).get('ts', 0) or 0
                            if (now - ts) > ewma_ttl:
                                h.pop(k, None)
                                changed = True
                        if changed:
                            try:
                                with open(ewma_path,'w',encoding='utf-8') as fh:
                                    json.dump(h, fh)
                            except Exception:
                                pass
                except Exception:
                    pass
            except Exception:
                pass
            await asyncio.sleep(max(5, interval))
    try:
        app.add_event_handler('startup', lambda: __import__('asyncio').create_task(_loop()))
    except Exception:
        try:
            import asyncio
            asyncio.create_task(_loop())
        except Exception:
            pass

__all__ = ['register_session_cleanup']
