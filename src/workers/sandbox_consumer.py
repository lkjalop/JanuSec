import sqlite3
import time
import json
from pathlib import Path
from src.workers.static_analyzer import analyze_pe_bytes
from src.repositories.feature_store_repo import FeatureStoreRepo


def _get_db_path():
    return Path('data') / 'app.db'


def process_once(db_path: str | None = None):
    db = str(_get_db_path())
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    try:
        cur.execute('SELECT id, payload_json, status FROM sandbox_queue WHERE status = "pending" LIMIT 1')
    except Exception:
        conn.close()
        return None
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    id, payload_json, status = row
    try:
        payload = json.loads(payload_json)
    except Exception:
        payload = {'filename': payload_json}
    # locate possible file under data/uploads or same-dir
    candidates = [Path('data/uploads') / payload.get('filename', ''), Path(payload.get('filename', ''))]
    fpath = None
    for c in candidates:
        if c.exists():
            fpath = c
            break
    if not fpath:
        # mark missing
        cur.execute('UPDATE sandbox_queue SET status = ? WHERE id = ?', ('missing', id))
        conn.commit(); conn.close()
        return {'id': id, 'status': 'missing'}
    with open(fpath, 'rb') as fh:
        buf = fh.read()
    res = analyze_pe_bytes(buf)
    # persist into feature_store for downstream learners
    fs = FeatureStoreRepo()
    import asyncio
    evt_id = f'sandbox-{id}'
    asyncio.get_event_loop().run_until_complete(fs.init_db())
    asyncio.get_event_loop().run_until_complete(fs.write(evt_id, {'analysis': res, 'filename': str(fpath), 'ts': int(time.time())}))
    cur.execute('UPDATE sandbox_queue SET status = ? WHERE id = ?', ('done', id))
    conn.commit(); conn.close()
    return {'id': id, 'status': 'done', 'analysis': res}
