import json
import os
import tempfile
from importlib import reload

from src.live import alert_store


def test_alert_store_integrity_chain(tmp_path):
    os.environ['ALERTS_LOG_PATH'] = str(tmp_path / 'alerts.jsonl')
    os.environ['ALERTS_MAX_BYTES'] = '100000'
    reload(alert_store)
    alert_store.append({'id':'a1','ts':1,'host':'h','verdict':'ALERT','score':0.9})
    alert_store.append({'id':'a2','ts':2,'host':'h','verdict':'ALERT','score':0.91})
    ok, err = alert_store.verify()
    assert ok, err
    # Tamper second line
    path = tmp_path / 'alerts.jsonl'
    lines = path.read_text(encoding='utf-8').splitlines()
    rec2 = json.loads(lines[1])
    rec2['host'] = 'evil'
    lines[1] = json.dumps(rec2)
    path.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    ok2, err2 = alert_store.verify()
    assert not ok2 and 'hash_mismatch' in err2
