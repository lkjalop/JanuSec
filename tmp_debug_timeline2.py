from src.api.app import create_app
from fastapi.testclient import TestClient
from src.core.event_store import append_event
import time, os, json
os.environ['EVENT_STORE_PATH'] = 'data/tmp_events.jsonl'
app = create_app({'mode':'test'})
client = TestClient(app)
append_event({'event_id':'evt_t1','sensor':'generic','ts': time.time()-5})
append_event({'event_id':'evt_t2','sensor':'generic','ts': time.time()})
resp = client.post('/api/v1/ingest/timeline', json={'events':['evt_t1','evt_t2']})
print('status', resp.status_code)
try:
    print('json', json.dumps(resp.json(), indent=2))
except Exception as e:
    print('body', resp.text)
