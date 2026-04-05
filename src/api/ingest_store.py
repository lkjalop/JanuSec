"""Simple in-memory ingest store for demo event_ids."""
import threading
import time
import uuid

_lock = threading.Lock()
_store = {}

def create_event_for_row(row):
    """Create a synthetic event and return an event_id."""
    with _lock:
        eid = str(uuid.uuid4())
        _store[eid] = {
            'event_id': eid,
            'created_at': time.time(),
            'row': row,
        }
        return eid

def get_event(eid):
    return _store.get(eid)
