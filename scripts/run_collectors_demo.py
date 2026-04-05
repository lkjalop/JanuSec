"""Demo runner to execute collectors in mock mode and forward normalized events
to the pipeline. Useful for local demos and smoke testing.
"""
import sys
import os
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.modules.collectors.runner import run_collectors_sync


def ingest_event(event, source='collector_demo'):
    try:
        # Try to use pipeline ingestion helper if available
        from src.pipeline.runner import ingest_event as ingest_fn
        ingest_fn(event, source=source)
        return True
    except Exception:
        # As fallback, just print minimal summary
        print(f"INGEST [{source}]: {event.get('event_type')} from {event.get('from_address')} -> {event.get('to_address')}")
        return False


def main():
    events = run_collectors_sync(since=datetime.utcnow(), mock=True)
    for e in events:
        ingest_event(e, source=e.get('source', 'collector'))


if __name__ == '__main__':
    main()
