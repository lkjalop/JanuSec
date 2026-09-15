"""Replay gray-tier scenarios and report simple recall metrics.

Usage: python scripts/evaluate_gray_tier_recall.py
"""
import json
from pathlib import Path
import time
import importlib
import os

ROOT = Path(__file__).resolve().parents[1]
SCEN = ROOT / 'tests' / 'data' / 'gray_tier_scenarios.json'

def run_in_memory(scenarios):
    from src.core.graph import hopgraph_lite
    importlib.reload(hopgraph_lite)
    g = hopgraph_lite.get_graph()
    # clear
    try:
        g.edges_ts.clear()
        g.events.clear()
    except Exception:
        pass
    for s in scenarios:
        for ev in s.get('events', []):
            g.observe(ev)
    time.sleep(0.05)
    # simple recall metric: number of edges
    return len(g.edges_ts)

def run_with_persistence(scenarios, db_path):
    import os
    os.environ['HOPGRAPH_PERSISTENCE_ENABLED'] = 'true'
    os.environ['HOPGRAPH_DB_PATH'] = str(db_path)
    from src.core.graph import hopgraph_lite
    importlib.reload(hopgraph_lite)
    g = hopgraph_lite.get_graph()
    for s in scenarios:
        for ev in s.get('events', []):
            g.observe(ev)
    time.sleep(0.05)
    # count persisted edges via backend
    loaded = g.backend.load_graph()
    return len(loaded.get('edges', []))

def main():
    scenarios = json.loads(SCEN.read_text())
    print('Loaded', len(scenarios), 'scenarios')
    inm = run_in_memory(scenarios)
    print('In-memory edges:', inm)
    db = ROOT / 'data' / 'gray_test_hopgraph.db'
    db.parent.mkdir(parents=True, exist_ok=True)
    pers = run_with_persistence(scenarios, db)
    print('Persisted edges:', pers)
    print('Delta (persisted - in-memory):', pers - inm)
    if pers < 1:
        print('Warning: persisted edges < 1; persistence may not be working')
    else:
        print('Persistence recorded edges OK')
    # Graylabel sink stats
    sink = Path(os.getenv('GRAYLABEL_SINK_PATH', 'data/gray_tier_events.jsonl'))
    if sink.exists():
        try:
            lines = sink.read_text(encoding='utf-8').splitlines()
            print('Graylabel sink entries:', len(lines))
        except Exception:
            print('Graylabel sink entries: n/a')
    else:
        print('Graylabel sink not found at', sink)

if __name__ == '__main__':
    main()
