#!/usr/bin/env python3
"""Ingest dump/janusec_batch1.json events directly into GLOBAL_HOPGRAPH.
This is a small helper to verify Zeek/XDR payloads produce hopgraph edges.
"""
import json
import sys
import time
from pathlib import Path

# Ensure project root on path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.graph.hopgraph import GLOBAL_HOPGRAPH


def edges_count():
    return sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())


def main():
    p = Path('dump/janusec_batch1.json')
    if not p.exists():
        print('Missing', p)
        return
    data = json.loads(p.read_text(encoding='utf-8'))
    events = data.get('events') or []
    print('Events to ingest:', len(events))
    before = edges_count()
    print('Edges before:', before)
    added = 0
    for ev in events:
        try:
            evt = {}
            evt['timestamp'] = ev.get('ts') or time.time()
            evt['host'] = ev.get('host')
            proc = ev.get('process') or {}
            evt['process'] = proc.get('name') or proc.get('proc_name')
            # try to pick a hash if present in details
            details = ev.get('details') or {}
            evt['file_hash'] = details.get('sha256') or details.get('md5') or details.get('sha1')
            try:
                from src.core.graph.hopgraph_utils import safe_upsert_node
            except Exception:
                safe_upsert_node = None
            try:
                if safe_upsert_node is not None and evt.get('type') == 'file_hash' and evt.get('id'):
                    safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', evt.get('id'), attrs=evt.get('attrs') or {}, source='janusec_batch')
                else:
                    try:
                        from src.core.graph.hopgraph_utils import safe_upsert_node
                    except Exception:
                        safe_upsert_node = None
                    if evt.get('type') == 'file_hash' and evt.get('id') and safe_upsert_node is not None:
                        try:
                            safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', evt.get('id'), attrs=evt.get('attrs') or {}, source='janusec_batch')
                        except Exception:
                            try:
                                GLOBAL_HOPGRAPH.ingest_event(evt, source='janusec_batch')
                            except Exception:
                                pass
                    else:
                        try:
                            GLOBAL_HOPGRAPH.ingest_event(evt, source='janusec_batch')
                        except Exception:
                            pass
            except Exception:
                try:
                    GLOBAL_HOPGRAPH.ingest_event(evt, source='janusec_batch')
                except Exception:
                    pass
            added += 1
        except Exception as e:
            print('ingest failed for event', ev.get('id'), e)
    after = edges_count()
    print('Ingested events:', added)
    print('Edges after:', after)
    # Show an example explain for first event host
    if events:
        host = events[0].get('host')
        if host:
            ex = GLOBAL_HOPGRAPH.explain_chain(start=f'host:{host}', max_depth=4, beam_width=6, top_k=3)
            print('Explain for host:', host)
            print(json.dumps(ex, indent=2)[:4000])


if __name__ == '__main__':
    main()
