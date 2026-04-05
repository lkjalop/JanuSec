#!/usr/bin/env python3
"""Ingest rows from dump/Cyberstash_csv2_sample.csv into GLOBAL_HOPGRAPH.
Maps CSV columns to event fields expected by HopGraph.ingest_event.
"""
import csv
from pathlib import Path
import time

IN_CSV = Path('dump/Cyberstash_csv2_sample.csv')
if not IN_CSV.exists():
    print('CSV file not found:', IN_CSV)
    raise SystemExit(2)

try:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH
except Exception:
    from graph.hopgraph import GLOBAL_HOPGRAPH

before = sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())
print('Edges before:', before)

added = 0
hosts_seen = set()
with IN_CSV.open(encoding='utf-8', newline='') as fh:
    rdr = csv.reader(fh)
    headers = next(rdr, [])
    for i, row in enumerate(rdr):
        data = {headers[j]: (row[j] if j < len(row) else '') for j in range(len(headers))}
        evt = {
            'timestamp': time.time(),
            'host': data.get('host') or data.get('host_name'),
            'process': data.get('process_name') or data.get('process'),
            'file_hash': data.get('hash') or data.get('file_hash'),
            'command_line': data.get('command_line'),
            'user': data.get('user'),
            'src_ip': data.get('src_ip') or None,
            'dst_ip': data.get('dst_ip') or None,
        }
        try:
            from src.core.graph.hopgraph_utils import safe_upsert_node
        except Exception:
            safe_upsert_node = None
        try:
            if safe_upsert_node is not None and evt.get('type') == 'file_hash' and evt.get('id'):
                safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', evt.get('id'), attrs=evt.get('attrs') or {}, source='csv_manual_ingest')
            else:
                try:
                    from src.core.graph.hopgraph_utils import safe_upsert_node
                except Exception:
                    safe_upsert_node = None
                if evt.get('type') == 'file_hash' and evt.get('id') and safe_upsert_node is not None:
                    try:
                        safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', evt.get('id'), attrs=evt.get('attrs') or {}, source='csv_manual_ingest')
                    except Exception:
                        try:
                            GLOBAL_HOPGRAPH.ingest_event(evt, source='csv_manual_ingest')
                        except Exception:
                            pass
                else:
                    try:
                        GLOBAL_HOPGRAPH.ingest_event(evt, source='csv_manual_ingest')
                    except Exception:
                        pass
        except Exception:
            try:
                GLOBAL_HOPGRAPH.ingest_event(evt, source='csv_manual_ingest')
            except Exception:
                pass
        added += 1
        if evt.get('host'):
            hosts_seen.add(evt.get('host'))

after = sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())
print('Ingested events:', added)
print('Edges after:', after)

# run explain on first host-like name
sample = None
for h in hosts_seen:
    if h:
        sample = f'host:{h}'
        break

if sample:
    print('Running explain for', sample)
    ex = GLOBAL_HOPGRAPH.explain_chain(start=sample, max_depth=4, beam_width=8, top_k=5)
    import json
    print(json.dumps(ex, indent=2))
else:
    print('No host available for explain')
