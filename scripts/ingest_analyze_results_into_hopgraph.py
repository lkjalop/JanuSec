#!/usr/bin/env python3
"""Read analyzer JSONL outputs and ingest into GLOBAL_HOPGRAPH with defensive mapping.
Produces per-line diagnostics when mappings fail and a final summary.
"""
import json
import time
from pathlib import Path

IN_PATH = Path('dump/session_manual_analyze.jsonl')
if not IN_PATH.exists():
    print('No analyze results found at', IN_PATH)
    raise SystemExit(2)

# import the canonical GLOBAL_HOPGRAPH
try:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH
except Exception:
    from graph.hopgraph import GLOBAL_HOPGRAPH

# Helper: load sample CSV rows if available (for correlation)
CSV_SAMPLE = Path('dump/Cyberstash_csv2_sample.csv')
csv_rows = []
if CSV_SAMPLE.exists():
    try:
        import csv as _csv
        with CSV_SAMPLE.open(encoding='utf-8', newline='') as fh:
            rdr = _csv.reader(fh)
            headers = next(rdr, [])
            for r in rdr:
                csv_rows.append({headers[i]: (r[i] if i < len(r) else '') for i in range(len(headers))})
        print(f'Loaded {len(csv_rows)} rows from {CSV_SAMPLE}')
    except Exception as e:
        print('Failed to load CSV sample:', e)
        csv_rows = []

before_edges = sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())
print('Edges before:', before_edges)

added = 0
line_no = 0
mapped_count = 0
unmapped_count = 0
for raw_line in IN_PATH.read_text(encoding='utf-8').splitlines():
    line_no += 1
    if not raw_line.strip():
        continue
    try:
        obj = json.loads(raw_line)
    except Exception as e:
        print(f'Line {line_no}: JSON parse error: {e}')
        continue
    # Try to map analyer row to CSV row via _row_index
    csv_row = None
    ri = obj.get('_row_index')
    if isinstance(ri, int) and 0 <= ri < len(csv_rows):
        csv_row = csv_rows[ri]
        print(f'Line {line_no}: mapped to CSV row index {ri}')
    else:
        # Try match by event_id against hash-like columns in CSV
        eid = obj.get('event_id') or obj.get('id') or obj.get('artifact_id')
        if eid and csv_rows:
            for r in csv_rows:
                for k in ('hash', 'file_hash', 'artifact_id', 'id'):
                    try:
                        if k in r and r[k] and str(r[k]).strip() == str(eid).strip():
                            csv_row = r
                            break
                    except Exception:
                        continue
                if csv_row:
                    print(f'Line {line_no}: matched CSV row by event_id/hash {eid}')
                    break
    # Compose event mapping
    host = None
    process = None
    file_hash = None
    if csv_row:
        mapped_count += 1
        host = csv_row.get('host') or csv_row.get('host_name') or csv_row.get('hostname')
        process = csv_row.get('process_name') or csv_row.get('process')
        file_hash = csv_row.get('hash') or csv_row.get('file_hash') or csv_row.get('artifact_id')
    else:
        unmapped_count += 1
        # fall back to analyzer raw fields
        raw = obj.get('raw') if isinstance(obj.get('raw'), dict) else obj
        host = raw.get('host') or raw.get('host_name')
        process = raw.get('process_name') or raw.get('process') or obj.get('process_name')
        file_hash = raw.get('hash') or raw.get('file_hash') or obj.get('event_id') or obj.get('id')
        if not (host or process or file_hash):
            print(f'Line {line_no}: no host/process/hash mapping for event_id={obj.get("event_id")}')
    evt = {
        'timestamp': time.time(),
        'host': host,
        'process': process,
        'file_hash': file_hash,
        'source': 'csv_analyzer'
    }
    try:
        try:
            from src.core.graph.hopgraph_utils import safe_upsert_node
        except Exception:
            safe_upsert_node = None
        try:
            if safe_upsert_node is not None and evt.get('type') == 'file_hash' and evt.get('id'):
                safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', evt.get('id'), attrs=evt.get('attrs') or {}, source='csv_analyze_ingest')
            else:
                GLOBAL_HOPGRAPH.ingest_event(evt, source='csv_analyze_ingest')
        except Exception:
            try:
                GLOBAL_HOPGRAPH.ingest_event(evt, source='csv_analyze_ingest')
            except Exception:
                pass
        added += 1
    except Exception as e:
        print(f'Line {line_no}: ingest_event failed: {e}')

after_edges = sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())
print('\nSummary:')
print('Lines processed:', line_no)
print('Mapped to CSV rows:', mapped_count)
print('Unmapped (used analyzer fields):', unmapped_count)
print('Ingested events:', added)
print('Edges before:', before_edges, 'after:', after_edges)

# Try running explain on any host found in the analyzer or csv sample
sample_host = None
for r in csv_rows:
    if r.get('host'):
        sample_host = f"host:{r.get('host')}".lower()
        break
if not sample_host:
    # scan analyzer file again for host
    for raw_line in IN_PATH.read_text(encoding='utf-8').splitlines():
        if not raw_line.strip():
            continue
        try:
            obj = json.loads(raw_line)
        except Exception:
            continue
        raw = obj.get('raw') if isinstance(obj.get('raw'), dict) else obj
        h = raw.get('host') or raw.get('host_name')
        if h:
            sample_host = f'host:{h}'.lower()
            break

if sample_host:
    print('\nExplain for', sample_host)
    ex = GLOBAL_HOPGRAPH.explain_chain(start=sample_host, max_depth=4, beam_width=8, top_k=5)
    print(json.dumps(ex, indent=2))
else:
    print('\nNo host found to run explain on')
