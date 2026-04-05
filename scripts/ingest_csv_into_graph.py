import os, sys, json, asyncio
here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
src_path = os.path.join(here, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Import the CSV processor via api.* and HopGraph via graph.* to ensure a single module path
from api.csv_handler import get_csv_processor
from graph.hopgraph import GLOBAL_HOPGRAPH

async def run():
    csvp = os.path.join(here, 'dump', 'Cyberstash_csv2_sample.csv')
    with open(csvp, 'rb') as f:
        content = f.read()
    proc = get_csv_processor()
    res = await proc.process_csv(content, filename='Cyberstash_csv2_sample.csv')
    print('Processed', res.get('processed'))
    # ingest each result into the canonical graph
    for r in res.get('results', []):
        raw = r.get('raw', {})
        event = {
            'timestamp': None,
            'host': raw.get('host'),
            'process': raw.get('process_name'),
            'pid': raw.get('pid'),
            'dst_ip': None,
            'src_ip': None,
            'domain': None,
            'file_hash': raw.get('hash'),
            'ja3': None,
            'certfp': None
        }
        try:
            from src.core.graph.hopgraph_utils import safe_upsert_node
        except Exception:
            safe_upsert_node = None
        try:
            if safe_upsert_node is not None and event.get('type') == 'file_hash' and event.get('id'):
                safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', event.get('id'), attrs=event.get('attrs') or {}, source='csv_upload')
            else:
                try:
                    from src.core.graph.hopgraph_utils import safe_upsert_node
                except Exception:
                    safe_upsert_node = None
                if event.get('type') == 'file_hash' and event.get('id') and safe_upsert_node is not None:
                    try:
                        safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', event.get('id'), attrs=event.get('attrs') or {}, source='csv_upload')
                    except Exception:
                        try:
                            GLOBAL_HOPGRAPH.ingest_event(event, source='csv_upload')
                        except Exception:
                            pass
                else:
                    try:
                        GLOBAL_HOPGRAPH.ingest_event(event, source='csv_upload')
                    except Exception:
                        pass
        except Exception:
            try:
                GLOBAL_HOPGRAPH.ingest_event(event, source='csv_upload')
            except Exception:
                pass
    print('Edges now:', sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values()))
    ex = GLOBAL_HOPGRAPH.explain_chain(start='host:host-alice', max_depth=4, beam_width=6, top_k=5)
    print('Explain for host:host-alice:')
    print(json.dumps(ex, indent=2))

if __name__ == '__main__':
    asyncio.run(run())
