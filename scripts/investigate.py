"""Investigate CLI: show top k-hop subgraph for a given node (event, host, ip)."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from graph.hopgraph import GLOBAL_HOPGRAPH

HTML_TEMPLATE = """<!DOCTYPE html><html><head><meta charset='utf-8'/><title>Investigation {node}</title>
<style>body{font-family:Arial;background:#111;color:#eee;padding:16px}table{border-collapse:collapse;width:100%;margin-top:1em}td,th{border:1px solid #444;padding:4px 6px;font-size:12px}h1{font-size:18px;margin:0 0 8px}code{color:#9cf}</style>
</head><body>
<h1>HopGraph Evidence Card: {node}</h1>
<h2>Nodes ({node_count})</h2>
<table><tr><th>Node ID</th><th>Created</th><th>Last Seen</th></tr>
{node_rows}
</table>
<h2>Edges ({edge_count})</h2>
<table><tr><th>Src</th><th>Dst</th><th>Type</th><th>Source</th><th>Timestamp</th></tr>
{edge_rows}
</table>
<p>Depth reached: {depth}</p>
</body></html>"""

def main():
    p = argparse.ArgumentParser(description='HopGraph Investigator')
    p.add_argument('node', nargs='?', help='Node id (host/ip/process/hash). If omitted and --from-events provided, derive from events.')
    p.add_argument('--from-events', action='store_true', help='Read newline-delimited JSON events from stdin and ingest before querying')
    p.add_argument('--hops', type=int, default=3)
    p.add_argument('--filter', nargs='*', help='Edge types to include')
    p.add_argument('--output', '-o', help='Optional output file (JSON or HTML if --html)')
    p.add_argument('--html', action='store_true', help='Render minimal HTML evidence card instead of raw JSON')
    args = p.parse_args()
    # Optional ingest from stdin
    if args.from_events:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except Exception:
                continue
            # Try ingestion
            try:
                from graph.ingest import ingest_event
                ingest_event(evt, source='cli')
                # If node unspecified, set to first host
                if args.node is None:
                    host = (evt.get('src_host') or evt.get('host') or evt.get('hostname'))
                    if host:
                        args.node = f'host:{host.lower()}'
            except Exception:
                pass
    if not args.node:
        print("ERROR: node argument missing and no derivable host from events", file=sys.stderr)
        return 1
    filt = set(args.filter) if args.filter else None
    result = GLOBAL_HOPGRAPH.k_hops(args.node, k=args.hops, filter_edge_types=filt)
    if args.html:
        node_rows = []
        for nid, nd in result.get('nodes', {}).items():
            node_rows.append(f"<tr><td><code>{nid}</code></td><td>{int(nd.get('created_ts',0))}</td><td>{int(nd.get('last_seen_ts',0))}</td></tr>")
        edge_rows = []
        for e in result.get('edges', []):
            edge_rows.append(f"<tr><td><code>{e['src']}</code></td><td><code>{e['dst']}</code></td><td>{e['etype']}</td><td>{e.get('source','')}</td><td>{int(e.get('ts',0))}</td></tr>")
        html = HTML_TEMPLATE.format(
            node=args.node,
            node_count=len(result.get('nodes', {})),
            edge_count=len(result.get('edges', [])),
            depth=result.get('depth_reached'),
            node_rows='\n'.join(node_rows),
            edge_rows='\n'.join(edge_rows)
        )
        if args.output:
            Path(args.output).write_text(html, encoding='utf-8')
            print(f"HTML written to {args.output}")
        else:
            print(html)
    else:
        out = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(out, encoding='utf-8')
        print(out)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
