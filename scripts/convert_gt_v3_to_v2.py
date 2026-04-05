"""Convert v3 ground_truth.json (nodes list) into v2-style 'chain' entries.

Writes converted file to <dataset>/ground_truth_v2.json
"""
import argparse
import json
import os
from datetime import datetime


def parse_iso(ts):
    try:
        return int(datetime.fromisoformat(ts).timestamp())
    except Exception:
        # fallback: return 0
        return 0


def convert(dataset_dir: str):
    p = os.path.join(dataset_dir, 'ground_truth.json')
    if not os.path.exists(p):
        print('ground_truth.json not found in', dataset_dir)
        return 1
    with open(p, 'r', encoding='utf-8') as fh:
        data = json.load(fh)

    out = []
    for incident in data:
        incident_id = incident.get('incident_id')
        nodes = incident.get('nodes') or incident.get('chain') or []
        # if nodes already look v2-like (dicts with host/process/timestamp), detect and passthru
        if nodes and isinstance(nodes[0], dict) and 'timestamp' in nodes[0] and ('process' in (nodes[0] or {}) or 'file_hash' in (nodes[0] or {})):
            out.append({'incident_id': incident_id, 'chain': nodes})
            continue

        # otherwise nodes are v3: list of {type,id,ts}
        # sort by ts
        try:
            nodes_sorted = sorted(nodes, key=lambda n: n.get('ts') or '')
        except Exception:
            nodes_sorted = nodes

        current_host = None
        chain = []
        for n in nodes_sorted:
            ntype = n.get('type')
            nid = n.get('id') or ''
            n_ts = n.get('ts')
            ts_int = parse_iso(n_ts) if n_ts else 0
            if ntype == 'host':
                # extract host name after 'host:'
                if nid.startswith('host:'):
                    current_host = nid.split(':',1)[1]
                else:
                    current_host = nid
                # add a step with host only (v2 expects host in first step)
                chain.append({'host': current_host, 'timestamp': ts_int})
            elif ntype == 'process':
                # id like 'process:cmd.exe_1_2' -> process name base 'cmd.exe'
                name = nid.split(':',1)[1] if ':' in nid else nid
                base = name.split('_',1)[0]
                chain.append({'host': current_host, 'process': base, 'timestamp': ts_int})
            elif ntype == 'hash':
                h = nid.split(':',1)[1] if ':' in nid else nid
                chain.append({'host': current_host, 'file_hash': h, 'timestamp': ts_int})
            else:
                # unknown type, skip
                pass

        out.append({'incident_id': incident_id, 'chain': chain})

    out_p = os.path.join(dataset_dir, 'ground_truth_v2.json')
    with open(out_p, 'w', encoding='utf-8') as oh:
        json.dump(out, oh, indent=2)
    print('Wrote converted ground truth to', out_p)
    return 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', '-d', required=True)
    args = p.parse_args()
    return convert(args.dataset)


if __name__ == '__main__':
    raise SystemExit(main())
