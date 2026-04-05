"""Compare per-incident chain exports between two evaluation runs.

Usage:
  python scripts/compare_incident_chains.py \
      --baseline results/runA_incidents \
      --candidate results/runB_incidents \
      --out diff_report.json

Each incidents directory should contain files named incident_<id>.json produced by
benchmark_evaluate_ground_truth.py with --emit-incidents. This tool produces:
  - A JSON report summarizing metric deltas per incident
  - A CSV (optional) for spreadsheet review
  - High-level aggregates: count improved sequence_score, precision, recall

Deltas computed as candidate - baseline.
"""
from __future__ import annotations
import json, argparse
from pathlib import Path
import csv
from typing import Dict, Any

def load_incidents(dir_path: Path) -> Dict[str, dict]:
    data = {}
    if not dir_path.exists():
        return data
    for f in dir_path.glob('incident_*.json'):
        try:
            inc = json.loads(f.read_text(encoding='utf-8'))
            iid = str(inc.get('incident_id'))
            data[iid] = inc
        except Exception:
            continue
    return data


def metrics_from(inc: dict) -> Dict[str, float]:
    m = inc.get('metrics') or {}
    out = {}
    for k in ['precision','recall','sequence_score','tp','extracted','gt']:
        v = m.get(k)
        if isinstance(v, (int,float)):
            out[k] = float(v)
    return out


def compare(baseline_dir: Path, candidate_dir: Path):
    base = load_incidents(baseline_dir)
    cand = load_incidents(candidate_dir)
    all_ids = sorted(set(base.keys()) | set(cand.keys()), key=lambda x: int(x) if str(x).isdigit() else x)
    rows = []
    improved_seq = improved_prec = improved_rec = 0
    for iid in all_ids:
        b = base.get(iid)
        c = cand.get(iid)
        bm = metrics_from(b) if b else {}
        cm = metrics_from(c) if c else {}
        row = {'incident_id': iid}
        for metric in ['precision','recall','sequence_score']:
            bval = bm.get(metric)
            cval = cm.get(metric)
            row[f'baseline_{metric}'] = bval
            row[f'candidate_{metric}'] = cval
            if bval is not None and cval is not None:
                row[f'delta_{metric}'] = cval - bval
        # chain length deltas
        try:
            brow_len = max((len(ch.get('nodes',[])) for ch in (b.get('chains') or [])), default=None) if b else None
        except Exception:
            brow_len = None
        try:
            crow_len = max((len(ch.get('nodes',[])) for ch in (c.get('chains') or [])), default=None) if c else None
        except Exception:
            crow_len = None
        if brow_len is not None:
            row['baseline_max_chain_len'] = brow_len
        if crow_len is not None:
            row['candidate_max_chain_len'] = crow_len
        if brow_len is not None and crow_len is not None:
            row['delta_max_chain_len'] = crow_len - brow_len
        # improvement counters
        if row.get('delta_sequence_score',0) > 0: improved_seq += 1
        if row.get('delta_precision',0) > 0: improved_prec += 1
        if row.get('delta_recall',0) > 0: improved_rec += 1
        rows.append(row)
    summary = {
        'baseline_dir': str(baseline_dir),
        'candidate_dir': str(candidate_dir),
        'incidents_compared': len(rows),
        'improved_sequence_score': improved_seq,
        'improved_precision': improved_prec,
        'improved_recall': improved_rec,
        'rows': rows
    }
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline', required=True, help='Path to baseline incidents directory')
    ap.add_argument('--candidate', required=True, help='Path to candidate incidents directory')
    ap.add_argument('--out', required=True, help='Output JSON report file')
    ap.add_argument('--emit-csv', action='store_true', help='Also emit CSV next to JSON report')
    args = ap.parse_args()
    baseline_dir = Path(args.baseline)
    candidate_dir = Path(args.candidate)
    report = compare(baseline_dir, candidate_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    if args.emit_csv:
        csv_path = out_path.with_suffix('.csv')
        headers = ['incident_id','baseline_precision','candidate_precision','delta_precision','baseline_recall','candidate_recall','delta_recall','baseline_sequence_score','candidate_sequence_score','delta_sequence_score','baseline_max_chain_len','candidate_max_chain_len','delta_max_chain_len']
        with csv_path.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in report['rows']:
                w.writerow([r.get(h) for h in headers])
    print('Diff report written to', out_path)

if __name__ == '__main__':
    main()
