"""Extended parameter sensitivity sweep for HopGraph explain + stitching.

Now sweeps across:
 - Primary explain beam width (beam_width)
 - Primary explain max depth (max_depth)
 - Stitch depth (HOPGRAPH_STITCH_DEPTH env)
 - Stitch beam (HOPGRAPH_STITCH_BEAM env)
 - gt_sequence edge weight cap (HOPGRAPH_GT_SEQUENCE_WEIGHT env)
 - Forced edge cap (HOPGRAPH_FORCED_EDGE_CAP env) to test masking effect

For each run we invoke the evaluator with deterministic + gt_sequence enabled.
Outputs one result JSON per configuration alongside an incidents directory emitted
by the evaluator that contains per-incident chain/subgraph JSON dumps. A master
CSV and JSON summary (tuning_report.*) are incrementally updated.

Runtime can become large (Cartesian product). Use --limit-runs to truncate after N.
"""
from __future__ import annotations
import os, subprocess, json, itertools, time
from pathlib import Path
import csv
import argparse


def run_eval(env, out_path, dataset, beam_width=20, top_k=10, max_depth=8, time_window=60):
    cmd = [
        'python', 'scripts/benchmark_evaluate_ground_truth.py',
        '--dataset', str(dataset),
        '--out', str(out_path),
        '--beam-width', str(beam_width),
        '--top-k', str(top_k),
        '--max-depth', str(max_depth),
        '--enable-gt-sequence',
        '--deterministic',
        '--time-window', str(time_window)
    ]
    # Enable per-incident exports always for sweep to allow diffing later
    cmd.append('--emit-incidents')
    # Run subprocess with env
    start = time.time()
    subprocess.run(cmd, check=True, env=env)
    elapsed = time.time() - start
    return elapsed


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', required=True, help='Path to benchmark dataset root (contains ground_truth.json)')
    p.add_argument('--out-dir', required=True, help='Output directory for sweep artifacts')
    p.add_argument('--limit-runs', type=int, default=None, help='Optional cap for number of runs (debug)')
    p.add_argument('--time-window', type=int, default=60, help='Timestamp matching window passed to evaluator')
    args = p.parse_args()
    dataset = Path(args.dataset)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Core parameter grids (can be tuned here)
    stitch_depths = [1,2,3]
    stitch_beams = [2,3,5]
    gt_weights = [2.8,3.2]  # lowered range to test masking
    forced_caps = [4.0,0.9,0.6]
    beam_widths = [20,50,100]
    max_depths = [6,8,10]

    runs = list(itertools.product(stitch_depths, stitch_beams, gt_weights, forced_caps, beam_widths, max_depths))
    report = {'runs': [], 'dataset': dataset.name, 'total_planned': len(runs)}

    base_env = os.environ.copy()
    base_env['PYTHONPATH'] = os.getcwd()

    for idx, (sd, sb, gw, fc, bw, md) in enumerate(runs, start=1):
        if args.limit_runs and idx > args.limit_runs:
            print(f"Reached limit {args.limit_runs}; stopping early.")
            break
        name = (
            f"sd{sd}_sb{sb}_gw{str(gw).replace('.','p')}"
            f"_bw{bw}_md{md}_fc{str(fc).replace('.','p')}"
        )
        out_json = out_dir / f"result_{name}.json"
        env = base_env.copy()
        env['HOPGRAPH_STITCH_DEPTH'] = str(sd)
        env['HOPGRAPH_STITCH_BEAM'] = str(sb)
        env['HOPGRAPH_GT_SEQUENCE_WEIGHT'] = str(gw)
        env['HOPGRAPH_FORCED_EDGE_CAP'] = str(fc)
        print(f"[{idx}/{len(runs)}] Running: sd={sd} sb={sb} gw={gw} bw={bw} md={md} fc={fc} -> {out_json.name}")
        try:
            t = run_eval(env, out_json, dataset, beam_width=bw, max_depth=md, time_window=args.time_window)
        except subprocess.CalledProcessError as e:
            print('Run failed for', name, 'error', e)
            continue
        # read result json
        try:
            data = json.loads(out_json.read_text(encoding='utf-8'))
            entry = {
                'name': name,
                'stitch_depth': sd,
                'stitch_beam': sb,
                'gt_weight': gw,
                'forced_cap': fc,
                'beam_width': bw,
                'max_depth': md,
                'precision_mean': data.get('precision_mean'),
                'recall_mean': data.get('recall_mean'),
                'sequence_score_mean': data.get('sequence_score_mean'),
                'ingestion_time_seconds': data.get('ingestion_time_seconds'),
                'explain_time_seconds_total': data.get('explain_time_seconds_total'),
                'run_seconds': t
            }
            report['runs'].append(entry)
            # write partial report as we go
            report_path = out_dir / 'tuning_report.json'
            report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
            # also append CSV
            csv_path = out_dir / 'tuning_report.csv'
            header = [
                'name','stitch_depth','stitch_beam','gt_weight','forced_cap','beam_width','max_depth',
                'precision_mean','recall_mean','sequence_score_mean','ingestion_time_seconds','explain_time_seconds_total','run_seconds'
            ]
            with csv_path.open('w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(header)
                for r in report['runs']:
                    w.writerow([r.get(h) for h in header])
        except Exception as e:
            print('Failed to parse result for', name, e)
            continue

    print('Tuning completed. Report at', (out_dir / 'tuning_report.json'))

if __name__ == '__main__':
    main()
