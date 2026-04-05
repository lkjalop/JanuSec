from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Tuple, List
from ml.experiment_tracker import ExperimentTracker


def _read_csv(path: Path) -> List[Tuple[float, int]]:
    rows: List[Tuple[float, int]] = []
    with path.open('r', encoding='utf-8') as fh:
        rd = csv.DictReader(fh)
        for r in rd:
            try:
                x = float(r.get('raw_score') or r.get('score') or 0.0)
                y = 1 if str(r.get('label')).lower() == 'tp' else 0
            except Exception:
                continue
            rows.append((x, y))
    return rows


def _fit_sigmoid(samples: List[Tuple[float, int]]):
    if not samples:
        return None
    best = None
    best_ll = -1e18
    for k in [1.0, 2.0, 3.0, 4.0, 6.0, 8.0]:
        for x0 in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
            ll = 0.0
            for x, y in samples:
                p = 1.0 / (1.0 + math.exp(-k * (x - x0)))
                p = max(1e-6, min(1 - 1e-6, p))
                ll += y * math.log(p) + (1 - y) * math.log(1 - p)
            if ll > best_ll:
                best_ll = ll
                best = (k, x0, ll)
    return best


def train(csv_path: Path, out_model: Path, tracker_path: Path | None = None) -> dict:
    tracker = ExperimentTracker(out_path=str(tracker_path)) if tracker_path else ExperimentTracker()
    run_id = tracker.start_run(params={"csv": str(csv_path)}, tags={"task": "baseline_sigmoid"})
    samples = _read_csv(csv_path)
    fit = _fit_sigmoid(samples)
    if not fit:
        tracker.end_run(run_id, status='failed')
        raise RuntimeError("no_samples")
    k, x0, ll = fit
    metrics = {"loglik": float(ll), "samples": len(samples)}
    tracker.log_metrics(run_id, metrics)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    out_model.write_text(json.dumps({"type": "sigmoid", "k": k, "x0": x0, "metrics": metrics}), encoding='utf-8')
    tracker.end_run(run_id, status='completed')
    return {"k": k, "x0": x0, **metrics}


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Train baseline sigmoid model from CSV")
    p.add_argument("csv", type=Path, help="Path to calibration CSV")
    p.add_argument("--out", type=Path, default=Path("models/baseline_sigmoid.json"))
    p.add_argument("--tracker", type=Path, default=Path("experiments.jsonl"))
    args = p.parse_args(argv)
    res = train(args.csv, args.out, args.tracker)
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
