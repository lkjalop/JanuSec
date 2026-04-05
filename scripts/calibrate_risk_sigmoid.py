#!/usr/bin/env python
"""Sigmoid Calibration Helper

Fits logistic calibration parameters (k, x0) mapping raw fused risk scores -> calibrated [0,1]
using labeled historical decisions.

Two optimization modes:
 - auc (maximize ROC AUC via simple grid / coordinate search)
 - logloss (minimize negative log likelihood)

Input formats supported: csv (with headers), jsonl (one JSON object per line).
Required columns/fields: raw_score (float), label (0/1 or false/true)

Example:
  python scripts/calibrate_risk_sigmoid.py --input decisions.csv --format csv \
      --score-col raw_score --label-col label --metric auc

Outputs recommended env vars:
  RISK_SIGMOID_ENABLED=1
  RISK_SIGMOID_SLOPE=<k>
  RISK_SIGMOID_CENTER=<x0>
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics as stats
from pathlib import Path
from typing import Iterable, List, Tuple


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to CSV or JSONL decisions file")
    ap.add_argument("--format", choices=["csv", "jsonl"], required=True)
    ap.add_argument("--score-col", default="raw_score")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--metric", choices=["auc", "logloss"], default="auc")
    ap.add_argument("--k-grid", default="2,3,4,5,6", help="Comma-separated candidate slopes")
    ap.add_argument("--center-grid", default="0.3,0.4,0.5,0.6,0.7", help="Comma-separated candidate centers")
    return ap.parse_args()


def load_rows(path: Path, fmt: str, score_col: str, label_col: str) -> List[Tuple[float, int]]:
    rows: List[Tuple[float, int]] = []
    if fmt == "csv":
        with path.open("r", newline="", encoding="utf-8") as fh:
            r = csv.DictReader(fh)
            for row in r:
                try:
                    s = float(row[score_col])
                    lab = row[label_col]
                    if isinstance(lab, str):
                        if lab.lower() in {"true", "t", "1", "yes"}: lab_i = 1
                        elif lab.lower() in {"false", "f", "0", "no"}: lab_i = 0
                        else: continue
                    else:
                        lab_i = int(lab)
                    rows.append((s, lab_i))
                except Exception:
                    continue
    else:  # jsonl
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try:
                    obj = json.loads(line)
                    s = float(obj[score_col])
                    lab = obj[label_col]
                    if isinstance(lab, str):
                        if lab.lower() in {"true", "t", "1", "yes"}: lab_i = 1
                        elif lab.lower() in {"false", "f", "0", "no"}: lab_i = 0
                        else: continue
                    else:
                        lab_i = int(lab)
                    rows.append((s, lab_i))
                except Exception:
                    continue
    return rows


def sigmoid(x: float, k: float, x0: float) -> float:
    # stable logistic
    try:
        z = k * (x - x0)
        if z >= 0:
            ez = math.exp(-z)
            return 1.0 / (1.0 + ez)
        else:
            ez = math.exp(z)
            return ez / (1.0 + ez)
    except Exception:
        return 0.5


def roc_auc(pairs: List[Tuple[float, int]]) -> float:
    # simple AUC via ranking
    pos = [s for s,l in pairs if l == 1]
    neg = [s for s,l in pairs if l == 0]
    if not pos or not neg: return 0.5
    # U statistic
    ranked = sorted(pairs, key=lambda t: t[0])
    rank = {idv: i for i,idv in enumerate(ranked)}  # not used strictly
    greater = 0
    for ps in pos:
        for ns in neg:
            if ps > ns: greater += 1
            elif ps == ns: greater += 0.5
    return greater / (len(pos) * len(neg))


def logloss(pairs: List[Tuple[float, int]]) -> float:
    eps = 1e-9
    total = 0.0
    for p,l in pairs:
        p = min(1-eps, max(eps, p))
        total += -(l*math.log(p) + (1-l)*math.log(1-p))
    return total / len(pairs) if pairs else 0.0


def evaluate(rows: List[Tuple[float,int]], k: float, x0: float], metric: str) -> float:  # type: ignore
    probs = [(sigmoid(s, k, x0), l) for s,l in rows]
    if metric == "auc":
        return roc_auc(probs)
    else:
        return -logloss(probs)  # higher is better (negated)


def main():
    args = parse_args()
    rows = load_rows(Path(args.input), args.format, args.score_col, args.label_col)
    if not rows:
        print("No valid rows parsed; aborting")
        return
    k_candidates = [float(x) for x in args.k_grid.split(',') if x]
    c_candidates = [float(x) for x in args.center_grid.split(',') if x]
    best_score = -1e9
    best = (None, None)
    for k in k_candidates:
        for c in c_candidates:
            score = evaluate(rows, k, c, args.metric)
            if score > best_score:
                best_score = score
                best = (k, c)
    k_out, c_out = best
    print("# Recommended sigmoid calibration params")
    print("RISK_SIGMOID_ENABLED=1")
    print(f"RISK_SIGMOID_SLOPE={k_out}")
    print(f"RISK_SIGMOID_CENTER={c_out}")
    print(f"# {args.metric}={best_score:.4f} on {len(rows)} samples")

if __name__ == "__main__":
    main()
