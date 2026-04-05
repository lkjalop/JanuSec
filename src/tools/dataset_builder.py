"""Dataset Builder (M2)

Exports a calibration/training dataset from in-memory snapshots and labels.
Provides CSV and JSONL export options.

Usage (programmatic):
  from src.tools.dataset_builder import export_calibration_dataset
  export_calibration_dataset(out_csv="calibration.csv")

Env options:
  CAL_EXPORT_LIMIT=5000 (default)
"""
from __future__ import annotations

import csv
import json
import os
from typing import Iterable, Dict, Any, List

from core.factor_attribution_store import FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS


def _iter_labeled(limit: int) -> Iterable[Dict[str, Any]]:
    seen = 0
    for snap in FACTOR_ATTRIBUTIONS.recent(limit * 2):
        labels = LABELS.get(snap.event_id)
        lab = None
        for l in reversed(labels):
            if l.label in {"tp","fp","benign"}:
                lab = l.label
                break
        if not lab:
            continue
        yield {
            "event_id": snap.event_id,
            "ts": snap.ts,
            "label": lab,
            "score": snap.score,
            "raw_score": snap.raw_score if snap.raw_score is not None else snap.score,
            "factors": list(snap.factors),
            "breakdown": snap.breakdown,
        }
        seen += 1
        if seen >= limit:
            break


def export_calibration_dataset(out_csv: str | None = None, out_jsonl: str | None = None, limit: int | None = None) -> Dict[str, Any]:
    lim = int(os.getenv("CAL_EXPORT_LIMIT", str(limit or 5000)))
    rows: List[Dict[str, Any]] = list(_iter_labeled(lim))
    if out_csv:
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["event_id","ts","label","score","raw_score","factors"])
            for r in rows:
                w.writerow([r["event_id"], r["ts"], r["label"], r["score"], r["raw_score"], ";".join(r["factors"])])
    if out_jsonl:
        with open(out_jsonl, "w", encoding="utf-8") as jh:
            for r in rows:
                jh.write(json.dumps(r) + "\n")
    return {"count": len(rows), "csv": out_csv, "jsonl": out_jsonl}

__all__ = ["export_calibration_dataset"]
